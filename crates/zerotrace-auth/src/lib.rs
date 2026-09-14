//! Authentication factors and how they combine into a key.
//!
//! # What this crate does and does not do
//!
//! The security-critical part of multi-factor unlocking is the *composition*:
//! how a second factor's secret is mixed with the password-derived key so that
//! both are genuinely required. That is implemented here and tested.
//!
//! The USB HID transport that talks to a physical authenticator is not. It
//! cannot be written and verified without hardware, and an untested transport
//! in a security boundary is worse than an absent one. [`Fido2Authenticator`]
//! therefore reports `NotImplemented` rather than pretending, and the vault
//! refuses to open a FIDO2-protected vault instead of silently downgrading to
//! password-only.

#![forbid(unsafe_code)]

pub mod audit_events;

use serde::{Deserialize, Serialize};
use zerotrace_core::{Assurance, Error, Result};
use zerotrace_crypto as crypto;
use zerotrace_secure_memory::Key256;

/// Kinds of factor the policy can require.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum FactorKind {
    /// Something you know. Always required; a vault with no password has no
    /// offline-guessing resistance at all.
    Password,
    /// Something you have, contributing key material through the FIDO2 PRF
    /// extension rather than merely asserting a yes/no result.
    Fido2Prf,
}

impl FactorKind {
    pub fn bit(&self) -> u16 {
        match self {
            FactorKind::Password => 1 << 0,
            FactorKind::Fido2Prf => 1 << 1,
        }
    }
    pub fn label(&self) -> &'static str {
        match self {
            FactorKind::Password => "password",
            FactorKind::Fido2Prf => "FIDO2 (PRF)",
        }
    }
}

/// Which factors a vault requires.
///
/// Stored inside the header's authenticated region, so an attacker cannot
/// strip the FIDO2 requirement and hand back a password-only vault.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct FactorSet(pub u16);

impl FactorSet {
    pub fn password_only() -> Self {
        FactorSet(FactorKind::Password.bit())
    }
    pub fn contains(&self, k: FactorKind) -> bool {
        self.0 & k.bit() != 0
    }
    pub fn with(mut self, k: FactorKind) -> Self {
        self.0 |= k.bit();
        self
    }
    pub fn count(&self) -> u32 {
        self.0.count_ones()
    }
    /// Rejects a set that would leave a vault with no knowledge factor.
    pub fn validate(&self) -> Result<()> {
        if !self.contains(FactorKind::Password) {
            return Err(Error::Other(
                "a vault must always require a password factor".into(),
            ));
        }
        if self.0 & !(FactorKind::Password.bit() | FactorKind::Fido2Prf.bit()) != 0 {
            return Err(Error::Unsupported {
                what: "authentication factor",
                value: format!("{:#06x}", self.0),
            });
        }
        Ok(())
    }
}

/// The authentication material recorded in a vault header.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AuthDescriptor {
    pub required: FactorSet,
    /// Salt handed to the authenticator's PRF. Unique per vault.
    pub prf_salt: [u8; 32],
    /// Truncated hash of the credential id, so the right key can be selected
    /// without storing the credential id itself.
    pub credential_hint: [u8; 20],
}

impl Default for AuthDescriptor {
    fn default() -> Self {
        Self {
            required: FactorSet::password_only(),
            prf_salt: [0u8; 32],
            credential_hint: [0u8; 20],
        }
    }
}

impl AuthDescriptor {
    pub fn requires_hardware(&self) -> bool {
        self.required.contains(FactorKind::Fido2Prf)
    }
}

/// A source of key material from a hardware authenticator.
pub trait Authenticator {
    fn kind(&self) -> FactorKind;
    /// Returns the PRF output for `salt` from the credential matching `hint`.
    fn prf_secret(&self, hint: &[u8; 20], salt: &[u8; 32]) -> Result<Key256>;
    /// What this implementation actually provides, for honest reporting.
    fn assurance(&self) -> Assurance;
}

/// Real FIDO2 authenticators. Transport not implemented.
pub struct Fido2Authenticator;

impl Authenticator for Fido2Authenticator {
    fn kind(&self) -> FactorKind {
        FactorKind::Fido2Prf
    }
    fn prf_secret(&self, _hint: &[u8; 20], _salt: &[u8; 32]) -> Result<Key256> {
        Err(Error::NotImplemented(
            "FIDO2 transport. This build cannot talk to a hardware authenticator, so a \
             vault requiring one cannot be opened here. It is refused rather than \
             opened with the password alone.",
        ))
    }
    fn assurance(&self) -> Assurance {
        Assurance::NotImplemented
    }
}

/// A software stand-in used only by tests.
///
/// This is not a security boundary and must never be offered to users: the
/// "device secret" is just bytes in the process. It exists so the composition
/// logic can be tested without hardware.
#[cfg(any(test, feature = "test-authenticator"))]
pub struct SoftwareAuthenticator {
    secret: [u8; 32],
}

#[cfg(any(test, feature = "test-authenticator"))]
impl SoftwareAuthenticator {
    pub fn new(secret: [u8; 32]) -> Self {
        Self { secret }
    }
}

#[cfg(any(test, feature = "test-authenticator"))]
impl Authenticator for SoftwareAuthenticator {
    fn kind(&self) -> FactorKind {
        FactorKind::Fido2Prf
    }
    fn prf_secret(&self, hint: &[u8; 20], salt: &[u8; 32]) -> Result<Key256> {
        // Mirrors the shape of a real PRF: a keyed function of the salt.
        let mut ikm = Vec::with_capacity(84);
        ikm.extend_from_slice(&self.secret);
        ikm.extend_from_slice(hint);
        ikm.extend_from_slice(salt);
        let mut out = Key256::zeroed();
        let h = hkdf::Hkdf::<sha2::Sha256>::new(Some(salt), &ikm);
        h.expand(b"apex-zerotrace:test-authenticator", out.expose_mut())
            .map_err(|_| Error::Crypto("test authenticator failed".into()))?;
        Ok(out)
    }
    fn assurance(&self) -> Assurance {
        // Never claim more than this. It is a test double.
        Assurance::NotSupported
    }
}

/// Domain separator for the composed key-encryption key.
const KEK_INFO: &[u8] = b"apex-zerotrace:v2:kek-composition";

/// Combines every required factor into the key that wraps the master key.
///
/// Concatenating the factor secrets as HKDF input material means all of them
/// are needed: omitting one, or supplying a wrong one, produces a different
/// KEK and the master key simply fails to unwrap. There is no code path where
/// a missing factor is "skipped".
///
/// Factors are fed in a fixed order so the result is deterministic.
pub fn compose_kek(
    descriptor: &AuthDescriptor,
    password_key: &Key256,
    hardware: Option<&Key256>,
    kdf_salt: &[u8],
) -> Result<Key256> {
    descriptor.required.validate()?;

    let mut ikm: Vec<u8> = Vec::with_capacity(64);
    ikm.extend_from_slice(password_key.expose());

    if descriptor.requires_hardware() {
        let hw = hardware.ok_or(Error::NotImplemented(
            "this vault requires a FIDO2 factor and none was supplied",
        ))?;
        ikm.extend_from_slice(hw.expose());
    } else if hardware.is_some() {
        // Supplying a factor the vault does not require must not silently
        // change the key; refuse rather than derive something unopenable.
        return Err(Error::Other(
            "a hardware factor was supplied but this vault does not require one".into(),
        ));
    }

    let h = hkdf::Hkdf::<sha2::Sha256>::new(Some(kdf_salt), &ikm);
    let mut kek = Key256::zeroed();
    h.expand(KEK_INFO, kek.expose_mut())
        .map_err(|_| Error::Crypto("KEK composition failed".into()))?;

    // The concatenated material is a secret in its own right.
    use zeroize_shim::Zeroize;
    ikm.zeroize();
    Ok(kek)
}

mod zeroize_shim {
    pub trait Zeroize {
        fn zeroize(&mut self);
    }
    impl Zeroize for Vec<u8> {
        fn zeroize(&mut self) {
            for b in self.iter_mut() {
                *b = 0;
            }
            self.clear();
        }
    }
}

/// Hashes a credential id down to the hint stored in the header.
pub fn credential_hint(credential_id: &[u8]) -> [u8; 20] {
    let full = crypto::sha256(credential_id);
    let mut hint = [0u8; 20];
    hint.copy_from_slice(&full[..20]);
    hint
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pw_key(b: u8) -> Key256 {
        Key256::new([b; 32])
    }

    #[test]
    fn a_vault_must_always_require_a_password() {
        assert!(FactorSet(0).validate().is_err());
        assert!(FactorSet(FactorKind::Fido2Prf.bit()).validate().is_err());
        assert!(FactorSet::password_only().validate().is_ok());
    }

    #[test]
    fn unknown_factor_bits_are_refused() {
        assert!(FactorSet(0xFF01).validate().is_err());
    }

    #[test]
    fn password_only_composition_is_deterministic() {
        let d = AuthDescriptor::default();
        let a = compose_kek(&d, &pw_key(1), None, b"salt-value-0123456789").unwrap();
        let b = compose_kek(&d, &pw_key(1), None, b"salt-value-0123456789").unwrap();
        assert_eq!(a, b);
        let c = compose_kek(&d, &pw_key(2), None, b"salt-value-0123456789").unwrap();
        assert_ne!(a, c, "a different password must give a different KEK");
    }

    #[test]
    fn the_hardware_factor_is_genuinely_required() {
        let d = AuthDescriptor {
            required: FactorSet::password_only().with(FactorKind::Fido2Prf),
            prf_salt: [7u8; 32],
            credential_hint: [9u8; 20],
        };
        let auth = SoftwareAuthenticator::new([42u8; 32]);
        let hw = auth.prf_secret(&d.credential_hint, &d.prf_salt).unwrap();

        let with_hw = compose_kek(&d, &pw_key(1), Some(&hw), b"salt-value-0123456789").unwrap();

        // Omitting it is an error, not a silent downgrade.
        assert!(compose_kek(&d, &pw_key(1), None, b"salt-value-0123456789").is_err());

        // A different device gives a different KEK, so the master key will not
        // unwrap. This is the property that makes the factor real.
        let other = SoftwareAuthenticator::new([43u8; 32]);
        let other_hw = other.prf_secret(&d.credential_hint, &d.prf_salt).unwrap();
        let with_other =
            compose_kek(&d, &pw_key(1), Some(&other_hw), b"salt-value-0123456789").unwrap();
        assert_ne!(with_hw, with_other);

        // And the password still matters when hardware is present.
        let other_pw = compose_kek(&d, &pw_key(2), Some(&hw), b"salt-value-0123456789").unwrap();
        assert_ne!(with_hw, other_pw);
    }

    #[test]
    fn a_password_only_vault_refuses_an_unexpected_hardware_factor() {
        let d = AuthDescriptor::default();
        let hw = pw_key(5);
        assert!(compose_kek(&d, &pw_key(1), Some(&hw), b"salt-value-0123456789").is_err());
    }

    #[test]
    fn real_fido2_reports_not_implemented_rather_than_failing_open() {
        let a = Fido2Authenticator;
        assert_eq!(a.assurance(), Assurance::NotImplemented);
        let err = a.prf_secret(&[0u8; 20], &[0u8; 32]).unwrap_err();
        assert!(matches!(err, Error::NotImplemented(_)));
    }

    #[test]
    fn the_prf_salt_separates_vaults_using_the_same_device() {
        let auth = SoftwareAuthenticator::new([42u8; 32]);
        let a = auth.prf_secret(&[1u8; 20], &[1u8; 32]).unwrap();
        let b = auth.prf_secret(&[1u8; 20], &[2u8; 32]).unwrap();
        assert_ne!(a, b, "one device must not give the same key to two vaults");
    }
}
