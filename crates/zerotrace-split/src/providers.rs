//! Where each component's key actually comes from.
//!
//! A provider either produces a key or reports why it cannot. Nothing here
//! invents a key: a component that is unavailable must fail loudly, because a
//! silently substituted key would turn a two-of-three vault into a one-of-two
//! one without anybody noticing.

use zerotrace_core::{Assurance, Error, Result};
use zerotrace_crypto as crypto;
use zerotrace_kdf::{derive_kek, KdfParams};
use zerotrace_secure_memory::Key256;

use crate::ComponentKind;

/// Supplies the key for one component.
pub trait ComponentProvider {
    fn kind(&self) -> ComponentKind;
    fn key(&self) -> Result<Key256>;
    /// What this provider genuinely offers on this machine.
    fn assurance(&self) -> Assurance;
    /// Whether the secret would be copied along with a stolen drive.
    fn on_drive(&self) -> bool;
}

/// The user component: a password, run through Argon2id.
///
/// A FIDO2 authenticator's PRF output can be folded in when one is enrolled;
/// that composition already exists in `zerotrace-auth` and is applied before
/// the key reaches here.
pub struct UserProvider {
    key: Key256,
}

impl UserProvider {
    pub fn from_password(password: &[u8], salt: &[u8], params: KdfParams) -> Result<Self> {
        let derived = derive_kek(password, salt, params)?;
        // Separated from the vault's own KEK derivation so that the same
        // password does not produce the same bytes in two different roles.
        let key = crypto::derive_subkey(&derived, salt, b"apex-zerotrace:split:user-component")?;
        Ok(Self { key })
    }
}

impl ComponentProvider for UserProvider {
    fn kind(&self) -> ComponentKind {
        ComponentKind::User
    }
    fn key(&self) -> Result<Key256> {
        Ok(self.key.clone())
    }
    fn assurance(&self) -> Assurance {
        Assurance::Verified
    }
    fn on_drive(&self) -> bool {
        false
    }
}

/// The machine component, sealed by a TPM or Secure Enclave.
///
/// Not implemented. This is the component that would bind a vault to one
/// physical computer, and it is precisely the one that needs hardware to be
/// meaningful: a "machine key" written to a file on the same disk travels with
/// the drive and defends against nothing.
///
/// It fails rather than falling back, because a fallback here would silently
/// remove the protection the component exists to provide.
pub struct MachineProvider;

impl ComponentProvider for MachineProvider {
    fn kind(&self) -> ComponentKind {
        ComponentKind::Machine
    }
    fn key(&self) -> Result<Key256> {
        Err(Error::NotImplemented(
            "machine key sealing. Binding a vault to this computer requires a TPM or Secure \
             Enclave, which this build does not use. A key file on the same disk would \
             travel with a stolen drive and is deliberately not offered as a substitute.",
        ))
    }
    fn assurance(&self) -> Assurance {
        Assurance::NotImplemented
    }
    fn on_drive(&self) -> bool {
        false
    }
}

/// The remote component, held as an offline token on separate media.
///
/// The specification's remote authorization service is not implemented. What
/// is implemented is the same share held as a file the owner keeps elsewhere:
/// a USB key, a second machine, a safe. That is weaker than a service, which
/// could also refuse to release a share for a superseded state, but it is
/// genuinely off the stolen drive and it can be built and tested now.
pub struct RecoveryToken {
    key: Key256,
}

impl RecoveryToken {
    /// Generates a fresh token.
    pub fn generate() -> Self {
        Self { key: crypto::random_key() }
    }

    /// The bytes to write to separate media.
    pub fn encode(&self) -> String {
        let hex: String = self.key.expose().iter().map(|b| format!("{b:02x}")).collect();
        format!("apex-zerotrace-recovery-token:v1:{hex}")
    }

    pub fn decode(text: &str) -> Result<Self> {
        let hex = text
            .trim()
            .strip_prefix("apex-zerotrace-recovery-token:v1:")
            .ok_or_else(|| Error::Format("not a ZeroTrace recovery token".into()))?;
        // Compared and sliced as bytes, never as a string. A length check
        // counts bytes while slicing a `str` requires character boundaries, so
        // a token containing one multi-byte character passed the check and
        // then panicked on the slice. Hex is ASCII by definition, so bytes are
        // the correct unit here anyway.
        let hex = hex.as_bytes();
        if hex.len() != 64 {
            return Err(Error::Format("recovery token has the wrong length".into()));
        }
        let mut key = Key256::zeroed();
        for i in 0..32 {
            key.expose_mut()[i] = hex_pair(hex[i * 2], hex[i * 2 + 1])
                .ok_or_else(|| Error::Format("recovery token is not hex".into()))?;
        }
        Ok(Self { key })
    }
}

impl ComponentProvider for RecoveryToken {
    fn kind(&self) -> ComponentKind {
        ComponentKind::Remote
    }
    fn key(&self) -> Result<Key256> {
        Ok(self.key.clone())
    }
    fn assurance(&self) -> Assurance {
        Assurance::BestEffort
    }
    fn on_drive(&self) -> bool {
        // True only if the owner stores it there, which cannot be detected
        // from inside the token itself. The CLI warns at enrollment instead.
        false
    }
}

/// Decodes one hex pair, or nothing.
///
/// Byte-wise on purpose: see the note in `RecoveryToken::decode`.
fn hex_pair(hi: u8, lo: u8) -> Option<u8> {
    let digit = |c: u8| match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        b'A'..=b'F' => Some(c - b'A' + 10),
        _ => None,
    };
    Some(digit(hi)? << 4 | digit(lo)?)
}

/// Collects keys from providers, reporting which were unavailable.
pub fn gather(
    providers: &[&dyn ComponentProvider],
) -> (Vec<(ComponentKind, Key256)>, Vec<(ComponentKind, String)>) {
    let mut got = Vec::new();
    let mut missing = Vec::new();
    for p in providers {
        match p.key() {
            Ok(k) => got.push((p.kind(), k)),
            Err(e) => missing.push((p.kind(), e.to_string())),
        }
    }
    (got, missing)
}
