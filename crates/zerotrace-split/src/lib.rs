//! Split-key protection of the vault's release key.
//!
//! # The attack this exists for
//!
//! An attacker removes the drive, mounts it elsewhere and copies the vault.
//! They never run our code, so the deadman switch never fires: the policy and
//! journal are files they now control and can simply delete. Against that
//! attacker the only thing standing between them and the plaintext is the
//! password, and a password is guessable offline for as long as they like.
//!
//! Split-key protection changes what a stolen drive is worth. The key that
//! unwraps the master key is divided into shares, each sealed under a
//! different component. A drive holds every share *ciphertext*, so the
//! attacker gains nothing by copying them; opening any two requires two
//! independent secrets, and at least one of those is deliberately not on the
//! drive.
//!
//! # Why two of three
//!
//! Three of three sounds stronger and is worse. It means any single loss is
//! permanent data loss: a dead motherboard, a discontinued service, a
//! forgotten password. For a vault holding things a person cannot afford to
//! lose, that availability profile is a bigger risk than the attack it
//! prevents.
//!
//! Two of three still defeats drive theft. An attacker holding the disk and
//! the password has one component and needs two. It survives the loss of any
//! single component. The cost is stated rather than hidden: a compromised
//! remote service combined with a compromised password opens the vault without
//! the machine, so the remote component must be treated as a real credential
//! and not a convenience.
//!
//! # What is not solved here
//!
//! Rollback. An attacker who physically holds the drive can restore an older
//! copy of any file on it, including this one. Detecting that needs an anchor
//! they do not control: a monotonic counter in a TPM, or the remote service
//! refusing to release its share for a state it has already superseded.
//! Neither exists yet, and this crate does not pretend otherwise.

#![forbid(unsafe_code)]

pub mod providers;

use serde::{Deserialize, Serialize};
use sharks::{Share, Sharks};
use zerotrace_core::{Error, Result, VaultId};
use zerotrace_crypto::{self as crypto, CryptoSuite};
use zerotrace_secure_memory::Key256;

pub use providers::{ComponentProvider, MachineProvider, RecoveryToken, UserProvider};

/// The threshold. See the module documentation for why it is not three.
pub const THRESHOLD: u8 = 2;

/// The independent things a share can be sealed under.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum ComponentKind {
    /// Something the person knows, and optionally holds: the password, and a
    /// FIDO2 authenticator when one is enrolled.
    User,
    /// Something bound to this physical machine, sealed by a TPM or Secure
    /// Enclave so it cannot leave with the drive.
    Machine,
    /// Something released by an authorization service, or by an offline token
    /// the owner keeps on separate media.
    Remote,
    /// A share held by a second party or in a second place: another person, a
    /// safe, a deposit box.
    ///
    /// This exists so a vault can have three components before a TPM is
    /// available. Two components with a threshold of two has no redundancy at
    /// all, and losing either one destroys the vault permanently. That is a
    /// live risk on an ordinary day, unlike the burglary the split defends
    /// against, so it is worth a component slot of its own.
    Custodian,
}

impl ComponentKind {
    pub fn label(&self) -> &'static str {
        match self {
            ComponentKind::User => "user",
            ComponentKind::Machine => "machine",
            ComponentKind::Remote => "remote",
            ComponentKind::Custodian => "custodian",
        }
    }

    /// Whether a stolen drive carries this component's secret.
    ///
    /// This is the property that makes the scheme work, so it is explicit
    /// rather than implied by where a file happens to live.
    pub fn travels_with_the_drive(&self) -> bool {
        match self {
            // A password is in the owner's head, not on the disk.
            ComponentKind::User => false,
            // The whole point of TPM sealing: the secret stays in the chip.
            ComponentKind::Machine => false,
            // Only if the owner stores the token on the same drive, which the
            // documentation and the CLI both warn against.
            ComponentKind::Remote => false,
            ComponentKind::Custodian => false,
        }
    }

    /// The Shamir share index. Fixed per component so shares stay identifiable
    /// across re-enrollment.
    fn index(&self) -> u8 {
        match self {
            ComponentKind::User => 1,
            ComponentKind::Machine => 2,
            ComponentKind::Remote => 3,
            ComponentKind::Custodian => 4,
        }
    }
}

/// One share, sealed under its component's key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SealedShare {
    pub component: ComponentKind,
    /// Nonce for this share's AEAD.
    pub nonce: [u8; 24],
    /// The Shamir share, encrypted under the component key.
    pub ciphertext: Vec<u8>,
}

/// Everything needed to reconstruct the release key given enough components.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SplitBundle {
    pub vault_id: VaultId,
    pub suite: CryptoSuite,
    pub threshold: u8,
    pub shares: Vec<SealedShare>,
}

/// Additional authenticated data binding a share to its vault and slot.
///
/// Without this, a share could be moved between vaults or between component
/// slots, and the substitution would go unnoticed.
fn share_aad(vault_id: &VaultId, component: ComponentKind, threshold: u8) -> Vec<u8> {
    let mut aad = Vec::with_capacity(40);
    aad.extend_from_slice(b"apex-zerotrace:split-share:v1");
    aad.extend_from_slice(vault_id.as_bytes());
    aad.push(component.index());
    aad.push(threshold);
    aad
}

impl SplitBundle {
    pub fn enrolled(&self) -> Vec<ComponentKind> {
        let mut k: Vec<ComponentKind> = self.shares.iter().map(|s| s.component).collect();
        k.sort();
        k
    }

    /// Whether the enrolled set can survive losing any one component.
    ///
    /// With only two enrolled, a two-of-two scheme has no redundancy: losing
    /// either is permanent data loss. That is a legitimate configuration but
    /// the owner must be told, so it is queryable rather than buried.
    pub fn tolerates_one_loss(&self) -> bool {
        self.shares.len() as u8 > self.threshold
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut b = Vec::with_capacity(256);
        b.extend_from_slice(b"AZSP");
        b.push(1); // format version
        b.extend_from_slice(self.vault_id.as_bytes());
        b.extend_from_slice(&(self.suite as u16).to_le_bytes());
        b.push(self.threshold);
        b.push(self.shares.len() as u8);
        for s in &self.shares {
            b.push(s.component.index());
            b.extend_from_slice(&s.nonce);
            b.extend_from_slice(&(s.ciphertext.len() as u16).to_le_bytes());
            b.extend_from_slice(&s.ciphertext);
        }
        b
    }

    pub fn decode(data: &[u8]) -> Result<Self> {
        let mut p = 0usize;
        let take = |p: &mut usize, n: usize| -> Result<&[u8]> {
            let s = data
                .get(*p..*p + n)
                .ok_or_else(|| Error::Format("split bundle ended unexpectedly".into()))?;
            *p += n;
            Ok(s)
        };
        if take(&mut p, 4)? != b"AZSP" {
            return Err(Error::Format("not a ZeroTrace split bundle".into()));
        }
        let version = take(&mut p, 1)?[0];
        if version != 1 {
            return Err(Error::Unsupported {
                what: "split bundle version",
                value: version.to_string(),
            });
        }
        let mut idb = [0u8; 16];
        idb.copy_from_slice(take(&mut p, 16)?);
        let vault_id = VaultId::from_bytes(idb);
        let suite = CryptoSuite::from_u16(u16::from_le_bytes(take(&mut p, 2)?.try_into().unwrap()))?;
        let threshold = take(&mut p, 1)?[0];
        let count = take(&mut p, 1)?[0];
        if threshold < 2 || count > 8 || threshold > count {
            return Err(Error::Format("split bundle has an impossible threshold".into()));
        }

        let mut shares = Vec::with_capacity(count as usize);
        for _ in 0..count {
            let component = match take(&mut p, 1)?[0] {
                1 => ComponentKind::User,
                2 => ComponentKind::Machine,
                3 => ComponentKind::Remote,
                4 => ComponentKind::Custodian,
                other => {
                    return Err(Error::Unsupported {
                        what: "split component",
                        value: other.to_string(),
                    })
                }
            };
            let mut nonce = [0u8; 24];
            nonce.copy_from_slice(take(&mut p, 24)?);
            let len = u16::from_le_bytes(take(&mut p, 2)?.try_into().unwrap()) as usize;
            if len > 4096 {
                return Err(Error::LimitExceeded("split share is implausibly large".into()));
            }
            shares.push(SealedShare { component, nonce, ciphertext: take(&mut p, len)?.to_vec() });
        }
        // Trailing bytes are refused rather than ignored. A parser that
        // accepts them lets the same bundle be presented in more than one
        // encoding, and gives somebody a place to hide data that every other
        // tool will overlook.
        if p != data.len() {
            return Err(Error::Format(format!(
                "split bundle has {} unexpected trailing bytes",
                data.len() - p
            )));
        }

        // A component appearing twice would mean one share silently shadowing
        // another, and which one wins would depend on iteration order.
        let mut seen: Vec<ComponentKind> = shares.iter().map(|s| s.component).collect();
        seen.sort();
        let before = seen.len();
        seen.dedup();
        if seen.len() != before {
            return Err(Error::Format(
                "split bundle names the same component more than once".into(),
            ));
        }

        Ok(SplitBundle { vault_id, suite, threshold, shares })
    }
}

/// Splits `release_key` across the given components.
///
/// Each component supplies a key; the share destined for it is sealed under
/// that key. The release key itself is never stored anywhere.
pub fn seal(
    release_key: &Key256,
    vault_id: VaultId,
    suite: CryptoSuite,
    components: &[(ComponentKind, Key256)],
) -> Result<SplitBundle> {
    if (components.len() as u8) < THRESHOLD {
        return Err(Error::Other(format!(
            "split protection needs at least {THRESHOLD} components; {} were supplied",
            components.len()
        )));
    }
    let mut kinds: Vec<ComponentKind> = components.iter().map(|(k, _)| *k).collect();
    kinds.sort();
    kinds.dedup();
    if kinds.len() != components.len() {
        return Err(Error::Other("a component was enrolled twice".into()));
    }

    // Shamir over the release key. The dealer produces shares in sequence, so
    // one is taken per component and pinned to that component's slot by AAD.
    let sharks = Sharks(THRESHOLD);
    let raw: Vec<Share> = sharks.dealer(release_key.expose()).take(components.len()).collect();

    let mut shares = Vec::with_capacity(components.len());
    for ((component, key), share) in components.iter().zip(raw.iter()) {
        let mut nonce = [0u8; 24];
        crypto::random_bytes(&mut nonce);
        let aad = share_aad(&vault_id, *component, THRESHOLD);
        let body = Vec::from(share);
        let ciphertext = crypto::seal(suite, key, &nonce[..suite.nonce_len()], &body, &aad)?;
        shares.push(SealedShare { component: *component, nonce, ciphertext });
    }

    Ok(SplitBundle { vault_id, suite, threshold: THRESHOLD, shares })
}

/// Reconstructs the release key from whatever components are available.
///
/// Supplying more than the threshold is fine. Supplying fewer fails, and the
/// error names how many were short rather than implying a wrong password.
pub fn unseal(bundle: &SplitBundle, available: &[(ComponentKind, Key256)]) -> Result<Key256> {
    let mut recovered: Vec<Share> = Vec::new();

    for (component, key) in available {
        let Some(sealed) = bundle.shares.iter().find(|s| s.component == *component) else {
            continue;
        };
        let aad = share_aad(&bundle.vault_id, *component, bundle.threshold);
        let nonce = &sealed.nonce[..bundle.suite.nonce_len()];
        // A component key that does not match simply yields no share. It is
        // not distinguished from an absent component, because telling the two
        // apart would let an attacker test component keys one at a time.
        if let Ok(body) = crypto::open(bundle.suite, key, nonce, &sealed.ciphertext, &aad) {
            if let Ok(share) = Share::try_from(body.as_slice()) {
                recovered.push(share);
            }
        }
    }

    if (recovered.len() as u8) < bundle.threshold {
        return Err(Error::Other(format!(
            "{} of {} required key components were available",
            recovered.len(),
            bundle.threshold
        )));
    }

    let sharks = Sharks(bundle.threshold);
    let secret = sharks
        .recover(recovered.as_slice())
        .map_err(|_| Error::AuthenticationFailed)?;
    if secret.len() != 32 {
        return Err(Error::Crypto("reconstructed release key has the wrong length".into()));
    }
    let mut key = Key256::zeroed();
    key.expose_mut().copy_from_slice(&secret);
    Ok(key)
}

/// A description of what a given enrollment actually protects against.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProtectionAssessment {
    pub enrolled: Vec<ComponentKind>,
    pub threshold: u8,
    /// True when a stolen drive plus a guessed password is not enough.
    pub resists_drive_theft: bool,
    /// True when losing any single component still leaves the vault openable.
    pub tolerates_one_loss: bool,
    pub notes: Vec<String>,
}

/// Assesses an enrollment honestly, including the ways it is weak.
pub fn assess(bundle: &SplitBundle) -> ProtectionAssessment {
    let enrolled = bundle.enrolled();
    let mut notes = Vec::new();

    let off_drive = enrolled.iter().filter(|k| !k.travels_with_the_drive()).count();
    let resists_drive_theft = off_drive as u8 >= bundle.threshold;

    if !resists_drive_theft {
        notes.push(
            "Fewer components are held off the drive than the threshold requires, so a \
             stolen drive plus one secret would be enough."
                .into(),
        );
    }
    if !bundle.tolerates_one_loss() {
        notes.push(format!(
            "Only {} components are enrolled with a threshold of {}, so losing either one \
             means the vault can never be opened again. Enroll a third, or keep a second \
             copy of the recovery token on separate media.",
            enrolled.len(),
            bundle.threshold
        ));
    }
    if !enrolled.contains(&ComponentKind::Machine) {
        notes.push(
            "No machine component is enrolled. Without one, nothing binds this vault to \
             this computer, and nothing anchors its security state against rollback."
                .into(),
        );
    }
    if enrolled.contains(&ComponentKind::Remote) {
        notes.push(
            "The recovery token must be kept on separate media. Stored beside the vault it \
             is on the same drive an attacker steals, and provides no protection."
                .into(),
        );
    }

    // The cost of adding a second token rather than a machine component: any
    // two shares open the vault, so two tokens together are full access
    // without the password.
    let token_like = enrolled
        .iter()
        .filter(|k| matches!(k, ComponentKind::Remote | ComponentKind::Custodian))
        .count() as u8;
    if token_like >= bundle.threshold {
        notes.push(
            "Two token components are enrolled, and any two components open this vault, so \
             whoever holds both tokens can open it without the password. Store them in \
             different places, held by different people or in different buildings."
                .into(),
        );
    }

    ProtectionAssessment {
        enrolled,
        threshold: bundle.threshold,
        resists_drive_theft,
        tolerates_one_loss: bundle.tolerates_one_loss(),
        notes,
    }
}
