//! A custodian that holds one key component somewhere the attacker is not.
//!
//! # The problem this solves
//!
//! Everything else in this project runs on the machine holding the vault.
//! Somebody who controls that machine can close the watcher, and no amount of
//! hiding or restarting changes that: on their computer, they win.
//!
//! A custodian is different because it is not on their computer. It holds one
//! share of the vault's release key and will hand it back only while the vault
//! is still checking in. Once the deadline passes it destroys the share and
//! there is nothing left to hand back, ever.
//!
//! The deadline is therefore enforced by *withholding* rather than by
//! destroying anything locally. Whatever the attacker kills on the machine is
//! beside the point.
//!
//! # Why check-ins are signed with a password-derived key
//!
//! This is the decision the whole design rests on.
//!
//! If the credential that proves "the owner is still here" lived on the
//! machine, an attacker holding the machine would simply keep checking in, and
//! the deadline would never arrive. So the signing key is derived from the
//! password through the same Argon2id the vault uses, and exists only for as
//! long as it takes to sign one request.
//!
//! An attacker who has not cracked the password cannot check in. One who
//! cracks it after the deadline has passed gains nothing, because the share
//! they would need is already gone.
//!
//! # What a custodian can and cannot do
//!
//! It holds one share of a threshold scheme. Alone it can open nothing. With a
//! compromised password it could, which is the documented cost of two-of-three
//! and the reason a custodian should not be run by whoever knows your password.
//!
//! It also cannot be made to keep a secret it has already destroyed, which is
//! the point.

#![forbid(unsafe_code)]

pub mod custodian;

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use zerotrace_core::{Error, Result, VaultId};
use zerotrace_crypto as crypto;
use zerotrace_kdf::{derive_kek, KdfParams};

pub use custodian::{Custodian, DirectoryCustodian, HeldShare};

/// Derives the key that signs check-ins, from the password.
///
/// Deliberately not stored. It is produced when a request is signed and
/// dropped immediately afterwards, so a machine at rest holds nothing that
/// could be used to check in on the owner's behalf.
pub fn signing_identity(password: &[u8], salt: &[u8], params: KdfParams) -> Result<SigningKey> {
    let derived = derive_kek(password, salt, params)?;
    let seed = crypto::derive_subkey(&derived, salt, b"apex-zerotrace:remote:checkin-key")?;
    Ok(SigningKey::from_bytes(seed.expose()))
}

/// The public half, which the custodian stores at enrollment.
pub fn verifying_key(password: &[u8], salt: &[u8], params: KdfParams) -> Result<[u8; 32]> {
    Ok(signing_identity(password, salt, params)?.verifying_key().to_bytes())
}

/// What a client is asking a custodian to do.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Intent {
    /// Confirm the owner is still present, resetting the deadline.
    CheckIn,
    /// Hand back the held share so the vault can be opened.
    Release,
}

impl Intent {
    fn label(&self) -> &'static str {
        match self {
            Intent::CheckIn => "CHECK_IN",
            Intent::Release => "RELEASE",
        }
    }
}

/// A signed request from a vault's owner.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Request {
    pub vault_id: VaultId,
    pub intent: Intent,
    /// Unique per request, so a captured one cannot be replayed.
    pub nonce: [u8; 16],
    pub issued_at: i64,
    pub signature: Vec<u8>,
}

impl Request {
    fn payload(
        vault_id: &VaultId,
        intent: Intent,
        nonce: &[u8; 16],
        issued_at: i64,
    ) -> Vec<u8> {
        let mut b = Vec::with_capacity(80);
        b.extend_from_slice(b"apex-zerotrace:custodian-request:v1");
        b.extend_from_slice(vault_id.as_bytes());
        let label = intent.label().as_bytes();
        b.extend_from_slice(&(label.len() as u32).to_le_bytes());
        b.extend_from_slice(label);
        b.extend_from_slice(nonce);
        b.extend_from_slice(&issued_at.to_le_bytes());
        b
    }

    /// Signs a request with a key derived from the password.
    pub fn sign(key: &SigningKey, vault_id: VaultId, intent: Intent, issued_at: i64) -> Self {
        let mut nonce = [0u8; 16];
        crypto::random_bytes(&mut nonce);
        let payload = Self::payload(&vault_id, intent, &nonce, issued_at);
        let signature: Signature = key.sign(&payload);
        Request { vault_id, intent, nonce, issued_at, signature: signature.to_bytes().to_vec() }
    }

    fn verify(&self, public: &[u8; 32]) -> Result<()> {
        let vk = VerifyingKey::from_bytes(public)
            .map_err(|_| Error::Crypto("stored public key is malformed".into()))?;
        let sig: [u8; 64] = self
            .signature
            .as_slice()
            .try_into()
            .map_err(|_| Error::Crypto("signature has the wrong length".into()))?;
        vk.verify(
            &Self::payload(&self.vault_id, self.intent, &self.nonce, self.issued_at),
            &Signature::from_bytes(&sig),
        )
        .map_err(|_| Error::AuthenticationFailed)
    }
}

/// How a custodian answered.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Verdict {
    /// A check-in was accepted; the deadline moved.
    CheckedIn { deadline: i64 },
    /// The share is returned.
    Released(Vec<u8>),
    /// The deadline passed. The share has been destroyed and will never be
    /// returned, by this or any later request.
    Expired { expired_at: i64 },
    /// The custodian holds nothing for this vault.
    Unknown,
    /// The request did not verify, was replayed, or was stale.
    Refused(&'static str),
}

impl Verdict {
    pub fn label(&self) -> &'static str {
        match self {
            Verdict::CheckedIn { .. } => "CHECKED IN",
            Verdict::Released(_) => "RELEASED",
            Verdict::Expired { .. } => "EXPIRED, SHARE DESTROYED",
            Verdict::Unknown => "UNKNOWN VAULT",
            Verdict::Refused(_) => "REFUSED",
        }
    }
}

/// How long a signed request stays valid, in seconds.
///
/// Short, because a request is signed and sent immediately. A long window
/// would let one captured in transit be used later.
pub const REQUEST_VALIDITY: i64 = 300;
