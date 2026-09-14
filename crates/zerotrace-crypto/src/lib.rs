//! Authenticated encryption, subkey derivation and randomness.
//!
//! No primitive is implemented here. This crate only selects between audited
//! implementations and enforces how they are used: which key derives which
//! subkey, and how nonces are formed.

#![forbid(unsafe_code)]

use aes_gcm::Aes256Gcm;
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::XChaCha20Poly1305;
use hkdf::Hkdf;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use zerotrace_core::{Error, Result};
use zerotrace_secure_memory::Key256;

pub const TAG_LEN: usize = 16;
pub const XNONCE_LEN: usize = 24;
pub const GCM_NONCE_LEN: usize = 12;

/// Which AEAD a vault uses. Recorded in the header; never guessed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u16)]
pub enum CryptoSuite {
    /// Default. The 192-bit nonce removes any practical nonce-collision risk.
    XChaCha20Poly1305 = 1,
    /// For deployments whose compliance regime requires it.
    Aes256Gcm = 2,
}

impl CryptoSuite {
    pub fn from_u16(v: u16) -> Result<Self> {
        match v {
            1 => Ok(CryptoSuite::XChaCha20Poly1305),
            2 => Ok(CryptoSuite::Aes256Gcm),
            other => Err(Error::Unsupported { what: "crypto suite", value: other.to_string() }),
        }
    }

    pub fn nonce_len(&self) -> usize {
        match self {
            CryptoSuite::XChaCha20Poly1305 => XNONCE_LEN,
            CryptoSuite::Aes256Gcm => GCM_NONCE_LEN,
        }
    }

    pub fn label(&self) -> &'static str {
        match self {
            CryptoSuite::XChaCha20Poly1305 => "XChaCha20-Poly1305",
            CryptoSuite::Aes256Gcm => "AES-256-GCM",
        }
    }
}

/// Fills `buf` from the OS CSPRNG.
pub fn random_bytes(buf: &mut [u8]) {
    rand::thread_rng().fill_bytes(buf);
}

pub fn random_key() -> Key256 {
    let mut k = Key256::zeroed();
    random_bytes(k.expose_mut());
    k
}

/// Builds a nonce for chunk `index`.
///
/// Counter-based rather than random, deliberately. Every chunk is encrypted
/// under a key unique to its file, so a counter within that file cannot
/// collide, which makes INV-4 a structural property rather than a probabilistic
/// one.
pub fn chunk_nonce(suite: CryptoSuite, index: u64) -> Vec<u8> {
    let mut n = vec![0u8; suite.nonce_len()];
    let len = n.len();
    n[len - 8..].copy_from_slice(&index.to_le_bytes());
    n
}

/// Encrypts with the given key, nonce and additional authenticated data.
pub fn seal(
    suite: CryptoSuite,
    key: &Key256,
    nonce: &[u8],
    plaintext: &[u8],
    aad: &[u8],
) -> Result<Vec<u8>> {
    if nonce.len() != suite.nonce_len() {
        return Err(Error::Crypto("nonce length does not match the suite".into()));
    }
    match suite {
        CryptoSuite::XChaCha20Poly1305 => {
            let c = XChaCha20Poly1305::new(key.expose().as_ref().into());
            c.encrypt(nonce.into(), Payload { msg: plaintext, aad })
                .map_err(|_| Error::Crypto("encryption failed".into()))
        }
        CryptoSuite::Aes256Gcm => {
            let c = Aes256Gcm::new(key.expose().as_ref().into());
            c.encrypt(nonce.into(), Payload { msg: plaintext, aad })
                .map_err(|_| Error::Crypto("encryption failed".into()))
        }
    }
}

/// Decrypts and verifies.
///
/// Any failure, whether a wrong key, a modified ciphertext or altered AAD,
/// surfaces as [`Error::AuthenticationFailed`] and nothing more specific
/// (INV-5).
pub fn open(
    suite: CryptoSuite,
    key: &Key256,
    nonce: &[u8],
    ciphertext: &[u8],
    aad: &[u8],
) -> Result<Vec<u8>> {
    if nonce.len() != suite.nonce_len() {
        return Err(Error::Crypto("nonce length does not match the suite".into()));
    }
    let out = match suite {
        CryptoSuite::XChaCha20Poly1305 => {
            let c = XChaCha20Poly1305::new(key.expose().as_ref().into());
            c.decrypt(nonce.into(), Payload { msg: ciphertext, aad })
        }
        CryptoSuite::Aes256Gcm => {
            let c = Aes256Gcm::new(key.expose().as_ref().into());
            c.decrypt(nonce.into(), Payload { msg: ciphertext, aad })
        }
    };
    out.map_err(|_| Error::AuthenticationFailed)
}

/// Labels for subkeys derived from the vault master key.
///
/// Distinct labels keep the uses cryptographically separated, so a weakness in
/// one does not carry into another.
pub mod info {
    pub const METADATA: &[u8] = b"apex-zerotrace:v1:metadata-key";
    pub const FILE: &[u8] = b"apex-zerotrace:v1:file-key";
    pub const INTEGRITY: &[u8] = b"apex-zerotrace:v1:integrity-key";
}

/// Derives a subkey from the master key with HKDF-SHA256.
pub fn derive_subkey(master: &Key256, salt: &[u8], info: &[u8]) -> Result<Key256> {
    let h = Hkdf::<Sha256>::new(if salt.is_empty() { None } else { Some(salt) }, master.expose());
    let mut out = Key256::zeroed();
    h.expand(info, out.expose_mut())
        .map_err(|_| Error::Crypto("subkey derivation failed".into()))?;
    Ok(out)
}

/// Per-file key, bound to that file's random object id.
pub fn derive_file_key(master: &Key256, object_id: &[u8; 16]) -> Result<Key256> {
    derive_subkey(master, object_id, info::FILE)
}

pub fn sha256(data: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(data);
    h.finalize().into()
}

/// Merkle root over chunk hashes, used as the vault's integrity root.
///
/// Interior nodes are domain-separated from leaves so a leaf cannot be passed
/// off as a subtree.
pub fn merkle_root(leaves: &[[u8; 32]]) -> [u8; 32] {
    if leaves.is_empty() {
        return sha256(b"apex-zerotrace:v1:empty-tree");
    }
    let mut level: Vec<[u8; 32]> = leaves.to_vec();
    while level.len() > 1 {
        let mut next = Vec::with_capacity((level.len() + 1) / 2);
        for pair in level.chunks(2) {
            let mut h = Sha256::new();
            h.update(b"apex-zerotrace:v1:node");
            h.update(pair[0]);
            // An odd node is paired with itself, which is safe here because
            // the leaf count is itself authenticated inside the manifest.
            h.update(if pair.len() > 1 { pair[1] } else { pair[0] });
            next.push(h.finalize().into());
        }
        level = next;
    }
    level[0]
}

#[cfg(test)]
mod tests {
    use super::*;

    fn suites() -> [CryptoSuite; 2] {
        [CryptoSuite::XChaCha20Poly1305, CryptoSuite::Aes256Gcm]
    }

    #[test]
    fn round_trip_under_both_suites() {
        for s in suites() {
            let k = random_key();
            let n = chunk_nonce(s, 0);
            let ct = seal(s, &k, &n, b"plaintext", b"aad").unwrap();
            assert_eq!(open(s, &k, &n, &ct, b"aad").unwrap(), b"plaintext");
        }
    }

    #[test]
    fn tampering_is_always_refused() {
        // INV-5: no corrupted record is ever accepted.
        for s in suites() {
            let k = random_key();
            let n = chunk_nonce(s, 1);
            let ct = seal(s, &k, &n, b"plaintext", b"aad").unwrap();

            for i in 0..ct.len() {
                let mut bad = ct.clone();
                bad[i] ^= 1;
                assert!(open(s, &k, &n, &bad, b"aad").is_err(), "byte {i} accepted");
            }
            assert!(open(s, &k, &n, &ct, b"different aad").is_err(), "AAD not bound");
            assert!(open(s, &k, &chunk_nonce(s, 2), &ct, b"aad").is_err(), "nonce not bound");
            assert!(open(s, &random_key(), &n, &ct, b"aad").is_err(), "key not bound");
        }
    }

    #[test]
    fn chunk_nonces_never_repeat_within_a_file() {
        // INV-4, by construction.
        for s in suites() {
            let mut seen = std::collections::HashSet::new();
            for i in 0..10_000u64 {
                assert!(seen.insert(chunk_nonce(s, i)), "nonce reused at index {i}");
            }
        }
    }

    #[test]
    fn subkeys_are_separated_by_label_and_object_id() {
        let m = random_key();
        let a = derive_subkey(&m, b"", info::METADATA).unwrap();
        let b = derive_subkey(&m, b"", info::INTEGRITY).unwrap();
        assert_ne!(a, b, "labels must separate subkeys");

        let f1 = derive_file_key(&m, &[1u8; 16]).unwrap();
        let f2 = derive_file_key(&m, &[2u8; 16]).unwrap();
        assert_ne!(f1, f2, "each file must get its own key");
        assert_ne!(f1, a);
    }

    #[test]
    fn merkle_root_detects_any_change() {
        let leaves: Vec<[u8; 32]> = (0..7u8).map(|i| sha256(&[i])).collect();
        let root = merkle_root(&leaves);
        for i in 0..leaves.len() {
            let mut altered = leaves.clone();
            altered[i][0] ^= 1;
            assert_ne!(merkle_root(&altered), root, "change at leaf {i} not detected");
        }
        let mut reordered = leaves.clone();
        reordered.swap(0, 1);
        assert_ne!(merkle_root(&reordered), root, "reordering not detected");
        assert_ne!(merkle_root(&leaves[..6]), root, "truncation not detected");
    }
}
