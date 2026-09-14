//! The AZV1 container format.
//!
//! # Why the header is authenticated
//!
//! The header carries the Argon2id parameters and the KDF salt, and it is read
//! before anything has been verified. If it were unauthenticated, an attacker
//! could hand back a vault with the memory cost lowered to a few kilobytes;
//! the owner would type the right password, derive a weak KEK, and never learn
//! that the vault's resistance to offline guessing had been removed.
//!
//! So the immutable prefix of the header, bytes 0..80, is passed as additional
//! authenticated data when the master key is wrapped. Any change to the magic,
//! version, suites, vault id, KDF parameters or salt makes the unwrap fail.
//!
//! The mutable fields (manifest location, integrity root) sit after that
//! region so they can be rewritten without rewrapping the key. They are
//! protected separately: the manifest is itself authenticated, and it contains
//! the authoritative integrity root, which is compared against the header copy
//! on open.

#![forbid(unsafe_code)]

pub mod manifest;

use zerotrace_compress::CompressSuite;
use zerotrace_core::{Error, Result, VaultId};
use zerotrace_crypto::CryptoSuite;
use zerotrace_auth::{AuthDescriptor, FactorSet};
use zerotrace_kdf::KdfParams;

pub const MAGIC: [u8; 8] = *b"AZV1\0\0\0\0";
pub const HEADER_LEN: usize = 256;
/// A second block, present in every format 3 vault.
///
/// It holds the wrapping for a duress identity: a separate master key, salt
/// and manifest, so one container can open two ways.
///
/// # Why it is always there
///
/// When no duress password is set the block is filled with random bytes. That
/// is deliberate and it is the whole point. If the block only appeared once
/// somebody enabled the feature, an adversary who examined the file would know
/// to demand a second password, and a duress password that is known to exist
/// protects nobody.
///
/// Nothing marks it as used or unused. Random bytes and a real wrapping are
/// indistinguishable without the password that unwraps them, so the file
/// cannot answer the question either way.
pub const DECOY_BLOCK_LEN: usize = 256;

/// Where a format 3 vault begins storing chunks.
pub const V3_DATA_START: u64 = (HEADER_LEN + DECOY_BLOCK_LEN) as u64;

/// The newest container format.
pub const FORMAT_VERSION_CURRENT: u16 = 3;
/// Bytes 0..80 are authenticated in every version.
pub const HEADER_AAD_LEN: usize = 80;
/// Version 2 additionally authenticates the auth descriptor at 200..256.
pub const AUTH_REGION: std::ops::Range<usize> = 200..256;
pub const FORMAT_VERSION: u16 = 3;
/// Versions this build will open.
pub const SUPPORTED_VERSIONS: &[u16] = &[1, 2, 3];
pub const KDF_SUITE_ARGON2ID: u16 = 1;
pub const WRAPPED_KEY_LEN: usize = 48; // 32-byte key plus 16-byte tag
pub const SALT_LEN: usize = 32;

/// Optional behavior recorded in the header.
pub mod flags {
    /// Chunks are padded to a fixed size to blunt size analysis.
    pub const PADDED_CHUNKS: u32 = 1 << 0;

    /// The master key is wrapped under a split release key, not under a
    /// password-derived key.
    ///
    /// This lives in the authenticated region on purpose. Without it an
    /// attacker could delete the split bundle and hope the vault fell back to
    /// password-only opening. It cannot, because the wrapped key would not
    /// unwrap, but the flag turns that into an accurate message instead of a
    /// bare authentication failure.
    pub const SPLIT_PROTECTED: u32 = 1 << 1;
}

#[derive(Debug, Clone)]
pub struct Header {
    pub format_version: u16,
    pub crypto_suite: CryptoSuite,
    pub compress_suite: CompressSuite,
    pub vault_id: VaultId,
    pub kdf_params: KdfParams,
    pub flags: u32,
    pub kdf_salt: [u8; SALT_LEN],
    pub master_key_nonce: [u8; 24],
    pub wrapped_master_key: [u8; WRAPPED_KEY_LEN],
    pub manifest_offset: u64,
    pub manifest_len: u64,
    pub integrity_root: [u8; 32],
    /// Which authentication factors this vault requires. Version 2 and later.
    pub auth: AuthDescriptor,
    /// The header exactly as it was read from disk.
    ///
    /// The AAD must be derived from these bytes rather than from a
    /// re-serialization of the parsed struct. Re-serializing normalizes any
    /// field that is derived or reserved, which would silently exclude those
    /// bytes from authentication: a flipped bit in a derived count would be
    /// rewritten to its expected value before the AAD was computed, and the
    /// modification would go undetected.
    raw: Option<[u8; HEADER_LEN]>,
    /// The duress block, verbatim. `None` for formats before 3.
    decoy: Option<[u8; DECOY_BLOCK_LEN]>,
}

/// The wrapping for a duress identity, parsed out of the decoy block.
///
/// Every field is meaningful only if the block holds a real wrapping. When it
/// holds random bytes these are random too, which is why nothing here is
/// validated at parse time: rejecting an implausible value would reveal that
/// the block was not a real one.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DecoySlot {
    pub key_nonce: [u8; 24],
    pub wrapped_key: [u8; WRAPPED_KEY_LEN],
    pub kdf_salt: [u8; 32],
    pub manifest_offset: u64,
    pub manifest_len: u64,
    /// Where the decoy's chunks and manifest begin, and how long they run.
    ///
    /// Recorded so the region can be picked up and moved. The real manifest is
    /// rewritten at the end of the chunk area every time a file is added, so
    /// anything sitting after it has to relocate or be overwritten.
    pub body_offset: u64,
    pub body_len: u64,
}

impl DecoySlot {
    /// A block of random bytes, which is what a vault without a duress
    /// password carries.
    pub fn random() -> Self {
        let mut key_nonce = [0u8; 24];
        let mut wrapped_key = [0u8; WRAPPED_KEY_LEN];
        let mut kdf_salt = [0u8; 32];
        zerotrace_crypto::random_bytes(&mut key_nonce);
        zerotrace_crypto::random_bytes(&mut wrapped_key);
        zerotrace_crypto::random_bytes(&mut kdf_salt);
        let mut off = [0u8; 8];
        let mut len = [0u8; 8];
        zerotrace_crypto::random_bytes(&mut off);
        zerotrace_crypto::random_bytes(&mut len);
        let mut boff = [0u8; 8];
        let mut blen = [0u8; 8];
        zerotrace_crypto::random_bytes(&mut boff);
        zerotrace_crypto::random_bytes(&mut blen);
        DecoySlot {
            key_nonce,
            wrapped_key,
            kdf_salt,
            manifest_offset: u64::from_le_bytes(off),
            manifest_len: u64::from_le_bytes(len),
            body_offset: u64::from_le_bytes(boff),
            body_len: u64::from_le_bytes(blen),
        }
    }

    pub fn encode(&self) -> [u8; DECOY_BLOCK_LEN] {
        let mut b = [0u8; DECOY_BLOCK_LEN];
        b[0..24].copy_from_slice(&self.key_nonce);
        b[24..72].copy_from_slice(&self.wrapped_key);
        b[72..104].copy_from_slice(&self.kdf_salt);
        b[104..112].copy_from_slice(&self.manifest_offset.to_le_bytes());
        b[112..120].copy_from_slice(&self.manifest_len.to_le_bytes());
        b[120..128].copy_from_slice(&self.body_offset.to_le_bytes());
        b[128..136].copy_from_slice(&self.body_len.to_le_bytes());
        // The remainder is random so the block never contains a run of zeroes,
        // which would itself distinguish an unused slot from a used one.
        zerotrace_crypto::random_bytes(&mut b[136..]);
        b
    }

    pub fn decode(b: &[u8]) -> Self {
        let mut key_nonce = [0u8; 24];
        let mut wrapped_key = [0u8; WRAPPED_KEY_LEN];
        let mut kdf_salt = [0u8; 32];
        key_nonce.copy_from_slice(&b[0..24]);
        wrapped_key.copy_from_slice(&b[24..72]);
        kdf_salt.copy_from_slice(&b[72..104]);
        DecoySlot {
            key_nonce,
            wrapped_key,
            kdf_salt,
            manifest_offset: u64::from_le_bytes(b[104..112].try_into().unwrap()),
            manifest_len: u64::from_le_bytes(b[112..120].try_into().unwrap()),
            body_offset: u64::from_le_bytes(b[120..128].try_into().unwrap()),
            body_len: u64::from_le_bytes(b[128..136].try_into().unwrap()),
        }
    }
}

impl Header {
    /// Builds a header for a new vault.
    ///
    /// The authenticated byte image is not set until [`Header::freeze`], so a
    /// half-built header cannot accidentally be used to wrap a key.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        crypto_suite: CryptoSuite,
        compress_suite: CompressSuite,
        vault_id: VaultId,
        kdf_params: KdfParams,
        kdf_salt: [u8; SALT_LEN],
        master_key_nonce: [u8; 24],
        auth: AuthDescriptor,
    ) -> Self {
        Header {
            format_version: FORMAT_VERSION,
            crypto_suite,
            compress_suite,
            vault_id,
            kdf_params,
            flags: 0,
            kdf_salt,
            master_key_nonce,
            wrapped_master_key: [0u8; WRAPPED_KEY_LEN],
            manifest_offset: V3_DATA_START,
            manifest_len: 0,
            integrity_root: [0u8; 32],
            auth,
            raw: None,
            // Random from the moment a vault is created, so a vault that never
            // gains a duress password is indistinguishable from one that has.
            decoy: Some(DecoySlot::random().encode()),
        }
    }
}

impl Header {
    /// The exact bytes authenticated when wrapping the master key.
    ///
    /// Version 2 extends the authenticated data to cover the authentication
    /// descriptor, so an attacker cannot strip a FIDO2 requirement and hand
    /// back a vault that opens with the password alone.
    ///
    /// A version 1 vault keeps the original, shorter AAD, so vaults written by
    /// v0.1 still open.
    pub fn aad(&self) -> Vec<u8> {
        let full = self.raw.unwrap_or_else(|| self.to_bytes());
        let mut aad = full[..HEADER_AAD_LEN].to_vec();
        if self.format_version >= 2 {
            aad.extend_from_slice(&full[AUTH_REGION]);
        }
        aad
    }

    pub fn to_bytes(&self) -> [u8; HEADER_LEN] {
        let mut b = [0u8; HEADER_LEN];
        b[0..8].copy_from_slice(&MAGIC);
        b[8..10].copy_from_slice(&self.format_version.to_le_bytes());
        b[10..12].copy_from_slice(&(self.crypto_suite as u16).to_le_bytes());
        b[12..14].copy_from_slice(&KDF_SUITE_ARGON2ID.to_le_bytes());
        b[14..16].copy_from_slice(&(self.compress_suite as u16).to_le_bytes());
        b[16..32].copy_from_slice(self.vault_id.as_bytes());
        b[32..36].copy_from_slice(&self.kdf_params.memory_kib.to_le_bytes());
        b[36..40].copy_from_slice(&self.kdf_params.time_cost.to_le_bytes());
        b[40..44].copy_from_slice(&self.kdf_params.parallelism.to_le_bytes());
        b[44..48].copy_from_slice(&self.flags.to_le_bytes());
        b[48..80].copy_from_slice(&self.kdf_salt);
        // Everything past here is outside the authenticated prefix.
        b[80..104].copy_from_slice(&self.master_key_nonce);
        b[104..152].copy_from_slice(&self.wrapped_master_key);
        b[152..160].copy_from_slice(&self.manifest_offset.to_le_bytes());
        b[160..168].copy_from_slice(&self.manifest_len.to_le_bytes());
        b[168..200].copy_from_slice(&self.integrity_root);
        if self.format_version >= 2 {
            b[200..202].copy_from_slice(&self.auth.required.0.to_le_bytes());
            b[202..204].copy_from_slice(&(self.auth.required.count() as u16).to_le_bytes());
            b[204..236].copy_from_slice(&self.auth.prf_salt);
            b[236..256].copy_from_slice(&self.auth.credential_hint);
        }
        b
    }

    /// The duress wrapping, if this format carries one.
    ///
    /// Always `Some` for format 3, whether or not a duress password has been
    /// set, because the block is always present.
    pub fn decoy_slot(&self) -> Option<DecoySlot> {
        self.decoy.as_ref().map(|b| DecoySlot::decode(b))
    }

    pub fn set_decoy_slot(&mut self, slot: &DecoySlot) {
        self.decoy = Some(slot.encode());
    }

    /// The decoy block as stored, for writing back out.
    pub fn decoy_bytes(&self) -> Option<[u8; DECOY_BLOCK_LEN]> {
        self.decoy
    }

    /// Where chunk data begins, which depends on the format.
    pub fn data_start(&self) -> u64 {
        if self.format_version >= 3 {
            V3_DATA_START
        } else {
            HEADER_LEN as u64
        }
    }

    /// Parses a header, validating every field that will later be trusted.
    ///
    /// Nothing here proves the header is authentic; that only happens when the
    /// master key unwraps successfully. This stage exists to reject values
    /// that would be dangerous to act on even briefly.
    pub fn from_bytes(b: &[u8]) -> Result<Self> {
        if b.len() < HEADER_LEN {
            return Err(Error::Format("file is too short to be an AZV vault".into()));
        }
        if b[0..8] != MAGIC {
            return Err(Error::Format(
                "not an Apex ZeroTrace vault (magic number does not match)".into(),
            ));
        }
        let format_version = u16::from_le_bytes([b[8], b[9]]);
        if !SUPPORTED_VERSIONS.contains(&format_version) {
            // Never guess at an unknown version.
            return Err(Error::Unsupported {
                what: "AZV format version",
                value: format_version.to_string(),
            });
        }
        let crypto_suite = CryptoSuite::from_u16(u16::from_le_bytes([b[10], b[11]]))?;
        let kdf_suite = u16::from_le_bytes([b[12], b[13]]);
        if kdf_suite != KDF_SUITE_ARGON2ID {
            return Err(Error::Unsupported { what: "KDF suite", value: kdf_suite.to_string() });
        }
        let compress_suite = CompressSuite::from_u16(u16::from_le_bytes([b[14], b[15]]))?;

        let mut idb = [0u8; 16];
        idb.copy_from_slice(&b[16..32]);
        let vault_id = VaultId::from_bytes(idb);

        let kdf_params = KdfParams {
            memory_kib: u32::from_le_bytes(b[32..36].try_into().unwrap()),
            time_cost: u32::from_le_bytes(b[36..40].try_into().unwrap()),
            parallelism: u32::from_le_bytes(b[40..44].try_into().unwrap()),
        };
        // Refuse a downgraded KDF before spending any time on it.
        kdf_params.validate()?;

        let flags = u32::from_le_bytes(b[44..48].try_into().unwrap());
        let mut kdf_salt = [0u8; SALT_LEN];
        kdf_salt.copy_from_slice(&b[48..80]);
        let mut master_key_nonce = [0u8; 24];
        master_key_nonce.copy_from_slice(&b[80..104]);
        let mut wrapped_master_key = [0u8; WRAPPED_KEY_LEN];
        wrapped_master_key.copy_from_slice(&b[104..152]);

        let manifest_offset = u64::from_le_bytes(b[152..160].try_into().unwrap());
        let manifest_len = u64::from_le_bytes(b[160..168].try_into().unwrap());
        if manifest_len > zerotrace_core::limits::MAX_MANIFEST_BYTES {
            return Err(Error::LimitExceeded(format!(
                "manifest declares {manifest_len} bytes, above the limit"
            )));
        }
        let min_offset = if format_version >= 3 { V3_DATA_START } else { HEADER_LEN as u64 };
        if manifest_offset < min_offset {
            return Err(Error::Format("manifest offset overlaps the header".into()));
        }
        let mut integrity_root = [0u8; 32];
        integrity_root.copy_from_slice(&b[168..200]);

        let auth = if format_version >= 2 {
            let required = FactorSet(u16::from_le_bytes([b[200], b[201]]));
            required.validate()?;
            let mut prf_salt = [0u8; 32];
            prf_salt.copy_from_slice(&b[204..236]);
            let mut credential_hint = [0u8; 20];
            credential_hint.copy_from_slice(&b[236..256]);
            AuthDescriptor { required, prf_salt, credential_hint }
        } else {
            // A version 1 vault predates factors; it is password only.
            AuthDescriptor::default()
        };

        Ok(Header {
            format_version,
            crypto_suite,
            compress_suite,
            vault_id,
            kdf_params,
            flags,
            kdf_salt,
            master_key_nonce,
            wrapped_master_key,
            manifest_offset,
            manifest_len,
            integrity_root,
            auth,
            raw: Some(b[..HEADER_LEN].try_into().unwrap()),
            decoy: if format_version >= 3 && b.len() >= HEADER_LEN + DECOY_BLOCK_LEN {
                Some(b[HEADER_LEN..HEADER_LEN + DECOY_BLOCK_LEN].try_into().unwrap())
            } else {
                None
            },
        })
    }

    /// Fixes the byte image used for the AAD.
    ///
    /// Called once at creation, after every authenticated field is final and
    /// before the master key is wrapped.
    pub fn freeze(&mut self) {
        self.raw = Some(self.to_bytes());
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use zerotrace_crypto as crypto;

    fn sample() -> Header {
        Header {
            format_version: FORMAT_VERSION,
            crypto_suite: CryptoSuite::XChaCha20Poly1305,
            compress_suite: CompressSuite::Zstd,
            vault_id: VaultId::from_bytes([9u8; 16]),
            kdf_params: KdfParams::INTERACTIVE,
            flags: 0,
            kdf_salt: [3u8; SALT_LEN],
            master_key_nonce: [4u8; 24],
            wrapped_master_key: [5u8; WRAPPED_KEY_LEN],
            manifest_offset: 4096,
            manifest_len: 128,
            integrity_root: [6u8; 32],
            auth: AuthDescriptor::default(),
            raw: None,
            decoy: Some(DecoySlot::random().encode()),
        }
    }

    #[test]
    fn header_round_trips() {
        let h = sample();
        let parsed = Header::from_bytes(&h.to_bytes()).unwrap();
        assert_eq!(parsed.vault_id, h.vault_id);
        assert_eq!(parsed.kdf_params, h.kdf_params);
        assert_eq!(parsed.kdf_salt, h.kdf_salt);
        assert_eq!(parsed.manifest_offset, h.manifest_offset);
    }

    #[test]
    fn a_downgraded_kdf_is_refused_at_parse_time() {
        let mut h = sample();
        h.kdf_params = KdfParams { memory_kib: 8, time_cost: 1, parallelism: 1 };
        assert!(Header::from_bytes(&h.to_bytes()).is_err());
    }

    #[test]
    fn unknown_versions_and_suites_are_never_guessed() {
        let mut b = sample().to_bytes();
        b[8..10].copy_from_slice(&99u16.to_le_bytes());
        assert!(Header::from_bytes(&b).is_err());

        let mut b = sample().to_bytes();
        b[10..12].copy_from_slice(&77u16.to_le_bytes());
        assert!(Header::from_bytes(&b).is_err());
    }

    #[test]
    fn junk_is_rejected() {
        assert!(Header::from_bytes(&[]).is_err());
        assert!(Header::from_bytes(&[0u8; HEADER_LEN]).is_err());
        assert!(Header::from_bytes(b"not a vault").is_err());
    }

    #[test]
    fn stripping_the_fido_requirement_breaks_the_wrap() {
        use zerotrace_auth::FactorKind;
        let mut h = sample();
        h.auth.required = FactorSet::password_only().with(FactorKind::Fido2Prf);
        h.auth.prf_salt = [11u8; 32];

        let kek = crypto::random_key();
        let master = crypto::random_key();
        let wrapped =
            crypto::seal(h.crypto_suite, &kek, &h.master_key_nonce, master.expose(), &h.aad())
                .unwrap();

        // Downgrade the vault to password-only and the wrap no longer opens.
        let mut stripped = h.clone();
        stripped.auth.required = FactorSet::password_only();
        assert!(crypto::open(
            h.crypto_suite,
            &kek,
            &h.master_key_nonce,
            &wrapped,
            &stripped.aad()
        )
        .is_err());

        // Changing the PRF salt is equally refused.
        let mut moved = h.clone();
        moved.auth.prf_salt[0] ^= 1;
        assert!(
            crypto::open(h.crypto_suite, &kek, &h.master_key_nonce, &wrapped, &moved.aad())
                .is_err()
        );
    }

    #[test]
    fn version_one_vaults_still_parse() {
        let mut h = sample();
        h.format_version = 1;
        let parsed = Header::from_bytes(&h.to_bytes()).unwrap();
        assert_eq!(parsed.format_version, 1);
        assert_eq!(parsed.auth, AuthDescriptor::default());
        // And its AAD is the original shorter one.
        assert_eq!(parsed.aad().len(), HEADER_AAD_LEN);
    }

    #[test]
    fn tampering_with_kdf_parameters_breaks_the_wrap() {
        // The property the AAD design exists to provide.
        let h = sample();
        let kek = crypto::random_key();
        let master = crypto::random_key();
        let wrapped = crypto::seal(
            h.crypto_suite,
            &kek,
            &h.master_key_nonce,
            master.expose(),
            &h.aad(),
        )
        .unwrap();

        // Unwrapping against the honest header works.
        assert!(crypto::open(h.crypto_suite, &kek, &h.master_key_nonce, &wrapped, &h.aad()).is_ok());

        // Raise the salt by one bit and the same wrap no longer opens.
        let mut tampered = h.clone();
        tampered.kdf_salt[0] ^= 1;
        assert!(crypto::open(
            h.crypto_suite,
            &kek,
            &h.master_key_nonce,
            &wrapped,
            &tampered.aad()
        )
        .is_err());

        // Mutable fields are outside the AAD, so rewriting them is fine.
        let mut moved = h.clone();
        moved.manifest_offset = 999_999;
        moved.integrity_root = [1u8; 32];
        assert!(crypto::open(h.crypto_suite, &kek, &h.master_key_nonce, &wrapped, &moved.aad())
            .is_ok());
    }
}
