//! Vault lifecycle: create, open, verify, import, export, close.
//!
//! # Layout
//!
//! ```text
//! [0..256)                 header (see zerotrace-format)
//! [256..manifest_offset)   authenticated chunks, back to back
//! [manifest_offset..)      manifest nonce, then the encrypted manifest
//! ```
//!
//! # Key hierarchy
//!
//! ```text
//! password --Argon2id--> KEK --unwraps--> master key
//!                                          |
//!                        +-----------------+------------------+
//!                        |                 |                  |
//!                   metadata key      per-file keys      integrity key
//!                   (HKDF, fixed)     (HKDF, salted by    (HKDF, fixed)
//!                                      random object id)
//! ```
//!
//! The password never encrypts anything directly (INV-3), and because it only
//! wraps the master key, changing it rewraps 48 bytes instead of re-encrypting
//! the vault.

#![forbid(unsafe_code)]

use std::fs::{File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Component, Path, PathBuf};

use zerotrace_compress::{self as compress, CompressSuite};
use zerotrace_core::{limits, Assurance, Error, Result, VaultId};
use zerotrace_crypto::{self as crypto, CryptoSuite};
use zerotrace_format::manifest::{ChunkRef, Entry, Manifest};
use zerotrace_format::{DecoySlot, Header, DECOY_BLOCK_LEN, HEADER_LEN};
use zerotrace_auth::{compose_kek, AuthDescriptor, Authenticator, FactorKind, FactorSet};
use zerotrace_kdf::{derive_kek, KdfParams};
use zerotrace_split::{seal as seal_split, unseal as unseal_split, ComponentKind, SplitBundle};
use zerotrace_secure_memory::Key256;

/// Plaintext bytes per chunk. Bounds memory and localises corruption.
pub const CHUNK_SIZE: usize = 1024 * 1024;

/// zstd level used for chunk compression. Modest on purpose: the vault's job
/// is confidentiality, and a slow compressor lengthens the window in which
/// plaintext is resident.
pub const COMPRESSION_LEVEL: i32 = 3;

/// Where a vault's split bundle lives.
pub fn split_bundle_path(vault: &Path) -> PathBuf {
    PathBuf::from(format!("{}.split", vault.display()))
}

/// Settings chosen when a vault is created.
#[derive(Debug, Clone)]
pub struct VaultOptions {
    pub crypto_suite: CryptoSuite,
    pub compress_suite: CompressSuite,
    pub kdf_params: KdfParams,
    pub compression_level: i32,
    /// Which authentication factors the vault will require.
    pub factors: FactorSet,
}

impl Default for VaultOptions {
    fn default() -> Self {
        Self {
            crypto_suite: CryptoSuite::XChaCha20Poly1305,
            compress_suite: CompressSuite::Zstd,
            kdf_params: KdfParams::INTERACTIVE,
            compression_level: 3,
            factors: FactorSet::password_only(),
        }
    }
}

/// An open vault. Dropping it destroys the in-memory keys.
/// Which set of contents a vault was opened into.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Identity {
    /// The real contents.
    Real,
    /// The duress contents. Reaching this means the real key has been
    /// destroyed.
    Decoy,
}

pub struct Vault {
    path: PathBuf,
    header: Header,
    manifest: Manifest,
    /// Present only while unlocked.
    master: Option<Key256>,
    /// First byte after the last chunk, and where the manifest begins.
    data_end: u64,
    /// Which contents this handle was opened into.
    identity: Identity,
}

/// Outcome of `verify`, reported per-check rather than as one boolean.
#[derive(Debug, Clone)]
pub struct VerifyReport {
    pub vault_id: VaultId,
    pub header_authentic: Assurance,
    pub manifest_authentic: Assurance,
    pub chunks_checked: usize,
    pub chunks_failed: usize,
    pub integrity_root_matches: Assurance,
    pub entries: usize,
    pub plaintext_bytes: u64,
    pub ciphertext_bytes: u64,
}

impl VerifyReport {
    pub fn is_intact(&self) -> bool {
        self.header_authentic == Assurance::Verified
            && self.manifest_authentic == Assurance::Verified
            && self.integrity_root_matches == Assurance::Verified
            && self.chunks_failed == 0
    }
}

/// Binds a manifest to its vault, its length, and which write it is.
///
/// The generation is what stops an older manifest being put back. Without it a
/// manifest proved only that it was genuine for this vault, so an earlier copy
/// spliced in would open onto the older list of files with every check
/// passing.
fn manifest_aad(vault_id: &VaultId, len: u64, generation: u64) -> Vec<u8> {
    let mut aad = Vec::with_capacity(32);
    aad.extend_from_slice(b"apex-zerotrace:manifest:v2");
    aad.extend_from_slice(vault_id.as_bytes());
    aad.extend_from_slice(&len.to_le_bytes());
    aad.extend_from_slice(&generation.to_le_bytes());
    aad
}

fn chunk_aad(object_id: &[u8; 16], index: u64, plaintext_len: u32, suite: CompressSuite) -> Vec<u8> {
    // Binding the index stops chunks being reordered, and binding the object
    // id stops a chunk being moved between files.
    let mut aad = Vec::with_capacity(30);
    aad.extend_from_slice(object_id);
    aad.extend_from_slice(&index.to_le_bytes());
    aad.extend_from_slice(&plaintext_len.to_le_bytes());
    aad.extend_from_slice(&(suite as u16).to_le_bytes());
    aad
}

/// Rejects absolute paths, drive prefixes and `..`, so a hostile manifest
/// cannot write outside the export directory.
pub fn sanitize_relative_path(p: &str) -> Result<PathBuf> {
    let raw = PathBuf::from(p.replace('\\', "/"));
    let mut out = PathBuf::new();
    let mut depth = 0usize;
    for c in raw.components() {
        match c {
            Component::Normal(s) => {
                out.push(s);
                depth += 1;
            }
            Component::CurDir => {}
            _ => return Err(Error::Format(format!("unsafe path in vault: {p}"))),
        }
    }
    if out.as_os_str().is_empty() {
        return Err(Error::Format("entry has an empty path".into()));
    }
    if depth > limits::MAX_PATH_DEPTH {
        return Err(Error::LimitExceeded("entry path is nested too deeply".into()));
    }
    Ok(out)
}

impl Vault {
    pub fn vault_id(&self) -> VaultId {
        self.header.vault_id
    }
    pub fn crypto_suite(&self) -> CryptoSuite {
        self.header.crypto_suite
    }
    pub fn compress_suite(&self) -> CompressSuite {
        self.header.compress_suite
    }
    pub fn kdf_params(&self) -> KdfParams {
        self.header.kdf_params
    }
    /// Whether this vault requires a quorum of key components to open.
    pub fn is_split_protected(&self) -> bool {
        self.header.flags & zerotrace_format::flags::SPLIT_PROTECTED != 0
    }

    pub fn factors(&self) -> FactorSet {
        self.header.auth.required
    }
    pub fn format_version(&self) -> u16 {
        self.header.format_version
    }
    pub fn is_unlocked(&self) -> bool {
        self.master.is_some()
    }
    pub fn entries(&self) -> &[Entry] {
        &self.manifest.entries
    }
    pub fn path(&self) -> &Path {
        &self.path
    }

    fn master(&self) -> Result<&Key256> {
        self.master.as_ref().ok_or(Error::Locked)
    }

    /// Creates a new vault at `path`, password only.
    pub fn create<P: AsRef<Path>>(path: P, password: &[u8], opts: &VaultOptions) -> Result<Self> {
        Self::create_with(path, password, None, opts)
    }

    /// Creates a vault, optionally binding a hardware factor.
    pub fn create_with<P: AsRef<Path>>(
        path: P,
        password: &[u8],
        authenticator: Option<&dyn Authenticator>,
        opts: &VaultOptions,
    ) -> Result<Self> {
        opts.kdf_params.validate()?;
        opts.factors.validate()?;
        let path = path.as_ref().to_path_buf();
        if path.exists() {
            return Err(Error::Other(format!("{} already exists", path.display())));
        }

        let mut kdf_salt = [0u8; zerotrace_format::SALT_LEN];
        crypto::random_bytes(&mut kdf_salt);
        let mut master_key_nonce = [0u8; 24];
        crypto::random_bytes(&mut master_key_nonce);

        let mut prf_salt = [0u8; 32];
        crypto::random_bytes(&mut prf_salt);

        let mut auth = AuthDescriptor {
            required: opts.factors,
            prf_salt,
            credential_hint: [0u8; 20],
        };

        // Obtain the hardware contribution before writing anything, so a
        // missing authenticator fails before a half-made vault exists.
        let hardware = if auth.requires_hardware() {
            let a = authenticator.ok_or(Error::NotImplemented(
                "this vault requires a FIDO2 factor but no authenticator was supplied",
            ))?;
            if a.kind() != FactorKind::Fido2Prf {
                return Err(Error::Other("authenticator is of the wrong kind".into()));
            }
            Some(a.prf_secret(&auth.credential_hint, &auth.prf_salt)?)
        } else {
            None
        };
        if !auth.requires_hardware() {
            auth.prf_salt = [0u8; 32];
        }

        let master = crypto::random_key();
        let password_key = derive_kek(password, &kdf_salt, opts.kdf_params)?;
        let kek = compose_kek(&auth, &password_key, hardware.as_ref(), &kdf_salt)?;

        let mut header = Header::new(
            opts.crypto_suite,
            opts.compress_suite,
            VaultId::from_bytes({
                let mut b = [0u8; 16];
                crypto::random_bytes(&mut b);
                b
            }),
            opts.kdf_params,
            kdf_salt,
            master_key_nonce,
            auth,
        );
        // Pin the authenticated byte image before wrapping the key.
        header.freeze();

        // Wrap the master key, binding the header's immutable prefix.
        let nonce = &master_key_nonce[..opts.crypto_suite.nonce_len()];
        let wrapped = crypto::seal(opts.crypto_suite, &kek, nonce, master.expose(), &header.aad())?;
        if wrapped.len() != zerotrace_format::WRAPPED_KEY_LEN {
            return Err(Error::Crypto("unexpected wrapped key length".into()));
        }
        header.wrapped_master_key.copy_from_slice(&wrapped);

        let mut v = Vault {
            path,
            header,
            manifest: Manifest::default(),
            master: Some(master),
            // Past the header and the duress block, both of which are always
            // present in this format.
            data_end: zerotrace_format::V3_DATA_START,
            identity: Identity::Real,
        };
        File::create(&v.path)?;
        v.save()?;
        Ok(v)
    }

    /// Opens and unlocks a password-only vault.
    pub fn open<P: AsRef<Path>>(path: P, password: &[u8]) -> Result<Self> {
        Self::open_with(path, password, None)
    }

    /// Opens a vault, supplying a hardware factor when one is required.
    ///
    /// A vault that requires FIDO2 is refused when no authenticator is given.
    /// There is no path that falls back to the password alone.
    pub fn open_with<P: AsRef<Path>>(
        path: P,
        password: &[u8],
        authenticator: Option<&dyn Authenticator>,
    ) -> Result<Self> {
        let path = path.as_ref().to_path_buf();
        let mut f = File::open(&path)?;
        let mut hb = [0u8; HEADER_LEN];
        f.read_exact(&mut hb)
            .map_err(|_| Error::Format("file is too short to be an AZV vault".into()))?;
        let header = Header::from_bytes(&hb)?;

        // Deriving the KEK is the expensive step; the parameters driving it
        // were range-checked during parsing and are authenticated below.
        let hardware = if header.auth.requires_hardware() {
            let a = authenticator.ok_or(Error::NotImplemented(
                "this vault requires a FIDO2 factor. No authenticator was supplied, and \
                 the vault is refused rather than opened with the password alone",
            ))?;
            Some(a.prf_secret(&header.auth.credential_hint, &header.auth.prf_salt)?)
        } else {
            None
        };

        let password_key = derive_kek(password, &header.kdf_salt, header.kdf_params)?;
        let kek = compose_kek(&header.auth, &password_key, hardware.as_ref(), &header.kdf_salt)?;

        if header.flags & zerotrace_format::flags::SPLIT_PROTECTED != 0 {
            // Tried before reporting the split requirement, because under
            // coercion the person will not have their token and the duress
            // path has to work from a password alone.
            if let Some(v) = Self::try_duress(&path, password)? {
                return Ok(v);
            }
            return Err(Error::Other(
                "this vault is protected by split keys and cannot be opened with a password \
                 alone. Supply the required key components; see `zt split status`"
                    .into(),
            ));
        }

        let nonce = &header.master_key_nonce[..header.crypto_suite.nonce_len()];
        // The real identity first. A duress password is only reached once this
        // has failed, so an ordinary open never goes near it.
        let master_bytes = match crypto::open(
            header.crypto_suite,
            &kek,
            nonce,
            &header.wrapped_master_key,
            &header.aad(),
        ) {
            Ok(m) => m,
            Err(e) => {
                if let Some(v) = Self::try_duress(&path, password)? {
                    return Ok(v);
                }
                return Err(e);
            }
        };
        if master_bytes.len() != 32 {
            return Err(Error::Crypto("unwrapped master key has the wrong length".into()));
        }
        let mut master = Key256::zeroed();
        master.expose_mut().copy_from_slice(&master_bytes);

        let manifest = read_manifest(&mut f, &header, &master)?;

        // The header's copy of the root is outside the authenticated prefix,
        // so the manifest's copy is authoritative and must agree.
        if manifest.integrity_root != header.integrity_root {
            return Err(Error::Integrity(
                "the header's integrity root does not match the manifest".into(),
            ));
        }
        if manifest.compute_root() != manifest.integrity_root {
            return Err(Error::Integrity("manifest integrity root is inconsistent".into()));
        }

        Ok(Vault {
            path,
            data_end: header.manifest_offset,
            header,
            manifest,
            master: Some(master),
            identity: Identity::Real,
        })
    }

    /// How a vault was opened.
    ///
    /// Returned so a caller can react, and named plainly so nothing in the
    /// code has to infer it from a side effect.
    ///
    /// Not shown to the person who opened it. A decoy that announced itself
    /// would be useless, since the whole point is that somebody watching over
    /// their shoulder sees an ordinary vault opening.
    pub fn opened_as(&self) -> Identity {
        self.identity
    }

    /// Opens a split-protected vault from a quorum of key components.
    ///
    /// The password still matters: it produces the user component. What
    /// changes is that the user component alone no longer unwraps anything.
    pub fn open_with_components<P: AsRef<Path>>(
        path: P,
        components: &[(ComponentKind, Key256)],
    ) -> Result<Self> {
        let path = path.as_ref().to_path_buf();
        let mut f = File::open(&path)?;
        let mut hb = [0u8; HEADER_LEN];
        f.read_exact(&mut hb)
            .map_err(|_| Error::Format("file is too short to be an AZV vault".into()))?;
        let header = Header::from_bytes(&hb)?;

        if header.flags & zerotrace_format::flags::SPLIT_PROTECTED == 0 {
            return Err(Error::Other(
                "this vault is not split protected; open it with a password".into(),
            ));
        }

        let bundle_path = split_bundle_path(&path);
        let bundle = SplitBundle::decode(&std::fs::read(&bundle_path).map_err(|_| {
            Error::Format(format!(
                "the split bundle {} is missing. Without it the vault cannot be opened by \
                 anyone, including its owner; restore it from a backup",
                bundle_path.display()
            ))
        })?)?;

        if bundle.vault_id != header.vault_id {
            return Err(Error::Integrity(
                "the split bundle belongs to a different vault".into(),
            ));
        }

        let release = unseal_split(&bundle, components)?;
        let nonce = &header.master_key_nonce[..header.crypto_suite.nonce_len()];
        let master_bytes = crypto::open(
            header.crypto_suite,
            &release,
            nonce,
            &header.wrapped_master_key,
            &header.aad(),
        )?;
        if master_bytes.len() != 32 {
            return Err(Error::Crypto("unwrapped master key has the wrong length".into()));
        }
        let mut master = Key256::zeroed();
        master.expose_mut().copy_from_slice(&master_bytes);

        let manifest = read_manifest(&mut f, &header, &master)?;
        if manifest.integrity_root != header.integrity_root {
            return Err(Error::Integrity(
                "the header's integrity root does not match the manifest".into(),
            ));
        }

        Ok(Vault {
            path,
            data_end: header.manifest_offset,
            header,
            manifest,
            master: Some(master),
            identity: Identity::Real,
        })
    }

    /// Converts an already-open vault to split protection.
    ///
    /// Only the 48-byte wrapped key is rewritten: the master key is unchanged,
    /// so nothing stored in the vault is re-encrypted however large it is.
    pub fn enroll_split(
        &mut self,
        components: &[(ComponentKind, Key256)],
    ) -> Result<SplitBundle> {
        if self.is_split_protected() {
            return Err(Error::Other("this vault is already split protected".into()));
        }
        let master = self.master()?.clone();

        let release = crypto::random_key();
        let bundle =
            seal_split(&release, self.header.vault_id, self.header.crypto_suite, components)?;

        // Set the flag before wrapping: it sits in the authenticated region,
        // so the wrap must commit to the vault already being split protected.
        self.header.flags |= zerotrace_format::flags::SPLIT_PROTECTED;
        let mut nonce = [0u8; 24];
        crypto::random_bytes(&mut nonce);
        self.header.master_key_nonce = nonce;
        self.header.freeze();

        let wrapped = crypto::seal(
            self.header.crypto_suite,
            &release,
            &nonce[..self.header.crypto_suite.nonce_len()],
            master.expose(),
            &self.header.aad(),
        )?;
        if wrapped.len() != zerotrace_format::WRAPPED_KEY_LEN {
            return Err(Error::Crypto("unexpected wrapped key length".into()));
        }
        self.header.wrapped_master_key.copy_from_slice(&wrapped);
        self.header.freeze();

        // Write the bundle first. If the process dies between the two writes,
        // an orphaned bundle is harmless, whereas a split-protected header
        // with no bundle would be an unopenable vault.
        let bundle_path = split_bundle_path(&self.path);
        std::fs::write(&bundle_path, bundle.encode())?;
        // Sealed shares of this vault's release key. Created through ordinary
        // filesystem calls it would inherit the umask, which on a shared
        // machine commonly leaves it world-readable.
        let _ = zerotrace_core::restrict_permissions(&bundle_path);
        self.save()?;
        Ok(bundle)
    }

    /// Tries the duress identity, and if it opens, destroys the real key.
    ///
    /// Attempted only after the real identity has failed, so an ordinary open
    /// never touches this path and cannot trigger it.
    ///
    /// The destruction is the same cryptographic erasure used everywhere else:
    /// the real wrapped key is overwritten and read back to confirm. It
    /// happens before the decoy contents are returned, so an adversary who
    /// interrupts the program mid-open still finds the real key gone.
    pub fn try_duress_open<P: AsRef<Path>>(path: P, password: &[u8]) -> Result<Option<Vault>> {
        Self::try_duress(path, password)
    }

    fn try_duress<P: AsRef<Path>>(path: P, password: &[u8]) -> Result<Option<Vault>> {
        let path = path.as_ref().to_path_buf();
        let mut f = OpenOptions::new().read(true).write(true).open(&path)?;
        let mut hb = [0u8; HEADER_LEN + DECOY_BLOCK_LEN];
        if f.read_exact(&mut hb).is_err() {
            return Ok(None);
        }
        let mut header = Header::from_bytes(&hb)?;
        let Some(slot) = header.decoy_slot() else { return Ok(None) };

        // A wrong password and a slot full of random bytes fail identically,
        // which is what keeps an unused slot indistinguishable from a used one.
        let kek = derive_kek(password, &slot.kdf_salt, header.kdf_params)?;
        let nonce = &slot.key_nonce[..header.crypto_suite.nonce_len()];
        let Ok(master_bytes) = crypto::open(
            header.crypto_suite,
            &kek,
            nonce,
            &slot.wrapped_key,
            &decoy_aad(&header.vault_id),
        ) else {
            return Ok(None);
        };
        if master_bytes.len() != 32 {
            return Ok(None);
        }
        let mut master = Key256::zeroed();
        master.expose_mut().copy_from_slice(&master_bytes);

        // The real key goes first. Everything after this point is presentation.
        let mut shredded = [0u8; zerotrace_format::WRAPPED_KEY_LEN];
        crypto::random_bytes(&mut shredded);
        f.seek(SeekFrom::Start(104))?;
        f.write_all(&shredded)?;
        f.flush()?;
        f.sync_all()?;

        let mut readback = [0u8; zerotrace_format::WRAPPED_KEY_LEN];
        f.seek(SeekFrom::Start(104))?;
        f.read_exact(&mut readback)?;
        if readback != shredded {
            return Err(Error::Other("the vault could not be opened".into()));
        }
        header.wrapped_master_key = shredded;

        let mut decoy_header = header.clone();
        decoy_header.manifest_offset = slot.manifest_offset;
        decoy_header.manifest_len = slot.manifest_len;
        let manifest = read_manifest(&mut f, &decoy_header, &master)?;
        // The header was cloned from the real identity, so its integrity root
        // describes the real contents. Left as it was, verifying the decoy
        // would report damage that is not there.
        decoy_header.integrity_root = manifest.integrity_root;

        Ok(Some(Vault {
            path,
            data_end: slot.manifest_offset,
            header: decoy_header,
            manifest,
            master: Some(master),
            identity: Identity::Decoy,
        }))
    }

    /// Removes the container and everything written beside it.
    ///
    /// Used after a duress extraction has handed over the decoy contents.
    /// There is nothing left worth keeping: the real key is already destroyed,
    /// so the container holds only unreadable bytes and a decoy, and the audit
    /// log and journal describe a vault that no longer opens.
    ///
    /// Removing them is the difference between an adversary finding a large
    /// container with two small files in it, which invites a question, and
    /// finding nothing at all.
    ///
    /// Best effort per file, and it reports what it could not remove rather
    /// than claiming success. A file that survives is worth knowing about.
    pub fn purge_all(path: &Path) -> Vec<String> {
        let mut failed = Vec::new();
        let mut remove = |p: PathBuf| {
            if p.exists() {
                // Overwritten before unlinking where that reaches the data.
                // On a copy-on-write filesystem it does not, which the
                // platform layer reports elsewhere rather than pretending.
                if let Ok(meta) = std::fs::metadata(&p) {
                    if meta.is_file() && meta.len() > 0 && meta.len() < 64 * 1024 * 1024 {
                        if let Ok(mut f) = OpenOptions::new().write(true).open(&p) {
                            let mut junk = vec![0u8; meta.len() as usize];
                            crypto::random_bytes(&mut junk);
                            let _ = f.write_all(&junk);
                            let _ = f.flush();
                            let _ = f.sync_all();
                        }
                    }
                }
                if std::fs::remove_file(&p).is_err() {
                    failed.push(p.display().to_string());
                }
            }
        };

        let base = path.display().to_string();
        for suffix in [
            "", ".audit", ".journal", ".policy", ".split", ".custodian", ".watch",
            ".watch.stop", ".decoy-build",
        ] {
            remove(PathBuf::from(format!("{base}{suffix}")));
        }
        failed
    }

    /// Installs a duress password and the contents it reveals.
    ///
    /// The decoy gets its own master key, its own manifest and its own chunks,
    /// all inside the same container. Nothing distinguishes the two identities
    /// from outside: both are wrappings that either open with the password
    /// offered or do not.
    ///
    /// The duress password must not resemble the real one. Typing the wrong
    /// one of two similar passwords from muscle memory would destroy a vault
    /// by accident, and an irreversible action reached by a typo is not a
    /// safety feature.
    pub fn set_duress_password(
        &mut self,
        real_password: &[u8],
        duress_password: &[u8],
        decoy_files: &[(PathBuf, String)],
    ) -> Result<()> {
        self.set_duress_password_with_progress(
            real_password,
            duress_password,
            decoy_files,
            |_, _| {},
        )
    }

    /// Installs a duress password, reporting bytes done and total as it goes.
    ///
    /// Decoy files are ordinary files and can be large, so building the decoy
    /// takes as long as importing them would. Without feedback the window
    /// stops painting and looks exactly like one that has crashed.
    pub fn set_duress_password_with_progress(
        &mut self,
        real_password: &[u8],
        duress_password: &[u8],
        decoy_files: &[(PathBuf, String)],
        mut progress: impl FnMut(u64, u64),
    ) -> Result<()> {
        if self.identity != Identity::Real {
            return Err(Error::Other("this handle is not the real vault".into()));
        }
        if decoy_files.is_empty() {
            return Err(Error::Other(
                "a duress password needs something to show. An empty vault under coercion \
                 invites the question of what else there is"
                    .into(),
            ));
        }
        // Checked before any work, so a mistyped path fails cleanly instead of
        // halfway through building a decoy vault.
        for (src, _) in decoy_files {
            if !src.is_file() {
                return Err(Error::Other(format!(
                    "{} is not a file that exists. Choose files already on this computer \
                     for the duress password to show",
                    src.display()
                )));
            }
        }
        // Checked here rather than in a front end, because a rule enforced in
        // one of two front ends is not enforced. Two passwords a keystroke
        // apart get confused under pressure, and confusing them destroys the
        // vault.
        let real = String::from_utf8_lossy(real_password);
        let duress = String::from_utf8_lossy(duress_password);
        if real == duress {
            return Err(Error::Other(
                "the duress password must be different from the real one".into(),
            ));
        }
        if too_similar(&real, &duress) {
            return Err(Error::Other(
                "the duress password is too close to the real one. Under pressure they \
                 would be confused, and confusing them destroys the vault. Choose a \
                 different phrase entirely"
                    .into(),
            ));
        }

        // Built as a complete second vault in a scratch file, then folded in,
        // so the chunk and manifest code is the same code the real side uses
        // rather than a parallel implementation that could diverge from it.
        // Where the decoy region will land once folded in. Known before the
        // decoy is built, because every offset recorded inside its manifest
        // has to be written in the real container's coordinates rather than
        // the scratch file's.
        let append_at = std::fs::metadata(&self.path)?.len();
        let shift = append_at - zerotrace_format::V3_DATA_START;

        // Removed however this function leaves, including by an early return.
        // A scratch file left beside a vault is both confusing and a tell:
        // somebody finding `v.azv.decoy-build` learns that a duress password
        // was being set up.
        struct Scratch(PathBuf);
        impl Drop for Scratch {
            fn drop(&mut self) {
                let _ = std::fs::remove_file(&self.0);
            }
        }
        let scratch_path = PathBuf::from(format!("{}.decoy-build", self.path.display()));
        let _ = std::fs::remove_file(&scratch_path);
        let scratch_guard = Scratch(scratch_path.clone());
        let scratch = &scratch_guard.0;
        let mut opts = VaultOptions {
            crypto_suite: self.header.crypto_suite,
            compress_suite: self.header.compress_suite,
            kdf_params: self.header.kdf_params,
            ..VaultOptions::default()
        };
        opts.factors = FactorSet::password_only();

        let total: u64 = decoy_files
            .iter()
            .filter_map(|(p, _)| std::fs::metadata(p).ok().map(|m| m.len()))
            .sum();
        let mut done = 0u64;
        progress(0, total);

        let mut decoy = Vault::create(&scratch, duress_password, &opts)?;
        for (src, name) in decoy_files {
            let base = done;
            decoy.import_with_progress(src, name, |d, _| progress(base + d, total))?;
            done = base + std::fs::metadata(src).map(|m| m.len()).unwrap_or(0);
            progress(done, total);
        }
        // The decoy manifest is authenticated against a vault identifier, and
        // it will be read back through the real container's header. Written
        // under the scratch vault's own identifier it would decrypt to a
        // failure that looks exactly like a wrong password.
        decoy.header.vault_id = self.header.vault_id;
        for entry in decoy.manifest.entries.iter_mut() {
            for chunk in entry.chunks.iter_mut() {
                chunk.offset += shift;
            }
        }
        decoy.save()?;
        let decoy_header = decoy.header.clone();
        let decoy_manifest_offset = decoy.header.manifest_offset;
        let decoy_manifest_len = decoy.header.manifest_len;
        // Re-wrapped under the duress AAD rather than the scratch vault's own
        // header, because the slot has to keep opening after the real wrapped
        // key beside it has been overwritten.
        let decoy_master = decoy.master()?.clone();
        decoy.close();

        let duress_kek = derive_kek(duress_password, &decoy_header.kdf_salt, self.header.kdf_params)?;
        let mut decoy_nonce = [0u8; 24];
        crypto::random_bytes(&mut decoy_nonce);
        let decoy_wrapped = crypto::seal(
            self.header.crypto_suite,
            &duress_kek,
            &decoy_nonce[..self.header.crypto_suite.nonce_len()],
            decoy_master.expose(),
            &decoy_aad(&self.header.vault_id),
        )?;
        if decoy_wrapped.len() != zerotrace_format::WRAPPED_KEY_LEN {
            return Err(Error::Crypto("unexpected wrapped key length".into()));
        }
        let mut decoy_wrapped_arr = [0u8; zerotrace_format::WRAPPED_KEY_LEN];
        decoy_wrapped_arr.copy_from_slice(&decoy_wrapped);

        // Everything after the scratch header is chunks and manifest. It is
        // appended to the real container and the offsets shifted to match.
        let blob = std::fs::read(scratch)?;
        let body_start = zerotrace_format::V3_DATA_START as usize;
        if blob.len() <= body_start {
            return Err(Error::Other("the decoy vault is empty".into()));
        }
        let body = &blob[body_start..];

        let mut f = OpenOptions::new().read(true).write(true).open(&self.path)?;
        if f.metadata()?.len() != append_at {
            return Err(Error::Other(
                "the vault changed while the duress contents were being prepared".into(),
            ));
        }
        f.seek(SeekFrom::End(0))?;
        f.write_all(body)?;

        let slot = DecoySlot {
            key_nonce: decoy_nonce,
            wrapped_key: decoy_wrapped_arr,
            kdf_salt: decoy_header.kdf_salt,
            manifest_offset: decoy_manifest_offset + shift,
            manifest_len: decoy_manifest_len,
            body_offset: append_at,
            body_len: body.len() as u64,
        };
        self.header.set_decoy_slot(&slot);

        f.seek(SeekFrom::Start(0))?;
        f.write_all(&self.header.to_bytes())?;
        if let Some(block) = self.header.decoy_bytes() {
            f.write_all(&block)?;
        }
        f.flush()?;
        f.sync_all()?;
        Ok(())
    }

    /// Locks the vault, destroying the in-memory key material.
    ///
    /// This is what PANIC LOCK will call in a later phase. It leaves the vault
    /// on disk completely intact.
    pub fn close(mut self) {
        self.master = None; // Key256 zeroes itself on drop
    }

    /// Imports a file from disk under `stored_path`.
    pub fn import<P: AsRef<Path>>(&mut self, source: P, stored_path: &str) -> Result<()> {
        self.import_with_progress(source, stored_path, |_, _| {})
    }

    /// Imports a file, reporting bytes done and total as it goes.
    ///
    /// A large file takes minutes, during which a window with no feedback
    /// looks exactly like one that has hung. The callback runs once per chunk,
    /// which is often enough to move a bar and rare enough not to cost
    /// anything.
    pub fn import_with_progress<P: AsRef<Path>>(
        &mut self,
        source: P,
        stored_path: &str,
        mut progress: impl FnMut(u64, u64),
    ) -> Result<()> {
        let master = self.master()?.clone();
        let source = source.as_ref();
        let meta = std::fs::metadata(source)?;
        if !meta.is_file() {
            return Err(Error::Other(format!("{} is not a file", source.display())));
        }
        sanitize_relative_path(stored_path)?;
        if self.manifest.entries.len() >= limits::MAX_ENTRIES {
            return Err(Error::LimitExceeded("vault holds too many entries".into()));
        }

        let mut object_id = [0u8; 16];
        crypto::random_bytes(&mut object_id);
        let file_key = crypto::derive_file_key(&master, &object_id)?;

        let expected = meta.len();
        let mut f = File::open(source)?;
        let mut out = OpenOptions::new().read(true).write(true).open(&self.path)?;
        out.seek(SeekFrom::Start(self.data_end))?;
        progress(0, expected);

        let mut chunks = Vec::new();
        let mut buf = vec![0u8; CHUNK_SIZE];
        let mut index = 0u64;
        let mut total = 0u64;
        let mut cursor = self.data_end;

        loop {
            let n = read_full(&mut f, &mut buf)?;
            if n == 0 {
                break;
            }
            let plain = &buf[..n];
            let (used, compressed) =
                compress::compress(plain, COMPRESSION_LEVEL, self.header.compress_suite)?;
            let aad = chunk_aad(&object_id, index, n as u32, used);
            let nonce = crypto::chunk_nonce(self.header.crypto_suite, index);
            let ct = crypto::seal(self.header.crypto_suite, &file_key, &nonce, &compressed, &aad)?;
            if ct.len() > limits::MAX_CHUNK_CIPHERTEXT {
                return Err(Error::LimitExceeded("chunk ciphertext is too large".into()));
            }
            out.write_all(&ct)?;
            chunks.push(ChunkRef {
                offset: cursor,
                ciphertext_len: ct.len() as u32,
                plaintext_len: n as u32,
                hash: crypto::sha256(&ct),
            });
            cursor += ct.len() as u64;
            total += n as u64;
            index += 1;
            progress(total, expected);
            if n < CHUNK_SIZE {
                break;
            }
        }
        out.flush()?;

        // Record the suite each chunk actually used. Mixed content can end up
        // partly stored and partly compressed, so the per-chunk decision is
        // what the entry reports.
        let entry_suite = if chunks.is_empty() {
            CompressSuite::Store
        } else {
            self.header.compress_suite
        };

        self.data_end = cursor;
        self.manifest.entries.push(Entry {
            object_id,
            path: stored_path.to_string(),
            size: total,
            mtime: meta
                .modified()
                .ok()
                .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
                .map(|d| d.as_secs() as i64)
                .unwrap_or(0),
            compress_suite: entry_suite,
            chunks,
        });
        self.save()
    }

    /// Exports entry `index` beneath `dest_dir`, recreating its relative path.
    pub fn export<P: AsRef<Path>>(&self, index: usize, dest_dir: P) -> Result<PathBuf> {
        self.export_with_progress(index, dest_dir, |_, _| {})
    }

    /// Exports an entry, reporting bytes done and total as it goes.
    ///
    /// Decryption is as slow as encryption on a large file, so extraction
    /// needs the same feedback importing does.
    pub fn export_with_progress<P: AsRef<Path>>(
        &self,
        index: usize,
        dest_dir: P,
        mut progress: impl FnMut(u64, u64),
    ) -> Result<PathBuf> {
        let master = self.master()?;
        let entry = self
            .manifest
            .entries
            .get(index)
            .ok_or_else(|| Error::Other("entry index out of range".into()))?;
        let rel = sanitize_relative_path(&entry.path)?;
        let out_path = dest_dir.as_ref().join(&rel);
        if let Some(parent) = out_path.parent() {
            std::fs::create_dir_all(parent)?;
            // Checked after the directories exist, so a link placed as one of
            // them is caught rather than silently followed.
            zerotrace_core::refuse_symlinked_path(parent)?;
        }
        zerotrace_core::refuse_symlinked_path(&out_path)?;

        // Written to a neighbouring temporary file and renamed into place only
        // once every chunk has authenticated and the length matches.
        //
        // Writing straight to the destination meant a file failing on its last
        // chunk left however much had already decrypted sitting there as
        // plaintext. An export should produce a complete verified file or
        // nothing.
        //
        // Created with `create_new`, which fails if anything is already at the
        // path. That is also what stops a link planted between the check above
        // and the open from being written through.
        let part_path = out_path.with_extension(format!(
            "{}.zt-part",
            out_path.extension().map(|e| e.to_string_lossy().into_owned()).unwrap_or_default()
        ));
        let _ = std::fs::remove_file(&part_path);

        struct Partial(PathBuf, bool);
        impl Drop for Partial {
            fn drop(&mut self) {
                if !self.1 {
                    // Overwritten before unlinking: this holds plaintext.
                    if let Ok(meta) = std::fs::metadata(&self.0) {
                        if meta.len() > 0 && meta.len() < 512 * 1024 * 1024 {
                            if let Ok(mut f) = OpenOptions::new().write(true).open(&self.0) {
                                let junk = vec![0u8; meta.len() as usize];
                                let _ = f.write_all(&junk);
                                let _ = f.flush();
                            }
                        }
                    }
                    let _ = std::fs::remove_file(&self.0);
                }
            }
        }
        let mut guard = Partial(part_path.clone(), false);

        let file_key = crypto::derive_file_key(master, &entry.object_id)?;
        let mut src = File::open(&self.path)?;
        let mut out = OpenOptions::new().write(true).create_new(true).open(&part_path)?;
        let _ = zerotrace_core::restrict_permissions(&part_path);
        let mut written = 0u64;

        progress(0, entry.size);
        for (i, c) in entry.chunks.iter().enumerate() {
            let plain = self.read_chunk(&mut src, &file_key, entry, i, c)?;
            out.write_all(&plain)?;
            written += plain.len() as u64;
            progress(written, entry.size);
        }
        out.flush()?;
        out.sync_all()?;
        drop(out);

        if written != entry.size {
            return Err(Error::Integrity("exported size does not match the manifest".into()));
        }

        std::fs::rename(&part_path, &out_path)?;
        guard.1 = true;
        Ok(out_path)
    }

    fn read_chunk(
        &self,
        src: &mut File,
        file_key: &Key256,
        entry: &Entry,
        index: usize,
        c: &ChunkRef,
    ) -> Result<Vec<u8>> {
        if c.ciphertext_len as usize > limits::MAX_CHUNK_CIPHERTEXT {
            return Err(Error::LimitExceeded("chunk ciphertext exceeds the limit".into()));
        }
        src.seek(SeekFrom::Start(c.offset))?;
        let mut ct = vec![0u8; c.ciphertext_len as usize];
        src.read_exact(&mut ct)
            .map_err(|_| Error::Integrity("vault is truncated".into()))?;

        if crypto::sha256(&ct) != c.hash {
            return Err(Error::Integrity(format!(
                "chunk {index} does not match its recorded hash"
            )));
        }

        // The suite recorded on the entry is what compression *may* have been
        // used; the AAD pins which one actually was, so a swapped value fails
        // authentication rather than silently mis-decompressing.
        for suite in [entry.compress_suite, CompressSuite::Store] {
            let aad = chunk_aad(&entry.object_id, index as u64, c.plaintext_len, suite);
            let nonce = crypto::chunk_nonce(self.header.crypto_suite, index as u64);
            if let Ok(inner) =
                crypto::open(self.header.crypto_suite, file_key, &nonce, &ct, &aad)
            {
                return compress::decompress(suite, &inner, c.plaintext_len as usize);
            }
        }
        Err(Error::AuthenticationFailed)
    }

    /// Verifies the vault without exporting anything.
    pub fn verify(&self) -> Result<VerifyReport> {
        let master = self.master()?;
        let mut report = VerifyReport {
            vault_id: self.header.vault_id,
            // Both were already proven during open: the header prefix by the
            // successful unwrap, the manifest by its own AEAD.
            header_authentic: Assurance::Verified,
            manifest_authentic: Assurance::Verified,
            chunks_checked: 0,
            chunks_failed: 0,
            integrity_root_matches: Assurance::Failed,
            entries: self.manifest.entries.len(),
            plaintext_bytes: self.manifest.total_plaintext(),
            ciphertext_bytes: self.manifest.total_ciphertext(),
        };

        if self.manifest.compute_root() == self.manifest.integrity_root
            && self.manifest.integrity_root == self.header.integrity_root
        {
            report.integrity_root_matches = Assurance::Verified;
        }

        let mut src = File::open(&self.path)?;
        for entry in &self.manifest.entries {
            let file_key = crypto::derive_file_key(master, &entry.object_id)?;
            for (i, c) in entry.chunks.iter().enumerate() {
                report.chunks_checked += 1;
                if self.read_chunk(&mut src, &file_key, entry, i, c).is_err() {
                    report.chunks_failed += 1;
                }
            }
        }
        Ok(report)
    }

    /// Writes the manifest and header. Called after every mutation.
    fn save(&mut self) -> Result<()> {
        let master = self.master()?.clone();
        self.manifest.integrity_root = self.manifest.compute_root();
        // Counted from one and never reused, so an older manifest
        // authenticates only against its own generation.
        self.manifest.generation = self.manifest.generation.saturating_add(1);

        let plain = self.manifest.encode();
        let metadata_key = crypto::derive_subkey(&master, b"", crypto::info::METADATA)?;
        let mut nonce_full = [0u8; 24];
        crypto::random_bytes(&mut nonce_full);
        let nonce = &nonce_full[..self.header.crypto_suite.nonce_len()];

        let aad = manifest_aad(&self.header.vault_id, plain.len() as u64, self.manifest.generation);
        let ct = crypto::seal(self.header.crypto_suite, &metadata_key, nonce, &plain, &aad)?;

        let blob_len = 24 + 8 + 8 + ct.len();
        if blob_len as u64 > limits::MAX_MANIFEST_BYTES {
            return Err(Error::LimitExceeded("manifest is too large".into()));
        }

        let mut f = OpenOptions::new().read(true).write(true).open(&self.path)?;

        // A decoy region lives after the real manifest, so it has to be picked
        // up and put back down each time the manifest is rewritten. It is
        // small, and losing it would take the duress password with it.
        let carried = match self.header.decoy_slot() {
            Some(slot) if slot.body_len > 0 && slot.body_len < limits::MAX_MANIFEST_BYTES * 8 => {
                let mut buf = vec![0u8; slot.body_len as usize];
                if f.seek(SeekFrom::Start(slot.body_offset)).is_ok()
                    && f.read_exact(&mut buf).is_ok()
                {
                    Some((slot, buf))
                } else {
                    None
                }
            }
            _ => None,
        };

        f.seek(SeekFrom::Start(self.data_end))?;
        f.write_all(&nonce_full)?;
        f.write_all(&(plain.len() as u64).to_le_bytes())?;
        // Written in the clear because a reader needs it before it can
        // decrypt: it is part of the additional data. Altering it here makes
        // the manifest fail to open, so it cannot be used to lie about which
        // generation this is; it can only be used to read the right one.
        f.write_all(&self.manifest.generation.to_le_bytes())?;
        f.write_all(&ct)?;
        let mut end = self.data_end + blob_len as u64;

        if let Some((mut slot, body)) = carried {
            let new_offset = end;
            f.seek(SeekFrom::Start(new_offset))?;
            f.write_all(&body)?;
            let delta = new_offset as i128 - slot.body_offset as i128;
            slot.manifest_offset = (slot.manifest_offset as i128 + delta) as u64;
            slot.body_offset = new_offset;
            self.header.set_decoy_slot(&slot);
            end = new_offset + body.len() as u64;
        }
        f.set_len(end)?;

        self.header.manifest_offset = self.data_end;
        self.header.manifest_len = blob_len as u64;
        self.header.integrity_root = self.manifest.integrity_root;

        f.seek(SeekFrom::Start(0))?;
        f.write_all(&self.header.to_bytes())?;
        // The duress block travels with the header, and is written on every
        // save whether or not a duress password exists. A vault that only
        // wrote it once the feature was enabled would announce the feature.
        if let Some(block) = self.header.decoy_bytes() {
            f.write_all(&block)?;
        }
        f.flush()?;
        // Durability matters here: a torn write between the chunks and the
        // header would leave a vault that cannot be opened.
        f.sync_all()?;
        Ok(())
    }
}

/// Binds a duress wrapping to its container.
///
/// Deliberately does not cover the header prefix the real key commits to. The
/// decoy must survive the real wrapped key being overwritten, and a decoy that
/// stopped opening the moment it fired would be worse than none at all.
/// Whether two passwords are close enough to be typed for one another.
///
/// A one or two character difference, or a long shared opening, is the shape
/// of a slip: the same phrase with a digit changed, or one character dropped.
/// Getting this wrong destroys a vault, so the check is deliberately blunt and
/// errs toward refusing.
fn too_similar(a: &str, b: &str) -> bool {
    if a.is_empty() || b.is_empty() {
        return false;
    }
    let x: Vec<char> = a.chars().collect();
    let y: Vec<char> = b.chars().collect();

    if x.len().abs_diff(y.len()) <= 1 {
        let mut diffs = 0usize;
        let (mut i, mut j) = (0usize, 0usize);
        while i < x.len() && j < y.len() && diffs <= 2 {
            if x[i] == y[j] {
                i += 1;
                j += 1;
            } else {
                diffs += 1;
                match x.len().cmp(&y.len()) {
                    std::cmp::Ordering::Greater => i += 1,
                    std::cmp::Ordering::Less => j += 1,
                    std::cmp::Ordering::Equal => {
                        i += 1;
                        j += 1;
                    }
                }
            }
        }
        diffs += (x.len() - i) + (y.len() - j);
        if diffs <= 2 {
            return true;
        }
    }

    // A long shared opening is the other common slip: muscle memory carries
    // through the first several characters before the phrases diverge.
    x.iter().zip(y.iter()).take_while(|(p, q)| p == q).count() >= 8
}


fn decoy_aad(vault_id: &zerotrace_core::VaultId) -> Vec<u8> {
    let mut aad = Vec::with_capacity(48);
    aad.extend_from_slice(b"apex-zerotrace:decoy-wrap:v1");
    aad.extend_from_slice(vault_id.as_bytes());
    aad
}

fn read_manifest(f: &mut File, header: &Header, master: &Key256) -> Result<Manifest> {
    if header.manifest_len == 0 {
        return Ok(Manifest::default());
    }
    if header.manifest_len < 32 {
        return Err(Error::Format("manifest record is too short".into()));
    }
    f.seek(SeekFrom::Start(header.manifest_offset))?;
    let mut nonce_full = [0u8; 24];
    f.read_exact(&mut nonce_full)
        .map_err(|_| Error::Format("vault is truncated at the manifest".into()))?;
    let mut lenb = [0u8; 8];
    f.read_exact(&mut lenb)?;
    let plain_len = u64::from_le_bytes(lenb);
    if plain_len > limits::MAX_MANIFEST_BYTES {
        return Err(Error::LimitExceeded("manifest declares an implausible size".into()));
    }

    let mut genb = [0u8; 8];
    f.read_exact(&mut genb)?;
    let generation = u64::from_le_bytes(genb);

    let ct_len = header
        .manifest_len
        .checked_sub(40)
        .ok_or_else(|| Error::Format("manifest region is too small".into()))?
        as usize;
    let mut ct = vec![0u8; ct_len];
    f.read_exact(&mut ct)
        .map_err(|_| Error::Format("vault is truncated at the manifest".into()))?;

    let metadata_key = crypto::derive_subkey(master, b"", crypto::info::METADATA)?;
    let nonce = &nonce_full[..header.crypto_suite.nonce_len()];
    let aad = manifest_aad(&header.vault_id, plain_len, generation);
    let plain = crypto::open(header.crypto_suite, &metadata_key, nonce, &ct, &aad)?;
    let manifest = Manifest::decode(&plain)?;

    // The generation outside and the generation inside must agree. The one
    // outside was needed to decrypt at all; checking it against the sealed
    // copy means the visible one cannot be used to point at a different
    // generation than the manifest claims to be.
    if manifest.generation != generation {
        return Err(Error::Integrity(
            "the manifest's generation does not match the one recorded beside it".into(),
        ));
    }
    Ok(manifest)
}

fn read_full(f: &mut File, buf: &mut [u8]) -> Result<usize> {
    let mut n = 0;
    while n < buf.len() {
        match f.read(&mut buf[n..]) {
            Ok(0) => break,
            Ok(k) => n += k,
            Err(ref e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(e.into()),
        }
    }
    Ok(n)
}
