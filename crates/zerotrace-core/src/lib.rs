//! Shared types and errors for Apex ZeroTrace.
//!
//! This crate sits at the root of the dependency graph and deliberately knows
//! nothing about cryptography, storage, the GUI or any platform. Everything
//! above it depends on these types; it depends on nothing of ours.

#![forbid(unsafe_code)]

pub mod limits;
pub mod state;
pub mod time;

use thiserror::Error;

/// Every fallible operation in ZeroTrace reports through this type.
///
/// Variants are deliberately coarse in what they reveal: an attacker probing a
/// vault should not learn from the error text whether a password was close,
/// which chunk failed, or what a decrypted length was.
#[derive(Debug, Error)]
pub enum Error {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    /// Authentication of an encrypted record failed. This covers a wrong
    /// password, a tampered vault and a corrupted vault alike, on purpose:
    /// distinguishing them leaks information.
    #[error("authentication failed: wrong credentials, or the vault has been modified")]
    AuthenticationFailed,

    #[error("vault format error: {0}")]
    Format(String),

    #[error("unsupported {what}: {value}")]
    Unsupported { what: &'static str, value: String },

    /// A declared size, count or depth exceeded a configured limit. Refusing
    /// here is what stops a hostile vault from exhausting memory.
    #[error("resource limit exceeded: {0}")]
    LimitExceeded(String),

    #[error("cryptographic operation failed: {0}")]
    Crypto(String),

    #[error("key derivation failed: {0}")]
    Kdf(String),

    #[error("compression error: {0}")]
    Compression(String),

    #[error("integrity verification failed: {0}")]
    Integrity(String),

    #[error("vault is locked")]
    Locked,

    #[error("invalid state transition: {from} -> {to}")]
    InvalidTransition { from: &'static str, to: &'static str },

    /// Reserved for capabilities that are architecturally present but not
    /// built yet. Reporting this is required rather than faking success.
    #[error("not implemented: {0}")]
    NotImplemented(&'static str),

    #[error("{0}")]
    Other(String),
}

pub type Result<T> = std::result::Result<T, Error>;

/// Identifies one vault. Random, and not derived from any user input.
pub type VaultId = uuid::Uuid;

/// How much confidence an operation's outcome carries, for honest reporting.
///
/// ZeroTrace must never report success it did not observe, so every assurance
/// surface uses this rather than a boolean.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum Assurance {
    /// Performed and confirmed by observation.
    Verified,
    /// Performed, but the result cannot be confirmed on this platform.
    BestEffort,
    /// Attempted and failed.
    Failed,
    /// Deliberately not attempted.
    NotAttempted,
    /// The platform provides no mechanism for this.
    NotSupported,
    /// Architecturally defined but not built.
    NotImplemented,
}

impl Assurance {
    pub fn label(&self) -> &'static str {
        match self {
            Assurance::Verified => "VERIFIED",
            Assurance::BestEffort => "BEST EFFORT",
            Assurance::Failed => "FAILED",
            Assurance::NotAttempted => "NOT ATTEMPTED",
            Assurance::NotSupported => "NOT SUPPORTED",
            Assurance::NotImplemented => "NOT IMPLEMENTED",
        }
    }
}

/// Restricts a file so only its owner can read it.
///
/// Applied to anything holding key material or describing a vault: split
/// bundles, recovery tokens, custody records, journals, audit logs. Created
/// through ordinary filesystem calls these inherit the process umask, which on
/// a shared machine commonly leaves them world-readable.
///
/// Best effort, and deliberately quiet about failure: a vault that refused to
/// work because a filesystem does not carry Unix permissions would be worse
/// than one that stores a file slightly more openly than intended. What it
/// must not do is claim more than it achieved, which is why it returns what
/// happened rather than nothing.
pub fn restrict_permissions(path: &std::path::Path) -> Assurance {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        match std::fs::metadata(path) {
            Ok(meta) => {
                let mut perms = meta.permissions();
                perms.set_mode(0o600);
                match std::fs::set_permissions(path, perms) {
                    Ok(()) => Assurance::Verified,
                    Err(_) => Assurance::BestEffort,
                }
            }
            Err(_) => Assurance::BestEffort,
        }
    }
    #[cfg(windows)]
    {
        // Windows inherits an access control list from the parent directory,
        // which for a user's own profile is already restricted to that user.
        // Tightening it further needs the Windows security APIs and is not
        // done here, so this reports what it is rather than claiming a
        // protection it did not apply.
        let _ = path;
        Assurance::NotImplemented
    }
    #[cfg(not(any(unix, windows)))]
    {
        let _ = path;
        Assurance::NotSupported
    }
}

/// Refuses a path that is a symbolic link, or a link anywhere above it.
///
/// Writing decrypted contents through a link somebody else placed would put
/// plaintext wherever they chose. Checked with `symlink_metadata`, which
/// reports the link itself rather than following it.
pub fn refuse_symlinked_path(path: &std::path::Path) -> Result<()> {
    if let Ok(meta) = std::fs::symlink_metadata(path) {
        if meta.file_type().is_symlink() {
            return Err(Error::Other(format!(
                "{} is a symbolic link. Writing decrypted contents through a link would \
                 put them wherever the link points, which may not be where you think",
                path.display()
            )));
        }
    }
    let mut cursor = path.parent();
    while let Some(dir) = cursor {
        if let Ok(meta) = std::fs::symlink_metadata(dir) {
            if meta.file_type().is_symlink() {
                return Err(Error::Other(format!(
                    "{} is a symbolic link, so the destination is not where it appears \
                     to be",
                    dir.display()
                )));
            }
        }
        cursor = dir.parent();
    }
    Ok(())
}
