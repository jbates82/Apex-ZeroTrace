//! Filesystem sanitization: the secondary assurance layer.
//!
//! Everything in this crate is best effort, and it says so. Overwriting a file
//! does not reliably destroy it on modern storage: copy-on-write filesystems
//! write elsewhere, journals retain old contents, snapshots hold whole prior
//! states, SSD wear levelling and flash translation layers remap blocks out
//! from under you, RAID mirrors have their own copies, and virtual disks and
//! backups are simply other files.
//!
//! No method here returns `Verified` for overwriting, because none of them can
//! observe what the storage stack actually did. The security boundary is
//! cryptographic erasure; this is an extra layer on top of it.

#![forbid(unsafe_code)]

use std::io::{Seek, SeekFrom, Write};
use std::path::Path;

use rand::RngCore;
use zerotrace_core::{Assurance, Result};

/// What a platform can offer. Implementations live behind this so the portable
/// core never contains filesystem internals.
pub trait PlatformSanitizer {
    fn name(&self) -> &'static str;

    /// Overwrite a file's bytes in place before removal.
    fn overwrite_in_place(&self, path: &Path) -> (Assurance, String);

    /// Look for filesystem snapshots holding older copies.
    fn detect_snapshots(&self, path: &Path) -> (usize, Assurance, String);

    /// Remove snapshots found by [`detect_snapshots`].
    fn remove_snapshots(&self, path: &Path) -> (usize, Assurance, String);

    /// Overwrite unallocated space so previously freed blocks are covered.
    fn sanitize_free_space(&self, path: &Path) -> (Assurance, String);
}

/// The portable implementation. Does what any filesystem allows and no more.
pub struct GenericSanitizer;

impl PlatformSanitizer for GenericSanitizer {
    fn name(&self) -> &'static str {
        "generic"
    }

    /// Overwrites the file's current extent with random bytes and flushes.
    ///
    /// Returns `BestEffort`, never `Verified`. The write is observable; where
    /// the storage stack actually put it is not.
    fn overwrite_in_place(&self, path: &Path) -> (Assurance, String) {
        let Ok(meta) = std::fs::metadata(path) else {
            return (Assurance::NotAttempted, "file was already absent".into());
        };
        let len = meta.len();

        let result = (|| -> Result<()> {
            let mut f = std::fs::OpenOptions::new().write(true).open(path)?;
            f.seek(SeekFrom::Start(0))?;
            let mut buf = vec![0u8; 64 * 1024];
            let mut written = 0u64;
            while written < len {
                let n = ((len - written) as usize).min(buf.len());
                rand::thread_rng().fill_bytes(&mut buf[..n]);
                f.write_all(&buf[..n])?;
                written += n as u64;
            }
            f.flush()?;
            f.sync_all()?;
            Ok(())
        })();

        match result {
            Ok(()) => (
                Assurance::BestEffort,
                format!(
                    "{len} bytes overwritten and flushed. Whether the storage device reused \
                     the same physical blocks cannot be observed from here."
                ),
            ),
            Err(e) => (Assurance::Failed, format!("overwrite failed: {e}")),
        }
    }

    fn detect_snapshots(&self, _path: &Path) -> (usize, Assurance, String) {
        (
            0,
            Assurance::NotImplemented,
            "Snapshot detection needs platform APIs (VSS on Windows, APFS and Time \
             Machine on macOS, LVM or Btrfs or ZFS on Linux). None are implemented, so \
             no claim is made about whether snapshots exist."
                .into(),
        )
    }

    fn remove_snapshots(&self, _path: &Path) -> (usize, Assurance, String) {
        (0, Assurance::NotImplemented, "no snapshot provider is implemented".into())
    }

    fn sanitize_free_space(&self, _path: &Path) -> (Assurance, String) {
        (
            Assurance::NotSupported,
            "Free-space sanitization is not portable and is not attempted. Even where it \
             is available it does not reach blocks retired by wear levelling."
                .into(),
        )
    }
}

/// Which secondary measures to attempt.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SanitizationProfile {
    /// Cryptographic erasure and container removal only.
    Standard,
    /// Also overwrite the container before removing it, and look for snapshots.
    Enhanced,
    /// Everything Enhanced does, plus free-space handling where supported.
    Maximum,
}

impl SanitizationProfile {
    pub fn label(&self) -> &'static str {
        match self {
            SanitizationProfile::Standard => "STANDARD",
            SanitizationProfile::Enhanced => "ENHANCED",
            SanitizationProfile::Maximum => "MAXIMUM",
        }
    }

    pub fn overwrites_container(&self) -> bool {
        !matches!(self, SanitizationProfile::Standard)
    }
    pub fn handles_snapshots(&self) -> bool {
        !matches!(self, SanitizationProfile::Standard)
    }
    pub fn handles_free_space(&self) -> bool {
        matches!(self, SanitizationProfile::Maximum)
    }
}

/// The platform sanitizer for this build.
pub fn platform_sanitizer() -> Box<dyn PlatformSanitizer> {
    // Windows, macOS and Linux specific implementations belong here. None
    // exist yet, so every platform gets the portable one and the report says
    // so rather than implying platform integration that is absent.
    Box::new(GenericSanitizer)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp(tag: &str) -> std::path::PathBuf {
        let d = std::env::temp_dir().join(format!("ztsan_{tag}_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d.join("f.bin")
    }

    #[test]
    fn overwriting_replaces_the_visible_contents() {
        let p = tmp("overwrite");
        let original = b"sensitive material that should not survive".repeat(100);
        std::fs::write(&p, &original).unwrap();

        let (a, note) = GenericSanitizer.overwrite_in_place(&p);
        assert_eq!(a, Assurance::BestEffort, "must never claim more than best effort");
        assert!(note.contains("cannot be observed"), "{note}");

        let after = std::fs::read(&p).unwrap();
        assert_eq!(after.len(), original.len(), "length must be preserved");
        assert_ne!(after, original);
        assert!(
            !after.windows(20).any(|w| w == &original[..20]),
            "original bytes still visible in the file"
        );
    }

    #[test]
    fn overwriting_an_absent_file_is_not_attempted_rather_than_failed() {
        let p = tmp("absent");
        let (a, _) = GenericSanitizer.overwrite_in_place(&p);
        assert_eq!(a, Assurance::NotAttempted);
    }

    #[test]
    fn unimplemented_measures_say_so_rather_than_claiming_success() {
        // INV-12. The temptation is to return "0 snapshots removed, success".
        let p = tmp("claims");
        std::fs::write(&p, b"x").unwrap();
        let (n, a, _) = GenericSanitizer.detect_snapshots(&p);
        assert_eq!(n, 0);
        assert_eq!(a, Assurance::NotImplemented);

        let (n, a, _) = GenericSanitizer.remove_snapshots(&p);
        assert_eq!(n, 0);
        assert_eq!(a, Assurance::NotImplemented);

        let (a, _) = GenericSanitizer.sanitize_free_space(&p);
        assert_eq!(a, Assurance::NotSupported);
    }

    #[test]
    fn profiles_describe_what_they_attempt() {
        assert!(!SanitizationProfile::Standard.overwrites_container());
        assert!(SanitizationProfile::Enhanced.overwrites_container());
        assert!(!SanitizationProfile::Enhanced.handles_free_space());
        assert!(SanitizationProfile::Maximum.handles_free_space());
    }
}
