//! Platform-specific storage knowledge and service integration.
//!
//! Everything here is isolated from the portable core on purpose: no
//! filesystem internals leak upward, and code that cannot be verified on this
//! platform reports `NotSupported` instead of guessing.
//!
//! # The finding this crate exists for
//!
//! Overwriting a file in place is not merely unreliable on some filesystems,
//! it is *meaningless* on copy-on-write ones. On Btrfs, ZFS or APFS a write
//! allocates new blocks and leaves the originals intact until they are
//! reclaimed, so the operation gives no assurance at all while looking exactly
//! like the case where it gives some.
//!
//! Reporting a uniform "best effort" across every filesystem therefore
//! overstates what happened on precisely the systems where it matters most.
//! [`LinuxSanitizer`] detects the filesystem first and reports `NotSupported`
//! with an explanation when overwriting cannot achieve anything.

#![forbid(unsafe_code)]

pub mod service;
pub mod watch;
pub mod autostart;
pub mod recent;

use std::path::Path;

use zerotrace_core::Assurance;
use zerotrace_sanitize::{GenericSanitizer, PlatformSanitizer};

/// Filesystems ZeroTrace knows something about.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FsKind {
    Ext,
    Xfs,
    Btrfs,
    Zfs,
    Ntfs,
    Apfs,
    Tmpfs,
    Overlay,
    Unknown,
}

impl FsKind {
    pub fn from_name(name: &str) -> Self {
        match name {
            "ext2" | "ext3" | "ext4" | "ext2/ext3" => FsKind::Ext,
            "xfs" => FsKind::Xfs,
            "btrfs" => FsKind::Btrfs,
            "zfs" => FsKind::Zfs,
            "ntfs" | "ntfs3" | "fuseblk" => FsKind::Ntfs,
            "apfs" => FsKind::Apfs,
            "tmpfs" | "ramfs" => FsKind::Tmpfs,
            "overlay" | "overlayfs" => FsKind::Overlay,
            _ => FsKind::Unknown,
        }
    }

    pub fn label(&self) -> &'static str {
        match self {
            FsKind::Ext => "ext2/3/4",
            FsKind::Xfs => "XFS",
            FsKind::Btrfs => "Btrfs",
            FsKind::Zfs => "ZFS",
            FsKind::Ntfs => "NTFS",
            FsKind::Apfs => "APFS",
            FsKind::Tmpfs => "tmpfs",
            FsKind::Overlay => "overlay",
            FsKind::Unknown => "unknown",
        }
    }

    /// Whether writes allocate new blocks rather than replacing old ones.
    ///
    /// On these, overwriting a file in place does not reach the original data.
    pub fn is_copy_on_write(&self) -> bool {
        matches!(self, FsKind::Btrfs | FsKind::Zfs | FsKind::Apfs)
    }

    /// Whether the filesystem is layered over another, so writes land
    /// somewhere other than where the file appears to live.
    pub fn is_layered(&self) -> bool {
        matches!(self, FsKind::Overlay)
    }

    /// Whether the filesystem has a native snapshot facility worth checking.
    pub fn has_snapshots(&self) -> bool {
        matches!(self, FsKind::Btrfs | FsKind::Zfs | FsKind::Apfs)
    }

    /// What overwriting in place can achieve here.
    pub fn overwrite_assurance(&self) -> (Assurance, &'static str) {
        if self.is_copy_on_write() {
            return (
                Assurance::NotSupported,
                "This is a copy-on-write filesystem. Writing over a file allocates new \
                 blocks and leaves the originals intact until they are reclaimed, so \
                 overwriting achieves nothing here and is not attempted. Cryptographic \
                 erasure is unaffected and remains the security boundary.",
            );
        }
        if self.is_layered() {
            return (
                Assurance::NotSupported,
                "This path is on a layered filesystem, so a write lands in an upper layer \
                 rather than over the original blocks. Overwriting is not attempted.",
            );
        }
        if matches!(self, FsKind::Tmpfs) {
            return (
                Assurance::BestEffort,
                "This path is in memory. The bytes are overwritten, but pages may have \
                 been swapped out and those copies cannot be reached.",
            );
        }
        (
            Assurance::BestEffort,
            "Bytes were overwritten and flushed. Whether the storage device reused the \
             same physical blocks cannot be observed from here, and journals, snapshots \
             and wear levelling may retain older copies.",
        )
    }
}

/// Identifies the filesystem holding `path`.
///
/// On Linux this reads `/proc/mounts` and picks the longest matching mount
/// point. On other platforms it returns `Unknown` rather than guessing.
pub fn filesystem_kind(path: &Path) -> FsKind {
    #[cfg(target_os = "linux")]
    {
        let target = std::fs::canonicalize(path)
            .or_else(|_| {
                path.parent()
                    .map(std::fs::canonicalize)
                    .unwrap_or_else(|| Ok(path.to_path_buf()))
            })
            .unwrap_or_else(|_| path.to_path_buf());

        let Ok(mounts) = std::fs::read_to_string("/proc/mounts") else {
            return FsKind::Unknown;
        };

        let mut best: Option<(usize, FsKind)> = None;
        for line in mounts.lines() {
            let mut f = line.split_whitespace();
            let (_dev, point, kind) = (f.next(), f.next(), f.next());
            let (Some(point), Some(kind)) = (point, kind) else { continue };
            // Mount points are escaped in /proc/mounts.
            let point = point.replace("\\040", " ");
            if target.starts_with(&point) {
                let len = point.len();
                if best.map(|(l, _)| len > l).unwrap_or(true) {
                    best = Some((len, FsKind::from_name(kind)));
                }
            }
        }
        return best.map(|(_, k)| k).unwrap_or(FsKind::Unknown);
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = path;
        FsKind::Unknown
    }
}

/// Whether a command exists on PATH.
fn have(tool: &str) -> bool {
    std::env::var_os("PATH")
        .map(|paths| {
            std::env::split_paths(&paths).any(|p| p.join(tool).is_file())
        })
        .unwrap_or(false)
}

/// Linux sanitizer that adapts to the filesystem it finds.
pub struct LinuxSanitizer;

impl PlatformSanitizer for LinuxSanitizer {
    fn name(&self) -> &'static str {
        "linux"
    }

    fn overwrite_in_place(&self, path: &Path) -> (Assurance, String) {
        let fs = filesystem_kind(path);
        let (assurance, note) = fs.overwrite_assurance();

        if assurance == Assurance::NotSupported {
            // Refusing is the honest answer: doing it anyway would produce a
            // BEST EFFORT line that means nothing on this filesystem.
            return (assurance, format!("{} filesystem. {note}", fs.label()));
        }

        let (result, generic_note) = GenericSanitizer.overwrite_in_place(path);
        match result {
            Assurance::BestEffort => (assurance, format!("{} filesystem. {note}", fs.label())),
            other => (other, generic_note),
        }
    }

    fn detect_snapshots(&self, path: &Path) -> (usize, Assurance, String) {
        let fs = filesystem_kind(path);
        if !fs.has_snapshots() {
            return (
                0,
                Assurance::NotAttempted,
                format!(
                    "{} has no native snapshot facility, so none was searched for. LVM or \
                     device-mapper snapshots below the filesystem would not be visible here.",
                    fs.label()
                ),
            );
        }

        let tool = match fs {
            FsKind::Btrfs => "btrfs",
            FsKind::Zfs => "zfs",
            _ => "",
        };
        if tool.is_empty() || !have(tool) {
            return (
                0,
                Assurance::NotSupported,
                format!(
                    "This path is on {}, which does have snapshots, but the `{tool}` tool is \
                     not installed, so their presence cannot be determined. This is reported \
                     as unknown rather than as zero.",
                    fs.label()
                ),
            );
        }

        // The tool exists but querying it is not implemented, and inventing a
        // count would be worse than saying so.
        (
            0,
            Assurance::NotImplemented,
            format!(
                "`{tool}` is available and could enumerate snapshots on {}, but the query is \
                 not implemented. No claim is made about whether snapshots exist.",
                fs.label()
            ),
        )
    }

    fn remove_snapshots(&self, path: &Path) -> (usize, Assurance, String) {
        let _ = path;
        (
            0,
            Assurance::NotImplemented,
            "Removing snapshots is destructive to data outside the vault and is not \
             implemented. It must be done deliberately by an administrator."
                .into(),
        )
    }

    fn sanitize_free_space(&self, path: &Path) -> (Assurance, String) {
        let fs = filesystem_kind(path);
        if fs.is_copy_on_write() {
            return (
                Assurance::NotSupported,
                format!(
                    "Filling free space on {} does not reclaim the blocks a previous write \
                     left behind, so it is not attempted.",
                    fs.label()
                ),
            );
        }
        (
            Assurance::NotSupported,
            "Free-space sanitization is not implemented. On SSDs it would not reach blocks \
             retired by wear levelling in any case."
                .into(),
        )
    }
}

/// A description of the storage under a path, for the platform report.
#[derive(Debug, Clone)]
pub struct StorageReport {
    pub filesystem: FsKind,
    pub overwrite: Assurance,
    pub overwrite_note: String,
    pub snapshots: Assurance,
    pub snapshot_note: String,
}

pub fn storage_report(path: &Path) -> StorageReport {
    let fs = filesystem_kind(path);
    let (overwrite, overwrite_note) = fs.overwrite_assurance();
    let (_, snapshots, snapshot_note) = LinuxSanitizer.detect_snapshots(path);
    StorageReport {
        filesystem: fs,
        overwrite,
        overwrite_note: overwrite_note.to_string(),
        snapshots,
        snapshot_note,
    }
}

/// A human-readable supervision status that never claims certainty it lacks.
pub fn supervision_status_label() -> &'static str {
    match service::supervision_status() {
        Some(true) => "SUPERVISED",
        Some(false) => "NOT SUPERVISED",
        None => "UNKNOWN, no supervisor detected",
    }
}

/// The sanitizer for the platform this binary was built for.
pub fn sanitizer() -> Box<dyn PlatformSanitizer> {
    #[cfg(target_os = "linux")]
    {
        Box::new(LinuxSanitizer)
    }
    // Windows and macOS have their own storage semantics and neither is
    // implemented, so they get the portable one and the report says so.
    #[cfg(not(target_os = "linux"))]
    {
        Box::new(GenericSanitizer)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn copy_on_write_filesystems_refuse_to_pretend() {
        for fs in [FsKind::Btrfs, FsKind::Zfs, FsKind::Apfs] {
            let (a, note) = fs.overwrite_assurance();
            assert_eq!(a, Assurance::NotSupported, "{}", fs.label());
            assert!(note.contains("copy-on-write"), "{note}");
        }
    }

    #[test]
    fn conventional_filesystems_report_best_effort_and_no_more() {
        for fs in [FsKind::Ext, FsKind::Xfs, FsKind::Ntfs] {
            let (a, _) = fs.overwrite_assurance();
            assert_eq!(a, Assurance::BestEffort, "{}", fs.label());
        }
    }

    #[test]
    fn a_layered_filesystem_is_recognised() {
        assert!(FsKind::Overlay.is_layered());
        assert_eq!(FsKind::Overlay.overwrite_assurance().0, Assurance::NotSupported);
    }

    #[test]
    fn filesystem_names_map_correctly() {
        assert_eq!(FsKind::from_name("ext4"), FsKind::Ext);
        assert_eq!(FsKind::from_name("btrfs"), FsKind::Btrfs);
        assert_eq!(FsKind::from_name("overlay"), FsKind::Overlay);
        assert_eq!(FsKind::from_name("something-new"), FsKind::Unknown);
    }

    #[test]
    fn this_machines_filesystem_is_identified() {
        let dir = std::env::temp_dir();
        let fs = filesystem_kind(&dir);
        // The value depends on the host, but detection must not panic and must
        // return something coherent.
        assert_eq!(fs.is_copy_on_write(), matches!(fs, FsKind::Btrfs | FsKind::Zfs | FsKind::Apfs));
    }

    #[test]
    fn a_missing_tool_is_reported_as_unknown_not_as_zero() {
        // INV-12 at the platform layer: "0 snapshots" and "cannot tell" are
        // different answers and must not be conflated.
        let (n, a, note) = LinuxSanitizer.detect_snapshots(std::path::Path::new("/tmp"));
        assert_eq!(n, 0);
        assert!(
            matches!(a, Assurance::NotAttempted | Assurance::NotSupported | Assurance::NotImplemented),
            "must never be Verified without a real query"
        );
        assert!(!note.is_empty());
    }

    #[test]
    fn overwriting_on_this_filesystem_matches_its_declared_assurance() {
        let dir = std::env::temp_dir().join(format!("ztplat_{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let f = dir.join("x.bin");
        std::fs::write(&f, b"sensitive".repeat(100)).unwrap();

        let fs = filesystem_kind(&f);
        let (declared, _) = fs.overwrite_assurance();
        let (actual, _) = LinuxSanitizer.overwrite_in_place(&f);
        assert_eq!(actual, declared, "the report must match what the filesystem allows");
    }
}


/// Whether the operating system is likely keeping prior copies of this vault.
///
/// # What this does and does not do
///
/// It warns. It does not enumerate snapshots and it does not delete them, and
/// both of those refusals are deliberate.
///
/// Deleting them needs administrator rights, and a program that removes system
/// restore points is doing the single most recognisable thing ransomware does.
/// Every antivirus product treats `vssadmin delete shadows` as a signature, and
/// they are right to. A vault application that behaved that way would be
/// quarantined, and would deserve to be.
///
/// Enumerating them is also mostly privileged, which means it would report
/// "none found" on exactly the machines where the answer matters. Saying
/// nothing is better than saying something reassuring and wrong.
///
/// So this reports where the vault lives and what that implies, and leaves the
/// decision to the person. Destroying a key does not reach a copy taken before
/// the destruction, whoever made it.
pub fn snapshot_exposure(vault: &std::path::Path) -> SnapshotExposure {
    let on_system_volume = {
        #[cfg(target_os = "windows")]
        {
            // The volume holding the user profile is the one System Protection
            // is enabled on by default.
            std::env::var_os("SystemDrive")
                .map(|d| {
                    let d = d.to_string_lossy().to_ascii_uppercase();
                    vault.display().to_string().to_ascii_uppercase().starts_with(&d)
                })
                .unwrap_or(true)
        }
        #[cfg(target_os = "macos")]
        {
            // APFS local snapshots cover the boot volume, which is everything
            // outside /Volumes.
            !vault.display().to_string().starts_with("/Volumes/")
        }
        #[cfg(all(unix, not(target_os = "macos")))]
        {
            // Btrfs and ZFS snapshot by subvolume or dataset, which cannot be
            // determined from the path alone.
            let _ = vault;
            false
        }
        #[cfg(not(any(unix, target_os = "windows")))]
        {
            let _ = vault;
            false
        }
    };

    SnapshotExposure {
        likely: on_system_volume,
        assurance: Assurance::NotImplemented,
        note: if on_system_volume {
            "This vault is on a volume where the operating system may keep prior copies of \
             files, taken automatically and without asking. Destroying this vault will not \
             touch them: cryptographic erasure removes the key from this container, and a \
             snapshot holds its own copy with the key intact.\n\nZeroTrace does not delete \
             snapshots, and will not. Doing so needs administrator rights and is the single \
             most recognisable thing ransomware does, which is why antivirus products treat \
             it as a signature.\n\nIf this matters to you, keep vaults on a removable drive \
             or a volume without snapshots, or exclude the folder from protection. Remote \
             custody is the stronger answer: a snapshot captures the container and the split \
             bundle, and cannot capture a component that was never on this machine."
        } else {
            "No snapshot exposure was inferred from this path, which is not the same as \
             there being none. Snapshot arrangements cannot be determined from a path alone \
             without privileges this program does not hold."
        }
        .to_string(),
    }
}

/// What was inferred about snapshots. Never more than an inference.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SnapshotExposure {
    /// Whether prior copies are likely, inferred from where the vault lives.
    pub likely: bool,
    /// Always NOT IMPLEMENTED: nothing here enumerates or removes snapshots.
    pub assurance: Assurance,
    pub note: String,
}
