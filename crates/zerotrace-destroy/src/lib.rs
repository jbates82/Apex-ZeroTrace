//! Destruction: authorization, cryptographic erasure, and reporting.
//!
//! # The order that matters
//!
//! The wrapped master key is destroyed *first*, before the container is
//! removed. Forty-eight bytes are what stand between the ciphertext and
//! meaning; once they are gone, every copy of the container anywhere becomes
//! equally useless, including copies this machine cannot reach. Removing the
//! file first and being interrupted would leave the key intact on a snapshot.
//!
//! # Failure posture inverts at commitment
//!
//! Before a [`DestructionAuthorization`] is committed, any error protects the
//! vault: nothing is touched. After it is committed, errors no longer abort.
//! Stopping halfway would leave a vault that a restart might treat as healthy,
//! so the process continues as far as it technically can and reports what it
//! actually achieved.

#![forbid(unsafe_code)]

use std::path::{Path, PathBuf};

use zerotrace_core::state::DeadmanState;
use zerotrace_core::time::TimeAnchor;
use zerotrace_core::{Assurance, Error, Result, VaultId};
use zerotrace_format::{HEADER_LEN, WRAPPED_KEY_LEN};
use zerotrace_journal::{AuditAnchor, JournalStatus, StateJournal};
use zerotrace_platform::sanitizer as platform_sanitizer;
use zerotrace_sanitize::SanitizationProfile;

/// Byte range of the wrapped master key inside the header.
const WRAPPED_KEY_RANGE: std::ops::Range<usize> = 104..104 + WRAPPED_KEY_LEN;

/// A committed decision to destroy a vault.
///
/// Binding the policy and the journal position means an authorization taken
/// from one vault cannot be replayed against another, and cannot be detached
/// from the state that produced it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DestructionAuthorization {
    pub vault_id: VaultId,
    pub authorized_at: TimeAnchor,
    pub journal_sequence: u64,
    pub reason: String,
}

/// Why destruction was authorized. Recorded so a report can never imply a
/// deadline expiry when a human pressed the button, or the reverse.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Trigger {
    /// The deadman deadline passed.
    DeadlineExpired,
    /// A human explicitly asked, with confirmation.
    PanicDestroy,
}

impl Trigger {
    pub fn label(&self) -> &'static str {
        match self {
            Trigger::DeadlineExpired => "deadman deadline expired",
            Trigger::PanicDestroy => "explicit panic destroy",
        }
    }
}

/// What a destruction run actually achieved.
#[derive(Debug, Clone)]
pub struct DestructionReport {
    pub vault_id: VaultId,
    pub trigger: String,
    pub profile: SanitizationProfile,
    pub authorization: Assurance,
    pub key_erasure: Assurance,
    pub key_erasure_note: String,
    pub container_removal: Assurance,
    pub snapshots_detected: usize,
    pub snapshots_removed: usize,
    pub snapshot_note: String,
    pub filesystem_sanitization: Assurance,
    pub filesystem_note: String,
    pub free_space: Assurance,
    pub free_space_note: String,
}

/// Overall confidence, derived from the parts rather than asserted.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OverallAssurance {
    High,
    Moderate,
    Low,
}

impl OverallAssurance {
    pub fn label(&self) -> &'static str {
        match self {
            OverallAssurance::High => "HIGH",
            OverallAssurance::Moderate => "MODERATE",
            OverallAssurance::Low => "LOW",
        }
    }
}

impl DestructionReport {
    /// Overall assurance is governed by cryptographic erasure alone.
    ///
    /// Secondary measures cannot raise it: no amount of overwriting
    /// compensates for a key that still exists. And they cannot lower it
    /// either: a destroyed key makes the ciphertext meaningless whether or not
    /// free space was scrubbed.
    pub fn overall(&self) -> OverallAssurance {
        match (self.key_erasure, self.container_removal) {
            (Assurance::Verified, Assurance::Verified) => OverallAssurance::High,
            (Assurance::Verified, _) => OverallAssurance::Moderate,
            _ => OverallAssurance::Low,
        }
    }

    pub fn render(&self) -> String {
        let mut s = String::new();
        s.push_str("APEX ZEROTRACE DESTRUCTION REPORT\n\n");
        s.push_str(&format!("Vault                     {}\n", self.vault_id));
        s.push_str(&format!("Trigger                   {}\n", self.trigger));
        s.push_str(&format!("Profile                   {}\n\n", self.profile.label()));
        s.push_str(&format!("Destruction Authorization {}\n", self.authorization.label()));
        s.push_str(&format!("Cryptographic Erasure     {}\n", self.key_erasure.label()));
        s.push_str(&format!("Vault Container Removal   {}\n", self.container_removal.label()));
        s.push_str(&format!(
            "Snapshots                 {} detected, {} removed ({})\n",
            self.snapshots_detected,
            self.snapshots_removed,
            self.snapshot_note_status()
        ));
        s.push_str(&format!("Filesystem Sanitization   {}\n", self.filesystem_sanitization.label()));
        s.push_str(&format!("Free-Space Sanitization   {}\n\n", self.free_space.label()));
        s.push_str(&format!("Overall Assurance         {}\n\n", self.overall().label()));
        s.push_str("Notes\n");
        s.push_str(&format!("  Keys        {}\n", self.key_erasure_note));
        s.push_str(&format!("  Snapshots   {}\n", self.snapshot_note));
        s.push_str(&format!("  Filesystem  {}\n", self.filesystem_note));
        s.push_str(&format!("  Free space  {}\n", self.free_space_note));
        s.push_str(
            "\nThis report describes this device only. Independent copies of the vault \
             elsewhere are unaffected by the container removal above, but they are \
             equally unreadable once the key is destroyed.\n",
        );
        s
    }

    fn snapshot_note_status(&self) -> &'static str {
        if self.snapshots_detected == 0 && self.snapshot_note.contains("not implemented") {
            "NOT IMPLEMENTED"
        } else {
            "reported"
        }
    }
}

/// Commits the decision to destroy.
///
/// This is the point of no return, and it is deliberately separate from doing
/// any destroying: if the process dies immediately afterwards, the journal
/// still says destruction was authorized, and the next run resumes.
pub fn authorize(
    journal: &mut StateJournal,
    vault_id: VaultId,
    now: TimeAnchor,
    trigger: Trigger,
    audit: AuditAnchor,
) -> Result<DestructionAuthorization> {
    // Refuse to act on a journal that has been tampered with. Blindly
    // destroying because the state file looks odd is exactly the denial of
    // service an attacker would want.
    match journal.verify()? {
        JournalStatus::Intact { .. } => {}
        JournalStatus::Broken { at_sequence, reason } => {
            return Err(Error::Integrity(format!(
                "refusing to authorize destruction: the state journal is broken at record \
                 {at_sequence} ({reason})"
            )))
        }
    }

    let state = journal.state();
    if state.is_committed() {
        return Err(Error::Other(
            "destruction has already been authorized for this vault".into(),
        ));
    }
    if state != DeadmanState::Armed {
        return Err(Error::InvalidTransition {
            from: state.label(),
            to: DeadmanState::DestructionAuthorized.label(),
        });
    }

    let rec = journal.record(DeadmanState::DestructionAuthorized, now, 0, 0, audit)?;

    Ok(DestructionAuthorization {
        vault_id,
        authorized_at: now,
        journal_sequence: rec.sequence,
        reason: trigger.label().to_string(),
    })
}

/// Authorizes destruction requested explicitly by a person.
///
/// A deadline-driven authorization requires the journal to already be ARMED,
/// because reaching that state is the evidence. An explicit request has
/// different evidence: a human confirmed it. The journal is still walked
/// through every intermediate state so the record shows what happened, and the
/// trigger recorded is `PanicDestroy` so no report can later imply a deadline
/// expired.
pub fn authorize_explicit(
    journal: &mut StateJournal,
    vault_id: VaultId,
    now: TimeAnchor,
    audit: AuditAnchor,
) -> Result<DestructionAuthorization> {
    match journal.verify()? {
        JournalStatus::Intact { .. } => {}
        JournalStatus::Broken { at_sequence, reason } => {
            return Err(Error::Integrity(format!(
                "refusing to authorize destruction: the state journal is broken at record                  {at_sequence} ({reason})"
            )))
        }
    }
    if journal.state().is_committed() {
        return Err(Error::Other("destruction has already been authorized".into()));
    }

    for step in [DeadmanState::Warning, DeadmanState::Critical, DeadmanState::Armed] {
        if journal.state() < step {
            journal.record(step, now, 0, 0, audit)?;
        }
    }
    authorize(journal, vault_id, now, Trigger::PanicDestroy, audit)
}

/// Carries out destruction, resuming from wherever the journal left off.
///
/// Safe to call repeatedly: each stage checks whether it has already happened.
pub fn execute(
    vault_path: &Path,
    journal: &mut StateJournal,
    profile: SanitizationProfile,
    trigger: Trigger,
    now: TimeAnchor,
) -> Result<DestructionReport> {
    if !journal.state().is_committed() {
        return Err(Error::Other(
            "destruction has not been authorized; refusing to erase anything".into(),
        ));
    }

    let vault_id = journal
        .records()?
        .last()
        .map(|r| r.vault_id)
        .unwrap_or_else(VaultId::nil);

    let mut report = DestructionReport {
        vault_id,
        trigger: trigger.label().to_string(),
        profile,
        authorization: Assurance::Verified,
        key_erasure: Assurance::NotAttempted,
        key_erasure_note: String::new(),
        container_removal: Assurance::NotAttempted,
        snapshots_detected: 0,
        snapshots_removed: 0,
        snapshot_note: String::new(),
        filesystem_sanitization: Assurance::NotAttempted,
        filesystem_note: String::new(),
        free_space: Assurance::NotAttempted,
        free_space_note: String::new(),
    };

    // From here failures are recorded, not propagated: stopping would leave a
    // half-destroyed vault behind.
    let sanitizer = platform_sanitizer();

    // Stage 1: cryptographic erasure.
    if journal.state() == DeadmanState::DestructionAuthorized {
        let _ = journal.record(DeadmanState::KeyErasure, now, 0, 0, AuditAnchor::default());
    }
    let (a, note) = erase_key_material(vault_path);
    report.key_erasure = a;
    report.key_erasure_note = note;

    // Stage 2: container removal, with an optional overwrite first.
    if journal.state() == DeadmanState::KeyErasure {
        let _ = journal.record(DeadmanState::VaultErasure, now, 0, 0, AuditAnchor::default());
    }
    if profile.overwrites_container() && vault_path.exists() {
        let (a, note) = sanitizer.overwrite_in_place(vault_path);
        report.filesystem_sanitization = a;
        report.filesystem_note = note;
    } else {
        report.filesystem_sanitization = Assurance::NotAttempted;
        report.filesystem_note =
            "the selected profile does not overwrite the container".into();
    }
    // The split bundle holds sealed shares of this vault's release key. It is
    // key material for a container that is being destroyed, so it goes with
    // it. A copy of the vault taken beforehand needs its own copy of the
    // bundle, which is stated in the documentation.
    let bundle = PathBuf::from(format!("{}.split", vault_path.display()));
    if bundle.exists() {
        if profile.overwrites_container() {
            let _ = sanitizer.overwrite_in_place(&bundle);
        }
        let _ = std::fs::remove_file(&bundle);
    }

    report.container_removal = match std::fs::remove_file(vault_path) {
        Ok(()) if !vault_path.exists() => Assurance::Verified,
        Ok(()) => Assurance::BestEffort,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Assurance::Verified,
        Err(_) => Assurance::Failed,
    };

    // Stage 3: platform sanitization.
    if journal.state() == DeadmanState::VaultErasure {
        let _ =
            journal.record(DeadmanState::PlatformSanitization, now, 0, 0, AuditAnchor::default());
    }
    if profile.handles_snapshots() {
        let (n, a, note) = sanitizer.detect_snapshots(vault_path);
        report.snapshots_detected = n;
        report.snapshot_note = note;
        if a == Assurance::Verified && n > 0 {
            let (removed, _, _) = sanitizer.remove_snapshots(vault_path);
            report.snapshots_removed = removed;
        }
    } else {
        report.snapshot_note = "the selected profile does not handle snapshots".into();
    }
    if profile.handles_free_space() {
        let (a, note) = sanitizer.sanitize_free_space(vault_path);
        report.free_space = a;
        report.free_space_note = note;
    } else {
        report.free_space = Assurance::NotAttempted;
        report.free_space_note = "the selected profile does not sanitize free space".into();
    }

    // Stage 4: verification, then terminal.
    if journal.state() == DeadmanState::PlatformSanitization {
        let _ = journal.record(DeadmanState::Verification, now, 0, 0, AuditAnchor::default());
    }
    if journal.state() == DeadmanState::Verification {
        let _ = journal.record(DeadmanState::Destroyed, now, 0, 0, AuditAnchor::default());
    }

    Ok(report)
}

/// Overwrites the wrapped master key in place, then confirms it is gone.
///
/// Verification here is genuine and worth stating precisely: the bytes are
/// read back and compared, so `Verified` means the wrapped key is no longer
/// present *in this file*. It does not mean no copy of those 48 bytes exists
/// anywhere on the device, which is why the report says what it says.
fn erase_key_material(vault_path: &Path) -> (Assurance, String) {
    use std::io::{Read, Seek, SeekFrom, Write};

    if !vault_path.exists() {
        return (
            Assurance::NotAttempted,
            "the container was already absent; no key material could be reached".into(),
        );
    }

    let before = match read_wrapped_key(vault_path) {
        Ok(k) => k,
        Err(e) => return (Assurance::Failed, format!("could not read the header: {e}")),
    };

    let mut replacement = [0u8; WRAPPED_KEY_LEN];
    rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut replacement);

    let write = (|| -> Result<()> {
        let mut f = std::fs::OpenOptions::new().read(true).write(true).open(vault_path)?;
        f.seek(SeekFrom::Start(WRAPPED_KEY_RANGE.start as u64))?;
        f.write_all(&replacement)?;
        f.flush()?;
        // Without this the erasure may exist only in the page cache, and a
        // power failure a moment later would leave the key intact.
        f.sync_all()?;
        let mut check = [0u8; WRAPPED_KEY_LEN];
        f.seek(SeekFrom::Start(WRAPPED_KEY_RANGE.start as u64))?;
        f.read_exact(&mut check)?;
        if check != replacement {
            return Err(Error::Integrity("the overwrite did not take effect".into()));
        }
        Ok(())
    })();

    match write {
        Err(e) => (Assurance::Failed, format!("key erasure failed: {e}")),
        Ok(()) => {
            let after = read_wrapped_key(vault_path).unwrap_or([0u8; WRAPPED_KEY_LEN]);
            if after == before {
                (Assurance::Failed, "the wrapped key is unchanged on disk".into())
            } else {
                (
                    Assurance::Verified,
                    "the wrapped master key was overwritten and the change confirmed by \
                     reading it back. The container is now undecryptable with any password. \
                     This confirms the key is gone from this file, not that no copy of those \
                     48 bytes survives elsewhere on the device."
                        .into(),
                )
            }
        }
    }
}

fn read_wrapped_key(path: &Path) -> Result<[u8; WRAPPED_KEY_LEN]> {
    use std::io::Read;
    let mut f = std::fs::File::open(path)?;
    let mut hb = [0u8; HEADER_LEN];
    f.read_exact(&mut hb)?;
    let mut k = [0u8; WRAPPED_KEY_LEN];
    k.copy_from_slice(&hb[WRAPPED_KEY_RANGE]);
    Ok(k)
}

/// Whether an interrupted destruction must be resumed.
///
/// Called at startup. A vault whose journal is past authorization but not yet
/// terminal was interrupted, and continuing is the only correct action:
/// reverting would resurrect a vault whose destruction was already committed.
pub fn needs_resume(journal: &StateJournal) -> bool {
    let s = journal.state();
    s.is_committed() && !s.is_terminal()
}

/// A dry run: what would happen, touching nothing.
pub fn simulate(vault_path: &Path, profile: SanitizationProfile) -> Vec<(String, String)> {
    let exists = vault_path.exists();
    vec![
        ("Timer expiration".into(), "state reaches ARMED".into()),
        (
            "Destruction authorization".into(),
            "a DESTRUCTION_AUTHORIZED record is committed to the journal; from this point \
             the process resumes after any interruption"
                .into(),
        ),
        (
            "Cryptographic erasure".into(),
            if exists {
                "the 48-byte wrapped master key in the header is overwritten with random \
                 bytes, flushed, and read back to confirm"
                    .into()
            } else {
                "the container is absent, so no key material could be reached".to_string()
            },
        ),
        (
            "Container removal".into(),
            if profile.overwrites_container() {
                "the container is overwritten with random bytes, then unlinked".into()
            } else {
                "the container is unlinked".to_string()
            },
        ),
        (
            "Snapshot handling".into(),
            if profile.handles_snapshots() {
                "snapshot detection would run, but no provider is implemented, so it will \
                 report NOT IMPLEMENTED rather than zero snapshots"
                    .into()
            } else {
                "not attempted by this profile".to_string()
            },
        ),
        (
            "Free-space sanitization".into(),
            if profile.handles_free_space() {
                "not supported on this platform; will report NOT SUPPORTED".into()
            } else {
                "not attempted by this profile".to_string()
            },
        ),
        (
            "Verification".into(),
            "the report states what was observed. Nothing in the vault, its backups, or \
             copies on other devices is restored by any means afterwards"
                .into(),
        ),
    ]
}

/// Sidecar paths a destroyed vault leaves behind.
pub fn sidecar_paths(vault_path: &Path) -> Vec<PathBuf> {
    let s = vault_path.to_string_lossy().into_owned();
    vec![PathBuf::from(format!("{s}.audit")), PathBuf::from(format!("{s}.journal"))]
}
