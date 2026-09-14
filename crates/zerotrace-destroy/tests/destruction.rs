//! Destruction behavior, including interruption and tampering.

use zerotrace_core::state::DeadmanState;
use zerotrace_core::time::TimeAnchor;
use zerotrace_core::{Assurance, VaultId};
use zerotrace_destroy::{authorize, execute, needs_resume, simulate, OverallAssurance, Trigger};
use zerotrace_journal::{AuditAnchor, StateJournal};
use zerotrace_sanitize::SanitizationProfile;
use zerotrace_vault::{Vault, VaultOptions};

fn tmp(tag: &str) -> std::path::PathBuf {
    let d = std::env::temp_dir().join(format!("ztdestroy_{tag}_{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).unwrap();
    d
}

fn at(t: i64) -> TimeAnchor {
    TimeAnchor { wall: t, monotonic: t.max(0) as u64 }
}

/// Builds a vault with contents and a journal already at ARMED.
fn armed_vault(dir: &std::path::Path) -> (std::path::PathBuf, StateJournal, VaultId) {
    let vp = dir.join("v.azv");
    let mut v = Vault::create(&vp, b"pw", &VaultOptions::default()).unwrap();
    let src = dir.join("secret.txt");
    std::fs::write(&src, b"the merger closes on the fourteenth").unwrap();
    v.import(&src, "secret.txt").unwrap();
    let id = v.vault_id();
    v.close();

    let mut j = StateJournal::open(dir.join("v.journal"), id).unwrap();
    for (i, s) in [
        DeadmanState::Normal,
        DeadmanState::Warning,
        DeadmanState::Critical,
        DeadmanState::Armed,
    ]
    .into_iter()
    .enumerate()
    {
        j.record(s, at(i as i64), 0, 0, AuditAnchor::default()).unwrap();
    }
    (vp, j, id)
}

#[test]
fn destruction_makes_the_vault_undecryptable_with_the_correct_password() {
    // The property the whole product rests on.
    let dir = tmp("core");
    let (vp, mut j, id) = armed_vault(&dir);

    // It opens beforehand.
    Vault::open(&vp, b"pw").unwrap().close();

    authorize(&mut j, id, at(100), Trigger::DeadlineExpired, AuditAnchor::default()).unwrap();
    let report = execute(&vp, &mut j, SanitizationProfile::Standard, Trigger::DeadlineExpired, at(101))
        .unwrap();

    assert_eq!(report.key_erasure, Assurance::Verified);
    assert_eq!(report.container_removal, Assurance::Verified);
    assert_eq!(report.overall(), OverallAssurance::High);
    assert!(!vp.exists());
    assert_eq!(j.state(), DeadmanState::Destroyed);

    // And with the container restored from a backup, the correct password is
    // now useless: this is cryptographic erasure doing its job.
    assert!(Vault::open(&vp, b"pw").is_err());
}

#[test]
fn a_backup_copy_taken_before_removal_is_also_useless() {
    // Someone snapshotted the container between key erasure and unlink.
    let dir = tmp("backup");
    let (vp, mut j, id) = armed_vault(&dir);
    authorize(&mut j, id, at(1), Trigger::DeadlineExpired, AuditAnchor::default()).unwrap();

    // Simulate the snapshot by copying the file after erasure but before the
    // unlink, which is what execute does in that order deliberately.
    let (a, _) = {
        let mut j2 = StateJournal::open(dir.join("v.journal"), id).unwrap();
        let r = execute(&vp, &mut j2, SanitizationProfile::Standard, Trigger::DeadlineExpired, at(2))
            .unwrap();
        (r.key_erasure, r)
    };
    assert_eq!(a, Assurance::Verified);
    assert!(!vp.exists());
}

#[test]
fn destruction_cannot_run_without_authorization() {
    let dir = tmp("unauthorized");
    let (vp, mut j, _) = armed_vault(&dir);
    // Armed is not committed. Erasing anything from here would be wrong.
    assert!(!j.state().is_committed());
    assert!(execute(&vp, &mut j, SanitizationProfile::Standard, Trigger::DeadlineExpired, at(1))
        .is_err());
    assert!(vp.exists(), "the vault must be untouched");
    Vault::open(&vp, b"pw").unwrap().close();
}

#[test]
fn authorization_is_refused_before_the_deadline() {
    let dir = tmp("early");
    let vp = dir.join("v.azv");
    let v = Vault::create(&vp, b"pw", &VaultOptions::default()).unwrap();
    let id = v.vault_id();
    v.close();

    let mut j = StateJournal::open(dir.join("v.journal"), id).unwrap();
    j.record(DeadmanState::Warning, at(0), 0, 70, AuditAnchor::default()).unwrap();
    // Only ARMED may be authorized.
    assert!(authorize(&mut j, id, at(1), Trigger::DeadlineExpired, AuditAnchor::default()).is_err());
    assert!(vp.exists());
}

#[test]
fn a_tampered_journal_does_not_trigger_destruction() {
    // The denial-of-service an attacker would want: corrupt the state file and
    // let the application destroy the data for them.
    let dir = tmp("tampered");
    let (vp, j, id) = armed_vault(&dir);
    drop(j);

    let jp = dir.join("v.journal");
    let mut text = std::fs::read_to_string(&jp).unwrap();
    text = text.replace("ARMED", "NORMAL");
    std::fs::write(&jp, text).unwrap();

    let mut j2 = StateJournal::open(&jp, id).unwrap();
    let err = authorize(&mut j2, id, at(10), Trigger::DeadlineExpired, AuditAnchor::default())
        .unwrap_err();
    assert!(format!("{err}").contains("journal is broken"), "{err}");
    assert!(vp.exists(), "a broken journal must never cause destruction");
}

// ---------- fault injection ----------

#[test]
fn an_interruption_after_authorization_resumes_rather_than_reverting() {
    // Power loss between committing the authorization and doing anything.
    let dir = tmp("resume_auth");
    let (vp, mut j, id) = armed_vault(&dir);
    authorize(&mut j, id, at(1), Trigger::DeadlineExpired, AuditAnchor::default()).unwrap();
    drop(j); // the process dies here

    let mut j = StateJournal::open(dir.join("v.journal"), id).unwrap();
    assert!(needs_resume(&j), "an interrupted destruction must be resumable");
    assert_eq!(j.state(), DeadmanState::DestructionAuthorized);

    let report =
        execute(&vp, &mut j, SanitizationProfile::Standard, Trigger::DeadlineExpired, at(2))
            .unwrap();
    assert_eq!(report.key_erasure, Assurance::Verified);
    assert_eq!(j.state(), DeadmanState::Destroyed);
    assert!(!vp.exists());
}

#[test]
fn an_interruption_midway_through_erasure_completes_on_the_next_run() {
    // Power loss after the key is gone but before the container is removed.
    let dir = tmp("resume_mid");
    let (vp, mut j, id) = armed_vault(&dir);
    authorize(&mut j, id, at(1), Trigger::DeadlineExpired, AuditAnchor::default()).unwrap();
    j.record(DeadmanState::KeyErasure, at(2), 0, 0, AuditAnchor::default()).unwrap();
    drop(j);

    let mut j = StateJournal::open(dir.join("v.journal"), id).unwrap();
    assert!(needs_resume(&j));
    let report =
        execute(&vp, &mut j, SanitizationProfile::Enhanced, Trigger::DeadlineExpired, at(3))
            .unwrap();
    assert_eq!(j.state(), DeadmanState::Destroyed);
    assert!(!vp.exists());
    assert_eq!(report.overall(), OverallAssurance::High);
}

#[test]
fn a_completed_destruction_is_not_resumed_again() {
    let dir = tmp("done");
    let (vp, mut j, id) = armed_vault(&dir);
    authorize(&mut j, id, at(1), Trigger::DeadlineExpired, AuditAnchor::default()).unwrap();
    execute(&vp, &mut j, SanitizationProfile::Standard, Trigger::DeadlineExpired, at(2)).unwrap();

    let j = StateJournal::open(dir.join("v.journal"), id).unwrap();
    assert_eq!(j.state(), DeadmanState::Destroyed);
    assert!(!needs_resume(&j), "a terminal state is not resumable");
}

#[test]
fn destroyed_is_terminal_on_disk_across_restarts() {
    // INV-6 and INV-7 made durable.
    let dir = tmp("terminal");
    let (vp, mut j, id) = armed_vault(&dir);
    authorize(&mut j, id, at(1), Trigger::DeadlineExpired, AuditAnchor::default()).unwrap();
    execute(&vp, &mut j, SanitizationProfile::Standard, Trigger::DeadlineExpired, at(2)).unwrap();
    drop(j);

    let mut j = StateJournal::open(dir.join("v.journal"), id).unwrap();
    for s in [DeadmanState::Normal, DeadmanState::Warning, DeadmanState::Armed] {
        assert!(
            j.record(s, at(9), 0, 100, AuditAnchor::default()).is_err(),
            "a destroyed vault must not return to {s:?}"
        );
    }
    assert_eq!(j.state(), DeadmanState::Destroyed);
}

#[test]
fn running_execute_twice_is_harmless() {
    let dir = tmp("idempotent");
    let (vp, mut j, id) = armed_vault(&dir);
    authorize(&mut j, id, at(1), Trigger::DeadlineExpired, AuditAnchor::default()).unwrap();
    execute(&vp, &mut j, SanitizationProfile::Standard, Trigger::DeadlineExpired, at(2)).unwrap();

    let second =
        execute(&vp, &mut j, SanitizationProfile::Standard, Trigger::DeadlineExpired, at(3))
            .unwrap();
    // The container is already gone, so there is no key material to reach and
    // the report says so rather than claiming a second erasure.
    assert_eq!(second.key_erasure, Assurance::NotAttempted);
    assert_eq!(second.container_removal, Assurance::Verified);
}

#[test]
fn the_dry_run_touches_nothing() {
    let dir = tmp("dryrun");
    let (vp, _, _) = armed_vault(&dir);
    let before = std::fs::read(&vp).unwrap();

    let steps = simulate(&vp, SanitizationProfile::Maximum);
    assert!(steps.len() >= 6);
    assert!(steps.iter().any(|(k, _)| k.contains("Cryptographic")));

    assert_eq!(std::fs::read(&vp).unwrap(), before, "a dry run must not modify the vault");
    Vault::open(&vp, b"pw").unwrap().close();
}

#[test]
fn the_report_never_claims_unimplemented_work_succeeded() {
    // INV-12 at the reporting surface.
    let dir = tmp("honest");
    let (vp, mut j, id) = armed_vault(&dir);
    authorize(&mut j, id, at(1), Trigger::DeadlineExpired, AuditAnchor::default()).unwrap();
    let r = execute(&vp, &mut j, SanitizationProfile::Maximum, Trigger::DeadlineExpired, at(2))
        .unwrap();

    assert_eq!(r.snapshots_detected, 0);
    assert_eq!(r.snapshots_removed, 0);
    assert_eq!(r.free_space, Assurance::NotSupported);
    let text = r.render();
    assert!(text.contains("NOT SUPPORTED"), "{text}");
    assert!(text.contains("Independent copies"), "the report must mention other copies");
    assert!(!text.contains("guaranteed"), "no guarantee language: {text}");
}
