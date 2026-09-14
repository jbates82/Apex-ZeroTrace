//! The rules the GUI boundary must enforce regardless of what the front end sends.

use zerotrace_ipc::{capabilities, Session, DESTROY_CONFIRMATION};
use zerotrace_policy::DeadmanPolicy;
use zerotrace_vault::VaultOptions;

/// Fixtures use a password that meets the floor, because creating a vault now
/// enforces it. The rule is only applied when a password is chosen.
const PW: &str = "correct-horse-battery-staple";

fn tmp(tag: &str) -> std::path::PathBuf {
    let d = std::env::temp_dir().join(format!("ztipc_{tag}_{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).unwrap();
    d
}

fn seeded(dir: &std::path::Path) -> Session {
    let s = Session::new(dir.join("v.azv"));
    s.create(PW, &VaultOptions::default()).unwrap();
    let src = dir.join("secret.txt");
    std::fs::write(&src, b"the merger closes on the fourteenth").unwrap();
    s.import(PW, &src, "secret.txt").unwrap();
    s
}

#[test]
fn a_summary_carries_no_secret_material() {
    // The front end receives this and may log it, cache it, or render it.
    let dir = tmp("nosecrets");
    let s = seeded(&dir);
    let summary = s.unlock(PW).unwrap();
    let json = format!("{summary:?}");

    for forbidden in [PW, "merger", "fourteenth"] {
        assert!(!json.contains(forbidden), "summary leaked {forbidden}: {json}");
    }
    assert_eq!(summary.entry_count, 1);
    assert_eq!(summary.crypto_suite, "XChaCha20-Poly1305");
}

#[test]
fn a_wrong_password_is_refused_and_recorded() {
    let dir = tmp("wrongpw");
    let s = seeded(&dir);
    assert!(s.unlock("wrong").is_err());
    assert!(s.list("wrong").is_err());
    assert!(s.verify("wrong").is_err());

    let audit = s.audit_tail(50).unwrap();
    assert!(audit.iter().any(|e| e.event == "AUTH_FAILURE"), "failure not recorded");
}

#[test]
fn the_gui_cannot_configure_a_dangerous_policy() {
    // INV-8. Every one of these is refused by validation, not by the caller
    // remembering to check.
    let dir = tmp("policy");
    let s = seeded(&dir);

    let too_short = DeadmanPolicy { enabled: true, timeout_seconds: 30, ..Default::default() };
    assert!(s.save_policy(&too_short).is_err());

    let ambient_satisfiable = DeadmanPolicy {
        enabled: true,
        required_confidence: 40,
        warning_threshold: 20,
        critical_threshold: 10,
        ..Default::default()
    };
    assert!(s.save_policy(&ambient_satisfiable).is_err());

    let unsatisfiable = DeadmanPolicy {
        enabled: true,
        timeout_seconds: 7200,
        heartbeat_seconds: 100_000,
        ..Default::default()
    };
    assert!(s.save_policy(&unsatisfiable).is_err());

    // Nothing was written, so the effective policy is still the safe default.
    assert!(!s.load_policy().enabled);
}

#[test]
fn a_valid_policy_round_trips() {
    let dir = tmp("policyok");
    let s = seeded(&dir);
    let p = DeadmanPolicy { enabled: true, timeout_seconds: 7200, heartbeat_seconds: 3600, ..Default::default() };
    s.save_policy(&p).unwrap();
    let loaded = s.load_policy();
    assert!(loaded.enabled);
    assert_eq!(loaded.timeout_seconds, 7200);
}

#[test]
fn a_corrupt_policy_file_falls_back_to_disabled() {
    let dir = tmp("policycorrupt");
    let s = seeded(&dir);
    std::fs::write(dir.join("v.azv.policy"), "enabled = true\ntimeout_seconds = 5\n").unwrap();
    // Five seconds is below the floor, so the file is not honoured at all.
    assert!(!s.load_policy().enabled);
}

#[test]
fn destruction_requires_the_exact_confirmation() {
    let dir = tmp("confirm");
    let s = seeded(&dir);

    for wrong in ["", "destroy", "DESTROY ", "yes", "DELETE"] {
        assert!(s.panic_destroy(PW, wrong).is_err(), "{wrong:?} was accepted");
        assert!(s.vault_path().exists(), "vault touched by a refused confirmation");
    }
    // And a right confirmation with a wrong password is still refused.
    assert!(s.panic_destroy("wrong", DESTROY_CONFIRMATION).is_err());
    assert!(s.vault_path().exists());
}

#[test]
fn panic_lock_never_destroys_anything() {
    let dir = tmp("paniclock");
    let s = seeded(&dir);
    let rows = s.panic_lock();
    assert!(rows.iter().any(|r| r.assurance == "UNTOUCHED"));
    assert!(s.vault_path().exists());
    assert_eq!(s.list(PW).unwrap().len(), 1);
}

#[test]
fn the_dry_run_changes_nothing() {
    let dir = tmp("dryrun");
    let s = seeded(&dir);
    let before = std::fs::read(s.vault_path()).unwrap();
    let steps = s.dry_run();
    assert!(steps.len() >= 6);
    assert_eq!(std::fs::read(s.vault_path()).unwrap(), before);
}

#[test]
fn confirmed_destruction_makes_the_vault_unopenable() {
    let dir = tmp("destroy");
    let s = seeded(&dir);
    let report = s.panic_destroy(PW, DESTROY_CONFIRMATION).unwrap();
    assert!(report.contains("Cryptographic Erasure     VERIFIED"), "{report}");
    assert!(!s.vault_path().exists());
    assert!(s.unlock(PW).is_err());

    let status = s.deadman_status().unwrap();
    assert!(status.terminal);
    assert_eq!(status.recorded_state, "DESTROYED");
}

#[test]
fn a_check_in_raises_confidence_and_needs_the_password() {
    let dir = tmp("checkin");
    let s = seeded(&dir);
    assert!(s.check_in("wrong").is_err(), "a check-in must cost a credential");
    let status = s.check_in(PW).unwrap();
    assert_eq!(status.confidence, 100);
    assert_eq!(status.state, "NORMAL");
}

#[test]
fn the_capability_table_never_overstates_this_build() {
    let caps = capabilities();
    let find = |n: &str| caps.iter().find(|c| c.name == n).expect(n);
    assert_eq!(find("FIDO2 transport").assurance, "NOT IMPLEMENTED");
    assert_eq!(find("Snapshot handling").assurance, "NOT IMPLEMENTED");
    assert_eq!(find("Free-space sanitization").assurance, "NOT SUPPORTED");
    assert_eq!(find("Container overwrite").assurance, "BEST EFFORT");
    assert_eq!(find("Cryptographic erasure").assurance, "VERIFIED");
    // Nothing may claim a guarantee.
    for c in &caps {
        assert!(!c.note.to_lowercase().contains("guarantee"), "{}", c.name);
    }
}

#[test]
fn chain_status_reports_audit_truncation() {
    let dir = tmp("chain");
    let s = seeded(&dir);
    s.check_in(PW).unwrap();

    let before = s.chain_status().unwrap();
    assert_eq!(before.audit_chain, "VERIFIED");

    // Remove the tail of the audit log.
    let ap = dir.join("v.azv.audit");
    let text = std::fs::read_to_string(&ap).unwrap();
    let kept: Vec<&str> = text.lines().take(2).collect();
    std::fs::write(&ap, kept.join("\n") + "\n").unwrap();

    let after = s.chain_status().unwrap();
    assert_eq!(after.audit_chain, "VERIFIED", "a prefix is still a valid chain");
    assert_eq!(after.audit_anchor, "FAILED", "the journal must notice the missing tail");
    assert!(after.detail.contains("journal recorded"), "{}", after.detail);
}

// ---------- split protection through the IPC boundary ----------

#[test]
fn the_boundary_reports_split_status_before_and_after_enrolment() {
    let dir = tmp("ipcsplit");
    let s = seeded(&dir);

    let before = s.split_status().unwrap();
    assert!(!before.enrolled);
    assert!(
        before.notes.iter().any(|n| n.contains("offline")),
        "an unenrolled vault must say what that means: {:?}",
        before.notes
    );

    let token = dir.join("token.txt");
    let custodian = dir.join("custodian.txt");
    let after = s.enroll_split(PW, &token, Some(&custodian)).unwrap();
    assert!(after.enrolled);
    assert_eq!(after.threshold, 2);
    assert_eq!(after.components.len(), 3);
    assert!(after.tolerates_one_loss);
    assert!(after.resists_drive_theft);
    assert!(token.exists() && custodian.exists());
}

#[test]
fn a_split_vault_cannot_be_opened_through_the_boundary_without_a_token() {
    let dir = tmp("ipcsplitrefuse");
    let s = seeded(&dir);
    let token = dir.join("token.txt");
    s.enroll_split(PW, &token, Some(&dir.join("custodian.txt"))).unwrap();

    // The password alone, through the same API the window uses.
    let plain = Session::new(dir.join("v.azv"));
    assert!(plain.is_split_protected());
    assert!(plain.unlock(PW).is_err());
    assert!(plain.list(PW).is_err());

    // With a token it opens.
    let with_token = Session::new(dir.join("v.azv")).with_tokens(vec![token.clone()]);
    assert_eq!(with_token.list(PW).unwrap().len(), 1);
}

#[test]
fn both_tokens_open_a_vault_whose_password_was_lost() {
    let dir = tmp("ipcnopw");
    let s = seeded(&dir);
    let token = dir.join("token.txt");
    let custodian = dir.join("custodian.txt");
    s.enroll_split(PW, &token, Some(&custodian)).unwrap();

    let recovered = Session::new(dir.join("v.azv"))
        .with_tokens(vec![token, custodian])
        .without_password();
    // The password passed here is ignored, because the user component is not
    // contributed at all.
    assert_eq!(recovered.list("the password is gone").unwrap().len(), 1);
}

#[test]
fn enrollment_refuses_to_overwrite_an_existing_token() {
    let dir = tmp("ipcoverwrite");
    let s = seeded(&dir);
    let token = dir.join("token.txt");
    std::fs::write(&token, b"something already here").unwrap();
    assert!(s.enroll_split(PW, &token, None).is_err());
    assert_eq!(std::fs::read(&token).unwrap(), b"something already here");
}


#[test]
fn a_split_vault_cannot_be_destroyed_without_its_components() {
    // The counterpart to the unlock test. Enforcement was correct here, but it
    // had never been asserted, and a destructive path is exactly where an
    // untested assumption is most expensive.
    let dir = tmp("ipcdestroyguard");
    let s = seeded(&dir);
    s.enroll_split(PW, &dir.join("token.txt"), Some(&dir.join("cust.txt"))).unwrap();

    let fresh = Session::new(dir.join("v.azv"));
    assert!(fresh.is_split_protected());

    let result = fresh.panic_destroy(PW, DESTROY_CONFIRMATION);
    assert!(result.is_err(), "a split vault was destroyed without its components");
    assert!(fresh.vault_path().exists(), "the container was removed");
    // And it is still openable by someone who does hold a component.
    let ok = Session::new(dir.join("v.azv")).with_tokens(vec![dir.join("token.txt")]);
    assert_eq!(ok.list(PW).unwrap().len(), 1);
}

#[test]
fn destruction_succeeds_once_a_component_is_supplied() {
    let dir = tmp("ipcdestroyok");
    let s = seeded(&dir);
    let token = dir.join("token.txt");
    s.enroll_split(PW, &token, Some(&dir.join("cust.txt"))).unwrap();

    let armed = Session::new(dir.join("v.azv")).with_tokens(vec![token]);
    let report = armed.panic_destroy(PW, DESTROY_CONFIRMATION).unwrap();
    assert!(report.contains("Cryptographic Erasure     VERIFIED"), "{report}");
    assert!(!armed.vault_path().exists());
}

#[test]
fn a_stale_or_wrong_file_does_not_block_a_valid_token() {
    // Reported from testing: attaching the wrong file first, then the right
    // one, left the vault unopenable because the bad path was still in the
    // list and failed the whole attempt.
    let dir = tmp("ipcstale");
    let s = seeded(&dir);
    let token = dir.join("token.txt");
    s.enroll_split(PW, &token, Some(&dir.join("cust.txt"))).unwrap();

    let junk = dir.join("shopping-list.txt");
    std::fs::write(&junk, b"milk, bread, a new drill bit\n").unwrap();

    // Junk alone gets nowhere.
    let only_junk = Session::new(dir.join("v.azv")).with_tokens(vec![junk.clone()]);
    assert!(only_junk.list(PW).is_err());

    // Junk alongside a real token must not poison it.
    let mixed = Session::new(dir.join("v.azv")).with_tokens(vec![junk.clone(), token.clone()]);
    assert_eq!(mixed.list(PW).unwrap().len(), 1, "a stale path blocked a valid token");

    // Order must not matter either.
    let other_order = Session::new(dir.join("v.azv")).with_tokens(vec![token, junk.clone()]);
    assert_eq!(other_order.list(PW).unwrap().len(), 1);

    // A path that does not exist at all is equally harmless.
    let missing = Session::new(dir.join("v.azv"))
        .with_tokens(vec![dir.join("nowhere.txt"), dir.join("token.txt")]);
    assert_eq!(missing.list(PW).unwrap().len(), 1);
}

#[test]
fn a_wrong_file_is_rejected_when_it_is_chosen() {
    let dir = tmp("ipcvalidate");
    let junk = dir.join("notes.txt");
    std::fs::write(&junk, b"just some notes\n").unwrap();
    assert!(zerotrace_ipc::validate_token_file(&junk).is_err());
    assert!(zerotrace_ipc::validate_token_file(&dir.join("absent.txt")).is_err());

    let s = seeded(&dir);
    let token = dir.join("token.txt");
    s.enroll_split(PW, &token, None).unwrap();
    assert!(zerotrace_ipc::validate_token_file(&token).is_ok());
}

#[test]
fn destruction_takes_the_split_bundle_with_it() {
    // The bundle holds sealed shares of this vault's release key. Leaving it
    // behind is leaving key material for a container that no longer exists,
    // and it made the window go on reporting a protection that was gone.
    let dir = tmp("bundlegone");
    let s = seeded(&dir);
    let token = dir.join("token.txt");
    s.enroll_split(PW, &token, Some(&dir.join("cust.txt"))).unwrap();

    let bundle = zerotrace_vault::split_bundle_path(&dir.join("v.azv"));
    assert!(bundle.exists());

    let armed = Session::new(dir.join("v.azv")).with_tokens(vec![token]);
    armed.panic_destroy(PW, DESTROY_CONFIRMATION).unwrap();

    assert!(!armed.vault_path().exists());
    assert!(!bundle.exists(), "the split bundle outlived the vault it protected");

    // And the boundary reports the vault as gone rather than as protected.
    assert!(!armed.split_status().unwrap().enrolled);
}

#[test]
fn a_vault_that_does_not_exist_yet_is_not_reported_as_destroyed() {
    // The window names a vault before creating it. Treating an absent
    // container as a destroyed one made it announce the destruction of a vault
    // the moment its filename was chosen.
    let dir = tmp("notyet");
    let s = Session::new(dir.join("brand-new.azv"));
    let status = s.deadman_status().unwrap();
    assert!(!status.terminal, "an uncreated vault must not look destroyed");
    assert!(!status.committed);
}

#[test]
fn a_new_vault_does_not_inherit_a_destroyed_one_s_journal() {
    // Destroying a vault leaves its journal behind on purpose: it is the
    // record of what happened. A new vault created at the same path must not
    // be reported as destroyed because of it.
    let dir = tmp("reuse");
    let s = seeded(&dir);
    let path = dir.join("v.azv");
    s.panic_destroy(PW, DESTROY_CONFIRMATION).unwrap();
    assert!(s.deadman_status().unwrap().terminal);
    assert!(!path.exists());

    // The journal survives, as designed.
    assert!(dir.join("v.azv.journal").exists());

    // Now create a fresh vault with the same name.
    let fresh = Session::new(&path);
    fresh.create("second-horse-battery-staple", &VaultOptions::default()).unwrap();
    let status = fresh.deadman_status().unwrap();
    assert!(
        !status.terminal,
        "a new vault inherited the journal of the destroyed one before it"
    );
    assert_eq!(fresh.list("second-horse-battery-staple").unwrap().len(), 0);
}

// ---------- password strength and failed attempts ----------

#[test]
fn a_weak_password_is_refused_when_a_vault_is_created() {
    let dir = tmp("weakpw");
    let s = Session::new(dir.join("v.azv"));
    // Passes every symbol-and-digit rule ever written, and is still terrible.
    let err = s.create("P@ssw0rd!", &VaultOptions::default()).unwrap_err();
    assert!(format!("{err}").contains("Too short"), "{err}");
    assert!(!dir.join("v.azv").exists(), "a vault was created with a weak password");

    s.create("correct-horse-battery-staple", &VaultOptions::default()).unwrap();
}

#[test]
fn an_existing_vault_still_opens_with_a_password_below_the_floor() {
    // The floor applies when a password is chosen, never when one is used. A
    // vault made under an older rule must not become unopenable.
    let dir = tmp("oldpw");
    let s = Session::new(dir.join("v.azv"));
    zerotrace_vault::Vault::create(&dir.join("v.azv"), b"short", &VaultOptions::default())
        .unwrap()
        .close();
    assert!(s.unlock("short").is_ok());
}

#[test]
fn failures_are_counted_and_reset_by_a_success() {
    let dir = tmp("failcount");
    let s = seeded(&dir);
    assert_eq!(s.consecutive_failures(), 0);

    for expected in 1..=3 {
        assert!(s.unlock("wrong").is_err());
        assert_eq!(s.consecutive_failures(), expected);
    }
    // Delays grow rather than staying flat.
    assert!(s.attempt_delay() > 0);

    s.unlock(PW).unwrap();
    assert_eq!(s.consecutive_failures(), 0, "a success must clear the count");
    assert_eq!(s.attempt_delay(), 0);
}

#[test]
fn repeated_failures_do_not_destroy_a_vault_by_default() {
    // The default matters more than the feature. A counter that destroys is a
    // weapon anyone with a keyboard can point at the owner.
    let dir = tmp("nodestroy");
    let s = seeded(&dir);
    assert_eq!(s.load_policy().destroy_after_failures, 0);

    for _ in 0..10 {
        assert!(s.unlock("wrong").is_err());
    }
    assert!(s.vault_path().exists(), "the vault was destroyed without being asked to");
    assert_eq!(s.list(PW).unwrap().len(), 1);
}

#[test]
fn a_failure_limit_below_three_is_refused() {
    let dir = tmp("lowlimit");
    let s = seeded(&dir);
    let mut p = s.load_policy();
    p.enabled = true;
    p.destroy_after_failures = 2;
    assert!(s.save_policy(&p).is_err(), "a limit reachable by a typo was accepted");
}

#[test]
fn an_opted_in_limit_destroys_the_vault_when_reached() {
    let dir = tmp("optedin");
    let s = seeded(&dir);
    let mut p = s.load_policy();
    p.enabled = true;
    p.destroy_after_failures = 3;
    s.save_policy(&p).unwrap();

    assert!(s.unlock("wrong").is_err());
    assert!(s.unlock("wrong").is_err());
    assert!(s.vault_path().exists(), "destroyed before the limit");

    let err = s.unlock("wrong").unwrap_err();
    assert!(format!("{err}").contains("has been destroyed"), "{err}");
    assert!(!s.vault_path().exists());
    // And the correct password no longer helps.
    assert!(s.unlock(PW).is_err());
}

#[test]
fn backoff_grows_and_is_capped() {
    use zerotrace_ipc::backoff_seconds;
    assert_eq!(backoff_seconds(0), 0);
    assert_eq!(backoff_seconds(1), 0, "one mistake should not be punished");
    assert!(backoff_seconds(2) > 0);
    assert!(backoff_seconds(4) > backoff_seconds(3));
    assert_eq!(backoff_seconds(50), backoff_seconds(5), "the wait is capped");
}

// ---------- custody through the opening path ----------

#[test]
fn a_custodian_supplies_its_component_when_the_vault_is_opened() {
    // The point of the whole arrangement: a component that is not on this
    // machine still reaches the threshold when the vault is opened.
    let dir = tmp("custodyopen");
    let s = seeded(&dir);
    let token = dir.join("token.txt");
    let custodian_token = dir.join("cust.txt");
    s.enroll_split(PW, &token, Some(&custodian_token)).unwrap();

    let vaultroom = dir.join("elsewhere");
    s.establish_custody(PW, &vaultroom, &custodian_token, 3600).unwrap();
    // The local copy goes, which is the whole point of handing it over.
    std::fs::remove_file(&custodian_token).unwrap();

    // Password plus custodian reaches two of three, with no token file at all.
    let s2 = Session::new(dir.join("v.azv"));
    assert_eq!(s2.list(PW).unwrap().len(), 1);
}

#[test]
fn an_expired_custodian_says_so_rather_than_looking_like_a_wrong_password() {
    let dir = tmp("custodyexpired");
    let s = seeded(&dir);
    let token = dir.join("token.txt");
    let custodian_token = dir.join("cust.txt");
    s.enroll_split(PW, &token, Some(&custodian_token)).unwrap();
    let room = dir.join("elsewhere");
    s.establish_custody(PW, &room, &custodian_token, 3600).unwrap();

    // Force expiry by rewriting the record's deadline into the past.
    let id = s.custody_status();
    assert!(id.established && id.reachable);
    for entry in std::fs::read_dir(&room).unwrap() {
        let p = entry.unwrap().path();
        let text = std::fs::read_to_string(&p).unwrap();
        let aged: String = text
            .lines()
            .map(|l| {
                if l.starts_with("last_check_in=") {
                    "last_check_in=1000".to_string()
                } else {
                    l.to_string()
                }
            })
            .collect::<Vec<_>>()
            .join("\n");
        std::fs::write(&p, aged + "\n").unwrap();
    }

    // The remaining local token still opens it, so the vault is not lost.
    let with_token = Session::new(dir.join("v.azv")).with_tokens(vec![token]);
    assert_eq!(with_token.list(PW).unwrap().len(), 1);

    // But asking the custodian reports expiry plainly.
    let s2 = Session::new(dir.join("v.azv"));
    let err = s2.list(PW).unwrap_err();
    assert!(format!("{err}").contains("expired"), "{err}");
    assert!(s2.custody_status().expired);
}

#[test]
fn an_unreachable_custodian_does_not_stop_a_vault_that_can_open_without_it() {
    let dir = tmp("custodygone");
    let s = seeded(&dir);
    let token = dir.join("token.txt");
    let custodian_token = dir.join("cust.txt");
    s.enroll_split(PW, &token, Some(&custodian_token)).unwrap();
    let room = dir.join("elsewhere");
    s.establish_custody(PW, &room, &custodian_token, 3600).unwrap();

    // The custodian's storage is not mounted today.
    std::fs::remove_dir_all(&room).unwrap();

    let with_token = Session::new(dir.join("v.azv")).with_tokens(vec![token]);
    assert_eq!(with_token.list(PW).unwrap().len(), 1);
    let view = with_token.custody_status();
    assert!(view.established && !view.reachable);
}

#[test]
fn checking_in_with_a_custodian_moves_its_deadline() {
    let dir = tmp("custodycheckin");
    let s = seeded(&dir);
    let token = dir.join("token.txt");
    let custodian_token = dir.join("cust.txt");
    s.enroll_split(PW, &token, Some(&custodian_token)).unwrap();
    s.establish_custody(PW, &dir.join("elsewhere"), &custodian_token, 3600).unwrap();

    let before = s.custody_status().seconds_remaining.unwrap();
    let deadline = s.custodian_check_in(PW).unwrap();
    assert!(deadline > 0);
    let after = s.custody_status().seconds_remaining.unwrap();
    assert!(after >= before.saturating_sub(2), "the deadline did not move");

    // And a wrong password cannot.
    assert!(s.custodian_check_in("wrong-password-entirely-here").is_err());
}

// ---------- duress reaching every path, and leaving nothing ----------

#[test]
fn duress_works_on_a_split_protected_vault() {
    // It did not. The split-key open path never tried the duress identity, so
    // the feature silently did nothing on exactly the vaults most likely to
    // need it: somebody under coercion with a token attached.
    let dir = tmp("duresssplit");
    let s = seeded(&dir);
    let token = dir.join("token.txt");
    s.enroll_split(PW, &token, Some(&dir.join("cust.txt"))).unwrap();

    let decoy = dir.join("shopping.txt");
    std::fs::write(&decoy, b"milk and bread").unwrap();
    // Setting it needs a session that can open the vault, which on a split
    // vault means a token.
    let owner = Session::new(dir.join("v.azv")).with_tokens(vec![token.clone()]);
    owner
        .set_duress_password(PW, "winter-harbor-lantern-quiet", &[decoy])
        .unwrap();

    // With a token attached, as somebody would have in ordinary use.
    let armed = Session::new(dir.join("v.azv")).with_tokens(vec![token.clone()]);
    let listed = armed.list("winter-harbor-lantern-quiet").unwrap();
    assert_eq!(listed.len(), 1);
    assert_eq!(listed[0].path, "shopping.txt");

    // And the real contents are gone, token or no token.
    let after = Session::new(dir.join("v.azv")).with_tokens(vec![token]);
    assert!(after.list(PW).is_err(), "the real contents survived duress");
}

#[test]
fn extracting_under_duress_leaves_nothing_behind() {
    let dir = tmp("duresspurge");
    let s = seeded(&dir);
    let decoy = dir.join("shopping.txt");
    std::fs::write(&decoy, b"milk and bread").unwrap();
    s.set_duress_password(PW, "winter-harbor-lantern-quiet", &[decoy]).unwrap();

    let vp = dir.join("v.azv");
    assert!(vp.exists() && dir.join("v.azv.audit").exists());

    let out = dir.join("recovered");
    let written = s.export("winter-harbor-lantern-quiet", 0, &out).unwrap();

    // The decoy really was handed over.
    assert_eq!(std::fs::read(&written).unwrap(), b"milk and bread");

    // And nothing remains of the vault or anything written beside it.
    for suffix in ["", ".audit", ".journal", ".policy", ".split", ".custodian"] {
        let p = std::path::PathBuf::from(format!("{}{suffix}", vp.display()));
        assert!(!p.exists(), "{} survived", p.display());
    }
}

#[test]
fn an_ordinary_extraction_leaves_the_vault_alone() {
    // The counterpart, and the one that matters more: normal use must not
    // delete anything.
    let dir = tmp("normalexport");
    let s = seeded(&dir);
    let decoy = dir.join("shopping.txt");
    std::fs::write(&decoy, b"milk").unwrap();
    s.set_duress_password(PW, "winter-harbor-lantern-quiet", &[decoy]).unwrap();

    s.export(PW, 0, &dir.join("out")).unwrap();
    assert!(dir.join("v.azv").exists());
    assert!(dir.join("v.azv.audit").exists());
    assert_eq!(s.list(PW).unwrap().len(), 1);
}

#[test]
fn winding_the_clock_back_across_a_restart_does_not_buy_time() {
    // Monotonic time is process-local, so after a restart it says nothing and
    // the wall clock is all that remains. The session used to set the
    // monotonic field from the wall clock, which made the two agree by
    // construction and disabled the rollback check entirely.
    //
    // Simulated by moving the recorded timestamps forward, which is
    // indistinguishable from the clock having been moved back.
    let dir = tmp("rollback");
    let s = seeded(&dir);
    let mut p = s.load_policy();
    p.enabled = true;
    p.timeout_seconds = 3600;
    p.heartbeat_seconds = 1800;
    s.save_policy(&p).unwrap();
    s.check_in(PW).unwrap();

    let before = s.deadman_status().unwrap();
    assert!(before.seconds_remaining.is_some());

    // Rewrite the audit log so its newest record claims a time well ahead of
    // the system clock, as it would be after somebody set the clock back.
    let audit = dir.join("v.azv.audit");
    let text = std::fs::read_to_string(&audit).unwrap();
    let ahead: String = text
        .lines()
        .map(|l| {
            let mut f: Vec<&str> = l.split('\t').collect();
            let bumped;
            if f.len() > 3 {
                if let Ok(t) = f[3].parse::<i64>() {
                    bumped = (t + 7200).to_string();
                    f[3] = &bumped;
                    return f.join("\t");
                }
            }
            l.to_string()
        })
        .collect::<Vec<_>>()
        .join("\n");
    std::fs::write(&audit, ahead + "\n").unwrap();

    // The clock now reads two hours behind what the records show. The deadline
    // must be measured from the records, not the clock.
    let after = s.deadman_status().unwrap();
    assert!(
        after.seconds_remaining.unwrap_or(0) <= before.seconds_remaining.unwrap_or(u64::MAX),
        "winding the clock back extended the deadline"
    );
}
