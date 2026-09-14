//! The attacker-owns-the-machine scenario, modeled directly.

use zerotrace_core::VaultId;
use zerotrace_kdf::KdfParams;
use zerotrace_remote::custodian::{record_fingerprint, Custodian, DirectoryCustodian, HeldShare};
use zerotrace_remote::{signing_identity, verifying_key, Intent, Request, Verdict};

const SALT: &[u8] = b"a-salt-that-is-long-enough-here!";

fn params() -> KdfParams {
    KdfParams { memory_kib: 19 * 1024, time_cost: 2, parallelism: 1 }
}

fn tmp(tag: &str) -> std::path::PathBuf {
    let d = std::env::temp_dir().join(format!("ztcust_{tag}_{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).unwrap();
    d
}

fn enrolled(dir: &std::path::Path, timeout: u64, now: i64) -> (DirectoryCustodian, VaultId) {
    let c = DirectoryCustodian::new(dir);
    let id = VaultId::from_bytes([5u8; 16]);
    c.enroll(&HeldShare::new(
        id,
        b"the-remote-share-bytes".to_vec(),
        verifying_key(b"correct horse", SALT, params()).unwrap(),
        timeout,
        now,
    ))
    .unwrap();
    (c, id)
}

fn signed(intent: Intent, id: VaultId, at: i64, password: &[u8]) -> Request {
    let key = signing_identity(password, SALT, params()).unwrap();
    Request::sign(&key, id, intent, at)
}

#[test]
fn the_owner_can_check_in_and_collect_the_share() {
    let dir = tmp("happy");
    let (c, id) = enrolled(&dir, 3600, 1000);

    match c.handle(&signed(Intent::CheckIn, id, 1100, b"correct horse"), 1100).unwrap() {
        Verdict::CheckedIn { deadline } => assert_eq!(deadline, 1100 + 3600),
        other => panic!("expected a check-in, got {other:?}"),
    }
    match c.handle(&signed(Intent::Release, id, 1200, b"correct horse"), 1200).unwrap() {
        Verdict::Released(s) => assert_eq!(s, b"the-remote-share-bytes"),
        other => panic!("expected a release, got {other:?}"),
    }
}

#[test]
fn an_attacker_holding_the_machine_cannot_check_in() {
    // The decision the whole design rests on. The credential that proves the
    // owner is present is derived from the password, so somebody who owns the
    // machine but not the password cannot hold the deadline open.
    let dir = tmp("cannotcheckin");
    let (c, id) = enrolled(&dir, 3600, 1000);

    let forged = signed(Intent::CheckIn, id, 1100, b"not the password");
    match c.handle(&forged, 1100).unwrap() {
        Verdict::Refused(why) => assert!(why.contains("not signed"), "{why}"),
        other => panic!("a forged check-in was accepted: {other:?}"),
    }

    // And it must not have moved the deadline either.
    match c.status(id, 1100).unwrap() {
        Some((deadline, expired)) => {
            assert_eq!(deadline, 1000 + 3600, "a refused request moved the deadline");
            assert!(!expired);
        }
        None => panic!("record vanished"),
    }
}

#[test]
fn the_share_is_destroyed_when_the_deadline_passes() {
    let dir = tmp("expire");
    let (c, id) = enrolled(&dir, 3600, 1000);

    let after = 1000 + 3600 + 1;
    match c.handle(&signed(Intent::Release, id, after, b"correct horse"), after).unwrap() {
        Verdict::Expired { expired_at } => assert_eq!(expired_at, 4600),
        other => panic!("expected expiry, got {other:?}"),
    }
}

#[test]
fn cracking_the_password_after_the_deadline_gains_nothing() {
    // The property that makes this survive total local compromise: an attacker
    // who kills every local process and then breaks the password at leisure
    // finds the share already gone.
    let dir = tmp("toolate");
    let (c, id) = enrolled(&dir, 3600, 1000);

    let much_later = 1000 + 3600 + 100_000;
    let _ = c.handle(&signed(Intent::Release, id, much_later, b"correct horse"), much_later);

    // Even with the correct password, and even checking in first.
    for intent in [Intent::CheckIn, Intent::Release] {
        match c.handle(&signed(intent, id, much_later + 10, b"correct horse"), much_later + 10)
            .unwrap()
        {
            Verdict::Expired { .. } => {}
            other => panic!("an expired custodian answered {other:?}"),
        }
    }
}

#[test]
fn an_expired_record_never_comes_back() {
    let dir = tmp("permanent");
    let (c, id) = enrolled(&dir, 3600, 1000);
    let after = 5000;
    let _ = c.handle(&signed(Intent::Release, id, after, b"correct horse"), after);

    // A later check-in with the right password must not revive it.
    match c.handle(&signed(Intent::CheckIn, id, after + 1, b"correct horse"), after + 1).unwrap() {
        Verdict::Expired { .. } => {}
        other => panic!("an expired share was revived: {other:?}"),
    }
    match c.status(id, after + 2).unwrap() {
        Some((_, expired)) => assert!(expired),
        None => panic!("record vanished"),
    }
}

#[test]
fn a_captured_request_cannot_be_replayed() {
    let dir = tmp("replay");
    let (c, id) = enrolled(&dir, 3600, 1000);
    let req = signed(Intent::CheckIn, id, 1100, b"correct horse");

    assert!(matches!(c.handle(&req, 1100).unwrap(), Verdict::CheckedIn { .. }));
    match c.handle(&req, 1150).unwrap() {
        Verdict::Refused(why) => assert!(why.contains("already been used"), "{why}"),
        other => panic!("a replay was accepted: {other:?}"),
    }
}

#[test]
fn a_stale_or_future_request_is_refused() {
    let dir = tmp("stale");
    let (c, id) = enrolled(&dir, 86_400, 1000);

    let old = signed(Intent::CheckIn, id, 1000, b"correct horse");
    assert!(matches!(c.handle(&old, 1000 + 3600).unwrap(), Verdict::Refused(_)));

    let future = signed(Intent::CheckIn, id, 50_000, b"correct horse");
    assert!(matches!(c.handle(&future, 1100).unwrap(), Verdict::Refused(_)));
}

#[test]
fn a_request_for_another_vault_is_unknown() {
    let dir = tmp("othervault");
    let (c, _) = enrolled(&dir, 3600, 1000);
    let other = VaultId::from_bytes([9u8; 16]);
    assert_eq!(
        c.handle(&signed(Intent::Release, other, 1100, b"correct horse"), 1100).unwrap(),
        Verdict::Unknown
    );
}

#[test]
fn a_vault_cannot_be_enrolled_twice() {
    // Otherwise an attacker could overwrite the record with their own owner
    // key and a fresh deadline.
    let dir = tmp("twice");
    let (c, id) = enrolled(&dir, 3600, 1000);
    let again = HeldShare::new(
        id,
        b"attacker share".to_vec(),
        verifying_key(b"attacker password", SALT, params()).unwrap(),
        999_999,
        9999,
    );
    assert!(c.enroll(&again).is_err());

    // The original owner still works, and the attacker's password does not.
    assert!(matches!(
        c.handle(&signed(Intent::CheckIn, id, 1100, b"correct horse"), 1100).unwrap(),
        Verdict::CheckedIn { .. }
    ));
    assert!(matches!(
        c.handle(&signed(Intent::CheckIn, id, 1200, b"attacker password"), 1200).unwrap(),
        Verdict::Refused(_)
    ));
}

#[test]
fn the_record_holds_no_password_and_no_usable_key_alone() {
    let dir = tmp("contents");
    let (_, id) = enrolled(&dir, 3600, 1000);
    let text = std::fs::read_to_string(dir.join(format!("{id}.custody"))).unwrap();
    assert!(!text.contains("correct horse"));
    // The share is present, which is the point: it is one component of a
    // threshold and opens nothing by itself.
    assert!(text.contains("share="));
    assert!(text.contains("owner_key="));
}

#[test]
fn a_fingerprint_lets_an_owner_recognise_their_record() {
    let held = HeldShare::new(
        VaultId::from_bytes([1u8; 16]),
        b"x".to_vec(),
        verifying_key(b"pw", SALT, params()).unwrap(),
        60,
        0,
    );
    let a = record_fingerprint(&held);
    let mut other = held.clone();
    other.vault_id = VaultId::from_bytes([2u8; 16]);
    assert_ne!(a, record_fingerprint(&other));
    assert_eq!(a.len(), 16);
}
