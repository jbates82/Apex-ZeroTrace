//! Presence, policy and journal working together.

use zerotrace_core::state::DeadmanState;
use zerotrace_core::time::TimeAnchor;
use zerotrace_core::VaultId;
use zerotrace_journal::{AuditAnchor, JournalStatus, StateJournal};
use zerotrace_policy::DeadmanPolicy;
use zerotrace_presence::{PresenceConfig, PresenceEngine, SignalKind};

fn tmp(tag: &str) -> std::path::PathBuf {
    let d = std::env::temp_dir().join(format!("ztdm_{tag}_{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).unwrap();
    d.join("state.journal")
}

fn at(t: i64) -> TimeAnchor {
    TimeAnchor { wall: t, monotonic: t.max(0) as u64 }
}

fn policy() -> DeadmanPolicy {
    DeadmanPolicy { enabled: true, timeout_seconds: 72 * 3600, ..Default::default() }
}

/// Walks a vault from a fresh check-in through to ARMED as time passes.
#[test]
fn absence_walks_the_state_machine_to_armed_and_stops() {
    let p = policy();
    let mut engine = PresenceEngine::new(PresenceConfig::default());
    engine.observe(SignalKind::ExplicitCheckIn, at(0));

    let mut seen = Vec::new();
    for hours in [0i64, 6, 18, 30, 71, 72, 96] {
        let now = at(hours * 3600);
        let a = engine.assess(now);
        let since = a.last_strong_age.unwrap_or(u64::MAX);
        seen.push((hours, p.evaluate(a.confidence, since)));
    }

    assert_eq!(seen[0].1, DeadmanState::Normal, "fresh check-in should be normal");
    assert_eq!(seen.last().unwrap().1, DeadmanState::Armed, "past the deadline");

    // Nothing may reach a destruction state without an authorization record,
    // which Phase 3 does not create.
    for (h, s) in &seen {
        assert!(!s.is_committed(), "hour {h} reached a committed state: {s:?}");
    }
}

#[test]
fn checking_in_returns_a_warned_vault_to_normal() {
    let p = policy();
    let mut engine = PresenceEngine::new(PresenceConfig::default());
    engine.observe(SignalKind::ExplicitCheckIn, at(0));

    // With a twelve-hour heartbeat a check-in counts in full for twelve hours
    // and then decays, so it is well past the requirement by forty.
    let late = at(40 * 3600);
    let a = engine.assess(late);
    let degraded = p.evaluate(a.confidence, a.last_strong_age.unwrap());
    assert_ne!(degraded, DeadmanState::Normal);

    // A fresh check-in restores it.
    engine.observe(SignalKind::ExplicitCheckIn, late);
    let a = engine.assess(late);
    assert_eq!(p.evaluate(a.confidence, a.last_strong_age.unwrap()), DeadmanState::Normal);
}

#[test]
fn a_journal_records_the_whole_progression_and_verifies() {
    let path = tmp("progression");
    let id = VaultId::from_bytes([4u8; 16]);
    let mut j = StateJournal::open(&path, id).unwrap();

    for (i, state) in [
        DeadmanState::Normal,
        DeadmanState::Warning,
        DeadmanState::Critical,
        DeadmanState::Armed,
    ]
    .into_iter()
    .enumerate()
    {
        j.record(state, at(i as i64 * 3600), 0, 0, AuditAnchor::default()).unwrap();
    }

    assert_eq!(
        j.verify().unwrap(),
        JournalStatus::Intact { records: 4, state: DeadmanState::Armed }
    );

    // An armed vault may still be rescued: nothing has been committed.
    j.record(DeadmanState::Normal, at(99), 0, 100, AuditAnchor::default()).unwrap();
    assert_eq!(j.state(), DeadmanState::Normal);
}

#[test]
fn a_suspended_machine_still_reaches_the_deadline() {
    // The scenario a monotonic-only deadline would get wrong: the laptop is
    // closed for four days, so no monotonic time passes at all.
    let p = policy();
    let mut engine = PresenceEngine::new(PresenceConfig::default());
    engine.observe(SignalKind::ExplicitCheckIn, TimeAnchor { wall: 0, monotonic: 0 });

    let after_suspend = TimeAnchor { wall: 4 * 24 * 3600, monotonic: 0 };
    let a = engine.assess(after_suspend);
    assert_eq!(a.confidence, 0);
    assert_eq!(
        p.evaluate(a.confidence, a.last_strong_age.unwrap()),
        DeadmanState::Armed,
        "suspend must count toward the deadline"
    );
}

#[test]
fn winding_the_clock_back_does_not_postpone_the_deadline() {
    let p = policy();
    let mut engine = PresenceEngine::new(PresenceConfig::default());
    engine.observe(SignalKind::ExplicitCheckIn, TimeAnchor { wall: 1_000_000, monotonic: 0 });

    // The attacker sets the wall clock back a week. Monotonic time still shows
    // 80 hours have elapsed.
    let rolled_back = TimeAnchor { wall: 1_000_000 - 7 * 24 * 3600, monotonic: 80 * 3600 };
    let a = engine.assess(rolled_back);
    assert_eq!(
        p.evaluate(a.confidence, a.last_strong_age.unwrap()),
        DeadmanState::Armed,
        "a clock rollback must not buy time"
    );
}

#[test]
fn an_abandoned_but_reachable_machine_still_arms() {
    // INV-10 end to end: the owner is gone, but the machine is powered on and
    // on the network. Ambient signals must not hold the deadline open.
    let p = policy();
    let mut engine = PresenceEngine::new(PresenceConfig::default());
    engine.observe(SignalKind::ExplicitCheckIn, at(0));

    for hour in 0..200i64 {
        engine.observe(SignalKind::NetworkReachable, at(hour * 3600));
        engine.observe(SignalKind::SystemUptime, at(hour * 3600));
    }

    let now = at(200 * 3600);
    let a = engine.assess(now);
    assert!(a.confidence < p.required_confidence);
    assert_eq!(p.evaluate(a.confidence, a.last_strong_age.unwrap()), DeadmanState::Armed);
}

#[test]
fn a_disabled_policy_never_leaves_normal() {
    let p = DeadmanPolicy::default();
    assert!(!p.enabled);
    let engine = PresenceEngine::new(PresenceConfig::default());
    let a = engine.assess(at(10_000_000));
    assert_eq!(p.evaluate(a.confidence, u64::MAX), DeadmanState::Normal);
    assert_eq!(p.remaining(u64::MAX), None);
}
