//! Presence scoring.
//!
//! The naive deadman switch is `if now - last_login > timeout { destroy() }`.
//! That is rejected here for two reasons. It treats every signal as equally
//! meaningful, so a scheduled ping from a machine whose owner is long gone
//! keeps the vault alive forever. And it has no notion of decay, so presence
//! is either perfect or absent with nothing in between.
//!
//! Instead each observation carries a trust level, contributes a score that
//! decays with age, and the total is capped so that weak evidence cannot on
//! its own satisfy a policy that asked for strong evidence.

#![forbid(unsafe_code)]

use serde::{Deserialize, Serialize};
use zerotrace_core::time::TimeAnchor;

/// How much a class of observation is worth believing.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum TrustLevel {
    /// Someone proved they hold a credential.
    Strong,
    /// Someone is using an already-authenticated session.
    Medium,
    /// Something is happening at the machine.
    Weak,
    /// The machine exists.
    VeryWeak,
}

impl TrustLevel {
    /// Score a perfectly fresh signal of this level contributes.
    pub fn weight(&self) -> u32 {
        match self {
            TrustLevel::Strong => 100,
            TrustLevel::Medium => 55,
            TrustLevel::Weak => 25,
            TrustLevel::VeryWeak => 10,
        }
    }

    pub fn label(&self) -> &'static str {
        match self {
            TrustLevel::Strong => "strong",
            TrustLevel::Medium => "medium",
            TrustLevel::Weak => "weak",
            TrustLevel::VeryWeak => "very weak",
        }
    }
}

/// The kinds of observation the engine understands.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SignalKind {
    /// The vault password was verified.
    PasswordAuth,
    /// The user explicitly checked in.
    ExplicitCheckIn,
    /// A vault operation was performed by an unlocked session.
    VaultOperation,
    /// The OS reports an authenticated, unlocked desktop session.
    OsSession,
    /// Keyboard or mouse activity.
    InputActivity,
    /// The machine has a network route.
    NetworkReachable,
    /// The machine has been running.
    SystemUptime,
}

impl SignalKind {
    pub fn trust(&self) -> TrustLevel {
        match self {
            SignalKind::PasswordAuth | SignalKind::ExplicitCheckIn => TrustLevel::Strong,
            SignalKind::VaultOperation | SignalKind::OsSession => TrustLevel::Medium,
            SignalKind::InputActivity => TrustLevel::Weak,
            // Neither says anything about whether a person is present, alive,
            // or acting freely.
            SignalKind::NetworkReachable | SignalKind::SystemUptime => TrustLevel::VeryWeak,
        }
    }

    pub fn label(&self) -> &'static str {
        match self {
            SignalKind::PasswordAuth => "password authentication",
            SignalKind::ExplicitCheckIn => "explicit check-in",
            SignalKind::VaultOperation => "vault operation",
            SignalKind::OsSession => "authenticated OS session",
            SignalKind::InputActivity => "input activity",
            SignalKind::NetworkReachable => "network reachable",
            SignalKind::SystemUptime => "system uptime",
        }
    }
}

/// One observation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Signal {
    pub kind: SignalKind,
    pub observed: TimeAnchor,
}

/// The ceiling on what non-strong evidence can contribute.
///
/// This is INV-10 made concrete. A policy requiring 80 cannot be satisfied by
/// any combination of medium, weak and very weak signals, no matter how many
/// or how fresh: their total is clamped below that. A machine that is merely
/// switched on and reachable is not evidence that its owner is alive and free.
pub const NON_STRONG_CEILING: u32 = 60;

/// Configuration for the engine.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct PresenceConfig {
    /// How long a strong signal counts as fully current, in seconds.
    ///
    /// This is the heartbeat interval. Inside it, a check-in is worth its full
    /// weight and nothing decays: the user is doing what they said they would.
    pub strong_full: u64,
    /// Age at which a strong signal has decayed to nothing, in seconds.
    ///
    /// This is the deadman timeout. Between the heartbeat and here, confidence
    /// falls from full to zero, which is what produces the WARNING and
    /// CRITICAL states rather than jumping straight from normal to armed.
    pub strong_horizon: u64,
    /// Age at which weaker signals have decayed to nothing, in seconds.
    pub weak_horizon: u64,
}

impl Default for PresenceConfig {
    fn default() -> Self {
        Self {
            strong_full: 12 * 3600,
            strong_horizon: 72 * 3600,
            weak_horizon: 2 * 3600,
        }
    }
}

impl PresenceConfig {
    /// Derives scoring from a deadman policy.
    ///
    /// Before this existed the heartbeat was validated and then ignored, which
    /// made it a documentation field wearing the costume of a control. Tying
    /// the full-credit window to it gives the setting the meaning its name
    /// promises: check in at least this often and presence stays at full.
    pub fn from_policy(heartbeat_seconds: u64, timeout_seconds: u64) -> Self {
        let horizon = timeout_seconds.max(heartbeat_seconds + 1);
        Self {
            strong_full: heartbeat_seconds.min(horizon - 1),
            strong_horizon: horizon,
            weak_horizon: (heartbeat_seconds / 6).max(600),
        }
    }
}

/// A presence assessment.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Assessment {
    /// 0 to 100.
    pub confidence: u32,
    /// Contribution from strong signals alone.
    pub strong_component: u32,
    /// Contribution from everything else, after clamping.
    pub other_component: u32,
    /// Age in seconds of the freshest strong signal, if any.
    pub last_strong_age: Option<u64>,
}

/// Scores observations into a confidence value.
#[derive(Debug, Clone, Default)]
pub struct PresenceEngine {
    config: PresenceConfig,
    signals: Vec<Signal>,
}

impl PresenceEngine {
    pub fn new(config: PresenceConfig) -> Self {
        Self { config, signals: Vec::new() }
    }

    pub fn observe(&mut self, kind: SignalKind, observed: TimeAnchor) {
        self.signals.push(Signal { kind, observed });
        // Only the freshest of each kind can matter, so the history does not
        // need to grow without bound.
        if self.signals.len() > 512 {
            self.signals.drain(..256);
        }
    }

    pub fn signals(&self) -> &[Signal] {
        &self.signals
    }

    /// Full weight until `full`, then linear decay to nothing at `horizon`.
    ///
    /// The flat region is the point: a user who checks in on schedule should
    /// see a steady reading, not a number sliding downwards from the moment
    /// they finish.
    fn decayed(weight: u32, age: u64, full: u64, horizon: u64) -> u32 {
        if horizon == 0 || age >= horizon {
            return 0;
        }
        if age <= full {
            return weight;
        }
        let span = horizon - full;
        let remaining = horizon - age;
        ((weight as u64 * remaining) / span) as u32
    }

    /// Scores presence as of `now`.
    ///
    /// Each signal kind contributes only its freshest observation, so
    /// repeating a weak signal cannot be used to accumulate confidence.
    pub fn assess(&self, now: TimeAnchor) -> Assessment {
        let mut strong = 0u32;
        let mut other = 0u32;
        let mut last_strong_age: Option<u64> = None;

        for kind in [
            SignalKind::PasswordAuth,
            SignalKind::ExplicitCheckIn,
            SignalKind::VaultOperation,
            SignalKind::OsSession,
            SignalKind::InputActivity,
            SignalKind::NetworkReachable,
            SignalKind::SystemUptime,
        ] {
            let freshest = self
                .signals
                .iter()
                .filter(|s| s.kind == kind)
                .map(|s| {
                    let (age, _) = zerotrace_core::time::elapsed_between(s.observed, now);
                    age
                })
                .min();

            let Some(age) = freshest else { continue };
            let trust = kind.trust();
            let (full, horizon) = if trust == TrustLevel::Strong {
                (self.config.strong_full, self.config.strong_horizon)
            } else {
                (0, self.config.weak_horizon)
            };
            let score = Self::decayed(trust.weight(), age, full, horizon);

            if trust == TrustLevel::Strong {
                strong = strong.max(score);
                if score > 0 || last_strong_age.is_none() {
                    last_strong_age = Some(match last_strong_age {
                        Some(prev) => prev.min(age),
                        None => age,
                    });
                }
            } else {
                other = other.saturating_add(score);
            }
        }

        // INV-10: ambient evidence has a ceiling it cannot pass.
        let other = other.min(NON_STRONG_CEILING);
        let confidence = (strong.max(other)).min(100);

        Assessment { confidence, strong_component: strong, other_component: other, last_strong_age }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn at(t: i64) -> TimeAnchor {
        TimeAnchor { wall: t, monotonic: t.max(0) as u64 }
    }

    #[test]
    fn a_fresh_check_in_gives_full_confidence() {
        let mut e = PresenceEngine::new(PresenceConfig::default());
        e.observe(SignalKind::ExplicitCheckIn, at(0));
        assert_eq!(e.assess(at(0)).confidence, 100);
    }

    #[test]
    fn a_check_in_holds_full_credit_for_the_heartbeat_then_decays() {
        // This is what makes the heartbeat setting mean something.
        let cfg = PresenceConfig::from_policy(12 * 3600, 72 * 3600);
        let mut e = PresenceEngine::new(cfg);
        e.observe(SignalKind::ExplicitCheckIn, at(0));

        // Anywhere inside the heartbeat, presence is full.
        for hours in [0i64, 1, 6, 11] {
            assert_eq!(e.assess(at(hours * 3600)).confidence, 100, "at {hours}h");
        }
        // Exactly at the heartbeat it is still full.
        assert_eq!(e.assess(at(12 * 3600)).confidence, 100);

        // Then it falls, reaching nothing at the timeout.
        let mid = e.assess(at(42 * 3600)).confidence;
        assert!((45..=55).contains(&mid), "expected roughly half at the midpoint, got {mid}");
        assert_eq!(e.assess(at(72 * 3600)).confidence, 0);
    }

    #[test]
    fn a_shorter_heartbeat_makes_presence_decay_sooner() {
        let lax = PresenceEngine::new(PresenceConfig::from_policy(24 * 3600, 72 * 3600));
        let strict = PresenceEngine::new(PresenceConfig::from_policy(2 * 3600, 72 * 3600));
        let mut lax = lax;
        let mut strict = strict;
        lax.observe(SignalKind::ExplicitCheckIn, at(0));
        strict.observe(SignalKind::ExplicitCheckIn, at(0));

        let t = at(20 * 3600);
        assert_eq!(lax.assess(t).confidence, 100, "still inside the lax heartbeat");
        assert!(
            strict.assess(t).confidence < 100,
            "a two-hour heartbeat must have started decaying by twenty hours"
        );
    }

    #[test]
    fn the_config_refuses_to_produce_an_impossible_window() {
        // A heartbeat at or beyond the timeout would leave no decay span.
        let c = PresenceConfig::from_policy(100, 50);
        assert!(c.strong_full < c.strong_horizon);
    }

    #[test]
    fn network_presence_alone_can_never_satisfy_a_strong_policy() {
        // INV-10, the property that stops an abandoned machine keeping a vault
        // alive indefinitely.
        let mut e = PresenceEngine::new(PresenceConfig::default());
        for t in 0..200 {
            e.observe(SignalKind::NetworkReachable, at(t));
            e.observe(SignalKind::SystemUptime, at(t));
        }
        let a = e.assess(at(200));
        assert!(a.confidence <= NON_STRONG_CEILING, "got {}", a.confidence);
        assert!(a.confidence < 80, "must not satisfy a policy requiring 80");
        assert_eq!(a.strong_component, 0);
    }

    #[test]
    fn every_weak_signal_together_still_cannot_reach_a_strong_threshold() {
        let mut e = PresenceEngine::new(PresenceConfig::default());
        for k in [
            SignalKind::VaultOperation,
            SignalKind::OsSession,
            SignalKind::InputActivity,
            SignalKind::NetworkReachable,
            SignalKind::SystemUptime,
        ] {
            e.observe(k, at(0));
        }
        let a = e.assess(at(0));
        assert_eq!(a.other_component, NON_STRONG_CEILING);
        assert!(a.confidence <= NON_STRONG_CEILING);
    }

    #[test]
    fn repeating_a_weak_signal_does_not_accumulate() {
        let mut e = PresenceEngine::new(PresenceConfig::default());
        let mut many = PresenceEngine::new(PresenceConfig::default());
        e.observe(SignalKind::InputActivity, at(0));
        for t in 0..100 {
            many.observe(SignalKind::InputActivity, at(t));
        }
        assert_eq!(e.assess(at(0)).confidence, many.assess(at(0)).confidence);
    }

    #[test]
    fn a_strong_signal_dominates_ambient_noise() {
        let mut e = PresenceEngine::new(PresenceConfig::default());
        e.observe(SignalKind::NetworkReachable, at(0));
        e.observe(SignalKind::ExplicitCheckIn, at(0));
        assert_eq!(e.assess(at(0)).confidence, 100);
    }

    #[test]
    fn trust_ordering_matches_the_specification() {
        assert!(TrustLevel::Strong < TrustLevel::Medium);
        assert!(TrustLevel::Medium < TrustLevel::Weak);
        assert!(TrustLevel::Weak < TrustLevel::VeryWeak);
        assert_eq!(SignalKind::NetworkReachable.trust(), TrustLevel::VeryWeak);
        assert_eq!(SignalKind::PasswordAuth.trust(), TrustLevel::Strong);
    }

    #[test]
    fn an_empty_engine_reports_no_confidence() {
        let e = PresenceEngine::new(PresenceConfig::default());
        let a = e.assess(at(0));
        assert_eq!(a.confidence, 0);
        assert_eq!(a.last_strong_age, None);
    }

    #[test]
    fn a_clock_rollback_does_not_refresh_stale_presence() {
        // Wind the wall clock back after a check-in has expired. Monotonic
        // time still advanced, so the signal stays expired.
        let mut e = PresenceEngine::new(PresenceConfig::default());
        e.observe(SignalKind::ExplicitCheckIn, TimeAnchor { wall: 100_000, monotonic: 0 });
        let later = TimeAnchor { wall: 100_000, monotonic: 80 * 3600 };
        assert_eq!(e.assess(later).confidence, 0, "rollback must not restore presence");
    }
}
