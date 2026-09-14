//! Deadman policy: what the user configured, and what it means.
//!
//! The policy is inert here. It says when a deadline falls and which state a
//! given confidence implies; it performs no action. Phase 4 supplies the code
//! that acts, and it is deliberately not present yet.

#![forbid(unsafe_code)]

use serde::{Deserialize, Serialize};
use zerotrace_core::state::DeadmanState;
use zerotrace_core::{Error, Result};
use zerotrace_presence::NON_STRONG_CEILING;

/// User-configured deadman settings.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeadmanPolicy {
    /// When false, no deadline is ever computed. The default.
    pub enabled: bool,
    /// Seconds of absence before the deadline passes.
    pub timeout_seconds: u64,
    /// How often the user is expected to check in, in seconds.
    pub heartbeat_seconds: u64,
    /// Confidence at or above which the vault is considered normal.
    pub required_confidence: u32,
    /// Below this, the state is WARNING.
    pub warning_threshold: u32,
    /// Below this, the state is CRITICAL.
    pub critical_threshold: u32,
    /// Consecutive wrong passwords before the vault is destroyed.
    ///
    /// Zero, meaning never, and that is the default deliberately.
    ///
    /// A counter that destroys a vault is a weapon pointed at its owner.
    /// Anybody with a minute at the keyboard can trigger it by typing nonsense:
    /// no password knowledge, no key component, and the result is
    /// irreversible. A hostile colleague, a curious child or a bad afternoon
    /// with caps lock all reach it.
    ///
    /// It also buys very little. Somebody serious copies the vault and attacks
    /// it offline, where no counter of ours exists. The only attacker it stops
    /// is one guessing by hand at this keyboard, which is exactly the case
    /// escalating delays already make hopeless.
    ///
    /// So it is offered, because it is the owner's vault and some threat
    /// models want it, and it is off unless deliberately turned on.
    pub destroy_after_failures: u32,
}

impl Default for DeadmanPolicy {
    fn default() -> Self {
        // Disabled by default, on purpose. A deadman switch that arms itself
        // because the user never visited the settings screen would destroy
        // data nobody meant to lose.
        Self {
            enabled: false,
            timeout_seconds: 72 * 3600,
            heartbeat_seconds: 12 * 3600,
            required_confidence: 80,
            warning_threshold: 60,
            critical_threshold: 30,
            destroy_after_failures: 0,
        }
    }
}

/// Shortest timeout the policy accepts.
///
/// A very short deadline turns an ordinary interruption, a flight or a stay in
/// hospital, into permanent data loss. It also makes accidental triggering far
/// more likely than any threat it defends against.
pub const MIN_TIMEOUT_SECONDS: u64 = 3600;
pub const MAX_TIMEOUT_SECONDS: u64 = 365 * 24 * 3600;

impl DeadmanPolicy {
    pub fn validate(&self) -> Result<()> {
        if !self.enabled {
            return Ok(());
        }
        if self.timeout_seconds < MIN_TIMEOUT_SECONDS {
            return Err(Error::Other(format!(
                "a deadman timeout of {}s is below the {MIN_TIMEOUT_SECONDS}s minimum",
                self.timeout_seconds
            )));
        }
        if self.timeout_seconds > MAX_TIMEOUT_SECONDS {
            return Err(Error::LimitExceeded("deadman timeout is too long".into()));
        }
        if self.heartbeat_seconds == 0 || self.heartbeat_seconds >= self.timeout_seconds {
            return Err(Error::Other(
                "the heartbeat interval must be shorter than the timeout, or the user \
                 can never satisfy the policy"
                    .into(),
            ));
        }
        if self.required_confidence > 100 {
            return Err(Error::Other("required confidence must be 0..=100".into()));
        }
        if !(self.critical_threshold <= self.warning_threshold
            && self.warning_threshold <= self.required_confidence)
        {
            return Err(Error::Other(
                "thresholds must satisfy critical <= warning <= required".into(),
            ));
        }
        // A policy that ambient signals alone could satisfy is not a deadman
        // switch, so refuse to configure one (INV-10).
        if self.required_confidence <= NON_STRONG_CEILING {
            return Err(Error::Other(format!(
                "required confidence of {} could be met by ambient signals alone; it must \
                 exceed {NON_STRONG_CEILING} so that a strong factor is genuinely required",
                self.required_confidence
            )));
        }
        if self.destroy_after_failures > 0 && self.destroy_after_failures < 3 {
            return Err(Error::Other(
                "destroying after fewer than three wrong passwords will happen by \
                 accident. A mistyped password, a caps lock key or the wrong keyboard \
                 layout reaches one or two on an ordinary day"
                    .into(),
            ));
        }
        Ok(())
    }

    /// Which state a confidence value and elapsed absence imply.
    ///
    /// Returns at most `Armed`. Nothing here can reach a destruction state:
    /// crossing that line requires a committed authorization record, which is
    /// Phase 4 work and does not exist.
    pub fn evaluate(&self, confidence: u32, seconds_since_strong: u64) -> DeadmanState {
        if !self.enabled {
            return DeadmanState::Normal;
        }
        if seconds_since_strong >= self.timeout_seconds {
            return DeadmanState::Armed;
        }
        if confidence >= self.required_confidence {
            DeadmanState::Normal
        } else if confidence >= self.warning_threshold {
            DeadmanState::Warning
        } else if confidence >= self.critical_threshold {
            DeadmanState::Critical
        } else {
            DeadmanState::Critical
        }
    }

    /// Seconds remaining before the deadline, or None when disabled or passed.
    pub fn remaining(&self, seconds_since_strong: u64) -> Option<u64> {
        if !self.enabled {
            return None;
        }
        self.timeout_seconds.checked_sub(seconds_since_strong).filter(|r| *r > 0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn enabled() -> DeadmanPolicy {
        DeadmanPolicy { enabled: true, ..Default::default() }
    }

    #[test]
    fn the_default_policy_is_disabled() {
        assert!(!DeadmanPolicy::default().enabled);
        assert_eq!(DeadmanPolicy::default().evaluate(0, u64::MAX), DeadmanState::Normal);
    }

    #[test]
    fn a_dangerously_short_timeout_is_refused() {
        let p = DeadmanPolicy { enabled: true, timeout_seconds: 60, ..Default::default() };
        assert!(p.validate().is_err());
    }

    #[test]
    fn a_policy_satisfiable_by_ambient_signals_is_refused() {
        // INV-10 enforced at configuration time, not just at scoring time.
        let p = DeadmanPolicy {
            enabled: true,
            required_confidence: NON_STRONG_CEILING,
            warning_threshold: 30,
            critical_threshold: 10,
            ..Default::default()
        };
        assert!(p.validate().is_err());
    }

    #[test]
    fn a_heartbeat_longer_than_the_timeout_is_refused() {
        let p = DeadmanPolicy {
            enabled: true,
            timeout_seconds: 3600,
            heartbeat_seconds: 7200,
            ..Default::default()
        };
        assert!(p.validate().is_err());
    }

    #[test]
    fn thresholds_must_be_ordered() {
        let p = DeadmanPolicy {
            enabled: true,
            required_confidence: 80,
            warning_threshold: 20,
            critical_threshold: 50,
            ..Default::default()
        };
        assert!(p.validate().is_err());
    }

    #[test]
    fn states_follow_confidence() {
        let p = enabled();
        assert_eq!(p.evaluate(100, 0), DeadmanState::Normal);
        assert_eq!(p.evaluate(70, 0), DeadmanState::Warning);
        assert_eq!(p.evaluate(40, 0), DeadmanState::Critical);
        assert_eq!(p.evaluate(0, 0), DeadmanState::Critical);
    }

    #[test]
    fn passing_the_deadline_arms_but_goes_no_further() {
        let p = enabled();
        let state = p.evaluate(0, p.timeout_seconds);
        assert_eq!(state, DeadmanState::Armed);
        // Phase 3 stops here. Nothing may reach a destruction state.
        assert!(!state.is_committed());
    }

    #[test]
    fn remaining_time_counts_down_and_then_stops() {
        let p = enabled();
        assert_eq!(p.remaining(0), Some(p.timeout_seconds));
        assert_eq!(p.remaining(p.timeout_seconds - 1), Some(1));
        assert_eq!(p.remaining(p.timeout_seconds), None);
        assert_eq!(p.remaining(u64::MAX), None);
    }

    #[test]
    fn a_valid_policy_passes() {
        enabled().validate().unwrap();
    }
}
