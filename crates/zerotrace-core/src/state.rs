//! The deadman state machine.
//!
//! v0.1 defines the states and the legal transitions but performs no
//! destruction: nothing in this release drives the machine past `Normal`. The
//! machine lives here, in the dependency root, so that the transition rules
//! are testable in isolation from any code that could act on them.

use serde::{Deserialize, Serialize};

/// States a vault's deadman policy can occupy.
///
/// The ordering is meaningful: with the single exception noted on
/// [`DeadmanState::can_transition_to`], progress is one-way.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum DeadmanState {
    /// Presence requirements are being met.
    Normal,
    /// The deadline is approaching; the user has been warned.
    Warning,
    /// The deadline is close.
    Critical,
    /// The deadline passed. Destruction has not yet been authorized.
    Armed,
    /// A destruction authorization record has been committed. From here the
    /// system fails forward rather than fail-closed.
    DestructionAuthorized,
    /// Key material is being erased.
    KeyErasure,
    /// The vault container is being removed.
    VaultErasure,
    /// Platform sanitization is running.
    PlatformSanitization,
    /// Results are being verified for the destruction report.
    Verification,
    /// Terminal.
    Destroyed,
}

impl DeadmanState {
    pub fn label(&self) -> &'static str {
        match self {
            DeadmanState::Normal => "NORMAL",
            DeadmanState::Warning => "WARNING",
            DeadmanState::Critical => "CRITICAL",
            DeadmanState::Armed => "ARMED",
            DeadmanState::DestructionAuthorized => "DESTRUCTION_AUTHORIZED",
            DeadmanState::KeyErasure => "KEY_ERASURE",
            DeadmanState::VaultErasure => "VAULT_ERASURE",
            DeadmanState::PlatformSanitization => "PLATFORM_SANITIZATION",
            DeadmanState::Verification => "VERIFICATION",
            DeadmanState::Destroyed => "DESTROYED",
        }
    }

    /// True once a destruction authorization has been committed.
    ///
    /// Past this point recovery keys must not restore the vault (INV-11) and
    /// the process must resume after a restart rather than reverting.
    pub fn is_committed(&self) -> bool {
        *self >= DeadmanState::DestructionAuthorized
    }

    pub fn is_terminal(&self) -> bool {
        *self == DeadmanState::Destroyed
    }

    /// Whether `self -> next` is permitted.
    ///
    /// Two rules carry the security weight:
    /// INV-6, `Destroyed` is terminal, and INV-7, nothing past
    /// `DestructionAuthorized` may move backwards. Before authorization the
    /// machine may relax freely, because a user who checks in during a warning
    /// must return to normal.
    pub fn can_transition_to(&self, next: DeadmanState) -> bool {
        use DeadmanState::*;

        if *self == Destroyed {
            return false; // INV-6
        }
        if *self == next {
            return true;
        }

        // Recovering presence before authorization is legitimate and expected.
        if !self.is_committed() && next < *self {
            return true;
        }

        // Otherwise only forward, and only one step at a time, so that no
        // stage of destruction can be skipped or its record omitted.
        let ordered = [
            Normal,
            Warning,
            Critical,
            Armed,
            DestructionAuthorized,
            KeyErasure,
            VaultErasure,
            PlatformSanitization,
            Verification,
            Destroyed,
        ];
        let i = ordered.iter().position(|s| s == self).unwrap();
        let j = ordered.iter().position(|s| s == &next).unwrap();
        j == i + 1
    }
}

/// Applies a transition, refusing anything the rules forbid.
pub fn transition(
    from: DeadmanState,
    to: DeadmanState,
) -> Result<DeadmanState, crate::Error> {
    if from.can_transition_to(to) {
        Ok(to)
    } else {
        Err(crate::Error::InvalidTransition { from: from.label(), to: to.label() })
    }
}

#[cfg(test)]
mod tests {
    use super::DeadmanState::*;
    use super::*;

    #[test]
    fn destroyed_is_terminal() {
        // INV-6. Nothing may leave the terminal state, including itself.
        for s in [
            Normal, Warning, Critical, Armed, DestructionAuthorized, KeyErasure,
            VaultErasure, PlatformSanitization, Verification, Destroyed,
        ] {
            assert!(!Destroyed.can_transition_to(s), "Destroyed -> {s:?} must be refused");
            assert!(transition(Destroyed, s).is_err());
        }
    }

    #[test]
    fn authorized_destruction_cannot_be_rolled_back() {
        // INV-7.
        let committed = [
            DestructionAuthorized, KeyErasure, VaultErasure, PlatformSanitization,
            Verification, Destroyed,
        ];
        for c in committed {
            for earlier in [Normal, Warning, Critical, Armed] {
                assert!(
                    !c.can_transition_to(earlier),
                    "{c:?} -> {earlier:?} must be refused"
                );
            }
        }
    }

    #[test]
    fn presence_recovery_before_authorization_is_allowed() {
        assert!(Warning.can_transition_to(Normal));
        assert!(Critical.can_transition_to(Normal));
        assert!(Armed.can_transition_to(Normal));
    }

    #[test]
    fn destruction_stages_cannot_be_skipped() {
        assert!(Armed.can_transition_to(DestructionAuthorized));
        assert!(!Armed.can_transition_to(KeyErasure));
        assert!(!Normal.can_transition_to(Destroyed));
        assert!(!DestructionAuthorized.can_transition_to(Verification));
    }

    #[test]
    fn the_full_forward_path_is_walkable() {
        let path = [
            Normal, Warning, Critical, Armed, DestructionAuthorized, KeyErasure,
            VaultErasure, PlatformSanitization, Verification, Destroyed,
        ];
        let mut s = Normal;
        for next in path.into_iter().skip(1) {
            s = transition(s, next).expect("forward step must be legal");
        }
        assert_eq!(s, Destroyed);
        assert!(s.is_terminal());
    }

    #[test]
    fn commitment_boundary_is_where_the_spec_puts_it() {
        assert!(!Armed.is_committed());
        assert!(DestructionAuthorized.is_committed());
        assert!(Destroyed.is_committed());
    }
}
