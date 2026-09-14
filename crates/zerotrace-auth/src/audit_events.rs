//! Event names shared between the auth and audit crates.
//!
//! Kept as constants rather than free-form strings so a typo cannot silently
//! create a new event class that no query looks for.

pub const VAULT_CREATED: &str = "VAULT_CREATED";
pub const VAULT_OPENED: &str = "VAULT_OPENED";
pub const VAULT_CLOSED: &str = "VAULT_CLOSED";
pub const AUTH_SUCCESS: &str = "AUTH_SUCCESS";
pub const AUTH_FAILURE: &str = "AUTH_FAILURE";
pub const FIDO_REGISTERED: &str = "FIDO_REGISTERED";
pub const FIDO_REMOVED: &str = "FIDO_REMOVED";
pub const FILE_IMPORTED: &str = "FILE_IMPORTED";
pub const FILE_EXPORTED: &str = "FILE_EXPORTED";
pub const INTEGRITY_VERIFIED: &str = "INTEGRITY_VERIFIED";
pub const INTEGRITY_FAILED: &str = "INTEGRITY_FAILED";
pub const POLICY_CHANGED: &str = "POLICY_CHANGED";

/// A watcher registered itself and began following a deadline.
pub const WATCH_STARTED: &str = "WATCH_STARTED";
/// A watcher was asked to stop and did so.
pub const WATCH_STOPPED: &str = "WATCH_STOPPED";
/// A watcher stopped without saying so: killed, crashed, or its window closed.
///
/// Recorded because it cannot be prevented. An attacker with the machine can
/// always end a process; what they cannot do is end it quietly, so the fact is
/// written down where it will be seen on return.
pub const WATCH_INTERRUPTED: &str = "WATCH_INTERRUPTED";

/// The system clock read earlier than something already written down.
pub const CLOCK_ANOMALY: &str = "CLOCK_ANOMALY";
