//! Enterprise control: signed remote commands and threshold recovery.
//!
//! Two capabilities that both need to be impossible to abuse.
//!
//! A remote command must be authenticated, authorized, replay-resistant and
//! auditable. An unauthenticated "kill URL" would be a denial-of-service
//! button pointed at the customer's own data, so every command carries an
//! Ed25519 signature over its full contents, a unique nonce, and an expiry.
//!
//! Threshold recovery lets a quorum of custodians reconstruct a vault key
//! without any single one holding it. What it must not do is survive a
//! committed destruction (INV-11): a recovery mechanism that outlives the
//! deadman switch makes the deadman switch decorative.

#![forbid(unsafe_code)]

pub mod recovery;
pub mod remote;

pub use recovery::{
    combine_shares, split_master_key, CustodianShare, RecoveryConfig, RecoveryGate, ShareSet,
};
pub use remote::{
    verify_command, CommandAction, CommandVerdict, RemoteCommand, ReplayGuard, SigningIdentity,
};
