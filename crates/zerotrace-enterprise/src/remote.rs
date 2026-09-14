//! Signed remote commands.
//!
//! The organization holds an Ed25519 signing key. ZeroTrace holds only the
//! public half, so a compromised endpoint cannot forge instructions to other
//! endpoints, and the server never possesses vault keys or plaintext.

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use zerotrace_core::{Error, Result, VaultId};

/// What an organization may instruct an endpoint to do.
///
/// The set is deliberately small. Anything that reads vault contents is absent
/// on purpose: the server must never be able to obtain plaintext.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum CommandAction {
    /// Close sessions and clear resident keys. Never destroys.
    Lock,
    /// Require a fresh check-in before the deadline resumes counting.
    RequireCheckIn,
    /// Shorten the deadman timeout. Cannot lengthen it: see `is_weakening`.
    TightenPolicy { timeout_seconds: u64 },
    /// Destroy the vault. Still goes through two-phase authorization locally.
    Destroy,
}

impl CommandAction {
    pub fn label(&self) -> &'static str {
        match self {
            CommandAction::Lock => "LOCK",
            CommandAction::RequireCheckIn => "REQUIRE_CHECK_IN",
            CommandAction::TightenPolicy { .. } => "TIGHTEN_POLICY",
            CommandAction::Destroy => "DESTROY",
        }
    }

    /// Whether the action reduces protection.
    ///
    /// A signed command must never be able to weaken a vault: an attacker who
    /// obtains the org key could otherwise disarm every endpoint quietly,
    /// which is worse than destroying them loudly.
    pub fn is_weakening(&self, current_timeout: u64) -> bool {
        match self {
            CommandAction::TightenPolicy { timeout_seconds } => *timeout_seconds > current_timeout,
            _ => false,
        }
    }

    pub fn is_destructive(&self) -> bool {
        matches!(self, CommandAction::Destroy)
    }
}

/// A command as issued by an organization.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RemoteCommand {
    pub vault_id: VaultId,
    pub action: CommandAction,
    /// Unique per command. Replaying a command with a seen nonce is refused.
    pub nonce: [u8; 16],
    pub issued_at: i64,
    /// After this, the command is refused however well signed it is.
    pub expires_at: i64,
    pub signature: Vec<u8>,
}

impl RemoteCommand {
    /// The bytes the signature covers.
    ///
    /// Every field is included and length-prefixed, so no field can be altered
    /// or moved between commands without invalidating the signature.
    fn signing_payload(
        vault_id: &VaultId,
        action: &CommandAction,
        nonce: &[u8; 16],
        issued_at: i64,
        expires_at: i64,
    ) -> Vec<u8> {
        let mut b = Vec::with_capacity(96);
        b.extend_from_slice(b"apex-zerotrace:remote-command:v1");
        b.extend_from_slice(vault_id.as_bytes());
        let label = action.label().as_bytes();
        b.extend_from_slice(&(label.len() as u32).to_le_bytes());
        b.extend_from_slice(label);
        if let CommandAction::TightenPolicy { timeout_seconds } = action {
            b.extend_from_slice(&timeout_seconds.to_le_bytes());
        }
        b.extend_from_slice(nonce);
        b.extend_from_slice(&issued_at.to_le_bytes());
        b.extend_from_slice(&expires_at.to_le_bytes());
        b
    }
}

/// An organization's signing key. Never present on an endpoint.
pub struct SigningIdentity {
    key: SigningKey,
}

impl SigningIdentity {
    pub fn generate() -> Self {
        let mut seed = [0u8; 32];
        zerotrace_crypto::random_bytes(&mut seed);
        Self { key: SigningKey::from_bytes(&seed) }
    }

    pub fn from_seed(seed: [u8; 32]) -> Self {
        Self { key: SigningKey::from_bytes(&seed) }
    }

    /// The public half, which is what an endpoint stores.
    pub fn verifying_key(&self) -> [u8; 32] {
        self.key.verifying_key().to_bytes()
    }

    pub fn issue(
        &self,
        vault_id: VaultId,
        action: CommandAction,
        issued_at: i64,
        valid_for_seconds: i64,
    ) -> RemoteCommand {
        let mut nonce = [0u8; 16];
        zerotrace_crypto::random_bytes(&mut nonce);
        let expires_at = issued_at + valid_for_seconds;
        let payload =
            RemoteCommand::signing_payload(&vault_id, &action, &nonce, issued_at, expires_at);
        let signature: Signature = self.key.sign(&payload);
        RemoteCommand {
            vault_id,
            action,
            nonce,
            issued_at,
            expires_at,
            signature: signature.to_bytes().to_vec(),
        }
    }
}

/// Refuses a command that has been seen, or that predates one already acted on.
///
/// # Why a set of nonces is not enough on its own
///
/// A set held only in memory forgets everything when the service restarts, so
/// a captured command could be replayed simply by waiting for a restart, or
/// causing one. It also grows without bound in a process that runs for months.
///
/// The high-water mark fixes both. A command must be issued strictly after the
/// newest one already accepted, which is a single integer, survives a restart
/// when persisted, and cannot grow.
///
/// The nonce set is kept alongside it and bounded, so a replay within a single
/// run is caught by the nonce rather than by the timestamp, and the reason
/// given is the more specific one.
#[derive(Debug, Default)]
pub struct ReplayGuard {
    seen: std::collections::HashSet<[u8; 16]>,
    order: std::collections::VecDeque<[u8; 16]>,
    newest_accepted: i64,
}

/// Nonces retained for same-second commands. Beyond this the high-water mark
/// is doing the work, and older nonces cannot be replayed anyway.
const NONCE_MEMORY: usize = 1024;

impl ReplayGuard {
    pub fn new() -> Self {
        Self::default()
    }

    /// Restores the mark after a restart.
    ///
    /// Without this the guard begins again at zero and every command issued
    /// since the beginning of time is acceptable once more.
    pub fn resume_from(newest_accepted: i64) -> Self {
        Self { newest_accepted, ..Self::default() }
    }

    /// The value to persist so a restart does not reopen the window.
    pub fn high_water(&self) -> i64 {
        self.newest_accepted
    }

    pub fn remember(&mut self, nonce: [u8; 16]) {
        self.remember_at(nonce, self.newest_accepted);
    }

    pub fn remember_at(&mut self, nonce: [u8; 16], issued_at: i64) {
        if self.seen.insert(nonce) {
            self.order.push_back(nonce);
            while self.order.len() > NONCE_MEMORY {
                if let Some(old) = self.order.pop_front() {
                    self.seen.remove(&old);
                }
            }
        }
        self.newest_accepted = self.newest_accepted.max(issued_at);
    }

    pub fn has_seen(&self, nonce: &[u8; 16]) -> bool {
        self.seen.contains(nonce)
    }

    /// Whether a command is no newer than one already acted on.
    ///
    /// Equal timestamps are refused, not only earlier ones. A replayed
    /// command carries the timestamp it was issued with, so accepting an equal
    /// value would let the newest accepted command be replayed for ever, which
    /// is precisely the case a restart exposes.
    ///
    /// The cost is that two commands issued in the same second cannot both be
    /// accepted. That is a real limitation and the right trade: commands are
    /// issued deliberately by an operator, timestamps are theirs to control,
    /// and a strictly increasing sequence is what makes the guard survive a
    /// restart at all.
    pub fn predates_accepted(&self, issued_at: i64) -> bool {
        self.newest_accepted > 0 && issued_at <= self.newest_accepted
    }

    pub fn len(&self) -> usize {
        self.seen.len()
    }
    pub fn is_empty(&self) -> bool {
        self.seen.is_empty()
    }
}

/// Why a command was accepted or refused.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CommandVerdict {
    Accepted,
    BadSignature,
    WrongVault,
    Expired,
    NotYetValid,
    Replayed,
    /// The command would reduce protection, so it is refused regardless of
    /// how well it is signed.
    WouldWeaken,
}

impl CommandVerdict {
    pub fn label(&self) -> &'static str {
        match self {
            CommandVerdict::Accepted => "ACCEPTED",
            CommandVerdict::BadSignature => "REFUSED: signature does not verify",
            CommandVerdict::WrongVault => "REFUSED: issued for a different vault",
            CommandVerdict::Expired => "REFUSED: expired",
            CommandVerdict::NotYetValid => "REFUSED: issued in the future",
            CommandVerdict::Replayed => "REFUSED: nonce already used",
            CommandVerdict::WouldWeaken => "REFUSED: would reduce protection",
        }
    }
    pub fn is_accepted(&self) -> bool {
        *self == CommandVerdict::Accepted
    }
}

/// Checks a command against every rule before it may be acted on.
///
/// Order matters only for the error reported; every rule is applied.
pub fn verify_command(
    command: &RemoteCommand,
    org_public_key: &[u8; 32],
    expected_vault: VaultId,
    now: i64,
    current_timeout: u64,
    guard: &ReplayGuard,
) -> Result<CommandVerdict> {
    if command.vault_id != expected_vault {
        return Ok(CommandVerdict::WrongVault);
    }
    if now > command.expires_at {
        return Ok(CommandVerdict::Expired);
    }
    // A command dated in the future suggests a clock problem at one end, and
    // acting on it would let a long-lived command be banked for later.
    if command.issued_at > now + 300 {
        return Ok(CommandVerdict::NotYetValid);
    }
    // Older than something already acted on, which catches a captured command
    // replayed after a restart even though its nonce is no longer remembered.
    if guard.predates_accepted(command.issued_at) {
        return Ok(CommandVerdict::Replayed);
    }
    if guard.has_seen(&command.nonce) {
        return Ok(CommandVerdict::Replayed);
    }
    if command.action.is_weakening(current_timeout) {
        return Ok(CommandVerdict::WouldWeaken);
    }

    let vk = VerifyingKey::from_bytes(org_public_key)
        .map_err(|_| Error::Crypto("organization public key is malformed".into()))?;
    let sig_bytes: [u8; 64] = command
        .signature
        .as_slice()
        .try_into()
        .map_err(|_| Error::Crypto("signature has the wrong length".into()))?;
    let signature = Signature::from_bytes(&sig_bytes);

    let payload = RemoteCommand::signing_payload(
        &command.vault_id,
        &command.action,
        &command.nonce,
        command.issued_at,
        command.expires_at,
    );

    Ok(match vk.verify(&payload, &signature) {
        Ok(()) => CommandVerdict::Accepted,
        Err(_) => CommandVerdict::BadSignature,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn setup() -> (SigningIdentity, [u8; 32], VaultId) {
        let id = SigningIdentity::from_seed([7u8; 32]);
        let pk = id.verifying_key();
        (id, pk, VaultId::from_bytes([1u8; 16]))
    }

    #[test]
    fn a_correctly_signed_command_is_accepted() {
        let (org, pk, vault) = setup();
        let cmd = org.issue(vault, CommandAction::Lock, 1000, 300);
        let guard = ReplayGuard::new();
        assert_eq!(
            verify_command(&cmd, &pk, vault, 1010, 72 * 3600, &guard).unwrap(),
            CommandVerdict::Accepted
        );
    }

    #[test]
    fn every_field_is_covered_by_the_signature() {
        let (org, pk, vault) = setup();
        let guard = ReplayGuard::new();
        let good = org.issue(vault, CommandAction::Lock, 1000, 300);

        // Escalating the action must invalidate the signature.
        let mut escalated = good.clone();
        escalated.action = CommandAction::Destroy;
        assert_eq!(
            verify_command(&escalated, &pk, vault, 1010, 72 * 3600, &guard).unwrap(),
            CommandVerdict::BadSignature
        );

        // Extending the window must too.
        let mut extended = good.clone();
        extended.expires_at += 100_000;
        assert_eq!(
            verify_command(&extended, &pk, vault, 1010, 72 * 3600, &guard).unwrap(),
            CommandVerdict::BadSignature
        );

        // And so must changing the nonce.
        let mut renonced = good.clone();
        renonced.nonce[0] ^= 1;
        assert_eq!(
            verify_command(&renonced, &pk, vault, 1010, 72 * 3600, &guard).unwrap(),
            CommandVerdict::BadSignature
        );
    }

    #[test]
    fn a_command_for_another_vault_is_refused() {
        let (org, pk, vault) = setup();
        let cmd = org.issue(vault, CommandAction::Destroy, 1000, 300);
        let other = VaultId::from_bytes([2u8; 16]);
        let guard = ReplayGuard::new();
        assert_eq!(
            verify_command(&cmd, &pk, other, 1010, 72 * 3600, &guard).unwrap(),
            CommandVerdict::WrongVault
        );
    }

    #[test]
    fn an_expired_command_is_refused_however_well_signed() {
        let (org, pk, vault) = setup();
        let cmd = org.issue(vault, CommandAction::Destroy, 1000, 300);
        let guard = ReplayGuard::new();
        assert_eq!(
            verify_command(&cmd, &pk, vault, 2000, 72 * 3600, &guard).unwrap(),
            CommandVerdict::Expired
        );
    }

    #[test]
    fn a_captured_command_cannot_be_replayed() {
        let (org, pk, vault) = setup();
        let cmd = org.issue(vault, CommandAction::Lock, 1000, 3600);
        let mut guard = ReplayGuard::new();
        assert!(verify_command(&cmd, &pk, vault, 1010, 72 * 3600, &guard).unwrap().is_accepted());
        guard.remember(cmd.nonce);
        assert_eq!(
            verify_command(&cmd, &pk, vault, 1020, 72 * 3600, &guard).unwrap(),
            CommandVerdict::Replayed
        );
    }

    #[test]
    fn a_signed_command_cannot_weaken_a_vault() {
        // Someone holding the org key must not be able to quietly disarm every
        // endpoint by extending their deadlines.
        let (org, pk, vault) = setup();
        let guard = ReplayGuard::new();
        let loosen = org.issue(
            vault,
            CommandAction::TightenPolicy { timeout_seconds: 365 * 24 * 3600 },
            1000,
            300,
        );
        assert_eq!(
            verify_command(&loosen, &pk, vault, 1010, 72 * 3600, &guard).unwrap(),
            CommandVerdict::WouldWeaken
        );

        // Tightening is permitted.
        let tighten =
            org.issue(vault, CommandAction::TightenPolicy { timeout_seconds: 3600 }, 1000, 300);
        assert!(verify_command(&tighten, &pk, vault, 1010, 72 * 3600, &guard)
            .unwrap()
            .is_accepted());
    }

    #[test]
    fn a_different_organisation_key_is_refused() {
        let (org, _, vault) = setup();
        let impostor = SigningIdentity::from_seed([8u8; 32]);
        let cmd = org.issue(vault, CommandAction::Destroy, 1000, 300);
        let guard = ReplayGuard::new();
        assert_eq!(
            verify_command(&cmd, &impostor.verifying_key(), vault, 1010, 72 * 3600, &guard)
                .unwrap(),
            CommandVerdict::BadSignature
        );
    }

    #[test]
    fn a_command_from_the_future_is_not_banked() {
        let (org, pk, vault) = setup();
        let cmd = org.issue(vault, CommandAction::Destroy, 100_000, 300);
        let guard = ReplayGuard::new();
        assert_eq!(
            verify_command(&cmd, &pk, vault, 1000, 72 * 3600, &guard).unwrap(),
            CommandVerdict::NotYetValid
        );
    }

    #[test]
    fn there_is_no_command_that_reads_vault_contents() {
        // The server must never be able to obtain plaintext. This is a
        // property of the action set, so it is asserted on the action set.
        for action in [
            CommandAction::Lock,
            CommandAction::RequireCheckIn,
            CommandAction::TightenPolicy { timeout_seconds: 60 },
            CommandAction::Destroy,
        ] {
            let l = action.label();
            assert!(!l.contains("READ") && !l.contains("EXPORT") && !l.contains("UNLOCK"), "{l}");
        }
    }
}

#[cfg(test)]
mod replay_across_restart {
    use super::*;

    fn cmd(id: &SigningIdentity, vault: VaultId, at: i64) -> RemoteCommand {
        id.issue(vault, CommandAction::Lock, at, 3600)
    }

    #[test]
    fn a_captured_command_cannot_be_replayed_after_a_restart() {
        // The guard used to be an in-memory set, so bouncing the service made
        // every captured command acceptable again.
        let key = SigningIdentity::from_seed([7u8; 32]);
        let vault = VaultId::from_bytes([1u8; 16]);
        let verifying = key.verifying_key();

        let captured = cmd(&key, vault, 1000);
        let mut guard = ReplayGuard::new();
        assert_eq!(
            verify_command(&captured, &verifying, vault, 1000, 3600, &guard).unwrap(),
            CommandVerdict::Accepted
        );
        guard.remember_at(captured.nonce, captured.issued_at);
        let mark = guard.high_water();

        // The service restarts. Without the mark this begins again at zero.
        let after_restart = ReplayGuard::resume_from(mark);
        assert_eq!(
            verify_command(&captured, &verifying, vault, 1100, 3600, &after_restart).unwrap(),
            CommandVerdict::Replayed
        );
    }

    #[test]
    fn a_newer_command_still_works_after_a_restart() {
        // The mark must not refuse everything, which would be a denial of
        // service dressed up as a safeguard.
        let key = SigningIdentity::from_seed([8u8; 32]);
        let vault = VaultId::from_bytes([2u8; 16]);
        let verifying = key.verifying_key();

        let mut guard = ReplayGuard::new();
        let first = cmd(&key, vault, 1000);
        assert_eq!(
            verify_command(&first, &verifying, vault, 1000, 3600, &guard).unwrap(),
            CommandVerdict::Accepted
        );
        guard.remember_at(first.nonce, first.issued_at);

        let after = ReplayGuard::resume_from(guard.high_water());
        let later = cmd(&key, vault, 2000);
        assert_eq!(
            verify_command(&later, &verifying, vault, 2000, 3600, &after).unwrap(),
            CommandVerdict::Accepted
        );
    }

    #[test]
    fn the_nonce_memory_does_not_grow_without_bound() {
        let mut guard = ReplayGuard::new();
        for i in 0..(NONCE_MEMORY * 3) {
            let mut n = [0u8; 16];
            n[..8].copy_from_slice(&(i as u64).to_le_bytes());
            guard.remember_at(n, i as i64);
        }
        assert!(guard.len() <= NONCE_MEMORY, "the set grew to {}", guard.len());
    }
}
