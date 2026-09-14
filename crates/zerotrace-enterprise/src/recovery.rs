//! Threshold recovery: k of n custodians.
//!
//! Shamir secret sharing over GF(256), via the `sharks` crate rather than a
//! hand-rolled implementation. Splitting a key is not a cryptographic
//! primitive in the sense that AES is, but it is still not something to
//! reinvent when an audited implementation exists.
//!
//! # Does escrow survive a deadman event?
//!
//! No, and the specification asks for this to be answered explicitly rather
//! than left ambiguous.
//!
//! A recovery quorum can reconstruct the master key while a vault is merely
//! locked. That is the point: it is what saves an organization from a departed
//! employee's forgotten password. But once destruction is committed, recovery
//! must fail, or the deadman switch is decorative: anyone who can compel three
//! custodians could undo it.
//!
//! Two things enforce this. Locally, [`RecoveryGate`] refuses to reconstruct
//! once the journal is past authorization. And structurally, the wrapped key
//! in the container is overwritten during erasure, so even a reconstructed
//! master key has nothing left to unwrap.
//!
//! The honest limit is the same one that applies everywhere else in this
//! product: a quorum plus a *copy of the container taken before erasure* can
//! still open that copy. Custodian shares should therefore be treated as
//! sensitive for as long as any backup of the vault exists.

use serde::{Deserialize, Serialize};
use sharks::{Share, Sharks};
use zerotrace_core::state::DeadmanState;
use zerotrace_core::{Error, Result, VaultId};
use zerotrace_secure_memory::Key256;

/// How a vault's recovery is configured.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct RecoveryConfig {
    /// How many custodians must cooperate.
    pub threshold: u8,
    /// How many shares exist in total.
    pub custodians: u8,
}

/// Fewer than two custodians is not threshold recovery, it is a spare key.
pub const MIN_THRESHOLD: u8 = 2;
pub const MAX_CUSTODIANS: u8 = 32;

impl RecoveryConfig {
    pub fn validate(&self) -> Result<()> {
        if self.threshold < MIN_THRESHOLD {
            return Err(Error::Other(format!(
                "a threshold of {} is a single point of failure; at least {MIN_THRESHOLD} \
                 custodians must cooperate",
                self.threshold
            )));
        }
        if self.threshold > self.custodians {
            return Err(Error::Other(
                "the threshold cannot exceed the number of custodians, or recovery is \
                 impossible"
                    .into(),
            ));
        }
        if self.custodians > MAX_CUSTODIANS {
            return Err(Error::LimitExceeded("too many custodians".into()));
        }
        Ok(())
    }
}

/// One custodian's share. Opaque, and useless on its own.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CustodianShare {
    pub vault_id: VaultId,
    pub bytes: Vec<u8>,
}

impl CustodianShare {
    /// Hex, for handing to a custodian out of band.
    pub fn encode(&self) -> String {
        format!(
            "{}:{}",
            self.vault_id,
            self.bytes.iter().map(|b| format!("{b:02x}")).collect::<String>()
        )
    }

    pub fn decode(s: &str) -> Result<Self> {
        let (id, hex) = s
            .split_once(':')
            .ok_or_else(|| Error::Format("share is missing its vault id".into()))?;
        let vault_id: VaultId =
            id.parse().map_err(|_| Error::Format("share has a malformed vault id".into()))?;
        // Bytes, not characters: a `str` slice on a non-character boundary
        // panics, and a share is text somebody else handed over.
        let hex = hex.as_bytes();
        if hex.len() % 2 != 0 || hex.is_empty() {
            return Err(Error::Format("share body is malformed".into()));
        }
        let digit = |c: u8| match c {
            b'0'..=b'9' => Some(c - b'0'),
            b'a'..=b'f' => Some(c - b'a' + 10),
            b'A'..=b'F' => Some(c - b'A' + 10),
            _ => None,
        };
        let mut bytes = Vec::with_capacity(hex.len() / 2);
        for i in (0..hex.len()).step_by(2) {
            bytes.push(
                digit(hex[i])
                    .zip(digit(hex[i + 1]))
                    .map(|(h, l)| h << 4 | l)
                    .ok_or_else(|| Error::Format("share body is not hex".into()))?,
            );
        }
        Ok(CustodianShare { vault_id, bytes })
    }
}

/// The full set produced by a split, for distribution.
#[derive(Debug, Clone)]
pub struct ShareSet {
    pub config: RecoveryConfig,
    pub vault_id: VaultId,
    pub shares: Vec<CustodianShare>,
}

/// Splits a master key into custodian shares.
///
/// Nothing is written to disk. Shares that stay on the machine holding the
/// vault provide no protection, so distribution is the operator's job and the
/// caller receives them in memory.
pub fn split_master_key(
    key: &Key256,
    vault_id: VaultId,
    config: RecoveryConfig,
) -> Result<ShareSet> {
    config.validate()?;
    let sharks = Sharks(config.threshold);
    let dealer = sharks.dealer(key.expose());
    let shares: Vec<CustodianShare> = dealer
        .take(config.custodians as usize)
        .map(|s| CustodianShare { vault_id, bytes: Vec::from(&s) })
        .collect();

    if shares.len() != config.custodians as usize {
        return Err(Error::Crypto("share generation produced the wrong count".into()));
    }
    Ok(ShareSet { config, vault_id, shares })
}

/// Reconstructs a master key from a quorum.
pub fn combine_shares(
    shares: &[CustodianShare],
    vault_id: VaultId,
    config: RecoveryConfig,
    state: DeadmanState,
) -> Result<Key256> {
    // The gate is taken here rather than left to the caller. It existed as a
    // function anybody could forget to call, which meant an API that
    // reconstructs a destroyed vault's key while bypassing the check was one
    // missed line away. A quorum of custodians must not be able to undo a
    // destruction that has been committed.
    if !RecoveryGate::permits(state) {
        return Err(Error::Other(format!(
            "this vault reached {}, and recovery is refused after destruction is \
             committed. The key it would rebuild no longer unwraps anything",
            state.label()
        )));
    }
    config.validate()?;
    if shares.len() < config.threshold as usize {
        return Err(Error::Other(format!(
            "{} shares supplied, {} required",
            shares.len(),
            config.threshold
        )));
    }
    // A share from another vault would silently produce a wrong key, so it is
    // refused rather than mixed in.
    if shares.iter().any(|s| s.vault_id != vault_id) {
        return Err(Error::Other("a share belongs to a different vault".into()));
    }

    let parsed: std::result::Result<Vec<Share>, _> =
        shares.iter().map(|s| Share::try_from(s.bytes.as_slice())).collect();
    let parsed = parsed.map_err(|_| Error::Format("a share is malformed".into()))?;

    let sharks = Sharks(config.threshold);
    let secret = sharks
        .recover(parsed.as_slice())
        .map_err(|_| Error::Crypto("the supplied shares do not reconstruct a key".into()))?;

    if secret.len() != 32 {
        return Err(Error::Crypto("reconstructed key has the wrong length".into()));
    }
    let mut key = Key256::zeroed();
    key.expose_mut().copy_from_slice(&secret);
    Ok(key)
}

/// Enforces that recovery cannot outlive a committed destruction (INV-11).
pub struct RecoveryGate;

impl RecoveryGate {
    /// Whether recovery may proceed given the vault's recorded state.
    pub fn permits(state: DeadmanState) -> bool {
        !state.is_committed()
    }

    pub fn check(state: DeadmanState) -> Result<()> {
        if Self::permits(state) {
            Ok(())
        } else {
            Err(Error::Other(format!(
                "destruction was authorized for this vault (state {}); recovery is refused. \
                 A recovery mechanism that survives a committed deadman event would make the \
                 deadman switch meaningless",
                state.label()
            )))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use zerotrace_crypto::random_key;

    fn config() -> RecoveryConfig {
        RecoveryConfig { threshold: 3, custodians: 5 }
    }

    #[test]
    fn a_quorum_reconstructs_the_key_exactly() {
        let key = random_key();
        let vault = VaultId::from_bytes([4u8; 16]);
        let set = split_master_key(&key, vault, config()).unwrap();
        assert_eq!(set.shares.len(), 5);

        // Any three of the five will do.
        for combo in [[0, 1, 2], [0, 2, 4], [2, 3, 4], [1, 3, 4]] {
            let quorum: Vec<CustodianShare> =
                combo.iter().map(|i| set.shares[*i].clone()).collect();
            assert_eq!(combine_shares(&quorum, vault, config(), DeadmanState::Normal).unwrap(), key, "{combo:?}");
        }
    }

    #[test]
    fn fewer_than_the_threshold_recovers_nothing() {
        let key = random_key();
        let vault = VaultId::from_bytes([4u8; 16]);
        let set = split_master_key(&key, vault, config()).unwrap();

        for n in 0..3 {
            let partial: Vec<CustodianShare> = set.shares[..n].to_vec();
            assert!(combine_shares(&partial, vault, config(), DeadmanState::Normal).is_err(), "{n} shares accepted");
        }
    }

    #[test]
    fn shares_from_another_vault_are_refused_rather_than_mixed_in() {
        let key = random_key();
        let a = VaultId::from_bytes([1u8; 16]);
        let b = VaultId::from_bytes([2u8; 16]);
        let set_a = split_master_key(&key, a, config()).unwrap();
        let set_b = split_master_key(&random_key(), b, config()).unwrap();

        let mixed =
            vec![set_a.shares[0].clone(), set_a.shares[1].clone(), set_b.shares[0].clone()];
        assert!(combine_shares(&mixed, a, config(), DeadmanState::Normal).is_err());
    }

    #[test]
    fn a_single_custodian_is_refused() {
        let bad = RecoveryConfig { threshold: 1, custodians: 5 };
        assert!(bad.validate().is_err());
        assert!(split_master_key(&random_key(), VaultId::nil(), bad).is_err());
    }

    #[test]
    fn an_unsatisfiable_configuration_is_refused() {
        let bad = RecoveryConfig { threshold: 6, custodians: 5 };
        assert!(bad.validate().is_err());
    }

    #[test]
    fn shares_survive_encoding_for_distribution() {
        let key = random_key();
        let vault = VaultId::from_bytes([9u8; 16]);
        let set = split_master_key(&key, vault, config()).unwrap();

        let text: Vec<String> = set.shares.iter().map(|s| s.encode()).collect();
        let back: Vec<CustodianShare> =
            text.iter().map(|t| CustodianShare::decode(t).unwrap()).collect();
        assert_eq!(back, set.shares);
        assert_eq!(combine_shares(&back[..3], vault, config(), DeadmanState::Normal).unwrap(), key);
    }

    #[test]
    fn malformed_shares_error_rather_than_panic() {
        assert!(CustodianShare::decode("").is_err());
        assert!(CustodianShare::decode("no-colon").is_err());
        assert!(CustodianShare::decode("not-a-uuid:aabb").is_err());
        let good = VaultId::from_bytes([1u8; 16]).to_string();
        assert!(CustodianShare::decode(&format!("{good}:xyz")).is_err());
        assert!(CustodianShare::decode(&format!("{good}:")).is_err());
    }

    #[test]
    fn recovery_is_refused_once_destruction_is_committed() {
        // INV-11. This is the answer to "does escrow survive a deadman event".
        for state in [
            DeadmanState::Normal,
            DeadmanState::Warning,
            DeadmanState::Critical,
            DeadmanState::Armed,
        ] {
            assert!(RecoveryGate::permits(state), "{state:?} should still allow recovery");
            RecoveryGate::check(state).unwrap();
        }
        for state in [
            DeadmanState::DestructionAuthorized,
            DeadmanState::KeyErasure,
            DeadmanState::VaultErasure,
            DeadmanState::Destroyed,
        ] {
            assert!(!RecoveryGate::permits(state), "{state:?} must refuse recovery");
            let err = RecoveryGate::check(state).unwrap_err();
            assert!(format!("{err}").contains("refused"));
        }
    }
}

#[cfg(test)]
mod gate_tests {
    use super::*;

    #[test]
    fn a_quorum_cannot_rebuild_a_key_after_destruction_is_committed() {
        // The gate used to be a function a caller could forget to call, which
        // left an API that reconstructs a destroyed vault's key one missed
        // line away.
        let vault = VaultId::from_bytes([4u8; 16]);
        let key = zerotrace_crypto::random_key();
        let config = RecoveryConfig { threshold: 3, custodians: 5 };
        let shares = split_master_key(&key, vault, config).unwrap();

        for state in [DeadmanState::Destroyed, DeadmanState::DestructionAuthorized] {
            let err = combine_shares(&shares.shares[..3], vault, config, state).unwrap_err();
            assert!(
                format!("{err}").contains("refused after destruction"),
                "{state:?}: {err}"
            );
        }

        // And an uncommitted state still recovers, so the gate is not simply
        // refusing everything.
        assert_eq!(
            combine_shares(&shares.shares[..3], vault, config, DeadmanState::Armed).unwrap(),
            key
        );
    }
}
