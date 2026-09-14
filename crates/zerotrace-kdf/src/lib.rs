//! Password-based key derivation.
//!
//! Only Argon2id is offered. Parameters live in the vault header so they can
//! be raised later, which means they are attacker-controlled bytes until the
//! header is authenticated: every value is therefore range-checked before use,
//! and values below the floor are refused rather than accepted quietly.

#![forbid(unsafe_code)]

pub mod strength;

use argon2::{Algorithm, Argon2, Params, Version};
use serde::{Deserialize, Serialize};
use zerotrace_core::{Error, Result};
use zerotrace_secure_memory::Key256;

/// Lowest parameters this build will derive with.
///
/// A vault whose header asks for less is refused. Without this an attacker who
/// can hand you a crafted vault could downgrade the KDF to something trivially
/// brute-forced and you would never see it happen.
pub const MIN_MEMORY_KIB: u32 = 19 * 1024; // 19 MiB, the OWASP Argon2id floor
pub const MIN_TIME_COST: u32 = 2;
pub const MIN_PARALLELISM: u32 = 1;

/// Upper bounds, so a hostile header cannot demand 64 GiB of memory.
pub const MAX_MEMORY_KIB: u32 = 4 * 1024 * 1024; // 4 GiB
pub const MAX_TIME_COST: u32 = 64;
pub const MAX_PARALLELISM: u32 = 64;

pub const SALT_LEN: usize = 32;

/// Argon2id cost parameters as stored in the vault header.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct KdfParams {
    /// Memory cost in KiB.
    pub memory_kib: u32,
    /// Iterations.
    pub time_cost: u32,
    /// Lanes.
    pub parallelism: u32,
}

impl KdfParams {
    /// Interactive default: roughly 140 ms on a 2020-era desktop core.
    pub const INTERACTIVE: KdfParams =
        KdfParams { memory_kib: 64 * 1024, time_cost: 3, parallelism: 1 };

    /// For vaults where unlock latency matters less than offline-guessing cost.
    pub const SENSITIVE: KdfParams =
        KdfParams { memory_kib: 256 * 1024, time_cost: 4, parallelism: 1 };

    /// Rejects anything outside the accepted range.
    ///
    /// Called before deriving, on parameters that came from a file.
    pub fn validate(&self) -> Result<()> {
        if self.memory_kib < MIN_MEMORY_KIB {
            return Err(Error::Kdf(format!(
                "vault requests {} KiB of KDF memory, below the {MIN_MEMORY_KIB} KiB minimum; \
                 refusing rather than deriving a weak key",
                self.memory_kib
            )));
        }
        if self.time_cost < MIN_TIME_COST {
            return Err(Error::Kdf(format!(
                "vault requests {} KDF iterations, below the minimum of {MIN_TIME_COST}",
                self.time_cost
            )));
        }
        if self.parallelism < MIN_PARALLELISM {
            return Err(Error::Kdf("vault requests zero KDF lanes".into()));
        }
        if self.memory_kib > MAX_MEMORY_KIB
            || self.time_cost > MAX_TIME_COST
            || self.parallelism > MAX_PARALLELISM
        {
            return Err(Error::LimitExceeded(format!(
                "KDF parameters exceed the accepted range (m={} t={} p={})",
                self.memory_kib, self.time_cost, self.parallelism
            )));
        }
        Ok(())
    }

    /// True when `other` is at least as strong in every dimension.
    ///
    /// Used to refuse a "re-key" that would quietly weaken a vault.
    pub fn is_at_least_as_strong_as(&self, other: &KdfParams) -> bool {
        self.memory_kib >= other.memory_kib
            && self.time_cost >= other.time_cost
            && self.parallelism >= other.parallelism
    }
}

impl Default for KdfParams {
    fn default() -> Self {
        Self::INTERACTIVE
    }
}

/// Derives the password-derived key-encryption key.
///
/// The result wraps the vault master key; it never encrypts file data
/// directly, so changing a password rewraps rather than re-encrypts (INV-3).
pub fn derive_kek(password: &[u8], salt: &[u8], params: KdfParams) -> Result<Key256> {
    params.validate()?;
    if salt.len() < 16 {
        return Err(Error::Kdf("KDF salt is too short".into()));
    }

    let p = Params::new(params.memory_kib, params.time_cost, params.parallelism, Some(32))
        .map_err(|e| Error::Kdf(format!("invalid Argon2 parameters: {e}")))?;
    let argon = Argon2::new(Algorithm::Argon2id, Version::V0x13, p);

    let mut key = Key256::zeroed();
    argon
        .hash_password_into(password, salt, key.expose_mut())
        .map_err(|e| Error::Kdf(format!("Argon2id failed: {e}")))?;
    Ok(key)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn weak_parameters_are_refused_not_accepted() {
        // The downgrade attack this exists to stop.
        let weak = KdfParams { memory_kib: 8, time_cost: 1, parallelism: 1 };
        assert!(weak.validate().is_err());
        assert!(derive_kek(b"password", &[0u8; 32], weak).is_err());
    }

    #[test]
    fn absurd_parameters_are_refused() {
        let huge = KdfParams { memory_kib: u32::MAX, time_cost: 1000, parallelism: 1 };
        assert!(huge.validate().is_err());
    }

    #[test]
    fn defaults_pass_their_own_floor() {
        KdfParams::INTERACTIVE.validate().unwrap();
        KdfParams::SENSITIVE.validate().unwrap();
        assert!(KdfParams::SENSITIVE.is_at_least_as_strong_as(&KdfParams::INTERACTIVE));
        assert!(!KdfParams::INTERACTIVE.is_at_least_as_strong_as(&KdfParams::SENSITIVE));
    }

    #[test]
    fn derivation_is_deterministic_and_salt_dependent() {
        let p = KdfParams { memory_kib: MIN_MEMORY_KIB, time_cost: 2, parallelism: 1 };
        let a = derive_kek(b"password", &[1u8; 32], p).unwrap();
        let b = derive_kek(b"password", &[1u8; 32], p).unwrap();
        let c = derive_kek(b"password", &[2u8; 32], p).unwrap();
        let d = derive_kek(b"different", &[1u8; 32], p).unwrap();
        assert_eq!(a, b);
        assert_ne!(a, c, "different salt must give a different key");
        assert_ne!(a, d, "different password must give a different key");
    }

    #[test]
    fn short_salt_is_refused() {
        let p = KdfParams { memory_kib: MIN_MEMORY_KIB, time_cost: 2, parallelism: 1 };
        assert!(derive_kek(b"password", &[0u8; 8], p).is_err());
    }
}
