//! The custodian side: holding a share and deciding whether to give it back.
//!
//! [`DirectoryCustodian`] keeps its records in a directory. That directory is
//! meant to be somewhere the vault's machine is not: a second computer, a
//! network share, a device in another building. The important property is not
//! the transport but the location. A custodian directory on the same disk as
//! the vault defends against nothing, exactly like a token stored beside it.
//!
//! A network service would be the same logic behind a socket. It is not
//! implemented here, because a protocol that cannot be exercised is worth less
//! than one that can, and this can be run against a mounted share today.

use std::path::{Path, PathBuf};

use zerotrace_core::{Error, Result, VaultId};
use zerotrace_crypto::sha256;

use crate::{Intent, Request, Verdict, REQUEST_VALIDITY};

/// What a custodian holds for one vault.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HeldShare {
    pub vault_id: VaultId,
    /// The share itself. Meaningless without the threshold's other components.
    pub share: Vec<u8>,
    /// Who may check in: the public half of a password-derived key.
    pub owner_key: [u8; 32],
    /// Seconds of silence before the share is destroyed.
    pub timeout_seconds: u64,
    pub last_check_in: i64,
    /// Set once the share has been destroyed. A destroyed record is kept
    /// rather than deleted, so a later request is told what happened instead
    /// of being told the vault is unknown.
    pub expired_at: Option<i64>,
    /// Nonces already used, so a captured request cannot be replayed.
    pub seen: Vec<[u8; 16]>,
}

impl HeldShare {
    /// A new record for a vault, with no requests seen yet.
    pub fn new(
        vault_id: VaultId,
        share: Vec<u8>,
        owner_key: [u8; 32],
        timeout_seconds: u64,
        now: i64,
    ) -> Self {
        Self {
            vault_id,
            share,
            owner_key,
            timeout_seconds,
            last_check_in: now,
            expired_at: None,
            seen: Vec::new(),
        }
    }
}

impl HeldShare {
    pub fn deadline(&self) -> i64 {
        self.last_check_in + self.timeout_seconds as i64
    }
    pub fn is_expired_at(&self, now: i64) -> bool {
        self.expired_at.is_some() || now >= self.deadline()
    }
}

/// Anything that can hold a share on an owner's behalf.
pub trait Custodian {
    fn enroll(&self, held: &HeldShare) -> Result<()>;
    fn handle(&self, request: &Request, now: i64) -> Result<Verdict>;
    fn status(&self, vault_id: VaultId, now: i64) -> Result<Option<(i64, bool)>>;
}

/// A custodian keeping its records in a directory.
pub struct DirectoryCustodian {
    root: PathBuf,
}

impl DirectoryCustodian {
    pub fn new<P: AsRef<Path>>(root: P) -> Self {
        Self { root: root.as_ref().to_path_buf() }
    }

    fn record_path(&self, vault_id: &VaultId) -> PathBuf {
        self.root.join(format!("{vault_id}.custody"))
    }

    fn read(&self, vault_id: &VaultId) -> Option<HeldShare> {
        let text = std::fs::read_to_string(self.record_path(vault_id)).ok()?;
        let mut share = Vec::new();
        let mut owner_key = [0u8; 32];
        let mut timeout_seconds = 0u64;
        let mut last_check_in = 0i64;
        let mut expired_at = None;
        let mut seen = Vec::new();

        for line in text.lines() {
            let Some((k, v)) = line.split_once('=') else { continue };
            match k.trim() {
                "share" => share = unhex_vec(v.trim()),
                "owner_key" => {
                    let b = unhex_vec(v.trim());
                    if b.len() == 32 {
                        owner_key.copy_from_slice(&b);
                    }
                }
                "timeout_seconds" => timeout_seconds = v.trim().parse().unwrap_or(0),
                "last_check_in" => last_check_in = v.trim().parse().unwrap_or(0),
                "expired_at" => expired_at = v.trim().parse().ok(),
                "seen" => {
                    for n in v.trim().split(',').filter(|s| !s.is_empty()) {
                        let b = unhex_vec(n);
                        if b.len() == 16 {
                            let mut a = [0u8; 16];
                            a.copy_from_slice(&b);
                            seen.push(a);
                        }
                    }
                }
                _ => {}
            }
        }
        Some(HeldShare {
            vault_id: *vault_id,
            share,
            owner_key,
            timeout_seconds,
            last_check_in,
            expired_at,
            seen,
        })
    }

    fn write(&self, held: &HeldShare) -> Result<()> {
        std::fs::create_dir_all(&self.root)?;
        let seen: Vec<String> = held.seen.iter().map(|n| hex(n)).collect();
        let text = format!(
            "vault_id={}\nshare={}\nowner_key={}\ntimeout_seconds={}\nlast_check_in={}\nexpired_at={}\nseen={}\n",
            held.vault_id,
            hex(&held.share),
            hex(&held.owner_key),
            held.timeout_seconds,
            held.last_check_in,
            held.expired_at.map(|v| v.to_string()).unwrap_or_default(),
            seen.join(",")
        );
        let path = self.record_path(&held.vault_id);
        std::fs::write(&path, text)?;
        // Holds a component key. A custodian directory is often a network
        // share, where a permissive default is likelier still.
        let _ = zerotrace_core::restrict_permissions(&path);
        Ok(())
    }

    /// Destroys the share, keeping the record so a later request is answered
    /// honestly rather than as an unknown vault.
    fn expire(&self, mut held: HeldShare, now: i64) -> Result<()> {
        held.share.clear();
        held.expired_at = Some(held.expired_at.unwrap_or(now));
        self.write(&held)
    }
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn unhex_vec(s: &str) -> Vec<u8> {
    // Bytes throughout. Slicing a `str` by byte index panics on a character
    // boundary, and a custody record is a file this program did not write.
    let s = s.as_bytes();
    if s.len() % 2 != 0 {
        return Vec::new();
    }
    let digit = |c: u8| match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        b'A'..=b'F' => Some(c - b'A' + 10),
        _ => None,
    };
    (0..s.len())
        .step_by(2)
        .filter_map(|i| Some(digit(s[i])? << 4 | digit(s[i + 1])?))
        .collect()
}

impl Custodian for DirectoryCustodian {
    fn enroll(&self, held: &HeldShare) -> Result<()> {
        if self.read(&held.vault_id).is_some() {
            return Err(Error::Other(
                "this custodian already holds a share for that vault".into(),
            ));
        }
        if held.timeout_seconds == 0 {
            return Err(Error::Other("a custodian needs a timeout".into()));
        }
        self.write(held)
    }

    fn handle(&self, request: &Request, now: i64) -> Result<Verdict> {
        let Some(mut held) = self.read(&request.vault_id) else {
            return Ok(Verdict::Unknown);
        };

        // Answered before the signature is checked, because there is nothing
        // left to protect and no reason to make an expired vault look like a
        // signature problem.
        if let Some(at) = held.expired_at {
            return Ok(Verdict::Expired { expired_at: at });
        }
        if now >= held.deadline() {
            let at = held.deadline();
            self.expire(held, at)?;
            return Ok(Verdict::Expired { expired_at: at });
        }

        if (now - request.issued_at).abs() > REQUEST_VALIDITY {
            return Ok(Verdict::Refused("the request is stale or dated in the future"));
        }
        if held.seen.contains(&request.nonce) {
            return Ok(Verdict::Refused("this request has already been used"));
        }
        if request.verify(&held.owner_key).is_err() {
            // Not recorded as a check-in: a wrong signature must not move the
            // deadline, or an attacker could hold a vault open by spamming
            // requests they cannot sign.
            return Ok(Verdict::Refused("the request was not signed by the owner"));
        }

        held.seen.push(request.nonce);
        // Bounded, so a long-lived record does not grow without limit. Old
        // nonces cannot be replayed usefully because the request itself has
        // long since gone stale.
        if held.seen.len() > 256 {
            let excess = held.seen.len() - 256;
            held.seen.drain(..excess);
        }

        match request.intent {
            Intent::CheckIn => {
                held.last_check_in = now;
                let deadline = held.deadline();
                self.write(&held)?;
                Ok(Verdict::CheckedIn { deadline })
            }
            Intent::Release => {
                let share = held.share.clone();
                self.write(&held)?;
                Ok(Verdict::Released(share))
            }
        }
    }

    fn status(&self, vault_id: VaultId, now: i64) -> Result<Option<(i64, bool)>> {
        Ok(self.read(&vault_id).map(|h| (h.deadline(), h.is_expired_at(now))))
    }
}

/// A fingerprint of a custodian record, for the owner to compare.
pub fn record_fingerprint(held: &HeldShare) -> String {
    let mut b = Vec::new();
    b.extend_from_slice(held.vault_id.as_bytes());
    b.extend_from_slice(&held.owner_key);
    hex(&sha256(&b)[..8])
}
