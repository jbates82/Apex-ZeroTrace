//! The persistent deadman state journal.
//!
//! Hash-chained like the audit log, but with two differences that matter.
//!
//! Every record carries the state machine's position, so the journal is the
//! authority on what state a vault is in across restarts. Phase 4 will read it
//! to decide whether a destruction that was interrupted must be resumed.
//!
//! And every record commits to the audit log's length and last hash. That is
//! what finally makes audit truncation detectable: a prefix of a valid audit
//! chain is itself a valid audit chain, so the audit log cannot notice its own
//! tail being removed, but the journal remembers how long it should be.
//!
//! State transitions are checked against the rules in `zerotrace-core::state`
//! before a record is written, so an illegal transition cannot be recorded
//! even by a caller that asks for one.

#![forbid(unsafe_code)]

use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};

use zerotrace_core::state::{transition, DeadmanState};
use zerotrace_core::time::TimeAnchor;
use zerotrace_core::{Error, Result, VaultId};
use zerotrace_crypto::sha256;

/// What the audit log looked like when a state record was written.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct AuditAnchor {
    pub records: u64,
    pub last_hash: [u8; 32],
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StateRecord {
    pub sequence: u64,
    pub vault_id: VaultId,
    pub state: DeadmanState,
    pub observed: TimeAnchor,
    /// Absolute wall-clock deadline, or 0 when the policy is disabled.
    pub deadline: i64,
    pub confidence: u32,
    pub audit: AuditAnchor,
    pub prev_hash: [u8; 32],
    pub hash: [u8; 32],
}

impl StateRecord {
    fn compute_hash(&self) -> [u8; 32] {
        let mut b = Vec::with_capacity(160);
        b.extend_from_slice(b"apex-zerotrace:journal:v1");
        b.extend_from_slice(&self.sequence.to_le_bytes());
        b.extend_from_slice(self.vault_id.as_bytes());
        b.extend_from_slice(self.state.label().as_bytes());
        b.extend_from_slice(&self.observed.wall.to_le_bytes());
        b.extend_from_slice(&self.observed.monotonic.to_le_bytes());
        b.extend_from_slice(&self.deadline.to_le_bytes());
        b.extend_from_slice(&self.confidence.to_le_bytes());
        b.extend_from_slice(&self.audit.records.to_le_bytes());
        b.extend_from_slice(&self.audit.last_hash);
        b.extend_from_slice(&self.prev_hash);
        sha256(&b)
    }

    fn encode(&self) -> String {
        format!(
            "{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}",
            self.sequence,
            self.vault_id,
            self.state.label(),
            self.observed.wall,
            self.observed.monotonic,
            self.deadline,
            self.confidence,
            self.audit.records,
            hex(&self.audit.last_hash),
            hex(&self.prev_hash),
            hex(&self.hash)
        )
    }

    fn decode(line: &str) -> Result<Self> {
        let f: Vec<&str> = line.split('\t').collect();
        if f.len() != 11 {
            return Err(Error::Format("journal record has the wrong field count".into()));
        }
        let state = state_from_label(f[2])?;
        Ok(StateRecord {
            sequence: f[0].parse().map_err(|_| Error::Format("bad sequence".into()))?,
            vault_id: f[1].parse().map_err(|_| Error::Format("bad vault id".into()))?,
            state,
            observed: TimeAnchor {
                wall: f[3].parse().map_err(|_| Error::Format("bad wall time".into()))?,
                monotonic: f[4].parse().map_err(|_| Error::Format("bad monotonic".into()))?,
            },
            deadline: f[5].parse().map_err(|_| Error::Format("bad deadline".into()))?,
            confidence: f[6].parse().map_err(|_| Error::Format("bad confidence".into()))?,
            audit: AuditAnchor {
                records: f[7].parse().map_err(|_| Error::Format("bad audit count".into()))?,
                last_hash: unhex(f[8])?,
            },
            prev_hash: unhex(f[9])?,
            hash: unhex(f[10])?,
        })
    }
}

fn state_from_label(s: &str) -> Result<DeadmanState> {
    use DeadmanState::*;
    Ok(match s {
        "NORMAL" => Normal,
        "WARNING" => Warning,
        "CRITICAL" => Critical,
        "ARMED" => Armed,
        "DESTRUCTION_AUTHORIZED" => DestructionAuthorized,
        "KEY_ERASURE" => KeyErasure,
        "VAULT_ERASURE" => VaultErasure,
        "PLATFORM_SANITIZATION" => PlatformSanitization,
        "VERIFICATION" => Verification,
        "DESTROYED" => Destroyed,
        other => {
            return Err(Error::Unsupported { what: "deadman state", value: other.to_string() })
        }
    })
}

fn hex(b: &[u8; 32]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

/// Decodes one hex pair, or nothing.
fn hex_pair(hi: u8, lo: u8) -> Option<u8> {
    let digit = |c: u8| match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        b'A'..=b'F' => Some(c - b'A' + 10),
        _ => None,
    };
    Some(digit(hi)? << 4 | digit(lo)?)
}

fn unhex(s: &str) -> Result<[u8; 32]> {
    // Bytes, not characters. A byte-length check followed by a `str` slice
    // panics on any multi-byte character, and a log line is untrusted input.
    let s = s.as_bytes();
    if s.len() != 64 {
        return Err(Error::Format("journal hash has the wrong length".into()));
    }
    let mut out = [0u8; 32];
    for i in 0..32 {
        out[i] = hex_pair(s[i * 2], s[i * 2 + 1])
            .ok_or_else(|| Error::Format("journal hash is not hex".into()))?;
    }
    Ok(out)
}

pub const GENESIS: [u8; 32] = [0u8; 32];

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum JournalStatus {
    Intact { records: u64, state: DeadmanState },
    Broken { at_sequence: u64, reason: String },
}

/// What checking the audit anchor found.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuditAnchorStatus {
    /// The audit log is at least as long as the journal remembers, and the
    /// remembered hash still appears at the remembered position.
    Consistent,
    /// The audit log is shorter than the journal recorded.
    Truncated { expected: u64, found: u64 },
    /// The audit record at the anchored position no longer matches.
    Diverged { at: u64 },
    /// No anchor has been written yet.
    NoAnchor,
}

pub struct StateJournal {
    path: PathBuf,
    vault_id: VaultId,
    last_hash: [u8; 32],
    next_sequence: u64,
    current: DeadmanState,
}

impl StateJournal {
    /// Opens or creates the journal, resuming the recorded state.
    pub fn open<P: AsRef<Path>>(path: P, vault_id: VaultId) -> Result<Self> {
        let path = path.as_ref().to_path_buf();
        let mut last_hash = GENESIS;
        let mut next_sequence = 0u64;
        let mut current = DeadmanState::Normal;

        if path.exists() {
            for r in read_all(&path)? {
                last_hash = r.hash;
                next_sequence = r.sequence + 1;
                current = r.state;
            }
        }
        Ok(Self { path, vault_id, last_hash, next_sequence, current })
    }

    /// The state this vault is in, as recorded on disk.
    pub fn state(&self) -> DeadmanState {
        self.current
    }

    pub fn records(&self) -> Result<Vec<StateRecord>> {
        if !self.path.exists() {
            return Ok(Vec::new());
        }
        read_all(&self.path)
    }

    /// Records a transition, refusing any the state machine forbids.
    ///
    /// This is where INV-6 and INV-7 become durable rather than merely
    /// in-memory: an illegal transition is never written, so a restart cannot
    /// read one back.
    pub fn record(
        &mut self,
        to: DeadmanState,
        observed: TimeAnchor,
        deadline: i64,
        confidence: u32,
        audit: AuditAnchor,
    ) -> Result<StateRecord> {
        transition(self.current, to)?;

        let mut rec = StateRecord {
            sequence: self.next_sequence,
            vault_id: self.vault_id,
            state: to,
            observed,
            deadline,
            confidence,
            audit,
            prev_hash: self.last_hash,
            hash: [0u8; 32],
        };
        rec.hash = rec.compute_hash();

        let mut f = std::fs::OpenOptions::new().create(true).append(true).open(&self.path)?;
        writeln!(f, "{}", rec.encode())?;
        f.flush()?;
        // A state record that is lost in a buffer during a power failure is
        // the difference between resuming correctly and not knowing.
        f.sync_all()?;

        self.last_hash = rec.hash;
        self.next_sequence += 1;
        self.current = to;
        Ok(rec)
    }

    pub fn verify(&self) -> Result<JournalStatus> {
        if !self.path.exists() {
            return Ok(JournalStatus::Intact { records: 0, state: DeadmanState::Normal });
        }
        let (records, stopped) = read_all_lenient(&self.path)?;
        if let Some(line) = stopped {
            return Ok(JournalStatus::Broken {
                at_sequence: records.len() as u64,
                reason: format!("record on line {} could not be read", line + 1),
            });
        }
        Ok(verify_records(&records))
    }

    /// Checks the audit log against the anchor in the newest record.
    ///
    /// This is what makes audit truncation detectable. The audit chain cannot
    /// see its own tail being removed; the journal remembers how long it was.
    pub fn check_audit_anchor(
        &self,
        audit_records: u64,
        hash_at: impl Fn(u64) -> Option<[u8; 32]>,
    ) -> Result<AuditAnchorStatus> {
        let records = self.records()?;
        let Some(last) = records.last() else {
            return Ok(AuditAnchorStatus::NoAnchor);
        };
        if last.audit.records == 0 {
            return Ok(AuditAnchorStatus::NoAnchor);
        }
        if audit_records < last.audit.records {
            return Ok(AuditAnchorStatus::Truncated {
                expected: last.audit.records,
                found: audit_records,
            });
        }
        match hash_at(last.audit.records - 1) {
            Some(h) if h == last.audit.last_hash => Ok(AuditAnchorStatus::Consistent),
            _ => Ok(AuditAnchorStatus::Diverged { at: last.audit.records - 1 }),
        }
    }
}

/// Reads the journal, stopping at the first line that will not parse.
///
/// See the equivalent in `zerotrace-audit` for why a damaged line is reported
/// rather than raised: for the journal it matters more, because failing to
/// load is indistinguishable from a missing file and could leave an
/// interrupted destruction unresumed.
fn read_all_lenient(path: &Path) -> Result<(Vec<StateRecord>, Option<u64>)> {
    let f = std::fs::File::open(path)?;
    let mut out = Vec::new();
    for (i, line) in BufReader::new(f).lines().enumerate() {
        let Ok(line) = line else {
            return Ok((out, Some(i as u64)));
        };
        if line.trim().is_empty() {
            continue;
        }
        match StateRecord::decode(&line) {
            Ok(r) => out.push(r),
            Err(_) => return Ok((out, Some(i as u64))),
        }
    }
    Ok((out, None))
}

fn read_all(path: &Path) -> Result<Vec<StateRecord>> {
    Ok(read_all_lenient(path)?.0)
}

pub fn verify_records(records: &[StateRecord]) -> JournalStatus {
    let mut expected_prev = GENESIS;
    let mut state = DeadmanState::Normal;
    let mut first = true;

    for (i, r) in records.iter().enumerate() {
        if r.sequence != i as u64 {
            return JournalStatus::Broken {
                at_sequence: r.sequence,
                reason: format!("sequence jumps to {} at position {i}", r.sequence),
            };
        }
        if r.prev_hash != expected_prev {
            return JournalStatus::Broken {
                at_sequence: r.sequence,
                reason: "record does not chain to its predecessor".into(),
            };
        }
        if r.compute_hash() != r.hash {
            return JournalStatus::Broken {
                at_sequence: r.sequence,
                reason: "record contents do not match its hash".into(),
            };
        }
        // A journal that records an impossible transition has been edited,
        // even if every hash was recomputed to match.
        if !first && !state.can_transition_to(r.state) {
            return JournalStatus::Broken {
                at_sequence: r.sequence,
                reason: format!("illegal transition {} -> {}", state.label(), r.state.label()),
            };
        }
        state = r.state;
        first = false;
        expected_prev = r.hash;
    }

    JournalStatus::Intact { records: records.len() as u64, state }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp(tag: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("ztjournal_{tag}_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d.join("state.journal")
    }

    fn at(t: i64) -> TimeAnchor {
        TimeAnchor { wall: t, monotonic: t as u64 }
    }

    #[test]
    fn a_clean_journal_verifies_and_reports_its_state() {
        let p = tmp("clean");
        let mut j = StateJournal::open(&p, VaultId::from_bytes([1u8; 16])).unwrap();
        j.record(DeadmanState::Normal, at(0), 0, 100, AuditAnchor::default()).unwrap();
        j.record(DeadmanState::Warning, at(10), 100, 70, AuditAnchor::default()).unwrap();
        j.record(DeadmanState::Critical, at(20), 100, 20, AuditAnchor::default()).unwrap();
        assert_eq!(
            j.verify().unwrap(),
            JournalStatus::Intact { records: 3, state: DeadmanState::Critical }
        );
    }

    #[test]
    fn the_recorded_state_survives_a_restart() {
        let p = tmp("restart");
        {
            let mut j = StateJournal::open(&p, VaultId::from_bytes([1u8; 16])).unwrap();
            j.record(DeadmanState::Warning, at(0), 0, 70, AuditAnchor::default()).unwrap();
        }
        let j = StateJournal::open(&p, VaultId::from_bytes([1u8; 16])).unwrap();
        assert_eq!(j.state(), DeadmanState::Warning);
    }

    #[test]
    fn an_illegal_transition_is_never_written() {
        let p = tmp("illegal");
        let mut j = StateJournal::open(&p, VaultId::from_bytes([1u8; 16])).unwrap();
        j.record(DeadmanState::Normal, at(0), 0, 100, AuditAnchor::default()).unwrap();
        // Skipping stages is refused, so it cannot reach the disk.
        assert!(j
            .record(DeadmanState::Destroyed, at(1), 0, 0, AuditAnchor::default())
            .is_err());
        assert_eq!(j.state(), DeadmanState::Normal);
        assert_eq!(j.records().unwrap().len(), 1);
    }

    #[test]
    fn editing_a_record_breaks_the_chain() {
        let p = tmp("edit");
        let mut j = StateJournal::open(&p, VaultId::from_bytes([1u8; 16])).unwrap();
        j.record(DeadmanState::Normal, at(0), 0, 100, AuditAnchor::default()).unwrap();
        j.record(DeadmanState::Warning, at(10), 0, 70, AuditAnchor::default()).unwrap();
        let mut recs = j.records().unwrap();
        recs[1].confidence = 100;
        assert!(matches!(verify_records(&recs), JournalStatus::Broken { .. }));
    }

    #[test]
    fn a_rewritten_rollback_is_caught_by_the_transition_rules() {
        // An attacker who recomputes every hash still cannot produce a journal
        // that walks backwards out of a committed state.
        let mut recs = Vec::new();
        let id = VaultId::from_bytes([2u8; 16]);
        let mut prev = GENESIS;
        for (i, st) in [
            DeadmanState::Normal,
            DeadmanState::Warning,
            DeadmanState::Critical,
            DeadmanState::Armed,
            DeadmanState::DestructionAuthorized,
            DeadmanState::Normal, // the forgery
        ]
        .into_iter()
        .enumerate()
        {
            let mut r = StateRecord {
                sequence: i as u64,
                vault_id: id,
                state: st,
                observed: at(i as i64),
                deadline: 0,
                confidence: 0,
                audit: AuditAnchor::default(),
                prev_hash: prev,
                hash: [0u8; 32],
            };
            r.hash = r.compute_hash();
            prev = r.hash;
            recs.push(r);
        }
        match verify_records(&recs) {
            JournalStatus::Broken { at_sequence, reason } => {
                assert_eq!(at_sequence, 5);
                assert!(reason.contains("illegal transition"), "{reason}");
            }
            other => panic!("rollback not detected: {other:?}"),
        }
    }

    #[test]
    fn the_journal_detects_audit_truncation() {
        // The promise made when the audit log was built: a hash chain cannot
        // see its own tail removed, but an external anchor can.
        let p = tmp("anchor");
        let mut j = StateJournal::open(&p, VaultId::from_bytes([1u8; 16])).unwrap();
        let audit_hashes: Vec<[u8; 32]> = (0..5u8).map(|i| sha256(&[i])).collect();
        j.record(
            DeadmanState::Normal,
            at(0),
            0,
            100,
            AuditAnchor { records: 5, last_hash: audit_hashes[4] },
        )
        .unwrap();

        let lookup = |i: u64| audit_hashes.get(i as usize).copied();
        assert_eq!(j.check_audit_anchor(5, lookup).unwrap(), AuditAnchorStatus::Consistent);

        // Two records removed from the end.
        assert_eq!(
            j.check_audit_anchor(3, lookup).unwrap(),
            AuditAnchorStatus::Truncated { expected: 5, found: 3 }
        );

        // Same length, different content.
        let tampered: Vec<[u8; 32]> = (10..15u8).map(|i| sha256(&[i])).collect();
        let lookup2 = |i: u64| tampered.get(i as usize).copied();
        assert_eq!(
            j.check_audit_anchor(5, lookup2).unwrap(),
            AuditAnchorStatus::Diverged { at: 4 }
        );
    }

    #[test]
    fn records_survive_a_round_trip_through_the_file() {
        let p = tmp("roundtrip");
        let mut j = StateJournal::open(&p, VaultId::from_bytes([7u8; 16])).unwrap();
        let written = j
            .record(DeadmanState::Warning, at(1234), 9999, 42, AuditAnchor { records: 3, last_hash: [8u8; 32] })
            .unwrap();
        let read = &StateJournal::open(&p, VaultId::from_bytes([7u8; 16]))
            .unwrap()
            .records()
            .unwrap()[0];
        assert_eq!(*read, written);
    }
}
