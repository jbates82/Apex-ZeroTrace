//! A tamper-evident audit log.
//!
//! Records are hash-chained: each one commits to its predecessor, so removing,
//! reordering or editing any record breaks every hash after it. That does not
//! make the log tamper-*proof* on a machine the attacker controls, since they
//! can recompute the whole chain from the point of change. What it does is make
//! a partial edit impossible to hide, and it is the substrate a later phase
//! needs for anchoring the destruction state.
//!
//! # What is deliberately not recorded
//!
//! No passwords, key material, plaintext, or file contents. Paths are recorded
//! only when the caller passes them, and the CLI does not.

#![forbid(unsafe_code)]

use std::fmt::Write as _;
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};

use zerotrace_core::{Error, Result, VaultId};
use zerotrace_crypto::sha256;

/// One entry in the chain.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuditRecord {
    pub sequence: u64,
    pub vault_id: VaultId,
    pub event: String,
    /// Seconds since the Unix epoch, from the wall clock. Phase 3 adds
    /// monotonic anchoring; until then a clock change is not detectable here.
    pub timestamp: i64,
    /// Free-form context. Must never contain secrets.
    pub detail: String,
    pub prev_hash: [u8; 32],
    pub hash: [u8; 32],
}

impl AuditRecord {
    /// The bytes the record's hash commits to.
    fn preimage(
        sequence: u64,
        vault_id: &VaultId,
        event: &str,
        timestamp: i64,
        detail: &str,
        prev_hash: &[u8; 32],
    ) -> Vec<u8> {
        // Length-prefixed so that moving a character between two fields cannot
        // produce the same preimage.
        let mut b = Vec::with_capacity(128);
        b.extend_from_slice(b"apex-zerotrace:audit:v1");
        b.extend_from_slice(&sequence.to_le_bytes());
        b.extend_from_slice(vault_id.as_bytes());
        b.extend_from_slice(&(event.len() as u32).to_le_bytes());
        b.extend_from_slice(event.as_bytes());
        b.extend_from_slice(&timestamp.to_le_bytes());
        b.extend_from_slice(&(detail.len() as u32).to_le_bytes());
        b.extend_from_slice(detail.as_bytes());
        b.extend_from_slice(prev_hash);
        b
    }

    fn compute_hash(&self) -> [u8; 32] {
        sha256(&Self::preimage(
            self.sequence,
            &self.vault_id,
            &self.event,
            self.timestamp,
            &self.detail,
            &self.prev_hash,
        ))
    }

    fn encode(&self) -> String {
        let mut s = String::new();
        let _ = write!(
            s,
            "{}\t{}\t{}\t{}\t{}\t{}\t{}",
            self.sequence,
            self.vault_id,
            self.event,
            self.timestamp,
            self.detail.replace('\t', " ").replace('\n', " "),
            hex(&self.prev_hash),
            hex(&self.hash)
        );
        s
    }

    fn decode(line: &str) -> Result<Self> {
        let f: Vec<&str> = line.split('\t').collect();
        if f.len() != 7 {
            return Err(Error::Format("audit record has the wrong field count".into()));
        }
        Ok(AuditRecord {
            sequence: f[0].parse().map_err(|_| Error::Format("bad sequence".into()))?,
            vault_id: f[1].parse().map_err(|_| Error::Format("bad vault id".into()))?,
            event: f[2].to_string(),
            timestamp: f[3].parse().map_err(|_| Error::Format("bad timestamp".into()))?,
            detail: f[4].to_string(),
            prev_hash: unhex(f[5])?,
            hash: unhex(f[6])?,
        })
    }
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
        return Err(Error::Format("audit hash has the wrong length".into()));
    }
    let mut out = [0u8; 32];
    for i in 0..32 {
        out[i] = hex_pair(s[i * 2], s[i * 2 + 1])
            .ok_or_else(|| Error::Format("audit hash is not hex".into()))?;
    }
    Ok(out)
}

/// The genesis value the first record chains from.
pub const GENESIS: [u8; 32] = [0u8; 32];

/// An append-only log on disk.
pub struct AuditLog {
    path: PathBuf,
    vault_id: VaultId,
    last_hash: [u8; 32],
    next_sequence: u64,
}

/// What `verify` found.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ChainStatus {
    /// Every record's hash and link check out.
    Intact { records: u64 },
    /// The chain breaks at this sequence number.
    Broken { at_sequence: u64, reason: String },
}

impl AuditLog {
    /// Opens or creates the log for a vault, resuming the chain.
    pub fn open<P: AsRef<Path>>(path: P, vault_id: VaultId) -> Result<Self> {
        let path = path.as_ref().to_path_buf();
        let mut last_hash = GENESIS;
        let mut next_sequence = 0u64;

        if path.exists() {
            for r in read_all(&path)? {
                last_hash = r.hash;
                next_sequence = r.sequence + 1;
            }
        }
        Ok(AuditLog { path, vault_id, last_hash, next_sequence })
    }

    pub fn append(&mut self, event: &str, detail: &str) -> Result<AuditRecord> {
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs() as i64)
            .unwrap_or(0);
        self.append_at(event, detail, timestamp)
    }

    /// Appends with an explicit timestamp, so tests are deterministic.
    pub fn append_at(&mut self, event: &str, detail: &str, timestamp: i64) -> Result<AuditRecord> {
        let mut rec = AuditRecord {
            sequence: self.next_sequence,
            vault_id: self.vault_id,
            event: event.to_string(),
            timestamp,
            detail: detail.replace('\t', " ").replace('\n', " "),
            prev_hash: self.last_hash,
            hash: [0u8; 32],
        };
        rec.hash = rec.compute_hash();

        let mut f = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.path)?;
        writeln!(f, "{}", rec.encode())?;
        // An audit record that is still in a buffer when the process dies is
        // not an audit record.
        f.flush()?;
        f.sync_all()?;

        self.last_hash = rec.hash;
        self.next_sequence += 1;
        Ok(rec)
    }

    pub fn records(&self) -> Result<Vec<AuditRecord>> {
        if !self.path.exists() {
            return Ok(Vec::new());
        }
        read_all(&self.path)
    }

    /// Walks the chain, reporting the first break.
    ///
    /// A line that will not parse is a break, not a read failure.
    pub fn verify(&self) -> Result<ChainStatus> {
        if !self.path.exists() {
            return Ok(ChainStatus::Intact { records: 0 });
        }
        let (records, stopped) = read_all_lenient(&self.path)?;
        if let Some(line) = stopped {
            return Ok(ChainStatus::Broken {
                at_sequence: records.len() as u64,
                reason: format!("record on line {} could not be read", line + 1),
            });
        }
        Ok(verify_records(&records))
    }
}

/// Reads the log, stopping at the first line that will not parse.
///
/// Returns the records read and, when parsing stopped early, the line number
/// it stopped at.
///
/// A damaged line used to abort the whole read, which had two bad effects: the
/// entire history became unviewable because of one bad byte, and `verify`
/// returned an I/O error instead of reporting tamper evidence. Silently
/// returning the good prefix would be worse still, since a prefix of a valid
/// chain is itself valid and the damage would look like a clean short log.
/// Reporting the stopping point lets the caller call it what it is: a break.
fn read_all_lenient(path: &Path) -> Result<(Vec<AuditRecord>, Option<u64>)> {
    let f = std::fs::File::open(path)?;
    let mut out = Vec::new();
    for (i, line) in BufReader::new(f).lines().enumerate() {
        let Ok(line) = line else {
            return Ok((out, Some(i as u64)));
        };
        if line.trim().is_empty() {
            continue;
        }
        match AuditRecord::decode(&line) {
            Ok(r) => out.push(r),
            Err(_) => return Ok((out, Some(i as u64))),
        }
    }
    Ok((out, None))
}

fn read_all(path: &Path) -> Result<Vec<AuditRecord>> {
    Ok(read_all_lenient(path)?.0)
}

/// Checks hashes and links across a sequence of records.
pub fn verify_records(records: &[AuditRecord]) -> ChainStatus {
    let mut expected_prev = GENESIS;
    for (i, r) in records.iter().enumerate() {
        if r.sequence != i as u64 {
            return ChainStatus::Broken {
                at_sequence: r.sequence,
                reason: format!("sequence jumps to {} at position {i}", r.sequence),
            };
        }
        if r.prev_hash != expected_prev {
            return ChainStatus::Broken {
                at_sequence: r.sequence,
                reason: "record does not chain to its predecessor".into(),
            };
        }
        if r.compute_hash() != r.hash {
            return ChainStatus::Broken {
                at_sequence: r.sequence,
                reason: "record contents do not match its hash".into(),
            };
        }
        expected_prev = r.hash;
    }
    ChainStatus::Intact { records: records.len() as u64 }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp(tag: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("ztaudit_{tag}_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d.join("audit.log")
    }

    fn seeded(path: &Path) -> AuditLog {
        let id = VaultId::from_bytes([3u8; 16]);
        let mut log = AuditLog::open(path, id).unwrap();
        log.append_at("VAULT_CREATED", "", 1000).unwrap();
        log.append_at("AUTH_SUCCESS", "password", 1001).unwrap();
        log.append_at("FILE_IMPORTED", "1 file", 1002).unwrap();
        log.append_at("VAULT_CLOSED", "", 1003).unwrap();
        log
    }

    #[test]
    fn a_clean_chain_verifies() {
        let p = tmp("clean");
        let log = seeded(&p);
        assert_eq!(log.verify().unwrap(), ChainStatus::Intact { records: 4 });
    }

    #[test]
    fn the_chain_resumes_across_reopening() {
        let p = tmp("resume");
        let _ = seeded(&p);
        let mut log = AuditLog::open(&p, VaultId::from_bytes([3u8; 16])).unwrap();
        log.append_at("VAULT_OPENED", "", 1004).unwrap();
        assert_eq!(log.verify().unwrap(), ChainStatus::Intact { records: 5 });
    }

    #[test]
    fn editing_a_record_breaks_the_chain() {
        let p = tmp("edit");
        let log = seeded(&p);
        let mut recs = log.records().unwrap();
        // Rewrite history: the import never happened.
        recs[2].event = "NOTHING_HAPPENED".into();
        match verify_records(&recs) {
            ChainStatus::Broken { at_sequence, .. } => assert_eq!(at_sequence, 2),
            other => panic!("edit not detected: {other:?}"),
        }
    }

    #[test]
    fn deleting_a_record_breaks_the_chain() {
        let p = tmp("delete");
        let log = seeded(&p);
        let mut recs = log.records().unwrap();
        recs.remove(1);
        assert!(matches!(verify_records(&recs), ChainStatus::Broken { .. }));
    }

    #[test]
    fn reordering_records_breaks_the_chain() {
        let p = tmp("reorder");
        let log = seeded(&p);
        let mut recs = log.records().unwrap();
        recs.swap(1, 2);
        assert!(matches!(verify_records(&recs), ChainStatus::Broken { .. }));
    }

    #[test]
    fn truncating_the_tail_is_not_detectable_and_that_is_documented() {
        // Honest negative result: a prefix of a valid chain is itself a valid
        // chain. Detecting truncation needs an external anchor, which is a
        // Phase 3 concern (the persistent state journal).
        let p = tmp("truncate");
        let log = seeded(&p);
        let mut recs = log.records().unwrap();
        recs.truncate(2);
        assert_eq!(verify_records(&recs), ChainStatus::Intact { records: 2 });
    }

    #[test]
    fn records_survive_a_round_trip_through_the_file() {
        let p = tmp("roundtrip");
        let log = seeded(&p);
        let recs = log.records().unwrap();
        assert_eq!(recs.len(), 4);
        assert_eq!(recs[0].event, "VAULT_CREATED");
        assert_eq!(recs[3].timestamp, 1003);
        assert_eq!(recs[0].prev_hash, GENESIS);
        assert_eq!(recs[1].prev_hash, recs[0].hash);
    }

    #[test]
    fn a_damaged_line_is_reported_as_a_break_not_as_a_read_failure() {
        // One bad byte used to make the whole history unreadable, and `verify`
        // returned an I/O error rather than tamper evidence.
        let p = tmp("damaged");
        // Called for the records it writes, not for the handle it returns.
        seeded(&p);
        let mut text = std::fs::read_to_string(&p).unwrap();
        text.push_str("this line is not a record at all\n");
        std::fs::write(&p, text).unwrap();

        let reopened = AuditLog::open(&p, VaultId::from_bytes([3u8; 16])).unwrap();
        // The readable history is still available.
        assert_eq!(reopened.records().unwrap().len(), 4);
        // And the damage is named.
        match reopened.verify().unwrap() {
            ChainStatus::Broken { reason, .. } => {
                assert!(reason.contains("could not be read"), "{reason}")
            }
            other => panic!("damage not reported: {other:?}"),
        }
    }

    #[test]
    fn tabs_and_newlines_in_detail_cannot_forge_fields() {
        let p = tmp("inject");
        let mut log = AuditLog::open(&p, VaultId::from_bytes([1u8; 16])).unwrap();
        log.append_at("AUTH_FAILURE", "evil\tfield\ninjection", 5).unwrap();
        let recs = log.records().unwrap();
        assert_eq!(recs.len(), 1);
        assert!(!recs[0].detail.contains('\t'));
        assert_eq!(verify_records(&recs), ChainStatus::Intact { records: 1 });
    }
}
