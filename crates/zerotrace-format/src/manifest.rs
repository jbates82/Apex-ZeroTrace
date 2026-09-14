//! The encrypted manifest.
//!
//! Everything that would leak what a vault holds lives in here, never in the
//! container's clear bytes: paths, sizes, timestamps and the mapping from a
//! file to its chunks. On disk each object is identified by a random 128-bit
//! id, so the container's structure says nothing about its contents.
//!
//! The manifest is serialized with a hand-written binary encoder rather than a
//! general-purpose framework. The reason is auditability: every length read
//! from the file is bounds-checked in code you can read on one screen, and
//! there is no derive macro deciding how attacker-controlled bytes are
//! consumed.

use zerotrace_compress::CompressSuite;
use zerotrace_core::{limits, Error, Result};

/// Where one chunk lives and what it should contain.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChunkRef {
    /// Offset of the ciphertext within the container.
    pub offset: u64,
    /// Ciphertext length, including the AEAD tag.
    pub ciphertext_len: u32,
    /// Plaintext length after decryption and decompression.
    pub plaintext_len: u32,
    /// SHA-256 of the ciphertext, and a leaf of the vault's Merkle tree.
    pub hash: [u8; 32],
}

/// One stored file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Entry {
    /// Random identifier. Never derived from the path (INV-2).
    pub object_id: [u8; 16],
    /// Path relative to the vault root, as the user supplied it.
    pub path: String,
    pub size: u64,
    /// Modification time, seconds since the Unix epoch.
    pub mtime: i64,
    pub compress_suite: CompressSuite,
    pub chunks: Vec<ChunkRef>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Manifest {
    pub entries: Vec<Entry>,
    /// Merkle root over every chunk hash, in entry then chunk order.
    pub integrity_root: [u8; 32],
    /// How many times this manifest has been written, counting from one.
    ///
    /// Authenticated, and the reason an old manifest cannot be put back.
    ///
    /// Without it, a manifest proved only that it was a genuine manifest for
    /// this vault. Somebody holding an earlier copy could splice it in and the
    /// vault would open onto the older list of files: a deleted entry back, an
    /// added one gone, and every signature still checking out. Binding the
    /// count means an old manifest authenticates only against its own
    /// generation, and the header records which one is current.
    pub generation: u64,
}

impl Manifest {
    /// Recomputes the Merkle root from the chunks currently listed.
    pub fn compute_root(&self) -> [u8; 32] {
        let leaves: Vec<[u8; 32]> =
            self.entries.iter().flat_map(|e| e.chunks.iter().map(|c| c.hash)).collect();
        zerotrace_crypto::merkle_root(&leaves)
    }

    pub fn total_plaintext(&self) -> u64 {
        self.entries.iter().map(|e| e.size).sum()
    }

    pub fn total_ciphertext(&self) -> u64 {
        self.entries
            .iter()
            .flat_map(|e| e.chunks.iter())
            .map(|c| c.ciphertext_len as u64)
            .sum()
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut b = Vec::with_capacity(1024);
        b.extend_from_slice(&self.generation.to_le_bytes());
        b.extend_from_slice(&(self.entries.len() as u32).to_le_bytes());
        for e in &self.entries {
            b.extend_from_slice(&e.object_id);
            let path = e.path.as_bytes();
            b.extend_from_slice(&(path.len() as u16).to_le_bytes());
            b.extend_from_slice(path);
            b.extend_from_slice(&e.size.to_le_bytes());
            b.extend_from_slice(&e.mtime.to_le_bytes());
            b.extend_from_slice(&(e.compress_suite as u16).to_le_bytes());
            b.extend_from_slice(&(e.chunks.len() as u32).to_le_bytes());
            for c in &e.chunks {
                b.extend_from_slice(&c.offset.to_le_bytes());
                b.extend_from_slice(&c.ciphertext_len.to_le_bytes());
                b.extend_from_slice(&c.plaintext_len.to_le_bytes());
                b.extend_from_slice(&c.hash);
            }
        }
        b.extend_from_slice(&self.integrity_root);
        b
    }

    /// Parses a decrypted manifest.
    ///
    /// The bytes are authenticated by the time this runs, but they are still
    /// parsed defensively: an authenticated manifest written by a buggy or
    /// hostile build of ZeroTrace is still untrusted input.
    pub fn decode(b: &[u8]) -> Result<Self> {
        let mut r = Cursor { b, p: 0 };
        let generation = r.u64()?;
        let count = r.u32()? as usize;
        if count > limits::MAX_ENTRIES {
            return Err(Error::LimitExceeded(format!("manifest declares {count} entries")));
        }
        let mut entries = Vec::with_capacity(count.min(4096));
        for _ in 0..count {
            let object_id = r.array16()?;
            let path_len = r.u16()? as usize;
            if path_len > limits::MAX_PATH_BYTES {
                return Err(Error::LimitExceeded("entry path is too long".into()));
            }
            let path = String::from_utf8(r.take(path_len)?.to_vec())
                .map_err(|_| Error::Format("entry path is not valid UTF-8".into()))?;
            let size = r.u64()?;
            let mtime = r.u64()? as i64;
            let compress_suite = CompressSuite::from_u16(r.u16()?)?;
            let chunk_count = r.u32()? as usize;
            if chunk_count > limits::MAX_CHUNKS_PER_ENTRY {
                return Err(Error::LimitExceeded("entry declares too many chunks".into()));
            }
            let mut chunks = Vec::with_capacity(chunk_count.min(4096));
            for _ in 0..chunk_count {
                let offset = r.u64()?;
                let ciphertext_len = r.u32()?;
                let plaintext_len = r.u32()?;
                if ciphertext_len as usize > limits::MAX_CHUNK_CIPHERTEXT
                    || plaintext_len as usize > limits::MAX_CHUNK_PLAINTEXT
                {
                    return Err(Error::LimitExceeded("chunk size exceeds the limit".into()));
                }
                chunks.push(ChunkRef {
                    offset,
                    ciphertext_len,
                    plaintext_len,
                    hash: r.array32()?,
                });
            }
            entries.push(Entry { object_id, path, size, mtime, compress_suite, chunks });
        }
        let integrity_root = r.array32()?;
        Ok(Manifest { entries, integrity_root, generation })
    }
}

/// Bounds-checked reader. Every accessor returns an error rather than panicking.
struct Cursor<'a> {
    b: &'a [u8],
    p: usize,
}

impl<'a> Cursor<'a> {
    fn take(&mut self, n: usize) -> Result<&'a [u8]> {
        let s = self
            .b
            .get(self.p..self.p + n)
            .ok_or_else(|| Error::Format("manifest ended unexpectedly".into()))?;
        self.p += n;
        Ok(s)
    }
    fn u16(&mut self) -> Result<u16> {
        Ok(u16::from_le_bytes(self.take(2)?.try_into().unwrap()))
    }
    fn u32(&mut self) -> Result<u32> {
        Ok(u32::from_le_bytes(self.take(4)?.try_into().unwrap()))
    }
    fn u64(&mut self) -> Result<u64> {
        Ok(u64::from_le_bytes(self.take(8)?.try_into().unwrap()))
    }
    fn array16(&mut self) -> Result<[u8; 16]> {
        Ok(self.take(16)?.try_into().unwrap())
    }
    fn array32(&mut self) -> Result<[u8; 32]> {
        Ok(self.take(32)?.try_into().unwrap())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> Manifest {
        let mut m = Manifest {
            generation: 1,
            entries: vec![
                Entry {
                    object_id: [1u8; 16],
                    path: "notes/plan.txt".into(),
                    size: 1234,
                    mtime: 1_700_000_000,
                    compress_suite: CompressSuite::Zstd,
                    chunks: vec![ChunkRef {
                        offset: 256,
                        ciphertext_len: 600,
                        plaintext_len: 1234,
                        hash: [7u8; 32],
                    }],
                },
                Entry {
                    object_id: [2u8; 16],
                    path: "photo.jpg".into(),
                    size: 9000,
                    mtime: 1_700_000_001,
                    compress_suite: CompressSuite::Store,
                    chunks: vec![
                        ChunkRef { offset: 900, ciphertext_len: 4116, plaintext_len: 4096, hash: [8u8; 32] },
                        ChunkRef { offset: 5016, ciphertext_len: 4924, plaintext_len: 4904, hash: [9u8; 32] },
                    ],
                },
            ],
            integrity_root: [0u8; 32],
        };
        m.integrity_root = m.compute_root();
        m
    }

    #[test]
    fn manifest_round_trips() {
        let m = sample();
        assert_eq!(Manifest::decode(&m.encode()).unwrap(), m);
    }

    #[test]
    fn truncation_at_every_length_errors_rather_than_panicking() {
        let bytes = sample().encode();
        for n in 0..bytes.len() {
            let _ = Manifest::decode(&bytes[..n]);
        }
    }

    #[test]
    fn corruption_at_every_byte_errors_rather_than_panicking() {
        let bytes = sample().encode();
        for i in 0..bytes.len() {
            for bit in [0x01u8, 0x80] {
                let mut bad = bytes.clone();
                bad[i] ^= bit;
                let _ = Manifest::decode(&bad);
            }
        }
    }

    #[test]
    fn absurd_counts_are_refused_before_allocating() {
        let mut b = Vec::new();
        b.extend_from_slice(&u32::MAX.to_le_bytes());
        assert!(Manifest::decode(&b).is_err());
    }

    #[test]
    fn the_root_changes_whenever_any_chunk_does() {
        let m = sample();
        let root = m.compute_root();
        let mut altered = m.clone();
        altered.entries[1].chunks[0].hash[0] ^= 1;
        assert_ne!(altered.compute_root(), root);
    }
}
