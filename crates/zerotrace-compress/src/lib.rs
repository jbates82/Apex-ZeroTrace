//! Compression, applied before encryption.
//!
//! Order matters: compressing after encryption achieves nothing, and
//! compressing before it means compressed length leaks something about
//! content. That trade is accepted here and documented in VAULT_FORMAT.md;
//! optional padding is the mitigation.
//!
//! zstd is a C library. It is used rather than something hand-written because
//! it is far more heavily reviewed, but it does mean untrusted bytes reach C
//! code, so every decompression is bounded by a caller-supplied limit.

#![forbid(unsafe_code)]

use serde::{Deserialize, Serialize};
use zerotrace_core::limits;
use zerotrace_core::{Error, Result};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u16)]
pub enum CompressSuite {
    /// Store verbatim. Chosen automatically for incompressible content.
    Store = 0,
    Zstd = 1,
}

impl CompressSuite {
    pub fn from_u16(v: u16) -> Result<Self> {
        match v {
            0 => Ok(CompressSuite::Store),
            1 => Ok(CompressSuite::Zstd),
            other => Err(Error::Unsupported { what: "compression suite", value: other.to_string() }),
        }
    }
    pub fn label(&self) -> &'static str {
        match self {
            CompressSuite::Store => "Store",
            CompressSuite::Zstd => "Zstandard",
        }
    }
}

/// Recognizes content that is already compressed.
///
/// Spending CPU on a JPEG buys nothing, and the result is usually larger.
pub fn looks_already_compressed(data: &[u8]) -> bool {
    const SIGNATURES: &[&[u8]] = &[
        b"\xFF\xD8\xFF",             // JPEG
        b"\x89PNG\r\n\x1a\n",        // PNG
        b"GIF87a",
        b"GIF89a",
        b"PK\x03\x04",               // zip, and every zip-based office format
        b"7z\xBC\xAF\x27\x1C",
        b"\x1F\x8B",                 // gzip
        b"\xFD7zXZ\x00",             // xz
        b"BZh",
        b"Rar!\x1A\x07",
        b"\x00\x00\x00\x18ftyp",     // MP4
        b"\x00\x00\x00\x20ftyp",
        b"OggS",
        b"fLaC",
        b"ID3",
        b"\x28\xB5\x2F\xFD",         // zstd
    ];
    if SIGNATURES.iter().any(|s| data.starts_with(s)) {
        return true;
    }
    // Fall back to an entropy estimate on a sample for unrecognised formats.
    if data.len() >= 4096 {
        let sample = &data[..4096];
        let mut hist = [0u32; 256];
        for &b in sample {
            hist[b as usize] += 1;
        }
        let n = sample.len() as f64;
        let mut entropy = 0.0f64;
        for &c in hist.iter() {
            if c > 0 {
                let p = c as f64 / n;
                entropy -= p * p.log2();
            }
        }
        return entropy > 7.8;
    }
    false
}

/// Compresses, or reports that storing verbatim is better.
///
/// Returns the suite actually used, so the caller records the truth rather
/// than the intent.
pub fn compress(data: &[u8], level: i32, suite: CompressSuite) -> Result<(CompressSuite, Vec<u8>)> {
    if suite == CompressSuite::Store || data.is_empty() || looks_already_compressed(data) {
        return Ok((CompressSuite::Store, data.to_vec()));
    }
    let out = zstd::encode_all(data, level)
        .map_err(|e| Error::Compression(format!("zstd compression failed: {e}")))?;
    if out.len() < data.len() {
        Ok((CompressSuite::Zstd, out))
    } else {
        Ok((CompressSuite::Store, data.to_vec()))
    }
}

/// Decompresses, refusing to produce more than `expected_len`.
///
/// `expected_len` comes from an authenticated manifest, so this is a
/// consistency check rather than the sole defense, but it is what stops a
/// decompression bomb from being expanded before anyone notices.
pub fn decompress(suite: CompressSuite, data: &[u8], expected_len: usize) -> Result<Vec<u8>> {
    if expected_len > limits::MAX_CHUNK_PLAINTEXT {
        return Err(Error::LimitExceeded(format!(
            "chunk declares {expected_len} plaintext bytes, above the \
             {} byte limit",
            limits::MAX_CHUNK_PLAINTEXT
        )));
    }
    match suite {
        CompressSuite::Store => {
            if data.len() != expected_len {
                return Err(Error::Integrity("stored chunk length does not match".into()));
            }
            Ok(data.to_vec())
        }
        CompressSuite::Zstd => {
            // `expected_len` was bounded above, and is passed to zstd as a hard
            // output cap, so a bomb cannot expand past one chunk. No ratio
            // heuristic is applied: real data routinely exceeds any threshold
            // that would be tight enough to matter.
            let out = zstd::bulk::decompress(data, expected_len)
                .map_err(|e| Error::Compression(format!("zstd decompression failed: {e}")))?;
            if out.len() != expected_len {
                return Err(Error::Integrity("decompressed length does not match".into()));
            }
            Ok(out)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip_preserves_bytes() {
        let cases: Vec<Vec<u8>> = vec![
            Vec::new(),
            b"a".to_vec(),
            b"the quick brown fox ".repeat(500),
            (0..5000u32).map(|i| (i % 251) as u8).collect(),
        ];
        for data in cases {
            let (s, c) = compress(&data, 3, CompressSuite::Zstd).unwrap();
            assert_eq!(decompress(s, &c, data.len()).unwrap(), data);
        }
    }

    #[test]
    fn already_compressed_content_is_stored_not_recompressed() {
        let mut jpeg = vec![0xFF, 0xD8, 0xFF];
        jpeg.extend_from_slice(&[0xAB; 1000]);
        let (s, _) = compress(&jpeg, 3, CompressSuite::Zstd).unwrap();
        assert_eq!(s, CompressSuite::Store);
    }

    #[test]
    fn incompressible_data_is_never_expanded() {
        let mut st = 0x1234_5678u32;
        let noise: Vec<u8> = (0..100_000)
            .map(|_| {
                st = st.wrapping_mul(1_103_515_245).wrapping_add(12345);
                (st >> 16) as u8
            })
            .collect();
        let (_, c) = compress(&noise, 3, CompressSuite::Zstd).unwrap();
        assert!(c.len() <= noise.len(), "{} -> {}", noise.len(), c.len());
    }

    #[test]
    fn a_decompression_bomb_cannot_exceed_one_chunk() {
        let bomb = zstd::encode_all(&vec![0u8; 1_000_000][..], 19).unwrap();

        // A claim beyond the absolute cap is refused outright.
        assert!(decompress(CompressSuite::Zstd, &bomb, 8 * 1024 * 1024 * 1024).is_err());
        assert!(decompress(CompressSuite::Zstd, &bomb, limits::MAX_CHUNK_PLAINTEXT + 1).is_err());

        // A claim within the cap is allowed but cannot produce more than it
        // declared, which is the property that matters.
        let out = decompress(CompressSuite::Zstd, &bomb, 1_000_000).unwrap();
        assert_eq!(out.len(), 1_000_000);
    }

    #[test]
    fn highly_compressible_data_is_not_mistaken_for_a_bomb() {
        // Over 1000:1, and entirely legitimate.
        let data = b"repeating payload block ".repeat(50_000);
        let c = zstd::encode_all(&data[..], 3).unwrap();
        assert!(data.len() / c.len() > 1000, "expected a high ratio for this test");
        assert_eq!(decompress(CompressSuite::Zstd, &c, data.len()).unwrap(), data);
    }

    #[test]
    fn corrupt_compressed_data_errors_rather_than_panicking() {
        let good = zstd::encode_all(&b"hello world ".repeat(100)[..], 3).unwrap();
        for i in 0..good.len().min(64) {
            let mut bad = good.clone();
            bad[i] ^= 0xFF;
            let _ = decompress(CompressSuite::Zstd, &bad, 1200);
        }
    }
}
