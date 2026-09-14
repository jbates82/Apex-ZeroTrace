//! Randomized mutation testing of every parser that reads untrusted bytes.
//!
//! # What this is, and what it is not
//!
//! This is not coverage-guided fuzzing. `cargo-fuzz` needs a nightly compiler,
//! which the development environment does not have, so a scaffold for it lives
//! in `fuzz/` for anyone who does. What runs here is a deterministic mutation
//! fuzzer: a corpus of valid structures, a set of mutators, and a fixed seed.
//!
//! It is weaker than libFuzzer because it explores blindly rather than
//! following coverage. It is stronger than the bit-flip tests it joins,
//! because those alter one byte of one valid input, while this splices,
//! truncates, extends, and drives length fields to their extremes.
//!
//! The property under test is the same everywhere: a parser handed arbitrary
//! bytes must return a value or an error, and must never panic, hang, or try
//! to allocate a quantity of memory it read out of the input. A panic in a
//! parser is a denial of service at best, and every archive tool that has ever
//! had a memory-corruption advisory got there through one of these functions.
//!
//! Failures are reproducible: the seed is fixed and printed.

use zerotrace_compress::CompressSuite;
use zerotrace_format::manifest::{ChunkRef, Entry, Manifest};
use zerotrace_format::Header;

/// Deterministic generator, so a failure can be reproduced exactly.
struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        // xorshift64*, adequate for choosing mutations and not used for
        // anything that needs to be unpredictable.
        let mut x = self.0;
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        self.0 = x;
        x.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }
    fn below(&mut self, n: usize) -> usize {
        if n == 0 {
            0
        } else {
            (self.next() % n as u64) as usize
        }
    }
    fn byte(&mut self) -> u8 {
        (self.next() & 0xFF) as u8
    }
}

/// Mutates `input` in one of several ways.
///
/// The interesting mutations are the structural ones. Flipping a bit tests
/// that a checksum is checked; truncating and extending test that a length
/// read from the data is bounded before it is trusted.
fn mutate(rng: &mut Rng, input: &[u8]) -> Vec<u8> {
    let mut out = input.to_vec();
    if out.is_empty() {
        return vec![rng.byte(); rng.below(64)];
    }
    match rng.below(9) {
        0 => {
            let i = rng.below(out.len());
            out[i] ^= 1 << rng.below(8);
        }
        1 => {
            let i = rng.below(out.len());
            out[i] = rng.byte();
        }
        // Truncation, which is what finds an unchecked read past the end.
        2 => out.truncate(rng.below(out.len())),
        3 => {
            let n = rng.below(64);
            for _ in 0..n {
                out.push(rng.byte());
            }
        }
        // Drive a field to its maximum. Length fields read from input are the
        // classic way a parser is talked into a huge allocation.
        4 => {
            let i = rng.below(out.len());
            for k in 0..4.min(out.len() - i) {
                out[i + k] = 0xFF;
            }
        }
        5 => {
            let i = rng.below(out.len());
            for k in 0..4.min(out.len() - i) {
                out[i + k] = 0x00;
            }
        }
        6 => {
            // Splice a run from elsewhere in the same buffer.
            let len = out.len();
            let from = rng.below(len);
            let to = rng.below(len);
            let n = rng.below(len - from.max(to).min(len - 1)).min(32);
            for k in 0..n {
                if to + k < len && from + k < len {
                    out[to + k] = out[from + k];
                }
            }
        }
        7 => {
            let i = rng.below(out.len());
            out.insert(i, rng.byte());
        }
        _ => {
            let i = rng.below(out.len());
            out.remove(i);
        }
    }
    out
}

fn valid_manifest() -> Vec<u8> {
    let mut m = Manifest {
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
                path: "a/b/c/deep.bin".into(),
                size: 9000,
                mtime: 1,
                compress_suite: CompressSuite::Store,
                chunks: vec![
                    ChunkRef { offset: 900, ciphertext_len: 4116, plaintext_len: 4096, hash: [8u8; 32] },
                    ChunkRef { offset: 5016, ciphertext_len: 4924, plaintext_len: 4904, hash: [9u8; 32] },
                ],
            },
        ],
        integrity_root: [0u8; 32],
        generation: 1,
    };
    m.integrity_root = m.compute_root();
    m.encode()
}

fn valid_header() -> Vec<u8> {
    // Built by creating a real vault, so the corpus is a genuine header rather
    // than one assembled by the test and possibly unrepresentative.
    let dir = std::env::temp_dir().join(format!("ztfuzzhdr_{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("v.azv");
    zerotrace_vault::Vault::create(
        &path,
        b"correct-horse-battery-staple",
        &zerotrace_vault::VaultOptions::default(),
    )
    .unwrap()
    .close();
    let bytes = std::fs::read(&path).unwrap();
    let _ = std::fs::remove_dir_all(&dir);
    bytes[..zerotrace_format::HEADER_LEN].to_vec()
}

/// Runs one target over many mutations of its corpus.
fn hammer(name: &str, seed: u64, corpus: Vec<Vec<u8>>, rounds: usize, parse: impl Fn(&[u8])) {
    let mut rng = Rng(seed);
    for round in 0..rounds {
        let base = &corpus[rng.below(corpus.len())];
        let mut case = mutate(&mut rng, base);
        // Occasionally stack mutations, which reaches shapes a single edit
        // cannot.
        for _ in 0..rng.below(3) {
            case = mutate(&mut rng, &case);
        }
        // A panic here fails the test and names the round, so the exact case
        // can be reproduced from the seed.
        let hint = format!("{name} round {round} seed {seed}");
        let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| parse(&case)))
            .unwrap_or_else(|_| panic!("{hint}: parser panicked"));
    }
}

#[test]
fn the_header_parser_survives_arbitrary_bytes() {
    let corpus = vec![
        valid_header(),
        vec![0u8; zerotrace_format::HEADER_LEN],
        b"AZV1\0\0\0\0".to_vec(),
        Vec::new(),
    ];
    hammer("header", 0x5EED_0001, corpus, 20_000, |b| {
        let _ = Header::from_bytes(b);
    });
}

#[test]
fn the_manifest_parser_survives_arbitrary_bytes() {
    let corpus = vec![
        valid_manifest(),
        vec![0xFFu8; 64],
        vec![0u8; 4],
        Vec::new(),
    ];
    hammer("manifest", 0x5EED_0002, corpus, 20_000, |b| {
        let _ = Manifest::decode(b);
    });
}

#[test]
fn the_split_bundle_parser_survives_arbitrary_bytes() {
    use zerotrace_crypto::{random_key, CryptoSuite};
    use zerotrace_split::{seal, ComponentKind, SplitBundle};

    let bundle = seal(
        &random_key(),
        zerotrace_core::VaultId::from_bytes([3u8; 16]),
        CryptoSuite::XChaCha20Poly1305,
        &[
            (ComponentKind::User, random_key()),
            (ComponentKind::Remote, random_key()),
            (ComponentKind::Custodian, random_key()),
        ],
    )
    .unwrap();

    let corpus = vec![bundle.encode(), b"AZSP".to_vec(), vec![0u8; 32], Vec::new()];
    hammer("split bundle", 0x5EED_0003, corpus, 20_000, |b| {
        let _ = SplitBundle::decode(b);
    });
}

#[test]
fn the_token_parser_survives_arbitrary_bytes() {
    use zerotrace_split::RecoveryToken;
    let corpus = vec![
        RecoveryToken::generate().encode().into_bytes(),
        b"apex-zerotrace-recovery-token:v1:".to_vec(),
        b"not a token".to_vec(),
        Vec::new(),
    ];
    hammer("recovery token", 0x5EED_0004, corpus, 20_000, |b| {
        if let Ok(text) = std::str::from_utf8(b) {
            let _ = RecoveryToken::decode(text);
        }
    });
}

#[test]
fn the_compressor_survives_arbitrary_bytes() {
    // Given a declared plaintext length it does not control, the decompressor
    // must refuse rather than expand without limit.
    let good = zstd_encoded();
    let corpus = vec![good, vec![0x28, 0xB5, 0x2F, 0xFD], vec![0u8; 16], Vec::new()];
    hammer("zstd", 0x5EED_0005, corpus, 10_000, |b| {
        let _ = zerotrace_compress::decompress(CompressSuite::Zstd, b, 4096);
        let _ = zerotrace_compress::decompress(CompressSuite::Store, b, b.len());
    });
}

fn zstd_encoded() -> Vec<u8> {
    let (_, c) =
        zerotrace_compress::compress(&b"repeating text ".repeat(200), 3, CompressSuite::Zstd)
            .unwrap();
    c
}

#[test]
fn the_custodian_record_parser_survives_arbitrary_bytes() {
    use zerotrace_remote::custodian::{Custodian, DirectoryCustodian, HeldShare};

    let dir = std::env::temp_dir().join(format!("ztfuzzcust_{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let id = zerotrace_core::VaultId::from_bytes([4u8; 16]);
    let c = DirectoryCustodian::new(&dir);
    c.enroll(&HeldShare::new(id, vec![7u8; 32], [1u8; 32], 3600, 1000)).unwrap();

    let record = dir.join(format!("{id}.custody"));
    let valid = std::fs::read(&record).unwrap();
    let corpus = vec![valid, b"share=zz".to_vec(), vec![0u8; 8], Vec::new()];

    let mut rng = Rng(0x5EED_0006);
    for round in 0..5_000 {
        let base = &corpus[rng.below(corpus.len())];
        let case = mutate(&mut rng, base);
        std::fs::write(&record, &case).unwrap();
        // Reading a record is what a custodian does with a file it did not
        // write, so it must tolerate anything.
        let hint = format!("custodian round {round}");
        let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _ = c.status(id, 2000);
        }))
        .unwrap_or_else(|_| panic!("{hint}: parser panicked"));
    }
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn a_parser_never_allocates_on_a_length_it_read() {
    // The specific failure this whole file exists to catch: a count taken from
    // the input and used to reserve memory before it is checked. Every one of
    // these declares an implausible size in a length field.
    let mut absurd = Vec::new();
    absurd.extend_from_slice(&u32::MAX.to_le_bytes()); // entry count
    assert!(Manifest::decode(&absurd).is_err());

    let mut bundle = b"AZSP".to_vec();
    bundle.push(1);
    bundle.extend_from_slice(&[9u8; 16]);
    bundle.extend_from_slice(&1u16.to_le_bytes());
    bundle.push(2);
    bundle.push(255); // share count
    assert!(zerotrace_split::SplitBundle::decode(&bundle).is_err());

    // And a chunk claiming more plaintext than the absolute cap.
    assert!(zerotrace_compress::decompress(
        CompressSuite::Zstd,
        &zstd_encoded(),
        usize::MAX / 2
    )
    .is_err());
}
