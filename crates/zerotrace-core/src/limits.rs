//! Hard limits applied to anything read from a vault.
//!
//! Every value here guards a path where an attacker controls a length or count
//! in the container. Without these, a hostile vault can allocate arbitrary
//! memory or drive unbounded decompression before any authentication happens.

/// Largest plaintext chunk. Bounds the working set per chunk.
pub const MAX_CHUNK_PLAINTEXT: usize = 8 * 1024 * 1024;

/// Largest ciphertext chunk: plaintext plus AEAD tag and framing slack.
pub const MAX_CHUNK_CIPHERTEXT: usize = MAX_CHUNK_PLAINTEXT + 4096;

/// Largest encrypted manifest.
pub const MAX_MANIFEST_BYTES: u64 = 64 * 1024 * 1024;

/// Largest number of entries in one vault.
pub const MAX_ENTRIES: usize = 1_000_000;

/// Largest number of chunks in one entry.
pub const MAX_CHUNKS_PER_ENTRY: usize = 1_000_000;

/// Longest stored path, in bytes of UTF-8.
pub const MAX_PATH_BYTES: usize = 4096;

/// Deepest directory nesting accepted on import or export.
pub const MAX_PATH_DEPTH: usize = 64;

/// Note on decompression bombs.
///
/// There is deliberately no compression-ratio limit here. A ratio heuristic
/// cannot distinguish a bomb from genuinely repetitive data: zstd compresses a
/// megabyte of a repeating phrase by well over 1000x, which is ordinary and
/// must not be refused.
///
/// What actually bounds expansion is [`MAX_CHUNK_PLAINTEXT`]. Every chunk
/// declares its plaintext length, that length is checked against this absolute
/// cap before any decompression is attempted, and the decompressor is given
/// that length as a hard output limit. A hostile chunk can therefore produce
/// at most one chunk's worth of memory regardless of its ratio.
pub const _BOMB_DEFENCE_IS_ABSOLUTE_NOT_RATIO: () = ();
