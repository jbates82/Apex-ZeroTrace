# AZV1 container format

## Layout

```
[0 .. 256)                  header
[256 .. manifest_offset)    authenticated chunks, back to back
[manifest_offset .. EOF)    manifest nonce, plaintext length, encrypted manifest
```

## Header

| Offset | Size | Field |
| --- | --- | --- |
| 0 | 8 | magic `AZV1\0\0\0\0` |
| 8 | 2 | format version |
| 10 | 2 | crypto suite |
| 12 | 2 | KDF suite |
| 14 | 2 | compression suite |
| 16 | 16 | vault UUID |
| 32 | 4 | Argon2id memory cost, KiB |
| 36 | 4 | Argon2id time cost |
| 40 | 4 | Argon2id parallelism |
| 44 | 4 | feature flags |
| 48 | 32 | KDF salt |
| **80** | | **end of the authenticated prefix** |
| 80 | 24 | master key nonce |
| 104 | 48 | wrapped master key |
| 152 | 8 | manifest offset |
| 160 | 8 | manifest length |
| 168 | 32 | integrity root |
| 200 | 56 | reserved, zero |

### Why bytes 0..80 are authenticated

The header is read before anything has been verified, and it carries the
Argon2id parameters. If it were unauthenticated an attacker could return a
vault with the memory cost lowered to a few kilobytes. The owner would type the
correct password, derive a weak KEK, unlock successfully, and never learn that
the vault's resistance to offline guessing had been removed.

Bytes 0..80 are therefore passed as additional authenticated data when the
master key is wrapped. Any change to the magic, version, suites, vault id, KDF
parameters or salt makes the unwrap fail.

The fields after byte 80 are mutable by design: the manifest moves whenever the
vault is written. They are protected separately. The manifest carries its own
authentication tag and contains the authoritative integrity root, which is
compared against the header's copy when the vault is opened.

A test flips every single bit of the authenticated prefix and asserts that the
vault refuses to open in all 640 cases.

## Key hierarchy

```
password --Argon2id(salt, params)--> KEK
KEK --AEAD unwrap, AAD = header[0..80]--> master key
master --HKDF-SHA256, "…metadata-key"--> metadata key
master --HKDF-SHA256, "…file-key", salt = object id--> per-file key
master --HKDF-SHA256, "…integrity-key"--> integrity key (reserved)
```

The password never encrypts data directly, so changing it rewraps 48 bytes
rather than re-encrypting the vault.

## Chunks

Plaintext is split at 1 MiB. Each chunk is compressed, then encrypted under its
file's key.

Nonces are counters, not random values. Every chunk is encrypted under a key
unique to its file, derived from that file's random 128-bit object id, so a
counter within the file cannot collide. This makes "no nonce is reused under a
key" a structural property rather than a probabilistic one.

Additional authenticated data per chunk is `object_id || chunk_index ||
plaintext_len || compression_suite`. Binding the index prevents reordering;
binding the object id prevents a chunk being moved between files; binding the
suite prevents a compressed chunk being passed off as stored.

## Manifest

Encoded with a hand-written binary format rather than a serialization
framework, so that every length read from a file is bounds-checked in code that
fits on one screen.

Contains, per entry: a random 128-bit object id, the path, size, mtime,
compression suite, and the chunk list with offsets, lengths and SHA-256 hashes.
Then the Merkle root over every chunk hash.

The whole structure is encrypted with the metadata key under a fresh random
nonce, with `vault_uuid || plaintext_length` as AAD.

## What the container still leaks

- Its total size, and therefore roughly how much is stored
- The number and size of chunks, and therefore approximate per-file sizes
- That it is an Apex ZeroTrace vault, from the magic number

Compression happens before encryption, so ciphertext length correlates with
content compressibility. Chunk padding is designed for (`flags::PADDED_CHUNKS`)
but is not implemented in v0.1.
