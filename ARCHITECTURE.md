# Architecture

## Crates

```
zerotrace-core            errors, limits, deadman state machine. Depends on nothing of ours.
zerotrace-secure-memory   SecretBytes, SecureBuffer. Zeroing, redacted Debug, constant-time eq.
zerotrace-kdf             Argon2id, parameter validation and floors.
zerotrace-crypto          AEAD suites, HKDF subkeys, nonce construction, Merkle root.
zerotrace-compress        Zstandard, content classification, bounded decompression.
zerotrace-format          AZV1 header and manifest encoding and parsing.
zerotrace-auth            Factor kinds, factor sets, multi-factor KEK composition.
zerotrace-presence        Signal trust levels, decaying confidence scoring.
zerotrace-policy          Deadman configuration and state evaluation.
zerotrace-journal         Hash-chained persistent state journal.
zerotrace-sanitize        Platform sanitizer trait and portable implementation.
zerotrace-destroy         Authorization, cryptographic erasure, reporting.
zerotrace-ipc             The command surface the GUI talks to.
zerotrace-platform        Filesystem knowledge and service definitions.
zerotrace-audit           Hash-chained tamper-evident log.
zerotrace-vault           Lifecycle: create, open, import, export, verify, close.
zerotrace-cli             The `zt` binary.
```

## Dependency direction

```
        zerotrace-cli
              |
        zerotrace-vault
         /    |     \
   format  crypto  compress
      |       |
     kdf   secure-memory
      \      /
    zerotrace-core
```

Strictly downward. `zerotrace-crypto` depends on no GUI, no networking and no
I/O. The security-relevant surface is deliberately small enough to audit: the
crypto, kdf, format and secure-memory crates together are around 1,100 lines
including their tests.

## Crates the spec lists that v0.1 does not contain

`watchdog`. Its role is filled by the OS supervisor, which is what
`zt service unit` generates a definition for. They are absent rather than stubbed. A
stub that returns success is worse than a missing crate, because it can be
mistaken for a working control.

## Design decisions worth stating

**The header authenticates its own KDF parameters.** See `VAULT_FORMAT.md`.

**Nonces are counters, not random.** Per-file keys make counter uniqueness
structural. A random 192-bit nonce would also be safe, but "provably cannot
collide" beats "collides with negligible probability" when the cost is the same.

**The manifest is hand-encoded.** A derive macro would be less code, but every
length read from an untrusted file would then be handled by machinery that is
harder to review. The parser is 60 lines and every read is bounds-checked.

**There is no ratio-based bomb detector.** An early version had one and it
rejected legitimate data: zstd exceeds 1000:1 on repetitive input routinely.
Expansion is bounded absolutely instead, by capping declared plaintext length
and passing that cap to the decompressor.

**The AAD comes from the bytes on disk, not from the parsed struct.** An early
version computed it by re-serializing the header. That silently excluded every
derived or reserved field from authentication, because re-serializing rewrote a
tampered byte to its expected value before the AAD was computed. Caught by the
test that flips every bit of the authenticated region.

**Deadlines are wall-clock, cross-checked monotonically.** `Instant` does not
advance during suspend on any supported platform, so a monotonic deadline could
be postponed indefinitely by closing a laptop lid. Elapsed time is therefore
the larger of the wall and monotonic deltas: suspend counts, and a clock
rollback cannot buy time.

**Ambient presence has a ceiling, not just a low weight.** Weighting network
reachability at 10 would still let enough weak signals accumulate past a
threshold. A hard cap below any valid `required_confidence` makes INV-10
structural, and `DeadmanPolicy::validate` refuses to configure a policy that
ambient signals alone could satisfy.

**The key is destroyed before the container is removed.** Forty-eight bytes are
what stand between the ciphertext and meaning. Removing the file first and
being interrupted would leave the key intact in a snapshot; erasing the key
first means an interruption still leaves the data unreadable.

**Overall assurance is governed by cryptographic erasure alone.** Secondary
measures cannot raise it, because no amount of overwriting compensates for a
key that still exists, and cannot lower it, because a destroyed key makes the
ciphertext meaningless whether or not free space was scrubbed.

**A broken journal refuses to authorize destruction.** Treating corruption as a
trigger would hand an attacker a denial of service that destroys the data for
them.

**The GUI is a client, not a participant.** No cryptography, policy evaluation
or destruction logic lives in the window. Every action forwards to
`zerotrace_ipc::Session` and renders what comes back, so the security boundary
never runs through the front end. The IPC crate is in the workspace and tested;
the window is a thin client over it and is checked by hand.

**A session holds no keys between requests.** Each operation unlocks, acts and
drops the key, so key lifetime is tied to one operation rather than to how long
a window happens to be open.

**Sanitization adapts to the filesystem rather than reporting uniformly.**
Overwriting in place is refused on copy-on-write and layered filesystems,
because there the write does not reach the original blocks. A uniform "best
effort" would have been least accurate exactly where the difference matters.

**ZeroTrace does not install its own service.** Writing to a service directory
needs privileges a vault application should not hold, and a silent privileged
install is not behavior a security tool should have. Definitions are printed
for review.

**Assurance is an enum, not a boolean.** INV-12 requires never claiming
unverified success. A type with `BestEffort`, `NotSupported` and
`NotImplemented` alongside `Verified` makes the honest answer expressible.
