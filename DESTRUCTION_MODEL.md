# Destruction model

**Implemented as of v0.4.** Cryptographic erasure, two-phase authorization,
resumption after interruption and the destruction report all work and are
tested. Platform sanitization is a framework with a portable best-effort
implementation; per-OS snapshot handling is not built.

## The central idea

Overwriting a file does not reliably destroy it on modern storage. Copy-on-write
filesystems, journals, snapshots, SSD wear levelling and flash translation
layers, RAID mirrors, virtual disk images and backups all mean the bytes you
overwrote may persist somewhere you cannot address.

Destroying the key is different. A 256-bit key that no longer exists cannot be
recovered from a wear-levelled block, and every copy of the ciphertext
everywhere becomes equally meaningless at once.

So: **cryptographic erasure is the security boundary. Filesystem sanitization
is an additional assurance layer and is never presented as a substitute.**

## State machine

Implemented and tested in `zerotrace-core::state`, driven by nothing.

```
NORMAL -> WARNING -> CRITICAL -> ARMED -> DESTRUCTION_AUTHORIZED
       -> KEY_ERASURE -> VAULT_ERASURE -> PLATFORM_SANITIZATION
       -> VERIFICATION -> DESTROYED
```

Before `DESTRUCTION_AUTHORIZED`, backward transitions are legal: a user who
checks in during a warning must return to normal. From `DESTRUCTION_AUTHORIZED`
onward the machine only moves forward, one step at a time, and `DESTROYED` has
no exit at all. Stages cannot be skipped, so no stage's record can be omitted.

## Two-phase authorization

A timer expiring does not erase anything. It commits a persistent
`DESTRUCTION_AUTHORIZATION` record binding the vault UUID, policy version,
expiry event and state sequence number.

The failure posture inverts at that commit:

- **Before**: fail closed. An error protects the vault.
- **After**: fail forward. An error must not leave a half-destroyed vault that
  a restart treats as healthy.

## Order of operations

1. Stop accepting vault operations
2. Lock the vault
3. Destroy plaintext buffers
4. Destroy in-memory keys
5. Destroy the wrapped master key in the header
6. Destroy recovery material where policy requires
7. Remove the container
8. Verify what steps 3-7 actually achieved
9. Secondary platform sanitization
10. Emit a report

Step 5 is the one that matters. After it, the container is 48 bytes short of
being interpretable, and no amount of recovered ciphertext helps.

## Reporting

A destruction report must distinguish what was verified from what was
attempted. `Assurance` already exists for this and has no boolean form, so
"probably fine" is not expressible.

```
Cryptographic Erasure:      VERIFIED
Vault Container Removal:    VERIFIED
Snapshots Detected:         2
Snapshots Removed:          2
Filesystem Sanitization:    BEST EFFORT
Free-Space Sanitization:    NOT GUARANTEED
Overall Assurance:          HIGH
```

## What cryptographic erasure does and does not reach

This is the most important limitation in the product and it is easy to
overstate, so it is stated precisely.

The wrapped master key lives inside the container, in the header. Destroying it
makes *that file* undecryptable with any password, permanently. This is
verified by reading the bytes back after the overwrite, and by a test that
opens a vault, destroys it, and confirms the correct password no longer works.

**A complete copy of the container taken before erasure carries its own copy of
the wrapped key, and remains openable with the password.** Destroying a vault
on this device does not reach a backup on a NAS, a file in cloud storage, a
filesystem snapshot predating the erasure, or a cloned virtual disk. This is
not a defect that a later phase removes; it is what copying means.

What cryptographic erasure genuinely buys over deleting a file:

- Bytes of *this* container that survive on the physical medium after unlinking
  are useless, because the key that gave them meaning is gone from them. This
  is the case that overwriting cannot reliably win on wear-levelled storage.
- Any copy made *after* erasure is equally useless.

The distributed-replica model in the specification, where destroying one
cryptographic root renders every replica unreadable, requires the key material
to live somewhere other than alongside the ciphertext. That is a different
architecture and is not what AZV1 or AZV2 does. The UI must not imply otherwise,
and the destruction report says so in as many words.

## Deliberate non-goals

**Recovery keys must not survive destruction.** A recovery key is useful while
a vault is merely locked. Once destruction is committed it must be gone too,
or the mechanism is theatre (INV-11).

**Destruction must not be easy to trigger by an attacker.** Killing a process
is not evidence of anything. A denial-of-service that destroys a user's data on
demand would be a worse vulnerability than the one it defends against. Tamper
signals are classified, and only the highest class contributes to a destruction
decision.

**Network presence cannot satisfy a strong policy alone** (INV-10). A machine
answering pings tells you nothing about whether its owner is alive and free.

**Independent copies are not affected.** Destroying this vault does not touch a
copy on a NAS or in cloud storage. The UI must say so plainly, before arming.
