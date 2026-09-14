# Threat model

## In scope for v0.1

| Threat | Handling |
| --- | --- |
| Stolen vault file | Content is AEAD-encrypted under a key derived by Argon2id. |
| Stolen computer, vault locked | Same. No key material is stored unwrapped. |
| Offline password guessing | Argon2id with an enforced floor of 19 MiB / t=2. |
| Modified vault | Header prefix is authenticated; every chunk and the manifest carry AEAD tags. |
| KDF downgrade | Parameters are inside the authenticated prefix and range-checked before use. |
| Corrupted vault | Detected. Refuses to open, or reports the failing chunk count. |
| Chunk reordering | Chunk index is bound into the AAD. |
| Chunk substitution between files | Object id is bound into the AAD. |
| Truncation | The manifest records chunk lengths; short reads are errors. |
| Decompression bomb | Plaintext length is capped absolutely and passed to the decompressor as a hard limit. |
| Hostile manifest | Parsed with bounds-checked reads; counts and lengths are limited before allocation. |
| Path traversal on export | Absolute paths, drive prefixes and `..` are refused. |
| Metadata disclosure | Filenames, paths, sizes and timestamps live only in the encrypted manifest. |

## Explicitly out of scope for v0.1

Rollback attacks, clock manipulation, malicious local processes, GUI or service
or watchdog termination, power failure during destruction, corrupted
destruction state, and audit tampering are all properties of subsystems that do
not exist yet. They are addressed in `DESTRUCTION_MODEL.md` as design, and are
not claimed as implemented.

## Out of scope permanently

**Malware on a live machine while the vault is unlocked.** Plaintext is
accessible to the user at that moment, and therefore to anything running as the
user.

**Independent copies.** Destroying a vault on one device does nothing to copies
on a NAS, in cloud storage, on a backup drive, or in a cloned virtual disk.
Because the wrapped master key lives inside the container, a complete copy
taken before erasure carries its own key and still opens with the password.
This is verified behavior, not an oversight: a test confirms it.

This is the single most important limitation of the product concept, and it is
a property of copying rather than a defect a later version removes. Making all
replicas die with one key requires the key to live somewhere other than beside
the ciphertext, which is a different architecture from AZV.

What cryptographic erasure does win is the case overwriting cannot: bytes of
this container that survive on wear-levelled storage after unlinking are
meaningless, because the key is gone from them.

**A malicious administrator with access before destruction.** Someone with
privileges on the machine while the vault is unlocked can read it.


## What the file names reveal

A vault is accompanied by files named after it:

```
vault.azv
vault.azv.audit
vault.azv.journal
vault.azv.policy
vault.azv.split
vault.azv.custodian
vault.azv.watch
```

Anybody who lists that directory learns that ZeroTrace is in use, and which
features are turned on. The presence of `.split` says the key is divided.
`.custodian` says a component is held somewhere else, and the file itself names
where. `.watch` says a deadline is being watched.

This is deliberate rather than overlooked, and it is worth being clear about
which parts matter.

It does not reveal contents. Every one of those files is either encrypted, a
hash chain over events, or a path.

It does not reveal whether a duress password exists. That lives inside the
container, in a block present in every vault and filled with random bytes when
unused, precisely so that the question cannot be answered from outside.

It does reveal the shape of your defenses, and to an adversary who has the
drive that is a map of what to look for. Somebody who sees `.custodian` knows
to ask about a machine elsewhere.

Hiding it would mean putting everything inside the container, which trades this
away for a worse problem: the audit log and journal must be appendable while
the vault is closed, and a service that had to open a vault to record that it
had been opened would need the key resident to do it.

If the existence of a vault is itself the thing you need to hide, this is not
the tool for that. Plausible deniability of that kind is a different design,
and one ZeroTrace does not attempt.
