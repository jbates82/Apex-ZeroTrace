# Security model

## Reporting

Security issues should be reported privately before any public disclosure.
This project has not had an independent cryptographic review. It must not carry
a 1.0 security claim until it has.

## What the design rests on

Apex ZeroTrace uses no novel cryptography. Every primitive is an established,
audited construction used through a maintained Rust implementation:

| Purpose | Construction | Crate |
| --- | --- | --- |
| Content encryption | XChaCha20-Poly1305 | `chacha20poly1305` |
| Compliance mode | AES-256-GCM | `aes-gcm` |
| Password derivation | Argon2id | `argon2` |
| Subkey derivation | HKDF-SHA256 | `hkdf` |
| Hashing, Merkle tree | SHA-256 | `sha2` |
| Randomness | OS CSPRNG | `rand` |

The security-relevant code in this project is not the algorithms; it is the
decisions about how they are composed. Those are: what the header authenticates,
how nonces are formed, which key derives which subkey, and where limits are
enforced on untrusted input.

## Enforced invariants

Each maps to a test.

- **INV-1** Plaintext is never written to the container.
  `filenames_and_contents_never_appear_in_the_container`
- **INV-2** Keys are never derived from filenames or predictable values.
  Object ids are 128 random bits; `subkeys_are_separated_by_label_and_object_id`
- **INV-3** The password is never used as an encryption key. It derives a KEK
  that wraps the master key and nothing else.
- **INV-4** No AEAD nonce is reused under a key.
  `chunk_nonces_never_repeat_within_a_file`, and structurally: per-file keys
  plus per-chunk counters.
- **INV-5** A corrupted authenticated record is never silently accepted.
  `tampering_is_always_refused` flips every bit of a ciphertext;
  `corrupting_a_chunk_is_detected_rather_than_returned`
- **INV-6** `DESTROYED` is terminal. `destroyed_is_terminal`
- **INV-7** A committed destruction authorization cannot be rolled back.
  `authorized_destruction_cannot_be_rolled_back`
- **INV-12** Success is never reported for an unverified operation. Every
  assurance surface uses the `Assurance` enum, which has no boolean form.

INV-8 through INV-11 concern the GUI, watchdog and destruction, none of which
exist yet. They are stated in `DESTRUCTION_MODEL.md` and are not claimed as
enforced.

## Multi-factor composition (v0.2)

Factor secrets are concatenated as HKDF input material and expanded into the
key that wraps the master key. Every required factor is therefore needed: a
missing or wrong one produces a different KEK and the master key simply fails
to unwrap. There is no code path that "skips" a factor.

The set of required factors lives inside the header's authenticated region, so
an attacker cannot strip the FIDO2 requirement and hand back a vault that opens
with the password alone. A test flips every bit of that region and confirms all
56 bytes are covered.

`the_hardware_factor_is_genuinely_required` checks the properties that matter:
omitting the device is an error rather than a downgrade, a different device
yields a different key, and the password still matters when a device is present.

### Why FIDO2 is refused rather than approximated

The composition layer is implemented and tested. The USB HID transport is not,
because it cannot be verified without hardware, and an untested transport
inside a security boundary is worse than an absent one.

`Fido2Authenticator` therefore returns `NotImplemented`, and creating a vault
that requires FIDO2 is refused outright: creating one would produce a vault
that could never be opened by this build. `SoftwareAuthenticator` exists only
for tests, is compiled out by default behind a feature flag, and reports its
own assurance as `NotSupported` so it can never be mistaken for a real factor.

## Audit log (v0.2)

Records are hash-chained: each commits to its predecessor, so editing,
deleting or reordering any record breaks every hash after it.

Two limits are stated plainly rather than glossed over. An attacker with write
access can recompute the entire chain from the point of change, so this
provides tamper *evidence*, not tamper *proofing*. And truncating the tail is
undetectable, because a prefix of a valid chain is itself a valid chain;
detecting that needs an external anchor, which is what the Phase 3 state
journal is for. There is a test asserting this negative result so nobody later
mistakes it for a bug.

The log records no passwords, key material, plaintext or file contents. Tabs
and newlines in detail text are neutralised so a crafted value cannot forge
extra fields.

## The header authentication decision

The most consequential design choice in v0.1. See `VAULT_FORMAT.md`. Without
it, an attacker who can return a modified vault can silently downgrade its KDF
parameters, and the owner sees a normal successful unlock.

## Enterprise control (v0.7)

An organization holds an Ed25519 signing key; endpoints hold only the public
half, so a compromised endpoint cannot forge instructions to others. Every
command is signed over all of its fields, carries a unique nonce checked
against a replay guard, and expires.

Two refusals matter more than the signature check. A command that would extend
a deadline is refused however well signed, so possession of the org key cannot
be used to quietly disarm a fleet. And there is no command that reads vault
contents, so a compromised server cannot obtain plaintext by asking for it.

## Does escrow survive a deadman event?

No. A recovery quorum can reconstruct a master key while a vault is locked,
which is what saves an organization from a forgotten password. Once destruction
is authorized, `RecoveryGate` refuses, and the wrapped key in the container has
been overwritten, so a reconstructed key has nothing left to unwrap.

The limit is the familiar one: a quorum plus a copy of the container taken
before erasure can still open that copy. Custodian shares stay sensitive for as
long as any backup exists.

## Known limitations

**Memory.** Secrets are zeroed on drop, cannot be printed or serialized by
accident, and their pages are locked out of swap where the OS permits it.

Locking addresses swap and nothing else. Hibernation writes all of RAM to disk
regardless. Core dumps are unaffected unless separately disabled. A hypervisor
snapshot captures everything. Locking is therefore reported as BEST EFFORT and
never as VERIFIED.

`RLIMIT_MEMLOCK` is often small, so locking fails routinely. A failure is
recorded and reported as FAILED rather than raised as an error: refusing to
open a vault because the OS declined to lock 32 bytes would trade a real
capability for a marginal one. Once a refusal has occurred it remains the
reported answer, because a later success does not un-reach a secret that
already went to swap.

**A live compromised machine.** If malware is running with your privileges
while the vault is unlocked, it can read plaintext, because plaintext is
legitimately accessible then. No vault design fixes this.

**Size leakage.** Compression precedes encryption, so ciphertext lengths
correlate with content. Padding is designed for and not implemented.

**No forensic testing.** The claims in this document concern cryptography and
container structure. Nothing here has been tested against NTFS, APFS, ext4,
SSD wear levelling, RAID or snapshots, because v0.1 performs no deletion at all.


## What a hash chain does not do

The audit log and the state journal are **tamper evident**, not authenticated.

Each entry seals the one before it, so editing, deleting or reordering any
entry breaks every entry after it. The state journal separately records how
long the audit log should be, which catches entries removed from its end, since
a shortened chain is otherwise still a valid chain.

What this detects is partial or careless tampering: a line changed, a record
dropped, a history quietly shortened.

What it does not detect is somebody who holds the whole file and recomputes it.
A chain is a sequence of hashes over public data, so an adversary with write
access to every record can rewrite them all and produce a chain that verifies
perfectly. Nothing here prevents that, and nothing here claims to.

Making these logs unforgeable rather than merely tamper evident needs a key the
adversary does not have: a MAC under a key held elsewhere, or a signature, or
an anchor published somewhere they do not control. None is implemented. The
capability table reports the chains as tamper evident for that reason, and
that wording is exact rather than modest.
