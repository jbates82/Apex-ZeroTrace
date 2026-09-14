# Testing

```
cargo test --release
```

287 tests pass as of v0.21.0.

## What is tested

**State machine.** Every state is checked for the terminal property; every
committed state is checked against every earlier state for rollback; stage
skipping is refused; the full forward path is walked.

**Cryptography.** Round trip under both suites. Then, for every byte of a
ciphertext, flipping one bit and asserting the open fails. AAD, nonce and key
are each separately confirmed to be bound. 10,000 chunk nonces are checked for
uniqueness.

**Merkle root.** Altering any leaf, reordering two leaves, or truncating the
list each change the root.

**KDF.** Weak parameters are refused, absurd parameters are refused,
derivation is deterministic and depends on both salt and password.

**Header.** Round trip; downgraded KDF parameters refused at parse time;
unknown versions and suites refused rather than guessed; junk refused. Then the
property that matters: a wrapped key opens against the honest header, fails
against a header whose salt moved by one bit, and still opens after the mutable
fields are rewritten.

**Manifest.** Round trip. Then truncation at every length and bit-flips at
every byte, asserting the parser errors rather than panicking.

**Compression.** Round trip across shapes; already-compressed content is
stored rather than recompressed; incompressible data never expands; a bomb
cannot exceed one chunk; highly compressible data is not mistaken for a bomb.

**Vault, end to end.** Six data shapes including empty, single-byte,
incompressible and multi-chunk. Wrong password refused. Every bit of the
authenticated header prefix flipped, 640 cases, all refused. A corrupted chunk
is reported and refuses to export. Both crypto suites. Filenames and content
absent from the container. Path traversal refused.

**Multi-factor composition.** A password-only vault refuses an unexpected
hardware factor. A two-factor vault opens with both, is refused with the
password alone, refused with the right device and wrong password, and refused
with the right password and a different device. Every bit of the 56-byte
authenticated auth region is flipped and all are refused. Stripping the FIDO2
requirement from the header is refused. Version 1 vaults still open.

**Audit chain.** A clean chain verifies and resumes across reopening. Editing,
deleting and reordering records each break it at the expected sequence number.
Truncation is asserted *not* to be detected, so the documented limitation
cannot silently become a false claim. Field-injection through tabs and newlines
is neutralised.

**Time.** Rollback cannot reduce elapsed time; suspend still counts; elapsed is
never negative and never below the monotonic delta; small divergence is not
flagged as an anomaly.

**Presence.** A fresh check-in scores 100 and decays to 0 over the horizon.
Every weak signal together cannot reach a strong threshold. Repeating a weak
signal does not accumulate. A clock rollback does not restore expired presence.

**Policy.** Dangerously short timeouts, unordered thresholds, a heartbeat
longer than the timeout, and any policy that ambient signals could satisfy are
all refused. Passing the deadline reaches ARMED and no further.

**Journal.** Illegal transitions are never written. Editing breaks the chain. A
forger who recomputes every hash is still caught by the transition rules when
the journal walks backwards out of a committed state. Audit truncation and
divergence are both detected through the anchor.

**End to end.** Absence walks a vault to ARMED and stops without ever reaching
a committed state; a check-in rescues a warned vault; a suspended machine still
arms; a wound-back clock still arms; an abandoned but network-reachable machine
still arms.

**Destruction.** A vault opens, is destroyed, and then refuses the correct
password. Destruction without authorization is refused and leaves the vault
openable. Authorization before ARMED is refused. A tampered journal refuses to
authorize rather than treating corruption as a trigger.

**Fault injection.** Interruption immediately after authorization resumes and
completes. Interruption midway through erasure completes on the next run.
Running destruction twice reports the second attempt honestly rather than
claiming a second erasure. `DESTROYED` remains terminal across a restart, and
every attempt to leave it is refused.

**Reporting.** The report never claims unimplemented work succeeded, contains
no guarantee language, and states the independent-copies limitation.

**IPC boundary.** A vault summary is formatted and checked for the password and
for two distinctive plaintext phrases. Three dangerous policy shapes are refused
and leave the effective policy disabled. A corrupt policy file falls back to
disabled rather than being partially honoured. Five near-miss destruction
confirmations are each refused with the vault left intact, as is a correct
confirmation with the wrong password. Panic lock leaves the vault listable. The
capability table is asserted not to overstate the build, and no note may contain
the word "guarantee".

**Split-key.** The stolen-drive scenario is modeled directly: the bundle is
encoded, decoded as an attacker would hold it, and a correctly guessed password
is shown to be one component short. A wrong password is asserted to be
indistinguishable from an absent component, so component keys cannot be tested
one at a time. Shares cannot be moved between vaults or between component
slots. Every byte of a share is flipped and each is refused. Enrolling below
the threshold, or the same component twice, is refused. Three components
tolerate losing any one, and any single component alone opens nothing. The
assessment is asserted to report the weaknesses, not only the strengths.

**Split enrollment.** Enrollment leaves the chunk region byte-identical, so no
content is re-encrypted. A split vault refuses the password alone and refuses a
single component. Deleting the bundle denies service rather than downgrading.
Clearing the authenticated split flag does not restore the password path. A
bundle from another vault is refused by vault id.

**Autostart.** Destruction is off by default in a generated entry and visible
in words as well as a flag when enabled. The entry names the vault and
interval. Different vaults get different entries. Installing without the
service program present is refused. Install and remove round-trip, removing
twice is not an error, and an unarmed entry reports that it cannot destroy.

**Watch locks.** An unwatched vault reports not running and cannot be asked to
stop. Acquiring registers this process and releasing clears it. A second
watcher is refused. A lock that has stopped being refreshed is stale
rather than running, and can be taken over. A refreshed lock stays live. A
watcher cannot refresh a lock another has taken over. The staleness limit
allows for a slow tick. Stopping is a request the watcher can see, and releasing
clears it. A leftover stop request does not stop the next watcher. Each vault
is tracked separately. An unreadable lock is not treated as a watcher.

**Damaged logs.** A line that will not parse is reported as a chain break
naming the line, while the records before it remain readable.

**Token handling.** A junk file alone opens nothing. A junk file alongside a
valid token does not block it, in either order, and neither does a path that
does not exist. Validation rejects a non-token file and a missing file, and
accepts a real one.

**Passwords.** Short passwords are refused however complex, including ones
that satisfy every symbol-and-digit rule. A dash, space or underscore separated
phrase of four words is recognized as strong. An existing vault still opens
with a password below the floor. The boundary is where it says it is.

**Failed attempts.** Failures are counted and cleared by a success. Repeated
failures do not destroy a vault by default. A limit below three is refused. An
opted-in limit destroys the vault when reached and not before, and the correct
password does not help afterwards. Backoff grows and is capped.

**Duress.** The real password opens the real contents. The duress password
shows the decoy and the real password never works again. The decoy keeps
working on repeated use. A vault with a duress password and one without have
comparable, non-zeroed duress blocks. A wrong password destroys nothing. The
container does not change size when duress fires. An empty decoy is refused.

**Replay across a restart.** A captured command is refused after the guard is
resumed from its high-water mark, a newer command is still accepted, and the
nonce memory stays bounded across three thousand commands.

**Manifest rollback.** Splicing an earlier manifest region over the current one
does not open the vault onto the older list of files.

**Recovery gate.** A quorum of custodian shares cannot rebuild a key once
destruction is committed, and an uncommitted state still recovers, so the gate
is not simply refusing everything.

**Components without a container.** The split bundle and every component
together recover the release key and nothing further: the wrapped master key is
not in the bundle.

**Password patterns.** Repetitive passwords are refused however long, covering
a single repeated character, digits, a repeated word and an alternating pair.
Ordinary long passwords with doubled letters are still accepted.

**Split bundle encoding.** Trailing bytes are refused rather than ignored, and
a bundle naming one component twice is rejected.

**Clock rollback across a restart.** A reading behind a time already recorded
is raised to it and reported as an anomaly; an honest reading is untouched.
Through the boundary, records claiming a later time than the system clock do
not extend a deadline.

**Export safety.** A corrupted late chunk leaves nothing at the destination,
complete or partial. Export refuses to write through a symbolic link, and the
link target stays empty. A split bundle is not readable by others on Unix.

**Duress on split vaults.** A duress password fires on a split-protected vault
with a token attached, and the real contents are gone afterwards. Extraction
under duress removes the container and every sidecar. An ordinary extraction
leaves all of them alone.

**Duress reach.** Duress fires on listing, extracting and verifying, not only
on unlocking, and the real contents are gone after each. A failed setup leaves
no scratch file beside the vault.

**Duress similarity.** A duress password one character from the real one, with
a digit substituted, or identical to it, is refused. A genuinely different
phrase is accepted. An empty password is not compared.

**Custody in use.** A custodian supplies its component when the vault is
opened, so password plus custodian reaches the threshold with no token file
present. An expired custodian says so rather than looking like a wrong
password, and does not prevent opening when the remaining components still add
up. An unreachable custodian is stepped over. Checking in moves the deadline,
and a wrong password cannot.

**Custody.** A forged check-in is refused and does not move the deadline. The
share is destroyed at the deadline and never returns, even to the correct
password. Requests cannot be replayed, and stale or future-dated ones are
refused. A vault cannot be re-enrolled over an existing record.

**Recent vaults.** The remembered list holds paths and nothing that describes a
vault, and drops entries whose file has gone.

**Vault identity.** A vault that does not exist yet is not reported as
destroyed, and a new vault created where a destroyed one used to be does not
inherit its journal.

**After destruction.** The split bundle is removed with the container, and the
boundary reports the vault as no longer protected rather than as protected.

**Destruction guards.** A split-protected vault cannot be destroyed by a
session holding no components, and the container survives the attempt. It
remains openable afterwards by someone who does hold one. Destruction succeeds
once a component is supplied.

**Split through the IPC boundary.** Status is reported before and after
enrollment. A split vault cannot be unlocked or listed through the boundary
without a token, using the same API the window uses. Both tokens open a vault
whose password was lost. Enrollment refuses to overwrite an existing token file.

**Heartbeat.** A check-in holds full credit throughout the heartbeat interval,
decays to roughly half at the midpoint between heartbeat and timeout, and
reaches zero at the timeout. A two-hour heartbeat has started decaying by
twenty hours where a twenty-four hour one has not. A heartbeat at or beyond the
timeout cannot produce an impossible window.

**Redundancy.** With three components, each of the three pairs opens the vault
and any single component alone does not. A stolen drive plus a correctly
guessed password is still short. A custodian share offered in the remote slot
does not authenticate, and vice versa. The assessment is asserted to warn that
two tokens bypass the password.

**Secret memory.** Locking is attempted and its outcome reported truthfully,
and the status is asserted never to be VERIFIED. A clone gets its own
allocation rather than aliasing. A secret keeps its address across a move. A
refused lock moves the reported outcome to Refused and a later success does not
clear it.

**Platform.** Copy-on-write and layered filesystems refuse to pretend an
overwrite achieved something; conventional ones report best effort and no more.
Filesystem names map correctly and an unrecognised one becomes Unknown. The
filesystem under this machine's temp directory is identified without panicking,
and the assurance actually returned by an overwrite matches what the filesystem
declares it allows. A missing query tool is reported as unknown rather than as
zero snapshots.

**Service definitions.** Destruction is off by default in all three formats,
and enabling it is visible in each. The systemd unit restarts on failure and
drops privileges. The launchd plist is balanced XML with KeepAlive. The Windows
script configures restart-on-failure. Supervision status is asserted to be
unknown rather than false when it cannot be determined.

**Remote commands.** A correctly signed command is accepted. Altering the
action, the expiry or the nonce each invalidate the signature. A command for
another vault, an expired one, a replayed one, one dated in the future, and one
signed by a different organization are each refused with a distinct verdict. A
command that would lengthen a deadline is refused; one that shortens it is
accepted. The action set is asserted to contain nothing that reads contents.

**Threshold recovery.** Any three of five shares reconstruct the key exactly,
across four different combinations; zero, one and two shares recover nothing.
Shares from another vault are refused rather than mixed in. A threshold of one
and an unsatisfiable configuration are both refused. Shares survive hex
encoding for distribution, and malformed shares error rather than panic.
Recovery is permitted in every pre-commitment state and refused in every
committed one.

## What is not tested

## Forensic validation

Run once, on Windows, on a USB stick formatted NTFS. A vault was created, a
file added, the 48-byte wrapped key recorded from offset 104, and the vault
destroyed. The raw disk was then searched for those bytes with a hex editor.

They were not found. Destruction behaved as described.

One run, one person, one kind of storage, and no attempt at physical media
recovery. It is the first evidence the central claim has ever had, and it is
not an audit. `docs/FORENSIC-TEST.txt` describes how to repeat it.

A first attempt produced a false alarm worth recording. The test file had been
saved onto the stick before being added to the vault, and NTFS stores files of
a few hundred bytes inside their own index entries rather than in separate
blocks. Deleting it left the text in place, so searching the disk found the
plain original and it looked like a leak. The giveaway was the filename sitting
beside it in readable form, which a vault could never produce because it
encrypts filenames. The guide now says to keep the test file off the drive
entirely.

- **Forensic behavior on real media.** Filesystem *identification* is tested,
  and behavior on ext4 is exercised directly. Nothing has been tested against
  NTFS, ReFS, APFS, XFS, Btrfs or ZFS, nor against HDD, SATA SSD, NVMe, VHDX,
  QCOW2 or RAID. The copy-on-write refusals are reasoned from how those
  filesystems work, not observed. Recovering a destroyed vault with forensic
  tooling has never been attempted, which is the experiment that would actually
  substantiate the destruction claims.
**Fuzzing.** A deterministic mutation fuzzer runs over the header, manifest,
split bundle, recovery token, decompressor and custody record parsers, with
fixed seeds so failures reproduce. Mutations include bit flips, truncation,
extension, splicing, and driving length fields to their extremes. It found a
byte-index slicing bug in five parsers on its first run.

Coverage-guided fuzzing is not done: `cargo-fuzz` needs nightly. Targets exist
in `fuzz/` and have never been run.
- **Concurrency.** `ztd` exists but is single-threaded and takes no lock, so
  two instances watching one vault, or `zt` and `ztd` running together, are not
  coordinated. Presence is still reconstructed from the audit log, so only
  strong signals are recovered; OS-level medium and weak signals need platform
  integration that is not built, and are not fabricated in its absence.
- **Real power loss.** Interruption is simulated by dropping the journal handle
  between stages, which exercises the resume logic but not a torn write inside
  a single `write` call. `sync_all` is used at every stage boundary, but this
  has not been tested against actual power removal.
- **The GUI, by automation.** The window is rendered and driven with synthetic
  clicks during development, and every check is a screenshot read by a person.
  Nothing in the test suite would catch a panel moving, overlapping or falling
  off the bottom, and no synthetic key events reach it, so password fields are
  covered only by hand. The tested part is `zerotrace-ipc`, which is where the
  security boundary actually sits.
- **Independent cryptographic review.** Not done. Required before 1.0.

## Manual verification performed

The CLI was exercised end to end on a vault holding a text file, an
incompressible 400 KB binary and a 380 KB compressible file: create, import,
verify (3 chunks, 0 failures, INTACT), export with byte-identical round trip,
and a wrong-password attempt that was refused. The container was then searched
for each filename and for a distinctive plaintext phrase; none appeared.
