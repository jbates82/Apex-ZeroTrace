# Apex ZeroTrace

An encrypted vault that destroys its own key if you stop checking in.

Your files go into a single container. Their names, sizes and dates are
encrypted along with the contents, so the vault doesn't even reveal what sort
of thing it's holding. You can split the key so that opening it needs two
pieces out of three, which means somebody who steals your drive *and* guesses
your password still can't get in. And you can set a deadline: miss it, and the
key is overwritten and everything inside becomes unreadable for good.

Written in Rust. Runs on Windows, macOS and Linux. Apache 2.0.

**Version 0.21.0. Not audited, not reviewed, not 1.0.** Please read
[what it can't do](#what-it-cant-do) before you trust it with anything you
can't replace.

## Why destroy the key instead of the file

This is the idea the whole program is built on, so it's worth a moment.

Overwriting a file doesn't reliably reach every copy of it. Filesystems move
blocks around. SSDs remap them behind a translation layer you can't see.
Copy-on-write filesystems write somewhere else by design. Snapshots keep entire
previous states. You can't overwrite what you can't address, and on modern
storage you can't address most of it.

But you don't need to. Forty-eight bytes stand between the ciphertext and
meaning. Destroy those and every copy becomes equally useless at the same
moment: the ones on the disk, the ones in a snapshot, the ones the drive
quietly relocated last year.

Wiping the container is still offered as a second layer, and never dressed up
as a substitute. Where it can't accomplish anything, as on a copy-on-write
filesystem, it refuses rather than reporting "best effort" and letting you
assume.

## Why Rust

One reason really decides it. This program's entire premise is destroying key
material at a known moment. In a garbage-collected language the collector may
copy your key somewhere else and leave the original bytes sitting in freed
memory: unreachable, un-erasable, and with nothing to tell you it happened. For
a vault that sells cryptographic erasure, that's not a tradeoff, it's a
contradiction. Rust drops values at a point you choose, so a secret can zero
itself and mean it.

There's a second reason. The parsers here read lengths and offsets straight out
of files that an attacker may have written. That's the classic source of
memory-corruption bugs in archive tools. In safe Rust the worst thing that
happens is an error.

And a third: the types carry meaning the compiler enforces. `Assurance` has no
boolean form, so "probably fine" is literally unspeakable. The deadman state
machine can't be driven backwards out of a committed state.

It costs a weaker desktop story than a native toolkit would give, and slow
builds. Worth it.

## What it does

- XChaCha20-Poly1305, or AES-256-GCM if a compliance rule demands it
- Argon2id key derivation, with a floor enforced at open time so a tampered
  header can't talk the program into something weaker
- Filenames, paths, sizes and timestamps encrypted with the contents
- Chunked authenticated storage under a Merkle root
- Split-key protection: three components, any two of which open the vault
- A deadman policy that weighs evidence rather than counting minutes. Proof
  you're there scores full marks; signs the computer is merely switched on
  can't reach the bar on their own
- Deadlines that count time asleep and can't be extended by winding the clock
  back
- A hash-chained audit log, with a state journal anchoring it so that entries
  removed from the end are caught
- Two-phase destruction that resumes if it's interrupted
- Cryptographic erasure confirmed by reading the bytes back
- Remote custody: one component held somewhere the attacker isn't
- A duress password that opens decoy contents and destroys the real ones
- Ed25519-signed remote commands, replay-resistant, and unable to weaken a
  vault however well signed
- Threshold recovery that deliberately doesn't survive a committed destruction

Three programs:

- `zerotrace`, the desktop window
- `zt`, the command line
- `ztd`, the background service that watches deadlines

## Build

```
cargo build --release
```

`Cargo.lock` is committed and ships in every release. This is an application
rather than a library, so pinning exact dependency versions is the point: a
build from this tree resolves to the same crates that were tested and audited,
rather than to whatever has been published since. If you want to move forward
deliberately, `cargo update` and run the tests.

You need a Rust toolchain and a C compiler, because Zstandard is a C library.
Nothing else on Linux or macOS; on Windows the Visual Studio C++ build tools,
which a normal Rust install offers to fetch for you.

The three programs land in `target/release`.

```
cargo test --release
```

287 tests. `TESTING.md` says what they cover and, more usefully, what they
don't.

## Using it

```
zt vault create secrets.azv
zt vault import secrets.azv report.pdf notes.txt
zt vault list   secrets.azv
zt vault export secrets.azv ./recovered
zt vault verify secrets.azv
```

Protect it against a stolen drive, then open it:

```
zt split enroll secrets.azv /media/usb/token.txt /media/safe/custodian.txt
zt split status secrets.azv
zt vault list   secrets.azv --token /media/usb/token.txt
```

Set a deadline, look at exactly what it would do, then let a service enforce
it:

```
zt destroy dry-run   secrets.azv
zt deadman configure secrets.azv --enable --timeout 259200 --heartbeat 86400
ztd watch secrets.azv --interval 300
ztd watch secrets.azv --interval 300 --allow-destruction
```

`zt` never destroys a vault on a timer. Only `ztd` does, and only when you
start it with `--allow-destruction`. Everything above is available in the
window too, including installing the service to come back after a restart
without needing administrator rights.

```
zerotrace secrets.azv
```

Passwords come from the terminal, or from stdin when there's no terminal. Never
from a command line argument, because those are readable by other processes on
most systems and live forever in shell history.

## What this build actually enforces

```
zt security audit
```

prints the table below, generated from the code, so it can't drift away from
what the binary really does.

| | |
| --- | --- |
| Authenticated encryption | VERIFIED |
| Header authentication | VERIFIED |
| KDF parameter floor | VERIFIED |
| Encrypted metadata | VERIFIED |
| Chunk integrity (Merkle) | VERIFIED |
| Secret zeroing on drop | VERIFIED |
| Memory locking | BEST EFFORT |
| Multi-factor key composition | VERIFIED |
| Tamper-evident audit chain | VERIFIED |
| FIDO2 hardware transport | NOT IMPLEMENTED |
| Presence engine | VERIFIED |
| Clock rollback resistance | VERIFIED |
| Rollback across restart | BEST EFFORT |
| Persistent state journal | VERIFIED |
| Audit truncation detection | VERIFIED |
| Deadman state machine | ENFORCED |
| Two-phase authorization | VERIFIED |
| Cryptographic erasure | VERIFIED |
| Resume after interruption | VERIFIED |
| Container overwrite | BEST EFFORT |
| Filesystem-aware sanitization | VERIFIED |
| Atomic export | VERIFIED |
| Symlink refusal on export | VERIFIED |
| Owner-only file permissions | BEST EFFORT |
| Snapshot handling | NOT IMPLEMENTED |
| Free-space sanitization | NOT SUPPORTED |
| Service unit generation | VERIFIED |
| Signed remote commands | VERIFIED |
| Replay resistance | VERIFIED |
| Threshold recovery | VERIFIED |
| Recovery refused after commit | VERIFIED |
| Split-key protection | VERIFIED |
| Remote custody | VERIFIED |
| Machine key binding (TPM) | NOT IMPLEMENTED |
| Manifest generation binding | VERIFIED |
| Rollback resistance | NOT IMPLEMENTED |

Memory locking says BEST EFFORT and will never say VERIFIED, because all it
does is keep secrets out of swap. Hibernation writes all of memory to disk
anyway. Core dumps are unaffected unless you disable them separately. A
hypervisor snapshot captures everything regardless. Claiming more than that
would be a lie told in capital letters.

## Before you trust it with anything

**A vault protects what is inside it. It says nothing about where that file has
been.**

Every file you put in a vault existed somewhere first, on an ordinary
unencrypted disk. Deleting the original afterwards does not remove it: deleting
takes the name off a list and leaves the contents where free recovery software
will find them. Emptying the recycle bin does not change that.

It is worse than the one file. Editors leave automatic backup copies. Your
computer keeps thumbnails and search indexes of what is inside your documents.
Windows and macOS take system snapshots without asking. Cloud folders keep
their own copies. Solid state drives keep spare space no program can reach.

None of this is something ZeroTrace can fix. The file was there before this
program saw it.

**Turn on full-disk encryption and leave it on.** BitLocker, FileVault, LUKS,
with a real passphrase, and shut the machine down rather than leaving it
asleep. That single step does more than anything else, and it composes with
this: disk encryption handles the leftovers, the vault handles the deadline,
the split key and the destruction.

`docs/BEFORE-THE-VAULT.txt` covers the rest, including which popular remedies
do not work and why.

## What it can't do

**Recover a lost password.** If a vault isn't split-key protected and the
password is gone, it's gone. Nobody can help, including whoever wrote this.
That's the design working, not a missing feature.

**Protect copies you already made.** The wrapped key lives inside the
container, so a backup taken before destruction carries its own key and opens
normally. Destroying a vault protects that file. It says nothing about copies
elsewhere.

**Defend a machine that's already compromised while a vault is open.** At that
moment your files are readable by you, and therefore by anything running as
you.

**Stop someone closing the watcher.** Nothing can, on a machine they control.
What defends a vault against that person is the split key, not the deadline:
stopping the watcher gives them unlimited time, and unlimited time is worth
nothing when they hold one component and need two.

**Notice a rolled-back drive.** Someone holding your disk can put yesterday's
copy back, policy and journal included. Catching that needs an anchor they
don't control, such as a counter in a TPM or a remote service. Neither is built
yet.

**Hide how compressible your files are.** Compression happens before
encryption, so the container's size leaks something about its contents. Padding
is designed and not implemented.

## Where it stands

Three things sit between this and a 1.0 security claim.

**Hardware key binding** isn't built. Without it nothing ties a vault to one
physical computer.

**Forensic validation** has been started rather than finished. Destruction was
tested once, on a USB stick formatted NTFS: afterwards the wrapped key couldn't
be found anywhere on the raw disk. That's one run, one machine, one filesystem,
by one person, with no attempt at physical media recovery. It's a great deal
better than the nothing that came before it and a great deal short of an audit.
`docs/FORENSIC-TEST.txt` explains how to repeat it, including the false alarm
that came first.

**Independent cryptographic review** hasn't happened at all. This is the big
one. Nothing in the code closes it, and no amount of testing substitutes for
somebody with no stake in the answer trying to break it.

Until then, keep a backup you control.

## Documentation

| | |
| --- | --- |
| `docs/ABOUT-ZEROTRACE.txt` | what it does, and how it compares to other tools |
| `docs/manuals/GUI-MANUAL.txt` | the desktop window, start to finish |
| `docs/manuals/CLI-MANUAL.txt` | the command line, start to finish |
| `docs/BEFORE-THE-VAULT.txt` | what happened to your file before it went in, and what to do |
| `docs/FORENSIC-TEST.txt` | how to check destruction really works |
| `SPLIT_KEY.md` | the split key, and the stolen-drive threat model |
| `REMOTE_CUSTODY.md` | holding a component off the machine |
| `DURESS.md` | the duress password, and what it does and does not defend |
| `SECURITY.md` | security model, invariants, reporting |
| `THREAT_MODEL.md` | what's in scope and what isn't |
| `ARCHITECTURE.md` | crates, dependency direction, design decisions |
| `VAULT_FORMAT.md` | the AZV container, byte by byte |
| `DESTRUCTION_MODEL.md` | how destruction works and what it reaches |
| `TESTING.md` | what's tested, and what isn't |
| `CHANGELOG.md` | every release, including the bugs and why they happened |

Both manuals assume no background in encryption and carry their own glossary.

## License

Apache 2.0.
