# Changelog

## 0.21.0 - what happened before the file went in the vault

The largest gap in this documentation, and it took a direct question to find:
what stops a forensics team recovering the original file from the disk it was
created on?

Nothing does. A vault protects what is inside it and says nothing about where
that file has been. Deleting the original takes its name off a list and leaves
the contents where free recovery software finds them, and the original is the
least of it: editors leave automatic backup copies, the operating system keeps
thumbnails and a search index of document contents, Windows and macOS take
system snapshots without asking, cloud folders keep their own copies, and solid
state drives keep spare space no program can reach.

None of it is fixable here. The file existed before this program saw it. But
the documentation never said so, and a reader could reasonably have assumed it
was handled.

Added `docs/BEFORE-THE-VAULT.txt`, written for somebody with no technical
background: what leaks and why, then what to do about it in order of how well
it works, then what does not work, then a routine an ordinary person can
actually follow.

The ranking matters more than the list. Full-disk encryption with a real
passphrase, machine shut down rather than asleep, is the answer for almost
everybody, and it composes with this program rather than competing: disk
encryption handles the leftovers, the vault handles the deadline, the split key
and the destruction. Creating files on an encrypted or removable drive from the
start is better still and harder to keep up. Virtual machines are assessed
honestly rather than recommended: a virtual disk is a large file on the real
disk, so a casual setup moves the problem rather than solving it.

A prominent warning now appears at the top of the limitations section in both
manuals, in the README, in the overview, and as a topic in the in-application
guide, which is what somebody using the window actually reads.

## 0.20.1 - the manuals caught up

The manuals and the overview had not been updated for five user-facing changes
made while working through the review. Asked directly whether all the
documentation had been updated, the answer was no.

Added to both manuals and `docs/ABOUT-ZEROTRACE.txt`:

- The password rules beyond length: at least six different characters, no long
  run of one, nothing that is a short piece repeated. Stated with the example
  that motivates it, since "twenty characters and worthless" explains the rule
  better than the rule does.
- That an extraction produces a complete checked file or nothing, and what the
  symbolic link refusal means when somebody meets it.
- That the operating system may hold snapshots ZeroTrace cannot reach, that
  `zt platform report` will say so, and why deleting them is not something this
  program will ever do.
- That password boxes are overwritten rather than merely emptied, and that this
  is weaker than it sounds because the toolkit may hold copies elsewhere.
- The progress bar while duress contents are prepared.

Two paragraphs were duplicated while doing this, because a replacement was
applied twice over two attempts and matched both times. Found by counting
occurrences rather than by reading, which is the only reason it was found at
all.

## 0.20.0 - the last of the review, and a check that keeps it honest

Findings 5, 15 and 18, plus the decoy progress bar.

**Finding 5, passwords in memory. Valid, already disclosed, now improved.**
The window held passwords in a `String` and called `clear`, which sets the
length to zero and leaves the characters in the allocation until something
happens to reuse it. They are now zeroed before being cleared.

Still reported as best effort, and the desktop README still says why. This is
weaker than the core's `SecretBytes`, which never lets a secret reach a
growable buffer at all, and it cannot be otherwise: egui needs an editable
`String` to draw a text field, and may hold its own copies in layout or undo
state that nothing here reaches.

**Finding 15, snapshots. Valid, and answered with a warning rather than a
feature.** `zt platform report` now says whether the vault sits on a volume
where the operating system keeps prior copies, and what that means: destroying
a key does not reach a copy taken beforehand.

It does not enumerate snapshots and does not delete them. Deleting them needs
administrator rights and is the single most recognisable thing ransomware does,
which is why antivirus products treat `vssadmin delete shadows` as a signature.
A vault application that behaved that way would be quarantined and would
deserve it. Enumerating is also mostly privileged, so it would report "none
found" on exactly the machines where the answer matters.

The note points at remote custody as the real answer: a snapshot captures the
container and the split bundle, and cannot capture a component that was never
on the machine.

**Finding 18, documentation drift. Valid, and worse than expected.**
`scripts/check-docs.sh` compares the capability table in README.md against what
`zt security audit` actually prints, and fails when they disagree.

It found nine rows on its first run. Six were ones I had added to the README
over previous releases without adding them to the binary; three predated this
work. The table had been describing capabilities the program never claimed.

Both are now aligned, and the check runs alongside `stamp-version.sh --check`
before a release.

Also added:
- A progress bar while the duress contents are prepared. Decoy files are
  ordinary files and can be large, and the work now happens on a background
  thread like every other import.

## 0.19.9 - replay across a restart

Findings 12 and 14 from the v0.19.2 review.

**Finding 12, replay state. Valid.** `ReplayGuard` was a `HashSet` held only in
memory. It forgot every nonce when the service restarted, so a captured command
could be replayed by waiting for a restart or causing one, and it grew without
bound in a process that ran for months.

It now carries a high-water mark: the newest timestamp already accepted. A
command must be issued strictly after it, which is one integer, survives a
restart when persisted, and cannot grow. The nonce set is kept alongside and
bounded at a thousand entries, so a replay within one run is still reported as
a replayed nonce rather than as an old timestamp.

Equal timestamps are refused, not only earlier ones. A replayed command carries
the timestamp it was issued with, so accepting an equal value would have left
the newest command replayable for ever, which is exactly what a restart
exposes. The cost is that two commands issued in the same second cannot both be
accepted. That is a real limitation and the right trade: commands are issued
deliberately, the timestamps are the operator's to control, and a strictly
increasing sequence is what makes the guard survive a restart at all.

Tested: a captured command is refused after a restart, a newer one still works
so the mark is not simply refusing everything, and the nonce memory stays
bounded across three thousand commands.

**Finding 14, file names. Valid, and deliberate.** No code change.
`THREAT_MODEL.md` now states what the sidecar names reveal: that ZeroTrace is
in use and which features are enabled, including where a custodian lives. It
also states what they do not reveal, which is contents, and whether a duress
password exists.

Hiding them would mean putting everything inside the container, which trades
this for a worse problem: the audit log and journal must be appendable while
the vault is closed, and a service that had to open a vault to record that it
had been opened would need the key resident to do it. If the existence of a
vault is itself what must be hidden, this is not the tool.

## 0.19.8 - manifest rollback

Finding 9 from the v0.19.2 review. Valid.

A manifest proved it was a genuine manifest for its vault, and nothing more.
Its additional data bound the vault identifier and the length, so an earlier
manifest from the same vault authenticated perfectly. Somebody holding an old
copy of the container could splice that region back over the current one and
the vault would open onto the older list of files: a deleted entry restored, an
added one gone, every check passing.

Manifests now carry a generation, counted from one and incremented on every
write, bound into the additional data. An older manifest authenticates only
against its own generation.

The generation is written in the clear beside the sealed manifest, because a
reader needs it before it can decrypt. That is not a weakness: altering it
makes the manifest fail to open, so it cannot be used to lie about which
generation this is, only to read the right one. The value outside is checked
against the sealed copy inside, so it cannot point at one generation while the
manifest claims another.

What this does and does not do. It stops a manifest being moved between
generations of the same vault, which was possible and is now not. It does not
stop somebody replacing the entire container with an older copy of itself,
which remains the documented limitation: that is rollback resistance, it needs
an anchor they do not control, and it is still NOT IMPLEMENTED.

Container format 3 changed shape, so vaults created before this release will
not open. Everything is pre-1.0 and there is no migration.

## 0.19.7 - the recovery gate could be walked past

Findings 3, 10 and 11 from the v0.19.2 review.

**Finding 11, recovery gate. Valid, and the most serious of the three.**
`combine_shares` reconstructed a master key from a quorum of custodian shares
and never consulted `RecoveryGate`. The gate existed as a function a caller had
to remember to call, which left an API that rebuilds a destroyed vault's key
one missed line away.

The gate is now taken inside `combine_shares`, which requires the deadman state
and refuses once destruction is committed. A quorum of custodians cannot undo a
destruction, and it is no longer possible to forget to check.

**Finding 3, copies after destruction. Valid as a documented limitation, not a
defect.** Now proved rather than asserted: a test holds the split bundle and
every component at once, confirms the release key is recoverable, and confirms
that this is the end of what they can do. The release key only unwraps a
wrapped master key, and that lives in the container. A backup of the container
taken beforehand still opens; every component in the world does not.

**Finding 10, hash chains. Valid as a documentation gap.** The capability table
already said "tamper evident" rather than "authenticated", which is exact, but
nowhere said plainly what that excludes. `SECURITY.md` now states that an
adversary holding the whole file can recompute every hash and produce a chain
that verifies, that nothing here prevents it, and what making the logs
unforgeable would actually require.

## 0.19.6 - password patterns and parser hardening

Findings 6, 7 and 8 from the v0.19.2 review.

**Finding 6, repetitive passwords. Valid.** A length floor alone accepted
`aaaaaaaaaaaaaaaaaaaa`, `111111111111111` and
`passwordpasswordpassword`, all of which are worthless and all of which
cleared fifteen characters comfortably.

Three checks added, all length-friendly rather than complexity rules: at least
six distinct characters, no run of one character longer than four, and a
refusal of anything that is one short piece repeated to length. A test asserts
ordinary choices such as `bookkeeper-committee-fluffy` still pass, because a
guard that rejects reasonable passwords pushes people toward writing them down.

**Finding 7, Argon2id parameters. Not valid; no change.** Verified against the
code rather than assumed:

    default   64 MiB, t=3, p=1
    minimum   19 MiB, t=2, p=1
    maximum    4 GiB, t=64, p=64

The default is comfortably above the OWASP recommendation, and the minimum is
exactly the OWASP floor, enforced when a vault is opened so a tampered header
cannot ask for less. A `sensitive` preset at 256 MiB, t=4 is available. Nothing
here needed changing, so nothing was changed.

**Finding 8, split bundle parser. Partly valid.** The parser already rejected a
wrong magic, an unknown version, an impossible threshold, an implausible share
length, an unknown component identifier and a short read. Two gaps were real:

- Trailing bytes were ignored. Accepting them lets one bundle be presented in
  several encodings and gives somebody a place to hide data that every other
  tool overlooks.
- A component named twice was accepted, so one share would silently shadow
  another and which one won would depend on iteration order.

Both now refused, with tests.

## 0.19.5 - clock rollback across a restart

Finding 2 from the v0.19.2 review. Valid, and more direct than the finding
describes.

The session and the service both built their time anchor like this:

    TimeAnchor { wall: raw.wall, monotonic: raw.wall.max(0) as u64 }

The monotonic field was set from the wall clock. The whole rollback defense
compares the two readings against each other, so making them agree by
construction disabled it completely. Shutting the machine down, winding the
clock back and starting again bought unlimited time, exactly as the review's
example described.

The comment beside it was not wrong about the problem: monotonic time is
process-local, so across a restart it genuinely cannot be compared against
anything written earlier. It was wrong about the remedy.

What survives a restart is what was written down. The audit log and the state
journal are append-only and timestamped, so their newest record is a time known
to have happened, and the clock is now held at or above it. A reading below
that is recorded as a clock anomaly and reported by the service rather than
passing silently.

This does not stop somebody editing those files. That is rollback resistance,
it needs an anchor they do not control, and it remains NOT IMPLEMENTED.

Tested: at the unit level, that a reading behind a known time is raised and an
honest reading is left alone; and through the boundary, that records claiming a
later time than the clock do not extend a deadline.

## 0.19.4 - export safety and file permissions

Findings 4, 13 and 17 from the v0.19.2 review. All three valid.

**Finding 4, partial plaintext.** Export wrote decrypted chunks straight to the
destination, so a file failing authentication on a late chunk left everything
decrypted up to that point sitting there in the clear. Export now writes to a
neighbouring temporary file and renames it into place only once every chunk has
authenticated and the length matches. A failure overwrites and removes the
partial file rather than leaving it.

An export now produces a complete verified file or nothing.

**Finding 17, symlinks.** `File::create` follows a symbolic link, so somebody
who could place one in the destination directory could have decrypted contents
written wherever they chose. The path traversal check did not catch this,
because the path itself is perfectly ordinary and the redirection happens in
the filesystem.

The destination and every directory above it are now checked with
`symlink_metadata`, which reports the link rather than following it, and the
temporary file is created with `create_new`, which fails if anything is already
at the path. That second part is what closes the gap between the check and the
open.

**Finding 13, permissions.** Files holding key material or describing a vault
were created through ordinary filesystem calls and inherited the process umask,
which on a shared machine commonly leaves them readable by everyone. Split
bundles, recovery tokens, custody records, custody pointers, audit logs and
journals are now restricted to their owner on Unix.

On Windows this reports NOT IMPLEMENTED rather than claiming a protection it
did not apply: files inherit an access control list from the parent directory,
which inside a user profile is already restricted, and tightening it further
needs the Windows security APIs.

Tested: a corrupted late chunk leaves nothing at the destination, an export
refuses to write through a symbolic link and the link target stays empty, and a
split bundle is not readable by others.

## 0.19.3 - duress reaches every path, and the lockfile ships

Findings 1 and 16 from the v0.19.2 review, both valid, both mine.

**Finding 1.** The split-key open path never tried the duress identity, so a
duress password did nothing at all on a split-protected vault. Somebody under
coercion with a token attached, which is ordinary use, would have got no
protection whatever. The duress attempt now happens before components are
gathered, on every path that accepts a password.

The review's underlying worry, that split components could reconstruct the
master key after duress, is not valid: duress overwrites the wrapped master
key, and components without a wrapped blob reconstruct nothing. The fault was
that the path was never wired, not that the architecture conflicted.

**Finding 16.** `Cargo.lock` was being deleted before packaging, so no release
archive carried one and nobody could rebuild what was shipped. It now ships,
and the README says why: this is an application, so pinning the exact versions
that were tested is the point.

Also finished, from the work in flight:
- Extracting under duress hands over the decoy and then removes the container
  and everything written beside it: audit log, journal, policy, split bundle,
  custody pointer, watch lock. Files are overwritten before unlinking where
  that reaches the data.
- Failures to remove are reported rather than swallowed. A file that survived
  is worth knowing about.
- No audit record is written for a duress extraction, because writing one
  would recreate the log that is about to be deleted.

Tested: duress on a split-protected vault with a token attached, extraction
under duress leaving nothing behind, and an ordinary extraction leaving
everything alone. That last one matters most: normal use must not delete
anything.

## 0.19.2 - the duress setup could fail without saying so

Reported from testing: setting a duress password in the window appeared to
work, the duress password then failed to open anything, and a file called
`v.azv.decoy-build` was left beside the vault.

The scratch file was the clue. Its presence meant the operation had failed
partway, and the error had gone to the status bar where it was easy to miss.
The likely cause was the file dialog, which said "Files the duress password
will show" and read as an invitation to name a new file rather than pick
existing ones.

Fixed:
- Decoy files are checked to exist before anything is written, so a mistyped
  path fails cleanly with a message naming it.
- The scratch file is removed however the operation ends, including an early
  return. A file called `v.azv.decoy-build` beside a vault tells anybody who
  looks that a duress password was being arranged.
- The dialog now says "Pick files that already exist, to show under duress",
  and the pane asks you to choose files it will show rather than where to place
  one.
- Success is confirmed in the pane, not only in the status bar.

Changed:
- Duress has its own section in the sidebar rather than sitting at the bottom
  of Key protection.

Also fixed, found by a test written for this:
- Verifying a vault opened under duress reported damage. The decoy header was
  cloned from the real identity, so it carried the real contents' integrity
  root. Nothing was wrong with the decoy.

A test now asserts duress fires on listing, extracting and verifying, not only
on unlocking. Anything narrower would be a trap: somebody reaching for Extract
under pressure would get no protection while believing they had.

On whether the program should show that a duress password is set: it says so
until the window closes, and never again. Anybody who can open this program
could otherwise read the answer off the screen.

## 0.19.1 - duress in the window, and a guard that works in both

Added:
- A Duress password panel in Key protection: choose the files it will show,
  then enter the real password and the duress password. The prompt states what
  it costs in the alert colour, because this is the one setting whose mistake
  is unrecoverable.
- The window's auto-lock clears the contents list and attached tokens after
  five minutes of inactivity.

Fixed before it shipped:
- The similarity guard was written into the IPC layer, so the command line
  walked straight past it and accepted a duress password one character from
  the real one. Moved into the vault, where both front ends reach it, which
  needed the real password passed through rather than inferred.

  This is the third time a rule has been written into one front end and missed
  the other: the password floor, the token requirement on destroy, and now
  this. The pattern is worth naming. A rule belongs where the operation
  happens, not where it is requested.

The guard refuses a one or two character difference and a shared opening of
eight characters or more, and is deliberately blunt: getting it wrong destroys
a vault, so it errs toward refusing.

## 0.19.0 - duress password, and auto-lock

Added:
- **A duress password.** A second password that opens the vault into different
  contents and destroys the real ones as it does so, silently. Both identities
  live in one container; there is no second file to notice.

  Container format 3. Every vault now carries a 256-byte block for a duress
  wrapping, filled with random bytes when unused. That is the point rather than
  an implementation detail: a block that only appeared once the feature was
  enabled would tell an adversary to demand a second password, and a duress
  password known to exist protects nobody.

  The real identity is tried first, so an ordinary open never reaches the
  duress path. A wrong password fails both and destroys nothing. The real key
  is overwritten and read back before the decoy contents are returned, so
  interrupting the program mid-open still leaves it gone. The decoy keeps
  working afterwards, because somebody watching will ask again.

  Refuses an empty decoy, and warns that the duress password must not resemble
  the real one. Two passwords a keystroke apart will be confused under stress,
  which is exactly when this would be used.

- **Auto-lock.** After five minutes without activity the window clears the
  contents list and any attached tokens.

  Described honestly in the code and the manual: there is no session to lock,
  because keys are derived per operation and dropped immediately. What this
  protects is the screen and the components sitting ready. Worth doing, and
  less than the name suggests.

Three bugs found building this, all in the same place:
- The decoy manifest was written under the scratch vault's identifier and read
  back under the real container's, so it decrypted to a failure that looked
  exactly like a wrong password.
- Chunk offsets inside the decoy manifest were left in scratch-file
  coordinates, so the contents opened and then failed their hashes.
- The decoy region sits after the real manifest, which is rewritten every time
  a file is added. It is now picked up and put back down on each save, or
  adding one file would have silently taken the duress password with it.

`DURESS.md` documents what this defends against and what it does not. It does
not defend against somebody who images the drive: the real chunks remain as
unreadable bytes, and a small decoy inside a large container invites an obvious
question. Against that adversary it buys the destruction, not the deception.

## 0.18.6 - em dashes removed

Eleven in the documentation and one in the desktop code, the last inside a
formatted string the window displays.

Rewritten rather than swapped for hyphens. An em dash usually holds a sentence
together, so removing one and leaving everything else produces a worse sentence
than the original. Each became a colon, a semicolon, a comma, or two sentences,
whichever the sentence actually wanted.

## 0.18.5 - references to a front end that no longer exists

The Tauri application was removed in 0.18.0, and four documents went on
describing it:

- `apps/zerotrace-desktop/README.md` had a whole section explaining why the
  egui window existed alongside it
- `ARCHITECTURE.md` said the security boundary must not run through TypeScript
- `TESTING.md` listed the Tauri GUI as untested
- the `zerotrace-ipc` module documentation made the same TypeScript argument

Deleting a directory does not delete the sentences pointing at it, and nothing
here checks for that.

The desktop README was rewritten while fixing this, and two other stale claims
came out with it. It said the window opens on the Guide, which stopped being
true in 0.10.1 when the Guide moved to the end. And it said no Windows build
had been observed to succeed, which was overtaken by the Windows testing that
found three platform-specific defects.

It now also states what the automated checks do not cover: layout regressions
are invisible, because every visual check is a screenshot read by a person, and
keyboard entry is exercised only by hand.

## 0.18.4 - American spelling throughout

All documentation, comments and user-facing text now use American spellings.
Thirty-one files in the first pass, twelve more in a second for inflected and
capitalized forms the first missed: "Recognises", "ORGANISATION",
"summarising", "Greyed", "Practise".

Changed: enrolment, licence, analyse, behaviour, organise, recognise,
authorise, colour, labelled, cancelled, defence, practise, minimise,
summarise, normalise, initialise, serialise, prioritise, specialise, grey,
whilst, artefact, centre, favour, programme, and their inflections.

Deliberately unchanged:
- `zt split enrol` still works as a command. Somebody may have it in a script,
  and breaking a working command to change one letter is not a fair trade. The
  help text shows `enroll`, which is what new users will see.
- "analysis" and "analyses" are identical in both spellings and were left
  alone. The first pass nearly caught them by matching a stem.

Two things worth noting about how this was done. Identifiers separated by
underscores, such as `cmd_split_enrol` and `enrolment_refuses_...`, are invisible
to word-boundary matching and had to be named individually. And the first pass
collapsed the `("enrol") | ("enroll")` command alias into a duplicate pattern,
which compiled cleanly and silently removed the compatibility it existed to
provide.

## 0.18.3 - documentation versions, stamped rather than typed

Both manuals still said "Applies to version 0.13.0". Their content was current
throughout, with remote custody, restart at login and the ambient signals
explanation all present, but the stamp had been stuck for six releases.

The cause has been the same every time. Each release bumped documentation with
a `sed` pattern naming the version it expected to find, so once a bump was
missed, every later bump silently missed too. It happened to the workspace
version, then twice to the README, and now to both manuals.

Added `scripts/stamp-version.sh`, which reads the version from `Cargo.toml`
and writes it into every document that carries one. Run with `--check` it
fails when anything has drifted, which makes this a thing that can be caught
rather than a thing to remember.

Verified by breaking a stamp deliberately and confirming the check catches it.

The lesson is one this project keeps relearning: a value written by hand in two
places will disagree eventually, and the fix is to derive it, not to be more
careful.

## 0.18.2 - README rewritten, and two things it uncovered

The README was rewritten in a plainer, more human voice. Same content, same
honesty about limits; less of the tone that reads like a specification.

Two real problems surfaced while doing it:

- The README still said version 0.13.0. The version bumps since then used a
  `sed` pattern matching the version they expected to find, so once one was
  missed they all missed. This is the second time that has happened in this
  file, which is an argument for the README not carrying a version number at
  all, or for reading it from the build the way the binaries now do.

- `REMOTE_CUSTODY.md` did not exist. It was written in 0.14.0 as part of a
  command chain that timed out partway, and the changelog has claimed it exists
  ever since. Restored, and extended with the enforcement table for the
  opening path added in 0.17.0.

A link check now confirms every document the README references is actually
present, which is what found the second one.

## 0.18.1 - warnings in test code, and the reason they were invisible

Fixed three compiler warnings, all in test code: two variables marked mutable
that are not, and one unused binding in the audit tests where a helper is
called for the records it writes rather than the handle it returns.

The warnings matter less than why they went unnoticed. Every release in this
project has been checked with `cargo build --release`, which does not compile
tests. Test code has therefore never been included in a warning count, and
these had been accumulating unseen. Reported by a user running
`cargo test --release`, which does compile them.

The check is now `cargo build --release --tests`, which covers both.

## 0.18.0 - fuzzing, and the bug it found immediately

Added:
- `crates/zerotrace-ipc/tests/fuzz.rs`, a deterministic mutation fuzzer over
  every parser that reads untrusted bytes: the header, the manifest, the split
  bundle, recovery tokens, the decompressor and custody records. It runs as
  part of `cargo test`, with fixed seeds so a failure is reproducible.

  It is not coverage-guided. `cargo-fuzz` needs nightly, which the development
  environment does not have, so `fuzz/` holds libFuzzer targets for anyone who
  does. Those have never been run and say so.

Fixed, found on the fuzzer's first run:
- Five parsers checked the byte length of a string and then sliced it by byte
  index. Hex is ASCII, so this worked on every input anybody had tried, and
  panicked on any input containing one multi-byte character. A 64-byte token
  holding a single non-ASCII character passed the length check and then
  crashed the program.

  Affected: recovery tokens, audit log hashes, journal hashes, custody records
  and enterprise recovery shares. All five now work on bytes throughout.

  This is the shape of bug the exhaustive bit-flip tests could not find,
  because flipping one bit of valid hex produces different valid hex. It took
  an input nobody would write by hand.

Removed:
- `apps/zerotrace-gui`, the Tauri front end. It was never compiled by anyone,
  and carrying two front ends means maintaining two. The egui window is the one
  that has been built, run and tested.

## 0.17.3 - the first forensic result

The destruction claim has evidence behind it for the first time. A vault was
created on a USB stick, its 48-byte wrapped key recorded, the vault destroyed,
and the raw disk searched for those bytes. They were not there.

One run, one machine, one filesystem. Not an audit, and it says so. But until
now the central claim of this program rested on the code doing what the code
appeared to do, which is not the same as checking.

Changed:
- `docs/FORENSIC-TEST.txt` rewritten. The first attempt produced a false alarm:
  the test file had been saved onto the stick before being added to the vault,
  and NTFS keeps small files inside their own index entries rather than in
  separate blocks, so deleting it left the text readable on the disk. The
  search found the plain original and it looked like a leak.

  The guide now says to keep the test file off the drive entirely, explains why
  in plain terms, and describes how to recognize that false alarm if it happens
  anyway: a readable filename beside the match, which a vault could never
  produce because it encrypts filenames.

  The earlier version of the guide caused this by suggesting the original be
  deleted from the stick and the search repeated, which does not work on NTFS.

- `TESTING.md` records the result and its limits.

## 0.17.2 - version numbers that were not true

Fixed:
- The workspace version had been stuck at 0.13.0 since then. A version bump
  ran as part of a long command chain that timed out partway, and every later
  bump used a `sed` pattern matching the version it expected to find, so once
  one was missed they all silently missed. The last several releases were
  labeled 0.14 through 0.17 in their documentation while the binaries
  reported 0.13.0.

  The code in them was real; the numbering was not.

- Version strings in the command-line banner, the service banner, the security
  audit header and the window are now taken from the build rather than written
  out, so they cannot fall behind again.

Added:
- `docs/ABOUT-ZEROTRACE.txt`, an overview of every feature with a comparison
  against VeraCrypt, BitLocker, Cryptomator, archivers, Shamir tools and
  deadman services, and a plain account of where ZeroTrace is behind them.

## 0.17.1 - a destroyed vault was a dead end, and extraction had no progress

Fixed:
- Destroying a vault replaced the Vault, Key protection and Deadman panes with
  a notice, and that notice had no Open or Create buttons on it. There was
  nothing to do next: the window was stuck on a vault that no longer existed.

  The destruction is now reported as a message you dismiss, and the window
  returns to the state it opens in, with the vault released and dropped from
  the remembered list. The report is still made, because a destruction should
  never be silent, but it gets out of the way afterwards.

  This was the second time treating a destroyed vault as a state to display
  rather than an event to report caused a problem. It is an event.

Added:
- A progress bar for extraction, on a background thread like importing.
  Decryption is as slow as encryption on a large file, so it needed the same
  feedback and for the same reason: a window that stops painting is
  indistinguishable from one that has crashed.

## 0.17.0 - custody in the window, and in the opening path

Added:
- A vault now asks its custodian for the component it holds when it is opened,
  so a component that is not on this machine still reaches the threshold.
  Verified: after handing a component over and deleting the local copy, the
  password alone opens the vault, because the custodian supplies the second
  part.
- A Remote custody panel in Key protection: establish custody, see whether the
  custodian is reachable and how long it will hold, and check in.
- `Session::establish_custody`, `custody_status` and `custodian_check_in`.

Fixed while testing, and the more interesting of the two:
- An expired custodian aborted the open even when the local token still
  reached the threshold, so a vault that was perfectly openable reported that
  its component had been destroyed. Expiry is now remembered and only reported
  if the vault genuinely did not open. Telling somebody their vault is lost
  when it is not would be worse than any failure this reports.
- The guard requiring a token before opening a split vault fired before the
  custodian was ever consulted. A custodian is a component too.

An unreachable custodian is not an error. A vault whose remaining components
still add up must still open, so a custodian that is simply not mounted today
is reported and stepped over.

## 0.16.0 - custodian enrollment, and a progress bar

Added:
- `zt split custody` and `zt split checkin`. A custodian is handed one key
  component and a timeout; it returns that component only while check-ins keep
  arriving and destroys it when they stop.

  Verified end to end: a check-in with the password succeeds and moves the
  deadline, and one with the wrong password is refused.

  It hands over the component *key* rather than the sealed share. Withholding
  the key is what puts the share out of reach, and it means the bundle can stay
  where it is.

- Adding a file now runs on a background thread and shows a progress bar with
  bytes done and total.

  Importing a large file takes minutes, during which a window that has stopped
  painting is indistinguishable from one that has crashed. The work moved off
  the painting thread, and the window requests a repaint while it runs so the
  bar moves without the mouse having to.

Note on spelling: new commands use `enroll` and `enrollment`. `zt split enroll`
still works, because breaking a command someone has in a script to change a
letter is not a fair trade.

## 0.15.0 - password strength, failed attempts, and a refusal

Added:
- A length floor of 15 characters for new passwords, with a dash-separated
  phrase encouraged rather than a symbol-and-digit rule demanded. Complexity
  rules produce `P@ssw0rd!`, which is worse than four unrelated words and
  harder to remember. Applied when a password is chosen, never when one is
  used, so an existing vault still opens.
- Failed attempts are counted from the audit log, so clearing the count means
  editing a hash chain that `zt audit verify` then reports.
- Escalating delays after repeated failures: nothing after the first, then
  four seconds, sixteen, a minute, capped at five. Unnoticeable once, unusable
  as an attack, and it costs nothing when it fires on a genuine mistake.

Not added as asked, and here is why:

Destroying a vault after three wrong passwords is a weapon pointed at its
owner. Anyone with a minute at the keyboard triggers it by typing nonsense: no
password knowledge, no key component, irreversible. A hostile colleague, a
curious child, or an afternoon with caps lock all reach three. It also buys
little, because a serious attacker copies the vault and attacks it offline
where no counter of ours exists, and the only attacker it does stop is one
guessing by hand at the keyboard, which the delays above already defeat. The
specification says the same thing at section 30.

So it exists as `destroy_after_failures`, off by default, and a limit below
three is refused outright because a typo reaches two on an ordinary day.

Fixed while building this:
- The new policy field was added to the structure but not to the code that
  writes and reads the policy file, in three separate places. It saved as
  absent and loaded as zero, so an opted-in limit would have silently never
  fired. Caught by the test for exactly that.
- The command line created vaults without checking the password floor, because
  it calls the vault directly rather than through the session. A rule enforced
  in one of two front ends is not enforced.

## 0.13.0 - other vaults, and evidence of a stopped watcher

Added:
- An "Other vaults" list in the sidebar. Every remembered vault, summarized
  without opening any of them: destroyed, not being watched, watcher was
  interrupted, or time remaining. Clicking one switches to it.

  Deliberately status only, and deliberately not several vaults open at once.
  Destruction is irreversible and every vault on screen is another chance to
  act on the wrong one. What this fixes is the opposite problem: a watcher that
  stopped on a vault you are not looking at was invisible until you happened to
  open it.

  The remembered list holds paths and nothing else. The file is unencrypted, so
  it must not describe a vault beyond saying one exists at a path.

- Watcher lifecycle is now recorded in the audit log: WATCH_STARTED,
  WATCH_STOPPED, and WATCH_INTERRUPTED when a watcher stopped without shutting
  down. The next start reports how long the vault was unwatched, and the window
  says so on the Deadman section.

  This is detection, not prevention, and is described as such. Nobody can stop
  a process being ended on a machine somebody else controls. What they cannot
  do is end it quietly: erasing the record would break the audit chain, which
  `zt audit verify` then reports.

Documented:
- A guide topic and a manual section stating plainly that key protection, not
  the deadline, is what defends a vault against somebody at your computer.
  Stopping the watcher buys an attacker unlimited time, and against a split key
  unlimited time is worth nothing: they hold one piece and need two.

  The deadman switch is for you not coming back, which is a different threat
  and the one it actually solves.

## 0.12.8 - a vault was declared destroyed the moment it was named

Fixed a regression introduced in 0.12.7. The check added there was:

    status.terminal || !vault.exists()

A vault that has been named in a save dialog but not yet created is also
absent, so "not created yet" and "destroyed" were the same condition. Choosing
a filename made the window announce that the vault had been destroyed.

Destruction is now judged only by the journal recording a terminal state, never
by the container being missing. That is the authoritative record, it is written
by the destruction itself, and it survives a restart.

Also fixed, the same confusion one step along:
- A journal is left behind deliberately when a vault is destroyed, because it
  is the record of what happened. Creating a new vault with the same name would
  have inherited that record and been reported as destroyed before it had been
  used. The journal is now matched against the vault identifier in the header,
  so a leftover journal from a different vault at the same path is disregarded.

Two tests were added for exactly these: an uncreated vault is not terminal, and
a new vault created where a destroyed one used to be is not terminal either.

The lesson is that absence is not evidence. A missing file can mean not yet, or
gone, or moved, and only a record written at the time can distinguish them.

## 0.12.7 - the window kept displaying a destroyed vault

Reported: after the deadman switch destroyed a vault, the Vault, Key protection
and Deadman sections still showed its contents, its protection and its policy.

Three separate causes.

- The window only cleared its state when it had done the destroying itself. A
  vault destroyed by the background service is a different process, so nothing
  told the window. It now detects a terminal state or a missing container while
  polling and clears the contents, protection, tokens and policy.
- Destruction left the split bundle behind, so Key protection went on reporting
  "2 of 3" for a vault that no longer existed. The bundle holds sealed shares of
  that vault's release key: it is key material and now goes with the container.
- Those three panes showed empty panels rather than saying what had happened.
  An empty panel is ambiguous; it could mean a vault with nothing in it. They
  now say the vault was destroyed, that no password or token will open it, and
  that copies made earlier are unaffected.

Also fixed, found while testing the above:
- `zt deadman checkin`, `zt auth list` and `zt panic destroy` ignored `--token`,
  so on a split-protected vault they could not open it at all. Checking in from
  the command line has been impossible on a protected vault since split-key
  protection was added, and failed quietly enough that earlier test runs
  discarded the error.

## 0.12.6 - explaining "ambient signals"

The deadman pane said a confidence below 60 would let "ambient signals alone
satisfy the policy". That is a term invented for this project and defined
nowhere a user would look, in a sentence explaining a limit they cannot change.

Replaced with what it actually means: only entering your password scores 100,
and signs that the computer is merely switched on, connected or being typed at
cannot total more than 60 between them, because a burglar sitting at your desk
produces all of them.

The same explanation is now in the in-app guide, and both manuals have an
"Ambient signals" glossary entry cross-referenced from "Presence score".

The lesson is the same one as the stale help text: jargon that is obvious to
whoever wrote the scoring is opaque to whoever reads the setting.

## 0.12.5 - making the arming gate visible

Reported: a deadline passed in the window and nothing was destroyed. The status
line said the vault would only reach ARMED.

That was the watch-only service behaving as designed, but the design was
hiding the way forward. "Start and arm" is locked until a dry run has been
read, and the only explanation was hover text on a grayed-out button. A
disabled control whose reason is invisible is a wall, not a safeguard.

Changed:
- The lock is now stated in the panel, in amber, with a "Run dry run now"
  button beside it that performs the dry run and switches to it. Reading it
  unlocks arming.
- A running watch-only service now says what it will do at the deadline:
  report ARMED and stop there, destroying nothing.
- Its status reads WATCHING ONLY, WILL NEVER DESTROY rather than the softer
  WATCHING, WILL NOT DESTROY.
- The message shown after pressing "Start watching" no longer claims the
  service stops at ARMED, which stopped being true in 0.12.4, and now names
  the button to use instead.

The gate itself is kept. Arming a mechanism that erases a vault should take a
deliberate second step; the fault was in hiding where that step was.

## 0.12.4 - an unarmed service gave up at the deadline

Fixed:
- A service started without `--allow-destruction` treated reaching ARMED as an
  end state. It printed a notice, exited, and released its watch lock. From
  that moment the vault was not being watched at all: checking in returned it
  to NORMAL with nothing following the countdown any more, so the deadline
  could never be reached again.

  Reported from testing: a one hour deadline passed, nothing happened, and a
  check-in restored the vault. The check-in was correct behavior, since
  destruction had not been authorized, but the silence afterwards was not.

- An unarmed service now keeps watching. The notice is printed once on entering
  ARMED rather than every interval, and is reset when the state leaves ARMED so
  a later expiry is announced again.

Verified: the service reaches ARMED, prints the notice exactly once, keeps its
lock, and follows a check-in back to NORMAL. The armed path was tested
separately and destroys correctly, which is what narrowed this to the unarmed
one.

Both manuals now say plainly that watching without `--allow-destruction` will
never destroy anything, however long you wait.

## 0.12.3 - a prompt could answer itself

Fixed:
- Creating a vault sometimes appeared not to ask for a password. Confirming the
  native save-file dialog with the Enter key left that keypress queued, and it
  arrived a frame later just as the password prompt appeared. A single-line
  text field surrenders focus on Enter, so the submit condition
  (`lost_focus() && key_pressed(Enter)`) was satisfied immediately and the
  prompt answered itself with an empty password.

  Confirming the file dialog with the mouse leaves nothing queued, which is why
  a second attempt always worked.

- Enter is now honoured only after the prompt has been visible for a few
  frames, and only with something in the field. Both guards exist for the same
  reason: a keypress left over from another window must not answer a question
  the person has not yet seen.

- Pressing Continue with an empty password now says so inside the prompt
  instead of failing further down.

- Errors raised inside a prompt are shown inside it, rather than in the status
  bar behind it where a modal hides them.

This was invisible to testing here because the virtual display cannot drive a
native file dialog, and the leaked keypress only exists because one was
involved.

## 0.12.2 - README rewritten

The README had drifted badly. It claimed both "v0.4 implements destruction" and
"nothing in this release can delete, erase or destroy a vault", was headed
"What v0.7 does" at version 0.12.1, said the binary was `target/release/zt`
when there are three programs, and listed cryptographic erasure in its
capability table twice with opposite answers.

Every one of those came from patching the file with a text substitution at each
release instead of rereading it. That is exactly the failure the stale `--help`
text showed at 0.11.1, in the most public file in the project.

Rewritten from scratch against the current build. The capability table is now
copied from what `zt security audit` prints, so the two can be compared rather
than assumed to agree.

## 0.12.1 - Windows build warning

Fixed:
- `home()` in the autostart module was dead code on Windows, which reads
  APPDATA directly and never calls it. Now scoped to the platforms that use it,
  and its unreachable USERPROFILE fallback removed since it can no longer be
  compiled for Windows.

This is the third Windows-only problem to reach a release, after the Wayland
dependency and the HANDLE type error. All three shared a cause: platform code
written where it cannot be compiled. The three remaining files containing
`cfg` branches have now been audited for the same shape, and this was the only
other instance.

## 0.12.0 - restart at login, without elevated privileges

Added:
- `zerotrace-platform::autostart`, and a "Restart at login" panel in the
  Deadman section. Install watch-only, install armed, or remove.

The earlier position, that installing a service needs privileges a vault
program should not hold, was right about the system-wide case and wrong as a
general claim. Per-user startup locations need no elevation at all: the
Startup folder on Windows, `~/Library/LaunchAgents` on macOS, the XDG autostart
directory on Linux. The generator in `service` already produced a systemd
*user* unit while the documentation said otherwise.

The usability argument settles it. A deadman switch that only survives a reboot
if you can write a systemd unit is a feature for people who do not need the
help, and the person most likely to rely on this is the least likely to open a
terminal.

Design notes:
- Arming an autostart entry is gated on having read a dry run, the same as
  arming the running service.
- Each vault gets its own entry, so autostarting one does not silently replace
  another.
- Whether an entry can destroy is read back from the file rather than
  remembered, so an entry edited by hand is reported as it actually is.
- The panel states that "at login" means this account logging in, and that a
  computer sitting at its login screen is watching nothing. That is not a hole
  in the deadline, since elapsed time comes from timestamps, but it is not the
  same as always-on and should not be implied to be.
- The system-wide `zt service unit` path remains for machines that should watch
  a vault whether or not anybody logs in.

## 0.11.2 - Windows build fix, and removing the reason it broke

Fixed:
- `zerotrace-platform` did not compile on Windows. A `HANDLE` in `windows-sys`
  is an integer, not a pointer, so calling `is_null()` on it is a type error.
  Written without a Windows compiler to check it, and shipped unverified.

Changed, to stop this recurring:
- Watcher liveness no longer asks the operating system whether a process id
  exists. A watcher refreshes a timestamp in its own lock file on every tick,
  and a lock that has stopped moving belongs to a watcher that has gone.

This removes the last platform-specific code in the crate, so
`forbid(unsafe_code)` is back and there is nothing left there that cannot be
tested on the machine it was written on. Seventeen of the eighteen crates now
forbid unsafe entirely; the exception is `zerotrace-secure-memory`, whose two
FFI calls genuinely need it.

It is also a better test, not merely a more portable one. A process id can be
recycled, making a dead watcher look alive. A process that is alive but wedged
looks healthy while watching nothing. A heartbeat catches both, and the old
check caught neither.

The staleness limit is three intervals plus thirty seconds, so an ordinary slow
tick or a briefly suspended machine does not make a healthy watcher look dead.

Verified end to end: the timestamp advances while a watcher runs, a second
watcher is refused while the first is live, and once the timestamp stops moving
the lock is reported stale and the next watcher takes over with a note saying
so.

## 0.11.1 - user manuals

Added:
- `docs/manuals/GUI-MANUAL.txt` and `docs/manuals/CLI-MANUAL.txt`. Plain text,
  written for somebody with no background in encryption, each with its own
  glossary so neither depends on the other.

Both are version-stamped, because a manual describing an older build is worse
than none: people trust it. They should be updated alongside any change to the
interface or the command surface.

Fixed while writing them:
- `zt --help` still claimed "The deadman mechanism is NOT IMPLEMENTED in v0.1.
  No command in this build can destroy a vault." That has been false since
  0.4.0 and was the most dangerous kind of stale documentation: it told a
  reader a destructive feature was absent.
- The note about split-protected vaults had been inserted into the middle of
  the vault command list, splitting it in two.

Every command example in the CLI manual was run before publication.

## 0.11.0 - starting and stopping the service from the window

Added:
- `zerotrace-platform::watch`: a per-vault watch lock recorded beside the vault
  it watches, so every vault is tracked independently and nothing can act on
  the wrong one.
- The service registers itself on start and refuses to start a second watcher
  for a vault that already has a live one, which would race on the same journal
  and be invisible to anyone trying to stop the first.
- The Deadman section shows the truth: WATCHING, WILL NOT DESTROY or ENFORCED,
  CAN DESTROY, with the process id and check interval, and a Stop watching
  button. It previously said CONFIGURED, NOT ENFORCED whether or not a service
  was running.
- Start watching, and Start and arm. Arming is disabled until a dry run has
  been read, as the specification requires.

Stopping is a request, not a signal. The window writes a small file and the
service notices it within a second, releases its own lock and exits. Killing
the process would need different APIs per platform, could strand a lock file,
and could interrupt a destruction midway.

A lock whose process is gone is reported as stale rather than running, so a
crashed service cannot leave a vault looking watched when it is not, and the
window offers to clear it.

Also fixed:
- `process_exists(0)` returned true on Unix, because `kill(0, ...)` addresses
  the caller's own process group. A lock claiming process zero would have
  looked alive for ever.
- Durations under a minute rendered as "0m".

Stated plainly in the window: starting from here survives closing the window
but not a logout or restart. For a deadline you rely on, install a service
definition with `zt service unit`.

## 0.10.4 - saying that the window does not enforce the policy

Added:
- The Deadman section now shows CONFIGURED, NOT ENFORCED whenever a policy is
  enabled, with the exact service command and a button to copy it.
- A guide topic, "Turning the deadman switch on for real".

Why this was needed: a person could configure a policy, watch a countdown, and
have nothing whatsoever enforcing it. Believing you are protected when you are
not is the worst failure this product can produce, and the window said nothing.

Why the window still does not start the service itself:
- Enabling a policy and arming a destroyer are different decisions. A checkbox
  should not be able to start a process authorized to erase files, and the
  specification requires a dry run before arming.
- A process started by the window would die with the window or at logout,
  leaving a deadman switch that had quietly stopped watching. Surviving a
  restart means the operating system's service manager, which is what
  `zt service unit` generates a definition for.

The guidance names the safe order: dry run, then the service without
permission to destroy so it can be watched reaching ARMED and stopping, then
the permission.

## 0.10.3 - a one-hour deadman switch was impossible to configure

Fixed:
- The heartbeat list started at one hour, and the heartbeat must be strictly
  shorter than the timeout. Choosing the shortest timeout the core allows, one
  hour, therefore left the heartbeat menu empty and the policy unsaveable, with
  nothing on screen explaining why.
- The list now runs from five minutes, so every timeout the core accepts has
  intervals that fit under it.
- If a filtered list ever comes out empty, the menu says so instead of showing
  nothing, and the automatic correction falls back to half the timeout rather
  than leaving a pair that can never be saved.
- Durations under an hour rendered as "0h 30m" in both the window and the
  command line. They now render as "30m".

The lists were introduced to stop invalid combinations being assembled. They
did, and then quietly excluded a valid one: constraining the offered choices
only helps if the constraint leaves every legitimate configuration reachable.

## 0.10.2 - stale state when switching vaults, properly this time

Fixed:
- Creating a vault after using another kept the previous vault's deadman
  policy on screen, and the guard that stops a background refresh overwriting
  an edit in progress then prevented the new vault's own settings from ever
  loading.

The cause was structural rather than a single missed line. Two separate reset
paths had grown, one for opening a vault and one for creating one, and they had
drifted: opening forgot the split status, creating forgot the policy, the draft,
the report and the dry run. Patching the second of them last time is what
allowed this.

There is now one `clear_vault_state` that forgets everything belonging to the
previous vault, used by both paths. Anything added to the per-vault state
belongs in it. Destroying a vault clears the same state rather than leaving the
old policy and split status attached to a container that no longer exists.

Also:
- The deadman settings gray out until Enabled is ticked, which was correct but
  looked like the controls were stuck. The pane now says so, and adds that
  while it is off nothing can destroy the vault on a timer.

Policies were always stored per vault on disk and still are; this was only the
window holding on to the previous one.

## 0.10.1 - three fixes from testing

Fixed:
- **Creating a vault asked for a key token.** The prompt decided whether
  components were needed from the split status of the vault that happened to be
  selected before, which was still in hand. Creating a vault has nothing to
  open, so it never needs a component, and pointing the window at a different
  vault now clears the previous one's status, summary, contents and tokens
  rather than inheriting them.
- The component prompt said "and so cannot destroy it" on prompts that were not
  destroying anything. The wording now matches the action.

Changed:
- Guide moved below the working sections and the window opens on Vault again.
- Timeout, heartbeat and required confidence are chosen from lists instead of
  typed. A free number field invites combinations the core will refuse and says
  nothing about what a sensible value looks like. Heartbeat offers only
  intervals shorter than the selected timeout, so an unsatisfiable policy
  cannot be assembled from the lists at all, and shortening the timeout pulls
  the heartbeat back rather than leaving an invalid pair on screen.

## 0.10.0 - an in-application guide

Added:
- A Guide section, and the window now opens on it. Twelve topics in plain
  words: what the program does, creating a vault, adding and extracting files,
  why a password alone may not be enough, setting up key protection, where to
  keep the two tokens, opening a protected vault, checking in and what the
  deadman settings mean, destroying a vault on purpose, what Records is for,
  what the program cannot do, and a suggested first hour.

The text lives in `guide.rs` as data rather than inline layout, so it can be
read and edited without touching any interface code.

Two things it does deliberately. The limitations get a topic of their own and
are stated as plainly as the features, because someone deciding what to trust
this with needs both. And the suggested first hour tells the reader to practice
on a vault they do not care about, including deliberately failing to open it,
before making a real one.

## 0.9.9 - audit of first-failure-aborts-everything

The token bug in 0.9.8 was one instance of a pattern, not a one-off: `?` on
user-supplied input inside a loop, so one bad element abandons the whole set.
Four sites were found and fixed.

- **Audit log reading.** A single damaged line made the entire history
  unreadable and made `verify` return an I/O error rather than tamper
  evidence. Reading now stops at the bad line, keeps everything before it, and
  `verify` reports a break naming the line. Silently returning the good prefix
  would have been worse than either, since a prefix of a valid chain is itself
  valid and the damage would have looked like a clean short log.
- **State journal reading.** The same fix. It matters more here: failing to
  load is indistinguishable from a missing journal, which could leave an
  interrupted destruction unresumed.
- **CLI import.** One unreadable file abandoned the rest of the batch.
  Failures are now reported per file and the exit status reflects them.
- **CLI export and the window's Extract all.** A damaged entry stopped every
  later entry from being recovered. During a recovery, getting back everything
  still intact is the whole job.

Verified from the command line: importing three files where the middle one
does not exist imports the other two and reports the skip; a damaged audit line
is reported as a break at that line while the readable history still displays.

## 0.9.8 - a wrong file no longer blocks the right one

Fixed:
- Attaching a file that was not a token left it in the session list, and every
  later attempt failed even once a valid token was added beside it. One
  unreadable path was aborting the whole open, so a single mistake made the
  vault unopenable until the application was restarted.
- A file that cannot be read or decoded is now skipped, contributing nothing,
  exactly like a component that was never supplied. That matches how a wrong
  component key already behaved and keeps the two indistinguishable.
- Files are validated when they are chosen, so a mistake is reported at the
  moment it is made rather than as a failure several steps later. The error
  appears inside the prompt rather than in the status bar behind it.
- Attached components can be cleared, in the prompt and in the Key protection
  pane.

Tested: junk alongside a real token, in either order, and a path that does not
exist at all. None of them prevent a valid token from working.

## 0.9.7 - the window stopped carrying a key component silently

Fixed:
- After enrolling split protection, the window kept the freshly written token
  attached to the session. A later Panic destroy then succeeded while the
  person believed they had supplied nothing but a password, which is the
  opposite of what a destructive prompt should feel like.
- The token is no longer retained after enrollment. Attaching it again also
  proves the file just written is readable and correct, which is worth doing
  immediately rather than discovering later.
- When a component *is* carried over, a destructive prompt now says so in the
  alert color: "This component is already attached and will authorize the
  destruction." A component that authorizes something irreversible must never
  be invisible at the moment it does so.

Not affected: the enforcement itself. A session holding no components cannot
destroy a split-protected vault, and could not before this change either. Two
tests now assert it, which they should have from the start.

## 0.9.6 - the destroy dialog asks for what it needs

Fixed:
- On a split-protected vault, Panic destroy collected only a password and the
  confirmation word, then failed afterwards because no key component had been
  attached. The requirement was enforced, which was correct, but the dialog
  never asked, which was not.
- The dialog now shows which components are required, attaches a token file
  directly, and keeps Destroy permanently disabled until enough are present.
  An irreversible action should not be reachable in a state where it can only
  fail.
- The dialog also states why: destroying needs the same components as opening,
  so nobody who cannot read a vault can destroy it either.

The same collection appears on every prompt for a split-protected vault, not
only destruction, so an unlock or a check-in no longer fails after the fact
either.

## 0.9.5 - the heartbeat means something, and the window explains itself

Fixed:
- **The heartbeat setting was validated and then ignored.** It had to be
  shorter than the timeout, and nothing used it: a documentation field wearing
  the costume of a control. Presence scoring now derives from the policy, so a
  check-in counts at full value for the heartbeat interval and then falls
  steadily to nothing at the timeout. A shorter heartbeat now genuinely means
  stricter presence, which is what the name always promised.
- The flat region matters on its own: a user who checks in on schedule sees a
  steady reading rather than a number sliding downwards from the moment they
  finish.

Added:
- An explanation at the head of every pane, and hover text on Check in, Unlock
  and Verify. A row of buttons whose effects a person has to guess at is worse
  than one fewer feature.

Confirmed rather than changed:
- Panic destroy already requires the same key components as opening, because
  it goes through the same split-aware path. Someone who cannot read a vault
  cannot destroy it either, which is the right asymmetry: a phished password
  should not enable sabotage.

## 0.9.4 - window layout

Changed:
- The window is now a sidebar and a single content pane rather than two
  columns of stacked cards. The previous layout put a nearly empty Vault panel
  beside a dense Key protection panel, left ragged gaps down both columns, and
  pushed half the application below the fold. Sections need different amounts
  of room, which a shared grid cannot give them.
- State, countdown, presence and the primary actions moved to the sidebar.
  They are what a person opens the window to see, and should not depend on
  which section is selected.
- Each nav entry carries a one-line summary, so the sidebar answers most
  questions without a click: entry count, split threshold, whether the policy
  is enabled, whether the chains verify.
- Content is constrained to a measured column. A label-and-value row stretched
  across a wide window reads badly.
- Cards fill their column instead of shrinking to content, so a sparse card is
  no longer narrower than a dense one below it.
- Card headings that merely repeated the pane title were removed.
- Scroll areas inside panes were enlarged now that they are not competing for
  vertical space.

## 0.9.3 - split-key protection in the window

Added:
- `Session::split_status`, `Session::enroll_split`, `Session::with_tokens` and
  `Session::without_password` in `zerotrace-ipc`
- A Key protection card in the desktop window: threshold, components, whether
  drive theft is resisted, whether losing one component is survivable, and
  every caveat the assessment produces
- Enrollment from the window, writing both tokens through file dialogs
- Add token, and a "Password lost" toggle for opening with two tokens

Notable:
- Every vault open in the IPC layer now goes through one split-aware helper, so
  a caller cannot bypass the split path by forgetting it exists. The public
  method signatures did not change, so nothing that used the boundary before
  needs updating.
- The window shows the warnings, not only the reassurances: no machine
  component, keep the token off the drive, and two tokens together open the
  vault without the password.

## 0.9.2 - a third component, and real redundancy

Added:
- `ComponentKind::Custodian`: a share held by a second party or in a second
  place. Three components with a threshold of two means no single loss destroys
  the vault.
- `zt split enroll` writes two tokens by default. Enrolling without redundancy
  now requires `--no-custodian`.
- Opening accepts `--token` more than once, and `--no-password` for the case
  the password is the thing that was lost. A token file may be either share;
  both slots are tried, and the one that does not match yields nothing, which
  is indistinguishable from an absent component by design.

Why this before rollback detection: two components with a threshold of two had
no redundancy at all, so losing one token destroyed the vault permanently. That
is a risk that materialises on an ordinary day, unlike the burglary the split
defends against.

The trade-off is reported, not buried: any two components open the vault, so
two tokens held together are full access without the password. `zt split
status` says so.

## 0.9.1 - split-key enrollment and opening

Added:
- `Vault::enroll_split` and `Vault::open_with_components`
- `flags::SPLIT_PROTECTED`, inside the authenticated header region
- CLI: `zt split enroll <vault> <token-file>`, and `--token` on every command
  that opens a vault

Enrollment rewrites only the 48-byte wrapped key. The master key is unchanged,
so no stored content is re-encrypted however large the vault; a test asserts
the chunk region is byte-identical before and after.

The split flag is authenticated, so clearing it does not restore the password
path, and a test flips it to confirm. The bundle is written before the header
is updated: an orphaned bundle is harmless, while a split-protected header with
no bundle would be an unopenable vault.

Verified end to end from the command line: an attacker with the vault, the
split bundle and the correct password is refused; the owner with the token
opens it.

## 0.9.0 - split-key architecture

Added:
- `zerotrace-split`: the release key is divided with Shamir sharing across
  independent components, each share sealed under its component's key with the
  vault's existing AEAD. Any two open it.
- CLI: `zt split status`, `zt split explain`
- `SPLIT_KEY.md`: the threat model, the component analysis, and what is not
  solved.

Threshold is two of three, not three of three. Three of three means any single
loss is permanent data loss, which for a vault of irreplaceable material is a
larger risk than the attack it prevents. The trade-off is documented rather
than hidden.

Components: user (implemented), machine via TPM (NOT IMPLEMENTED), remote as an
offline token on separate media (implemented) or an authorization service (NOT
IMPLEMENTED).

The master-key hierarchy is unchanged. The release key replaces what the
password-derived KEK used to be; everything below it is untouched, and no new
cryptographic primitive was introduced.

Stated plainly in the docs and in `zt split explain`:
- Before this, the deadman switch did not survive drive theft at all, and still
  does not. The policy and journal are files the attacker controls.
- Rollback is not detected. That needs an anchor off the drive, which is what
  the TPM and service components would provide.
- `MachineProvider` fails rather than falling back to a key file, because a key
  file on the same disk travels with a stolen drive and would silently remove
  the protection the component exists to provide.

## 0.8.0 - memory locking

Added:
- `zerotrace-secure-memory::lock`: `mlock` on Unix, `VirtualLock` on Windows,
  applied to every secret allocation.

Changed:
- `SecretBytes<N>` is now heap allocated rather than inline. Locking works on
  pages, not objects: locking a stack-resident secret would lock the whole
  surrounding page and unlocking on drop would unlock it for every other live
  secret sharing it, while a moved value would leave its locked page behind.
  Boxing gives each secret a stable address, so a move relocates the pointer
  and not the bytes.
- The crate is `deny(unsafe_code)` rather than `forbid`, with the two FFI calls
  isolated in `lock.rs` and each `unsafe` block documented.
- `memory_protection_status` reports the observed outcome instead of a fixed
  string, and `probe_memory_protection` allocates one secret first so callers
  learn what the machine can do rather than "not attempted".

Honest limits, stated in the code and in the reports:
- Locking is reported as BEST EFFORT and never VERIFIED. It prevents swap and
  nothing else: hibernation writes all of RAM regardless, core dumps are
  unaffected unless separately disabled, and a hypervisor snapshot captures
  everything.
- A refusal, which is common because `RLIMIT_MEMLOCK` is often small, is
  recorded and reported as FAILED rather than treated as an error. Refusing to
  open a vault because the OS declined to lock 32 bytes would trade a real
  capability for a marginal one.
- Once anything has been refused, that stays the reported answer. A later
  success does not un-reach a secret that already went to swap.
- `SecureBuffer` locks the allocation it was built with. A `Vec` that grows
  reallocates, and the old allocation is freed without being locked or zeroed,
  so callers that will append should reserve capacity up front.

## 0.7.5 - remove a duplicated match arm

Fixed:
- `zerotrace-desktop` carried two identical `Pending::Export | Pending::ExportAll`
  arms, left behind when the export handler was moved into `run_pending`. The
  second was unreachable, so the build warned but behaved correctly. Removed.

The build is now warning-free.

## 0.7.4 - vault contents and extraction in the window

Fixed:
- **The window could not get files out of a vault.** `zerotrace-ipc` had an
  export command and the desktop front end never called it, so files could be
  added and never retrieved. There is now an Extract button per file and an
  Extract all button.
- The entry list was a 110-pixel scroll area buried inside the Vault card,
  which is not where anyone looks for the contents of a vault. It is now a
  full-width Contents panel showing each file's name, size and chunk count.

The locked state explains itself rather than appearing empty: filenames and
sizes live in the encrypted manifest, so nothing can be listed until the vault
is unlocked.

## 0.7.3 - policy editing in the window

Added:
- A Deadman policy panel in `zerotrace-desktop`. The timer could previously
  only be configured from the CLI, which meant the window could not set up the
  product's central feature.

Notes:
- Values are edited in hours; seconds are unreadable at this scale.
- The draft is kept separate from the saved policy, so a half-typed value is
  never written and background polling cannot overwrite an edit in progress.
- Validation is the core's, not the widget's. The panel shows what
  `DeadmanPolicy::validate` says before anything is written, and Save is
  disabled while the draft is invalid.
- Required confidence is clamped to 61 and above in the widget, matching the
  rule that ambient signals alone must never satisfy a policy.

## 0.7.2 - Windows build fix

Fixed:
- `zerotrace-desktop` declared Wayland crates and Linux display features as
  unconditional dependencies, so a Windows build tried to compile
  `wayland-sys`, which uses `std::os::unix`. They are now under
  `[target.'cfg(target_os = "linux")'.dependencies]`, and Windows and macOS use
  the platform's own dialogs and windowing.

These pins were added to work around an older toolchain during development and
should have been target-scoped from the start. The project had only ever been
built on Linux, so nothing caught it.

## 0.7.1 - a native desktop window

Added:
- `apps/zerotrace-desktop`: an egui/eframe window over `zerotrace-ipc`, in the
  workspace and buildable with the same toolchain as everything else.

Why: the Tauri front end could not be compiled or rendered during development,
so the security-critical application had the unverified GUI while the
compression tool had a verified one. This corrects that. It also removes Node
from the build entirely.

Two bugs found by running it that inspection would not have caught:
- The capability list collapsed to two rows. A nested scroll area with only a
  max height does not size itself inside a column.
- The password field re-requested focus every frame, and a single-line
  TextEdit consumes Enter, so the key press had to be read from the field's own
  response rather than global input state.

Not verified: keyboard entry. No synthetic key events reached the window under
the virtual display, so every password field is untested with real typing. The
submit path is exercised by clicking through with an empty field, which
produces the expected authentication error.

## 0.7.0 - Phase 7, enterprise (hardware deferred)

Added:
- `zerotrace-enterprise`: Ed25519-signed remote commands with replay
  resistance, and k-of-n threshold recovery via Shamir sharing
- CLI: `zt enterprise keygen`, `zt recovery explain`

Design decisions worth recording:
- **No signed command can weaken a vault.** Extending a deadline is refused
  however well signed. Someone holding the organization key could otherwise
  disarm every endpoint quietly, which is worse than destroying them loudly.
- **There is no command that reads vault contents.** The action set is Lock,
  RequireCheckIn, TightenPolicy and Destroy. The server must never be able to
  obtain plaintext, so no command exists that could return it.
- **Escrow does not survive a deadman event.** The specification asks for this
  to be answered explicitly. A quorum can reconstruct the key while a vault is
  merely locked; once destruction is authorized, recovery is refused, and the
  wrapped key has already been overwritten. A recovery mechanism that outlived
  the deadman switch would make it decorative.
- **A threshold of one is refused.** That is a spare key, not threshold
  recovery, and it reintroduces the single point of failure the scheme exists
  to remove.
- Shares are produced in memory and never written beside the vault. A share
  stored on the machine holding the vault protects nothing.

Deferred, not abandoned:
- FIDO2 transport, TPM and Secure Enclave binding. These need hardware to test
  against, and an untested authenticator can lock a user out of their own
  vault permanently.

## 0.6.0 - Phase 6, platform hardening

Added:
- `zerotrace-platform`: filesystem identification, filesystem-aware
  sanitization, and service-definition generation for systemd, launchd and
  Windows
- CLI: `zt platform report`, `zt service unit`

Changed, and this is the substantive part:
- Overwriting a file in place is now reported as **NOT SUPPORTED** on
  copy-on-write filesystems rather than BEST EFFORT, and is not attempted. On
  Btrfs, ZFS and APFS a write allocates new blocks and leaves the originals
  intact, so the operation achieves nothing while looking exactly like the case
  where it achieves something. Reporting it uniformly overstated the result on
  precisely the systems where it mattered most.
- The same applies to layered filesystems such as overlayfs, where a write
  lands in an upper layer rather than over the original blocks.
- Snapshot detection distinguishes three answers that were previously one:
  the filesystem has no snapshot facility, it has one but the tool to query it
  is absent, or the query is not implemented. None of them is "zero snapshots".

Notable:
- Generated service units never enable destruction by default. A unit that can
  destroy data has to be written deliberately, and the Windows script says so
  in words rather than only in a flag.
- The systemd unit is a user unit with `NoNewPrivileges`, `ProtectSystem` and
  a narrow `ReadWritePaths`. The service holds no vault keys, so it needs no
  elevated access.
- ZeroTrace does not install service definitions itself. Writing to a service
  directory needs privileges a vault application should not hold.
- Supervision status reports UNKNOWN when it cannot be determined, rather than
  claiming the service is unsupervised.

Still NOT IMPLEMENTED:
- Enumerating and removing snapshots. Removal is destructive to data outside
  the vault and should be an administrator's deliberate act.
- Free-space and device sanitization
- Hardware authentication
- The GUI remains source only and unverified

## 0.5.0 - Phase 5, GUI

Added:
- `zerotrace-ipc`: the typed command surface the GUI talks to. Tested.
- `apps/zerotrace-gui`: Tauri shell and TypeScript front end. **Source only,
  not built or verified.** See the caveat below.

Notable:
- No response type can carry key material, a password, or plaintext. A test
  formats a summary and asserts none of them appear.
- Policy changes from the GUI go through `DeadmanPolicy::validate`, so the
  window cannot weaken a vault (INV-8). Tested against three dangerous shapes.
- Destruction requires the exact string `DESTROY` plus the vault password.
  Five near-miss confirmations are tested and each leaves the vault intact.
- A GUI check-in now anchors the audit log in the state journal, which the
  first version failed to do. Caught by a test asserting truncation detection.

### Unverified

The GUI is source only. Tauri 2 needs a newer Rust toolchain than the
development environment had, and that environment has no working browser
engine, so neither the shell nor the front end was compiled or rendered.
Treat `apps/zerotrace-gui` as unverified until it builds on your machine. It is
excluded from the workspace, so the rest of the project is unaffected.

## 0.4.0 - Phase 4, destruction

Added:
- `zerotrace-sanitize`: platform sanitizer trait with a portable best-effort
  implementation, and STANDARD / ENHANCED / MAXIMUM profiles
- `zerotrace-destroy`: two-phase authorization, cryptographic erasure,
  resumption after interruption, dry run, and the destruction report
- `ztd`, a resident service that evaluates the policy on a timer, resumes an
  interrupted destruction, and refuses to destroy unless explicitly permitted
- Fault-injection tests: interruption after authorization, interruption midway
  through erasure, repeated execution, and terminal state across restarts

Notable:
- Destruction is off by default in the service. Without `--allow-destruction`
  it observes, records state, and stops at ARMED.
- A broken state journal refuses to authorize destruction rather than treating
  corruption as a trigger, which would be a denial of service.
- The service walks intermediate states one at a time rather than jumping to
  ARMED, so the journal always shows how a vault came to be armed.

Documented more precisely:
- A complete copy of a container taken before erasure carries its own wrapped
  key and still opens. Cryptographic erasure protects the bytes of this
  container, not copies made beforehand.

Still NOT IMPLEMENTED:
- OS service manager integration, so nothing restarts `ztd` if it dies
- Per-platform snapshot detection and removal
- Free-space and device sanitization
- Hardware authentication
- GUI

## 0.3.0 - Phase 3, presence and time

Added:
- `zerotrace-core::time`: wall-clock deadlines cross-checked against monotonic
  time, clock-anomaly detection
- `zerotrace-presence`: trust-levelled signals, decaying confidence, and a hard
  ceiling on what non-strong evidence can contribute
- `zerotrace-policy`: deadman configuration with safety floors
- `zerotrace-journal`: hash-chained persistent state journal that also anchors
  the audit log
- CLI: `zt deadman status|checkin|configure`, `zt journal verify`

Notable:
- Audit truncation is now detectable. The audit chain cannot see its own tail
  removed; the journal records how long it should be. This closes the gap
  documented as a known limitation in 0.2.
- The deadman policy is disabled by default and refuses timeouts under an hour,
  refuses a heartbeat longer than the timeout, and refuses a required
  confidence that ambient signals alone could satisfy.

Still NOT IMPLEMENTED:
- Any destruction. The state machine stops at ARMED.
- The watchdog as a supervised OS service.
- Hardware authentication.

## 0.2.0 - Phase 2, authentication

Added:
- `zerotrace-auth`: factor kinds, factor sets, multi-factor KEK composition
- AZV format version 2, with the required-factor set inside the authenticated
  header region. Version 1 vaults still open.
- `zerotrace-audit`: hash-chained tamper-evident log
- CLI: `zt auth list`, `zt audit show`, `zt audit verify`

Changed:
- The header AAD is now taken from the bytes as read rather than from a
  re-serialization of the parsed struct. Re-serializing normalized derived and
  reserved fields, which silently excluded them from authentication. Found by a
  test that flips every bit of the authenticated region.

Still NOT IMPLEMENTED:
- FIDO2 hardware transport. Composition is built and tested; creating a vault
  that requires FIDO2 is refused rather than producing an unopenable vault.
- Everything in Phases 3 onward.

## 0.1.0

First release. Security foundation only.

Added:
- AZV1 container format with an authenticated header prefix
- XChaCha20-Poly1305 and AES-256-GCM
- Argon2id with an enforced parameter floor and validation on open
- Zstandard compression with content classification and bounded decompression
- Chunked authenticated storage, counter nonces under per-file keys
- Encrypted manifest: filenames, paths, sizes and timestamps
- Merkle integrity root over all chunks
- Secure memory: zero on drop, redacted Debug, constant-time comparison
- Deadman state machine, defined and tested but not driven
- `zt` CLI: vault create, status, list, verify, import, export; security audit

Not included, and reported as NOT IMPLEMENTED rather than stubbed:
- Any destruction mechanism
- Presence engine, heartbeat, watchdog, service supervision
- FIDO2 and hardware authentication
- Filesystem sanitization
- GUI
