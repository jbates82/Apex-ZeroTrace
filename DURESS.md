# The duress password

## What it does

A second password that opens the vault into different contents, and destroys
the real ones as it does so. Silently. Somebody watching sees an ordinary vault
open onto ordinary files.

Both identities live in one container. There is no second file to notice.

## What it is for

Somebody standing over you who wants the vault opened. You open it. They see
what you chose for them to see, and the real contents are already gone.

## What it is not for

**Somebody who images the drive and examines it at leisure.** The container
does not shrink when duress fires, and the decoy block is present in every
vault whether used or not, so neither of those gives the game away. But the
real chunks remain in the file as unreadable bytes, and a decoy holding three
small files inside a five gigabyte container invites an obvious question.

Against that adversary this buys you the destruction, not the deception. That
is still worth having; it is just a different claim.

## Why the block is always there

Every format 3 vault carries a 256-byte block for a duress wrapping, filled
with random bytes when no duress password is set.

This is the design, not an implementation detail. If the block only appeared
once somebody enabled the feature, an adversary examining the file would know
to demand a second password, and a duress password known to exist protects
nobody. Random bytes and a real wrapping are indistinguishable without the
password that opens them, so the file cannot answer the question either way.

Nothing marks the slot as used. A test asserts that a vault with a duress
password and one without have blocks of comparable bit density and that neither
is zeroed.

## Where it fires

Everywhere a password is accepted: unlocking, extracting, verifying, checking
in. Every one of those goes through a single open, and the duress identity is
reached inside it.

Anything narrower would be a trap. Somebody reaching for Extract under pressure
would get no protection, which is worse than not having the feature, because
they would believe they did.

## How opening works

The real identity is tried first. Only when it fails is the duress wrapping
attempted, so an ordinary open never goes near this path and cannot trigger it.

A wrong password fails both and destroys nothing.

When the duress wrapping does open, the real wrapped key is overwritten and
read back to confirm, before the decoy contents are returned. Interrupting the
program mid-open still leaves the real key gone.

The decoy keeps working afterwards, every time. It has to: somebody watching
will ask again, and a vault that opened once and then refused would be an
obvious tell.

## Guards

**It must not resemble the real password.** Two passwords a keystroke apart
will be confused under stress, which is precisely when this would be used.

Refused, not merely warned about. A one or two character difference, or a
shared opening of eight characters or more, is rejected before anything is
written. The check lives in the vault rather than in a front end, because a
rule enforced in one of two front ends is not enforced: the first version put
it in the window only, and the command line walked straight past it.

**It needs something to show.** A duress password revealing an empty vault
invites the question of what else there is, so an empty decoy is refused.

**It is subject to the same length floor** as any other password.

**Setting it leaves nothing behind if it fails.** The decoy is built in a
scratch file, removed however the operation ends. A file called
`v.azv.decoy-build` sitting beside a vault would tell anybody who looked that a
duress password was being arranged.

**Decoy files must already exist.** Checked before anything is written, so a
mistyped path fails cleanly rather than partway through.

## What it costs

The real contents are gone. Not hidden, not archived, not recoverable by
anyone including you. Typing it by accident is the same as destroying the
vault.

That is the feature working. It is also the reason it is not on by default and
never will be.
