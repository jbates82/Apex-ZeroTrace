# Remote custody

## The problem it solves

Everything else in ZeroTrace runs on the machine holding the vault. Somebody
who controls that machine can close the watcher, and no local trick changes
that. A hidden process shows up in the task list within a minute. Refusing to
close is beaten by End Task. Two processes restarting each other is how malware
persists, and antivirus will treat it that way. On their computer, they win.

A custodian is different, because it is not on their computer.

## How it works

The vault's key is already split three ways. One of those pieces goes to a
custodian, which hands it back only while you keep checking in. When the
check-ins stop, it destroys the piece.

So the deadline is enforced by **withholding**, not by destroying anything
locally. Whatever an attacker kills on your machine is beside the point: they
still need something the machine never had.

## The decision everything rests on

Check-in requests are signed with a key derived from your **password**, using
the same Argon2id the vault uses. That key exists for as long as it takes to
sign one request and is never stored.

This is the whole design. If the credential proving "the owner is still here"
lived on the machine, somebody holding the machine would simply keep checking
in, and the deadline would never arrive.

Because it does not:

- An attacker who has not cracked your password cannot check in.
- An attacker who cracks it *after* the deadline gains nothing, because the
  piece is already destroyed.

That second point is what makes this survive total local compromise. Killing
every local process buys unlimited time to attack the password, and unlimited
time is worth nothing once the custodian has expired.

## What a custodian can and cannot do

It holds **one piece** of three. Alone it opens nothing.

With a compromised password it could reach the threshold, which is the honest
cost of two-of-three. So a custodian should not be run by whoever knows your
password, and a custodian folder must not live on the machine holding the
vault. That is the same mistake as keeping a token beside the vault.

It cannot hand back something it has already destroyed. An expired record is
kept rather than deleted, so a later request is told the vault expired instead
of being told it is unknown.

## Where to put one

`DirectoryCustodian` keeps its records in a folder. What matters is where that
folder is, not how it is reached: another computer, a network share, a machine
somewhere else. A mounted share works today.

A network service would be the same logic behind a socket, and is not built. A
protocol nobody can exercise is worth less than one they can.

## What is enforced

| | |
| --- | --- |
| A forged check-in is refused, and does not move the deadline | VERIFIED |
| The piece is destroyed when the deadline passes | VERIFIED |
| An expired record never returns, even to the right password | VERIFIED |
| A captured request cannot be replayed | VERIFIED |
| A stale or future-dated request is refused | VERIFIED |
| A vault cannot be re-enrolled over an existing record | VERIFIED |
| The record holds no password | VERIFIED |
| A custodian supplies its piece when the vault is opened | VERIFIED |
| An unreachable custodian does not block a vault that can open without it | VERIFIED |
| Network transport | NOT IMPLEMENTED |
