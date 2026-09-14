# Split-key architecture

## The attack

1. An attacker obtains the physical storage device.
2. They remove it from the original computer.
3. They connect it to another machine.
4. They copy the vault.
5. They attempt to open it, with our implementation or their own.
6. They modify, delete or replace the policy and journal files.
7. They roll the vault back to an earlier security state.
8. They replay previously valid authorization.
9. They wait out the deadman switch while the original machine is offline.

## What was true before this work

Steps 6 through 9 all succeed, completely.

The policy and journal are ordinary files beside the vault. An attacker
holding the drive deletes them, never runs our code, and no deadline ever
arrives. Cryptographic erasure only fires if `ztd` is running on the original
machine, which by assumption it is not.

So against a removed drive the vault was protected by its password alone, and a
password is guessable offline for as long as the attacker likes. This was not
hardening a working defense. It was building the first one.

## The model

The key that unwraps the master key, called the release key, is split with
Shamir sharing. Each share is sealed with AEAD under a different component key.
Any two shares reconstruct the release key.

| Component | Secret | On a stolen drive? | Status |
| --- | --- | --- | --- |
| user | password, plus FIDO2 PRF when enrolled | no, it is in the owner's head | implemented |
| machine | key sealed by a TPM or Secure Enclave | no, it stays in the chip | NOT IMPLEMENTED |
| remote | authorization service, or an offline token on separate media | only if the owner stores it there | token implemented, service not |
| custodian | a share held by a second party or in a second place | only if the owner stores it there | implemented |

The drive holds every share *ciphertext*. Copying them gains nothing: opening
two requires two independent secrets, and at least one is deliberately not on
the drive.

The existing master-key hierarchy is untouched. The release key replaces what
the password-derived KEK used to be, and everything below it, the wrapped
master key, the metadata and file subkeys, the manifest and chunk formats, is
unchanged. No new cryptographic primitive was introduced: Shamir sharing comes
from the `sharks` crate, and the sealing uses the AEAD the vault already uses.

## Why two of three

Three of three sounds stronger and is worse.

It means any single loss is permanent data loss. A dead motherboard destroys
the machine share. A discontinued service destroys the remote share. A
forgotten password destroys the user share. For a vault holding things a person
cannot afford to lose, that availability profile is a larger risk than the
attack it prevents, and it is the kind of risk that materialises on an ordinary
Tuesday rather than during a burglary.

Two of three still defeats drive theft. An attacker with the disk and the
password holds one component and needs two. It survives losing any one
component.

The cost, stated rather than buried: a compromised remote component combined
with a compromised password opens the vault without the machine. The recovery
token is a real credential and must be treated as one.

## Analysis against the required scenarios

**Availability.** Two of three tolerates one loss. Two components enrolled with
a threshold of two does not, and `zt split status` says `PERMANENT DATA LOSS`
rather than leaving the owner to work it out.

**Password compromise.** One component. Not sufficient.

**Machine compromise.** One component. An attacker who owns the running machine
has other routes to plaintext while the vault is unlocked, which no vault
design fixes.

**Remote-service compromise.** One component. Not sufficient alone, but see the
cost above.

**Physical theft of the drive.** The central case. Every share ciphertext is
copied, and the attacker is still short of the threshold.

**Hardware failure.** The machine share is lost; the other two still open the
vault.

**Disaster recovery and account recovery.** The recovery token on separate
media is the intended path. It must be stored somewhere the drive is not.

**Key rotation.** Re-sealing the release key under fresh component keys
re-splits without touching the master key or re-encrypting any content.

**Destruction behavior.** Unchanged. Cryptographic erasure overwrites the
wrapped master key, after which no quorum of components helps, because there is
nothing left to unwrap.

## What this does not solve

**Rollback.** An attacker who physically holds the drive can restore an older
copy of any file on it, including the split bundle, the policy and the journal.
Nothing in this build detects that. Detecting it needs an anchor the attacker
does not control: a monotonic counter in a TPM, or a remote service that
refuses to release its share for a state it has already superseded. This is the
main reason the machine and service components matter beyond key splitting.

**Replay of authorization.** The enterprise remote commands are already
replay-resistant through nonces and expiry, but that guards commands, not the
security state of a vault on a drive someone else is holding.

**The deadman switch under drive theft.** It does not survive, and cannot,
without an anchor off the drive. Split-key protection is what makes the stolen
copy useless. The deadman switch protects the machine you left running.

**The split bundle can be deleted.** It sits beside the vault, so an attacker
who holds the drive can destroy it and the owner loses access. That is denial
of service, not disclosure, and the answer is a backup of the bundle rather
than a change of design.

## Using it

```
zt split enroll  vault.azv /media/usb/token.txt /media/safe/custodian.txt
zt split status vault.azv

zt vault list vault.azv --token /media/usb/token.txt
zt vault list vault.azv --token /media/usb/token.txt --token /media/safe/custodian.txt --no-password
```

Three components with a threshold of two means no single loss destroys the
vault. All three recovery paths are exercised end to end: password with either
token, and both tokens with the password forgotten.

The cost of buying redundancy with a second token rather than a machine
component, stated by `zt split status` rather than left to be discovered: any
two components open the vault, so whoever holds both tokens opens it without
the password. Keep them in different places, or with different people.

Enrolling without a custodian requires `--no-custodian`, so a vault with no
redundancy is a deliberate choice rather than a default.

Every command that opens a split-protected vault needs `--token`. Enrollment
rewrites only the 48-byte wrapped key, so a vault of any size converts in the
time it takes to derive one key; nothing stored is re-encrypted. A test asserts
the chunk region is byte-identical before and after.

Verified end to end: an attacker holding a copy of the vault, the split bundle
and the correct password is refused. Deleting the bundle does not produce a
fallback to password-only opening, because the split flag is inside the
authenticated header region and the wrapped key is under the release key
regardless.

## Enrollment guidance

Enroll the user component and a recovery token, and put the token on separate
media: a USB key in a different place, or a second machine. A token stored
beside the vault is on the same drive an attacker steals and provides nothing.

Keep two copies of the token until a machine component exists, because two
enrolled components with a threshold of two has no redundancy.
