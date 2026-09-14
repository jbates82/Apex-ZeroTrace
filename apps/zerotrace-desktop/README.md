# zerotrace-desktop

The native desktop window, built with egui/eframe.

```
cargo run --release --bin zerotrace -- /path/to/vault.azv
```

The path argument is optional; the window can open or create a vault itself.

## Why egui

It builds with the same toolchain as everything else in the workspace, with no
separate front-end build step, and it was run and driven throughout
development. For a security tool, a front end somebody has actually executed is
worth more than a prettier one nobody has.

It also keeps Node out of the build entirely. A web-based front end would pull
hundreds of transitive packages into an application whose selling point is a
small auditable boundary, which sits badly next to a project where the manifest
parser is written by hand to avoid a derive macro.

The cost is real and worth stating: egui is not native, so the window does not
look or behave quite like the rest of your desktop, and its accessibility is
poor. Screen readers struggle with it. For a tool meant to be usable by anyone,
that is a genuine failing rather than a stylistic quibble.

## What was verified

Rendered under Xvfb and driven with synthetic clicks:

- Live data throughout: state, countdown, presence against its threshold,
  audit and journal chain status, activity log
- The capability table, generated from the core so it cannot claim more than
  the binary does
- Opening the check-in prompt, submitting it, and receiving a proper
  authentication error
- Canceling a prompt, which reports that nothing was changed
- The deadman policy panel, including its live validation message
- The sidebar and all six content panes, navigated by clicking
- The remote custody, key protection and destruction panels
- The destroyed-vault message, and that dismissing it returns the window to the
  state it opens in

## What was not verified here

**Keyboard entry, by automation.** No synthetic key events reached the
application under the virtual display, though pointer events did. Every
password field is therefore untested by the automated checks. It has since been
exercised by hand on Windows and works, but nothing in the test suite covers
it, so a regression would go unnoticed.

**The destroy dialog end to end, by automation.** It renders and is wired like
the others, and completing it needs the word `DESTROY` typed, which is the same
keyboard path the harness could not drive.

**Anything automated on Windows or macOS.** Development and rendering happened
on Linux. The Wayland and GTK dependencies are scoped to Linux so other
platforms do not try to compile them. Windows has been built and used by hand
throughout, which is how three Windows-only defects were found; macOS has not
been tried at all.

**Layout regressions.** Every visual check was a screenshot read by a person.
Nothing would catch a panel moving, overlapping, or falling off the bottom of
the window.

## Security notes

No cryptography, policy evaluation or destruction logic lives here. Every
action forwards to `zerotrace-ipc` and renders what comes back.

Passwords are held in a `String` while a prompt is open and cleared when the
operation completes. That is weaker than the core's `SecretBytes`, which zeroes
on drop, because egui needs an editable `String` to render a text field. Said
plainly here rather than left to be discovered.

Recovery tokens are held as paths, never as key material, and are dropped when
the window changes vault. A component that authorized something irreversible
should not be able to linger invisibly into an unrelated operation.
