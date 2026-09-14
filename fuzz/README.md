# Coverage-guided fuzzing

The targets here are for `cargo-fuzz`, which needs a nightly compiler. The
environment this project was developed in has stable Rust only, so **these
targets have never been run.** They are written from the documented interface
and should be treated as untested until they build on your machine.

What *has* run is `crates/zerotrace-ipc/tests/fuzz.rs`, a deterministic
mutation fuzzer that works on stable and is part of `cargo test`. It is weaker
than libFuzzer because it explores blindly rather than following coverage, but
it found a real bug on its first run: five parsers sliced a string by byte
index after checking its byte length, which panics on any multi-byte character.

Run these with a nightly toolchain:

```
cargo install cargo-fuzz
cargo +nightly fuzz run header
cargo +nightly fuzz run manifest
cargo +nightly fuzz run split_bundle
cargo +nightly fuzz run recovery_token
```

Anything that panics is a bug worth reporting. A parser handed arbitrary bytes
must return a value or an error, never panic, hang, or allocate on a length it
read out of the input.
