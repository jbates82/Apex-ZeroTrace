#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = zerotrace_format::manifest::Manifest::decode(data);
});
