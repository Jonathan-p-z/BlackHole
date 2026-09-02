//! Fuzzes `blackhole-fingerprint::exposure::parse_report` — the boundary
//! that turns an arbitrary byte response from the third-party IP-info
//! service into findings. Bytes are not guaranteed to be valid JSON, or
//! even valid UTF-8 (a compromised or misbehaving service could return
//! anything); the goal is "never panics, never mis-scores", not "always
//! parses".
#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = blackhole_fingerprint::exposure::parse_report(data);
});
