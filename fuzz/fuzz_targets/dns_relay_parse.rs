//! Fuzzes `blackhole-dns`'s handling of a raw incoming UDP DNS datagram —
//! the exact untrusted-input boundary `Relay::serve_udp` feeds to
//! `hickory_proto::op::Message::from_vec`, plus everything the relay does
//! with a successfully-parsed query afterward (`Relay::build_response`).
//! Malformed bytes, truncated messages, and corrupted hickory-proto fields
//! are all in scope; the goal is "never panics", not "always parses".
//!
//! Deliberately calls `Message::from_vec` directly rather than
//! `Relay::safe_parse_message` (the `catch_unwind`-wrapped path the real
//! relay uses): `libfuzzer-sys` installs a panic hook that calls
//! `process::abort()` *before* unwinding starts specifically so that no
//! `catch_unwind` anywhere in the fuzzed binary can hide a panic from
//! libFuzzer's crash detection (see `libfuzzer_sys::fuzz_target!`'s own
//! source). So there is no way to fuzz "past" a known, still-reachable
//! panic from inside this harness — `safe_parse_message`'s fix is real
//! and effective for the actual shipped relay binary (pinned by
//! `relay::tests::malformed_tsig_record_does_not_panic_the_relay`, which
//! runs under a normal `cargo test`, not this harness), but this fuzz
//! target itself will keep re-finding the same upstream hickory-proto
//! TSIG panic (see `THREAT_MODEL.md`) until hickory-proto fixes it or a
//! local `[patch]` override is added.
#![no_main]

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use blackhole_dns::error::DnsError;
use blackhole_dns::relay::Relay;
use hickory_proto::op::Message;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let Ok(request) = Message::from_vec(data) else {
        return;
    };
    let Some(query) = request.queries.first() else {
        return;
    };

    // Exercise field accessors on an adversarial-but-successfully-parsed
    // query, same as `Relay::handle_datagram` does.
    let _ = query.name().to_string();
    let _ = query.query_type();

    // Both branches `build_response` can take, same as the real relay
    // takes depending on whether the upstream resolve succeeded.
    let err: Result<Vec<IpAddr>, DnsError> = Err(DnsError::Resolve("fuzz".into()));
    let response = Relay::build_response(request.metadata.id, request.metadata.op_code, query, &err);
    let _ = response.to_vec();

    let ok: Result<Vec<IpAddr>, DnsError> = Ok(vec![
        IpAddr::V4(Ipv4Addr::new(203, 0, 113, 1)),
        IpAddr::V6(Ipv6Addr::LOCALHOST),
    ]);
    let response = Relay::build_response(request.metadata.id, request.metadata.op_code, query, &ok);
    let _ = response.to_vec();
});
