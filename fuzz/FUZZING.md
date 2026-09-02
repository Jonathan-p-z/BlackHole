# Fuzzing report

Fuzz targets for the parts of the BlackHole workspace that parse data from
outside the process: `blackhole-dns`'s handling of incoming DNS datagrams,
and `blackhole-fingerprint`'s handling of the third-party IP-info service's
response. `blackhole-core` is out of scope for now — its default `arti`
backend's bootstrap is blocked on an upstream issue (see project history;
partially unblocked since by an alternative subprocess-based Tor backend,
see `TOR_BACKENDS.md`, but that doesn't change what there is to fuzz here),
so there's nothing in it to fuzz productively yet. **Update, post-dating
the "Scope note" below**: `blackhole-core`, `blackhole-dns`, and
`blackhole-fingerprint` all gained a TOML config-file parser after this
report was first written (see each crate's `config.rs` and the root
`config.example.toml`) — none is fuzzed yet; a reasonable next target if
this gets revisited, not done as part of this pass.

Requires WSL (Ubuntu) on Windows — `cargo-fuzz`/libFuzzer need LLVM
sanitizer/coverage instrumentation that isn't supported by the MSVC
toolchain. See the root `README.md`'s Fuzzing section for setup.

## Targets

| Target | Exercises | Corpus seed |
| --- | --- | --- |
| `dns_relay_parse` | `hickory_proto::op::Message::from_vec` on a raw UDP datagram, then `blackhole_dns::relay::Relay::build_response` on the parsed query — the exact path `Relay::serve_udp` runs for every incoming packet. | `fuzz/corpus/dns_relay_parse/`: 5 correctly-encoded DNS messages generated via `cargo run -p blackhole-dns --example gen_fuzz_corpus` (A/AAAA/MX queries, a deep subdomain, a query with no question section). |
| `fingerprint_report_parse` | `blackhole_fingerprint::exposure::parse_report` — arbitrary bytes standing in for the third-party IP-info service's HTTP response body. | `fuzz/corpus/fingerprint_report_parse/`: 8 files mirroring the crate's own unit test cases — valid full response, Tor/VPN-org response, `error: true` response, empty object, missing fields, wrong JSON shape (array), truncated JSON, and a raw non-UTF-8 byte sequence. |

## Crash found and fixed

**2026-08-31, `dns_relay_parse`, within the first 2-minute local run.**

A crafted TSIG resource record in an otherwise ordinary-looking DNS
message triggers `attempt to subtract with overflow` inside
**hickory-proto 0.26.1's own TSIG rdata parser**
(`rr::rdata::tsig::TSIG::read_data`, two sites: the `mac_size` and
`other_len` length checks both compute `end_idx - decoder.index()` in
their error path without proving `decoder.index() <= end_idx` first).
This is a bug in the dependency, not in this workspace's own code — but
`handle_datagram` parsed every incoming UDP datagram directly with no
isolation, so any client that could reach the relay's listening port could
crash the entire process with one malformed packet. Found 3 times total
(2 local runs, same root cause each time — see
`blackhole-dns/THREAT_MODEL.md`'s "Fuzzing findings" section for full
detail and the exact reproduction steps).

**Fix, shipped in the real `blackhole-dns` crate** (not fuzzing-only):
`Relay::safe_parse_message` in `blackhole-dns/src/relay.rs` wraps the parse
in `std::panic::catch_unwind` — a panic there now drops the one bad packet
and logs a warning instead of taking the relay down. Regression-tested as
`relay::tests::malformed_tsig_record_does_not_panic_the_relay`, pinned
with the exact bytes the fuzzer found; runs under a normal `cargo test`
(no WSL needed to verify the fix).

**Why the fuzz target itself doesn't just call the fixed function**:
`libfuzzer-sys` installs a panic hook that calls `process::abort()` before
Rust's unwinding machinery runs, specifically so that no `catch_unwind`
anywhere in a fuzzed binary can hide a panic from libFuzzer's crash
detection. That means there's no way to fuzz "past" a still-reachable
panic in a dependency from inside a libFuzzer harness — calling the
hardened wrapper instead of the raw parser wouldn't have helped. See the
local patch below for how this was actually unblocked.

## Local patch: `hickory-proto` (fuzzing only)

To let `dns_relay_parse` explore past the known TSIG bug instead of
re-finding the same crash on nearly every run, `fuzz/patched-deps/`
vendors a copy of `hickory-proto` 0.26.1 with the two `end_idx -
decoder.index()` subtractions changed to `saturating_sub`, wired in via
`fuzz/Cargo.toml`'s `[patch.crates-io]`. **Scoped to the `fuzz` crate's own
standalone workspace only** — the real `blackhole-dns`/`blackhole-core`
binaries, built from the root workspace, are unaffected and still use the
real, unpatched `hickory-proto` from crates.io. See
`fuzz/patched-deps/README.md` for the exact rationale, what's changed, and
how to regenerate it against a newer version. Not reported upstream yet
as of 2026-08-31.

Verified against all 3 saved crash artifacts post-patch — none reproduce:

```
$ cargo fuzz run dns_relay_parse artifacts/dns_relay_parse/crash-fe873f7e8a41fac4db8cb3f40c47da4f8eac2d70
Executed ... in 7 ms   (no crash)
$ cargo fuzz run dns_relay_parse artifacts/dns_relay_parse/crash-2c6f0de00df08120a62f85eda5deb772a4b97302
Executed ... in 8 ms   (no crash)
$ cargo fuzz run dns_relay_parse artifacts/dns_relay_parse/crash-d21cb3ff3a1879fb9a6b6491ae2e048f3771e143
Executed ... in 8 ms   (no crash)
```

## `fingerprint_report_parse`: clean

3-minute local run, 3,101,094 executions, 0 crashes. `parse_report`
handles malformed JSON, truncated input, wrong-shaped JSON, and raw
non-UTF-8 bytes without panicking — matches the unit tests already in
`blackhole-fingerprint/src/exposure.rs`.

## Deep local runs (2026-08-31, several hours each)

Both targets launched for a 3-hour local pass each — `dns_relay_parse`
against the `[patch.crates-io]`-patched `hickory-proto`, so it isn't
stalled re-finding the already-fixed TSIG bug.

**Results:**

| Target | Executions | Corpus | Crashes |
| --- | --- | --- | --- |
| `dns_relay_parse` (patched) | 14,055,319 | 5,190 | 0 |
| `fingerprint_report_parse` | 153,664,084 | 9,789 | 0 |

Zero crashes in either target across ~168M combined executions. The 3
crash artifacts from earlier short runs (all the same TSIG bug, see
above) are still the only ones in `fuzz/artifacts/dns_relay_parse/`;
`fuzz/artifacts/fingerprint_report_parse/` has never existed — that
target has never crashed once. Both corpora grew substantially from their
seed size (5 and 8 files respectively) and are checked into the repo as
the new starting corpus for future runs.

## Scope note: no TOML config parser exists

The original plan (per the requesting prompt) included a fuzz target for
"each module's TOML config parser." As of 2026-08-31, no crate in this
workspace parses a TOML config file — none has a `toml` dependency of its
own, and `TorClientConfig::default()` (the only place `blackhole-core`
touches Tor config) is a hardcoded default, not something read from a
file. Rather than fabricate a config-parsing module solely to have
something to fuzz, this target was dropped; revisit if/when one of these
crates actually grows one.
