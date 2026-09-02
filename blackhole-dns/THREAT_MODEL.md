# Threat model: `blackhole-dns`

## What this protects

Forces DNS resolution through a priority-ordered list of encrypted, DNSSEC-
validating resolvers (DoH/DoT: Cloudflare, Quad9, Mullvad configurable in
any order), detects when the OS is still sending plaintext DNS queries
elsewhere despite that, and can trigger `blackhole-core`'s kill switch when
it does (`leak::enforce_on_leak`).

This reduces:

- **Plaintext DNS query exposure** to a local network observer or your
  ISP: normally the single easiest way to reconstruct someone's browsing
  even when the actual HTTP/TLS traffic is otherwise protected.
- **A malicious or compromised resolver forging answers for signed
  zones**: every resolver in `EncryptedResolver`'s chain validates DNSSEC
  (`ResolverOpts::validate = true`). An answer whose DNSSEC proof is
  `Bogus` (the chain of trust says it should validate and doesn't) is
  rejected outright (`resolver::reject_bogus`), treated exactly like any
  other resolve failure, never returned to the caller as if it were
  trustworthy. This is authenticity on top of the confidentiality DoH/DoT
  alone provides; see "What this does NOT protect against" for the limits
  (DNSSEC only catches tampering on zones that are actually signed).
- **A single resolver being a single point of failure or a single point
  of trust**: `EncryptedResolver::resolve` tries the configured provider
  chain in priority order, falling back to the next on any failure
  (network error or DNSSEC-bogus) and logging the switch
  (`switched DoH/DoT resolver after a failure`). Every provider in the
  chain is always itself encrypted DoH/DoT; there is no code path that
  can fall back to an unencrypted resolver, at any priority.
- **Silent leaks**: if the OS resolver configuration reverts (a VPN
  reconnect resets it, a new network interface comes up with its own
  DHCP-provided resolver, etc.), `leak::check` compares the OS's *actually
  active* resolver config against what was intended, not just what this
  crate thinks it set.
- **An unreachable encrypted resolver silently degrading to no
  protection**: `leak::check` treats "the encrypted resolver itself
  doesn't answer" as a leak too (`encrypted_resolver_reachable == false`
  drives `leak_detected = true`), so a DNS timeout doesn't get treated as
  "nothing to see here."

## Against what adversary

- A **passive network/ISP observer** watching for DNS queries in the
  clear.
- **Configuration drift**: this crate's own threat model includes itself
  going stale relative to what the OS is actually doing.

## What this does NOT protect against

- **The DNS provider(s) themselves** (Cloudflare/Quad9/Mullvad, whichever
  ends up in the configured chain). They still see every query:
  encrypted DNS protects the wire, not the destination's visibility into
  what you asked. If every provider you configure is itself the
  adversary you're modeling, this crate doesn't help: DNSSEC validates
  *authenticity* of the answer, not confidentiality of the *question*
  from the resolver you sent it to.
- **Correlation via DNS query timing or volume**, even without seeing
  plaintext content.
- **A malicious resolver returning a technically-valid answer for an
  unsigned zone.** DNSSEC only catches tampering where the zone is
  actually signed (`Proof::Secure`/`Proof::Bogus`); most of the internet
  still doesn't deploy DNSSEC at all, so a compromised resolver can still
  lie about an unsigned domain's answer (`Proof::Insecure`) without being
  caught: there is no cryptographic proof to check in that case, by
  design of DNSSEC itself, not a gap in this crate.
- **Non-DNS leaks.** This crate only reasons about DNS. An application
  that hardcodes an IP and skips DNS entirely is invisible to this
  module; `blackhole-core`'s kill switch is what actually blocks
  arbitrary egress, not this crate.
- **The relay itself as a trust boundary.** `relay::Relay` answers
  `A`/`AAAA` over UDP only, with a fixed TTL, and no TCP fallback for
  large/truncated responses (documented limitation in `relay.rs`): not a
  full recursive resolver replacement.

## Fail-closed properties (automated)

Covered by `cargo test -p blackhole-dns`, no network or OS access needed:

- `relay::Relay::build_response`: a failed upstream resolve (timeout,
  unreachable resolver: the exact shape of what happens if the encrypted
  path breaks mid-session) always yields `SERVFAIL` with **zero** answer
  records. It never falls back to a cached, stale, or fabricated address.
  A resolved IP whose family doesn't match the query type (`AAAA` result
  for an `A` query, or vice versa) is silently dropped, never coerced into
  a wrong-but-present answer.
- `leak::enforce_on_leak`: on any detected leak, including "the encrypted
  resolver is unreachable", always drives the guard to a known-blocking
  state (`disable()` then `enable()` if it claimed to already be enabled,
  since a leak getting through means whatever's currently applied can't be
  trusted; `enable()` directly from `Disabled`/`Faulted`), in every guard
  state except an in-flight `Enabling`/`Disabling` transition it
  deliberately doesn't race.
- `resolver::reject_bogus`: a record with DNSSEC proof `Bogus` is always
  rejected (`Insecure`/`Secure` both pass); tested directly against
  hand-built records, no network needed.
- `resolver::EncryptedResolver::resolve`: a failing or DNSSEC-bogus
  primary provider falls back to the next configured provider, and *only*
  the fallback's answer is ever returned; nothing from the failed
  attempt leaks through to the caller. Tested against a fake backend
  (`resolver::tests::FakeBackend`) covering: healthy primary (no
  fallback), failing primary, DNSSEC-bogus primary, all providers
  failing (reported, not silently swallowed), and that the provider
  which last succeeded is tried first on the next query (self-healing:
  if it starts failing, the search still walks the rest of the chain
  rather than getting stuck).

## Fuzzing findings

`fuzz/fuzz_targets/dns_relay_parse.rs` fuzzes the exact untrusted-input
boundary `Relay::serve_udp` feeds every incoming UDP datagram through
(`Message::from_vec`), plus `Relay::build_response`.

- **2026-08-31**: within the first 2-minute local run, found a
  denial-of-service: a crafted TSIG resource record in an otherwise
  ordinary-looking query triggers `attempt to subtract with overflow`
  inside **hickory-proto 0.26.1's own TSIG rdata parser**
  (`rr::rdata::tsig`, not this crate's code), reachable by *any* UDP
  client that can reach the relay's listening port, since `handle_datagram`
  parsed every datagram directly with no isolation. Before the fix, one
  malformed packet crashed the entire relay process: a DoS against
  whichever DNS query happened to be in flight, and against every
  subsequent client until the process was restarted. The bug itself lives
  upstream in `hickory-proto`, out of this crate's control; what this
  crate is responsible for is not letting an attacker-controlled input
  boundary take the whole process down over someone else's parser bug.
  **Fixed** in `relay.rs` by wrapping the parse in
  `std::panic::catch_unwind` (`Relay::safe_parse_message`): a panic there
  now drops the one bad packet and logs a warning instead of crashing the
  relay. Pinned as `relay::tests::malformed_tsig_record_does_not_panic_the_relay`
  with the exact crash bytes the fuzzer found; this test runs under a
  normal `cargo test` and confirms the fix works for the actual shipped
  relay binary.
- **Known limitation of this fuzz target, not of the fix**: `libfuzzer-sys`
  installs a panic hook that calls `process::abort()` *before* unwinding
  starts, specifically so no `catch_unwind` anywhere in a fuzzed binary
  can hide a panic from libFuzzer's crash detection. That means fuzzing
  `Relay::safe_parse_message` instead of the raw `Message::from_vec` would
  not have let the fuzzer progress past this bug either: there is no way,
  from inside a libFuzzer harness, to fuzz "past" a panic that's still
  reachable in the dependency being called. **Update**: a local, fuzzing-only patch
  was added (`fuzz/patched-deps/`, wired via `fuzz/Cargo.toml`'s
  `[patch.crates-io]`) fixing the underlying `saturating_sub` bug so
  `dns_relay_parse` can explore past it, scoped to the `fuzz` crate's own
  standalone workspace only; the real `blackhole-dns` binary still uses
  the real, unpatched `hickory-proto`. See `fuzz/patched-deps/README.md`
  and `fuzz/FUZZING.md`.

## What would need manual/integration verification

- That `system_dns::active_servers()` (Linux: `resolvectl`/systemd-resolved
  query; Windows: `Get-DnsClientServerAddress` via PowerShell) actually
  reflects reality after a real network change (new Wi-Fi network, VPN
  connect/disconnect); this crate's unit tests can't exercise the real OS
  resolver subsystem.
- That `force_via_relay`/`force_via_dot` actually take effect at the OS
  level (requires elevated privileges on both platforms).
