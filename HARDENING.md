# BlackHole hardening report (2026-08-31)

Cross-cutting hardening pass across the whole workspace: dependency audit,
sensitive-data-in-memory policy, fail-closed verification, `unsafe` audit,
and per-crate threat models. This file is the index; details live in the
documents it links to.

## 1. Dependency audit: `cargo audit`

- **Status: clean.** `bash scripts/audit.sh` (also `scripts/audit.ps1`, and
  `.github/workflows/audit.yml` in CI) exits 0.
- 1 real advisory (`RUSTSEC-2023-0071`, `rsa` timing side-channel) and 2
  unmaintained-crate warnings (`RUSTSEC-2024-0436` `paste`,
  `RUSTSEC-2025-0141` `bincode`) found, all **transitive through
  `arti-client`**, none in first-party code, none with a fix available or
  needed. Documented, dated, and traced to their exact dependency path in
  [`SECURITY.md`](SECURITY.md); the ignore list lives in
  `.cargo/audit.toml` and the two files are required to stay in sync.
- CI runs on every push/PR touching a `Cargo.toml`/`Cargo.lock`, plus a
  weekly schedule (new advisories can land against unchanged
  dependencies).
- **Caveat**: no git repository exists yet in this working directory, so
  the GitHub Actions workflow can't actually run until this is pushed to a
  GitHub repo. It's ready to go the moment that happens; `scripts/audit.sh`
  /`scripts/audit.ps1` work today, locally, regardless.

## 2. Sensitive data in memory: `zeroize`

- **Finding, not an implementation**: audited every struct in all 5
  workspace crates; none hold secret material (keys, tokens, passwords,
  session cookies) in first-party code. Tor key material stays entirely
  inside `arti-client`'s own state. `blackhole-fingerprint` reads
  quasi-identifiers (hostname, MachineGuid, MAC) whose entire purpose is to
  be displayed in its report; zeroizing them would be theater, not
  hardening.
- `zeroize` is **not** added as a dependency: no real use site exists
  today, and adding an unused dependency isn't hardening. Full reasoning
  and the **policy for future code** (when/how to apply
  `Zeroize`/`ZeroizeOnDrop` the moment a real secret shows up) is in
  [`SECURITY.md`](SECURITY.md).

## 3. Fail-closed review + tests

Reviewed `blackhole-core`, `blackhole-dns`, and `blackhole-dashboard`.
Found the design already fail-closed-first at the architecture level
(`GuardState::Faulted` exists specifically so a partial failure is never
silently treated as safe; DNS resolve failures already produced
`SERVFAIL`, never a plaintext-resolver fallback). What was missing was
*test coverage* and, in one place, *duplicated logic that could drift*.

Changes:

- **`blackhole-core/src/guard.rs`**: extracted the in-memory-vs-actual-OS
  reconciliation logic (previously copy-pasted identically in
  `platform/linux.rs` and `platform/windows.rs`) into
  `GuardStateMachine::reconcile()`, and added 3 tests for it (mismatch in
  each direction, and the quiet/agreeing case). Both platform backends now
  call the same, single, tested implementation.
- **`blackhole-dns/src/relay.rs`**: extracted `Relay::build_response()` as
  a pure function so the resolve-failure path is directly testable without
  a real network round-trip. 4 new tests, including the core fail-closed
  claim: a failed upstream resolve always produces `SERVFAIL` with zero
  answer records, never a fabricated/stale address, and a query-type/IP
  family mismatch is dropped rather than coerced into a wrong answer.
- **`blackhole-dns/src/leak.rs`**: added a `FakeGuard` test double and 6
  tests for `enforce_on_leak` covering every `GuardState` (including the
  "encrypted resolver unreachable" case, what a DNS timeout looks like
  upstream of this function); the kill switch is (re-)enforced in every
  case except an in-flight transition it must not race.
- Test count: **36 passing** across the workspace (`cargo test
  --workspace`), up from 13 before this pass.

**What's still manual, and why**: these structural claims (the OS enforces
the rules, not this process) needed root on a live OS to verify, which
this sandbox didn't have at the time this section was first written.
**Update**: for Linux, that gap is now closed: `chaos/` is a real,
root-requiring integration suite (network namespaces, a real `nft`,
real killed processes) that exercises exactly these claims: a permitted
process dying mid-connection never opens a leak window, a SIGKILLed
`blackhole-core` leaves the firewall exactly as it was, and (a genuine
gap this suite *found*, not just confirmed) nftables' ruleset didn't
survive a reboot at all until this pass added persistence + a
`restore-firewall` boot path for it (see
[`BOOT_PERSISTENCE.md`](BOOT_PERSISTENCE.md) and
[`chaos/README.md`](chaos/README.md)). Windows/WFP verification is still
manual; exact steps for both platforms are in
[`blackhole-core/THREAT_MODEL.md`](blackhole-core/THREAT_MODEL.md#manual-fail-closed-verification-checklist).

**Bonus fix surfaced by this pass, not deferred**: while reviewing
`platform/windows.rs` for fail-closed correctness, found and fixed a real
use-after-return bug: `block_all_filter`/`permit_filter` pointed a WFP
struct's `providerKey` field at a local that didn't outlive the function
call site that actually dereferenced it. See §4 and
[`UNSAFE_AUDIT.md`](UNSAFE_AUDIT.md) for detail.

## 4. `unsafe` surface

Full listing, safety-comment verification, and safe-alternative
assessment: [`UNSAFE_AUDIT.md`](UNSAFE_AUDIT.md). Summary:

- 16 `unsafe` blocks/functions total, all in `blackhole-core` (14) and
  `blackhole-mobile-ffi` (2). Zero in `blackhole-dns`,
  `blackhole-dashboard`, `blackhole-fingerprint`.
- 100% already carried a `SAFETY`/`# Safety` comment; every one was
  checked against its actual call site, not taken on faith.
- 1 real bug found and fixed this pass (the `providerKey` use-after-return
  above): the comment on the pattern's *first* use (`add_sublayer`) was
  correct, but two later functions reused the same shape in a context
  where it no longer held (returning the struct by value to a caller that
  makes the FFI call later, rather than making the call itself).
- 15 of 16 have no viable safe alternative: WFP and a C-ABI FFI export
  are inherently `unsafe` in Rust, and no safe wrapper crate exists for
  WFP. 1 (`libc::getuid()`) has a safe alternative (`rustix`/`nix`) that
  wasn't adopted: it's an infallible, argument-free syscall with no real
  risk, and a new dependency isn't worth it for that.

## 5. Per-crate threat models

- [`blackhole-core/THREAT_MODEL.md`](blackhole-core/THREAT_MODEL.md)
- [`blackhole-dns/THREAT_MODEL.md`](blackhole-dns/THREAT_MODEL.md)
- [`blackhole-dashboard/THREAT_MODEL.md`](blackhole-dashboard/THREAT_MODEL.md)
- [`blackhole-fingerprint/THREAT_MODEL.md`](blackhole-fingerprint/THREAT_MODEL.md)
- [`blackhole-mobile-ffi/THREAT_MODEL.md`](blackhole-mobile-ffi/THREAT_MODEL.md)

Each states what it protects, against what adversary, and, deliberately
as prominent as the protections, what it explicitly does not protect
against. `blackhole-mobile-ios` (Swift, not a Cargo workspace member) is
out of scope for this pass.

## 6. Fuzzing

Fuzz targets for the workspace's untrusted-external-input parsers:
incoming DNS datagrams (`blackhole-dns::relay`) and the third-party
IP-info service's response (`blackhole-fingerprint::exposure`). Full
detail: [`fuzz/FUZZING.md`](fuzz/FUZZING.md). Summary:

- **1 real bug found and fixed**: a crafted TSIG record panics
  `hickory-proto` 0.26.1's own rdata parser (integer underflow), reachable
  by any UDP client hitting the relay's listening port: a DoS against the
  whole process. Fixed in `blackhole-dns` with a `catch_unwind` boundary
  (`Relay::safe_parse_message`), regression-tested with the exact
  fuzzer-found bytes. Documented in `blackhole-dns/THREAT_MODEL.md`.
  Not an `unsafe`-block issue, so nothing to add to `UNSAFE_AUDIT.md`.
- **Deep 3-hour runs, both targets, zero new crashes**: `dns_relay_parse`
  (against a locally `[patch.crates-io]`-patched `hickory-proto`, so it
  isn't stalled re-finding the already-fixed TSIG bug): 14,055,319
  executions, 0 crashes. `fingerprint_report_parse`: 153,664,084
  executions, 0 crashes, and has never crashed once across any run.
- A TOML config parser was added to `blackhole-core`/`blackhole-dns`/
  `blackhole-fingerprint` after the fuzzing pass above. Not fuzzed yet;
  see `fuzz/FUZZING.md`'s scope note.
- `blackhole-core` is out of scope for now (its Tor bootstrap is blocked
  on an upstream `arti-client` issue, so there's nothing to fuzz there
  productively yet).
- Windows requires WSL for this step only; see the root `README.md`'s
  Fuzzing section.

## Checklist

| Crate | Audit clean | Zeroize reviewed | Fail-closed tests | Unsafe audited | Threat model |
| --- | --- | --- | --- | --- | --- |
| `blackhole-core` | yes (transitive-only findings) | yes: none needed | yes (13 tests, incl. 3 new `reconcile` tests) | yes (14 blocks, 1 bug fixed) | yes |
| `blackhole-dns` | yes | yes: none needed | yes (11 tests: 10 from this pass + 1 fuzzer-found regression) | yes (0 blocks) | yes |
| `blackhole-dashboard` | yes | yes: none needed | reviewed (see its threat model for why unit tests don't apply) | yes (0 blocks) | yes |
| `blackhole-fingerprint` | yes | yes: none needed, explained | yes (10 tests, pre-existing) | yes (0 blocks) | yes |
| `blackhole-mobile-ffi` | yes | yes: none needed | yes (3 tests, pre-existing) | yes (2 blocks, both inherent to FFI) | yes |

Full workspace: `cargo build --workspace` clean, `cargo test --workspace`
47/47 passing, `cargo clippy --workspace` clean, `bash scripts/audit.sh`
exits 0. (The `blackhole-dashboard` clippy lints noted in an earlier
version of this report have since been cleaned up: an unused
`ModuleState::ok`, an enum-variant-name lint, and two clamp/modulo style
suggestions.)
