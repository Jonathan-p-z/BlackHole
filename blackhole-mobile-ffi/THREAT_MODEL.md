# Threat model: `blackhole-mobile-ffi`

## What this protects

Nothing directly. This is a tiny `extern "C"` scoring bridge so
`blackhole-mobile-ios` (and potentially a future Android client) can
compute the same severity-weighted traceability score as
`blackhole-fingerprint::report`, from findings the mobile app collected
itself, without reimplementing the scoring formula per platform. It passes
plain integers (`u32` severity codes) across the FFI boundary on purpose
(see the module doc) rather than sharing Rust types, since that's the part
of an FFI boundary that's easiest to keep correct.

## Against what adversary

Not adversary-facing. The only "threat" this crate's design defends
against is **its own FFI boundary being misused**: a caller passing a
pointer/length pair that doesn't describe a valid, readable `u32` array.
`blackhole_score_from_severities`'s `# Safety` doc comment states the exact
precondition, and a `debug_assert!` catches an obviously-null pointer with
nonzero `len` in debug builds (a release build trusts the caller, per the
documented contract; this is standard for `unsafe extern "C" fn`).

## What this does NOT protect against

- **A Swift caller violating the documented safety contract.** This crate
  cannot enforce pointer/length validity across the FFI boundary from the
  Rust side; a buggy Swift call site can still hand it a dangling pointer
  or a `len` longer than the actual buffer, which is undefined behavior
  this crate has no way to detect at runtime in a release build. The
  contract has to be upheld on the Swift side.
- **Anything about mobile app security beyond this one scoring
  computation.** Network protection, VPN/Tor tunneling, or any other part
  of the iOS app's threat model is out of scope for this crate; see
  `blackhole-mobile-ios`'s own documentation.
- **Score integrity/tampering.** This function trusts whatever severity
  codes it's handed; it has no way to verify the caller actually collected
  those findings honestly. It's a shared-formula convenience, not an
  attestation mechanism.
