# Security

## Dependency audit

`cargo audit` (RustSec advisory database) runs against every crate in the
workspace:

- Locally: `bash scripts/audit.sh` (or `scripts/audit.ps1` on Windows).
- In CI: `.github/workflows/audit.yml`, on every push/PR that touches a
  `Cargo.toml`/`Cargo.lock`, plus a weekly scheduled run (advisories can be
  published against dependency versions that haven't changed).

Policy: zero open advisories without a documented, dated exception below.
Every ignored advisory ID in `.cargo/audit.toml` must have a matching entry
here — if the two ever disagree, `.cargo/audit.toml` is wrong.

### Accepted exceptions

#### RUSTSEC-2023-0071 — `rsa` 0.9.10, Marvin Attack timing side-channel

- **Status**: accepted, no fixed upgrade published upstream as of 2026-08-31.
- **Path**: transitive only, via
  `arti-client -> tor-keymgr -> tor-key-forge -> ssh-key-fork-arti`, which
  uses `rsa` to parse RSA keys in SSH-format key files as part of arti's key
  manager.
- **Why accepted**: BlackHole never performs RSA private-key operations
  itself, and doesn't expose this dependency chain as a service an attacker
  could time (no network-facing RSA decryption oracle in our own code). The
  affected code lives entirely inside `arti-client`'s own key-management
  internals.
- **Revisit when**: a `rsa` release fixes the timing side-channel, or
  `arti-client` moves off the affected code path.

#### RUSTSEC-2024-0436 — `paste` unmaintained

- **Status**: accepted; informational warning, not a vulnerability.
- **Path**: transitive proc-macro dependency via
  `arti-client -> tor-memquota -> slotmap-careful`.
- **Why accepted**: `paste` is a small, stable, already-finished proc-macro
  with no known issues; "unmaintained" here means no further releases are
  expected, not that anything is broken.
- **Revisit when**: `slotmap-careful` (or `tor-memquota`) drops the
  dependency, or an actual advisory is filed against `paste` itself.

#### RUSTSEC-2025-0141 — `bincode` 2.0.1 unmaintained

- **Status**: accepted; informational warning, not a vulnerability, and not
  actually compiled into this workspace.
- **Path**: present in `Cargo.lock` only as an unactivated optional feature
  of `typed-index-collections` (pulled in via `tor-dirmgr`). Confirmed via
  `cargo tree -i bincode --workspace --all-features --target all`, which
  resolves to nothing — `bincode` is not part of any target this workspace
  actually builds.
- **Revisit when**: `typed-index-collections` (or `tor-dirmgr`) drops the
  dependency, or we ever enable a feature that activates it.

## Sensitive data in memory (`zeroize`)

As of 2026-08-31, an audit of every crate in the workspace
(`blackhole-core`, `blackhole-dns`, `blackhole-dashboard`,
`blackhole-fingerprint`, `blackhole-mobile-ffi`) found **no struct that
holds secret material** (private keys, tokens, passwords, session
cookies) in our own code:

- Tor key material is managed entirely inside `arti-client`'s own state,
  never surfaced to `blackhole-core`.
- `blackhole-dns` holds only IP addresses and provider config, never
  credentials.
- `blackhole-fingerprint` reads identifiers (hostname, MachineGuid, MAC
  addresses) that are quasi-identifying but not secrets — and the tool's
  entire purpose is to display them in its report, so wrapping them in
  `zeroize` would add no real protection while implying one that isn't
  there.
- `blackhole-mobile-ffi` passes only `u32` severity codes across the FFI
  boundary.

Given that, `zeroize` is deliberately **not** added as a dependency yet —
adding it with no real use site would be dead weight, not hardening.

**Policy for future code**: the moment any crate in this workspace holds
real secret material in memory (a Tor control-port auth cookie, a stored
session token, a SOCKS/relay credential, anything similar), that struct
must:

1. Depend on `zeroize` and derive `ZeroizeOnDrop` (and `Zeroize` on any
   type it's built from that also holds the secret).
2. Avoid `Clone`/`Debug` derives that would copy or print the secret
   verbatim — implement `Debug` by hand to redact it if a `Debug` impl is
   needed at all.
3. Be re-audited here, with this section updated to name the struct and
   why it's exempt from (or covered by) the above.

## Fail-closed guarantees

See each crate's `THREAT_MODEL.md` for what it protects and against whom.
Summary of what's automated vs. manual:

- **Unit-tested** (`cargo test`, no privileged access needed):
  `blackhole-core::guard::GuardStateMachine` (every state transition, and
  `reconcile()` — the in-memory-vs-actual-OS-state cross-check shared by
  both platform backends); `blackhole-dns::relay::Relay::build_response`
  (a failed upstream resolve always yields `SERVFAIL` with zero answer
  records, never a fabricated or stale address);
  `blackhole-dns::leak::enforce_on_leak` (a detected leak — including "the
  encrypted resolver itself is unreachable," i.e. what a DNS timeout looks
  like — always drives the kill switch to a known-blocking state, in every
  guard state except an in-flight transition it must not race).
- **Structural, not unit-testable in this environment** (requires a live
  OS and admin/root): once `enable()` succeeds, blocking is enforced by
  the OS itself (`nftables`/WFP default-deny), independent of this
  process staying alive — so a crash of the BlackHole process does not
  open the firewall back up, and a lost Tor circuit does not create a
  path around the firewall (only loopback and the Tor-owning
  process/UID are ever permitted). Verify manually with the checklist in
  each crate's `THREAT_MODEL.md`.
