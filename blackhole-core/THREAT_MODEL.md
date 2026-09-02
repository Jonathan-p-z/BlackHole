# Threat model: `blackhole-core`

## What this protects

A fail-closed kill switch (nftables on Linux, WFP on Windows) paired with
Tor orchestration behind one `NetworkGuard` trait: `arti`, in-process, by
default, or (see `TOR_BACKENDS.md`) the official `tor` binary as a
subprocess, behind a second trait, `TorBackend`, that both share. When
`enable()` succeeds, the only outbound traffic permitted is: loopback,
already-established connections, and (depending on platform *and* Tor
backend) traffic owned by this process's UID (Linux, either Tor backend)
or a single executable (Windows: this process itself for `arti`, or the
child `tor.exe`'s own path for the subprocess backend; see
`TorBackend::permit_target`). Everything else is dropped by the firewall's
default policy, at the OS level, independent of this process (or its Tor
child process, if any) staying alive.

This reduces:

- **Commercial/web tracking and correlation** of your real IP/location by
  sites and services you connect to, by forcing all traffic through Tor.
- **Accidental plaintext egress** if Tor bootstraps slowly, stalls, or a
  circuit is torn down mid-session: the firewall blocks first, Tor
  connects second, not the other way around.
- **Light forensic exposure** on a device you control: no direct-connection
  history to those sites from this machine's own network stack, since
  those connections never left except via Tor.

## Against what adversary

- A **passive network observer** on the same LAN, or your ISP, trying to
  see what services this machine talks to directly.
- **Sites/services you connect to**, trying to learn your real IP.
- **Your own misconfiguration or a stalled Tor bootstrap**, i.e. this
  crate's own failure modes. The `Faulted` state (see
  `blackhole-core/src/guard.rs`) exists specifically so a partially-applied
  or crashed state is never silently treated as "safe to assume nothing is
  blocked."

## What this does NOT protect against

- **A state-level adversary with sustained physical access** to the
  machine, or the ability to compel key disclosure.
- **Anything once traffic reaches a Tor exit node**: exit-node
  observation, or a destination site correlating you by content (login,
  cookies, browser fingerprint) rather than IP.
- **Root/Administrator-level compromise of this machine.** If an attacker
  already has that level of access, they can disable the firewall or kill
  switch directly; this crate assumes the OS and its own process integrity
  are trusted.
- **Traffic from other processes not covered by the permit rule.** On
  Linux, the UID-based rule (see `platform/linux.rs` module docs) allows
  *any* process run by the same user, not just this binary; documented as
  a known scoping limitation, not a hidden one.
- **A lost Tor circuit turning into a plaintext leak.** By design this
  can't happen (the firewall doesn't know or care whether Tor is healthy;
  it only ever permits the narrow egress rule), but this crate does not
  itself detect or alert on Tor being stuck; that's `blackhole-dns`'s and
  `blackhole-dashboard`'s job for DNS and status respectively.
- **Evading a lawful investigation.** This is a privacy tool against
  commercial/network-level tracking, not a tool for evading law
  enforcement with legal authority and physical device access.

## The `subprocess` Tor backend specifically

See `TOR_BACKENDS.md` for the full picture (why it exists, how to use it,
what's temporary about it). Threat-model-relevant points:

- **No new leak surface.** The Windows permit rule scopes to the child
  `tor.exe`'s path instead of this process's own path (same mechanism as
  the `arti` backend, different target), and the Linux UID-scoped rule
  needs no change at all (a spawned child inherits the parent's UID).
- **If `blackhole-core` crashes while a `subprocess` child is running,**
  that child can become an orphan (best-effort `kill_on_drop` cleanup
  covers normal exit and unwinding panics, not a hard crash or external
  `SIGKILL`). This is **not** a fail-open condition: the nftables/WFP
  rules live in the OS, scoped to that same orphaned process either way,
  and keep blocking everything else regardless of whether
  `blackhole-core` itself is still running, the same structural
  guarantee the `arti` backend already relies on (see "What this
  protects" above). An orphan is a stray process to notice and clean up,
  not a leak.
- **Version floor, not a live feed.** `SubprocessTorBackend::start`
  refuses to run a `tor` binary older than 0.4.8: a point-in-time
  judgment call (see `tor_subprocess.rs`'s `MIN_TOR_VERSION` doc comment),
  not something that stays correct forever without revisiting.
- **The control-port channel is local-only and cookie-authenticated**
  (127.0.0.1, `CookieAuthentication 1`, a freshly-generated per-run cookie
  file), not exposed beyond this machine, and only readable by whichever
  account can read the `DataDirectory` this process itself created.

Automated coverage: `blackhole-core/tests/subprocess_backend.rs` spawns a
fake `tor` binary (no real Tor bootstrap, no network; see the file's own
doc comment) and verifies the permit-target scoping, a full control-port
round trip (status + `NEWNYM`), and (the fail-closed-relevant case
specifically) that killing the child unexpectedly is correctly reported
by `status()` (not silently treated as still healthy) and that
`new_identity()` refuses to claim success against a dead backend.

## Boot persistence (Linux)

nftables' ruleset lives in kernel memory only: a reboot wipes it, and
nothing reapplied it before this was added. `enable()`/`disable()` now
persist/remove a ruleset file (`platform::default_ruleset_path()`, override
via `BLACKHOLE_NFTABLES_RULESET_PATH`); `blackhole-core restore-firewall`
re-applies it, with no Tor backend started, meant to run once at boot
before network comes up (see the optional systemd unit in
`packaging/systemd/`). Full detail, including what this does and does not
guarantee (a corrupted persisted file fails loudly rather than silently
proceeding open, but there's no blind "block everything" fallback in that
case): [`BOOT_PERSISTENCE.md`](../BOOT_PERSISTENCE.md).

## Manual fail-closed verification checklist

The properties below are structural (enforced by the OS, not this
process). Below, most are also now covered by `chaos/`, a root-requiring
network-namespace integration suite that exercises them against a real
`nft` and real killed processes (a permitted process dying mid-connection,
`blackhole-core` itself crashing, and the boot-restore path above) rather
than only trusting this checklist; see [`chaos/README.md`](../chaos/README.md).
What isn't yet automated (WFP on Windows has no equivalent suite) still
needs manual verification on a live OS:

**Linux** (needs `nft`, run as the target user):
1. `blackhole-core` enable, then `sudo nft list table inet blackhole`:
   confirm the `policy drop` chain and the expected accept rules exist.
2. Kill the `blackhole-core` process (`kill -9`), then re-run the same
   `nft list table`: the table must still be present (proof that
   blocking survives a process crash).
3. Attempt an outbound connection from a *different* process (a browser)
   not matching the permitted UID/executable: confirm it's blocked while
   the table is still present.
4. `sudo nft delete table inet blackhole` to clean up.

**Windows** (needs Administrator, run `netsh wfp show filters` or
`Get-NetFirewallRule`-equivalent WFP inspection):
1. Enable the kill switch, then confirm the `blackhole-core` sublayer and
   its filters exist via `netsh wfp show filters` (look for the
   `BlackHole Kill Switch` sublayer name).
2. End the `blackhole-core` process from Task Manager, then re-check the
   WFP filters are still present.
3. Attempt an outbound connection from a different executable: confirm
   it's blocked.
