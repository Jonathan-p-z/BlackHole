# Tor backends

`blackhole-core` can run Tor two ways, behind the same `TorBackend` trait
and the same kill switch:

| | `arti` (default) | `subprocess` |
| --- | --- | --- |
| What runs Tor | `arti-client`, in-process (pure Rust) | The official C `tor` binary, as a child process |
| Status | **Recommended default** | **Temporary workaround** |
| Extra install step | None | Yes — you provide the `tor` binary |

## Why `subprocess` exists

As of 2026-08-31, `arti-client` 0.44.0/0.45.0 has a bootstrap bug on this
project's Windows development machine: `TorClient::create_bootstrapped()`
builds circuits to fallback directories successfully (handshake completes
in under 2 seconds) but then never uses them — the call hangs
indefinitely, reproduced identically across both versions, independent of
persisted state. Full diagnostic writeup in the project's session
history; not yet filed upstream. Until that's fixed (or otherwise
diagnosed further), the `arti` backend can't bootstrap at all on an
affected machine — which meant the Windows kill switch couldn't be
enabled, at all, full stop.

`subprocess` unblocks that: the official `tor` binary is mature, widely
audited, and doesn't have this bug. `blackhole-core` orchestrates it —
spawns it with a minimal config, and talks to its already-documented
control-port protocol for status and identity rotation — the same way
this project already prefers a mature dependency over rewriting one
(`hickory-proto` for DNS parsing, `arti-client` itself for Tor, `windows-rs`
for WFP). **This module never reimplements anything about Tor's own
network protocol or cryptography** — see
`blackhole-core/src/tor_subprocess.rs`'s module doc and
`blackhole-core/src/tor_control.rs`'s module doc for exactly where that
line is drawn.

## Why `arti` stays the recommended default

Once the bootstrap bug is fixed upstream (or a workaround is found that
doesn't need a second binary), `arti` should stay the default for anyone
not specifically working around this issue: it's one fewer external
dependency to obtain, version-check, and keep updated — `arti-client` is
just a Rust dependency like any other, built into the binary you already
compiled, whereas `subprocess` requires you to separately download,
place, and maintain a `tor` binary yourself. `subprocess` is an escape
hatch for a known, specific problem, not a general recommendation.

## Using the `subprocess` backend

### Get a `tor` binary

Two ways:

1. **Download Tor directly** from
   <https://www.torproject.org/download/tor/> (the "Expert Bundle" —
   just the `tor` binary and its libraries, no browser).
2. **Use an existing Tor Browser install.** `blackhole-core` will look for
   one automatically in a few common locations (Desktop, `%LOCALAPPDATA%`
   on Windows; `~/tor-browser`, `~/Desktop/tor-browser`, `/opt/tor-browser`
   on Linux) if you don't set an explicit path — but this list isn't
   exhaustive, so an explicit `tor_binary_path` (below) is the reliable
   option if auto-detection doesn't find yours.

`blackhole-core` refuses to run a `tor` binary older than version
**0.4.8** (checked via `tor --version` before spawning it) — running an
unversioned or too-old binary would mean no assurance against a
known-fixed vulnerability. This floor is a point-in-time judgment call,
not a live feed; if you hit it unexpectedly, get a current release.

### Select it

In the shared config file (see the root `README.md`'s Installation
section for where that lives, or `config.example.toml`):

```toml
[core]
tor_backend = "subprocess"
# Only needed if auto-detection doesn't find your install:
tor_binary_path = "/path/to/tor"
```

Or per-invocation, without touching the config file:

```sh
blackhole-core --tor-backend subprocess enable
```

A CLI flag always overrides the config file.

## What's the same, what's different

- **The kill switch's fail-closed guarantee is unchanged.** On Linux, the
  nftables rule is scoped by UID, and a child `tor` process spawned by
  `blackhole-core` inherits the same UID — no code change was needed
  there at all. On Windows, the WFP permit rule is scoped to a single
  executable path; with `subprocess`, that's now the child `tor.exe`'s
  path instead of `blackhole-core.exe`'s own path (see
  `TorBackend::permit_target`) — same mechanism, different target.
- **If `blackhole-core` crashes while `subprocess` is active,** the
  spawned `tor` process may become an orphan (best-effort cleanup via
  `kill_on_drop` handles normal exit and panics, but not a hard crash or
  external `SIGKILL`/`taskkill` of `blackhole-core` itself — that can't be
  intercepted by definition). This does **not** create a leak: the
  nftables/WFP rules live in the OS, not in the `blackhole-core` process,
  and stay scoped to exactly that one orphaned `tor` process either way —
  see each platform backend's section of `blackhole-core/THREAT_MODEL.md`.
  What an orphan *does* mean is a stray process using a small amount of
  resources until you notice and kill it (or reboot); `blackhole-core
  status` will correctly report the backend as down once you next run it
  and it can't reach the child's control port.
- **What doesn't work yet with `subprocess`**: `blackhole-dashboard`'s
  exit-IP display and `blackhole-dns`'s in-process Tor stream usage are
  wired to the `arti` backend specifically (`TorOrchestrator::exit_ip`
  opens a stream via arti's in-process API — there's no equivalent for a
  backend that only exposes a SOCKS proxy). Only `blackhole-core`'s own
  kill switch (`enable`/`disable`/`status`/`new-identity`) supports
  backend selection today. Extending the other two conveniences to work
  through the subprocess backend's SOCKS port is a real gap, not
  something silently working — noted here rather than left to be
  discovered.
