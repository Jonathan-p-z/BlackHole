# Threat model — `blackhole-fingerprint`

## What this protects

Nothing, by design — this is a read-only *audit* tool. It inspects local
network identity (hostname, machine ID, MAC addresses), OS telemetry
settings, and public network exposure, and reports findings with concrete
recommendations. It never changes system configuration itself (see the
module doc on `telemetry`): every fix it suggests requires the operator to
run a command or change a setting themselves, since most of those changes
need elevation and the operator should see the exact command first.

Its value is entirely informational: it tells you what a network operator,
a website, or the OS vendor could learn about this specific machine from
signals other than a real browser fingerprint.

## Against what adversary

- **A network operator or ISP**, learning your MAC address (manufacturer
  OUI vs. randomized) or hostname if it leaks your username.
- **The OS vendor's own telemetry pipeline**, if diagnostic data
  collection is left at a non-minimal level.
- **Any site you connect to directly** (outside Tor/a VPN), learning your
  public IP/ISP/approximate location via `exposure.rs`'s plain-HTTP
  check — this deliberately measures what a *non-Tor* connection reveals,
  as a "here's what you're protecting against" baseline.

## What this does NOT protect against

- **Real browser fingerprinting** (canvas rendering, WebGL, installed
  fonts, JS API surface). `exposure.rs`'s module doc is explicit about
  this: there's no meaningful way for a headless Rust HTTP client to
  reproduce what a service like EFF's Cover Your Tracks measures via
  client-side JavaScript in an actual browser. Run
  <https://coveryourtracks.eff.org> manually in the browser you actually
  use for a real fingerprint score.
- **Anything not covered by these three specific checks.** This is not a
  general security scanner — no port scanning, no application-level
  telemetry beyond OS diagnostic settings, no browser extension audit.
- **Enforcement.** Finding a manufacturer-original MAC address doesn't
  randomize it; finding DiagTrack running doesn't stop it. The operator
  has to act on the recommendation.
- **Any adversary who already has console access to this machine and its
  actual OS-reported values** — this tool reads the same information any
  local process could read; it adds no new exposure by existing, but also
  no confidentiality protection to the values it reports (they're printed
  to stdout for the operator).

## Scan history (`history.rs`)

Every `scan` (unless `--no-history`) is appended to a local JSON Lines
file (`history::default_history_path()` — the platform's per-user data
directory) so `diff` and `daemon` mode can show what changed since last
time instead of only the current snapshot. This carries the same
identifiers as the report itself (hostname, MAC, MachineGuid — see the
`zeroize` note below for why that's fine to display/store here), now
persisted across runs instead of only printed once.

**Strictly local**: nothing in `history.rs` makes a network call or writes
anywhere outside the one history file — no telemetry, no sync, no cloud
backup. This holds even in `daemon` mode: the periodic scan loop
(`daemon.rs`) only ever calls the same local checks `scan` does, on the
same interval, appending to the same local file.

**Plain text, not a proprietary format**: `history.jsonl` is exactly what
gets written on disk and exactly what an operator would want to export or
back up — `cp history.jsonl backup.jsonl` is a complete, readable export,
no separate step or format conversion needed. An operator can also read,
grep, or hand-edit it directly; `history::load_all` treats an unparseable
line as an error to report, not something to silently skip, so a
hand-edit mistake is surfaced rather than quietly losing that scan from
view.

**What `daemon` mode changes about the threat model**: none of the
above — same local checks, same local-only storage, just run on a timer
instead of on demand. A `daemon` process running unattended is a slightly
larger window for something with local access to the machine to see it
running (e.g. in a process list) than a one-shot `scan` invocation, but it
reads nothing it couldn't already read on demand, and still writes nowhere
but the local history file.

## Note on why `zeroize` isn't used here

`hostname`, `MachineGuid`, and MAC addresses read by this crate are
quasi-identifiers, not secrets — and this tool's entire purpose is to
display them in its report. Wrapping them in `zeroize::Zeroize` would
scrub a value that was, moments earlier, printed to the terminal on
purpose; it would imply a confidentiality guarantee this tool was never
designed to provide. See the root `SECURITY.md` for the workspace-wide
`zeroize` policy.
