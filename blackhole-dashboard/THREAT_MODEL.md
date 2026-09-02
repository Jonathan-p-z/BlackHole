# Threat model — `blackhole-dashboard`

## What this protects

Nothing directly — this is a `ratatui` TUI that polls `blackhole-core` and
`blackhole-dns` on a fixed interval and displays their status. Its only
active capability is "panic mode": force the kill switch on immediately,
regardless of current state (`data.rs::LiveDataSource::panic`).

Its actual security-relevant job is **not misleading the operator**: every
panel must degrade to `ModuleState::Unavailable` rather than crash or show
stale-but-confident data when a module can't be reached
(`data.rs` module doc: "Both sides of `DataSource` must never panic").
`Snapshot::danger()` (`app.rs`) is the single place that decides the
dashboard's overall color, and treats a DNS leak or a faulted kill switch
as `Danger::Danger`, and any `Unavailable` module (including a kill switch
still `Initializing`) as at least `Danger::Warning` rather than defaulting
to "looks fine."

## Against what adversary

Not adversary-facing in the traditional sense — its threat model is really
about **correctness under partial failure**, since a dashboard that shows
green when something is actually broken is worse than no dashboard at all.
The "adversary" here is closer to "a stuck Tor bootstrap, a hung DNS query,
or a crashed kill-switch process," and the property being defended is "the
operator finds out."

## What this does NOT protect against

- **Anything `blackhole-core`/`blackhole-dns` themselves don't protect
  against** — this crate only displays their state, it adds no
  independent protection layer beyond the panic-mode trigger.
- **A dashboard process itself being killed or hung.** If the whole
  process dies, there's no dashboard to show a warning — the underlying
  kill switch state (enforced by the OS, see `blackhole-core`'s threat
  model) is what actually matters at that point, not this TUI.
- **Race conditions between the 3-second poll interval and a fast-moving
  failure.** A leak or fault that both starts and resolves between two
  polls won't be shown; `backend.rs` runs on its own tokio task
  specifically so a slow module never blocks the *UI*, but it does not
  guarantee catching every transient event.
- **`MockDataSource`.** It exists purely for demoing/developing the UI
  without bootstrapping real Tor circuits or touching the system firewall
  (`data.rs` doc comment) — it fabricates leak/status data on a timer and
  must never be reachable in a real "am I protected" decision path.
