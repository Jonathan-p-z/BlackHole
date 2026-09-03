# Threat model: `blackhole-cli`

## What this protects

Nothing directly. This is a thin dispatch layer: each subcommand calls
the exact same public function the corresponding module's own binary
already calls (`blackhole enable` calls the same `start_backend` +
`PlatformGuard::enable()` `blackhole-core enable` does; `blackhole scan`
calls the same `blackhole_fingerprint::scan_record_and_report`
`blackhole-fingerprint scan` does; and so on). It adds no independent
protection layer of its own, only a single set of subcommands so a user
doesn't need to know or launch four separate binaries for everyday use.

## Against what adversary

Not adversary-facing, for the same reason `blackhole-dashboard` isn't
(see its own `THREAT_MODEL.md`): this crate's only real risk is
**dispatching to the wrong function**, i.e. a wiring bug where a
subcommand silently calls something other than what its name and help
text claim. That's what `src/main.rs`'s own `#[cfg(test)]` module and
`tests/scan_wiring.rs` exist to catch, not a security property.

## What this does NOT protect against

- **Anything `blackhole-core`/`blackhole-dns`/`blackhole-dashboard`/
  `blackhole-fingerprint` themselves don't protect against.** See each
  one's own `THREAT_MODEL.md`; this crate inherits their exact threat
  models unchanged, since it never touches their internals, only their
  public API surface.
- **`blackhole panic`'s backend scope.** It reuses
  `blackhole_dashboard::data::LiveDataSource::panic()` exactly, which
  always uses the arti Tor backend; `--tor-backend subprocess` has no
  effect on this subcommand, since blackhole-dashboard itself doesn't
  support backend selection today. Not a gap introduced here, an
  inherited one, flagged rather than silently different from what
  `--tor-backend`'s help text might otherwise imply.
- **`blackhole status`'s speed for the kill-switch/Tor section.** The
  fingerprint section reads cached history only (fast, no scan). The
  kill-switch/Tor section still has to start a Tor backend to ask it
  anything at all, exactly like running `blackhole-core status` on its
  own does; this command doesn't make that any faster, it only combines
  the same underlying queries into one output.
