# Quickstart

Five minutes, one command, then one more. For everything this doesn't
cover — advanced config, what each module actually protects against, why
it works the way it does — see [`README.md`](README.md) and each crate's
own `THREAT_MODEL.md`.

## 1. Install

You need [Rust](https://rustup.rs) installed first — BlackHole is built
from source, and the install script won't silently install a toolchain
for you (see [`README.md`](README.md#installation) for why).

**Linux / macOS**, from inside a clone of this repo:

```sh
./install.sh
```

**Windows** (PowerShell), from inside a clone of this repo:

```powershell
.\install.ps1
```

Either script: compiles the workspace, installs the binaries for your
user only (no root/sudo/Administrator), and drops a commented starter
config — it tells you exactly what it's about to do before it does it.
Prefer to see what a script does before running it? Both are short
enough to read in a couple of minutes; open `install.sh`/`install.ps1`
first.

## 2. Turn on the kill switch

```sh
blackhole-core enable
```

This is the one command that requests elevation (WFP on Windows, `nft` on
Linux — the kill switch itself needs it; nothing else in BlackHole does).
It bootstraps Tor and blocks all other outbound traffic while it does.

Check it's actually doing something:

```sh
blackhole-core status
```

## What next

- `blackhole-dns check` — confirm DNS isn't leaking outside the encrypted
  path.
- `blackhole-fingerprint scan` — see what this machine looks like to a
  network operator right now.
- `blackhole-dashboard` — a live TUI view of all of the above at once.
- `blackhole-core disable` — turn the kill switch back off when you're
  done; it's the only command that intentionally leaves you unprotected,
  so it's never implicit.

Every advanced option (which DoH/DoT resolvers, how often
`blackhole-fingerprint daemon` scans, ...) lives in one config file —
see [`config.example.toml`](config.example.toml) for what's there and
where it goes. None of it is required to get started; that's what steps 1
and 2 above already did with sensible defaults.
