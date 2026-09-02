# BlackHole

BlackHole is a small set of command-line privacy tools for Linux and
Windows: a fail-closed kill switch that blocks network traffic outside
Tor, a DNS leak detector that forces encrypted resolution, a status
dashboard, and a local traceability auditor. Each tool is a separate
binary and can be used on its own.

**This is a personal project, not a commercial product or a
professionally audited security tool.** It has not been reviewed by a
third-party security firm. What it does and does not protect against is
documented per crate in each `THREAT_MODEL.md`, and the honest summary is:
it reduces commercial/network tracking for someone willing to read the
threat models and verify the firewall behavior on their own machine, not
a guarantee against a determined or well-resourced adversary. New here?
[`QUICKSTART.md`](QUICKSTART.md) is the 5-minute version of the
Installation section below.

## Contents

- [What's here](#whats-here)
- [Installation](#installation)
- [Security, testing, and limits](#security-testing-and-limits)
- [Fuzzing](#fuzzing)
- [Chaos tests (network-failure injection)](#chaos-tests-network-failure-injection)
- [Contributing](#contributing)

## What's here

| Crate | Purpose |
| --- | --- |
| `blackhole-core` | Fail-closed kill switch (nftables on Linux, WFP on Windows) plus Tor orchestration: `arti` in-process by default, or the official `tor` binary as a subprocess (see [`TOR_BACKENDS.md`](TOR_BACKENDS.md)). Linux firewall state survives a reboot (see [`BOOT_PERSISTENCE.md`](BOOT_PERSISTENCE.md)). |
| `blackhole-dns` | Anti-DNS-leak: forces encrypted DNS (DoH/DoT), detects leaks, can trigger the kill switch. |
| `blackhole-dashboard` | `ratatui` status TUI over the two modules above. |
| `blackhole-fingerprint` | Read-only local traceability audit (hostname/MAC/telemetry/public exposure). |
| `blackhole-mobile-ffi` | C-ABI scoring bridge shared with `blackhole-mobile-ios`. |
| `blackhole-mobile-ios` | SwiftUI + `PacketTunnelProvider` iOS app (separate, non-Cargo project). |

Each crate carries a `THREAT_MODEL.md`: what it protects, against what
adversary, and what it explicitly does not protect against.

## Installation

Two paths, both land in the same place: your own build of the binaries,
installed for your user only, never root/Administrator.

### Quick install (the install script)

```sh
# Linux / macOS, from inside a clone of this repo:
./install.sh

# Windows (PowerShell), from inside a clone of this repo:
.\install.ps1
```

The script compiles the workspace with `cargo build --release`, copies
the resulting binaries to a per-user directory (`~/.local/bin`, or
`%USERPROFILE%\.local\bin` on Windows), and drops a commented starter
config if one doesn't already exist (see
[`config.example.toml`](config.example.toml)). It prints what it's about
to do before doing it. It never touches anything outside your user
profile, and never requests elevation.

**Read the script before you run it.** It downloads nothing and executes
code on your machine (`cargo build`, which itself pulls and compiles
dependencies); both scripts are deliberately kept short specifically so
that's a quick read, not a leap of faith. There's no `curl | sh` one-liner
yet because there's no public release to fetch: this project doesn't have
a public GitHub repo or binary releases at the time of writing, so both
scripts currently assume you're running them from inside a local clone.
Once that changes, this section will document the real one-liner (and
checksum/signature verification for the precompiled binaries, and a
winget/Scoop package for Windows), not before, since promising either
today would point at something that doesn't exist.

### From source

For auditing the code before it touches your machine, or if you'd rather
not run either install script at all:

```sh
cargo build --release --workspace --bins
# or, for a single module (what install.sh/install.ps1 do per binary):
cargo install --path blackhole-core
cargo install --path blackhole-dns
cargo install --path blackhole-dashboard
cargo install --path blackhole-fingerprint
```

This is a Cargo workspace with several binary crates, not one single
package: `cargo install --path .` from the repo root won't resolve to a
specific binary on its own, so `--path <crate-dir>` per module, as above,
is what works. Then, optionally, copy
[`config.example.toml`](config.example.toml) to the location noted in
its own header comment and edit it; every setting it documents is
optional and has a sensible default without it.

## Security, testing, and limits

The short version is above: no third-party audit, threat models per
crate document exactly what's covered. The rest of this section points
at where the actual evidence lives rather than restating it here.

- **[`SECURITY.md`](SECURITY.md)**: dependency-audit policy (`cargo
  audit`, currently accepted exceptions and why), the `zeroize`/
  sensitive-data policy, and a summary of what's fail-closed by automated
  test versus by OS-level design.
- **[`UNSAFE_AUDIT.md`](UNSAFE_AUDIT.md)**: every `unsafe` block in the
  workspace, what invariant it relies on, and whether a safe alternative
  exists.
- **[`HARDENING.md`](HARDENING.md)**: the cross-cutting hardening pass
  tying the above together, plus fail-closed test coverage added on top
  of the architecture.

Run the automated checks locally:

```sh
cargo build --workspace
cargo test --workspace
bash scripts/audit.sh   # or scripts/audit.ps1 on Windows
```

## Fuzzing

`fuzz/` fuzzes the parts of the workspace that parse untrusted external
input (incoming DNS datagrams, the third-party IP-info service's
response); see [`fuzz/FUZZING.md`](fuzz/FUZZING.md) for targets, corpus,
and findings, including one real crash found and fixed.

**On Windows, fuzzing requires WSL.** `cargo-fuzz`/libFuzzer need LLVM
sanitizer and coverage instrumentation (`-Z sanitizer=address`,
SanitizerCoverage) that the MSVC toolchain doesn't support: only the
`x86_64-unknown-linux-gnu` target does. The rest of the workspace builds
and tests normally on Windows; only the fuzzing step needs a Linux
environment:

```sh
# One-time setup, inside WSL (Ubuntu):
sudo apt-get install -y pkg-config libssl-dev
rustup toolchain install nightly --profile minimal
cargo install cargo-fuzz --locked

# From WSL, cd into the repo via its /mnt/c/... path, then:
cd fuzz
cargo fuzz build
cargo fuzz run dns_relay_parse -- -max_total_time=300
cargo fuzz run fingerprint_report_parse -- -max_total_time=300
```

A found crash is saved under `fuzz/artifacts/<target>/`; reproduce with
`cargo fuzz run <target> artifacts/<target>/<crash-file>`.

## Chaos tests (network-failure injection)

`chaos/` simulates realistic network failures (a permitted connection
dying mid-transfer, an unreachable encrypted DNS resolver,
`blackhole-core` itself crashing, a simulated reboot) against the real
code (real `nft`, real network namespaces, real killed processes) and
verifies the result stays fail-closed. See
[`chaos/README.md`](chaos/README.md).

**Linux only, and needs root** (network namespaces plus nftables plus
setuid probes): not run by `cargo test --workspace`, and, like `fuzz/`,
`chaos/` is deliberately its own standalone workspace, not a member of
the root one.

```sh
./chaos/scripts/install_prereqs.sh   # once per machine
sudo -E ./chaos/scripts/run_chaos_tests.sh
```

## Contributing

There's no public repository for this project yet (see the
[Installation](#installation) section above), so there's no issue tracker
or pull request flow to point to right now. It's licensed under the
[MIT License](LICENSE); if
you have a clone and want to change something, the per-crate
`THREAT_MODEL.md` files and `SECURITY.md` are the right starting context
before touching anything security-relevant.
