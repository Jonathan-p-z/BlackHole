# BlackHole

A privacy-hardening toolkit: a fail-closed network kill switch, an
anti-DNS-leak layer, a status TUI, and a local traceability auditor — see
each crate's own docs for details. New here? [`QUICKSTART.md`](QUICKSTART.md)
is the 5-minute version of this section.

## Installation

Two paths, both land in the same place: your own build of the binaries,
installed for your user only, never root/Administrator.

### Installation rapide (the install script)

```sh
# Linux / macOS, from inside a clone of this repo:
./install.sh

# Windows (PowerShell), from inside a clone of this repo:
.\install.ps1
```

This compiles the workspace with `cargo build --release`, copies the
resulting binaries to a per-user directory (`~/.local/bin`, or
`%USERPROFILE%\.local\bin` on Windows), and — only if one doesn't already
exist — drops a commented starter config (see
[`config.example.toml`](config.example.toml)). It prints what it's about
to do before doing it; it never touches anything outside your user
profile, and never requests elevation.

**Read the script before you run it.** It downloads nothing and executes
code on your machine (`cargo build`, which itself pulls and compiles
dependencies) — both scripts are deliberately kept short specifically so
that's a quick read, not a leap of faith. There's no `curl | sh` one-liner
yet because there's no public release to fetch: this project doesn't have
a public GitHub repo or binary releases at the time of writing, so both
scripts currently assume you're running them from inside a local clone.
Once that changes, this section will document the real one-liner (and
checksum/signature verification for the precompiled binaries, and a
winget/Scoop package for Windows) — not before, since promising either
today would point at something that doesn't exist.

### Installation manuelle / depuis les sources

For auditing the code before it touches your machine, or if you'd rather
not run either install script at all:

```sh
cargo build --release --workspace --bins
# or, for a single module — e.g. what install.sh/install.ps1 do per binary:
cargo install --path blackhole-core
cargo install --path blackhole-dns
cargo install --path blackhole-dashboard
cargo install --path blackhole-fingerprint
```

(This is a Cargo workspace with several binary crates, not one single
package — `cargo install --path .` from the repo root won't resolve to a
specific binary on its own; `--path <crate-dir>` per module, as above,
does.) Then, optionally, copy [`config.example.toml`](config.example.toml)
to the location noted in its own header comment and edit it — every
setting it documents is optional and has a sensible default without it.

## Workspace layout

| Crate | Purpose |
| --- | --- |
| `blackhole-core` | Fail-closed kill switch (nftables/Linux, WFP/Windows) + Tor orchestration — `arti` in-process by default, or the official `tor` binary as a subprocess (see [`TOR_BACKENDS.md`](TOR_BACKENDS.md)). Linux firewall state survives a reboot — see [`BOOT_PERSISTENCE.md`](BOOT_PERSISTENCE.md). |
| `blackhole-dns` | Anti-DNS-leak: forces encrypted DNS (DoH/DoT), detects leaks, can trigger the kill switch. |
| `blackhole-dashboard` | `ratatui` status TUI over the two modules above. |
| `blackhole-fingerprint` | Read-only local traceability audit (hostname/MAC/telemetry/public exposure). |
| `blackhole-mobile-ffi` | C-ABI scoring bridge shared with `blackhole-mobile-ios`. |
| `blackhole-mobile-ios` | SwiftUI + `PacketTunnelProvider` iOS app (separate, non-Cargo project). |

Each crate carries a `THREAT_MODEL.md`: what it protects, against what
adversary, and what it explicitly does not protect against.

## Security

See [`SECURITY.md`](SECURITY.md) for the dependency-audit policy (and its
currently accepted exceptions), the `zeroize`/sensitive-data policy, and a
summary of what's fail-closed by automated test vs. by OS-level design.
[`UNSAFE_AUDIT.md`](UNSAFE_AUDIT.md) lists every `unsafe` block in the
workspace and why it's there.

```sh
cargo build --workspace
cargo test --workspace
bash scripts/audit.sh   # or scripts/audit.ps1 on Windows
```

## Fuzzing

`fuzz/` fuzzes the parts of the workspace that parse untrusted external
input (incoming DNS datagrams, the third-party IP-info service's
response) — see [`fuzz/FUZZING.md`](fuzz/FUZZING.md) for targets, corpus,
and findings.

**On Windows, fuzzing requires WSL.** `cargo-fuzz`/libFuzzer need LLVM
sanitizer and coverage instrumentation (`-Z sanitizer=address`, SanitizerCoverage)
that the MSVC toolchain doesn't support — only the `x86_64-unknown-linux-gnu`
target does. The rest of the workspace builds and tests normally on
Windows; only the fuzzing step needs a Linux environment:

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

`chaos/` simulates realistic network failures — a permitted connection
dying mid-transfer, an unreachable encrypted DNS resolver, `blackhole-core`
itself crashing, a simulated reboot — against the real code (real `nft`,
real network namespaces, real killed processes) and verifies the result
stays fail-closed. See [`chaos/README.md`](chaos/README.md).

**Linux only, and needs root** (network namespaces + nftables + setuid
probes): not run by `cargo test --workspace`, and — like `fuzz/` — `chaos/`
is deliberately its own standalone workspace, not a member of the root one.

```sh
./chaos/scripts/install_prereqs.sh   # once per machine
sudo -E ./chaos/scripts/run_chaos_tests.sh
```
