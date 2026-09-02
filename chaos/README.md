# blackhole-chaos

Network-failure injection tests: real integration tests that simulate
realistic failure scenarios against the real `blackhole-core`/`blackhole-dns`
code (real `nft`, real network namespaces, real killed processes — nothing
mocked at the OS level) and verify the result stays fail-closed, not just
in the nominal case.

**Linux only. Must run as root. Not part of the root `Cargo.toml` workspace**
— same reasoning as `fuzz/`: this is a separate, standalone, root-requiring,
slow test suite that shouldn't affect an ordinary `cargo build --workspace`
on any platform. See `Cargo.toml`'s own comment.

## The four scenarios

| # | File | What it proves |
| --- | --- | --- |
| 1 | `tests/scenario_1_tor_circuit_cut.rs` | Killing the process driving a permitted connection (standing in for a Tor circuit being cut mid-transfer) never opens a window — before, during, or immediately after — for a different, disallowed process's traffic to leave the sandbox. |
| 2 | `tests/scenario_2_dns_timeout_no_fallback.rs` | An unreachable encrypted DNS resolver produces `SERVFAIL` with no answers, never a silent fallback query to a plaintext resolver — and the real `leak::enforce_on_leak` → real `LinuxGuard::enable()` path fires end-to-end against real nftables, not just the `FakeGuard` unit tests in `blackhole-dns/src/leak.rs`. |
| 3 | `tests/scenario_3_core_crash_state_persists.rs` | SIGKILLing the process that enabled the kill switch leaves the nftables table — and its default-deny policy — exactly as it was, provably enforced with **no process alive anywhere** to be maintaining it. |
| 4 | `tests/scenario_4_reboot_restores_firewall.rs` | Simulating what a reboot does to nftables (its ruleset lives in kernel memory only) and then running the real `blackhole-core restore-firewall` binary restores the same blocking state — and a machine that never enabled the kill switch correctly restores *nothing*. This scenario is what led to `BOOT_PERSISTENCE.md`/`packaging/systemd/`: before this pass, nothing restored the ruleset after a reboot at all. |

Each file's own doc comment explains the honest reinterpretation where the
prompt's scenario doesn't map onto something directly reproducible in CI
(there's no real Tor circuit or real machine reboot here) — see especially
scenario 1's comment on why "cut the circuit" reduces to "kill the
permitted process" given how the firewall actually works.

## Prerequisites

- Linux (native, or WSL2 — the kernel needs network namespace and nftables
  support; most current distributions' default kernels have both).
- Root (`sudo`) — network namespaces, nftables, and the disallowed-UID
  probes (`setpriv --reuid`) all need `CAP_NET_ADMIN`/`CAP_SETUID`.
- `nftables`, `iproute2` (`ip netns`, `ip link`), `util-linux` (`setpriv`).
  Install with `./scripts/install_prereqs.sh` (reads clearly, asks for
  `sudo` itself, nothing hidden).
- A normal Rust toolchain (stable; no nightly/cargo-fuzz needed here,
  unlike `fuzz/`).

## Running it

```sh
./chaos/scripts/install_prereqs.sh   # once per machine
sudo -E ./chaos/scripts/run_chaos_tests.sh
```

That script builds the real `blackhole-core`/`blackhole-dns` binaries from
the *root* workspace first (scenarios 2 and 4 exercise those directly, not
reimplementations — see "Why real binaries, not mocks" below), then runs
`cargo test` inside `chaos/`'s own standalone workspace.

To run a single scenario directly while iterating:

```sh
sudo -E env -C chaos cargo test --test scenario_1_tor_circuit_cut -- --nocapture
```

### CI

`.github/workflows/chaos.yml` runs the same steps on `ubuntu-latest`
(GitHub-hosted runners have passwordless `sudo` and run as a real VM, not a
restricted container, so `ip netns`/nftables/`setpriv` all work the same as
on any Ubuntu box). If GitHub-hosted runners ever restrict that, the
fallback is a self-hosted dedicated Linux runner — swap `runs-on` in that
workflow; nothing else about the suite changes. **Not yet verified against
a real GitHub Actions run** (this repo has no public remote to push the
workflow to yet — see the root README's own installation section for that
same caveat) — flagged here rather than silently assumed working.

## Why real binaries, not mocks

Every scenario exercises the actual shipped code, not a reimplementation:

- `LinuxGuard::enable`/`disable`/`status` (via `chaos_enable_and_hang`, a
  thin wrapper needed only to avoid a real Tor bootstrap — see below).
- The real `blackhole-core restore-firewall` binary, built from the root
  workspace, for scenario 4.
- The real `blackhole-dns serve` binary, built from the root workspace,
  for scenario 2's relay.
- The real `blackhole_dns::leak::check`/`enforce_on_leak` (via
  `chaos_dns_enforce`, again only wrapped to avoid a real Tor bootstrap).

The only things standing in for something real:

- **`blackhole_chaos::AlwaysReadyTor`**, a trivial `TorBackend` used
  wherever a helper needs to construct a real `LinuxGuard` without
  bootstrapping actual Tor (arti or the subprocess backend). This is safe
  to stand in for: `LinuxGuard::enable()`/`disable()` never call any
  `TorBackend` method at all (only `status()`/`new_identity()` do — see
  `blackhole-core/src/platform/linux.rs`), so nothing about the firewall
  behavior under test depends on Tor being real. Matches this project's
  existing rule against exercising a real Tor bootstrap in CI (see
  `fuzz/FUZZING.md` and `blackhole-core/tests/subprocess_backend.rs`,
  which take the same approach with `fake_tor`).
- **No real Cloudflare/Quad9/Mullvad DNS servers** — `NetnsSandbox` gives
  every scenario an isolated network namespace with *no default route* at
  all, so a real `EncryptedResolver` genuinely, deterministically fails to
  reach any of them (`ENETUNREACH`), which is indistinguishable from a
  real timeout at every layer this suite checks (the code path taken, the
  reply produced, the leak enforcement triggered) — just fast and
  reproducible instead of slow and CI-flaky.
- **No real machine reboot** (scenario 4) — see that file's own doc
  comment for exactly what's simulated and why it's a faithful proxy.

## Architecture

- **`src/lib.rs`**: shared test-support code.
  - `NetnsSandbox`: creates an isolated network namespace with a private
    veth link to the host's default namespace (`Drop` tears it down —
    deleting the namespace also destroys both veth ends and any nftables
    table that lived only inside it). `outside_ip` is directly reachable
    from the test process itself with no routing; `inside_ip` is what
    processes launched via `exec`/`exec_as_uid` see as their own address.
    No default route exists inside the namespace at all — see scenario 2.
  - `exec`/`exec_as_uid`: build an `ip netns exec [setpriv --reuid=<uid>]`-
    wrapped `Command` targeting the sandbox. Arbitrary numeric UIDs (no
    real `/etc/passwd` entry needed) stand in for "a different, disallowed
    user on the same machine" — deliberately *not* uid 0, since the
    realistic deployment model has `blackhole-core enable` itself running
    as root (it needs `CAP_NET_ADMIN` for `nft`), which is also why the
    "permitted" side of every scenario runs as root, matching the already-
    documented UID-scoping caveat in `platform/linux.rs`'s module doc.
  - `spawn_udp_echo`, `spawn_and_wait_for_line`, `kill_pid`,
    `workspace_binary`: smaller pieces described in their own doc comments.
- **`src/bin/`**: three tiny helper binaries, only as large as they need to
  be to avoid a real Tor bootstrap (see above) — `chaos_enable_and_hang`,
  `chaos_dns_enforce`, `chaos_udp_probe` (a UDP echo probe run as a
  specific UID, since a plain in-process socket can't do that per-call
  without `setuid`-ing the whole test binary).
- **`tests/`**: one file per scenario, described in the table above.

## A note on what this suite found

Scenario 4's premise — "the firewall should still be blocking after a
reboot" — wasn't true of `blackhole-core` before this pass: nftables'
ruleset is kernel-memory-only, and nothing reapplied it at boot. That gap
is now closed (`enable()`/`disable()` persist/remove a ruleset file;
`blackhole-core restore-firewall` + the optional systemd unit in
`packaging/systemd/` reapply it) — see `BOOT_PERSISTENCE.md` for the full
story, including what it does and doesn't guarantee. Scenarios 1–3 describe
properties the design already claimed structurally
(`blackhole-core/THREAT_MODEL.md`); this suite is what actually exercises
those claims against a real `nft`, rather than only trusting the doc
comments and the `GuardStateMachine` unit tests (which mock the OS backend
entirely, by design — see `blackhole-core/src/guard.rs`).
