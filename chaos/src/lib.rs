//! Shared test-support helpers for `blackhole-chaos`'s network-failure
//! integration tests — see `README.md` for what this crate is, why it
//! exists as its own standalone (non-workspace-member) crate, and what
//! each scenario in `tests/` actually proves.
//!
//! Everything here that touches the network runs inside an isolated Linux
//! network namespace ([`NetnsSandbox`]) connected to the test process only
//! by a private veth link — never the real host network — so a
//! default-deny firewall policy applied for a test can never affect the
//! machine running the test suite itself.

use std::io::{BufRead, BufReader};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::sync::mpsc;
use std::time::{Duration, Instant};

use blackhole_core::tor::{PermitTarget, TorBackend};
use blackhole_core::{BlackholeError, TorStatus};

/// Panics with a clear message if not running as root. Every scenario
/// needs `CAP_NET_ADMIN` (network namespaces, veth, nftables) and
/// `CAP_SETUID` (the disallowed-UID probes) — there's no meaningful
/// degraded mode, so failing fast with a clear reason beats a confusing
/// permission-denied error three steps into a test.
pub fn require_root() {
    // SAFETY: geteuid(2) takes no arguments, performs no pointer
    // dereferences, and cannot fail.
    let euid = unsafe { libc::geteuid() };
    assert_eq!(
        euid, 0,
        "blackhole-chaos tests must run as root (network namespaces + nftables + setuid probes \
         all need it) — see README.md's Prerequisites section. Try: sudo -E cargo test"
    );
}

/// Trivial `TorBackend` that's always ready — used by every chaos helper
/// binary that needs to construct a real `LinuxGuard` without bootstrapping
/// real Tor (arti or subprocess). `blackhole-core`'s own Linux firewall
/// backend never actually calls any `TorBackend` method during `enable()`
/// or `disable()` (only `status()`/`new_identity()` do), so this stand-in
/// is exactly as good as a real backend for every scenario here — none of
/// them exercise Tor bootstrap itself, which the project's own fuzzing and
/// subprocess-backend testing already deliberately excludes from CI (see
/// `fuzz/FUZZING.md` and `blackhole-core/tests/subprocess_backend.rs`).
pub struct AlwaysReadyTor;

#[async_trait::async_trait]
impl TorBackend for AlwaysReadyTor {
    async fn status(&self) -> TorStatus {
        TorStatus {
            bootstrap_percent: 100,
            ready_for_traffic: true,
            blocked_reason: None,
        }
    }

    async fn new_identity(&self) -> Result<(), BlackholeError> {
        Ok(())
    }

    fn permit_target(&self) -> PermitTarget {
        PermitTarget::ThisProcess
    }
}

/// Locate a real workspace binary (`blackhole-core`, `blackhole-dns`) built
/// from the *root* workspace — not this crate's own binaries, which Cargo
/// already exposes to `chaos/tests/*.rs` via the standard
/// `CARGO_BIN_EXE_<name>` mechanism since they're in this same package.
/// Cross-package `CARGO_BIN_EXE_*` isn't set by Cargo (this crate is
/// deliberately its own standalone workspace, not a member of the root
/// one — see `Cargo.toml`), so this instead looks in the root workspace's
/// own `target/{release,debug}/`, or an explicit
/// `BLACKHOLE_CHAOS_BIN_<NAME>` env override.
pub fn workspace_binary(name: &str) -> PathBuf {
    let env_key = format!("BLACKHOLE_CHAOS_BIN_{}", name.to_uppercase().replace('-', "_"));
    if let Some(p) = std::env::var_os(&env_key) {
        return PathBuf::from(p);
    }

    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let workspace_root = manifest_dir
        .parent()
        .expect("chaos/ is always a subdirectory of the repo root");

    for profile in ["release", "debug"] {
        let candidate = workspace_root.join("target").join(profile).join(name);
        if candidate.is_file() {
            return candidate;
        }
    }

    panic!(
        "could not find workspace binary '{name}' in {}/target/{{release,debug}}/ — build it \
         first from the repo root (e.g. `cargo build -p blackhole-core -p blackhole-dns --bins`), \
         or set {env_key} explicitly. See chaos/README.md.",
        workspace_root.display()
    );
}

/// An isolated Linux network namespace with a private veth link to the
/// host's default namespace, so a test can apply a default-deny firewall
/// policy inside it without ever touching the real machine's connectivity.
///
/// `outside_ip` is reachable from the *test process itself* (which runs in
/// the host's default namespace, unaffected by anything applied inside the
/// sandbox) with no extra routing — it's the directly-connected veth peer
/// address. `inside_ip` is what processes launched via [`Self::exec`] /
/// [`Self::exec_as_uid`] see as their own address. Deliberately has **no
/// default route** at all: any attempt from inside to reach a real
/// internet address (e.g. a real DoH provider's IP) fails immediately and
/// deterministically (`ENETUNREACH`) rather than hanging on a real
/// timeout — see `tests/scenario_2_dns_timeout_no_fallback.rs` for why
/// that's exactly the failure mode this suite wants.
pub struct NetnsSandbox {
    pub name: String,
    pub inside_ip: Ipv4Addr,
    pub outside_ip: Ipv4Addr,
    veth_outside: String,
    veth_inside: String,
}

impl NetnsSandbox {
    /// `id` picks the `10.200.<id>.0/30` subnet and the `blackhole-chaos-<id>`
    /// namespace/interface names — give each test scenario (and each test
    /// function within a scenario, if it creates more than one sandbox) its
    /// own `id` so concurrent `cargo test` runs never collide.
    pub fn create(id: u8) -> Self {
        require_root();

        let name = format!("blackhole-chaos-{id}");
        let veth_outside = format!("chv{id}o");
        let veth_inside = format!("chv{id}i");
        let inside_ip = Ipv4Addr::new(10, 200, id, 2);
        let outside_ip = Ipv4Addr::new(10, 200, id, 1);

        // Best-effort cleanup of a leftover namespace from a previous
        // crashed/interrupted run before creating a fresh one — `ip netns
        // add` fails outright if the name already exists.
        let _ = run(Command::new("ip").args(["netns", "delete", &name]));

        run_checked(Command::new("ip").args(["netns", "add", &name]), "ip netns add");
        run_checked(
            Command::new("ip").args(["link", "add", &veth_outside, "type", "veth", "peer", "name", &veth_inside]),
            "ip link add (veth pair)",
        );
        run_checked(
            Command::new("ip").args(["link", "set", &veth_inside, "netns", &name]),
            "ip link set (move veth end into namespace)",
        );
        run_checked(
            Command::new("ip").args(["addr", "add", &format!("{outside_ip}/30"), "dev", &veth_outside]),
            "ip addr add (outside)",
        );
        run_checked(Command::new("ip").args(["link", "set", &veth_outside, "up"]), "ip link set up (outside)");
        run_checked(
            Command::new("ip").args(["netns", "exec", &name, "ip", "addr", "add", &format!("{inside_ip}/30"), "dev", &veth_inside]),
            "ip addr add (inside)",
        );
        run_checked(
            Command::new("ip").args(["netns", "exec", &name, "ip", "link", "set", &veth_inside, "up"]),
            "ip link set up (inside)",
        );
        run_checked(
            Command::new("ip").args(["netns", "exec", &name, "ip", "link", "set", "lo", "up"]),
            "ip link set up (inside loopback)",
        );

        Self { name, inside_ip, outside_ip, veth_outside, veth_inside }
    }

    pub fn outside_addr(&self, port: u16) -> SocketAddr {
        SocketAddr::new(IpAddr::V4(self.outside_ip), port)
    }

    pub fn inside_addr(&self, port: u16) -> SocketAddr {
        SocketAddr::new(IpAddr::V4(self.inside_ip), port)
    }

    /// Build (not spawn) a `Command` that runs `program` inside this
    /// namespace, as whatever user invoked the test (root — see
    /// [`require_root`]). Caller adds args/env and calls `.spawn()`/
    /// `.output()`/`.status()`.
    pub fn exec(&self, program: impl AsRef<std::ffi::OsStr>) -> Command {
        let mut cmd = Command::new("ip");
        cmd.args(["netns", "exec", &self.name]).arg(program);
        cmd
    }

    /// Same as [`Self::exec`], but the target program runs as `uid` (via
    /// `setpriv --reuid --regid --clear-groups`) instead of root. `uid`
    /// doesn't need a real `/etc/passwd` entry — arbitrary numeric UIDs
    /// work fine for `setpriv` given `CAP_SETUID`, which the root process
    /// running these tests has.
    pub fn exec_as_uid(&self, uid: u32, program: impl AsRef<std::ffi::OsStr>) -> Command {
        let mut cmd = Command::new("ip");
        cmd.args(["netns", "exec", &self.name, "setpriv"])
            .arg(format!("--reuid={uid}"))
            .arg(format!("--regid={uid}"))
            .arg("--clear-groups")
            .arg("--")
            .arg(program);
        cmd
    }

    /// `nft list table inet blackhole`'s stdout, inside this namespace —
    /// `None` if the table doesn't exist (nftables state, like everything
    /// else about a network namespace's networking, is itself
    /// namespace-scoped, so this only ever sees what's inside `self`, never
    /// the host's own ruleset).
    pub fn nft_table_listing(&self) -> Option<String> {
        let output = self.exec("nft").args(["list", "table", "inet", "blackhole"]).output().ok()?;
        output.status.success().then(|| String::from_utf8_lossy(&output.stdout).into_owned())
    }

    pub fn table_exists(&self) -> bool {
        self.nft_table_listing().is_some()
    }

    /// Deletes the `inet blackhole` table if present — used to simulate
    /// what a real reboot does to nftables' kernel-memory-only ruleset
    /// (see `tests/scenario_4_reboot_restores_firewall.rs`). Ignores
    /// "already absent" so it's safe to call unconditionally.
    pub fn simulate_reboot_wipe(&self) {
        let _ = run(self.exec("nft").args(["delete", "table", "inet", "blackhole"]));
    }
}

impl Drop for NetnsSandbox {
    fn drop(&mut self) {
        // Deleting the namespace also destroys both veth ends (the inside
        // one directly; the outside one because a veth pair is destroyed
        // as a unit when either end goes away) and every nftables table
        // that lived only inside this namespace — no separate cleanup
        // needed. Best-effort: a test that panicked mid-setup may not have
        // gotten far enough for there to be anything to clean up.
        let _ = run(Command::new("ip").args(["netns", "delete", &self.name]));
        let _ = (&self.veth_outside, &self.veth_inside); // silence unused-field warnings; kept for Debug/diagnostics
    }
}

/// Bind a UDP echo listener at `bind_addr` (any datagram it receives is
/// sent straight back to the sender) and let it run in the background for
/// the rest of the test process's lifetime. Stands in for "the outside
/// world" a probe is trying to reach — bound on the *host* side of a
/// [`NetnsSandbox`]'s veth link (the test process itself, not inside the
/// namespace), so whether a probe launched inside the sandbox reaches it
/// is a direct, real measurement of what the sandbox's firewall actually
/// allowed out, not a mocked stand-in.
pub async fn spawn_udp_echo(bind_addr: SocketAddr) {
    let socket = tokio::net::UdpSocket::bind(bind_addr)
        .await
        .unwrap_or_else(|e| panic!("bind UDP echo listener at {bind_addr}: {e}"));

    tokio::spawn(async move {
        let mut buf = [0u8; 256];
        while let Ok((len, src)) = socket.recv_from(&mut buf).await {
            let _ = socket.send_to(&buf[..len], src).await;
        }
    });
}

/// Spawn `cmd` (stdout/stderr piped) and block until it prints a line
/// exactly equal to `expected_line`, or `timeout` elapses. Used to know a
/// long-running helper (e.g. `chaos_enable_and_hang`) has actually
/// finished its setup — kill switch genuinely live — before a test starts
/// probing it, rather than guessing with a fixed sleep. Returns the
/// spawned [`Child`] so the caller can kill it later by PID (or just drop
/// it, which does *not* kill it — these helpers are meant to keep running
/// after this function returns).
pub fn spawn_and_wait_for_line(cmd: &mut Command, expected_line: &str, timeout: Duration) -> Child {
    let mut child = cmd
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap_or_else(|e| panic!("failed to spawn helper process: {e}"));

    let stdout = child.stdout.take().expect("stdout was piped");
    let (tx, rx) = mpsc::channel();
    std::thread::spawn(move || {
        let mut reader = BufReader::new(stdout);
        let mut line = String::new();
        loop {
            line.clear();
            match reader.read_line(&mut line) {
                Ok(0) | Err(_) => break, // EOF or read error
                Ok(_) => {
                    if tx.send(line.trim_end().to_string()).is_err() {
                        break;
                    }
                }
            }
        }
    });

    let deadline = Instant::now() + timeout;
    loop {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            let _ = child.kill();
            panic!("timed out after {timeout:?} waiting for a helper process to print {expected_line:?}");
        }
        match rx.recv_timeout(remaining) {
            Ok(line) if line == expected_line => return child,
            Ok(_other_line) => continue,
            Err(_disconnected) => {
                let _ = child.kill();
                panic!("helper process exited (or closed stdout) before printing {expected_line:?}");
            }
        }
    }
}

/// SIGKILL a process by PID outright, bypassing any graceful shutdown —
/// simulates an unexpected crash (or, for scenario 1, a Tor circuit being
/// torn down mid-transfer along with the process driving it), the same
/// way `blackhole-core/tests/subprocess_backend.rs` does for the
/// Tor-subprocess-child-dies scenario.
pub fn kill_pid(pid: u32) {
    let _ = run(Command::new("kill").args(["-KILL", &pid.to_string()]));
}

fn run(cmd: &mut Command) -> std::io::Result<std::process::Output> {
    cmd.stdout(Stdio::piped()).stderr(Stdio::piped()).output()
}

fn run_checked(cmd: &mut Command, what: &str) {
    match run(cmd) {
        Ok(output) if output.status.success() => {}
        Ok(output) => panic!("{what} failed (status {}): {}", output.status, String::from_utf8_lossy(&output.stderr)),
        Err(e) => panic!("{what} failed to run: {e}"),
    }
}
