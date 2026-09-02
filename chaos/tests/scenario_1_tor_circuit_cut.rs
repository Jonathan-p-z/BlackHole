//! Scenario 1: "Tor circuit cut mid-transfer" — the kill switch must keep
//! blocking non-permitted traffic continuously, both while a permitted
//! connection is active and immediately after it dies unexpectedly.
//!
//! There's no real Tor circuit in this sandbox (per the project's own rule
//! against exercising a real Tor bootstrap in CI — see `fuzz/FUZZING.md`
//! and `blackhole-core/tests/subprocess_backend.rs`). What actually makes
//! the kill switch's fail-closed guarantee hold, per
//! `blackhole-core/THREAT_MODEL.md`, is that nftables' default-deny output
//! policy is entirely independent of Tor's health: it only ever looks at
//! which UID sent a packet, never whether that UID's Tor circuit is up.
//! So "the circuit gets cut mid-transfer" is simulated the way it actually
//! matters at the firewall layer: the permitted process (standing in for
//! blackhole-core + its Tor backend) is killed outright while a disallowed
//! process keeps probing throughout — before, during, and after. If
//! killing the permitted side ever opened even a brief window for that
//! disallowed traffic to get through, this test would catch it.

use std::time::Duration;

use blackhole_chaos::{kill_pid, spawn_and_wait_for_line, spawn_udp_echo, NetnsSandbox};

const DISALLOWED_UID: u32 = 65123;
const PROBE_TIMEOUT_MS: &str = "1500";

// Multi-threaded: `spawn_udp_echo`'s background task must keep running
// (and actually reply) *while* this test makes blocking `std::process`
// calls (`.status()`, `spawn_and_wait_for_line`'s `.spawn()`+thread) — a
// single-threaded runtime would stall the echo task for the duration of
// every blocking call on the same OS thread, turning a real "reached the
// listener" into a false-negative timeout.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn killing_the_permitted_process_never_opens_a_window_for_other_traffic() {
    let sandbox = NetnsSandbox::create(1);
    let ruleset_path = std::env::temp_dir().join(format!("blackhole-chaos-1-ruleset-{}.rules", std::process::id()));
    let _ = std::fs::remove_file(&ruleset_path);

    // Stands in for "the Tor guard relay" / whatever a permitted connection
    // actually talks to — bound on the host side of the veth link, so
    // whether a probe reaches it is a direct measurement of the sandbox's
    // real firewall behavior, not a mock.
    let outside = sandbox.outside_addr(9001);
    spawn_udp_echo(outside).await;

    // Enable the real kill switch inside the sandbox, as root — the
    // realistic deployment model (blackhole-core itself needs CAP_NET_ADMIN
    // for `nft`, so it runs elevated; see the module doc on
    // blackhole-core/src/platform/linux.rs about the resulting "any process
    // by the same UID" scoping this relies on).
    let mut enabled = spawn_and_wait_for_line(
        sandbox.exec(env!("CARGO_BIN_EXE_chaos_enable_and_hang")).arg(&ruleset_path),
        "READY",
        Duration::from_secs(10),
    );
    let permitted_pid = enabled.id();

    assert!(sandbox.table_exists(), "kill switch must be live before this test probes it");

    // A disallowed (non-permitted) UID's traffic must be blocked *during*
    // the "transfer" — i.e. while the permitted process is alive and well,
    // not just after something has already gone wrong.
    assert!(
        !probe(&sandbox, DISALLOWED_UID, outside),
        "a disallowed UID's traffic must be blocked while the kill switch is enabled, \
         even while the permitted process is alive"
    );

    // Simulate the circuit being cut: the permitted process dies
    // unexpectedly (SIGKILL, no graceful shutdown).
    kill_pid(permitted_pid);
    let _ = enabled.wait();

    // The core assertion: killing it must not open any window, immediately
    // or shortly after, for other traffic to leak out in the clear.
    assert!(
        !probe(&sandbox, DISALLOWED_UID, outside),
        "disallowed traffic must still be blocked immediately after the permitted process dies"
    );
    tokio::time::sleep(Duration::from_millis(500)).await;
    assert!(
        !probe(&sandbox, DISALLOWED_UID, outside),
        "disallowed traffic must still be blocked shortly after the permitted process dies — \
         no delayed fail-open window either"
    );

    assert!(
        sandbox.table_exists(),
        "the nftables table itself must still be present with no process left alive to maintain it"
    );
    let listing = sandbox.nft_table_listing().unwrap();
    assert!(
        listing.contains("policy drop"),
        "the output chain's default-deny policy must still be in place:\n{listing}"
    );

    let _ = std::fs::remove_file(&ruleset_path);
}

/// True if a UDP probe sent from `uid` inside `sandbox` reaches `target`
/// and gets echoed back within the timeout.
fn probe(sandbox: &NetnsSandbox, uid: u32, target: std::net::SocketAddr) -> bool {
    sandbox
        .exec_as_uid(uid, env!("CARGO_BIN_EXE_chaos_udp_probe"))
        .arg(target.to_string())
        .arg(PROBE_TIMEOUT_MS)
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}
