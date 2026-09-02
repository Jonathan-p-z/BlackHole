//! Scenario 3: `blackhole-core` itself crashes — the firewall state must
//! stay in its last safe (blocking) state, with no process left alive to
//! maintain it. This is the structural fail-closed guarantee documented in
//! `blackhole-core/THREAT_MODEL.md` ("Everything else is dropped by the
//! firewall's default policy, at the OS level, independent of this
//! process ... staying alive") — this test is what actually exercises it
//! against a real `nft`, rather than only trusting the doc comment.

use std::time::Duration;

use blackhole_chaos::{kill_pid, spawn_and_wait_for_line, spawn_udp_echo, NetnsSandbox};

const DISALLOWED_UID: u32 = 65124;
const PROBE_TIMEOUT_MS: &str = "1500";

// Multi-threaded: see the identical note in scenario_1_tor_circuit_cut.rs
// — the spawned UDP echo listener needs a free OS thread to actually reply
// while this test makes blocking `std::process` calls.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn firewall_state_survives_the_enabling_process_being_killed() {
    let sandbox = NetnsSandbox::create(3);
    let ruleset_path = std::env::temp_dir().join(format!("blackhole-chaos-3-ruleset-{}.rules", std::process::id()));
    let _ = std::fs::remove_file(&ruleset_path);

    let outside = sandbox.outside_addr(9002);
    spawn_udp_echo(outside).await;

    let mut enabled = spawn_and_wait_for_line(
        sandbox.exec(env!("CARGO_BIN_EXE_chaos_enable_and_hang")).arg(&ruleset_path),
        "READY",
        Duration::from_secs(10),
    );
    let pid = enabled.id();

    assert!(sandbox.table_exists(), "sanity: kill switch must be live before the crash");
    let listing_before = sandbox.nft_table_listing().unwrap();
    assert!(listing_before.contains("policy drop"));

    // Positive control, taken *before* the crash: the permitted UID (root
    // — see scenario 1's doc comment on why) really can reach the outside
    // listener right now, so a later "blocked" result for a different UID
    // is evidence of the firewall discriminating, not just "nothing works
    // in this sandbox."
    assert!(
        probe(&sandbox, 0, outside),
        "sanity: the permitted UID must be able to reach the outside listener before the crash"
    );

    // The crash: SIGKILL, no graceful shutdown, no chance to run any
    // cleanup code — the OS-crash scenario the prompt asked for, not a
    // clean `disable()`.
    kill_pid(pid);
    let _ = enabled.wait();
    tokio::time::sleep(Duration::from_millis(300)).await;

    // No blackhole-core-equivalent process is alive anywhere at this point
    // — everything below checks the OS's own state, not asks a process
    // about itself.
    assert!(
        sandbox.table_exists(),
        "the nftables table must still exist with the enabling process dead — \
         firewall state must not depend on any process staying alive"
    );
    let listing_after = sandbox.nft_table_listing().unwrap();
    assert!(
        listing_after.contains("policy drop"),
        "must still be in its last safe (default-deny) state after the crash:\n{listing_after}"
    );

    // And it's not just an inert table object: traffic is still actually
    // being dropped for anyone but the permitted UID, with nothing alive
    // to be enforcing that decision moment to moment.
    assert!(
        !probe(&sandbox, DISALLOWED_UID, outside),
        "a disallowed UID must still be blocked after the crash, with no live process \
         enforcing it — the positive control above already proved the listener itself works"
    );

    let _ = std::fs::remove_file(&ruleset_path);
}

fn probe(sandbox: &NetnsSandbox, uid: u32, target: std::net::SocketAddr) -> bool {
    sandbox
        .exec_as_uid(uid, env!("CARGO_BIN_EXE_chaos_udp_probe"))
        .arg(target.to_string())
        .arg(PROBE_TIMEOUT_MS)
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}
