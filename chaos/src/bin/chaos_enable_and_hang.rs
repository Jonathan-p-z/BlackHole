//! Test-only helper: enables the real `LinuxGuard` kill switch (against a
//! trivial always-ready fake Tor backend — see [`blackhole_chaos::AlwaysReadyTor`]
//! — so no real Tor bootstrap is needed) and then blocks forever, standing
//! in for a live `blackhole-core enable`d process. Killed by the test
//! itself to simulate a crash or a circuit being cut mid-transfer — see
//! `tests/scenario_1_tor_circuit_cut.rs` and
//! `tests/scenario_3_core_crash_state_persists.rs`.
//!
//! Usage: `chaos_enable_and_hang <ruleset-path>`. Prints `READY` (and
//! flushes stdout) once the kill switch is confirmed enabled — the caller
//! should wait for that line before treating the sandbox as protected.

use std::io::Write;
use std::sync::Arc;

use blackhole_chaos::AlwaysReadyTor;
use blackhole_core::{NetworkGuard, PlatformGuard};

#[tokio::main]
async fn main() {
    let ruleset_path = std::env::args()
        .nth(1)
        .expect("usage: chaos_enable_and_hang <ruleset-path>");

    let guard = PlatformGuard::with_ruleset_path(Arc::new(AlwaysReadyTor), ruleset_path.into());
    guard
        .enable()
        .await
        .expect("kill switch enable() must succeed under chaos_enable_and_hang");

    println!("READY");
    std::io::stdout().flush().ok();

    // Block forever. The test kills this process's PID directly (SIGKILL)
    // to simulate an unexpected crash / circuit cut — no graceful shutdown
    // path is exercised here on purpose, that's not what these scenarios
    // test (see blackhole-core/tests/subprocess_backend.rs for the
    // analogous "child dies unexpectedly" test on the Tor-subprocess side).
    std::future::pending::<()>().await;
}
