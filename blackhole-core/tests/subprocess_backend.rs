//! Integration tests for `SubprocessTorBackend` against `fake_tor`
//! (`src/bin/fake_tor.rs`), a test double understanding just enough of the
//! real `tor` binary's CLI and control-port protocol to exercise process
//! management and control-port orchestration — no real `tor` binary, no
//! real Tor bootstrap, no network access, per the project's rule against
//! testing a real Tor bootstrap in CI. Cargo builds `fake_tor` as an
//! ordinary workspace binary and exposes its path via the
//! `CARGO_BIN_EXE_fake_tor` environment variable automatically.

use std::time::Duration;

use blackhole_core::tor::{PermitTarget, TorBackend};
use blackhole_core::tor_subprocess::{SubprocessConfig, SubprocessTorBackend};

fn fake_tor_config(test_name: &str, port_offset: u16) -> SubprocessConfig {
    let data_dir = std::env::temp_dir().join(format!(
        "blackhole-core-subprocess-test-{test_name}-{}",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&data_dir);
    SubprocessConfig {
        binary_path: Some(std::path::PathBuf::from(env!("CARGO_BIN_EXE_fake_tor"))),
        data_dir,
        // Distinct ports per test so parallel `cargo test` runs don't
        // collide on the same loopback port.
        socks_port: 29050 + port_offset,
        control_port: 29051 + port_offset,
    }
}

#[tokio::test]
async fn starts_and_reports_ready_via_the_fake_binary() {
    let config = fake_tor_config("starts", 0);
    let data_dir = config.data_dir.clone();

    let backend = SubprocessTorBackend::start(config)
        .await
        .expect("subprocess backend should start against fake_tor");

    let status = backend.status().await;
    assert!(
        status.ready_for_traffic,
        "fake_tor always reports 100%/done bootstrap"
    );
    assert_eq!(status.bootstrap_percent, 100);
    assert!(status.blocked_reason.is_none());

    std::fs::remove_dir_all(&data_dir).ok();
}

#[tokio::test]
async fn permit_target_is_the_child_binary_path_not_this_process() {
    let config = fake_tor_config("permit-target", 10);
    let data_dir = config.data_dir.clone();
    let expected_path = config.binary_path.clone().unwrap();

    let backend = SubprocessTorBackend::start(config).await.unwrap();

    match backend.permit_target() {
        PermitTarget::ChildProcess(path) => assert_eq!(path, expected_path),
        PermitTarget::ThisProcess => {
            panic!("subprocess backend must report ChildProcess, not ThisProcess")
        }
    }

    std::fs::remove_dir_all(&data_dir).ok();
}

#[tokio::test]
async fn new_identity_round_trips_through_the_control_port() {
    let config = fake_tor_config("newnym", 20);
    let data_dir = config.data_dir.clone();

    let backend = SubprocessTorBackend::start(config).await.unwrap();
    backend
        .new_identity()
        .await
        .expect("SIGNAL NEWNYM should succeed against fake_tor");

    std::fs::remove_dir_all(&data_dir).ok();
}

#[tokio::test]
async fn reports_faulted_status_when_the_child_process_dies_unexpectedly() {
    // The scenario the prompt asked to cover explicitly: blackhole-core's
    // child tor process dies out from under it (crash, killed by
    // something else, OOM — anything other than our own clean shutdown).
    // `status()` must surface that clearly rather than keep reporting a
    // healthy bootstrap. The kill switch's actual fail-closed guarantee
    // doesn't depend on this (the OS-level nftables/WFP rules persist
    // independent of any process, tor or blackhole-core, staying alive —
    // see THREAT_MODEL.md) — this test is specifically about *knowing*
    // the backend is down, not about whether traffic is still blocked.
    let config = fake_tor_config("child-dies", 30);
    let data_dir = config.data_dir.clone();

    let backend = SubprocessTorBackend::start(config).await.unwrap();

    // Sanity check: healthy before we kill it.
    assert!(backend.status().await.ready_for_traffic);

    // Simulate an unexpected death: kill the fake_tor process directly by
    // PID, bypassing the backend's own (graceful) shutdown path entirely,
    // exactly like an external crash or OOM-kill would.
    let pid = backend
        .child_id()
        .expect("child should still be running here");
    kill_process(pid);

    // Give the OS a moment to actually reap/report the exit.
    tokio::time::sleep(Duration::from_millis(500)).await;

    let status = backend.status().await;
    assert!(
        !status.ready_for_traffic,
        "must not report ready after the child died"
    );
    assert!(
        status.blocked_reason.is_some(),
        "must explain that the child is gone, not report a silent/empty status"
    );

    let new_identity_result = backend.new_identity().await;
    assert!(
        new_identity_result.is_err(),
        "must not claim success rotating identity on a dead backend"
    );

    std::fs::remove_dir_all(&data_dir).ok();
}

/// Kill process `pid` outright (SIGKILL-equivalent) — used to simulate the
/// fake_tor child dying unexpectedly, bypassing any graceful shutdown.
fn kill_process(pid: u32) {
    #[cfg(windows)]
    {
        let _ = std::process::Command::new("taskkill")
            .args(["/F", "/PID", &pid.to_string()])
            .output();
    }
    #[cfg(target_os = "linux")]
    {
        let _ = std::process::Command::new("kill")
            .args(["-KILL", &pid.to_string()])
            .output();
    }
}
