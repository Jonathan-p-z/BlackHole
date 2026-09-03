//! End-to-end wiring tests against the real compiled `blackhole` binary,
//! covering the two subcommand paths that need neither root nor network
//! access: `scan --offline --no-history` and `scan diff`. The other
//! subcommands (`enable`/`disable`/`status`/`panic`/`dashboard`) all need
//! a live OS firewall backend, a real Tor bootstrap, or a terminal, so
//! they're covered instead by `src/main.rs`'s own `#[cfg(test)]`
//! CLI-parsing tests (verifying each parses into the `Command` variant
//! `main`'s `match` dispatches correctly), not executed here. Same
//! reasoning `blackhole-core/tests/subprocess_backend.rs` and `chaos/`
//! already document for not exercising a real Tor bootstrap in tests.

use std::process::Command;

fn blackhole_bin() -> &'static str {
    env!("CARGO_BIN_EXE_blackhole")
}

#[test]
fn scan_offline_no_history_runs_the_real_fingerprint_checks() {
    // `--offline` skips the network exposure check (no outbound HTTP
    // request) and `--no-history` skips touching any history file, so
    // this exercises `blackhole_fingerprint::run_scan`/`scan_record_and_report`
    // for real (the same local-only checks `network_identity`/`telemetry`
    // do) without needing network access or leaving anything on disk.
    let output = Command::new(blackhole_bin())
        .args(["scan", "--offline", "--no-history"])
        .output()
        .expect("run blackhole scan --offline --no-history");

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("BlackHole Fingerprint Report"),
        "expected the real Report's Display header in stdout, got:\n{stdout}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        stdout.contains("score:"),
        "expected a score line from the real Report, got:\n{stdout}"
    );
}

#[test]
fn scan_diff_reports_not_enough_history_against_an_empty_file() {
    let dir = std::env::temp_dir().join(format!(
        "blackhole-cli-scan-diff-empty-{}",
        std::process::id()
    ));
    std::fs::create_dir_all(&dir).unwrap();
    let history_path = dir.join("history.jsonl");
    let _ = std::fs::remove_file(&history_path);

    let output = Command::new(blackhole_bin())
        .args(["scan", "diff", "--history-path"])
        .arg(&history_path)
        .output()
        .expect("run blackhole scan diff");

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("not enough recorded scans yet to diff"),
        "got:\n{stdout}"
    );
    assert!(output.status.success());

    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn scan_diff_detects_a_real_change_between_two_crafted_scans() {
    // Craft two ScanRecords directly via the real `blackhole_fingerprint`
    // history API (append/from_report), then run the real `blackhole scan
    // diff` binary against that file: this proves the subcommand actually
    // calls `history::load_all` + `HistoryDiff::compute` + prints the
    // real `Display` impl, not a placeholder.
    use blackhole_fingerprint::history::{self, ScanRecord};
    use blackhole_fingerprint::report::{Category, Finding, Report, Severity};

    let dir = std::env::temp_dir().join(format!(
        "blackhole-cli-scan-diff-real-{}",
        std::process::id()
    ));
    std::fs::create_dir_all(&dir).unwrap();
    let history_path = dir.join("history.jsonl");
    let _ = std::fs::remove_file(&history_path);

    let previous = Report::new(vec![]);
    let previous_record = ScanRecord::from_report(&previous, 1_000);
    history::append(&history_path, &previous_record).unwrap();

    let current = Report::new(vec![Finding::new(
        Category::Telemetry,
        Severity::Medium,
        "DiagTrack service is running",
    )]);
    let current_record = ScanRecord::from_report(&current, 2_000);
    history::append(&history_path, &current_record).unwrap();

    let output = Command::new(blackhole_bin())
        .args(["scan", "diff", "--history-path"])
        .arg(&history_path)
        .output()
        .expect("run blackhole scan diff");

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("DiagTrack service is running"),
        "expected the new finding in the real diff output, got:\n{stdout}"
    );
    assert!(
        stdout.contains("score:"),
        "expected the real HistoryDiff Display's score line, got:\n{stdout}"
    );
    // A new Medium-severity finding is a 12-point penalty
    // (report::Severity::penalty), past the real
    // SIGNIFICANT_DEGRADATION_THRESHOLD of -10, so the real
    // HistoryDiff::is_significant_degradation() is true here and `scan
    // diff` must exit non-zero, the same real threshold check
    // `blackhole-fingerprint diff` itself uses.
    assert!(!output.status.success());

    std::fs::remove_dir_all(&dir).ok();
}
