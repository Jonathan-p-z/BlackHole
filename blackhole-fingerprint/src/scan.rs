//! Orchestrates a full audit scan: runs every check module, and (unless
//! skipped) records the result to history and reports the diff against
//! the previous scan. Shared by the `blackhole-fingerprint` binary's
//! `scan`/`daemon` subcommands and any other orchestrator (e.g.
//! `blackhole-cli`) that wants "run a scan the same way the CLI does"
//! without re-implementing the history/diff bookkeeping itself.

use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use crate::error::FingerprintError;
use crate::history::{self, HistoryDiff, ScanRecord};
use crate::report::Report;
use crate::{exposure, network_identity, telemetry};

/// Run every check module and roll the findings into a [`Report`]. Does
/// not touch history; see [`scan_record_and_report`] for that.
pub fn run_scan(offline: bool) -> Report {
    let mut findings = Vec::new();

    match network_identity::checks() {
        Ok(f) => findings.extend(f),
        Err(e) => eprintln!("warning: network identity checks failed: {e}"),
    }

    findings.extend(telemetry::checks());

    if !offline {
        findings.extend(exposure::checks());
    }

    Report::new(findings)
}

/// `explicit`, if given, else [`history::default_history_path`].
pub fn resolve_history_path(explicit: Option<PathBuf>) -> Result<PathBuf, FingerprintError> {
    match explicit {
        Some(p) => Ok(p),
        None => history::default_history_path(),
    }
}

pub fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

/// Run a scan, print the report, record it to `history_path` (unless
/// `no_history`), and, if there was a previous scan, print the diff
/// against it and warn loudly on a significant degradation. Shared by
/// `scan` and each `daemon` tick.
pub fn scan_record_and_report(
    offline: bool,
    no_history: bool,
    history_path: &Path,
) -> Result<Report, FingerprintError> {
    let report = run_scan(offline);
    println!("{report}");

    if no_history {
        return Ok(report);
    }

    let previous = history::load_all(history_path)?.into_iter().next_back();
    let record = ScanRecord::from_report(&report, now_unix());
    history::append(history_path, &record)?;

    if let Some(previous) = previous {
        let diff = HistoryDiff::compute(&previous, &record);
        if !diff.unchanged() {
            println!("\n--- change since last scan ---");
            println!("{diff}");
        }
        if diff.is_significant_degradation() {
            eprintln!(
                "\n/!\\ traceability has significantly worsened since the last scan (score {} -> {})",
                previous.score, record.score
            );
        }
    }

    Ok(report)
}
