use std::path::PathBuf;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use blackhole_fingerprint::history::{self, HistoryDiff, ScanRecord};
use blackhole_fingerprint::report::Report;
use blackhole_fingerprint::{config, daemon, exposure, network_identity, telemetry};
use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(
    name = "blackhole-fingerprint",
    about = "Traceability audit: local identity, OS telemetry, network exposure"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Run the full audit, print a report, and record it to the local
    /// history file (unless `--no-history`).
    Scan {
        /// Skip the network exposure check (no outbound HTTP request).
        #[arg(long)]
        offline: bool,
        /// Don't record this scan to the history file.
        #[arg(long)]
        no_history: bool,
        /// History file path. Defaults to the platform's per-user data
        /// directory (see `history::default_history_path`).
        #[arg(long)]
        history_path: Option<PathBuf>,
    },
    /// Show what changed between the two most recent recorded scans.
    Diff {
        #[arg(long)]
        history_path: Option<PathBuf>,
    },
    /// Run a scan now, then again every `--interval-secs`, until killed.
    /// Each scan is recorded to history and checked for a significant
    /// degradation from the one before it, same as `scan` + `diff`
    /// combined on every tick.
    Daemon {
        /// Defaults to the config file's `[fingerprint] daemon_interval_secs`,
        /// or 86400 (once a day) if neither is set.
        #[arg(long)]
        interval_secs: Option<u64>,
        #[arg(long)]
        offline: bool,
        #[arg(long)]
        history_path: Option<PathBuf>,
    },
}

fn run_scan(offline: bool) -> Report {
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

fn resolve_history_path(explicit: Option<PathBuf>) -> anyhow::Result<PathBuf> {
    match explicit {
        Some(p) => Ok(p),
        None => Ok(history::default_history_path()?),
    }
}

fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

/// Print the report, record it to history (unless `no_history`), and — if
/// there was a previous scan — print the diff against it and warn loudly
/// on a significant degradation. Shared by `scan` and each `daemon` tick.
fn scan_record_and_report(
    offline: bool,
    no_history: bool,
    history_path: &std::path::Path,
) -> anyhow::Result<Report> {
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

fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Command::Scan {
            offline,
            no_history,
            history_path,
        } => {
            let history_path = resolve_history_path(history_path)?;
            let report = scan_record_and_report(offline, no_history, &history_path)?;

            if report.score() < 50 {
                std::process::exit(1);
            }
        }
        Command::Diff { history_path } => {
            let history_path = resolve_history_path(history_path)?;
            let records = history::load_all(&history_path)?;
            if records.len() < 2 {
                println!(
                    "not enough recorded scans yet to diff (need at least 2, have {})",
                    records.len()
                );
                return Ok(());
            }
            let current = &records[records.len() - 1];
            let previous = &records[records.len() - 2];
            let diff = HistoryDiff::compute(previous, current);
            println!("{diff}");

            if diff.is_significant_degradation() {
                std::process::exit(1);
            }
        }
        Command::Daemon {
            interval_secs,
            offline,
            history_path,
        } => {
            let history_path = resolve_history_path(history_path)?;
            let fp_config =
                config::load_from(&config::default_config_path()?).unwrap_or_else(|e| {
                    eprintln!("warning: ignoring config file ({e})");
                    config::FingerprintConfig::default()
                });
            let interval_secs = interval_secs
                .or(fp_config.daemon_interval_secs)
                .unwrap_or(86400);
            eprintln!(
                "blackhole-fingerprint daemon: scanning every {interval_secs}s (Ctrl+C to stop)"
            );

            daemon::run(
                Duration::from_secs(interval_secs),
                || {
                    let ts = now_unix();
                    eprintln!("\n=== scan at unix time {ts} ===");
                    scan_record_and_report(offline, false, &history_path)
                        .map(|_| ())
                        .map_err(|e| {
                            blackhole_fingerprint::error::FingerprintError::History(e.to_string())
                        })
                },
                || false,
            )?;
        }
    }

    Ok(())
}
