//! `blackhole`: a single orchestrator binary for the four BlackHole
//! modules, so a user doesn't need to know or launch four separate
//! binaries for everyday use. Every subcommand below calls the exact same
//! public functions each module's own binary already calls; nothing here
//! reimplements kill-switch, DNS, dashboard, or fingerprint logic. Each
//! module's own binary (`blackhole-core`, `blackhole-dns`,
//! `blackhole-dashboard`, `blackhole-fingerprint`) keeps working exactly
//! as before; this is an additional, optional layer, not a replacement.

use std::path::PathBuf;

use blackhole_core::config::{CoreConfig, TorBackendKind};
use blackhole_core::{NetworkGuard, PlatformGuard};
use blackhole_dns::EncryptedResolver;
use blackhole_dns::config::DnsConfig;
use blackhole_fingerprint::history;
use clap::{Args, Parser, Subcommand, ValueEnum};

#[derive(Parser)]
#[command(
    name = "blackhole",
    version,
    about = "Orchestrates the kill switch, anti-DNS-leak, dashboard, and traceability audit modules from one binary"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,

    /// Which Tor backend to use for `enable`/`disable`/`status`: "arti"
    /// (default, in-process, recommended) or "subprocess" (drives the
    /// official `tor` binary as a child process; see the root
    /// TOR_BACKENDS.md). Overrides the config file's `[core] tor_backend`
    /// when given. Not used by `dashboard`/`panic`, which always use arti
    /// (an existing limitation of blackhole-dashboard itself, not
    /// introduced here).
    #[arg(long, value_enum, global = true)]
    tor_backend: Option<TorBackendArg>,
}

#[derive(Clone, Copy, ValueEnum)]
enum TorBackendArg {
    Arti,
    Subprocess,
}

impl From<TorBackendArg> for TorBackendKind {
    fn from(a: TorBackendArg) -> Self {
        match a {
            TorBackendArg::Arti => TorBackendKind::Arti,
            TorBackendArg::Subprocess => TorBackendKind::Subprocess,
        }
    }
}

#[derive(Subcommand, Debug, PartialEq, Eq)]
enum Command {
    /// Bootstrap Tor and apply the default-deny firewall rules
    /// (blackhole-core).
    Enable,
    /// Remove the firewall rules, restoring normal connectivity
    /// (blackhole-core).
    Disable,
    /// One aggregate status: kill switch + Tor (live), DNS leak check
    /// (live), and the last recorded fingerprint scan (cached: never
    /// runs a fresh scan, see `scan`).
    Status,
    /// Launch the real-time status TUI (blackhole-dashboard).
    Dashboard {
        /// Synthetic demo data instead of the real modules.
        #[arg(long)]
        mock: bool,
    },
    /// Run a traceability audit scan, or `scan diff` to show what changed
    /// since the last one (blackhole-fingerprint).
    Scan(ScanArgs),
    /// Force the kill switch on immediately, without launching the TUI:
    /// the dashboard's 'p' panic-mode key, as a standalone command, handy
    /// for a script or a system shortcut.
    Panic,
}

#[derive(Args, Debug, PartialEq, Eq)]
struct ScanArgs {
    #[command(subcommand)]
    action: Option<ScanAction>,

    /// Skip the network exposure check (no outbound HTTP request). Only
    /// applies to a plain `blackhole scan`, not `scan diff`.
    #[arg(long)]
    offline: bool,
    /// Don't record this scan to the history file. Only applies to a
    /// plain `blackhole scan`, not `scan diff`.
    #[arg(long)]
    no_history: bool,
    /// History file path. Defaults to the platform's per-user data
    /// directory (same default `blackhole-fingerprint` itself uses).
    #[arg(long)]
    history_path: Option<PathBuf>,
}

#[derive(Subcommand, Debug, PartialEq, Eq)]
enum ScanAction {
    /// Show what changed between the two most recent recorded scans.
    Diff {
        #[arg(long)]
        history_path: Option<PathBuf>,
    },
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Command::Enable => run_enable(cli.tor_backend).await,
        Command::Disable => run_disable(cli.tor_backend).await,
        Command::Status => run_status(cli.tor_backend).await,
        Command::Dashboard { mock } => blackhole_dashboard::run(mock).await,
        Command::Scan(args) => run_scan_command(args),
        Command::Panic => run_panic().await,
    }
}

fn load_core_config() -> anyhow::Result<CoreConfig> {
    Ok(
        blackhole_core::config::load_from(&blackhole_core::config::default_config_path()?)
            .unwrap_or_else(|e| {
                eprintln!("warning: ignoring config file ({e})");
                CoreConfig::default()
            }),
    )
}

async fn build_guard(tor_backend: Option<TorBackendArg>) -> anyhow::Result<PlatformGuard> {
    let core_config = load_core_config()?;
    let backend_kind =
        blackhole_core::config::resolve_backend_kind(tor_backend.map(Into::into), &core_config);
    let tor = blackhole_core::start_backend(backend_kind, &core_config).await?;
    Ok(PlatformGuard::new(tor))
}

async fn run_enable(tor_backend: Option<TorBackendArg>) -> anyhow::Result<()> {
    let guard = build_guard(tor_backend).await?;
    guard.enable().await?;
    println!("kill switch enabled.");
    Ok(())
}

async fn run_disable(tor_backend: Option<TorBackendArg>) -> anyhow::Result<()> {
    let guard = build_guard(tor_backend).await?;
    guard.disable().await?;
    println!("kill switch disabled.");
    Ok(())
}

/// Aggregate status across all four modules in one readable output.
/// Deliberately never propagates a single module's failure as an error
/// for the whole command: each module is checked independently and
/// prints its own "unavailable: <reason>" line on failure, the same
/// degrade-gracefully approach `blackhole-dashboard` already uses (see
/// its `data.rs` module doc), so one broken module never hides the
/// others' real status. The fingerprint section reads the last *recorded*
/// scan from history rather than running a fresh one, so this command
/// stays fast; the kill-switch/Tor section still needs to start a Tor
/// backend to ask it anything, exactly like `blackhole-core status`
/// already does, so that part's speed matches that command's, not
/// instant.
async fn run_status(tor_backend: Option<TorBackendArg>) -> anyhow::Result<()> {
    println!("=== BlackHole status ===");

    println!("\n-- Kill switch + Tor (blackhole-core) --");
    match build_guard(tor_backend).await {
        Ok(guard) => match guard.status().await {
            Ok(status) => {
                println!("state:          {}", status.state);
                if let Some(pct) = status.tor_bootstrap_percent {
                    println!("tor bootstrap:  {pct}%");
                }
                if let Some(egress) = status.allowed_egress {
                    println!("allowed egress: {egress}");
                }
                if let Some(detail) = status.detail {
                    println!("detail:         {detail}");
                }
            }
            Err(e) => println!("unavailable: status query failed: {e}"),
        },
        Err(e) => println!("unavailable: could not start Tor backend: {e}"),
    }

    println!("\n-- DNS (blackhole-dns) --");
    match run_dns_check().await {
        Ok(report) => println!("{report}"),
        Err(e) => println!("unavailable: {e}"),
    }

    println!("\n-- Fingerprint (blackhole-fingerprint), last recorded scan --");
    match fingerprint_status() {
        Ok(Some((timestamp, score))) => {
            println!("last scan: {timestamp} (score {score}/100)");
            println!(
                "(run `blackhole scan` for a fresh check, or `blackhole scan diff` to compare the two most recent)"
            );
        }
        Ok(None) => println!("no scan recorded yet; run `blackhole scan` first."),
        Err(e) => println!("unavailable: {e}"),
    }

    Ok(())
}

async fn run_dns_check() -> anyhow::Result<blackhole_dns::LeakReport> {
    let dns_config =
        blackhole_dns::config::load_from(&blackhole_dns::config::default_config_path()?)
            .unwrap_or_else(|e| {
                eprintln!("warning: ignoring config file ({e})");
                DnsConfig::default()
            });
    let providers = blackhole_dns::config::resolve_providers(None, &dns_config);
    let transport = blackhole_dns::config::resolve_transport(None, &dns_config);
    let resolver = EncryptedResolver::new(&providers, transport)?;
    Ok(blackhole_dns::leak::check(&resolver, &[]).await?)
}

/// `Ok(Some((human_timestamp, score)))` for the last recorded scan,
/// `Ok(None)` if none is recorded yet. Reads history only; never runs
/// `blackhole_fingerprint::run_scan`, which is what keeps this fast.
fn fingerprint_status() -> anyhow::Result<Option<(String, u32)>> {
    let history_path = history::default_history_path()?;
    let records = history::load_all(&history_path)?;
    Ok(records
        .last()
        .map(|record| (record.human_timestamp(), record.score)))
}

fn run_scan_command(args: ScanArgs) -> anyhow::Result<()> {
    match args.action {
        Some(ScanAction::Diff { history_path }) => run_scan_diff(history_path),
        None => run_scan(args.offline, args.no_history, args.history_path),
    }
}

fn run_scan(offline: bool, no_history: bool, history_path: Option<PathBuf>) -> anyhow::Result<()> {
    let history_path = blackhole_fingerprint::resolve_history_path(history_path)?;
    let report = blackhole_fingerprint::scan_record_and_report(offline, no_history, &history_path)?;

    if report.score() < 50 {
        std::process::exit(1);
    }
    Ok(())
}

fn run_scan_diff(history_path: Option<PathBuf>) -> anyhow::Result<()> {
    let history_path = blackhole_fingerprint::resolve_history_path(history_path)?;
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
    let diff = history::HistoryDiff::compute(previous, current);
    println!("{diff}");

    if diff.is_significant_degradation() {
        std::process::exit(1);
    }
    Ok(())
}

/// The dashboard's panic-mode key, as a standalone command: reuses
/// `blackhole_dashboard::data::LiveDataSource::panic()` exactly, the same
/// method the TUI's 'p' key calls, so "force the kill switch on" behaves
/// identically whether triggered from the TUI or from here. Note this
/// inherits that method's own scope: it always uses the arti backend
/// (blackhole-dashboard doesn't support backend selection today), so
/// `--tor-backend` has no effect on this subcommand.
async fn run_panic() -> anyhow::Result<()> {
    use blackhole_dashboard::data::{DataSource, LiveDataSource};

    let mut source = LiveDataSource::new();
    let snapshot = source.panic().await;

    let banner = snapshot.banner.unwrap_or_default();
    println!("{banner}");

    if banner.contains("FAILED") {
        std::process::exit(1);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    //! Verifies each subcommand parses into the `Command`/`ScanArgs`
    //! variant that `main`'s `match` dispatches to the right module's
    //! function: the "wiring" contract this crate owns. The business
    //! logic each variant ultimately calls (guard.enable(), leak::check,
    //! run_scan, LiveDataSource::panic, ...) is already covered by each
    //! module's own tests; re-testing it here would be exactly the
    //! duplication this crate is supposed to avoid. See
    //! `tests/cli_wiring.rs` for the subset of these (the ones needing no
    //! root/network/Tor) exercised end-to-end against the real compiled
    //! binary.
    use super::*;

    fn parse(args: &[&str]) -> Cli {
        let mut full = vec!["blackhole"];
        full.extend_from_slice(args);
        Cli::try_parse_from(full).expect("valid CLI invocation")
    }

    #[test]
    fn enable_routes_to_core() {
        assert_eq!(parse(&["enable"]).command, Command::Enable);
    }

    #[test]
    fn disable_routes_to_core() {
        assert_eq!(parse(&["disable"]).command, Command::Disable);
    }

    #[test]
    fn status_routes_to_aggregate_status() {
        assert_eq!(parse(&["status"]).command, Command::Status);
    }

    #[test]
    fn dashboard_routes_to_dashboard_with_mock_flag() {
        assert_eq!(
            parse(&["dashboard"]).command,
            Command::Dashboard { mock: false }
        );
        assert_eq!(
            parse(&["dashboard", "--mock"]).command,
            Command::Dashboard { mock: true }
        );
    }

    #[test]
    fn plain_scan_routes_to_run_scan_with_no_action() {
        let cli = parse(&["scan", "--offline", "--no-history"]);
        match cli.command {
            Command::Scan(args) => {
                assert_eq!(args.action, None);
                assert!(args.offline);
                assert!(args.no_history);
            }
            other => panic!("expected Command::Scan, got {other:?}"),
        }
    }

    #[test]
    fn scan_diff_routes_to_diff_action() {
        let cli = parse(&["scan", "diff"]);
        match cli.command {
            Command::Scan(args) => {
                assert_eq!(args.action, Some(ScanAction::Diff { history_path: None }));
            }
            other => panic!("expected Command::Scan, got {other:?}"),
        }
    }

    #[test]
    fn scan_diff_accepts_its_own_history_path() {
        let cli = parse(&["scan", "diff", "--history-path", "/tmp/h.jsonl"]);
        match cli.command {
            Command::Scan(args) => {
                assert_eq!(
                    args.action,
                    Some(ScanAction::Diff {
                        history_path: Some(PathBuf::from("/tmp/h.jsonl"))
                    })
                );
            }
            other => panic!("expected Command::Scan, got {other:?}"),
        }
    }

    #[test]
    fn panic_routes_to_panic() {
        assert_eq!(parse(&["panic"]).command, Command::Panic);
    }

    #[test]
    fn tor_backend_flag_is_parsed_and_defaults_to_none() {
        assert!(parse(&["status"]).tor_backend.is_none());
        assert!(
            parse(&["status", "--tor-backend", "subprocess"])
                .tor_backend
                .is_some()
        );
    }
}
