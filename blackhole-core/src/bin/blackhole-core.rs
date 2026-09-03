use blackhole_core::config::{self, CoreConfig, TorBackendKind};
use blackhole_core::{NetworkGuard, PlatformGuard};
use clap::{Parser, Subcommand, ValueEnum};

#[derive(Parser)]
#[command(
    name = "blackhole-core",
    version,
    about = "Fail-closed Tor kill switch"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
    /// Which Tor backend to run: "arti" (default, in-process, recommended)
    /// or "subprocess" (drives the official `tor` binary as a child
    /// process — a temporary workaround for a known arti-client bootstrap
    /// bug, not a permanent replacement; see TOR_BACKENDS.md). Overrides
    /// the config file's `[core] tor_backend` when given.
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

#[derive(Subcommand)]
enum Command {
    /// Show current guard and Tor bootstrap status.
    Status,
    /// Bootstrap Tor and apply the default-deny firewall rules.
    Enable,
    /// Remove the firewall rules, restoring normal connectivity.
    Disable,
    /// Rotate to a fresh Tor identity (new circuits for new streams).
    NewIdentity,
    /// (Linux only) Re-apply the last-persisted kill-switch ruleset,
    /// without starting Tor. Meant to run once at boot, before network
    /// comes up — see BOOT_PERSISTENCE.md for the systemd unit that calls
    /// this, and why it exists (nftables' ruleset is kernel-memory-only
    /// and doesn't survive a reboot on its own).
    #[cfg(target_os = "linux")]
    RestoreFirewall,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();

    let cli = Cli::parse();

    // `restore-firewall` deliberately runs before anything below starts a
    // Tor backend: it's meant to run at boot, as early as possible, and
    // must not block on (or require) a Tor bootstrap just to re-apply a
    // firewall ruleset that has nothing to do with Tor being up yet.
    #[cfg(target_os = "linux")]
    if matches!(cli.command, Command::RestoreFirewall) {
        return match blackhole_core::restore_persisted_ruleset(
            &blackhole_core::default_ruleset_path(),
        )
        .await
        {
            Ok(blackhole_core::RulesetRestoreOutcome::Restored) => {
                println!("kill-switch ruleset restored from disk.");
                Ok(())
            }
            Ok(blackhole_core::RulesetRestoreOutcome::NothingPersisted) => {
                println!("no persisted kill-switch ruleset found; nothing to restore.");
                Ok(())
            }
            Err(e) => Err(e.into()),
        };
    }

    let core_config = config::load_from(&config::default_config_path()?).unwrap_or_else(|e| {
        eprintln!("warning: ignoring config file ({e})");
        CoreConfig::default()
    });
    let backend_kind = config::resolve_backend_kind(cli.tor_backend.map(Into::into), &core_config);

    // Every remaining subcommand needs a running Tor backend, since
    // `status` reports bootstrap progress and `enable` needs it before the
    // firewall rules can name it as the allowed egress. A future revision
    // could persist guard state across invocations instead of re-starting
    // per CLI call.
    let tor = blackhole_core::start_backend(backend_kind, &core_config).await?;
    let guard = PlatformGuard::new(tor);

    match cli.command {
        Command::Status => {
            let status = guard.status().await?;
            println!("state:            {}", status.state);
            if let Some(pct) = status.tor_bootstrap_percent {
                println!("tor bootstrap:    {pct}%");
            }
            if let Some(egress) = status.allowed_egress {
                println!("allowed egress:   {egress}");
            }
            if let Some(detail) = status.detail {
                println!("detail:           {detail}");
            }
        }
        Command::Enable => {
            guard.enable().await?;
            println!("kill switch enabled.");
        }
        Command::Disable => {
            guard.disable().await?;
            println!("kill switch disabled.");
        }
        Command::NewIdentity => {
            guard.new_identity().await?;
            println!("new Tor identity requested.");
        }
        #[cfg(target_os = "linux")]
        Command::RestoreFirewall => unreachable!("handled above, before any Tor backend starts"),
    }

    Ok(())
}
