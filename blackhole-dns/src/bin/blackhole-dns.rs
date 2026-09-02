use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;

use blackhole_core::{PlatformGuard, TorOrchestrator};
use blackhole_dns::config::DnsConfig;
use blackhole_dns::resolver::Transport;
use blackhole_dns::{config, leak, relay, EncryptedResolver, Provider};
use clap::{Parser, Subcommand, ValueEnum};

#[derive(Parser)]
#[command(name = "blackhole-dns", version, about = "Anti-DNS-leak toolkit")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Run a leak check and print a report.
    Check {
        /// One or more DoH/DoT providers, in priority order (the first is
        /// tried first; later ones are only used if an earlier one fails
        /// or fails DNSSEC validation). Defaults to the config file's
        /// `[dns] providers`, or Cloudflare alone if neither is set.
        #[arg(long = "provider", value_enum, num_args = 1..)]
        providers: Option<Vec<ProviderArg>>,
        /// Defaults to the config file's `[dns] transport`, or DoH.
        #[arg(long, value_enum)]
        transport: Option<TransportArg>,
        /// If a leak is detected, trigger blackhole-core's kill switch.
        /// Bootstraps Tor, so this is slower than a plain check.
        #[arg(long)]
        enforce: bool,
    },
    /// Point the OS's resolver configuration at the encrypted resolver
    /// (systemd-resolved DoT on Linux) or at the local relay (Windows, or
    /// Linux with `--relay`).
    Force {
        #[arg(long, value_enum, default_value_t = ProviderArg::Cloudflare)]
        provider: ProviderArg,
        /// Use the local DoH-forwarding relay instead of the OS's native
        /// encrypted-DNS support.
        #[arg(long)]
        relay: bool,
    },
    /// Run the local DoH-forwarding relay in the foreground.
    Serve {
        /// One or more DoH/DoT providers, in priority order — see `check
        /// --provider`.
        #[arg(long = "provider", value_enum, num_args = 1..)]
        providers: Option<Vec<ProviderArg>>,
        #[arg(long, value_enum)]
        transport: Option<TransportArg>,
        #[arg(long, default_value = "127.0.0.1:53")]
        listen: SocketAddr,
    },
}

#[derive(Clone, Copy, ValueEnum)]
enum ProviderArg {
    Cloudflare,
    Quad9,
    Mullvad,
}

impl From<ProviderArg> for Provider {
    fn from(p: ProviderArg) -> Self {
        match p {
            ProviderArg::Cloudflare => Provider::Cloudflare,
            ProviderArg::Quad9 => Provider::Quad9,
            ProviderArg::Mullvad => Provider::Mullvad,
        }
    }
}

#[derive(Clone, Copy, ValueEnum)]
enum TransportArg {
    Doh,
    Dot,
}

impl From<TransportArg> for Transport {
    fn from(t: TransportArg) -> Self {
        match t {
            TransportArg::Doh => Transport::Doh,
            TransportArg::Dot => Transport::Dot,
        }
    }
}

/// CLI flag (if given) > config file's `[dns]` section (if set) > this
/// crate's own hardcoded default. Never silently ignores an explicit
/// `--provider`/`--transport` in favor of the config file.
fn resolve_providers(cli: Option<Vec<ProviderArg>>, config: &DnsConfig) -> Vec<Provider> {
    if let Some(cli) = cli {
        return cli.into_iter().map(Into::into).collect();
    }
    if let Some(configured) = &config.providers {
        return configured.clone();
    }
    vec![Provider::Cloudflare]
}

fn resolve_transport(cli: Option<TransportArg>, config: &DnsConfig) -> Transport {
    cli.map(Into::into).or(config.transport).unwrap_or(Transport::Doh)
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();

    let cli = Cli::parse();
    let config = config::load_from(&config::default_config_path()?).unwrap_or_else(|e| {
        eprintln!("warning: ignoring config file ({e})");
        DnsConfig::default()
    });

    match cli.command {
        Command::Check {
            providers,
            transport,
            enforce,
        } => {
            let providers = resolve_providers(providers, &config);
            let transport = resolve_transport(transport, &config);
            let resolver = EncryptedResolver::new(&providers, transport)?;
            let report = leak::check(&resolver, &[]).await?;
            println!("{report}");

            if enforce && report.leak_detected {
                eprintln!("\nleak detected; bootstrapping Tor to enforce kill switch...");
                let tor = std::sync::Arc::new(TorOrchestrator::start().await?);
                let guard = PlatformGuard::new(tor);
                leak::enforce_on_leak(&report, &guard).await?;
                eprintln!("kill switch enforced.");
            }

            if report.leak_detected {
                std::process::exit(1);
            }
        }
        Command::Force { provider, relay } => {
            if relay {
                blackhole_dns::system_dns::force_via_relay(IpAddr::V4(
                    std::net::Ipv4Addr::LOCALHOST,
                ))?;
                println!("OS resolver now points at the local relay (start it with `blackhole-dns serve`).");
            } else {
                blackhole_dns::system_dns::force_via_dot(provider.into())?;
                println!("OS resolver forced to {} via encrypted DNS.", Provider::from(provider));
            }
        }
        Command::Serve {
            providers,
            transport,
            listen,
        } => {
            let providers = resolve_providers(providers, &config);
            let transport = resolve_transport(transport, &config);
            let resolver = Arc::new(EncryptedResolver::new(&providers, transport)?);
            let server = relay::Relay::new(resolver);
            server.serve_udp(listen).await?;
        }
    }

    Ok(())
}
