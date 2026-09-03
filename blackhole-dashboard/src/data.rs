//! Where the dashboard's numbers come from: either the real
//! `blackhole-core`/`blackhole-dns` modules, or synthetic data for
//! development and demos. Both sides of [`DataSource`] must never panic —
//! every failure becomes a [`ModuleState::Unavailable`] entry in the
//! snapshot instead.

use std::net::{IpAddr, Ipv4Addr};
use std::sync::Arc;

use async_trait::async_trait;
use rand::RngExt;

use crate::app::{DnsInfo, KillSwitchInfo, ModuleState, Snapshot, TorInfo};

use blackhole_core::{GuardState, NetworkGuard, PlatformGuard, TorOrchestrator};
use blackhole_dns::resolver::Transport;
use blackhole_dns::{EncryptedResolver, Provider, leak};

#[async_trait]
pub trait DataSource: Send {
    /// Regular 2-3s poll: refresh every panel independently.
    async fn poll(&mut self) -> Snapshot;

    /// Panic mode: force the kill switch closed *now*, regardless of its
    /// current state, and return a snapshot with a banner describing the
    /// outcome.
    async fn panic(&mut self) -> Snapshot;
}

/// Talks to the real modules. Everything is set up lazily on first poll so
/// dashboard startup (and its first frame) isn't blocked on a full Tor
/// bootstrap; until setup finishes or fails, the kill-switch/Tor panels
/// report `Initializing`, and each module fails independently rather than
/// taking the other one down with it.
pub struct LiveDataSource {
    tor_and_guard: Option<Result<(Arc<TorOrchestrator>, PlatformGuard), String>>,
    dns_resolver: Option<Result<EncryptedResolver, String>>,
}

impl Default for LiveDataSource {
    fn default() -> Self {
        Self::new()
    }
}

impl LiveDataSource {
    pub fn new() -> Self {
        Self {
            tor_and_guard: None,
            dns_resolver: None,
        }
    }

    async fn ensure_tor_and_guard(
        &mut self,
    ) -> &Result<(Arc<TorOrchestrator>, PlatformGuard), String> {
        if self.tor_and_guard.is_none() {
            let result = match TorOrchestrator::start().await {
                Ok(tor) => {
                    let tor = Arc::new(tor);
                    let backend: Arc<dyn blackhole_core::TorBackend> = tor.clone();
                    let guard = PlatformGuard::new(backend);
                    Ok((tor, guard))
                }
                Err(e) => Err(format!("blackhole-core module non détecté: {e}")),
            };
            self.tor_and_guard = Some(result);
        }
        self.tor_and_guard.as_ref().unwrap()
    }

    fn ensure_dns_resolver(&mut self) -> &Result<EncryptedResolver, String> {
        if self.dns_resolver.is_none() {
            let result = EncryptedResolver::new(
                &[Provider::Cloudflare, Provider::Quad9, Provider::Mullvad],
                Transport::Doh,
            )
            .map_err(|e| format!("blackhole-dns module non détecté: {e}"));
            self.dns_resolver = Some(result);
        }
        self.dns_resolver.as_ref().unwrap()
    }

    async fn kill_switch_and_tor(&mut self) -> (ModuleState<KillSwitchInfo>, ModuleState<TorInfo>) {
        let (tor, guard) = match self.ensure_tor_and_guard().await {
            Ok(pair) => pair,
            Err(e) => {
                let msg = e.clone();
                return (
                    ModuleState::Unavailable(msg.clone()),
                    ModuleState::Unavailable(msg),
                );
            }
        };

        let kill_switch = match guard.status().await {
            Ok(status) => ModuleState::Ok(KillSwitchInfo {
                state: status.state.to_string(),
                allowed_egress: status.allowed_egress,
            }),
            Err(e) => ModuleState::Unavailable(format!("status query failed: {e}")),
        };

        let tor_status = tor.status();
        // Best-effort: only worth spending a network round-trip on the exit
        // IP once Tor is actually ready for traffic, and a failure here
        // must not blank out the bootstrap percent we already have.
        let exit_ip = if tor_status.ready_for_traffic {
            tor.exit_ip().await.ok()
        } else {
            None
        };
        let tor = ModuleState::Ok(TorInfo {
            bootstrap_percent: tor_status.bootstrap_percent,
            ready_for_traffic: tor_status.ready_for_traffic,
            exit_ip,
        });

        (kill_switch, tor)
    }

    async fn dns(&mut self) -> ModuleState<DnsInfo> {
        let resolver = match self.ensure_dns_resolver() {
            Ok(r) => r,
            Err(e) => return ModuleState::Unavailable(e.clone()),
        };

        match leak::check(resolver, &[]).await {
            Ok(report) => ModuleState::Ok(DnsInfo {
                provider: report.provider.to_string(),
                leak_detected: report.leak_detected,
                leaking_servers: report.leaking_servers,
                latency_ms: report.latency.map(|d| d.as_millis()),
            }),
            Err(e) => ModuleState::Unavailable(format!("leak check failed: {e}")),
        }
    }
}

#[async_trait]
impl DataSource for LiveDataSource {
    async fn poll(&mut self) -> Snapshot {
        let (kill_switch, tor) = self.kill_switch_and_tor().await;
        let dns = self.dns().await;
        Snapshot {
            kill_switch,
            tor,
            dns,
            banner: None,
        }
    }

    async fn panic(&mut self) -> Snapshot {
        let mut snapshot = self.poll().await;

        let outcome = match self.ensure_tor_and_guard().await {
            Ok((_, guard)) => {
                let status = guard.status().await;
                let result = match status.map(|s| s.state) {
                    Ok(GuardState::Enabled) => Ok(()),
                    _ => guard.enable().await,
                };
                match result {
                    Ok(()) => "PANIC MODE: kill switch forced ON.".to_string(),
                    Err(e) => format!("PANIC MODE FAILED: {e}"),
                }
            }
            Err(e) => format!("PANIC MODE FAILED: kill switch module non détecté ({e})"),
        };

        snapshot.banner = Some(outcome);
        snapshot
    }
}

/// Fabricated, slowly-drifting data so the dashboard is demoable without
/// bootstrapping real Tor circuits or touching the system firewall.
pub struct MockDataSource {
    bootstrap_percent: u8,
    leak_toggle_counter: u32,
}

impl Default for MockDataSource {
    fn default() -> Self {
        Self::new()
    }
}

impl MockDataSource {
    pub fn new() -> Self {
        Self {
            bootstrap_percent: 0,
            leak_toggle_counter: 0,
        }
    }
}

#[async_trait]
impl DataSource for MockDataSource {
    async fn poll(&mut self) -> Snapshot {
        let mut rng = rand::rng();

        self.bootstrap_percent = (self.bootstrap_percent + rng.random_range(5..25)).min(100);
        self.leak_toggle_counter += 1;
        // Briefly simulate a leak every so often so the red/danger styling
        // is visible without needing a real leak.
        let leak_detected = self.leak_toggle_counter.is_multiple_of(9);

        Snapshot {
            kill_switch: ModuleState::Ok(KillSwitchInfo {
                state: "enabled".to_string(),
                allowed_egress: Some("uid 1000 (mock)".to_string()),
            }),
            tor: ModuleState::Ok(TorInfo {
                bootstrap_percent: self.bootstrap_percent,
                ready_for_traffic: self.bootstrap_percent == 100,
                exit_ip: Some(IpAddr::V4(Ipv4Addr::new(
                    185,
                    rng.random_range(0..255),
                    rng.random_range(0..255),
                    rng.random_range(1..255),
                ))),
            }),
            dns: ModuleState::Ok(DnsInfo {
                provider: "Cloudflare (1.1.1.1) [mock]".to_string(),
                leak_detected,
                leaking_servers: if leak_detected {
                    vec![IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1))]
                } else {
                    vec![]
                },
                latency_ms: Some(rng.random_range(15..80)),
            }),
            banner: None,
        }
    }

    async fn panic(&mut self) -> Snapshot {
        let mut snapshot = self.poll().await;
        snapshot.kill_switch = ModuleState::Ok(KillSwitchInfo {
            state: "enabled".to_string(),
            allowed_egress: Some("uid 1000 (mock)".to_string()),
        });
        snapshot.banner = Some("PANIC MODE: kill switch forced ON (mock).".to_string());
        snapshot
    }
}
