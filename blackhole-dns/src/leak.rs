//! DNS leak detection: compares the OS's actually-active resolver
//! configuration against the resolver we intended to force everything
//! through, and separately confirms that encrypted resolver is reachable.

use std::net::IpAddr;
use std::time::Duration;

use blackhole_core::{GuardState, NetworkGuard};
use tracing::{error, warn};

use crate::error::DnsError;
use crate::resolver::{EncryptedResolver, Provider};
use crate::system_dns;

/// A stable, widely-cached domain resolved purely to measure the encrypted
/// resolver's own reachability and round-trip latency. It carries no
/// significance beyond "does a query round-trip successfully" — this is not
/// a third-party DNS-leak-testing service and makes no other assumptions
/// about the response.
const CONTROL_DOMAIN: &str = "example.com";

#[derive(Debug, Clone)]
pub struct LeakReport {
    pub provider: Provider,
    pub expected_servers: Vec<IpAddr>,
    pub active_servers: Vec<IpAddr>,
    pub leaking_servers: Vec<IpAddr>,
    pub encrypted_resolver_reachable: bool,
    pub latency: Option<Duration>,
    pub leak_detected: bool,
}

impl std::fmt::Display for LeakReport {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        writeln!(f, "provider:           {}", self.provider)?;
        writeln!(f, "expected servers:   {}", fmt_ips(&self.expected_servers))?;
        writeln!(f, "active OS servers:  {}", fmt_ips(&self.active_servers))?;
        writeln!(
            f,
            "encrypted resolver: {}{}",
            if self.encrypted_resolver_reachable {
                "reachable"
            } else {
                "UNREACHABLE"
            },
            self.latency
                .map(|d| format!(" ({} ms)", d.as_millis()))
                .unwrap_or_default()
        )?;
        write!(
            f,
            "leak detected:      {}",
            if self.leak_detected {
                format!("YES ({})", fmt_ips(&self.leaking_servers))
            } else {
                "no".to_string()
            }
        )
    }
}

fn fmt_ips(ips: &[IpAddr]) -> String {
    if ips.is_empty() {
        "(none)".to_string()
    } else {
        ips.iter()
            .map(IpAddr::to_string)
            .collect::<Vec<_>>()
            .join(", ")
    }
}

/// Run a full leak check: read the OS's active resolver configuration and
/// compare it against `resolver`'s provider, plus confirm the encrypted
/// resolver itself is reachable. `extra_allowed` lets a caller running the
/// local relay on a non-loopback address (loopback is always allowed)
/// recognize that address as expected too.
pub async fn check(
    resolver: &EncryptedResolver,
    extra_allowed: &[IpAddr],
) -> Result<LeakReport, DnsError> {
    // Any provider in the configured chain is expected, not just whichever
    // one is currently active — a fallback to the next provider is a
    // logged, intentional switch (see `resolver::EncryptedResolver::resolve`),
    // not something leak detection should flag.
    let expected_servers: Vec<IpAddr> = resolver
        .all_provider_ips()
        .into_iter()
        .chain(extra_allowed.iter().copied())
        .collect();

    let active_servers = system_dns::active_servers().unwrap_or_default();
    let leaking_servers: Vec<IpAddr> = active_servers
        .iter()
        .copied()
        .filter(|ip| !ip.is_loopback() && !expected_servers.contains(ip))
        .collect();

    let (encrypted_resolver_reachable, latency) = match resolver.resolve(CONTROL_DOMAIN).await {
        Ok((_, elapsed)) => (true, Some(elapsed)),
        Err(e) => {
            warn!(error = %e, "control query against encrypted resolver failed");
            (false, None)
        }
    };

    let leak_detected = !leaking_servers.is_empty() || !encrypted_resolver_reachable;

    Ok(LeakReport {
        provider: resolver.provider(),
        expected_servers,
        active_servers,
        leaking_servers,
        encrypted_resolver_reachable,
        latency,
        leak_detected,
    })
}

/// If a leak was detected, (re-)assert the kill switch's default-deny
/// firewall rules so nothing further leaves the machine outside the
/// intended encrypted path. Safe to call regardless of the guard's current
/// state.
pub async fn enforce_on_leak(
    report: &LeakReport,
    guard: &dyn NetworkGuard,
) -> Result<(), DnsError> {
    if !report.leak_detected {
        return Ok(());
    }

    error!(
        leaking = ?report.leaking_servers,
        "DNS leak detected; enforcing kill switch"
    );

    let status = guard.status().await?;
    match status.state {
        GuardState::Enabled => {
            // Rules were supposedly already active but a leak still got
            // through: reset to a known-clean blocking state rather than
            // trusting whatever is currently applied.
            guard.disable().await?;
            guard.enable().await?;
        }
        GuardState::Disabled | GuardState::Faulted => {
            guard.enable().await?;
        }
        GuardState::Enabling | GuardState::Disabling => {
            warn!("guard transition already in flight; leak reported but not re-enforced");
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use blackhole_core::{BlackholeError, GuardStatus};
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Mutex;

    /// A `NetworkGuard` double that records calls instead of touching any
    /// real firewall/Tor state, so `enforce_on_leak`'s fail-closed decision
    /// logic — reassert the kill switch on any detected leak, regardless of
    /// what the guard currently reports — is testable without a live OS
    /// backend or network access.
    struct FakeGuard {
        state: Mutex<GuardState>,
        enable_calls: AtomicUsize,
        disable_calls: AtomicUsize,
    }

    impl FakeGuard {
        fn with_state(state: GuardState) -> Self {
            Self {
                state: Mutex::new(state),
                enable_calls: AtomicUsize::new(0),
                disable_calls: AtomicUsize::new(0),
            }
        }
    }

    #[async_trait::async_trait]
    impl NetworkGuard for FakeGuard {
        async fn enable(&self) -> Result<(), BlackholeError> {
            self.enable_calls.fetch_add(1, Ordering::SeqCst);
            *self.state.lock().unwrap() = GuardState::Enabled;
            Ok(())
        }

        async fn disable(&self) -> Result<(), BlackholeError> {
            self.disable_calls.fetch_add(1, Ordering::SeqCst);
            *self.state.lock().unwrap() = GuardState::Disabled;
            Ok(())
        }

        async fn status(&self) -> Result<GuardStatus, BlackholeError> {
            Ok(GuardStatus {
                state: *self.state.lock().unwrap(),
                tor_bootstrap_percent: None,
                allowed_egress: None,
                detail: None,
            })
        }

        async fn new_identity(&self) -> Result<(), BlackholeError> {
            Ok(())
        }
    }

    fn leaking_report() -> LeakReport {
        LeakReport {
            provider: Provider::Cloudflare,
            expected_servers: vec![],
            active_servers: vec!["198.51.100.1".parse().unwrap()],
            leaking_servers: vec!["198.51.100.1".parse().unwrap()],
            encrypted_resolver_reachable: true,
            latency: None,
            leak_detected: true,
        }
    }

    fn clean_report() -> LeakReport {
        LeakReport {
            leak_detected: false,
            leaking_servers: vec![],
            ..leaking_report()
        }
    }

    #[tokio::test]
    async fn no_leak_never_touches_the_guard() {
        let guard = FakeGuard::with_state(GuardState::Enabled);
        enforce_on_leak(&clean_report(), &guard).await.unwrap();
        assert_eq!(guard.enable_calls.load(Ordering::SeqCst), 0);
        assert_eq!(guard.disable_calls.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn leak_while_enabled_resets_to_a_known_clean_blocking_state() {
        // Rules claimed to already be enforcing but a leak got through
        // anyway: don't trust what's currently applied — tear down and
        // reapply from scratch rather than assume it's a no-op.
        let guard = FakeGuard::with_state(GuardState::Enabled);
        enforce_on_leak(&leaking_report(), &guard).await.unwrap();
        assert_eq!(guard.disable_calls.load(Ordering::SeqCst), 1);
        assert_eq!(guard.enable_calls.load(Ordering::SeqCst), 1);
        assert_eq!(*guard.state.lock().unwrap(), GuardState::Enabled);
    }

    #[tokio::test]
    async fn leak_while_disabled_enables_the_kill_switch() {
        let guard = FakeGuard::with_state(GuardState::Disabled);
        enforce_on_leak(&leaking_report(), &guard).await.unwrap();
        assert_eq!(guard.enable_calls.load(Ordering::SeqCst), 1);
        assert_eq!(*guard.state.lock().unwrap(), GuardState::Enabled);
    }

    #[tokio::test]
    async fn leak_while_faulted_enables_rather_than_giving_up() {
        // Faulted must never be treated as "nothing we can do" — always
        // attempt to reach a clean blocking state.
        let guard = FakeGuard::with_state(GuardState::Faulted);
        enforce_on_leak(&leaking_report(), &guard).await.unwrap();
        assert_eq!(guard.enable_calls.load(Ordering::SeqCst), 1);
        assert_eq!(*guard.state.lock().unwrap(), GuardState::Enabled);
    }

    #[tokio::test]
    async fn leak_during_in_flight_transition_does_not_race_it() {
        let guard = FakeGuard::with_state(GuardState::Enabling);
        enforce_on_leak(&leaking_report(), &guard).await.unwrap();
        assert_eq!(guard.enable_calls.load(Ordering::SeqCst), 0);
        assert_eq!(guard.disable_calls.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn unreachable_encrypted_resolver_alone_counts_as_a_leak() {
        // Even with zero leaking plaintext servers observed, an
        // unreachable encrypted resolver must still be treated as "we
        // cannot currently guarantee encrypted DNS" and enforce the kill
        // switch — this is what a DNS timeout/failure looks like upstream
        // of `enforce_on_leak`.
        let report = LeakReport {
            leaking_servers: vec![],
            encrypted_resolver_reachable: false,
            leak_detected: true,
            ..leaking_report()
        };
        let guard = FakeGuard::with_state(GuardState::Disabled);
        enforce_on_leak(&report, &guard).await.unwrap();
        assert_eq!(guard.enable_calls.load(Ordering::SeqCst), 1);
    }
}
