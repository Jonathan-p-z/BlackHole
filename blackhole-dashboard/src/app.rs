use std::net::IpAddr;
use std::time::Instant;

/// A module's data, or an explanation of why it isn't available right now.
/// The dashboard must render something sensible for `Unavailable` in every
/// panel rather than treating it as a fatal error.
#[derive(Debug, Clone)]
pub enum ModuleState<T> {
    Initializing,
    Ok(T),
    Unavailable(String),
}

#[derive(Debug, Clone)]
pub struct KillSwitchInfo {
    pub state: String,
    pub allowed_egress: Option<String>,
}

#[derive(Debug, Clone)]
pub struct TorInfo {
    pub bootstrap_percent: u8,
    pub ready_for_traffic: bool,
    pub exit_ip: Option<IpAddr>,
}

#[derive(Debug, Clone)]
pub struct DnsInfo {
    pub provider: String,
    pub leak_detected: bool,
    pub leaking_servers: Vec<IpAddr>,
    pub latency_ms: Option<u128>,
}

#[derive(Debug, Clone)]
pub struct Snapshot {
    pub kill_switch: ModuleState<KillSwitchInfo>,
    pub tor: ModuleState<TorInfo>,
    pub dns: ModuleState<DnsInfo>,
    pub banner: Option<String>,
}

impl Default for Snapshot {
    fn default() -> Self {
        Self {
            kill_switch: ModuleState::Initializing,
            tor: ModuleState::Initializing,
            dns: ModuleState::Initializing,
            banner: None,
        }
    }
}

/// Overall danger level implied by the current snapshot, used to pick the
/// dashboard's dominant color: green when everything we could check looks
/// protected, red when anything looks actively dangerous (a leak, or the
/// kill switch faulted), yellow/gray otherwise (still initializing, or a
/// module we simply couldn't reach).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
// `Danger::Danger` reads more clearly here than an awkward rename
// (`Critical`, `Unsafe`, ...) would improve on; the Protected/Warning/Danger
// triad is the point.
#[allow(clippy::enum_variant_names)]
pub enum Danger {
    Protected,
    Warning,
    Danger,
}

impl Snapshot {
    pub fn danger(&self) -> Danger {
        let dns_leak = matches!(&self.dns, ModuleState::Ok(d) if d.leak_detected);
        let guard_faulted = matches!(&self.kill_switch, ModuleState::Ok(k) if k.state == "faulted");

        if dns_leak || guard_faulted {
            Danger::Danger
        } else if matches!(self.kill_switch, ModuleState::Unavailable(_))
            || matches!(self.tor, ModuleState::Unavailable(_))
            || matches!(self.dns, ModuleState::Unavailable(_))
            || matches!(self.kill_switch, ModuleState::Initializing)
        {
            Danger::Warning
        } else {
            Danger::Protected
        }
    }
}

const BANNER_LIFETIME: std::time::Duration = std::time::Duration::from_secs(5);

pub struct App {
    pub snapshot: Snapshot,
    pub last_updated: Option<Instant>,
    pub panic_in_flight: bool,
    pub should_quit: bool,
    banner_expires_at: Option<Instant>,
}

impl App {
    pub fn new() -> Self {
        Self {
            snapshot: Snapshot::default(),
            last_updated: None,
            panic_in_flight: false,
            should_quit: false,
            banner_expires_at: None,
        }
    }

    /// Apply a fresh snapshot. A banner carried on it (e.g. a panic-mode
    /// outcome) is shown for a fixed duration rather than forever, so it
    /// doesn't get stuck on screen once the next regular poll comes in
    /// without one.
    pub fn apply(&mut self, mut snapshot: Snapshot) {
        if snapshot.banner.is_some() {
            self.banner_expires_at = Some(Instant::now() + BANNER_LIFETIME);
        } else if self.banner_expires_at.is_some_and(|deadline| Instant::now() < deadline) {
            snapshot.banner = self.snapshot.banner.clone();
        } else {
            self.banner_expires_at = None;
        }

        self.snapshot = snapshot;
        self.last_updated = Some(Instant::now());
    }

    /// Called on every render tick so an expired banner disappears even
    /// without a new snapshot arriving.
    pub fn expire_banner(&mut self) {
        if self.banner_expires_at.is_some_and(|deadline| Instant::now() >= deadline) {
            self.snapshot.banner = None;
            self.banner_expires_at = None;
        }
    }
}
