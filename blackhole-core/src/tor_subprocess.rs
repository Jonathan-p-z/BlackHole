//! Alternative Tor backend: drives the official C `tor` binary (the
//! mature, widely-audited Tor Project daemon) as a subprocess, instead of
//! running `arti` in-process. Exists as a **temporary workaround** for a
//! known `arti-client` bootstrap bug that currently blocks the Windows
//! kill switch — see the root `TOR_BACKENDS.md` for the full story and
//! why `arti` stays the recommended default once that's fixed upstream.
//!
//! This module never touches Tor's own network protocol or cryptography.
//! It only does two things a mature, external process needs from any
//! supervisor: spawn it with a minimal config, and talk to its
//! already-documented control-port protocol (`crate::tor_control`) to ask
//! about bootstrap status and request a new identity. Nothing here
//! reimplements anything the Tor Project already built and audits.

use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::Duration;

use async_trait::async_trait;
use tokio::process::{Child, Command};
use tracing::{info, warn};

use crate::error::BlackholeError;
use crate::tor::{PermitTarget, TorBackend, TorStatus};
use crate::tor_control::ControlClient;

/// Below this version, `SubprocessTorBackend::start` refuses to run the
/// binary at all: skipping a version check would mean no assurance we're
/// not running a `tor` build with a since-fixed known vulnerability. This
/// is a point-in-time floor, not a live vulnerability feed — revisit it
/// periodically against the Tor Project's current stable series
/// (<https://gitweb.torproject.org/tor.git/tree/ReleaseNotes>), don't
/// assume it stays correct forever.
pub const MIN_TOR_VERSION: (u32, u32, u32) = (0, 4, 8);

const DEFAULT_SOCKS_PORT: u16 = 19050;
const DEFAULT_CONTROL_PORT: u16 = 19051;
const CONTROL_CONNECT_TIMEOUT: Duration = Duration::from_secs(20);

#[derive(Debug, Clone)]
pub struct SubprocessConfig {
    /// Explicit path to the `tor`/`tor.exe` binary. If `None`,
    /// `locate_tor_binary` searches `PATH` and a short list of common Tor
    /// Browser install locations.
    pub binary_path: Option<PathBuf>,
    pub data_dir: PathBuf,
    pub socks_port: u16,
    pub control_port: u16,
}

impl Default for SubprocessConfig {
    fn default() -> Self {
        Self {
            binary_path: None,
            data_dir: std::env::temp_dir().join("blackhole-core-tor"),
            socks_port: DEFAULT_SOCKS_PORT,
            control_port: DEFAULT_CONTROL_PORT,
        }
    }
}

pub struct SubprocessTorBackend {
    binary_path: PathBuf,
    socks_addr: SocketAddr,
    control_addr: SocketAddr,
    cookie_path: PathBuf,
    child: Mutex<Child>,
}

impl SubprocessTorBackend {
    /// Locate the binary (explicit path, `PATH`, or a Tor-Browser install),
    /// version-check it, spawn it, and confirm its control port actually
    /// comes up before returning — a backend this constructor returns is
    /// one that's genuinely running, not just "spawn didn't immediately
    /// error."
    pub async fn start(config: SubprocessConfig) -> Result<Self, BlackholeError> {
        let binary_path = locate_tor_binary(config.binary_path.as_deref())?;
        let version = tor_binary_version(&binary_path).await?;
        if version < MIN_TOR_VERSION {
            return Err(BlackholeError::Tor(format!(
                "tor binary at {} reports version {}.{}.{}, below the minimum {}.{}.{} this backend will run \
                 (no version check would mean no assurance against a known-vulnerable build) — get a current \
                 release from https://www.torproject.org/download/tor/",
                binary_path.display(),
                version.0, version.1, version.2,
                MIN_TOR_VERSION.0, MIN_TOR_VERSION.1, MIN_TOR_VERSION.2
            )));
        }

        std::fs::create_dir_all(&config.data_dir)?;
        let cookie_path = config.data_dir.join("control_auth_cookie");
        let socks_addr: SocketAddr = format!("127.0.0.1:{}", config.socks_port).parse().unwrap();
        let control_addr: SocketAddr = format!("127.0.0.1:{}", config.control_port).parse().unwrap();

        info!(
            binary = %binary_path.display(),
            version = format!("{}.{}.{}", version.0, version.1, version.2),
            %socks_addr,
            %control_addr,
            "starting Tor via the subprocess backend (temporary arti-bootstrap-bug workaround — see TOR_BACKENDS.md)"
        );

        let child = Command::new(&binary_path)
            .arg("--SocksPort").arg(socks_addr.to_string())
            .arg("--ControlPort").arg(control_addr.to_string())
            .arg("--CookieAuthentication").arg("1")
            .arg("--DataDirectory").arg(&config.data_dir)
            .arg("--RunAsDaemon").arg("0")
            .arg("--ClientOnly").arg("1")
            .kill_on_drop(true)
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn()
            .map_err(|e| BlackholeError::Tor(format!("failed to spawn tor binary at {}: {e}", binary_path.display())))?;

        // Confirm the control port actually comes up (and the cookie file
        // appears) before declaring success — a spawn() that "succeeded"
        // but produced a process that immediately dies would otherwise
        // look like a healthy backend until the first status() call.
        drop(ControlClient::connect(control_addr, &cookie_path, CONTROL_CONNECT_TIMEOUT).await?);

        Ok(Self {
            binary_path,
            socks_addr,
            control_addr,
            cookie_path,
            child: Mutex::new(child),
        })
    }

    pub fn binary_path(&self) -> &Path {
        &self.binary_path
    }

    pub fn socks_addr(&self) -> SocketAddr {
        self.socks_addr
    }

    /// The child process's OS PID, for logging/diagnostics — `None` if it
    /// has already exited (Rust's `Child::id()` stops returning one once
    /// the process has been `wait()`-ed on).
    pub fn child_id(&self) -> Option<u32> {
        self.child.lock().unwrap().id()
    }

    /// `Some(exit status)` if the child has already exited (crashed, was
    /// killed, or exited on its own) — checked without blocking. `None`
    /// means it's still running as far as we can tell right now.
    fn child_exit_status(&self) -> Option<std::process::ExitStatus> {
        self.child.lock().unwrap().try_wait().ok().flatten()
    }
}

#[async_trait]
impl TorBackend for SubprocessTorBackend {
    async fn status(&self) -> TorStatus {
        if let Some(exit_status) = self.child_exit_status() {
            let reason = format!("tor subprocess exited unexpectedly (status: {exit_status})");
            warn!(%reason, "subprocess tor backend is down");
            return TorStatus {
                bootstrap_percent: 0,
                ready_for_traffic: false,
                blocked_reason: Some(reason),
            };
        }

        match ControlClient::connect(self.control_addr, &self.cookie_path, Duration::from_secs(5)).await {
            Ok(mut client) => match client.bootstrap_status().await {
                Ok((percent, ready_for_traffic, blocked_reason)) => TorStatus { bootstrap_percent: percent, ready_for_traffic, blocked_reason },
                Err(e) => TorStatus { bootstrap_percent: 0, ready_for_traffic: false, blocked_reason: Some(e.to_string()) },
            },
            Err(e) => TorStatus { bootstrap_percent: 0, ready_for_traffic: false, blocked_reason: Some(e.to_string()) },
        }
    }

    async fn new_identity(&self) -> Result<(), BlackholeError> {
        if let Some(exit_status) = self.child_exit_status() {
            return Err(BlackholeError::Tor(format!("cannot request a new identity: tor subprocess has exited (status: {exit_status})")));
        }
        let mut client = ControlClient::connect(self.control_addr, &self.cookie_path, Duration::from_secs(5)).await?;
        client.new_identity().await
    }

    fn permit_target(&self) -> PermitTarget {
        PermitTarget::ChildProcess(self.binary_path.clone())
    }
}

/// `explicit` (from config), else `tor`/`tor.exe` on `PATH`, else a short
/// list of common Tor Browser install locations. Not exhaustive by
/// design — an explicit config path is always the reliable option; this
/// is best-effort convenience on top of it.
fn locate_tor_binary(explicit: Option<&Path>) -> Result<PathBuf, BlackholeError> {
    if let Some(path) = explicit {
        if path.is_file() {
            return Ok(path.to_path_buf());
        }
        return Err(BlackholeError::Tor(format!(
            "configured tor_binary_path {} does not exist or isn't a file",
            path.display()
        )));
    }

    let exe_name = if cfg!(windows) { "tor.exe" } else { "tor" };

    if let Some(path) = std::env::var_os("PATH").and_then(|paths| {
        std::env::split_paths(&paths).map(|dir| dir.join(exe_name)).find(|p| p.is_file())
    }) {
        return Ok(path);
    }

    for candidate in tor_browser_candidates(exe_name) {
        if candidate.is_file() {
            return Ok(candidate);
        }
    }

    Err(BlackholeError::Tor(
        "no tor binary found on PATH or in a common Tor Browser install location. \
         Download one from https://www.torproject.org/download/tor/ (or use Tor Browser, \
         which bundles one), then set `tor_binary_path` in the config file — see TOR_BACKENDS.md."
            .to_string(),
    ))
}

fn tor_browser_candidates(exe_name: &str) -> Vec<PathBuf> {
    let mut candidates = Vec::new();
    let Some(home) = directories::UserDirs::new().map(|d| d.home_dir().to_path_buf()) else {
        return candidates;
    };

    if cfg!(windows) {
        candidates.push(home.join("Desktop").join("Tor Browser").join("Browser").join("TorBrowser").join("Tor").join(exe_name));
        if let Some(local_appdata) = std::env::var_os("LOCALAPPDATA") {
            candidates.push(PathBuf::from(local_appdata).join("Tor Browser").join("Browser").join("TorBrowser").join("Tor").join(exe_name));
        }
    } else {
        candidates.push(home.join("tor-browser").join("Browser").join("TorBrowser").join("Tor").join(exe_name));
        candidates.push(home.join("Desktop").join("tor-browser").join("Browser").join("TorBrowser").join("Tor").join(exe_name));
        candidates.push(PathBuf::from("/opt/tor-browser/Browser/TorBrowser/Tor").join(exe_name));
    }

    candidates
}

/// Run `<binary> --version` and parse the `X.Y.Z` out of Tor's own
/// version string (e.g. `Tor version 0.4.8.13.`). Any binary whose output
/// doesn't parse is treated as failing the version check — an unparsed
/// version is exactly as untrustworthy as a too-old one.
async fn tor_binary_version(binary_path: &Path) -> Result<(u32, u32, u32), BlackholeError> {
    let output = Command::new(binary_path)
        .arg("--version")
        .output()
        .await
        .map_err(|e| BlackholeError::Tor(format!("failed to run '{} --version': {e}", binary_path.display())))?;

    let text = String::from_utf8_lossy(&output.stdout);
    parse_tor_version(&text)
        .ok_or_else(|| BlackholeError::Tor(format!("could not parse a version number out of '{} --version' output: {text:?}", binary_path.display())))
}

fn parse_tor_version(text: &str) -> Option<(u32, u32, u32)> {
    let after = text.split("Tor version ").nth(1)?;
    let version_str = after.split(|c: char| c != '.' && !c.is_ascii_digit()).next()?;
    let mut parts = version_str.split('.');
    let major: u32 = parts.next()?.parse().ok()?;
    let minor: u32 = parts.next()?.parse().ok()?;
    let patch: u32 = parts.next()?.parse().ok()?;
    Some((major, minor, patch))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_real_tor_version_string() {
        assert_eq!(parse_tor_version("Tor version 0.4.8.13.\nThis is experimental software.\n"), Some((0, 4, 8)));
    }

    #[test]
    fn parses_version_with_git_suffix() {
        // Real tor builds sometimes append a git revision, e.g.
        // "Tor version 0.4.9.1-alpha (git-abcdef1234)."
        assert_eq!(parse_tor_version("Tor version 0.4.9.1-alpha (git-abcdef1234).\n"), Some((0, 4, 9)));
    }

    #[test]
    fn unparseable_output_is_none_not_a_panic() {
        assert_eq!(parse_tor_version("command not found"), None);
        assert_eq!(parse_tor_version(""), None);
    }

    #[test]
    fn min_version_floor_rejects_old_versions() {
        assert!((0, 4, 7) < MIN_TOR_VERSION);
        assert!((0, 4, 8) >= MIN_TOR_VERSION);
        assert!((0, 5, 0) >= MIN_TOR_VERSION);
    }

    #[test]
    fn locate_tor_binary_reports_explicit_path_that_does_not_exist() {
        let bogus = std::env::temp_dir().join("definitely-not-a-real-tor-binary-blackhole-test");
        let err = locate_tor_binary(Some(&bogus)).unwrap_err();
        assert!(matches!(err, BlackholeError::Tor(_)));
    }
}
