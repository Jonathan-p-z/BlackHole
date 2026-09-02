//! Tor orchestration via `arti` (a pure-Rust Tor implementation), used
//! instead of shelling out to the C `tor` daemon or driving it over a
//! control port. `arti-client` runs natively on Linux and Windows, which
//! keeps this module free of `cfg(target_os = ...)` branches.
//!
//! This is the *default* Tor backend — see
//! [`crate::tor_subprocess::SubprocessTorBackend`] for the alternative
//! backend that drives the official C `tor` binary as a subprocess
//! instead, and [`TorBackend`] for the trait both share so platform
//! kill-switch backends don't need to know which one they're holding.

use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use arti_client::{TorClient, TorClientConfig};
use async_trait::async_trait;
use tor_rtcompat::PreferredRuntime;
use tracing::{info, warn};

use crate::error::BlackholeError;

/// Snapshot of Tor bootstrap progress, decoupled from `arti_client`'s own
/// status type so it can be displayed by the CLI (or a future GUI) without
/// pulling `arti_client` into every caller.
#[derive(Debug, Clone)]
pub struct TorStatus {
    pub bootstrap_percent: u8,
    pub ready_for_traffic: bool,
    pub blocked_reason: Option<String>,
}

/// What a platform kill-switch backend should scope its "allow this to
/// reach the network" permit rule to, for whichever [`TorBackend`] is
/// actually running Tor.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PermitTarget {
    /// Tor runs in-process (arti): scope the permit rule to this running
    /// executable — see `TorOrchestrator::client_executable_path`. This is
    /// what the Windows backend already did before there was more than
    /// one `TorBackend` impl; Linux's UID-scoped nftables rule doesn't
    /// distinguish this case from `ChildProcess` at all, since a spawned
    /// child inherits the same UID either way.
    ThisProcess,
    /// Tor runs as a separate child process at this path (the subprocess
    /// backend): the permit rule must scope to *that* executable instead,
    /// since outbound connections are made by the child, not by us.
    ChildProcess(PathBuf),
}

/// Common interface both Tor backends implement, so platform kill-switch
/// backends (`platform::linux`/`platform::windows`) can hold either one
/// behind `Arc<dyn TorBackend>` without caring which. Deliberately minimal:
/// only what a kill switch actually needs (status, identity rotation, and
/// where to scope its permit rule) — backend-specific conveniences like
/// `TorOrchestrator::exit_ip` stay on the concrete type, not this trait,
/// since not every backend can support them the same way (the subprocess
/// backend has no in-process `TorClient` to open a stream on; a caller
/// that wants exit-IP display today needs the arti backend specifically).
#[async_trait]
pub trait TorBackend: Send + Sync {
    /// Async (not a cheap in-memory read for every backend): arti's
    /// bootstrap status is free to read, but the subprocess backend has
    /// to make a control-port round trip to ask the child process.
    async fn status(&self) -> TorStatus;
    async fn new_identity(&self) -> Result<(), BlackholeError>;
    fn permit_target(&self) -> PermitTarget;
}

/// Thin wrapper around an `arti_client::TorClient` that exposes only what
/// `blackhole-core` needs: bootstrap, status, and "new identity".
///
/// `arti-client` has no direct equivalent of C-tor's control-port `SIGNAL
/// NEWNYM`. Instead it isolates circuits per `TorClient` handle
/// (`isolated_client()`): calling it returns a new handle whose streams
/// never share circuits with the old one. We hold the "current" handle
/// behind a mutex and swap it on `new_identity`, so callers who ask this
/// orchestrator for a client always get the freshest one, while already-open
/// streams on the old handle are left alone.
pub struct TorOrchestrator {
    current: Mutex<Arc<TorClient<PreferredRuntime>>>,
}

impl TorOrchestrator {
    /// Build a client and bootstrap it, using arti's default on-disk config
    /// (state/cache dirs under the user's standard config directory on both
    /// Linux and Windows).
    pub async fn start() -> Result<Self, BlackholeError> {
        let config = TorClientConfig::default();

        info!("bootstrapping Tor via arti");
        let client = TorClient::create_bootstrapped(config)
            .await
            .map_err(|e| BlackholeError::Tor(format!("bootstrap failed: {e}")))?;

        Ok(Self {
            current: Mutex::new(client),
        })
    }

    /// Handle to use for new connections right now.
    pub fn client(&self) -> Arc<TorClient<PreferredRuntime>> {
        Arc::clone(&self.current.lock().unwrap())
    }

    pub fn status(&self) -> TorStatus {
        let status = self.client().bootstrap_status();
        let blocked_reason = status.blocked().map(|b| b.to_string());
        if let Some(reason) = &blocked_reason {
            warn!(%reason, "tor bootstrap appears stuck");
        }
        TorStatus {
            bootstrap_percent: (status.as_frac() * 100.0).round() as u8,
            ready_for_traffic: status.ready_for_traffic(),
            blocked_reason,
        }
    }

    /// Swap in a freshly isolated client so subsequent streams get new
    /// circuits over new relays. Already-open streams on the previous
    /// handle are unaffected (arti has no "kill existing streams" call;
    /// that's the caller's responsibility if it matters for their use
    /// case).
    pub async fn new_identity(&self) -> Result<(), BlackholeError> {
        info!("rotating Tor identity (isolated client)");
        let fresh = self.client().isolated_client();
        *self.current.lock().unwrap() = fresh;
        Ok(())
    }

    /// Path to the current process's own executable, used by the Windows
    /// backend to scope its WFP allow-rule to "whatever binary is running
    /// this Tor client" rather than a hardcoded path.
    pub fn client_executable_path() -> Result<std::path::PathBuf, BlackholeError> {
        std::env::current_exe().map_err(BlackholeError::from)
    }

    /// Fetch the public IP address our traffic is currently exiting from,
    /// by making a plain-HTTP request over a Tor stream to a small
    /// well-known IP-echo service. This is a display convenience (e.g. for
    /// `blackhole-dashboard`), not a security check: failures are expected
    /// occasionally (the echo service is a third party) and should be
    /// treated as "unknown", not as evidence Tor itself is broken.
    pub async fn exit_ip(&self) -> Result<std::net::IpAddr, BlackholeError> {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        const ECHO_HOST: &str = "api.ipify.org";

        let mut stream = self
            .client()
            .connect((ECHO_HOST, 80))
            .await
            .map_err(|e| BlackholeError::Tor(format!("exit-ip stream failed: {e}")))?;

        stream
            .write_all(
                format!("GET / HTTP/1.1\r\nHost: {ECHO_HOST}\r\nConnection: close\r\n\r\n")
                    .as_bytes(),
            )
            .await?;

        let mut buf = Vec::new();
        stream.read_to_end(&mut buf).await?;
        let text = String::from_utf8_lossy(&buf);
        let body = text
            .rsplit_once("\r\n\r\n")
            .map(|(_, b)| b)
            .unwrap_or("")
            .trim();

        body.parse()
            .map_err(|_| BlackholeError::Tor(format!("unexpected exit-ip response body: {body:?}")))
    }
}

#[async_trait]
impl TorBackend for TorOrchestrator {
    async fn status(&self) -> TorStatus {
        TorOrchestrator::status(self)
    }

    async fn new_identity(&self) -> Result<(), BlackholeError> {
        TorOrchestrator::new_identity(self).await
    }

    fn permit_target(&self) -> PermitTarget {
        PermitTarget::ThisProcess
    }
}
