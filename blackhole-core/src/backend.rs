//! Picks and starts the `TorBackend` selected by [`crate::config::TorBackendKind`].
//! Shared by the `blackhole-core` binary's CLI and any other orchestrator
//! (e.g. `blackhole-cli`) that needs "give me a running Tor backend for
//! this config" without re-implementing backend selection itself.

use std::sync::Arc;

use crate::config::{CoreConfig, TorBackendKind};
use crate::error::BlackholeError;
use crate::tor::{TorBackend, TorOrchestrator};
use crate::tor_subprocess::{SubprocessConfig, SubprocessTorBackend};

/// Start the Tor backend selected by `kind`, using `config` for
/// backend-specific settings (currently just `tor_binary_path` for
/// `subprocess`). Prints (not logs: this is meant to be visible
/// regardless of `RUST_LOG`) which backend is starting and why, since
/// backend choice affects what "the kill switch is protecting you" means
/// (see the root `TOR_BACKENDS.md`).
pub async fn start_backend(
    kind: TorBackendKind,
    config: &CoreConfig,
) -> Result<Arc<dyn TorBackend>, BlackholeError> {
    let backend: Arc<dyn TorBackend> = match kind {
        TorBackendKind::Arti => {
            eprintln!(
                "[tor backend: arti, in-process] bootstrapping (this can take a while on first run)..."
            );
            Arc::new(TorOrchestrator::start().await?)
        }
        TorBackendKind::Subprocess => {
            eprintln!(
                "[tor backend: subprocess, official tor binary] starting; this is a temporary workaround \
                 for a known arti bootstrap bug, not a permanent replacement; see TOR_BACKENDS.md"
            );
            let subprocess_config = SubprocessConfig {
                binary_path: config.tor_binary_path.clone(),
                ..Default::default()
            };
            Arc::new(SubprocessTorBackend::start(subprocess_config).await?)
        }
    };
    Ok(backend)
}
