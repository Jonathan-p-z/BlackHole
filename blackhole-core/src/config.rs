//! Optional local config file (TOML), shared with the other BlackHole
//! modules that have one — one file, one `[core]`/`[dns]`/... section per
//! module, each module reads only its own section. Every field has a
//! default and the file itself is optional. CLI flags, where given,
//! always take priority over the config file.
//!
//! The one setting here that matters most right now: `tor_backend`.
//! `"arti"` (the default) runs Tor in-process via `arti-client`.
//! `"subprocess"` drives the official `tor` binary as a child process
//! instead — a temporary workaround for a known arti bootstrap bug, not a
//! permanent replacement. See the root `TOR_BACKENDS.md`.

use std::path::{Path, PathBuf};

use serde::Deserialize;

use crate::error::BlackholeError;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum TorBackendKind {
    Arti,
    Subprocess,
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default)]
pub struct CoreConfig {
    /// Defaults to `Arti` when unset — see the module doc for why.
    pub tor_backend: Option<TorBackendKind>,
    /// Explicit path to the `tor`/`tor.exe` binary, for the `subprocess`
    /// backend. If unset, it's located via `PATH` or a common Tor Browser
    /// install location — see `tor_subprocess::locate_tor_binary`.
    pub tor_binary_path: Option<PathBuf>,
}

#[derive(Debug, Clone, Default, Deserialize)]
struct RootConfig {
    #[serde(default)]
    core: CoreConfig,
}

pub fn default_config_path() -> Result<PathBuf, BlackholeError> {
    let dirs = directories::ProjectDirs::from("", "", "blackhole")
        .ok_or_else(|| BlackholeError::Platform("could not determine a user config directory on this platform".to_string()))?;
    Ok(dirs.config_dir().join("config.toml"))
}

/// CLI flag (if given) > config file's `[core] tor_backend` (if set) >
/// `Arti`, the default. Pure and synchronous so the selection logic
/// itself — not which backend actually gets constructed from it — is
/// directly unit-testable without starting anything.
pub fn resolve_backend_kind(cli: Option<TorBackendKind>, config: &CoreConfig) -> TorBackendKind {
    cli.or(config.tor_backend).unwrap_or(TorBackendKind::Arti)
}

/// Load the `[core]` section from `path`. A missing file is not an
/// error — returns all-defaults. A file that exists but fails to parse
/// *is* an error: this file is meant to be hand-editable, so a broken
/// edit should be reported, not silently ignored in favor of unrequested
/// defaults.
pub fn load_from(path: &Path) -> Result<CoreConfig, BlackholeError> {
    let text = match std::fs::read_to_string(path) {
        Ok(t) => t,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(CoreConfig::default()),
        Err(e) => return Err(e.into()),
    };
    let root: RootConfig = toml::from_str(&text)
        .map_err(|e| BlackholeError::Platform(format!("{}: invalid config file: {e}", path.display())))?;
    Ok(root.core)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn backend_selection_prefers_cli_over_config_over_default() {
        let no_config = CoreConfig::default();
        let config_wants_subprocess = CoreConfig { tor_backend: Some(TorBackendKind::Subprocess), ..Default::default() };

        // Nothing set anywhere -> the documented default.
        assert_eq!(resolve_backend_kind(None, &no_config), TorBackendKind::Arti);
        // Config sets it -> config wins over the default.
        assert_eq!(resolve_backend_kind(None, &config_wants_subprocess), TorBackendKind::Subprocess);
        // CLI flag given -> CLI wins even when the config disagrees.
        assert_eq!(resolve_backend_kind(Some(TorBackendKind::Arti), &config_wants_subprocess), TorBackendKind::Arti);
        assert_eq!(resolve_backend_kind(Some(TorBackendKind::Subprocess), &no_config), TorBackendKind::Subprocess);
    }

    #[test]
    fn missing_file_is_all_defaults_not_an_error() {
        let path = std::env::temp_dir().join(format!("blackhole-core-config-test-missing-{}.toml", std::process::id()));
        let _ = std::fs::remove_file(&path);
        let config = load_from(&path).unwrap();
        assert!(config.tor_backend.is_none());
        assert!(config.tor_binary_path.is_none());
    }

    #[test]
    fn parses_subprocess_backend_selection() {
        let path = write_temp("subprocess", "[core]\ntor_backend = \"subprocess\"\ntor_binary_path = \"/usr/bin/tor\"\n");
        let config = load_from(&path).unwrap();
        assert_eq!(config.tor_backend, Some(TorBackendKind::Subprocess));
        assert_eq!(config.tor_binary_path, Some(PathBuf::from("/usr/bin/tor")));
        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn parses_arti_backend_selection() {
        let path = write_temp("arti", "[core]\ntor_backend = \"arti\"\n");
        let config = load_from(&path).unwrap();
        assert_eq!(config.tor_backend, Some(TorBackendKind::Arti));
        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn other_sections_are_ignored_not_rejected() {
        let path = write_temp("shared", "[dns]\nproviders = [\"cloudflare\"]\n\n[core]\ntor_backend = \"subprocess\"\n");
        let config = load_from(&path).unwrap();
        assert_eq!(config.tor_backend, Some(TorBackendKind::Subprocess));
        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn malformed_toml_is_a_reported_error() {
        let path = write_temp("broken", "not [ valid toml");
        assert!(load_from(&path).is_err());
        std::fs::remove_file(&path).ok();
    }

    fn write_temp(name: &str, contents: &str) -> PathBuf {
        let path = std::env::temp_dir().join(format!("blackhole-core-config-test-{name}-{}.toml", std::process::id()));
        std::fs::write(&path, contents).unwrap();
        path
    }
}
