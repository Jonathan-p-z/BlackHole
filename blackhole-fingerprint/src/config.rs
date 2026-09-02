//! Optional local config file (TOML), shared with the other BlackHole
//! modules that have one — one file, one `[fingerprint]`/`[dns]`/...
//! section per module, each module reads only its own section. Every
//! field has a default and the file itself is optional: a missing file, a
//! missing `[fingerprint]` section, or a subset of its keys are all
//! fine — this is a way to override defaults, never a requirement. CLI
//! flags, where given, always take priority over the config file (see the
//! `blackhole-fingerprint` binary's `main.rs`).
//!
//! This is a *config* concern (`<user config dir>/blackhole/config.toml`,
//! shared across modules), distinct from `history`'s *data* concern
//! (`<user data dir>/blackhole-fingerprint/history.jsonl`, private to this
//! crate) — different directories, different lifetimes, deliberately not
//! merged into one path-resolution function.

use std::path::{Path, PathBuf};

use serde::Deserialize;

use crate::error::FingerprintError;

#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
#[serde(default)]
pub struct FingerprintConfig {
    /// Default interval for `blackhole-fingerprint daemon`, in seconds,
    /// when `--interval-secs` isn't given on the command line.
    pub daemon_interval_secs: Option<u64>,
}

#[derive(Debug, Clone, Default, Deserialize)]
struct RootConfig {
    #[serde(default)]
    fingerprint: FingerprintConfig,
}

pub fn default_config_path() -> Result<PathBuf, FingerprintError> {
    let dirs = directories::ProjectDirs::from("", "", "blackhole")
        .ok_or_else(|| FingerprintError::History("could not determine a user config directory on this platform".to_string()))?;
    Ok(dirs.config_dir().join("config.toml"))
}

/// Load the `[fingerprint]` section from `path`. A missing file is not an
/// error — returns all-defaults, same as an empty or absent
/// `[fingerprint]` section. A file that exists but fails to parse *is* an
/// error: this file is meant to be hand-editable, so a broken edit should
/// be reported, not silently ignored in favor of unrequested defaults.
pub fn load_from(path: &Path) -> Result<FingerprintConfig, FingerprintError> {
    let text = match std::fs::read_to_string(path) {
        Ok(t) => t,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(FingerprintConfig::default()),
        Err(e) => return Err(e.into()),
    };
    let root: RootConfig = toml::from_str(&text)
        .map_err(|e| FingerprintError::History(format!("{}: invalid config file: {e}", path.display())))?;
    Ok(root.fingerprint)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn missing_file_is_all_defaults_not_an_error() {
        let path = std::env::temp_dir().join(format!("blackhole-fp-config-test-missing-{}.toml", std::process::id()));
        let _ = std::fs::remove_file(&path);
        assert_eq!(load_from(&path).unwrap(), FingerprintConfig::default());
    }

    #[test]
    fn parses_daemon_interval() {
        let path = write_temp("interval", "[fingerprint]\ndaemon_interval_secs = 3600\n");
        let config = load_from(&path).unwrap();
        assert_eq!(config.daemon_interval_secs, Some(3600));
        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn other_sections_are_ignored_not_rejected() {
        let path = write_temp(
            "shared",
            "[dns]\nproviders = [\"cloudflare\"]\n\n[fingerprint]\ndaemon_interval_secs = 60\n",
        );
        let config = load_from(&path).unwrap();
        assert_eq!(config.daemon_interval_secs, Some(60));
        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn malformed_toml_is_a_reported_error() {
        let path = write_temp("broken", "not [ valid toml");
        assert!(load_from(&path).is_err());
        std::fs::remove_file(&path).ok();
    }

    fn write_temp(name: &str, contents: &str) -> std::path::PathBuf {
        let path = std::env::temp_dir().join(format!("blackhole-fp-config-test-{name}-{}.toml", std::process::id()));
        std::fs::write(&path, contents).unwrap();
        path
    }
}
