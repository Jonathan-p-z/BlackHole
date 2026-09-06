//! Optional local config file (TOML), shared with the other BlackHole
//! modules that have one; see `blackhole-dns/src/config.rs`'s module doc
//! for the shared-file convention this follows exactly (one `[cookies]`
//! section, everything optional with a safe default, CLI flags win over
//! the config file).
//!
//! The one default that matters most: `enabled` defaults to `false`.
//! Nothing in this crate flips it to `true` on its own; see
//! `THREAT_MODEL.md`'s "Mandatory safeguards".

use std::path::{Path, PathBuf};

use serde::Deserialize;

use crate::error::CookiesError;

#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct CookiesConfig {
    /// Never `true` unless the operator explicitly set it, or the
    /// `enable` subcommand wrote it there. See `THREAT_MODEL.md`.
    pub enabled: bool,
    /// Path to a tracker list file (EasyList-subset or plain domains; see
    /// `tracker_list.rs`). `None` means pure pass-through: no list
    /// configured yet, so nothing is treated as a tracker.
    pub tracker_list_path: Option<PathBuf>,
    /// Local port the proxy listens on, `127.0.0.1` only, never `0.0.0.0`
    /// or any other interface (not configurable: see `THREAT_MODEL.md`'s
    /// "What this technically does", point 1).
    pub proxy_port: u16,
}

impl Default for CookiesConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            tracker_list_path: None,
            proxy_port: 9080,
        }
    }
}

#[derive(Debug, Clone, Default, Deserialize)]
struct RootConfig {
    #[serde(default)]
    cookies: CookiesConfig,
}

pub fn default_config_path() -> Result<PathBuf, CookiesError> {
    let dirs = directories::ProjectDirs::from("", "", "blackhole").ok_or_else(|| {
        CookiesError::Platform(
            "could not determine a user config directory on this platform".to_string(),
        )
    })?;
    Ok(dirs.config_dir().join("config.toml"))
}

/// Load the `[cookies]` section from `path`. A missing file is not an
/// error; returns all-defaults (`enabled: false`), same as an empty or
/// absent `[cookies]` section. A file that exists but fails to parse *is*
/// an error, matching every other module's config-loading convention.
pub fn load_from(path: &Path) -> Result<CookiesConfig, CookiesError> {
    let text = match std::fs::read_to_string(path) {
        Ok(t) => t,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(CookiesConfig::default()),
        Err(e) => return Err(e.into()),
    };
    let root: RootConfig = toml::from_str(&text).map_err(|e| {
        CookiesError::Platform(format!("{}: invalid config file: {e}", path.display()))
    })?;
    Ok(root.cookies)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_is_disabled_with_no_tracker_list() {
        let config = CookiesConfig::default();
        assert!(!config.enabled);
        assert!(config.tracker_list_path.is_none());
    }

    #[test]
    fn missing_file_is_all_defaults_not_an_error() {
        let path = std::env::temp_dir().join(format!(
            "blackhole-cookies-config-test-missing-{}.toml",
            std::process::id()
        ));
        let _ = std::fs::remove_file(&path);
        let config = load_from(&path).unwrap();
        assert!(!config.enabled);
    }

    #[test]
    fn parses_enabled_and_tracker_list_path() {
        let path = write_temp(
            "full",
            "[cookies]\nenabled = true\ntracker_list_path = \"/tmp/easyprivacy.txt\"\nproxy_port = 9999\n",
        );
        let config = load_from(&path).unwrap();
        assert!(config.enabled);
        assert_eq!(
            config.tracker_list_path,
            Some(PathBuf::from("/tmp/easyprivacy.txt"))
        );
        assert_eq!(config.proxy_port, 9999);
        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn other_sections_are_ignored_not_rejected() {
        let path = write_temp(
            "shared",
            "[dns]\nproviders = [\"cloudflare\"]\n\n[cookies]\nenabled = true\n",
        );
        let config = load_from(&path).unwrap();
        assert!(config.enabled);
        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn malformed_toml_is_a_reported_error() {
        let path = write_temp("broken", "not [ valid toml");
        assert!(load_from(&path).is_err());
        std::fs::remove_file(&path).ok();
    }

    fn write_temp(name: &str, contents: &str) -> PathBuf {
        let path = std::env::temp_dir().join(format!(
            "blackhole-cookies-config-test-{name}-{}.toml",
            std::process::id()
        ));
        std::fs::write(&path, contents).unwrap();
        path
    }
}
