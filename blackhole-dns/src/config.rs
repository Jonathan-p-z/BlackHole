//! Optional local config file (TOML), shared with the other BlackHole
//! modules that have one — one file, one `[dns]`/`[fingerprint]`/...
//! section per module, each module reads only its own section. Every
//! field has a default and the file itself is optional: a missing file, a
//! missing `[dns]` section, or a subset of its keys are all fine — this
//! is a way to override defaults, never a requirement. CLI flags, where
//! given, always take priority over the config file (see the `blackhole-dns`
//! binary's `main.rs`).

use std::path::{Path, PathBuf};

use serde::Deserialize;

use crate::error::DnsError;
use crate::resolver::{Provider, Transport};

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default)]
pub struct DnsConfig {
    pub providers: Option<Vec<Provider>>,
    pub transport: Option<Transport>,
}

#[derive(Debug, Clone, Default, Deserialize)]
struct RootConfig {
    #[serde(default)]
    dns: DnsConfig,
}

/// `<user config dir>/blackhole/config.toml` — shared across modules, so
/// `directories::ProjectDirs` is scoped to the umbrella "blackhole" name,
/// not this crate's own name (contrast `blackhole-fingerprint::history`,
/// which intentionally uses its own crate-scoped *data* directory for
/// scan history, a concern this file has nothing to do with).
pub fn default_config_path() -> Result<PathBuf, DnsError> {
    let dirs = directories::ProjectDirs::from("", "", "blackhole").ok_or_else(|| {
        DnsError::SystemConfig(
            "could not determine a user config directory on this platform".to_string(),
        )
    })?;
    Ok(dirs.config_dir().join("config.toml"))
}

/// Load the `[dns]` section from `path`. A missing file is not an error —
/// returns all-defaults, same as an empty or absent `[dns]` section. A
/// file that exists but fails to parse *is* an error: this file is meant
/// to be hand-editable, so a broken edit should be reported, not silently
/// ignored in favor of defaults the operator didn't ask for.
pub fn load_from(path: &Path) -> Result<DnsConfig, DnsError> {
    let text = match std::fs::read_to_string(path) {
        Ok(t) => t,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(DnsConfig::default()),
        Err(e) => return Err(e.into()),
    };
    let root: RootConfig = toml::from_str(&text).map_err(|e| {
        DnsError::SystemConfig(format!("{}: invalid config file: {e}", path.display()))
    })?;
    Ok(root.dns)
}

/// CLI flag (if given) > config file's `[dns] providers` (if set) > this
/// crate's own default (`[Provider::Cloudflare]`). Never silently ignores
/// an explicit CLI choice in favor of the config file. Shared by the
/// `blackhole-dns` binary and any other orchestrator (e.g. `blackhole-cli`)
/// that needs the same providers-resolution precedence.
pub fn resolve_providers(cli: Option<Vec<Provider>>, config: &DnsConfig) -> Vec<Provider> {
    if let Some(cli) = cli {
        return cli;
    }
    if let Some(configured) = &config.providers {
        return configured.clone();
    }
    vec![Provider::Cloudflare]
}

/// Same precedence as [`resolve_providers`], for transport.
pub fn resolve_transport(cli: Option<Transport>, config: &DnsConfig) -> Transport {
    cli.or(config.transport).unwrap_or(Transport::Doh)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn missing_file_is_all_defaults_not_an_error() {
        let path = std::env::temp_dir().join(format!(
            "blackhole-dns-test-missing-{}.toml",
            std::process::id()
        ));
        let _ = std::fs::remove_file(&path);
        let config = load_from(&path).unwrap();
        assert!(config.providers.is_none());
        assert!(config.transport.is_none());
    }

    #[test]
    fn empty_file_is_all_defaults() {
        let path = write_temp("empty", "");
        let config = load_from(&path).unwrap();
        assert!(config.providers.is_none());
        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn parses_providers_and_transport() {
        let path = write_temp(
            "full",
            r#"
            [dns]
            providers = ["quad9", "mullvad"]
            transport = "dot"
            "#,
        );
        let config = load_from(&path).unwrap();
        assert_eq!(
            config.providers,
            Some(vec![Provider::Quad9, Provider::Mullvad])
        );
        assert_eq!(config.transport, Some(Transport::Dot));
        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn other_sections_are_ignored_not_rejected() {
        // A shared file also containing `[fingerprint]` (blackhole-fingerprint's
        // own section) must not fail to parse just because this crate
        // doesn't know that section.
        let path = write_temp(
            "shared",
            r#"
            [fingerprint]
            daemon_interval_secs = 3600

            [dns]
            providers = ["cloudflare"]
            "#,
        );
        let config = load_from(&path).unwrap();
        assert_eq!(config.providers, Some(vec![Provider::Cloudflare]));
        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn malformed_toml_is_a_reported_error_not_silently_defaulted() {
        let path = write_temp("broken", "this is not [ valid toml");
        assert!(load_from(&path).is_err());
        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn resolve_providers_prefers_cli_over_config_over_default() {
        let no_config = DnsConfig::default();
        let config_wants_quad9 = DnsConfig {
            providers: Some(vec![Provider::Quad9]),
            ..Default::default()
        };

        assert_eq!(
            resolve_providers(None, &no_config),
            vec![Provider::Cloudflare]
        );
        assert_eq!(
            resolve_providers(None, &config_wants_quad9),
            vec![Provider::Quad9]
        );
        assert_eq!(
            resolve_providers(Some(vec![Provider::Mullvad]), &config_wants_quad9),
            vec![Provider::Mullvad]
        );
    }

    #[test]
    fn resolve_transport_prefers_cli_over_config_over_default() {
        let no_config = DnsConfig::default();
        let config_wants_dot = DnsConfig {
            transport: Some(Transport::Dot),
            ..Default::default()
        };

        assert_eq!(resolve_transport(None, &no_config), Transport::Doh);
        assert_eq!(resolve_transport(None, &config_wants_dot), Transport::Dot);
        assert_eq!(
            resolve_transport(Some(Transport::Doh), &config_wants_dot),
            Transport::Doh
        );
    }

    fn write_temp(name: &str, contents: &str) -> std::path::PathBuf {
        let path = std::env::temp_dir().join(format!(
            "blackhole-dns-test-{name}-{}.toml",
            std::process::id()
        ));
        std::fs::write(&path, contents).unwrap();
        path
    }
}
