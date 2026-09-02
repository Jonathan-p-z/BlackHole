//! Windows: inspect and configure per-interface DNS servers via PowerShell
//! (`Get-DnsClientServerAddress` / `Set-DnsClientServerAddress`).
//!
//! Windows has no single native "speak DoH/DoT system-wide" switch this
//! crate drives directly here (Windows 11 does have its own encrypted-DNS
//! template support via `netsh dns add encryption`, left as a documented
//! future alternative). Instead, `force_via_relay` points the active
//! interface's resolver at a local relay address (typically `127.0.0.1`,
//! see [`crate::relay`]), which performs the actual DoH forwarding.

use std::net::IpAddr;
use std::process::Command;

use serde::Deserialize;

use crate::error::DnsError;

fn run_powershell(script: &str) -> Result<String, DnsError> {
    let output = Command::new("powershell")
        .args(["-NoProfile", "-NonInteractive", "-Command", script])
        .output()
        .map_err(|e| DnsError::SystemConfig(format!("failed to run powershell: {e}")))?;
    if !output.status.success() {
        return Err(DnsError::SystemConfig(format!(
            "powershell command failed: {}",
            String::from_utf8_lossy(&output.stderr)
        )));
    }
    Ok(String::from_utf8_lossy(&output.stdout).into_owned())
}

#[derive(Debug, Deserialize)]
struct DnsClientServerAddress {
    #[serde(rename = "ServerAddresses")]
    server_addresses: Option<Vec<String>>,
}

/// All DNS server IPs currently active across every network interface.
/// `ConvertTo-Json -InputObject @(...)` (rather than piping into
/// ConvertTo-Json) keeps the array as a single argument so it still
/// serializes as a JSON array when only one (or zero) interfaces have
/// servers configured — piping an `@(...)` array enumerates it element by
/// element before ConvertTo-Json sees it, which silently degrades a
/// single-element result to a bare JSON object.
pub fn active_servers() -> Result<Vec<IpAddr>, DnsError> {
    let raw = run_powershell(
        "ConvertTo-Json -Compress -InputObject @(Get-DnsClientServerAddress -AddressFamily IPv4 | \
           Select-Object ServerAddresses)",
    )?;
    let entries: Vec<DnsClientServerAddress> = serde_json::from_str(raw.trim())
        .map_err(|e| DnsError::SystemConfig(format!("failed to parse DNS config JSON: {e}")))?;

    Ok(entries
        .into_iter()
        .flat_map(|e| e.server_addresses.unwrap_or_default())
        .filter_map(|s| s.parse::<IpAddr>().ok())
        .collect())
}

fn default_interface_alias() -> Result<String, DnsError> {
    let raw = run_powershell(
        "(Get-NetRoute -DestinationPrefix '0.0.0.0/0' | \
           Sort-Object RouteMetric | \
           Select-Object -First 1 -ExpandProperty InterfaceAlias)",
    )?;
    let alias = raw.trim();
    if alias.is_empty() {
        return Err(DnsError::SystemConfig(
            "no default route interface found".to_string(),
        ));
    }
    Ok(alias.to_string())
}

/// Escape a value for embedding inside a PowerShell single-quoted string
/// literal (double any embedded `'`, per PowerShell quoting rules).
fn ps_quote(value: &str) -> String {
    value.replace('\'', "''")
}

/// Point the default interface's DNS servers at `relay_addr`.
pub fn force_via_relay(relay_addr: IpAddr) -> Result<(), DnsError> {
    let alias = default_interface_alias()?;
    run_powershell(&format!(
        "Set-DnsClientServerAddress -InterfaceAlias '{}' -ServerAddresses ('{}')",
        ps_quote(&alias),
        relay_addr
    ))?;
    Ok(())
}
