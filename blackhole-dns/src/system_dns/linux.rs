//! Linux: inspect and configure DNS via `systemd-resolved`'s `resolvectl`
//! CLI. Shelling out to `resolvectl` avoids depending on systemd-resolved's
//! D-Bus API surface directly for what is, in the end, a handful of simple
//! commands.

use std::net::IpAddr;
use std::process::Command;

use crate::error::DnsError;
use crate::resolver::Provider;

fn run(args: &[&str]) -> Result<String, DnsError> {
    let output = Command::new("resolvectl")
        .args(args)
        .output()
        .map_err(|e| DnsError::SystemConfig(format!("failed to run resolvectl: {e}")))?;
    if !output.status.success() {
        return Err(DnsError::SystemConfig(format!(
            "resolvectl {} failed: {}",
            args.join(" "),
            String::from_utf8_lossy(&output.stderr)
        )));
    }
    Ok(String::from_utf8_lossy(&output.stdout).into_owned())
}

/// Name of the interface carrying the default route, e.g. `eth0` or
/// `wlan0`. `resolvectl` operates per-link, so we need this to scope our
/// `dns`/`dnsovertls` calls to the interface that actually carries traffic.
fn default_interface() -> Result<String, DnsError> {
    let output = Command::new("ip")
        .args(["route", "show", "default"])
        .output()
        .map_err(|e| DnsError::SystemConfig(format!("failed to run ip route: {e}")))?;
    let stdout = String::from_utf8_lossy(&output.stdout);
    stdout
        .split_whitespace()
        .collect::<Vec<_>>()
        .windows(2)
        .find(|w| w[0] == "dev")
        .map(|w| w[1].to_string())
        .ok_or_else(|| DnsError::SystemConfig("no default route interface found".to_string()))
}

/// Parse the IP addresses out of `resolvectl dns` output. That command's
/// format looks like:
/// ```text
/// Link 2 (eth0): 192.168.1.1
/// Global:
/// ```
/// so we just take everything after the first `:` on each line and pick out
/// tokens that parse as an IP address, ignoring everything else (link
/// names, "Global", empty lines).
pub fn active_servers() -> Result<Vec<IpAddr>, DnsError> {
    let raw = run(&["dns"])?;
    let mut servers = Vec::new();
    for line in raw.lines() {
        let Some((_, rest)) = line.split_once(':') else {
            continue;
        };
        for token in rest.split_whitespace() {
            if let Ok(ip) = token.parse::<IpAddr>() {
                servers.push(ip);
            }
        }
    }
    Ok(servers)
}

/// Point the default interface's systemd-resolved link at `provider` and
/// turn on DNS-over-TLS for it.
pub fn force_via_dot(provider: Provider) -> Result<(), DnsError> {
    let interface = default_interface()?;
    let ip_args: Vec<String> = provider.ip_addrs().iter().map(|ip| ip.to_string()).collect();

    let mut dns_args: Vec<&str> = vec!["dns", &interface];
    dns_args.extend(ip_args.iter().map(String::as_str));
    run(&dns_args)?;

    run(&["dnsovertls", &interface, "yes"])?;
    Ok(())
}

/// Point the default interface's systemd-resolved link at a local relay
/// (typically `127.0.0.1`), used when the caller prefers a local
/// DoH-forwarding relay over systemd-resolved's native DoT support.
pub fn force_via_relay(relay_addr: IpAddr) -> Result<(), DnsError> {
    let interface = default_interface()?;
    run(&["dns", &interface, &relay_addr.to_string()])?;
    run(&["dnsovertls", &interface, "no"])?;
    Ok(())
}
