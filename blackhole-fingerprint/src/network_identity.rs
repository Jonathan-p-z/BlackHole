//! Local network-identity audit: MAC addresses (randomized vs.
//! manufacturer-original), hostname, and the OS's stable machine ID —
//! everything that can uniquely tag this machine to a network operator or a
//! service without any browser involved.

use crate::error::FingerprintError;
use crate::report::{Category, Finding, Severity};

pub fn checks() -> Result<Vec<Finding>, FingerprintError> {
    let mut findings = Vec::new();
    findings.extend(check_hostname());
    findings.extend(check_machine_id());
    findings.extend(check_mac_addresses()?);
    Ok(findings)
}

fn current_username() -> Option<String> {
    std::env::var("USER")
        .or_else(|_| std::env::var("USERNAME"))
        .ok()
}

fn is_generic_hostname(name: &str) -> bool {
    let upper = name.to_uppercase();
    upper.starts_with("DESKTOP-")
        || upper.starts_with("LAPTOP-")
        || matches!(
            name.to_lowercase().as_str(),
            "localhost" | "ubuntu" | "debian" | "archlinux" | "fedora"
        )
}

fn check_hostname() -> Vec<Finding> {
    let name = match hostname::get() {
        Ok(os_str) => os_str.to_string_lossy().to_string(),
        Err(_) => {
            return vec![Finding::new(
                Category::NetworkIdentity,
                Severity::Info,
                "could not read hostname",
            )];
        }
    };

    let lower = name.to_lowercase();
    let username = current_username().unwrap_or_default().to_lowercase();

    if !username.is_empty() && !lower.is_empty() && lower.contains(&username) {
        vec![Finding::new(
            Category::NetworkIdentity,
            Severity::High,
            format!("hostname '{name}' contains the local username, making it identifiable to anyone who sees it on a network"),
        )
        .with_recommendation(
            "set a generic hostname, e.g. `hostnamectl set-hostname host` (Linux) or Settings > System > About > Rename this PC (Windows)",
        )]
    } else if is_generic_hostname(&name) {
        vec![Finding::new(
            Category::NetworkIdentity,
            Severity::Info,
            format!("hostname '{name}' looks auto-generated, low identifiability"),
        )]
    } else {
        vec![Finding::new(
            Category::NetworkIdentity,
            Severity::Low,
            format!("hostname '{name}' is custom; harmless unless it encodes personal information"),
        )]
    }
}

fn truncated(id: &str) -> String {
    format!("{}...", &id[..id.len().min(8)])
}

#[cfg(target_os = "linux")]
fn check_machine_id() -> Vec<Finding> {
    match std::fs::read_to_string("/etc/machine-id") {
        Ok(id) => {
            let id = id.trim();
            vec![Finding::new(
                Category::NetworkIdentity,
                Severity::Low,
                format!(
                    "/etc/machine-id is set ({}), a stable identifier some software uses to correlate you across sessions",
                    truncated(id)
                ),
            )
            .with_recommendation(
                "regenerating it (`sudo rm /etc/machine-id && sudo systemd-machine-id-setup`) helps against long-term correlation, \
                 but some services key local state off it — only do this if you understand the tradeoff",
            )]
        }
        Err(_) => vec![Finding::new(
            Category::NetworkIdentity,
            Severity::Info,
            "no /etc/machine-id found",
        )],
    }
}

#[cfg(target_os = "windows")]
fn check_machine_id() -> Vec<Finding> {
    match crate::powershell::run(
        "(Get-ItemProperty 'HKLM:\\SOFTWARE\\Microsoft\\Cryptography' -ErrorAction SilentlyContinue).MachineGuid",
    ) {
        Ok(raw) if !raw.trim().is_empty() => {
            let id = raw.trim();
            vec![Finding::new(
                Category::NetworkIdentity,
                Severity::Low,
                format!(
                    "MachineGuid is set ({}), a stable identifier some software uses to correlate you across sessions",
                    truncated(id)
                ),
            )
            .with_recommendation(
                "Windows regenerates this per-install; there is no supported way to change it without reinstalling, which this tool will not automate",
            )]
        }
        _ => vec![Finding::new(
            Category::NetworkIdentity,
            Severity::Info,
            "could not read MachineGuid",
        )],
    }
}

fn evaluate_mac(iface: &str, mac: &str) -> Finding {
    let first_octet_hex = mac.split([':', '-']).next().unwrap_or("");
    let Ok(first_octet) = u8::from_str_radix(first_octet_hex, 16) else {
        return Finding::new(
            Category::NetworkIdentity,
            Severity::Info,
            format!("{iface}: could not parse MAC address '{mac}'"),
        );
    };

    // The second-least-significant bit of the first octet is the
    // "locally administered" bit: set means this address was assigned by
    // software (typically randomized), unset means it's the manufacturer's
    // original, globally unique OUI-based address.
    let locally_administered = first_octet & 0b0000_0010 != 0;

    if locally_administered {
        Finding::new(
            Category::NetworkIdentity,
            Severity::Info,
            format!("{iface}: MAC {mac} is locally administered (looks randomized) — good"),
        )
    } else {
        Finding::new(
            Category::NetworkIdentity,
            Severity::Medium,
            format!("{iface}: MAC {mac} is the manufacturer-assigned original address, unique and trackable across networks you join"),
        )
        .with_recommendation(mac_randomization_hint())
    }
}

fn mac_randomization_hint() -> &'static str {
    #[cfg(target_os = "linux")]
    {
        "enable MAC randomization, e.g. via NetworkManager: `nmcli connection modify <profile> 802-11-wireless.cloned-mac-address random`, \
         or systemd-networkd's `MACAddressPolicy=random`"
    }
    #[cfg(target_os = "windows")]
    {
        "enable random hardware addresses in Settings > Network & Internet > Wi-Fi > Random hardware addresses (wireless NICs); \
         wired NICs generally require a third-party tool or driver-level support"
    }
}

#[cfg(target_os = "linux")]
fn is_virtual_interface(name: &str) -> bool {
    ["docker", "veth", "br-", "virbr", "tun", "tap", "wg", "lo"]
        .iter()
        .any(|prefix| name.starts_with(prefix))
}

#[cfg(target_os = "linux")]
fn check_mac_addresses() -> Result<Vec<Finding>, FingerprintError> {
    let entries = std::fs::read_dir("/sys/class/net").map_err(|e| {
        FingerprintError::Inspect(format!("failed to list network interfaces: {e}"))
    })?;

    let mut findings = Vec::new();
    for entry in entries.flatten() {
        let iface = entry.file_name().to_string_lossy().into_owned();
        if is_virtual_interface(&iface) {
            continue;
        }
        if let Ok(mac) = std::fs::read_to_string(entry.path().join("address")) {
            findings.push(evaluate_mac(&iface, mac.trim()));
        }
    }
    Ok(findings)
}

#[cfg(target_os = "windows")]
fn check_mac_addresses() -> Result<Vec<Finding>, FingerprintError> {
    #[derive(serde::Deserialize)]
    struct Adapter {
        #[serde(rename = "Name")]
        name: String,
        #[serde(rename = "MacAddress")]
        mac_address: Option<String>,
    }

    // ConvertTo-Json on Windows PowerShell 5.1 unwraps a single-element
    // array when it arrives via the pipeline, even with `@(...)` — the
    // array still gets enumerated element-by-element before reaching
    // ConvertTo-Json. Passing it as -InputObject instead (not piped) keeps
    // it as one array argument, so a single adapter still serializes as a
    // JSON array instead of a bare object.
    let raw = crate::powershell::run(
        "ConvertTo-Json -Compress -InputObject @(Get-NetAdapter -Physical | Where-Object Status -eq 'Up' | Select-Object Name,MacAddress)",
    )?;
    let adapters: Vec<Adapter> = serde_json::from_str(raw.trim())
        .map_err(|e| FingerprintError::Inspect(format!("failed to parse adapter JSON: {e}")))?;

    Ok(adapters
        .into_iter()
        .filter_map(|a| a.mac_address.map(|mac| evaluate_mac(&a.name, &mac)))
        .collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generic_hostnames_are_recognized() {
        assert!(is_generic_hostname("DESKTOP-AB12CD3"));
        assert!(is_generic_hostname("laptop-xyz"));
        assert!(is_generic_hostname("localhost"));
        assert!(is_generic_hostname("Ubuntu"));
    }

    #[test]
    fn custom_hostnames_are_not_generic() {
        assert!(!is_generic_hostname("my-workstation"));
        assert!(!is_generic_hostname("blackhole-dev"));
    }

    #[test]
    fn locally_administered_mac_is_info() {
        // 0x02 has the locally-administered bit set.
        let finding = evaluate_mac("eth0", "02:00:00:00:00:00");
        assert_eq!(finding.severity, Severity::Info);
        assert_eq!(finding.category, Category::NetworkIdentity);
    }

    #[test]
    fn manufacturer_mac_is_medium_with_recommendation() {
        // 0xd4 has the locally-administered bit unset (real Intel OUI byte).
        let finding = evaluate_mac("eth0", "d4:be:d9:00:00:00");
        assert_eq!(finding.severity, Severity::Medium);
        assert!(finding.recommendation.is_some());
    }

    #[test]
    fn unparseable_mac_is_reported_as_info_not_a_panic() {
        let finding = evaluate_mac("eth0", "not-a-mac");
        assert_eq!(finding.severity, Severity::Info);
        assert!(finding.summary.contains("could not parse"));
    }
}
