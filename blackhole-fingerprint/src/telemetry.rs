//! OS-level telemetry audit: is the platform's own diagnostic/telemetry
//! collection active, and how to turn it off. This only *reports and
//! recommends* — it never changes system configuration itself, since that
//! generally needs elevation and the user should see the exact command
//! first.

use crate::report::{Category, Finding, Severity};

pub fn checks() -> Vec<Finding> {
    imp::checks()
}

#[cfg(target_os = "linux")]
mod imp {
    use super::*;

    pub fn checks() -> Vec<Finding> {
        let mut findings = Vec::new();
        findings.extend(check_ubuntu_report());
        findings.extend(check_service("whoopsie", "Ubuntu crash report uploader"));
        findings.extend(check_service("apport", "crash report collector"));
        findings.extend(check_popularity_contest());
        findings
    }

    fn check_ubuntu_report() -> Vec<Finding> {
        if std::path::Path::new("/usr/bin/ubuntu-report").exists() {
            vec![Finding::new(
                Category::Telemetry,
                Severity::Medium,
                "ubuntu-report is installed (Ubuntu's system/hardware telemetry tool)",
            )
            .with_recommendation("opt out with `ubuntu-report -f send no` (add `sudo` to also cover the system-wide report)")]
        } else {
            vec![]
        }
    }

    fn systemctl_is_active(unit: &str) -> Option<bool> {
        let output = std::process::Command::new("systemctl")
            .args(["is-active", unit])
            .output()
            .ok()?;
        Some(String::from_utf8_lossy(&output.stdout).trim() == "active")
    }

    fn check_service(unit: &str, description: &str) -> Vec<Finding> {
        match systemctl_is_active(unit) {
            Some(true) => vec![
                Finding::new(
                    Category::Telemetry,
                    Severity::Medium,
                    format!("{unit} ({description}) is active"),
                )
                .with_recommendation(format!("disable it: `sudo systemctl disable --now {unit}`")),
            ],
            Some(false) => vec![Finding::new(
                Category::Telemetry,
                Severity::Info,
                format!("{unit} is installed but not active"),
            )],
            // systemctl unavailable, or the unit doesn't exist on this
            // system at all — not applicable, so no finding either way.
            None => vec![],
        }
    }

    fn check_popularity_contest() -> Vec<Finding> {
        match std::fs::read_to_string("/etc/popularity-contest.conf") {
            Ok(contents) if contents.lines().any(|l| l.trim() == "PARTICIPATE=\"yes\"") => {
                vec![Finding::new(
                    Category::Telemetry,
                    Severity::Medium,
                    "popularity-contest is enabled (periodically reports your installed packages upstream)",
                )
                .with_recommendation("disable it: `sudo dpkg-reconfigure popularity-contest` and choose No")]
            }
            _ => vec![],
        }
    }
}

#[cfg(target_os = "windows")]
mod imp {
    use super::*;

    pub fn checks() -> Vec<Finding> {
        let mut findings = Vec::new();
        findings.extend(check_diagtrack());
        findings.extend(check_telemetry_policy());
        findings
    }

    #[derive(serde::Deserialize)]
    struct ServiceInfo {
        #[serde(rename = "Status")]
        status: String,
        #[serde(rename = "StartType")]
        start_type: String,
    }

    fn check_diagtrack() -> Vec<Finding> {
        let raw = match crate::powershell::run(
            "Get-Service DiagTrack -ErrorAction SilentlyContinue | \
             Select-Object @{N='Status';E={$_.Status.ToString()}},@{N='StartType';E={$_.StartType.ToString()}} | \
             ConvertTo-Json -Compress",
        ) {
            Ok(raw) => raw,
            Err(_) => {
                return vec![Finding::new(
                    Category::Telemetry,
                    Severity::Info,
                    "could not query the DiagTrack service",
                )];
            }
        };

        if raw.trim().is_empty() {
            return vec![Finding::new(
                Category::Telemetry,
                Severity::Info,
                "DiagTrack service not found",
            )];
        }

        let info: ServiceInfo = match serde_json::from_str(raw.trim()) {
            Ok(info) => info,
            Err(_) => {
                return vec![Finding::new(
                    Category::Telemetry,
                    Severity::Info,
                    "could not parse DiagTrack service state",
                )];
            }
        };

        if info.status == "Running" {
            vec![Finding::new(
                Category::Telemetry,
                Severity::Medium,
                "DiagTrack (Connected User Experiences and Telemetry) service is running",
            )
            .with_recommendation(
                "disable it as Administrator: `Stop-Service DiagTrack; Set-Service DiagTrack -StartupType Disabled`",
            )]
        } else {
            vec![Finding::new(
                Category::Telemetry,
                Severity::Info,
                format!(
                    "DiagTrack service is {} (start type: {})",
                    info.status, info.start_type
                ),
            )]
        }
    }

    fn check_telemetry_policy() -> Vec<Finding> {
        let raw = crate::powershell::run(
            "(Get-ItemProperty 'HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\DataCollection' -ErrorAction SilentlyContinue).AllowTelemetry",
        );

        match raw {
            Ok(value) if !value.trim().is_empty() => {
                let level: i32 = value.trim().parse().unwrap_or(-1);
                if level <= 1 {
                    vec![Finding::new(
                        Category::Telemetry,
                        Severity::Info,
                        format!("AllowTelemetry policy set to {level} (Security/Basic)"),
                    )]
                } else {
                    vec![Finding::new(
                        Category::Telemetry,
                        Severity::Medium,
                        format!("AllowTelemetry policy set to {level} (above Basic)"),
                    )
                    .with_recommendation(
                        "lower it via Group Policy, or (Enterprise/Education only) \
                         `New-ItemProperty -Path 'HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\DataCollection' -Name AllowTelemetry -Value 0 -PropertyType DWord -Force`",
                    )]
                }
            }
            _ => vec![Finding::new(
                Category::Telemetry,
                Severity::Medium,
                "no AllowTelemetry policy set (default diagnostic data collection level applies)",
            )
            .with_recommendation("Settings > Privacy & security > Diagnostics & feedback, set to the minimum available level")],
        }
    }
}
