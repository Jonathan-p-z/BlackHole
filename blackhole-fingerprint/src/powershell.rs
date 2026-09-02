//! Tiny PowerShell shell-out helper shared by the Windows-specific checks in
//! `network_identity` and `telemetry`. Kept minimal on purpose: this crate
//! is standalone (no dependency on `blackhole-core`/`blackhole-dns`), so it
//! carries its own small copy rather than sharing one across the workspace.

use crate::error::FingerprintError;

pub fn run(script: &str) -> Result<String, FingerprintError> {
    let output = std::process::Command::new("powershell")
        .args(["-NoProfile", "-NonInteractive", "-Command", script])
        .output()
        .map_err(|e| FingerprintError::Inspect(format!("failed to run powershell: {e}")))?;
    if !output.status.success() {
        return Err(FingerprintError::Inspect(format!(
            "powershell command failed: {}",
            String::from_utf8_lossy(&output.stderr)
        )));
    }
    Ok(String::from_utf8_lossy(&output.stdout).into_owned())
}
