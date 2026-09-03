//! Traceability audit for the BlackHole project: local network identity
//! (MAC/hostname/machine-id), OS telemetry, and public network exposure,
//! rolled up into one score with concrete recommendations.

pub mod config;
pub mod daemon;
pub mod error;
pub mod exposure;
pub mod history;
pub mod network_identity;
pub mod report;
pub mod scan;
pub mod telemetry;

#[cfg(target_os = "windows")]
pub mod powershell;

pub use error::FingerprintError;
pub use report::Report;
pub use scan::{now_unix, resolve_history_path, run_scan, scan_record_and_report};
