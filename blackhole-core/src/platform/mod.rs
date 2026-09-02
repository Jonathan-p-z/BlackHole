//! Platform selection: each OS backend implements the same
//! [`crate::guard::NetworkGuard`] trait; callers only ever see
//! [`PlatformGuard`], selected at compile time.

#[cfg(target_os = "linux")]
mod linux;
#[cfg(target_os = "linux")]
pub use linux::LinuxGuard as PlatformGuard;
#[cfg(target_os = "linux")]
pub use linux::{RulesetRestoreOutcome, default_ruleset_path, restore_persisted_ruleset};

#[cfg(target_os = "windows")]
mod windows;
#[cfg(target_os = "windows")]
pub use windows::WindowsGuard as PlatformGuard;

#[cfg(not(any(target_os = "linux", target_os = "windows")))]
compile_error!("blackhole-core currently supports only Linux and Windows");
