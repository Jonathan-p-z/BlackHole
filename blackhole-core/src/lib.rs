//! Core networking primitives for the BlackHole project: a fail-closed
//! kill switch (Linux/nftables, Windows/WFP) paired with in-process Tor
//! orchestration via `arti`, behind one OS-independent [`NetworkGuard`]
//! trait.
//!
//! Threat model: reduces commercial tracking, web fingerprinting, basic
//! network correlation, and light forensic exposure on devices you
//! control. It is not designed to resist a state-level adversary with
//! sustained physical access, nor to evade a lawful investigation.

pub mod config;
pub mod error;
pub mod guard;
pub mod platform;
pub mod tor;
pub mod tor_control;
pub mod tor_subprocess;

pub use error::BlackholeError;
pub use guard::{GuardState, GuardStateMachine, GuardStatus, NetworkGuard};
pub use platform::PlatformGuard;
#[cfg(target_os = "linux")]
pub use platform::{default_ruleset_path, restore_persisted_ruleset, RulesetRestoreOutcome};
pub use tor::{PermitTarget, TorBackend, TorOrchestrator, TorStatus};
pub use tor_subprocess::{SubprocessConfig, SubprocessTorBackend};
