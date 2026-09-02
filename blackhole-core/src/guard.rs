use std::fmt;
use std::sync::Mutex;

use async_trait::async_trait;

use crate::error::BlackholeError;

/// Lifecycle state of a [`NetworkGuard`].
///
/// `Faulted` exists so the state machine can be fail-closed: if `enable` or
/// `disable` fails partway through applying platform firewall rules, the
/// guard does *not* fall back to `Disabled` (which would imply "safe to
/// assume nothing is blocked"). It moves to `Faulted` instead, because
/// partially-applied rules must be assumed to still be blocking traffic
/// until a subsequent call succeeds in fully clearing or re-applying them.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum GuardState {
    Disabled,
    Enabling,
    Enabled,
    Disabling,
    Faulted,
}

impl fmt::Display for GuardState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            GuardState::Disabled => "disabled",
            GuardState::Enabling => "enabling",
            GuardState::Enabled => "enabled",
            GuardState::Disabling => "disabling",
            GuardState::Faulted => "faulted",
        };
        f.write_str(s)
    }
}

/// Point-in-time snapshot returned by [`NetworkGuard::status`].
#[derive(Debug, Clone)]
pub struct GuardStatus {
    pub state: GuardState,
    /// Tor bootstrap progress in `0..=100`, if the Tor orchestrator has been
    /// started. `None` before the first `enable`.
    pub tor_bootstrap_percent: Option<u8>,
    /// Human-readable description of what traffic is currently allowed to
    /// leave the machine (e.g. the Tor executable path on Windows, or the
    /// designated interface name on Linux). Mainly for `status` output.
    pub allowed_egress: Option<String>,
    /// Free-form detail, e.g. the reason a guard is `Faulted`.
    pub detail: Option<String>,
}

/// Common interface implemented by every OS-specific kill switch backend.
///
/// Implementations must be fail-closed: `enable` should block all outbound
/// traffic except through the designated Tor/VPN egress *before* returning
/// success, and if the underlying tunnel disappears afterwards, previously
/// applied firewall rules must keep blocking traffic rather than fail open.
#[async_trait]
pub trait NetworkGuard: Send + Sync {
    /// Apply firewall rules that block all outbound traffic except through
    /// the designated Tor egress, then start/attach the Tor orchestration.
    async fn enable(&self) -> Result<(), BlackholeError>;

    /// Tear down the firewall rules applied by `enable`, restoring normal
    /// connectivity. This is the only call that intentionally leaves the
    /// machine unprotected; it must be explicit and never implicit.
    async fn disable(&self) -> Result<(), BlackholeError>;

    /// Report the current lifecycle state plus Tor bootstrap progress.
    async fn status(&self) -> Result<GuardStatus, BlackholeError>;

    /// Request a fresh Tor circuit / identity. Requires the guard to be
    /// `Enabled`.
    async fn new_identity(&self) -> Result<(), BlackholeError>;
}

/// OS-independent state machine shared by every `NetworkGuard` backend.
///
/// This type owns no firewall or Tor state itself — platform backends embed
/// it and drive it with `begin_*`/`finish_*` around their actual work, so the
/// transition rules can be unit-tested without a Linux or Windows host.
#[derive(Debug)]
pub struct GuardStateMachine {
    state: Mutex<GuardState>,
}

impl Default for GuardStateMachine {
    fn default() -> Self {
        Self::new()
    }
}

impl GuardStateMachine {
    pub fn new() -> Self {
        Self {
            state: Mutex::new(GuardState::Disabled),
        }
    }

    pub fn current(&self) -> GuardState {
        *self.state.lock().unwrap()
    }

    /// `Disabled` or `Faulted` -> `Enabling`. Retrying from `Faulted` is
    /// allowed so a caller can attempt to reach a clean, fully-blocking
    /// state again.
    pub fn begin_enable(&self) -> Result<(), BlackholeError> {
        let mut state = self.state.lock().unwrap();
        match *state {
            GuardState::Disabled | GuardState::Faulted => {
                *state = GuardState::Enabling;
                Ok(())
            }
            other => Err(BlackholeError::InvalidTransition {
                action: "enable",
                state: other,
            }),
        }
    }

    pub fn finish_enable(&self, success: bool) {
        let mut state = self.state.lock().unwrap();
        *state = if success {
            GuardState::Enabled
        } else {
            GuardState::Faulted
        };
    }

    /// `Enabled`, `Faulted`, or `Disabled` -> `Disabling`. Allowed from
    /// `Faulted` so a caller can attempt to tear down whatever rules were
    /// partially applied. Also allowed from `Disabled` — deliberately: a
    /// freshly started process always begins in-memory `Disabled`
    /// (`GuardStateMachine::new`), with no idea whether a *previous*
    /// process instance left real OS-level rules behind (crashed after
    /// `enable()`, killed, etc.). Refusing `disable()` there would leave an
    /// operator with no way to ask "make sure nothing is blocking" without
    /// already knowing the answer. Platform backends' `delete_all_our_objects`
    /// is already idempotent (ignores "not found" errors) specifically so
    /// this is always safe to attempt, blocking or not.
    ///
    /// Still refused from `Enabling`/`Disabling`: those are in-flight
    /// transitions this must not race.
    pub fn begin_disable(&self) -> Result<(), BlackholeError> {
        let mut state = self.state.lock().unwrap();
        match *state {
            GuardState::Enabled | GuardState::Faulted | GuardState::Disabled => {
                *state = GuardState::Disabling;
                Ok(())
            }
            other => Err(BlackholeError::InvalidTransition {
                action: "disable",
                state: other,
            }),
        }
    }

    pub fn finish_disable(&self, success: bool) {
        let mut state = self.state.lock().unwrap();
        *state = if success {
            GuardState::Disabled
        } else {
            GuardState::Faulted
        };
    }

    /// Guard for operations (like `new_identity`) that only make sense while
    /// fully `Enabled`.
    pub fn require_enabled(&self, action: &'static str) -> Result<(), BlackholeError> {
        let state = self.state.lock().unwrap();
        match *state {
            GuardState::Enabled => Ok(()),
            other => Err(BlackholeError::InvalidTransition { action, state: other }),
        }
    }

    /// Cross-check the in-memory state against ground truth from the OS
    /// backend (nftables/WFP), so a stale or crashed process can never
    /// *report* itself as safe when it isn't. Shared by every platform
    /// backend's `status()` so this fail-closed reconciliation logic is
    /// unit-tested once here instead of duplicated (and drifting) per
    /// backend.
    ///
    /// `backend_object` names whatever "actually blocking" checked for, used
    /// only to phrase the `detail` message (e.g. `"nftables table"`,
    /// `"WFP sublayer"`).
    pub fn reconcile(&self, actually_blocking: bool, backend_object: &str) -> (GuardState, Option<String>) {
        match (self.current(), actually_blocking) {
            (GuardState::Enabled, false) => (
                GuardState::Faulted,
                Some(format!("in-memory state says enabled but {backend_object} is missing")),
            ),
            (GuardState::Disabled, true) => (
                GuardState::Faulted,
                Some(format!("in-memory state says disabled but {backend_object} is still present")),
            ),
            (other, _) => (other, None),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn starts_disabled() {
        let sm = GuardStateMachine::new();
        assert_eq!(sm.current(), GuardState::Disabled);
    }

    #[test]
    fn happy_path_enable_then_disable() {
        let sm = GuardStateMachine::new();
        sm.begin_enable().unwrap();
        assert_eq!(sm.current(), GuardState::Enabling);
        sm.finish_enable(true);
        assert_eq!(sm.current(), GuardState::Enabled);

        sm.begin_disable().unwrap();
        assert_eq!(sm.current(), GuardState::Disabling);
        sm.finish_disable(true);
        assert_eq!(sm.current(), GuardState::Disabled);
    }

    #[test]
    fn cannot_enable_twice_concurrently() {
        let sm = GuardStateMachine::new();
        sm.begin_enable().unwrap();
        let err = sm.begin_enable().unwrap_err();
        assert!(matches!(
            err,
            BlackholeError::InvalidTransition {
                action: "enable",
                state: GuardState::Enabling
            }
        ));
    }

    #[test]
    fn disable_from_already_disabled_is_allowed_for_crash_recovery() {
        // A freshly started process always begins in-memory `Disabled`,
        // with no idea whether a *previous* instance crashed after
        // `enable()` and left real OS-level rules behind. `disable()` must
        // stay callable here so an operator (or a recovery script) can
        // always ask "make sure nothing is blocking" without already
        // knowing the answer.
        let sm = GuardStateMachine::new();
        sm.begin_disable().unwrap();
        assert_eq!(sm.current(), GuardState::Disabling);
        sm.finish_disable(true);
        assert_eq!(sm.current(), GuardState::Disabled);
    }

    #[test]
    fn cannot_disable_mid_transition() {
        let sm = GuardStateMachine::new();
        sm.begin_enable().unwrap();
        let err = sm.begin_disable().unwrap_err();
        assert!(matches!(
            err,
            BlackholeError::InvalidTransition {
                action: "disable",
                state: GuardState::Enabling
            }
        ));
    }

    #[test]
    fn failed_enable_is_fail_closed_into_faulted() {
        let sm = GuardStateMachine::new();
        sm.begin_enable().unwrap();
        sm.finish_enable(false);
        assert_eq!(sm.current(), GuardState::Faulted);

        // Faulted must NOT be silently treated as safe/disabled.
        let err = sm.require_enabled("new_identity").unwrap_err();
        assert!(matches!(
            err,
            BlackholeError::InvalidTransition {
                action: "new_identity",
                state: GuardState::Faulted
            }
        ));
    }

    #[test]
    fn can_retry_enable_from_faulted() {
        let sm = GuardStateMachine::new();
        sm.begin_enable().unwrap();
        sm.finish_enable(false);
        assert_eq!(sm.current(), GuardState::Faulted);

        sm.begin_enable().unwrap();
        sm.finish_enable(true);
        assert_eq!(sm.current(), GuardState::Enabled);
    }

    #[test]
    fn can_attempt_disable_from_faulted() {
        let sm = GuardStateMachine::new();
        sm.begin_enable().unwrap();
        sm.finish_enable(false);

        sm.begin_disable().unwrap();
        sm.finish_disable(true);
        assert_eq!(sm.current(), GuardState::Disabled);
    }

    #[test]
    fn failed_disable_stays_faulted_not_enabled() {
        let sm = GuardStateMachine::new();
        sm.begin_enable().unwrap();
        sm.finish_enable(true);

        sm.begin_disable().unwrap();
        sm.finish_disable(false);
        assert_eq!(sm.current(), GuardState::Faulted);
    }

    #[test]
    fn new_identity_requires_enabled() {
        let sm = GuardStateMachine::new();
        assert!(sm.require_enabled("new_identity").is_err());

        sm.begin_enable().unwrap();
        sm.finish_enable(true);
        assert!(sm.require_enabled("new_identity").is_ok());
    }

    #[test]
    fn reconcile_flags_enabled_state_with_no_actual_blocking_as_faulted() {
        let sm = GuardStateMachine::new();
        sm.begin_enable().unwrap();
        sm.finish_enable(true);

        // A crashed process, or rules removed out from under us: the
        // in-memory state claims Enabled but the OS backend disagrees. Must
        // never be reported as still safe.
        let (state, detail) = sm.reconcile(false, "nftables table");
        assert_eq!(state, GuardState::Faulted);
        assert!(detail.unwrap().contains("nftables table"));
    }

    #[test]
    fn reconcile_flags_disabled_state_with_lingering_rules_as_faulted() {
        let sm = GuardStateMachine::new();
        // Still Disabled (never enabled), but the OS backend reports rules
        // present anyway — e.g. left over from a previous run that crashed
        // before it could record success. Not dangerous by itself (rules
        // present means still blocking), but the mismatch must surface.
        let (state, detail) = sm.reconcile(true, "WFP sublayer");
        assert_eq!(state, GuardState::Faulted);
        assert!(detail.unwrap().contains("WFP sublayer"));
    }

    #[test]
    fn reconcile_is_quiet_when_state_and_reality_agree() {
        let sm = GuardStateMachine::new();
        let (state, detail) = sm.reconcile(false, "nftables table");
        assert_eq!(state, GuardState::Disabled);
        assert!(detail.is_none());

        sm.begin_enable().unwrap();
        sm.finish_enable(true);
        let (state, detail) = sm.reconcile(true, "nftables table");
        assert_eq!(state, GuardState::Enabled);
        assert!(detail.is_none());
    }

    #[test]
    fn cannot_finish_enable_without_begin_is_harmless_but_should_not_be_called() {
        // Documents current behavior: finish_enable/finish_disable are
        // unconditional setters driven only by the backend that already
        // validated the transition via begin_*. This test pins that
        // behavior so a future refactor notices if it changes.
        let sm = GuardStateMachine::new();
        sm.finish_enable(true);
        assert_eq!(sm.current(), GuardState::Enabled);
    }
}
