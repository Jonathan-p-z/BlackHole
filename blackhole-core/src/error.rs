use crate::guard::GuardState;

/// Errors produced by `blackhole-core`.
///
/// Platform backends and the Tor orchestration layer are collapsed into
/// string-carrying variants on purpose: callers (the CLI, or a future GUI)
/// only ever need to log or display these, and it keeps this crate's public
/// error type decoupled from the exact version of `arti-client` or the shape
/// of a given platform's FFI errors.
#[derive(Debug, thiserror::Error)]
pub enum BlackholeError {
    #[error("cannot {action} while guard is {state}")]
    InvalidTransition {
        action: &'static str,
        state: GuardState,
    },

    #[error("firewall backend error: {0}")]
    Platform(String),

    #[error("tor orchestration error: {0}")]
    Tor(String),

    #[error("external command '{command}' failed (status {status}): {stderr}")]
    CommandFailed {
        command: String,
        status: String,
        stderr: String,
    },

    #[error(transparent)]
    Io(#[from] std::io::Error),
}
