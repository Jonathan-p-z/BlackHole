#[derive(Debug, thiserror::Error)]
pub enum FingerprintError {
    #[error("failed to inspect system configuration: {0}")]
    Inspect(String),

    #[error("failed to apply hardening change: {0}")]
    Harden(String),

    #[error("exposure check request failed: {0}")]
    Exposure(#[from] reqwest::Error),

    #[error("scan history error: {0}")]
    History(String),

    #[error(transparent)]
    Io(#[from] std::io::Error),
}
