#[derive(Debug, thiserror::Error)]
pub enum CookiesError {
    #[error("certificate authority error: {0}")]
    Ca(String),

    #[error("proxy error: {0}")]
    Proxy(String),

    #[error("failed to inspect or configure this platform's paths: {0}")]
    Platform(String),

    #[error(transparent)]
    Io(#[from] std::io::Error),
}
