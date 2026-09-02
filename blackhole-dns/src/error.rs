#[derive(Debug, thiserror::Error)]
pub enum DnsError {
    #[error("encrypted resolver query failed: {0}")]
    Resolve(String),

    /// A resolved answer's DNSSEC proof was `Bogus` — the chain of trust
    /// says this record *should* be signed, but the signature (or a link
    /// in the chain) doesn't check out. Treated as tampering, not as a
    /// normal resolve failure: never fall back to trusting the answer
    /// anyway, and never confuse this with `Insecure` (a domain that
    /// legitimately isn't signed at all, which is not an error).
    #[error("DNSSEC validation failed for '{name}': {detail}")]
    DnssecValidationFailed { name: String, detail: String },

    #[error("failed to inspect or configure the OS resolver: {0}")]
    SystemConfig(String),

    #[error("local relay server error: {0}")]
    Relay(String),

    #[error("kill switch integration error: {0}")]
    Guard(#[from] blackhole_core::BlackholeError),

    #[error(transparent)]
    Io(#[from] std::io::Error),
}
