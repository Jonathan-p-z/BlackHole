//! Anti-DNS-leak module for the BlackHole project: forces DNS resolution
//! through an encrypted resolver (DoH/DoT), detects when the OS is still
//! leaking plaintext queries elsewhere, and can trigger `blackhole-core`'s
//! kill switch when it does.

pub mod config;
pub mod error;
pub mod leak;
pub mod relay;
pub mod resolver;
pub mod system_dns;

pub use error::DnsError;
pub use leak::LeakReport;
pub use resolver::{EncryptedResolver, Provider, Transport};
