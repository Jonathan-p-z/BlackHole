//! Reads (and can rewrite) the OS's currently *active* DNS server
//! configuration. This is the ground truth leak detection compares against:
//! it doesn't matter what we intended to configure if the OS is actually
//! still sending plaintext queries somewhere else.

#[cfg(target_os = "windows")]
use std::net::IpAddr;

#[cfg(target_os = "windows")]
use crate::error::DnsError;
#[cfg(target_os = "windows")]
use crate::resolver::Provider;

#[cfg(target_os = "linux")]
mod linux;
#[cfg(target_os = "linux")]
pub use linux::{active_servers, force_via_dot, force_via_relay};

#[cfg(target_os = "windows")]
mod windows;
#[cfg(target_os = "windows")]
pub use windows::{active_servers, force_via_relay};

/// DNS-over-TLS is configured through systemd-resolved on Linux; Windows
/// has no equivalent single OS-native switch this crate drives directly
/// (see module docs on the Windows side), so on Windows this always
/// forwards to `force_via_relay` against the loopback relay instead.
#[cfg(target_os = "windows")]
pub fn force_via_dot(_provider: Provider) -> Result<(), DnsError> {
    force_via_relay(IpAddr::V4(std::net::Ipv4Addr::LOCALHOST))
}
