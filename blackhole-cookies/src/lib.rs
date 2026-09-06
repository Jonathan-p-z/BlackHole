//! Local HTTP/HTTPS proxy that randomizes third-party tracker cookie
//! values per session, without blocking the trackers' requests outright.
//! **Read `THREAT_MODEL.md` before using this crate**: it uses the same
//! local TLS-interception mechanism as spyware, and installing its root
//! CA is a decision with real, permanent consequences if that CA's key
//! is ever compromised. This crate is never enabled by installing
//! BlackHole; see `THREAT_MODEL.md`'s "Mandatory safeguards".

pub mod ca;
pub mod config;
pub mod cookie_store;
pub mod error;
pub mod handler;
pub mod proxy;
pub mod stats;
pub mod tracker_list;

pub use error::CookiesError;
