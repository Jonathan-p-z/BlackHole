//! Builds and runs the actual local proxy. Binds to `127.0.0.1` only,
//! never `0.0.0.0` or any other interface; see `THREAT_MODEL.md`'s
//! opening section, point 1. This is the only file in this crate that
//! constructs a `hudsucker::Proxy`.

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;

use hudsucker::Proxy;
use hudsucker::rustls::crypto::aws_lc_rs;

use crate::ca::{self, CaPaths};
use crate::cookie_store::CookieStore;
use crate::error::CookiesError;
use crate::handler::CookieRandomizingHandler;
use crate::tracker_list::TrackerList;

/// Runs the proxy until `shutdown` completes. Never returns while the
/// proxy is healthy; `shutdown` is how a caller (the CLI's signal
/// handler, or a test) asks it to stop.
pub async fn run(
    port: u16,
    tracker_list: TrackerList,
    ca_paths: CaPaths,
    shutdown: impl std::future::Future<Output = ()> + Send + 'static,
) -> Result<Arc<CookieStore>, CookiesError> {
    let authority = ca::load_or_generate(&ca_paths)?;
    let cookie_store = Arc::new(CookieStore::new());
    let handler = CookieRandomizingHandler::new(Arc::new(tracker_list), Arc::clone(&cookie_store));

    let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), port);

    let proxy = Proxy::builder()
        .with_addr(addr)
        .with_ca(authority)
        .with_rustls_connector(aws_lc_rs::default_provider())
        .with_http_handler(handler)
        .with_graceful_shutdown(shutdown)
        .build()
        .map_err(|e| CookiesError::Proxy(format!("failed to build proxy: {e}")))?;

    proxy
        .start()
        .await
        .map_err(|e| CookiesError::Proxy(format!("proxy exited with an error: {e}")))?;

    Ok(cookie_store)
}
