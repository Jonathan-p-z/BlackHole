//! Real end-to-end test: a genuine `blackhole_cookies::proxy::run` proxy,
//! a fake local "tracker" HTTP server (never a real tracker domain, per
//! the project's testing convention), and a real HTTP client routed
//! through the proxy over plain HTTP. Plain HTTP (not HTTPS) is used
//! deliberately: it exercises the exact same `HttpHandler` code path a
//! real MITM'd HTTPS connection would (hudsucker calls
//! `handle_request`/`handle_response` identically either way), without
//! this test needing to also stand up a TLS server and get a test HTTP
//! client to trust a freshly generated CA, which the proxy's own CA
//! machinery is already covered by real unit tests for (`ca.rs`,
//! `handler.rs`).

use std::io::ErrorKind;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::time::Duration;

use blackhole_cookies::ca;
use blackhole_cookies::tracker_list::TrackerList;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

/// A minimal fake HTTP/1.1 server standing in for a third-party tracker:
/// reads one request and replies with a fixed `Set-Cookie` header
/// carrying an obviously-fake "real" value, then closes the connection.
/// Never a real tracker's hostname or response shape, just enough HTTP to
/// exercise the proxy's request/response handling.
async fn spawn_fake_tracker_server() -> SocketAddr {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let addr = listener.local_addr().unwrap();

    tokio::spawn(async move {
        loop {
            let Ok((mut socket, _)) = listener.accept().await else {
                break;
            };
            tokio::spawn(async move {
                let mut buf = [0u8; 4096];
                // Just drain whatever the client sent; this fake server
                // doesn't need to parse the request, only respond.
                let _ = socket.read(&mut buf).await;

                let body = "ok";
                let response = format!(
                    "HTTP/1.1 200 OK\r\n\
                     Set-Cookie: trackid=REALVALUE123; Path=/\r\n\
                     Content-Length: {}\r\n\
                     Connection: close\r\n\
                     \r\n\
                     {body}",
                    body.len()
                );
                let _ = socket.write_all(response.as_bytes()).await;
                let _ = socket.shutdown().await;
            });
        }
    });

    addr
}

/// A free `127.0.0.1` port for the proxy itself to listen on, obtained
/// the standard way (bind to port 0, read back the assigned port, then
/// drop the listener before the real proxy binds the same port).
async fn free_local_port() -> u16 {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    listener.local_addr().unwrap().port()
}

#[tokio::test]
async fn tracker_domain_gets_its_set_cookie_value_randomized_end_to_end() {
    let tracker_addr = spawn_fake_tracker_server().await;
    let tracker_host = tracker_addr.ip().to_string(); // "127.0.0.1": see module doc.

    let proxy_port = free_local_port().await;
    let ca_dir = std::env::temp_dir().join(format!(
        "blackhole-cookies-proxy-it-ca-{}",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&ca_dir);
    let ca_paths = ca::CaPaths {
        cert_path: ca_dir.join("hudsucker.cer"),
        key_path: ca_dir.join("hudsucker.key"),
    };

    let tracker_list = TrackerList::from_domains([tracker_host.clone()]);
    let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel::<()>();
    let shutdown = async {
        let _ = shutdown_rx.await;
    };

    let proxy_handle = tokio::spawn(blackhole_cookies::proxy::run(
        proxy_port,
        tracker_list,
        ca_paths,
        shutdown,
    ));

    wait_for_port_open(proxy_port).await;

    let proxy_url = format!("http://127.0.0.1:{proxy_port}");
    let client = reqwest::Client::builder()
        .proxy(reqwest::Proxy::http(&proxy_url).unwrap())
        .build()
        .expect("build proxied HTTP client");

    let target_url = format!("http://{tracker_addr}/");
    let response = client
        .get(&target_url)
        .send()
        .await
        .expect("request through the proxy to the fake tracker");

    let set_cookie_values: Vec<String> = response
        .headers()
        .get_all(reqwest::header::SET_COOKIE)
        .iter()
        .map(|v| v.to_str().unwrap().to_string())
        .collect();

    assert_eq!(
        set_cookie_values.len(),
        1,
        "expected exactly one Set-Cookie header, got: {set_cookie_values:?}"
    );
    assert!(
        !set_cookie_values[0].contains("REALVALUE123"),
        "the tracker's real cookie value must never reach the client unmodified, got: {}",
        set_cookie_values[0]
    );
    assert!(
        set_cookie_values[0].starts_with("trackid="),
        "cookie name must be preserved, only the value randomized, got: {}",
        set_cookie_values[0]
    );
    assert!(
        set_cookie_values[0].contains("Path=/"),
        "non-value attributes must be preserved, got: {}",
        set_cookie_values[0]
    );

    let _ = shutdown_tx.send(());
    let _ = tokio::time::timeout(Duration::from_secs(5), proxy_handle).await;
    std::fs::remove_dir_all(&ca_dir).ok();
}

#[tokio::test]
async fn non_tracker_domain_passes_through_with_the_real_cookie_value_untouched() {
    let server_addr = spawn_fake_tracker_server().await;

    let proxy_port = free_local_port().await;
    let ca_dir = std::env::temp_dir().join(format!(
        "blackhole-cookies-proxy-it-passthrough-ca-{}",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&ca_dir);
    let ca_paths = ca::CaPaths {
        cert_path: ca_dir.join("hudsucker.cer"),
        key_path: ca_dir.join("hudsucker.key"),
    };

    // Deliberately does NOT include this server's host: this is the
    // "site you're actually visiting" case from THREAT_MODEL.md's "For
    // everything else: pass through unchanged".
    let tracker_list = TrackerList::from_domains(["totally-different-domain.invalid".to_string()]);
    let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel::<()>();
    let shutdown = async {
        let _ = shutdown_rx.await;
    };

    let proxy_handle = tokio::spawn(blackhole_cookies::proxy::run(
        proxy_port,
        tracker_list,
        ca_paths,
        shutdown,
    ));
    wait_for_port_open(proxy_port).await;

    let proxy_url = format!("http://127.0.0.1:{proxy_port}");
    let client = reqwest::Client::builder()
        .proxy(reqwest::Proxy::http(&proxy_url).unwrap())
        .build()
        .expect("build proxied HTTP client");

    let response = client
        .get(format!("http://{server_addr}/"))
        .send()
        .await
        .expect("request through the proxy to the fake (non-tracker) server");

    let set_cookie = response
        .headers()
        .get(reqwest::header::SET_COOKIE)
        .unwrap()
        .to_str()
        .unwrap();
    assert!(
        set_cookie.contains("REALVALUE123"),
        "a non-tracker domain's cookie must pass through completely unmodified, got: {set_cookie}"
    );

    let _ = shutdown_tx.send(());
    let _ = tokio::time::timeout(Duration::from_secs(5), proxy_handle).await;
    std::fs::remove_dir_all(&ca_dir).ok();
}

async fn wait_for_port_open(port: u16) {
    let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), port);
    for _ in 0..100 {
        match tokio::net::TcpStream::connect(addr).await {
            Ok(_) => return,
            Err(e) if e.kind() == ErrorKind::ConnectionRefused => {
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
            Err(_) => {
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        }
    }
    panic!("proxy never started listening on 127.0.0.1:{port}");
}
