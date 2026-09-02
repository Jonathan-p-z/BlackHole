//! Test-only helper: sends one UDP datagram to `target` and waits up to
//! `timeout_ms` for it to be echoed back, then exits 0 (reached the
//! destination and got a reply) or 1 (blocked, or the reply didn't arrive
//! in time). Exists so the chaos tests can observe "did this traffic
//! actually leave the network namespace" as a real black-box outcome, run
//! as a specific UID via `NetnsSandbox::exec_as_uid` — a plain socket
//! opened from inside the test's own (always-root) process couldn't do
//! that per-probe without `setuid`-ing the whole test binary.
//!
//! Usage: `chaos_udp_probe <target ip:port> <timeout_ms>`
//! Pair with a UDP echo listener bound at `target` (see
//! `blackhole_chaos`'s test modules / `spawn_udp_echo` usage in `tests/`).

use std::net::SocketAddr;
use std::time::Duration;

use tokio::net::UdpSocket;

const NONCE: &[u8] = b"blackhole-chaos-probe";

#[tokio::main]
async fn main() {
    let mut args = std::env::args().skip(1);
    let target: SocketAddr = args
        .next()
        .expect("usage: chaos_udp_probe <target> <timeout_ms>")
        .parse()
        .expect("first argument must be a valid ip:port");
    let timeout_ms: u64 = args
        .next()
        .expect("usage: chaos_udp_probe <target> <timeout_ms>")
        .parse()
        .expect("second argument must be a timeout in milliseconds");

    let socket = UdpSocket::bind("0.0.0.0:0")
        .await
        .expect("bind an ephemeral local UDP socket");
    socket.connect(target).await.expect("set default destination on the UDP socket");
    socket.send(NONCE).await.expect("send the probe datagram");

    let mut buf = [0u8; 64];
    let reached = match tokio::time::timeout(Duration::from_millis(timeout_ms), socket.recv(&mut buf)).await {
        Ok(Ok(n)) => &buf[..n] == NONCE,
        _ => false,
    };

    std::process::exit(if reached { 0 } else { 1 });
}
