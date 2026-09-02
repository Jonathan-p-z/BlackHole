//! Minimal client for Tor's control-port protocol — a simple,
//! line-oriented text protocol the Tor Project documents at
//! <https://spec.torproject.org/control-spec/>. Implements only the three
//! operations [`crate::tor_subprocess::SubprocessTorBackend`] needs:
//! cookie authentication, `GETINFO status/bootstrap-phase`, and `SIGNAL
//! NEWNYM`. Deliberately not a general-purpose Tor control library —
//! consistent with this project's rule for the subprocess backend as a
//! whole: orchestrate the official binary, never reimplement anything
//! about Tor itself. This module doesn't touch Tor's network protocol or
//! cryptography at all; it only speaks the small operator-facing control
//! channel the Tor Project built for exactly this kind of external
//! supervision.

use std::path::Path;
use std::time::Duration;

use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpStream;
use tokio::time::Instant;

use crate::error::BlackholeError;

pub struct ControlClient {
    stream: BufReader<TcpStream>,
}

impl ControlClient {
    /// Connect to the control port at `addr` and authenticate using the
    /// cookie at `cookie_path`, retrying both the TCP connection and the
    /// cookie-file read for up to `deadline_from_now` — right after
    /// spawning `tor`, its listener and cookie file don't exist yet, and
    /// there's no signal-free way to know exactly when they will.
    pub async fn connect(
        addr: std::net::SocketAddr,
        cookie_path: &Path,
        deadline_from_now: Duration,
    ) -> Result<Self, BlackholeError> {
        let deadline = Instant::now() + deadline_from_now;

        let stream = retry_until(deadline, || async {
            TcpStream::connect(addr).await.map_err(|e| e.to_string())
        })
        .await
        .map_err(|e| {
            BlackholeError::Tor(format!(
                "could not connect to tor control port at {addr}: {e}"
            ))
        })?;

        let cookie = retry_until(deadline, || async {
            tokio::fs::read(cookie_path)
                .await
                .map_err(|e| e.to_string())
        })
        .await
        .map_err(|e| {
            BlackholeError::Tor(format!(
                "tor control auth cookie never appeared at {}: {e}",
                cookie_path.display()
            ))
        })?;

        let mut client = Self {
            stream: BufReader::new(stream),
        };
        client.authenticate(&cookie).await?;
        Ok(client)
    }

    async fn send_line(&mut self, line: &str) -> Result<(), BlackholeError> {
        let stream = self.stream.get_mut();
        stream.write_all(line.as_bytes()).await?;
        stream.write_all(b"\r\n").await?;
        Ok(())
    }

    async fn read_reply_line(&mut self) -> Result<String, BlackholeError> {
        let mut line = String::new();
        let n = self.stream.read_line(&mut line).await?;
        if n == 0 {
            return Err(BlackholeError::Tor(
                "tor control port closed the connection unexpectedly".to_string(),
            ));
        }
        Ok(line.trim_end_matches(['\r', '\n']).to_string())
    }

    async fn authenticate(&mut self, cookie: &[u8]) -> Result<(), BlackholeError> {
        let hex: String = cookie.iter().map(|b| format!("{b:02x}")).collect();
        self.send_line(&format!("AUTHENTICATE {hex}")).await?;
        let reply = self.read_reply_line().await?;
        if !reply.starts_with("250") {
            return Err(BlackholeError::Tor(format!(
                "tor control AUTHENTICATE failed: {reply}"
            )));
        }
        Ok(())
    }

    /// `GETINFO status/bootstrap-phase` → `(percent, ready_for_traffic, blocked_reason)`.
    /// A single-key `GETINFO` reply is two lines: `250-key=value` (the
    /// data line) then `250 OK` (the terminator) — read both.
    pub async fn bootstrap_status(&mut self) -> Result<(u8, bool, Option<String>), BlackholeError> {
        self.send_line("GETINFO status/bootstrap-phase").await?;
        let data_line = self.read_reply_line().await?;
        let terminator = self.read_reply_line().await?;
        if !terminator.starts_with("250") {
            return Err(BlackholeError::Tor(format!(
                "unexpected GETINFO status/bootstrap-phase reply: {data_line} / {terminator}"
            )));
        }

        let percent = data_line
            .split("PROGRESS=")
            .nth(1)
            .and_then(|rest| rest.split_whitespace().next())
            .and_then(|s| s.parse::<u8>().ok())
            .unwrap_or(0);
        let ready_for_traffic = data_line.contains("TAG=done");
        let blocked_reason = (data_line.contains(" WARN ") || data_line.contains(" ERR "))
            .then(|| data_line.clone());

        Ok((percent, ready_for_traffic, blocked_reason))
    }

    /// `SIGNAL NEWNYM` — request a fresh identity (new circuits for new
    /// streams), the subprocess-backend equivalent of arti's
    /// `isolated_client()`.
    pub async fn new_identity(&mut self) -> Result<(), BlackholeError> {
        self.send_line("SIGNAL NEWNYM").await?;
        let reply = self.read_reply_line().await?;
        if !reply.starts_with("250") {
            return Err(BlackholeError::Tor(format!(
                "tor control SIGNAL NEWNYM failed: {reply}"
            )));
        }
        Ok(())
    }
}

/// Retry `f` (an async operation returning `Result<T, String>`) every
/// 100ms until it succeeds or `deadline` passes.
async fn retry_until<T, F, Fut>(deadline: Instant, mut f: F) -> Result<T, String>
where
    F: FnMut() -> Fut,
    Fut: std::future::Future<Output = Result<T, String>>,
{
    loop {
        match f().await {
            Ok(v) => return Ok(v),
            Err(e) => {
                if Instant::now() >= deadline {
                    return Err(e);
                }
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::AsyncReadExt;
    use tokio::net::TcpListener;

    /// Spawn a tiny in-process fake control port that speaks just enough
    /// of the protocol to exercise `ControlClient` end to end, without a
    /// real `tor` binary. Real subprocess-management (spawning the actual
    /// child) is covered separately in `tests/subprocess_backend.rs`
    /// against a fake `tor` executable; this is the protocol layer alone.
    async fn fake_control_server(listener: TcpListener, script: Vec<(&'static str, &'static str)>) {
        let (mut socket, _) = listener.accept().await.unwrap();
        let mut buf = [0u8; 1024];
        for (expect_prefix, reply) in script {
            let n = socket.read(&mut buf).await.unwrap();
            let received = String::from_utf8_lossy(&buf[..n]);
            assert!(
                received.starts_with(expect_prefix),
                "expected command starting with {expect_prefix:?}, got {received:?}"
            );
            socket.write_all(reply.as_bytes()).await.unwrap();
        }
    }

    #[tokio::test]
    async fn authenticates_and_reads_bootstrap_status() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let dir = std::env::temp_dir().join(format!(
            "blackhole-core-control-test-{}",
            std::process::id()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let cookie_path = dir.join("cookie");
        std::fs::write(&cookie_path, [0xABu8; 32]).unwrap();

        let server = tokio::spawn(fake_control_server(
            listener,
            vec![
                ("AUTHENTICATE", "250 OK\r\n"),
                (
                    "GETINFO status/bootstrap-phase",
                    "250-status/bootstrap-phase=NOTICE BOOTSTRAP PROGRESS=100 TAG=done SUMMARY=\"Done\"\r\n250 OK\r\n",
                ),
            ],
        ));

        let mut client = ControlClient::connect(addr, &cookie_path, Duration::from_secs(2))
            .await
            .unwrap();
        let (percent, ready, blocked) = client.bootstrap_status().await.unwrap();

        assert_eq!(percent, 100);
        assert!(ready);
        assert!(blocked.is_none());

        server.await.unwrap();
        std::fs::remove_dir_all(&dir).ok();
    }

    #[tokio::test]
    async fn authenticate_failure_is_reported_not_panicked() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let dir = std::env::temp_dir().join(format!(
            "blackhole-core-control-test-authfail-{}",
            std::process::id()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let cookie_path = dir.join("cookie");
        std::fs::write(&cookie_path, [0u8; 32]).unwrap();

        let server = tokio::spawn(fake_control_server(
            listener,
            vec![("AUTHENTICATE", "515 Authentication failed\r\n")],
        ));

        let result = ControlClient::connect(addr, &cookie_path, Duration::from_secs(2)).await;
        assert!(result.is_err());

        server.await.unwrap();
        std::fs::remove_dir_all(&dir).ok();
    }

    #[tokio::test]
    async fn new_identity_sends_signal_newnym() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let dir = std::env::temp_dir().join(format!(
            "blackhole-core-control-test-newnym-{}",
            std::process::id()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let cookie_path = dir.join("cookie");
        std::fs::write(&cookie_path, [0u8; 32]).unwrap();

        let server = tokio::spawn(fake_control_server(
            listener,
            vec![
                ("AUTHENTICATE", "250 OK\r\n"),
                ("SIGNAL NEWNYM", "250 OK\r\n"),
            ],
        ));

        let mut client = ControlClient::connect(addr, &cookie_path, Duration::from_secs(2))
            .await
            .unwrap();
        client.new_identity().await.unwrap();

        server.await.unwrap();
        std::fs::remove_dir_all(&dir).ok();
    }

    #[tokio::test]
    async fn bootstrap_in_progress_is_not_ready_and_not_blocked() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let dir = std::env::temp_dir().join(format!(
            "blackhole-core-control-test-progress-{}",
            std::process::id()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let cookie_path = dir.join("cookie");
        std::fs::write(&cookie_path, [0u8; 32]).unwrap();

        let server = tokio::spawn(fake_control_server(
            listener,
            vec![
                ("AUTHENTICATE", "250 OK\r\n"),
                (
                    "GETINFO status/bootstrap-phase",
                    "250-status/bootstrap-phase=NOTICE BOOTSTRAP PROGRESS=42 TAG=handshake_dir SUMMARY=\"Handshaking\"\r\n250 OK\r\n",
                ),
            ],
        ));

        let mut client = ControlClient::connect(addr, &cookie_path, Duration::from_secs(2))
            .await
            .unwrap();
        let (percent, ready, blocked) = client.bootstrap_status().await.unwrap();

        assert_eq!(percent, 42);
        assert!(!ready);
        assert!(blocked.is_none());

        server.await.unwrap();
        std::fs::remove_dir_all(&dir).ok();
    }
}
