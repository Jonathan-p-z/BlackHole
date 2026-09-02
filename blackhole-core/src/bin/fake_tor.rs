//! Test double for the real `tor` binary — **not shipped or installed**
//! (see `install.sh`/`install.ps1`, which only ever copy the four real
//! product binaries). Exists purely so `tests/subprocess_backend.rs` can
//! exercise `SubprocessTorBackend`'s process-management and control-port
//! logic without a real `tor` install or any network access, per the
//! project's rule against testing a real Tor bootstrap in CI.
//!
//! Understands just enough of `tor`'s CLI and control-port protocol to be
//! indistinguishable from the real thing as far as `SubprocessTorBackend`
//! can tell: `--version`, `--SocksPort`/`--ControlPort`/`--DataDirectory`,
//! a cookie file, and `AUTHENTICATE`/`GETINFO status/bootstrap-phase`/
//! `SIGNAL NEWNYM` on the control port.

use std::io::{BufRead, BufReader, Write};
use std::net::TcpListener;
use std::path::PathBuf;

fn main() {
    let args: Vec<String> = std::env::args().collect();

    if args.iter().any(|a| a == "--version") {
        println!("Tor version 0.4.8.99 (fake, for tests).");
        return;
    }

    let control_port = arg_value(&args, "--ControlPort").expect("fake_tor requires --ControlPort");
    let data_dir = PathBuf::from(
        arg_value(&args, "--DataDirectory").expect("fake_tor requires --DataDirectory"),
    );

    std::fs::create_dir_all(&data_dir).expect("create DataDirectory");
    std::fs::write(data_dir.join("control_auth_cookie"), [0xABu8; 32]).expect("write cookie");

    let control_addr = control_port_addr(&control_port);
    let listener = TcpListener::bind(&control_addr).expect("bind fake control port");

    for stream in listener.incoming() {
        let Ok(mut stream) = stream else { continue };
        let mut reader = BufReader::new(stream.try_clone().expect("clone stream"));
        let mut line = String::new();
        loop {
            line.clear();
            let n = reader.read_line(&mut line).unwrap_or(0);
            if n == 0 {
                break;
            }
            let cmd = line.trim_end();

            if cmd.starts_with("AUTHENTICATE") {
                let _ = stream.write_all(b"250 OK\r\n");
            } else if cmd.starts_with("GETINFO status/bootstrap-phase") {
                let _ = stream.write_all(b"250-status/bootstrap-phase=NOTICE BOOTSTRAP PROGRESS=100 TAG=done SUMMARY=\"Done\"\r\n250 OK\r\n");
            } else if cmd.starts_with("SIGNAL NEWNYM") {
                let _ = stream.write_all(b"250 OK\r\n");
            } else if cmd.starts_with("QUIT") {
                let _ = stream.write_all(b"250 closing connection\r\n");
                break;
            } else {
                let _ = stream.write_all(b"510 Unrecognized command\r\n");
            }
        }
    }
}

fn arg_value(args: &[String], flag: &str) -> Option<String> {
    args.iter()
        .position(|a| a == flag)
        .and_then(|i| args.get(i + 1))
        .cloned()
}

fn control_port_addr(control_port_arg: &str) -> String {
    // `SubprocessTorBackend` passes "127.0.0.1:PORT" as the whole
    // --ControlPort value, matching real tor's own accepted syntax.
    control_port_arg.to_string()
}
