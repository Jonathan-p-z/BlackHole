//! Scenario 2: DNS resolution failure ("timeout") — no silent fallback to
//! the unencrypted system resolver, and the real leak-detection/kill-
//! switch enforcement path fires when the encrypted resolver can't be
//! reached at all.
//!
//! [`NetnsSandbox`] deliberately has no default route out at all, so a
//! real `EncryptedResolver` trying to reach a real DoH provider's IP fails
//! immediately and deterministically (`ENETUNREACH`) — functionally the
//! same "no answer ever arrives" outcome a genuine timeout produces, just
//! fast and reproducible instead of waiting out a real multi-second
//! network timeout every CI run.

use std::net::SocketAddr;
use std::time::Duration;

use blackhole_chaos::{kill_pid, workspace_binary, NetnsSandbox};
use hickory_proto::op::{Message, Query, ResponseCode};
use hickory_proto::rr::{Name, RecordType};
use tokio::net::UdpSocket;

#[tokio::test]
async fn resolve_failure_is_servfail_with_no_query_ever_sent_elsewhere() {
    let sandbox = NetnsSandbox::create(2);
    let dns_bin = workspace_binary("blackhole-dns");
    let relay_addr = sandbox.inside_addr(5300);

    // Stands in for "the OS's real unencrypted stub resolver". If anything
    // in the resolution path ever silently fell back to querying it, this
    // would see the packet. `EncryptedResolver` never actually addresses
    // this today (its own module doc: "there is no code path that can
    // fall back to an unencrypted resolver, at any priority") — the
    // assertion below is a regression guard for that invariant, not proof
    // of a currently-live risk.
    let fake_system_resolver = UdpSocket::bind(sandbox.outside_addr(53))
        .await
        .expect("bind fake system resolver stand-in");

    let mut relay = sandbox
        .exec(&dns_bin)
        .args(["serve", "--listen"])
        .arg(relay_addr.to_string())
        .spawn()
        .unwrap_or_else(|e| panic!("spawn blackhole-dns serve inside the sandbox: {e}"));

    let client = UdpSocket::bind("0.0.0.0:0").await.expect("bind test client socket");
    let query_bytes = build_a_query("example.com.");

    // Retry a few times: the relay's UDP bind happens almost instantly,
    // but `serve` has no explicit readiness signal to wait on (it logs via
    // `tracing`, gated by `RUST_LOG`, not a stable line worth matching on)
    // — a short bounded retry is more robust than guessing a fixed sleep.
    let response_bytes = send_and_receive_with_retry(&client, relay_addr, &query_bytes, 6, Duration::from_millis(400))
        .await
        .expect("relay never answered — did `blackhole-dns serve` fail to start inside the sandbox?");

    let response = Message::from_vec(&response_bytes).expect("relay's reply must be a well-formed DNS message");
    assert_eq!(
        response.metadata.response_code,
        ResponseCode::ServFail,
        "an unreachable encrypted resolver must produce SERVFAIL, never a fabricated or stale answer"
    );
    assert!(response.answers.is_empty(), "a SERVFAIL reply must carry no answer records");

    // Give a hypothetical fallback query a moment to have arrived, then
    // confirm it never did.
    tokio::time::sleep(Duration::from_millis(200)).await;
    let mut buf = [0u8; 16];
    let saw_fallback_query = tokio::time::timeout(Duration::from_millis(100), fake_system_resolver.recv(&mut buf))
        .await
        .is_ok();
    assert!(
        !saw_fallback_query,
        "no query should ever have reached the fake system resolver — that would mean a \
         silent fallback path exists"
    );

    kill_pid(relay.id());
    let _ = relay.wait();
}

#[tokio::test]
async fn unreachable_resolver_triggers_the_real_kill_switch_enforcement() {
    let sandbox = NetnsSandbox::create(6);
    let ruleset_path = std::env::temp_dir().join(format!("blackhole-chaos-6-ruleset-{}.rules", std::process::id()));
    let _ = std::fs::remove_file(&ruleset_path);

    assert!(!sandbox.table_exists(), "sanity: kill switch starts disabled");

    let output = sandbox
        .exec(env!("CARGO_BIN_EXE_chaos_dns_enforce"))
        .arg(&ruleset_path)
        .output()
        .expect("run chaos_dns_enforce");
    assert!(
        output.status.success(),
        "chaos_dns_enforce failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("LEAK_DETECTED=true"),
        "an unreachable encrypted resolver must be treated as a leak:\n{stdout}"
    );
    assert!(
        stdout.contains("ENCRYPTED_RESOLVER_REACHABLE=false"),
        "sanity: this must be the unreachable-resolver case specifically:\n{stdout}"
    );
    assert!(
        stdout.contains("GUARD_STATE=enabled"),
        "detecting the leak must actually enable the real kill switch, not just report it:\n{stdout}"
    );

    assert!(sandbox.table_exists(), "the real nftables table must exist after enforcement");
    let listing = sandbox.nft_table_listing().unwrap();
    assert!(listing.contains("policy drop"), "must be the default-deny policy, not an empty table:\n{listing}");

    let _ = std::fs::remove_file(&ruleset_path);
}

fn build_a_query(name: &str) -> Vec<u8> {
    let mut msg = Message::query();
    let mut q = Query::new();
    q.set_name(Name::from_ascii(name).expect("valid DNS name"));
    q.set_query_type(RecordType::A);
    msg.add_query(q);
    msg.to_vec().expect("serialize the query message")
}

async fn send_and_receive_with_retry(
    client: &UdpSocket,
    target: SocketAddr,
    payload: &[u8],
    attempts: u32,
    per_attempt_timeout: Duration,
) -> Option<Vec<u8>> {
    let mut buf = [0u8; 512];
    for _ in 0..attempts {
        if client.send_to(payload, target).await.is_err() {
            tokio::time::sleep(per_attempt_timeout).await;
            continue;
        }
        if let Ok(Ok((len, _src))) = tokio::time::timeout(per_attempt_timeout, client.recv_from(&mut buf)).await {
            return Some(buf[..len].to_vec());
        }
    }
    None
}
