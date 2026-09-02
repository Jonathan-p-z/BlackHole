//! Test-only helper: runs one real `blackhole_dns::leak::check` against a
//! Cloudflare-only `EncryptedResolver`, then — since inside the chaos
//! sandbox there's deliberately no route to a real Cloudflare IP (see
//! `blackhole_chaos::NetnsSandbox`'s doc comment), that's a genuine,
//! deterministic "encrypted resolver unreachable" leak — runs the real
//! `leak::enforce_on_leak` against a real `LinuxGuard` (built against the
//! always-ready fake Tor backend, no real bootstrap needed).
//!
//! This exists so `tests/scenario_2_dns_timeout_no_fallback.rs` can prove
//! the enforcement path fires end-to-end against real nftables, not just
//! the `FakeGuard`-based unit tests already in `blackhole-dns/src/leak.rs`.
//!
//! Usage: `chaos_dns_enforce <ruleset-path>`. Prints one line:
//! `LEAK_DETECTED=<bool> ENCRYPTED_RESOLVER_REACHABLE=<bool> GUARD_STATE=<state>`

use std::sync::Arc;

use blackhole_chaos::AlwaysReadyTor;
use blackhole_core::{NetworkGuard, PlatformGuard};
use blackhole_dns::resolver::Transport;
use blackhole_dns::{leak, EncryptedResolver, Provider};

#[tokio::main]
async fn main() {
    let ruleset_path = std::env::args()
        .nth(1)
        .expect("usage: chaos_dns_enforce <ruleset-path>");

    let resolver = EncryptedResolver::single(Provider::Cloudflare, Transport::Doh)
        .expect("building a single-provider resolver cannot fail");

    let report = leak::check(&resolver, &[])
        .await
        .expect("leak::check never itself errors, even when the resolver is unreachable");

    let guard = PlatformGuard::with_ruleset_path(Arc::new(AlwaysReadyTor), ruleset_path.into());
    leak::enforce_on_leak(&report, &guard)
        .await
        .expect("enforce_on_leak must succeed against a real, working nft backend");

    let status = guard
        .status()
        .await
        .expect("status() must succeed right after enforcement");

    println!(
        "LEAK_DETECTED={} ENCRYPTED_RESOLVER_REACHABLE={} GUARD_STATE={}",
        report.leak_detected, report.encrypted_resolver_reachable, status.state
    );
}
