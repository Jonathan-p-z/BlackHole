//! Scenario 4: the machine reboots with the kill switch active — the
//! firewall state must be restored at boot from what was persisted, not
//! silently reset to open by default. See `BOOT_PERSISTENCE.md` for the
//! feature this exercises (added specifically because this test's premise
//! exposed a real, previously-unhandled gap: nftables' ruleset lives in
//! kernel memory only, so nothing restored it after a reboot before this).
//!
//! A real reboot isn't reproducible in CI, so this simulates precisely the
//! part of a reboot that matters here: the in-kernel nftables ruleset
//! disappearing ([`NetnsSandbox::simulate_reboot_wipe`]) while the
//! persisted ruleset *file* survives (plain disk state, unaffected by a
//! reboot) — then runs the real `blackhole-core restore-firewall` binary,
//! with no `blackhole-core`-equivalent process left alive at all, exactly
//! as the optional systemd unit in `packaging/systemd/` would at boot.

use std::time::Duration;

use blackhole_chaos::{kill_pid, spawn_and_wait_for_line, workspace_binary, NetnsSandbox};

#[tokio::test]
async fn restore_firewall_reapplies_the_persisted_ruleset_after_a_simulated_reboot() {
    let sandbox = NetnsSandbox::create(4);
    let core_bin = workspace_binary("blackhole-core");
    let ruleset_path = std::env::temp_dir().join(format!("blackhole-chaos-4-ruleset-{}.rules", std::process::id()));
    let _ = std::fs::remove_file(&ruleset_path);

    // Enable the real kill switch — this also persists the ruleset to
    // `ruleset_path` as a side effect of a real `enable()` (see
    // blackhole-core/src/platform/linux.rs).
    let mut enabled = spawn_and_wait_for_line(
        sandbox.exec(env!("CARGO_BIN_EXE_chaos_enable_and_hang")).arg(&ruleset_path),
        "READY",
        Duration::from_secs(10),
    );
    assert!(sandbox.table_exists(), "sanity: kill switch must be live right after enable");
    assert!(ruleset_path.is_file(), "enable() must have persisted the ruleset to disk");

    // "The machine reboots": no blackhole-core-equivalent process survives
    // a reboot either, so kill it first — matches scenario 3's already-
    // proven baseline that OS state doesn't depend on this.
    kill_pid(enabled.id());
    let _ = enabled.wait();

    sandbox.simulate_reboot_wipe();
    assert!(
        !sandbox.table_exists(),
        "sanity: the simulated reboot must actually have wiped the live nftables state"
    );
    assert!(
        ruleset_path.is_file(),
        "the persisted ruleset *file* must survive a reboot — it's plain disk state, \
         unlike nftables' kernel-memory-only ruleset"
    );

    // The actual boot-restore step — exactly what
    // packaging/systemd/blackhole-killswitch-restore.service runs, with no
    // Tor backend started and no blackhole-core process alive at all.
    let output = sandbox
        .exec(&core_bin)
        .arg("restore-firewall")
        .env("BLACKHOLE_NFTABLES_RULESET_PATH", &ruleset_path)
        .output()
        .expect("run blackhole-core restore-firewall");
    assert!(
        output.status.success(),
        "restore-firewall must succeed against a ruleset it just wrote itself: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("restored"), "expected a 'restored' confirmation, got:\n{stdout}");

    assert!(
        sandbox.table_exists(),
        "the nftables table must be back after restore-firewall, with no live process \
         maintaining it beyond that one-shot command"
    );
    let listing = sandbox.nft_table_listing().unwrap();
    assert!(listing.contains("policy drop"), "must be the same default-deny policy as before the reboot:\n{listing}");

    let _ = std::fs::remove_file(&ruleset_path);
}

#[tokio::test]
async fn restore_firewall_with_nothing_persisted_is_a_correct_no_op() {
    // The other half of "not reset to clear by default": a machine that
    // never enabled the kill switch (or cleanly disabled it before
    // shutting down) must NOT come up with any table at all — restoring
    // *something* unconditionally would be its own kind of wrong.
    let sandbox = NetnsSandbox::create(5);
    let core_bin = workspace_binary("blackhole-core");
    let ruleset_path = std::env::temp_dir().join(format!("blackhole-chaos-5-ruleset-{}.rules", std::process::id()));
    let _ = std::fs::remove_file(&ruleset_path);

    let output = sandbox
        .exec(&core_bin)
        .arg("restore-firewall")
        .env("BLACKHOLE_NFTABLES_RULESET_PATH", &ruleset_path)
        .output()
        .expect("run blackhole-core restore-firewall");
    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("nothing to restore"),
        "a missing ruleset file must be treated as the correct 'never enabled' baseline, \
         not an error, and must not install a spurious table:\n{stdout}"
    );

    assert!(
        !sandbox.table_exists(),
        "restoring with nothing persisted must not create any nftables table at all"
    );
}
