# Boot persistence for the Linux kill switch

## The gap this closes

nftables' ruleset lives in kernel memory only. `blackhole-core enable`
applies it with `nft -f -`, and it stays enforced for as long as the kernel
keeps running — independent of whether `blackhole-core` itself is still
alive (that's the whole point of the fail-closed design: killing the
process doesn't open the firewall back up). But a **reboot** resets kernel
memory entirely. Left alone, that means: kill switch on, machine reboots
(planned or crashed), machine comes back up with **no rules at all** —
wide open, silently, exactly the "reset to clear by default" this project
exists to prevent.

This has two independent halves:

1. **Persisting what to restore** — automatic, always on, no setup needed.
2. **Actually restoring it at boot** — optional, one-time, requires root to
   install. Without step 2, step 1 alone changes nothing.

## 1. Persisting the ruleset (automatic)

Every successful `blackhole-core enable` writes the exact ruleset it just
applied to `/etc/blackhole/nftables.rules` (owner-only, mode `0600` — it's
trusted `nft -f` input re-run as root later). Every successful `disable`
removes that file again. This requires no extra setup: `enable`/`disable`
already need root for `nft` itself, so writing to `/etc/blackhole/` adds no
new privilege requirement.

If the write fails (read-only `/etc`, disk full, ...), `enable` itself
fails — the boot-restore guarantee is treated as part of what "enabled"
means, not a best-effort extra that can silently not happen.

Override the path with `BLACKHOLE_NFTABLES_RULESET_PATH` if `/etc/blackhole`
doesn't fit your system's layout. If you do, also update `ConditionPathExists`
and add `Environment=BLACKHOLE_NFTABLES_RULESET_PATH=...` to the systemd
unit below.

## 2. Restoring it at boot (opt-in, one-time setup, needs root)

`blackhole-core restore-firewall` re-applies the persisted file. It starts
no Tor backend and attempts no bootstrap — it only needs the ruleset file
to be readable and `nft` to be on `PATH`, so it runs fast, early in boot,
before the network is up.

Nothing calls this automatically until you install the provided systemd
unit — deliberately not done by `install.sh`/`install.ps1`, which never
touch root-owned or system-wide paths. To enable it:

```sh
# 1. blackhole-core needs to be reachable from a system path root can
#    exec at boot — install.sh only puts it in ~/.local/bin. Either copy
#    it system-wide, or point ExecStart at your actual install path:
sudo cp ~/.local/bin/blackhole-core /usr/local/bin/blackhole-core

# 2. Install and enable the unit:
sudo cp packaging/systemd/blackhole-killswitch-restore.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable blackhole-killswitch-restore.service
```

Verify it actually ran after a real reboot:

```sh
systemctl status blackhole-killswitch-restore.service
sudo nft list table inet blackhole   # should show the restored table
```

If the kill switch was never enabled (or was cleanly disabled) before that
reboot, the unit is skipped (`ConditionPathExists` fails) — that's the
correct, expected outcome, not an error.

## What this does — and does not — guarantee

- **Does**: close the specific gap above — a *clean* persisted ruleset from
  the last successful `enable` gets re-applied before network comes up, with
  no dependency on `blackhole-core` or Tor being alive yet.
- **Does not**: proactively fall back to a hard "block everything" ruleset
  if the persisted file is missing or corrupted. `restore_persisted_ruleset`
  reports "nothing to restore" for a missing file (the correct baseline for
  "never enabled") and returns a loud error for a file that exists but
  fails to parse — visible in `systemctl status` as a failed unit — rather
  than silently doing nothing or guessing a safe ruleset. Deciding on a
  blind pre-Tor default-deny fallback in the corrupted-file case is a
  reasonable future addition, not something this pass implements; flagged
  here rather than left as a silent assumption.
- **Does not** protect against an attacker with root who deletes the
  ruleset file, disables the unit, or edits it before the restore runs —
  same trust boundary as the rest of `blackhole-core` (see its
  `THREAT_MODEL.md`: root-level compromise of the machine is out of scope).
- **Windows**: no equivalent exists yet. WFP filters, unlike nftables
  tables, are already commonly re-applied by whatever service manages them
  at logon/boot in a typical setup, but `blackhole-core` doesn't currently
  register itself as a boot-time Windows service either — this doc and the
  systemd unit are Linux-only. Flagged as a gap, not silently assumed
  covered.

## Tested by

`chaos/tests/scenario_4_reboot_restores_firewall.rs` (see `chaos/README.md`)
exercises this exact path end-to-end: enable the real kill switch inside an
isolated network namespace, wipe the live nftables ruleset to simulate what
a reboot does to kernel memory, then run the real `blackhole-core
restore-firewall` binary — with no `blackhole-core` process left running at
all — and confirm the table (default-deny policy) is back.
