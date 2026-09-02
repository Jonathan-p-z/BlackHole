//! Linux kill switch backend, implemented on top of `nftables` (via the
//! `nft` CLI rather than a netlink binding, so this crate doesn't need to
//! track the kernel's nftables netlink ABI itself).
//!
//! "Only allow traffic via the designated Tor egress" is implemented as
//! "only allow outbound traffic owned by this process's UID, plus loopback
//! and already-established connections". Everything else is dropped by the
//! chain's default policy, so the kill switch fails closed if the process
//! crashes or the rules are only partially applied. This holds for either
//! `TorBackend`: `arti` runs in-process (no separate daemon), and the
//! subprocess backend's child `tor` process inherits this process's UID
//! when spawned — a UID-scoped rule doesn't need to distinguish the two.
//!
//! Known scoping limitation (documented rather than hidden): matching on
//! UID allows *any* process run by the same user, not just this binary (or
//! its Tor child). For stricter isolation, run blackhole-core under a
//! dedicated system account and adjust `current_uid()` accordingly, or
//! extend this backend to match on cgroup instead of UID (`nft` supports
//! `socket cgroupv2 ...` matches on recent kernels).
//!
//! ## Boot persistence
//!
//! nftables' ruleset lives in kernel memory only — nothing reloads it
//! automatically after a reboot. Left alone, that means a machine that had
//! the kill switch on before a reboot (or a crash that took the whole
//! machine down) comes back up with **no rules at all**: wide open,
//! silently, exactly the "reset to clear by default" this crate exists to
//! prevent. `enable()` closes that gap by writing the exact ruleset it just
//! applied to disk (see [`default_ruleset_path`]); `disable()` removes that
//! file again. [`restore_persisted_ruleset`] re-applies it — this is what
//! `blackhole-core restore-firewall` runs, and what the optional systemd
//! unit in `packaging/systemd/` calls at boot, before network comes up.
//! **The persistence file alone does nothing without that unit being
//! installed** — see `BOOT_PERSISTENCE.md` for the (opt-in, one-time,
//! root-requiring) setup and exactly what it does and doesn't guarantee.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use async_trait::async_trait;
use tokio::process::Command;
use tracing::{info, warn};

use crate::error::BlackholeError;
use crate::guard::{GuardStateMachine, GuardStatus, NetworkGuard};
use crate::tor::TorBackend;

const NFT_BIN: &str = "nft";
const TABLE_FAMILY: &str = "inet";
const TABLE_NAME: &str = "blackhole";

/// Where `enable()`/`disable()` persist (or remove) the applied ruleset so
/// [`restore_persisted_ruleset`] can re-apply it at boot. Overridable via
/// `BLACKHOLE_NFTABLES_RULESET_PATH` — mainly so `blackhole-chaos`'s
/// reboot-simulation test doesn't need to write into the real `/etc`, but
/// it's a legitimate knob for a non-standard system layout too.
pub fn default_ruleset_path() -> PathBuf {
    if let Some(p) = std::env::var_os("BLACKHOLE_NFTABLES_RULESET_PATH") {
        return PathBuf::from(p);
    }
    PathBuf::from("/etc/blackhole/nftables.rules")
}

/// What [`restore_persisted_ruleset`] actually did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RulesetRestoreOutcome {
    /// A persisted ruleset existed and was successfully re-applied.
    Restored,
    /// No persisted ruleset file was found — correct baseline for a
    /// machine that never enabled the kill switch, or cleanly disabled it
    /// before shutting down. Not an error.
    NothingPersisted,
}

/// Re-apply the ruleset last written by `enable()`, if any. Deliberately
/// standalone (no `LinuxGuard`, no `TorBackend`) — this is what runs at
/// boot, before Tor or blackhole-core itself needs to be alive, so a
/// reboot's window of "firewall not yet re-applied" stays as short as
/// possible. A persisted file that fails to load (corrupted, hand-edited
/// into something invalid) is reported as an error rather than silently
/// skipped — loud failure over a silent fail-open. See `BOOT_PERSISTENCE.md`
/// for what this does and does not guarantee.
pub async fn restore_persisted_ruleset(path: &Path) -> Result<RulesetRestoreOutcome, BlackholeError> {
    if !path.is_file() {
        info!(path = %path.display(), "no persisted kill-switch ruleset; nothing to restore");
        return Ok(RulesetRestoreOutcome::NothingPersisted);
    }

    let path_str = path.to_string_lossy().into_owned();
    let output = run_nft(&["-f", &path_str]).await?;
    if !output.status.success() {
        return Err(BlackholeError::CommandFailed {
            command: format!("{NFT_BIN} -f {path_str}"),
            status: output.status.to_string(),
            stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
        });
    }
    info!(path = %path.display(), "restored persisted kill-switch ruleset");
    Ok(RulesetRestoreOutcome::Restored)
}

async fn run_nft(args: &[&str]) -> Result<std::process::Output, BlackholeError> {
    Command::new(NFT_BIN)
        .args(args)
        .output()
        .await
        .map_err(BlackholeError::from)
}

async fn run_nft_with_stdin(args: &[&str], stdin_data: &str) -> Result<(), BlackholeError> {
    use tokio::io::AsyncWriteExt;
    use std::process::Stdio;

    let mut child = Command::new(NFT_BIN)
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(BlackholeError::from)?;

    child
        .stdin
        .take()
        .expect("stdin was piped")
        .write_all(stdin_data.as_bytes())
        .await
        .map_err(BlackholeError::from)?;

    let output = child.wait_with_output().await.map_err(BlackholeError::from)?;
    if !output.status.success() {
        return Err(BlackholeError::CommandFailed {
            command: format!("{NFT_BIN} {}", args.join(" ")),
            status: output.status.to_string(),
            stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
        });
    }
    Ok(())
}

/// Write `ruleset` to `path` (creating parent directories as needed) and
/// restrict it to owner-only (0600) — it's re-executed as trusted `nft -f`
/// input at boot, by root, so it deserves the same care as any other
/// root-trusted config file.
fn persist_ruleset(path: &Path, ruleset: &str) -> Result<(), BlackholeError> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::write(path, ruleset)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut perms = std::fs::metadata(path)?.permissions();
        perms.set_mode(0o600);
        std::fs::set_permissions(path, perms)?;
    }
    Ok(())
}

fn remove_persisted_ruleset(path: &Path) -> Result<(), BlackholeError> {
    match std::fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(e.into()),
    }
}

pub struct LinuxGuard {
    state: GuardStateMachine,
    tor: Arc<dyn TorBackend>,
    ruleset_path: PathBuf,
}

impl LinuxGuard {
    /// Takes a shared `Arc<dyn TorBackend>` (rather than owning it
    /// outright) so callers can keep their own handle for Tor-specific
    /// queries (bootstrap detail, exit IP — arti-backend-specific, see
    /// `TorOrchestrator`) alongside the guard. Works with either Tor
    /// backend (`TorOrchestrator`/arti, or `SubprocessTorBackend`) — the
    /// UID-scoped nftables rule this backend applies doesn't need to know
    /// which: a child process spawned by either backend inherits the same
    /// UID as this one, so it's already covered without any
    /// backend-specific logic (contrast the Windows backend, which scopes
    /// its permit rule per-executable and does need to know).
    ///
    /// Persists to [`default_ruleset_path`] — use [`Self::with_ruleset_path`]
    /// to override (e.g. in tests).
    pub fn new(tor: Arc<dyn TorBackend>) -> Self {
        Self::with_ruleset_path(tor, default_ruleset_path())
    }

    /// Same as [`Self::new`], but persists the boot-restore ruleset at
    /// `ruleset_path` instead of the default. Exists mainly for
    /// `blackhole-chaos`'s reboot-simulation test, which needs to point
    /// this at a throwaway path rather than the real `/etc/blackhole/`.
    pub fn with_ruleset_path(tor: Arc<dyn TorBackend>, ruleset_path: PathBuf) -> Self {
        Self {
            state: GuardStateMachine::new(),
            tor,
            ruleset_path,
        }
    }

    /// Where this guard persists its ruleset for boot-time restore.
    pub fn ruleset_path(&self) -> &Path {
        &self.ruleset_path
    }

    fn current_uid() -> u32 {
        // SAFETY: getuid(2) takes no arguments, performs no pointer
        // dereferences, and cannot fail.
        unsafe { libc::getuid() }
    }

    fn ruleset(uid: u32) -> String {
        format!(
            "table {family} {name} {{\n\
             \x20   chain output {{\n\
             \x20       type filter hook output priority 0; policy drop;\n\
             \x20       oif \"lo\" accept\n\
             \x20       ct state established,related accept\n\
             \x20       meta skuid {uid} accept\n\
             \x20   }}\n\
             }}\n",
            family = TABLE_FAMILY,
            name = TABLE_NAME,
            uid = uid
        )
    }

    /// True if the `inet blackhole` table currently exists in the kernel's
    /// ruleset, independent of what this process's in-memory state machine
    /// thinks. Used by `status()` so a stale or crashed process doesn't lie
    /// about whether the machine is actually protected.
    async fn table_exists() -> Result<bool, BlackholeError> {
        let output = run_nft(&["list", "table", TABLE_FAMILY, TABLE_NAME]).await?;
        Ok(output.status.success())
    }

    async fn delete_table_if_present() -> Result<(), BlackholeError> {
        let output = run_nft(&["delete", "table", TABLE_FAMILY, TABLE_NAME]).await?;
        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            if !stderr.contains("No such file or directory") {
                return Err(BlackholeError::CommandFailed {
                    command: format!("{NFT_BIN} delete table {TABLE_FAMILY} {TABLE_NAME}"),
                    status: output.status.to_string(),
                    stderr: stderr.into_owned(),
                });
            }
        }
        Ok(())
    }
}

#[async_trait]
impl NetworkGuard for LinuxGuard {
    async fn enable(&self) -> Result<(), BlackholeError> {
        self.state.begin_enable()?;

        let uid = Self::current_uid();
        let ruleset = Self::ruleset(uid);
        let result: Result<(), BlackholeError> = async {
            // Start from a clean slate so re-enabling never layers stale
            // rules from a previous crashed run on top of new ones.
            Self::delete_table_if_present().await?;
            run_nft_with_stdin(&["-f", "-"], &ruleset).await?;
            // Persist last, only once the live rules are confirmed applied:
            // a boot-restore file for rules that were never actually live
            // would be worse than no file at all (a false "this was
            // protected" record). If this write fails (read-only /etc,
            // out of disk...), the whole enable() fails too — the reboot
            // guarantee is part of what "enabled" means here, not a
            // best-effort extra.
            persist_ruleset(&self.ruleset_path, &ruleset)?;
            Ok(())
        }
        .await;

        self.state.finish_enable(result.is_ok());
        if result.is_ok() {
            info!(uid, path = %self.ruleset_path.display(), "nftables kill switch enabled (default-deny output, persisted for boot restore)");
        } else {
            warn!(?result, "failed to fully apply nftables kill switch; treating as faulted (fail-closed)");
        }
        result
    }

    async fn disable(&self) -> Result<(), BlackholeError> {
        self.state.begin_disable()?;
        let result: Result<(), BlackholeError> = async {
            Self::delete_table_if_present().await?;
            remove_persisted_ruleset(&self.ruleset_path)?;
            Ok(())
        }
        .await;
        self.state.finish_disable(result.is_ok());
        if result.is_ok() {
            info!("nftables kill switch disabled");
        }
        result
    }

    async fn status(&self) -> Result<GuardStatus, BlackholeError> {
        let actually_blocking = Self::table_exists().await.unwrap_or(false);
        let (state, detail) = self.state.reconcile(actually_blocking, "nftables table");

        let tor = self.tor.status().await;
        Ok(GuardStatus {
            state,
            tor_bootstrap_percent: Some(tor.bootstrap_percent),
            allowed_egress: Some(format!("uid {}", Self::current_uid())),
            detail: detail.or(tor.blocked_reason),
        })
    }

    async fn new_identity(&self) -> Result<(), BlackholeError> {
        self.state.require_enabled("new_identity")?;
        self.tor.new_identity().await
    }
}

#[cfg(test)]
mod persistence_tests {
    //! Covers the file-persistence half of the boot-restore feature —
    //! pure I/O, no root/`nft` needed, so it runs under a plain `cargo
    //! test` on any Linux box. The half that actually needs a live `nft`
    //! and root (does `restore_persisted_ruleset` really re-apply a
    //! blocking table?) is covered end-to-end by `blackhole-chaos`'s
    //! reboot-simulation test instead — see `chaos/tests/`.
    use super::*;

    fn temp_path(name: &str) -> PathBuf {
        std::env::temp_dir().join(format!(
            "blackhole-core-linux-persist-test-{name}-{}",
            std::process::id()
        ))
    }

    #[test]
    fn default_ruleset_path_honors_env_override() {
        let key = "BLACKHOLE_NFTABLES_RULESET_PATH";
        let previous = std::env::var_os(key);

        // SAFETY (env mutation in tests): `cargo test` runs each test in
        // its own thread but shares the process environment; this could
        // race another test reading the same var concurrently. No other
        // test in this crate reads or writes this specific key, so in
        // practice it's safe — flagged here rather than silently relied on.
        unsafe { std::env::set_var(key, "/tmp/custom-ruleset.rules") };
        assert_eq!(default_ruleset_path(), PathBuf::from("/tmp/custom-ruleset.rules"));
        unsafe { std::env::remove_var(key) };
        assert_eq!(default_ruleset_path(), PathBuf::from("/etc/blackhole/nftables.rules"));

        match previous {
            Some(v) => unsafe { std::env::set_var(key, v) },
            None => unsafe { std::env::remove_var(key) },
        }
    }

    #[test]
    fn persist_then_remove_ruleset_round_trips() {
        let path = temp_path("round-trip");
        let _ = std::fs::remove_file(&path);

        persist_ruleset(&path, "table inet blackhole {}\n").unwrap();
        assert_eq!(std::fs::read_to_string(&path).unwrap(), "table inet blackhole {}\n");

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o600, "persisted ruleset must be owner-only: it's trusted `nft -f` input re-run as root at boot");
        }

        remove_persisted_ruleset(&path).unwrap();
        assert!(!path.exists());
    }

    #[test]
    fn persist_ruleset_creates_missing_parent_directories() {
        let path = temp_path("nested").join("nested").join("nftables.rules");
        let _ = std::fs::remove_dir_all(path.parent().unwrap().parent().unwrap());

        persist_ruleset(&path, "table inet blackhole {}\n").unwrap();
        assert!(path.exists());

        std::fs::remove_dir_all(path.parent().unwrap().parent().unwrap()).ok();
    }

    #[test]
    fn removing_an_already_absent_ruleset_is_not_an_error() {
        let path = temp_path("never-existed");
        let _ = std::fs::remove_file(&path);
        remove_persisted_ruleset(&path).unwrap();
    }

    #[tokio::test]
    async fn restoring_with_no_persisted_file_is_a_no_op_not_an_error() {
        // The correct baseline for "never enabled, or cleanly disabled
        // before shutdown" — must not be treated as a failure, and must
        // not shell out to `nft` at all (this branch needs no root).
        let path = temp_path("nothing-to-restore");
        let _ = std::fs::remove_file(&path);

        let outcome = restore_persisted_ruleset(&path).await.unwrap();
        assert_eq!(outcome, RulesetRestoreOutcome::NothingPersisted);
    }
}
