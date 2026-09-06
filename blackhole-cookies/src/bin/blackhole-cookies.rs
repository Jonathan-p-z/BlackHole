//! `blackhole-cookies` CLI. Read `../THREAT_MODEL.md` before using any of
//! this; `enable` starts a local TLS-intercepting proxy and only makes
//! sense once you've deliberately decided to install its CA certificate.

use std::path::PathBuf;

use blackhole_cookies::ca;
use blackhole_cookies::config::{self, CookiesConfig};
use blackhole_cookies::tracker_list::TrackerList;
use blackhole_cookies::{proxy, stats};
use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(
    name = "blackhole-cookies",
    version,
    about = "Randomizes third-party tracker cookie values via a local proxy. Read THREAT_MODEL.md first."
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Start the proxy in the foreground (Ctrl+C to stop) and mark it
    /// enabled in the config file. Does nothing to your traffic until
    /// you've also installed the CA certificate; see `ca-fingerprint`
    /// and THREAT_MODEL.md before that step.
    Enable {
        /// Local port to listen on. Defaults to the config file's
        /// `[cookies] proxy_port`, or 9080 if neither is set.
        #[arg(long)]
        port: Option<u16>,
        /// Tracker list file (EasyList-subset or plain domains). Defaults
        /// to the config file's `[cookies] tracker_list_path`. Leaving
        /// this unset means pure pass-through: nothing is treated as a
        /// tracker until a list is configured.
        #[arg(long)]
        tracker_list: Option<PathBuf>,
    },
    /// Stop a running proxy (if the PID file from `enable` is still
    /// present) and mark it disabled in the config file.
    Disable,
    /// Report whether the proxy is currently running, whether it's
    /// marked enabled, the tracker list size if configured, and today's
    /// aggregate randomized-cookie count. Never a domain or cookie name;
    /// see THREAT_MODEL.md's "No browsing logs".
    Status,
    /// Print the CA certificate's SHA-256 fingerprint, generating the CA
    /// first if this is the first run. Does not start the proxy. This is
    /// what THREAT_MODEL.md tells you to check before installing the
    /// certificate in your browser/OS trust store.
    CaFingerprint,
}

fn load_config() -> anyhow::Result<CookiesConfig> {
    Ok(
        config::load_from(&config::default_config_path()?).unwrap_or_else(|e| {
            eprintln!("warning: ignoring config file ({e})");
            CookiesConfig::default()
        }),
    )
}

fn save_enabled_flag(enabled: bool) -> anyhow::Result<()> {
    let path = config::default_config_path()?;
    let mut current = std::fs::read_to_string(&path).unwrap_or_default();
    // Minimal, surgical edit: flip (or add) `[cookies] enabled` without
    // rewriting the whole shared config file, so any other module's
    // section (or hand-written comments) in the same file survive
    // untouched. A full TOML round-trip (parse -> mutate -> reserialize)
    // would risk reformatting or reordering content this crate doesn't
    // own.
    if current.contains("[cookies]") {
        // Best-effort: only handles the common case of an existing,
        // already-well-formed `enabled = ...` line; anything more unusual
        // (a differently-cased key, a value on the same line as the
        // section header, ...) is left alone rather than risk corrupting
        // a hand-edited file, and `enabled` simply keeps whatever value
        // was already there until the user edits it themselves.
        if let Some(cookies_start) = current.find("[cookies]") {
            let after = &current[cookies_start..];
            let section_end = after[1..].find("\n[").map(|i| i + 1).unwrap_or(after.len());
            let section = &after[..section_end];
            if let Some(line_start) = section.find("enabled") {
                let abs_start = cookies_start + line_start;
                if let Some(line_end) = current[abs_start..].find('\n') {
                    let abs_end = abs_start + line_end;
                    current.replace_range(abs_start..abs_end, &format!("enabled = {enabled}"));
                } else {
                    current.push_str(&format!("\nenabled = {enabled}\n"));
                }
            } else {
                let insert_at = cookies_start + "[cookies]".len();
                current.insert_str(insert_at, &format!("\nenabled = {enabled}"));
            }
        }
    } else {
        if !current.is_empty() && !current.ends_with('\n') {
            current.push('\n');
        }
        current.push_str(&format!("\n[cookies]\nenabled = {enabled}\n"));
    }

    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::write(&path, current)?;
    Ok(())
}

fn pid_file_path() -> anyhow::Result<PathBuf> {
    let dirs = directories::ProjectDirs::from("", "", "blackhole-cookies").ok_or_else(|| {
        anyhow::anyhow!("could not determine a user data directory on this platform")
    })?;
    Ok(dirs.data_dir().join("proxy.pid"))
}

fn write_pid_file() -> anyhow::Result<PathBuf> {
    let path = pid_file_path()?;
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::write(&path, std::process::id().to_string())?;
    Ok(path)
}

fn kill_pid(pid: u32) {
    #[cfg(windows)]
    {
        let _ = std::process::Command::new("taskkill")
            .args(["/F", "/PID", &pid.to_string()])
            .output();
    }
    #[cfg(unix)]
    {
        let _ = std::process::Command::new("kill")
            .args(["-TERM", &pid.to_string()])
            .output();
    }
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();

    let cli = Cli::parse();

    match cli.command {
        Command::Enable { port, tracker_list } => {
            let config = load_config()?;
            let port = port.unwrap_or(config.proxy_port);
            let tracker_list_path = tracker_list.or(config.tracker_list_path);

            let tracker_list = match &tracker_list_path {
                Some(path) => {
                    let list = TrackerList::load_from_file(path)?;
                    eprintln!(
                        "loaded {} tracker domain(s) from {}",
                        list.len(),
                        path.display()
                    );
                    list
                }
                None => {
                    eprintln!(
                        "no tracker list configured; running in pure pass-through mode. \
                         See THREAT_MODEL.md's \"Tracker list\" section to configure one \
                         (e.g. https://easylist.to/easylist/easyprivacy.txt)."
                    );
                    TrackerList::empty()
                }
            };

            let ca_paths = ca::default_ca_paths()?;
            let fingerprint = match std::fs::read_to_string(&ca_paths.cert_path) {
                Ok(pem) => Some(ca::fingerprint(&pem)?),
                Err(_) => None,
            };

            save_enabled_flag(true)?;
            let pid_path = write_pid_file()?;

            eprintln!(
                "starting blackhole-cookies proxy on 127.0.0.1:{port} (Ctrl+C to stop). \
                 THREAT_MODEL.md explains what this does and what to verify before trusting its CA."
            );

            let shutdown = async {
                let _ = tokio::signal::ctrl_c().await;
            };

            let cookie_store = proxy::run(port, tracker_list, ca_paths, shutdown).await?;
            let _ = std::fs::remove_file(&pid_path);

            let randomized = cookie_store.randomized_count() as u64;
            stats::record(&stats::default_stats_path()?, randomized)?;

            if let Some(fp) = fingerprint {
                eprintln!("(CA fingerprint was: {fp})");
            }
            eprintln!("proxy stopped; {randomized} cookie(s) randomized this run.");
            Ok(())
        }
        Command::Disable => {
            save_enabled_flag(false)?;
            let pid_path = pid_file_path()?;
            match std::fs::read_to_string(&pid_path) {
                Ok(pid_text) => {
                    if let Ok(pid) = pid_text.trim().parse::<u32>() {
                        kill_pid(pid);
                        println!("stopped the running proxy (pid {pid}).");
                    }
                    let _ = std::fs::remove_file(&pid_path);
                }
                Err(_) => println!("no running proxy found (nothing to stop)."),
            }
            println!("marked disabled in the config file.");
            Ok(())
        }
        Command::Status => {
            let config = load_config()?;
            println!("enabled (config):  {}", config.enabled);

            let running = pid_file_path()
                .ok()
                .and_then(|p| std::fs::read_to_string(p).ok())
                .is_some();
            println!("proxy running:     {running}");

            match &config.tracker_list_path {
                Some(path) => match TrackerList::load_from_file(path) {
                    Ok(list) => println!(
                        "tracker list:      {} domain(s) from {}",
                        list.len(),
                        path.display()
                    ),
                    Err(e) => println!(
                        "tracker list:      configured at {} but unreadable: {e}",
                        path.display()
                    ),
                },
                None => println!("tracker list:      not configured (pure pass-through)"),
            }

            let ca_paths = ca::default_ca_paths()?;
            match std::fs::read_to_string(&ca_paths.cert_path) {
                Ok(pem) => println!("CA fingerprint:    {}", ca::fingerprint(&pem)?),
                Err(_) => println!(
                    "CA fingerprint:    no CA generated yet (run `ca-fingerprint` or `enable` once)"
                ),
            }

            let today = stats::load_today(&stats::default_stats_path()?);
            println!("cookies randomized today: {}", today.cookies_randomized);
            Ok(())
        }
        Command::CaFingerprint => {
            let ca_paths = ca::default_ca_paths()?;
            if !ca_paths.cert_path.is_file() {
                // Generating just to fingerprint it is the same
                // load-or-generate path `enable` uses; this command never
                // starts the proxy itself.
                ca::load_or_generate(&ca_paths)?;
            }
            let pem = std::fs::read_to_string(&ca_paths.cert_path)?;
            println!("{}", ca::fingerprint(&pem)?);
            println!(
                "\nVerify this matches what you expect before installing the certificate at\n{}\nSee THREAT_MODEL.md's \"What you MUST verify before installing the certificate\".",
                ca_paths.cert_path.display()
            );
            Ok(())
        }
    }
}
