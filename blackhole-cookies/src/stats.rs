//! The only thing this module persists across runs besides the CA
//! material: an aggregate, domain-free count of cookies randomized
//! today. See `THREAT_MODEL.md`'s "No browsing logs, ever, even
//! locally": this file's own fields are the complete list of what's
//! recorded, and neither of them is a domain, a cookie name, or a value.

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::error::CookiesError;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct DailyStats {
    /// Unix days since epoch (`unix_seconds / 86400`), not a timestamp:
    /// coarse enough that it can't be used to reconstruct when in the day
    /// anything happened, which isn't needed for a daily counter anyway.
    pub day: u64,
    pub cookies_randomized: u64,
}

pub fn default_stats_path() -> Result<PathBuf, CookiesError> {
    let dirs = directories::ProjectDirs::from("", "", "blackhole-cookies").ok_or_else(|| {
        CookiesError::Platform(
            "could not determine a user data directory on this platform".to_string(),
        )
    })?;
    Ok(dirs.data_dir().join("stats.json"))
}

fn today() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
        / 86_400
}

/// Load today's count, or a fresh zeroed record if none is saved yet, or
/// if the saved record is for a previous day (the counter resets daily by
/// design, matching what it's displayed as: "N cookies randomized
/// today").
pub fn load_today(path: &Path) -> DailyStats {
    let today = today();
    match std::fs::read_to_string(path) {
        Ok(text) => match serde_json::from_str::<DailyStats>(&text) {
            Ok(stats) if stats.day == today => stats,
            _ => DailyStats {
                day: today,
                cookies_randomized: 0,
            },
        },
        Err(_) => DailyStats {
            day: today,
            cookies_randomized: 0,
        },
    }
}

pub fn save(path: &Path, stats: &DailyStats) -> Result<(), CookiesError> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let text = serde_json::to_string(stats)
        .map_err(|e| CookiesError::Platform(format!("failed to serialize stats: {e}")))?;
    std::fs::write(path, text)?;
    Ok(())
}

/// Add `count` to today's total and persist it. Loads first so a run
/// spanning midnight (or a second run today) accumulates correctly
/// rather than overwriting.
pub fn record(path: &Path, count: u64) -> Result<DailyStats, CookiesError> {
    let mut stats = load_today(path);
    stats.cookies_randomized += count;
    save(path, &stats)?;
    Ok(stats)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_path(name: &str) -> PathBuf {
        std::env::temp_dir().join(format!(
            "blackhole-cookies-stats-test-{name}-{}.json",
            std::process::id()
        ))
    }

    #[test]
    fn missing_file_loads_as_zero_for_today() {
        let path = temp_path("missing");
        let _ = std::fs::remove_file(&path);
        let stats = load_today(&path);
        assert_eq!(stats.cookies_randomized, 0);
        assert_eq!(stats.day, today());
    }

    #[test]
    fn record_accumulates_across_calls_on_the_same_day() {
        let path = temp_path("accumulate");
        let _ = std::fs::remove_file(&path);

        record(&path, 3).unwrap();
        let stats = record(&path, 4).unwrap();
        assert_eq!(stats.cookies_randomized, 7);

        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn a_stale_record_from_a_previous_day_resets_rather_than_accumulates() {
        let path = temp_path("stale");
        save(
            &path,
            &DailyStats {
                day: 0,
                cookies_randomized: 999,
            },
        )
        .unwrap();

        let stats = record(&path, 1).unwrap();
        assert_eq!(stats.cookies_randomized, 1);
        assert_eq!(stats.day, today());

        std::fs::remove_file(&path).ok();
    }
}
