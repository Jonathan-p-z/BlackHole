//! Local, append-only history of past scans, so the CLI can show what
//! changed since last time instead of only the current snapshot.
//!
//! Stored as JSON Lines (`history.jsonl`: one JSON object per scan, one
//! scan per line) — plain text, human-readable, greppable, and already in
//! the exact format an operator would want to export: `cp
//! history.jsonl backup.jsonl` *is* the export, no separate step or
//! opaque binary format involved. Nothing in this module makes a network
//! call or writes anywhere outside the local history file — this data
//! never leaves the machine, consistent with the rest of the project.

use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::error::FingerprintError;
use crate::report::{Category, Report};

/// A single finding as recorded in history — a snapshot of the parts that
/// matter for comparing two scans, decoupled from `report::Finding` so the
/// on-disk format doesn't change shape just because the in-memory enum
/// representations do.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FindingSnapshot {
    pub category: String,
    pub severity: String,
    pub summary: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CategoryScore {
    pub category: String,
    pub score: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanRecord {
    /// Unix seconds. Plain integer, not a formatted string, so the file
    /// sorts and diffs cleanly and doesn't depend on any particular
    /// timezone at write time; `human_timestamp` renders it for display.
    pub timestamp_unix: u64,
    pub score: u32,
    pub category_scores: Vec<CategoryScore>,
    pub findings: Vec<FindingSnapshot>,
}

impl ScanRecord {
    pub fn from_report(report: &Report, timestamp_unix: u64) -> Self {
        Self {
            timestamp_unix,
            score: report.score(),
            category_scores: Category::ALL
                .iter()
                .map(|&c| CategoryScore {
                    category: c.label().to_string(),
                    score: report.category_score(c),
                })
                .collect(),
            findings: report
                .findings
                .iter()
                .map(|f| FindingSnapshot {
                    category: f.category.label().to_string(),
                    severity: f.severity.label().to_string(),
                    summary: f.summary.clone(),
                })
                .collect(),
        }
    }

    /// `timestamp_unix` rendered as `YYYY-MM-DD HH:MM:SS UTC`.
    pub fn human_timestamp(&self) -> String {
        const FORMAT: &[time::format_description::FormatItem<'_>] =
            time::macros::format_description!("[year]-[month]-[day] [hour]:[minute]:[second] UTC");
        match time::OffsetDateTime::from_unix_timestamp(self.timestamp_unix as i64) {
            Ok(dt) => dt
                .format(FORMAT)
                .unwrap_or_else(|_| self.timestamp_unix.to_string()),
            Err(_) => self.timestamp_unix.to_string(),
        }
    }
}

/// Default path for the history file: `<user data dir>/blackhole-fingerprint/history.jsonl`
/// (e.g. `~/.local/share/blackhole-fingerprint/history.jsonl` on Linux,
/// `%APPDATA%\blackhole-fingerprint\history.jsonl` on Windows).
pub fn default_history_path() -> Result<PathBuf, FingerprintError> {
    let dirs =
        directories::ProjectDirs::from("", "", "blackhole-fingerprint").ok_or_else(|| {
            FingerprintError::History(
                "could not determine a user data directory on this platform".to_string(),
            )
        })?;
    Ok(dirs.data_dir().join("history.jsonl"))
}

/// Append `record` as one new line. Creates the file (and its parent
/// directory) on first use. Never rewrites or truncates existing history —
/// a write failure partway through a run never loses prior scans.
pub fn append(path: &Path, record: &ScanRecord) -> Result<(), FingerprintError> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let mut file = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)?;
    let line = serde_json::to_string(record)
        .map_err(|e| FingerprintError::History(format!("failed to serialize scan record: {e}")))?;
    writeln!(file, "{line}")?;
    Ok(())
}

/// Load every recorded scan, oldest first. A missing file (no scans yet)
/// is not an error — returns an empty history. A line that fails to parse
/// *is* an error (rather than silently skipped): this file is documented
/// as human-editable/exportable, so a caller who hand-edited it and broke
/// a line deserves to know, not to silently lose that scan from view.
pub fn load_all(path: &Path) -> Result<Vec<ScanRecord>, FingerprintError> {
    let file = match std::fs::File::open(path) {
        Ok(f) => f,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(e) => return Err(e.into()),
    };

    BufReader::new(file)
        .lines()
        .enumerate()
        .filter(|(_, line)| !matches!(line, Ok(l) if l.trim().is_empty()))
        .map(|(i, line)| {
            let line = line?;
            serde_json::from_str(&line).map_err(|e| {
                FingerprintError::History(format!(
                    "{}: line {} is not a valid scan record: {e}",
                    path.display(),
                    i + 1
                ))
            })
        })
        .collect()
}

/// What changed between two scans: score movement, per-category movement,
/// findings that newly appeared, and findings that are no longer present.
/// A finding is matched by its exact `(category, severity, summary)`
/// triple, so a state change that changes the summary text (e.g.
/// telemetry's "DiagTrack service is Running" vs "... is Stopped") shows
/// up naturally as one resolved + one new finding, without needing any
/// special-cased "this specific finding changed" tracking.
pub struct HistoryDiff<'a> {
    pub previous: &'a ScanRecord,
    pub current: &'a ScanRecord,
    pub score_delta: i32,
    pub category_deltas: Vec<(String, i32)>,
    pub new_findings: Vec<FindingSnapshot>,
    pub resolved_findings: Vec<FindingSnapshot>,
}

/// A drop of this many points or more between two scans is flagged as a
/// significant degradation — roughly "one Medium-severity finding's worth
/// of penalty," see `report::Severity::penalty`.
pub const SIGNIFICANT_DEGRADATION_THRESHOLD: i32 = -10;

impl<'a> HistoryDiff<'a> {
    pub fn compute(previous: &'a ScanRecord, current: &'a ScanRecord) -> Self {
        let score_delta = current.score as i32 - previous.score as i32;

        let category_deltas = current
            .category_scores
            .iter()
            .filter_map(|cur| {
                previous
                    .category_scores
                    .iter()
                    .find(|prev| prev.category == cur.category)
                    .map(|prev| (cur.category.clone(), cur.score as i32 - prev.score as i32))
            })
            .filter(|(_, delta)| *delta != 0)
            .collect();

        let new_findings = current
            .findings
            .iter()
            .filter(|f| !previous.findings.contains(f))
            .cloned()
            .collect();
        let resolved_findings = previous
            .findings
            .iter()
            .filter(|f| !current.findings.contains(f))
            .cloned()
            .collect();

        Self {
            previous,
            current,
            score_delta,
            category_deltas,
            new_findings,
            resolved_findings,
        }
    }

    pub fn is_significant_degradation(&self) -> bool {
        self.score_delta <= SIGNIFICANT_DEGRADATION_THRESHOLD
    }

    pub fn unchanged(&self) -> bool {
        self.score_delta == 0 && self.new_findings.is_empty() && self.resolved_findings.is_empty()
    }
}

impl std::fmt::Display for HistoryDiff<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        writeln!(
            f,
            "comparing {} -> {}",
            self.previous.human_timestamp(),
            self.current.human_timestamp()
        )?;

        if self.unchanged() {
            writeln!(f, "no change")?;
            return Ok(());
        }

        writeln!(
            f,
            "score: {} -> {} ({}{})",
            self.previous.score,
            self.current.score,
            if self.score_delta > 0 { "+" } else { "" },
            self.score_delta
        )?;

        for (category, delta) in &self.category_deltas {
            writeln!(
                f,
                "  {category}: {}{delta}",
                if *delta > 0 { "+" } else { "" }
            )?;
        }

        for finding in &self.resolved_findings {
            writeln!(
                f,
                "resolved: [{}] ({}) {}",
                finding.severity, finding.category, finding.summary
            )?;
        }
        for finding in &self.new_findings {
            writeln!(
                f,
                "new:      [{}] ({}) {}",
                finding.severity, finding.category, finding.summary
            )?;
        }

        if self.is_significant_degradation() {
            writeln!(
                f,
                "\n/!\\ significant degradation since last scan (score dropped by {})",
                -self.score_delta
            )?;
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::report::{Finding, Severity};

    fn record(score_findings: Vec<(Category, Severity, &str)>, timestamp_unix: u64) -> ScanRecord {
        let findings = score_findings
            .into_iter()
            .map(|(c, s, summary)| Finding::new(c, s, summary))
            .collect();
        ScanRecord::from_report(&Report::new(findings), timestamp_unix)
    }

    // --- storage ---

    #[test]
    fn append_then_load_round_trips() {
        let dir = std::env::temp_dir().join(format!("blackhole-fp-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("history.jsonl");
        let _ = std::fs::remove_file(&path);

        let r1 = record(
            vec![(Category::Telemetry, Severity::Medium, "diagtrack running")],
            1000,
        );
        let r2 = record(vec![], 2000);
        append(&path, &r1).unwrap();
        append(&path, &r2).unwrap();

        let loaded = load_all(&path).unwrap();
        assert_eq!(loaded.len(), 2);
        assert_eq!(loaded[0].timestamp_unix, 1000);
        assert_eq!(loaded[1].timestamp_unix, 2000);
        assert_eq!(loaded[0].findings[0].summary, "diagtrack running");

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn loading_a_missing_file_is_an_empty_history_not_an_error() {
        let path = std::env::temp_dir().join(format!(
            "blackhole-fp-test-missing-{}.jsonl",
            std::process::id()
        ));
        let _ = std::fs::remove_file(&path);
        assert_eq!(load_all(&path).unwrap().len(), 0);
    }

    // --- diff: the behavior the prompt specifically asked to verify ---

    #[test]
    fn diff_detects_a_finding_that_appeared() {
        // The exact scenario from the prompt: telemetry disabled -> enabled
        // after a Windows update.
        let previous = record(vec![], 1000);
        let current = record(
            vec![(
                Category::Telemetry,
                Severity::Medium,
                "DiagTrack service is running",
            )],
            2000,
        );

        let diff = HistoryDiff::compute(&previous, &current);
        assert!(!diff.unchanged());
        assert_eq!(diff.new_findings.len(), 1);
        assert_eq!(diff.new_findings[0].summary, "DiagTrack service is running");
        assert!(diff.resolved_findings.is_empty());
        assert_eq!(diff.score_delta, -12); // Medium penalty
    }

    #[test]
    fn diff_detects_a_finding_that_was_resolved() {
        let previous = record(
            vec![(
                Category::Telemetry,
                Severity::Medium,
                "DiagTrack service is running",
            )],
            1000,
        );
        let current = record(vec![], 2000);

        let diff = HistoryDiff::compute(&previous, &current);
        assert_eq!(diff.resolved_findings.len(), 1);
        assert!(diff.new_findings.is_empty());
        assert_eq!(diff.score_delta, 12);
    }

    #[test]
    fn diff_is_quiet_when_nothing_changed() {
        let previous = record(
            vec![(Category::NetworkIdentity, Severity::Low, "custom hostname")],
            1000,
        );
        let current = record(
            vec![(Category::NetworkIdentity, Severity::Low, "custom hostname")],
            2000,
        );

        let diff = HistoryDiff::compute(&previous, &current);
        assert!(diff.unchanged());
        assert_eq!(diff.score_delta, 0);
    }

    #[test]
    fn category_deltas_only_include_categories_that_actually_moved() {
        let previous = record(
            vec![
                (Category::Telemetry, Severity::Medium, "diagtrack running"),
                (Category::NetworkIdentity, Severity::Low, "custom hostname"),
            ],
            1000,
        );
        let current = record(
            vec![(Category::NetworkIdentity, Severity::Low, "custom hostname")],
            2000,
        );

        let diff = HistoryDiff::compute(&previous, &current);
        assert_eq!(diff.category_deltas.len(), 1);
        assert_eq!(diff.category_deltas[0].0, Category::Telemetry.label());
        assert_eq!(diff.category_deltas[0].1, 12);
    }

    #[test]
    fn significant_degradation_is_flagged_at_the_threshold() {
        let previous = record(vec![], 1000);
        let just_under = record(vec![(Category::Telemetry, Severity::Low, "x")], 2000); // -5, not significant
        let at_threshold = record(
            vec![
                (Category::Telemetry, Severity::Medium, "y"),
                (Category::Telemetry, Severity::Low, "z"),
            ],
            3000,
        ); // -17, significant

        assert!(!HistoryDiff::compute(&previous, &just_under).is_significant_degradation());
        assert!(HistoryDiff::compute(&previous, &at_threshold).is_significant_degradation());
    }

    #[test]
    fn severity_change_on_the_same_underlying_check_shows_as_resolved_plus_new() {
        // A finding whose text encodes severity-relevant state (not just a
        // literal severity bump) is the realistic case: the summary text
        // itself changes, so it's naturally seen as "resolved" + "new"
        // rather than needing special same-finding-different-severity
        // tracking.
        let previous = record(
            vec![(
                Category::Telemetry,
                Severity::Info,
                "AllowTelemetry policy set to 1 (Basic)",
            )],
            1000,
        );
        let current = record(
            vec![(
                Category::Telemetry,
                Severity::Medium,
                "AllowTelemetry policy set to 3 (above Basic)",
            )],
            2000,
        );

        let diff = HistoryDiff::compute(&previous, &current);
        assert_eq!(diff.resolved_findings.len(), 1);
        assert_eq!(diff.new_findings.len(), 1);
    }
}
