//! Shared report/scoring model. Every check module (`network_identity`,
//! `telemetry`, `exposure`) produces a `Vec<Finding>`; this module turns
//! that into a single traceability score and a printable report.

use std::fmt;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Severity {
    Info,
    Low,
    Medium,
    High,
}

impl Severity {
    /// Points deducted from the starting score of 100.
    fn penalty(self) -> i32 {
        match self {
            Severity::Info => 0,
            Severity::Low => 5,
            Severity::Medium => 12,
            Severity::High => 25,
        }
    }

    pub fn label(self) -> &'static str {
        match self {
            Severity::Info => "INFO",
            Severity::Low => "LOW",
            Severity::Medium => "MEDIUM",
            Severity::High => "HIGH",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Category {
    NetworkIdentity,
    Telemetry,
    Exposure,
}

impl Category {
    /// Every category, in a fixed order — used to walk "all categories"
    /// consistently (e.g. building a per-category score breakdown for
    /// `history::ScanRecord`).
    pub const ALL: [Category; 3] = [
        Category::NetworkIdentity,
        Category::Telemetry,
        Category::Exposure,
    ];

    pub fn label(self) -> &'static str {
        match self {
            Category::NetworkIdentity => "network identity",
            Category::Telemetry => "OS telemetry",
            Category::Exposure => "public exposure",
        }
    }
}

#[derive(Debug, Clone)]
pub struct Finding {
    pub category: Category,
    pub severity: Severity,
    pub summary: String,
    pub recommendation: Option<String>,
}

impl Finding {
    pub fn new(category: Category, severity: Severity, summary: impl Into<String>) -> Self {
        Self {
            category,
            severity,
            summary: summary.into(),
            recommendation: None,
        }
    }

    pub fn with_recommendation(mut self, recommendation: impl Into<String>) -> Self {
        self.recommendation = Some(recommendation.into());
        self
    }
}

pub struct Report {
    pub findings: Vec<Finding>,
}

impl Report {
    pub fn new(findings: Vec<Finding>) -> Self {
        Self { findings }
    }

    /// 0-100 traceability score: 100 means nothing this tool checked looked
    /// identifying or exposed; each finding subtracts points by severity,
    /// floored at 0. This scores what *this tool* could observe locally and
    /// over the network — it is not a substitute for a real browser-based
    /// fingerprinting test (see the module docs on `exposure`).
    pub fn score(&self) -> u32 {
        let total: i32 = 100
            - self
                .findings
                .iter()
                .map(|f| f.severity.penalty())
                .sum::<i32>();
        total.clamp(0, 100) as u32
    }

    /// Same 0-100 scoring formula as [`Report::score`], restricted to
    /// findings in just one category — lets `history` track "telemetry
    /// got worse" separately from "network identity got worse" instead of
    /// only a single blended number.
    pub fn category_score(&self, category: Category) -> u32 {
        let total: i32 = 100
            - self
                .findings
                .iter()
                .filter(|f| f.category == category)
                .map(|f| f.severity.penalty())
                .sum::<i32>();
        total.clamp(0, 100) as u32
    }

    pub fn score_label(&self) -> &'static str {
        match self.score() {
            80..=100 => "well hardened",
            50..=79 => "moderate exposure",
            20..=49 => "significant exposure",
            _ => "highly traceable",
        }
    }
}

impl fmt::Display for Report {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "BlackHole Fingerprint Report")?;
        writeln!(f, "============================")?;
        writeln!(f, "score: {}/100 ({})", self.score(), self.score_label())?;
        writeln!(f)?;

        let mut sorted = self.findings.clone();
        sorted.sort_by_key(|f| std::cmp::Reverse(f.severity));

        for finding in &sorted {
            writeln!(
                f,
                "[{}] ({}) {}",
                finding.severity.label(),
                finding.category.label(),
                finding.summary
            )?;
            if let Some(rec) = &finding.recommendation {
                writeln!(f, "    -> {rec}")?;
            }
        }

        if sorted.is_empty() {
            writeln!(f, "(no findings)")?;
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn finding(severity: Severity) -> Finding {
        Finding::new(Category::NetworkIdentity, severity, "test")
    }

    #[test]
    fn no_findings_scores_perfect() {
        assert_eq!(Report::new(vec![]).score(), 100);
    }

    #[test]
    fn penalties_stack_and_floor_at_zero() {
        let report = Report::new(vec![finding(Severity::High); 10]);
        assert_eq!(report.score(), 0);
    }

    #[test]
    fn score_matches_penalty_arithmetic() {
        let report = Report::new(vec![finding(Severity::Medium), finding(Severity::Low)]);
        assert_eq!(report.score(), 100 - 12 - 5);
    }

    #[test]
    fn score_label_boundaries() {
        assert_eq!(Report::new(vec![]).score_label(), "well hardened");
        assert_eq!(
            Report::new(vec![finding(Severity::High), finding(Severity::Low)]).score_label(),
            "moderate exposure"
        );
        assert_eq!(
            Report::new(vec![
                finding(Severity::High),
                finding(Severity::High),
                finding(Severity::High)
            ])
            .score_label(),
            "significant exposure"
        );
        assert_eq!(
            Report::new(vec![finding(Severity::High); 5]).score_label(),
            "highly traceable"
        );
    }

    #[test]
    fn category_score_is_scoped_to_that_category_only() {
        let report = Report::new(vec![
            Finding::new(Category::Telemetry, Severity::High, "telemetry bad"),
            Finding::new(Category::NetworkIdentity, Severity::Info, "identity fine"),
        ]);
        assert_eq!(report.category_score(Category::Telemetry), 75);
        assert_eq!(report.category_score(Category::NetworkIdentity), 100);
        assert_eq!(report.category_score(Category::Exposure), 100);
    }

    #[test]
    fn display_sorts_most_severe_first() {
        let report = Report::new(vec![
            finding(Severity::Low),
            finding(Severity::High),
            finding(Severity::Info),
        ]);
        let text = report.to_string();
        let high_pos = text.find("[HIGH]").unwrap();
        let low_pos = text.find("[LOW]").unwrap();
        let info_pos = text.find("[INFO]").unwrap();
        assert!(high_pos < low_pos);
        assert!(low_pos < info_pos);
    }
}
