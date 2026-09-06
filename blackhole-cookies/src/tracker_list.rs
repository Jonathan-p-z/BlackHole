//! Loads a domain-blocking list in a small subset of the AdBlock/EasyList
//! filter syntax, so this crate can point at a real, community-maintained
//! list (EasyPrivacy, uBlock Origin's own lists, ...) rather than
//! inventing its own tracker domains. Deliberately implements only the
//! plain-domain-rule subset of that syntax, not the full filter grammar:
//!
//! - `||domain.tld^` and `||domain.tld^$anything` recognized: the domain
//!   between `||` and `^` is extracted, everything after `$` (options) is
//!   ignored rather than interpreted.
//! - A bare domain per line (no `||`/`^` at all) is also accepted, so a
//!   plain "one tracker domain per line" file works too, not just real
//!   EasyList syntax.
//! - Comment lines (`!` prefix), cosmetic filter rules (containing `##`
//!   or `#@#`), exception/allowlist rules (`@@` prefix), and regex rules
//!   (`/.../`) are recognized and skipped, not misparsed as domains.
//! - Anything else unrecognized is skipped silently: a real EasyPrivacy
//!   file has thousands of lines using parts of the filter syntax this
//!   module doesn't implement (this is not a general-purpose AdBlock
//!   filter engine; see `adblock-rust`/uBlock Origin's own engine for
//!   that), so "skip what we don't understand" is the correct behavior
//!   here, not an error.

use std::collections::HashSet;
use std::path::Path;

use crate::error::CookiesError;

/// A loaded set of tracker domains, matched by exact hostname or by
/// suffix (`sub.doubleclick.net` matches a `doubleclick.net` entry, the
/// same "domain and its subdomains" semantics EasyList itself uses for a
/// `||domain^` rule).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct TrackerList {
    domains: HashSet<String>,
}

impl TrackerList {
    /// No domains at all: every host is treated as non-tracker (pure
    /// pass-through). This is the correct, safe state for "no list has
    /// been configured yet", not an error.
    pub fn empty() -> Self {
        Self::default()
    }

    pub fn from_domains(domains: impl IntoIterator<Item = String>) -> Self {
        Self {
            domains: domains
                .into_iter()
                .map(|d| d.to_ascii_lowercase())
                .collect(),
        }
    }

    pub fn load_from_file(path: &Path) -> Result<Self, CookiesError> {
        let text = std::fs::read_to_string(path)?;
        Ok(Self::parse(&text))
    }

    pub fn parse(text: &str) -> Self {
        let domains = text.lines().filter_map(parse_line).collect();
        Self { domains }
    }

    pub fn len(&self) -> usize {
        self.domains.len()
    }

    pub fn is_empty(&self) -> bool {
        self.domains.is_empty()
    }

    /// True if `host` is the tracker list, or a subdomain of an entry on
    /// it. Case-insensitive; a trailing dot (as sometimes appears in a
    /// `Host` header) is stripped before comparing.
    pub fn matches(&self, host: &str) -> bool {
        let host = host.trim_end_matches('.').to_ascii_lowercase();
        self.domains
            .iter()
            .any(|domain| host == *domain || host.ends_with(&format!(".{domain}")))
    }
}

fn parse_line(line: &str) -> Option<String> {
    let line = line.trim();

    if line.is_empty() || line.starts_with('!') || line.starts_with('@') {
        return None;
    }
    if line.contains("##") || line.contains("#@#") || line.starts_with('/') {
        return None;
    }

    if let Some(rest) = line.strip_prefix("||") {
        let domain = rest.split(['^', '$']).next().unwrap_or("").trim();
        return valid_domain(domain);
    }

    // Not an EasyList-style rule at all: accept it as a bare domain if it
    // looks like one, so a plain "one domain per line" file also works.
    valid_domain(line)
}

fn valid_domain(candidate: &str) -> Option<String> {
    let candidate = candidate.trim();
    if candidate.is_empty() {
        return None;
    }
    let looks_like_domain = candidate
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '-')
        && candidate.contains('.')
        && !candidate.starts_with('.')
        && !candidate.starts_with('-');
    looks_like_domain.then(|| candidate.to_ascii_lowercase())
}

#[cfg(test)]
mod tests {
    use super::*;

    // Fake, non-existent domains throughout: `.test`/`.invalid` are
    // IANA-reserved for exactly this purpose (RFC 2606), so these can
    // never collide with a real tracker or a real site.

    #[test]
    fn parses_easylist_style_domain_rules() {
        let list = TrackerList::parse("||faketracker.test^\n||adnetwork.invalid^$third-party\n");
        assert_eq!(list.len(), 2);
        assert!(list.matches("faketracker.test"));
        assert!(list.matches("adnetwork.invalid"));
    }

    #[test]
    fn parses_bare_domain_lines_too() {
        let list = TrackerList::parse("faketracker.test\nadnetwork.invalid\n");
        assert_eq!(list.len(), 2);
        assert!(list.matches("faketracker.test"));
    }

    #[test]
    fn subdomains_of_a_listed_domain_match() {
        let list = TrackerList::parse("||faketracker.test^\n");
        assert!(list.matches("cdn.faketracker.test"));
        assert!(list.matches("a.b.faketracker.test"));
    }

    #[test]
    fn unrelated_domains_do_not_match() {
        let list = TrackerList::parse("||faketracker.test^\n");
        assert!(!list.matches("example.test"));
        assert!(!list.matches("notfaketracker.test"));
        assert!(!list.matches("faketracker.test.evil.invalid"));
    }

    #[test]
    fn comments_and_cosmetic_and_exception_rules_are_skipped() {
        let list = TrackerList::parse(
            "! this is a comment\n\
             ##.ad-banner\n\
             example.test#@#.allowed-ad\n\
             @@||exception.test^\n\
             /some-regex-rule.*/\n",
        );
        assert!(list.is_empty());
    }

    #[test]
    fn blank_lines_are_ignored() {
        let list = TrackerList::parse("\n\n||faketracker.test^\n\n");
        assert_eq!(list.len(), 1);
    }

    #[test]
    fn matching_is_case_insensitive_and_ignores_a_trailing_dot() {
        let list = TrackerList::parse("||FakeTracker.test^\n");
        assert!(list.matches("faketracker.test"));
        assert!(list.matches("faketracker.test."));
        assert!(list.matches("FAKETRACKER.TEST"));
    }

    #[test]
    fn empty_list_matches_nothing_pure_pass_through() {
        let list = TrackerList::empty();
        assert!(!list.matches("faketracker.test"));
        assert!(!list.matches("anything.at.all"));
    }

    #[test]
    fn loading_from_a_real_file_works() {
        let dir = std::env::temp_dir().join(format!(
            "blackhole-cookies-tracker-list-test-{}",
            std::process::id()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("list.txt");
        std::fs::write(&path, "||faketracker.test^\n").unwrap();

        let list = TrackerList::load_from_file(&path).unwrap();
        assert!(list.matches("faketracker.test"));

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn loading_a_missing_file_is_a_reported_error_not_an_empty_list() {
        // Distinguishing "no list configured" (TrackerList::empty(), a
        // deliberate default) from "a list was configured but the file
        // is gone" (an error the caller should surface) matters: silently
        // treating a missing configured file as "nothing to block" would
        // hide a real misconfiguration.
        let path = std::env::temp_dir().join(format!(
            "blackhole-cookies-tracker-list-missing-{}.txt",
            std::process::id()
        ));
        let _ = std::fs::remove_file(&path);
        assert!(TrackerList::load_from_file(&path).is_err());
    }
}
