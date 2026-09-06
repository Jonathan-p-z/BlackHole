//! The per-session cookie-value randomization table: see
//! `THREAT_MODEL.md`'s "How the randomization works" for the exact
//! behavior this implements. One random value per `(domain, cookie
//! name)` pair, generated the first time that pair is seen (from either
//! an outgoing `Cookie:` header or an incoming `Set-Cookie:` header) and
//! reused for the rest of this store's lifetime, which is one proxy run
//! ("session", in the sense this module means it).
//!
//! Holds no browsing data beyond the current in-memory table: no domain
//! or cookie name here is ever written to disk (see `THREAT_MODEL.md`'s
//! "No browsing logs, ever, even locally").

use std::collections::HashMap;
use std::sync::Mutex;

use rand::RngExt;
use rand::distr::Alphanumeric;

/// Length of a generated replacement cookie value. Long enough that it
/// doesn't look truncated next to typical tracker-assigned IDs (which
/// are often 16-32 characters themselves), short enough to stay well
/// under the ~4KB per-cookie size limit browsers enforce.
const RANDOM_VALUE_LEN: usize = 32;

#[derive(Debug, Default)]
pub struct CookieStore {
    values: Mutex<HashMap<(String, String), String>>,
}

impl CookieStore {
    pub fn new() -> Self {
        Self::default()
    }

    /// The randomized value to use for `(domain, cookie_name)`: an
    /// existing one if this pair has been seen before in this session, a
    /// freshly generated one (recorded for next time) otherwise. Never
    /// returns the real value passed in anywhere else in this module;
    /// this is the only function that produces the substitute value.
    pub fn randomized_value(&self, domain: &str, cookie_name: &str) -> String {
        let key = (domain.to_ascii_lowercase(), cookie_name.to_string());
        let mut values = self.values.lock().unwrap();
        values
            .entry(key)
            .or_insert_with(generate_random_value)
            .clone()
    }

    /// Number of distinct `(domain, cookie name)` pairs randomized so far
    /// this session. Used only for the aggregate counter in `stats.rs`;
    /// never exposes which domains or names, just a count.
    pub fn randomized_count(&self) -> usize {
        self.values.lock().unwrap().len()
    }
}

fn generate_random_value() -> String {
    rand::rng()
        .sample_iter(&Alphanumeric)
        .take(RANDOM_VALUE_LEN)
        .map(char::from)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn same_pair_gets_the_same_value_across_repeated_lookups() {
        let store = CookieStore::new();
        let first = store.randomized_value("faketracker.test", "trackid");
        let second = store.randomized_value("faketracker.test", "trackid");
        assert_eq!(first, second);
    }

    #[test]
    fn different_cookie_names_on_the_same_domain_get_different_values() {
        let store = CookieStore::new();
        let a = store.randomized_value("faketracker.test", "trackid");
        let b = store.randomized_value("faketracker.test", "sessionid");
        assert_ne!(a, b);
    }

    #[test]
    fn the_same_cookie_name_on_different_domains_gets_different_values() {
        let store = CookieStore::new();
        let a = store.randomized_value("faketracker.test", "trackid");
        let b = store.randomized_value("otherfaketracker.test", "trackid");
        assert_ne!(a, b);
    }

    #[test]
    fn domain_matching_is_case_insensitive() {
        let store = CookieStore::new();
        let a = store.randomized_value("FakeTracker.test", "trackid");
        let b = store.randomized_value("faketracker.test", "trackid");
        assert_eq!(a, b);
    }

    #[test]
    fn generated_values_do_not_echo_a_real_value_passed_in_elsewhere() {
        // randomized_value never takes the real value as input at all
        // (by construction: its signature has no such parameter), which
        // is itself the property that matters; this test just pins the
        // generated shape (non-empty, fixed length, alphanumeric) so a
        // future change can't accidentally shrink it to something
        // trivially guessable.
        let store = CookieStore::new();
        let value = store.randomized_value("faketracker.test", "trackid");
        assert_eq!(value.len(), RANDOM_VALUE_LEN);
        assert!(value.chars().all(|c| c.is_ascii_alphanumeric()));
    }

    #[test]
    fn randomized_count_tracks_distinct_pairs_not_lookups() {
        let store = CookieStore::new();
        store.randomized_value("faketracker.test", "a");
        store.randomized_value("faketracker.test", "a"); // repeat lookup
        store.randomized_value("faketracker.test", "b");
        assert_eq!(store.randomized_count(), 2);
    }
}
