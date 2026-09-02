//! C-ABI wrapper around the same severity-weighted traceability scoring
//! model as `blackhole-fingerprint::report`, so mobile front ends (this
//! iOS app, and potentially the Android one) can score their own findings
//! the same way instead of reimplementing the formula per-platform.
//!
//! Kept deliberately tiny and `extern "C"`-only: mobile FFI
//! boundaries are easiest to keep correct when they pass plain integers,
//! not shared Rust types, so this does not attempt to hand `Finding`/
//! `Report` values themselves across the boundary.

/// Severity levels, matching `blackhole_fingerprint::report::Severity`'s
/// ordering. Kept as plain `u32` codes (rather than sharing the enum
/// directly) since that's what's actually safe to pass across a C ABI.
#[repr(u32)]
pub enum Severity {
    Info = 0,
    Low = 1,
    Medium = 2,
    High = 3,
}

fn penalty(severity_code: u32) -> i32 {
    match severity_code {
        0 => 0,  // Info
        1 => 5,  // Low
        2 => 12, // Medium
        3 => 25, // High
        _ => 0,  // unknown code: don't let a bad input tank the score
    }
}

/// Compute a 0-100 traceability score from an array of severity codes
/// (`Severity` as `u32`), one per finding. Mirrors
/// `blackhole_fingerprint::report::Report::score()` exactly — if you change
/// the weights there, change them here too.
///
/// # Safety
/// `severities` must point to a valid, readable array of at least `len`
/// `u32` values; `severities` may be null only if `len` is 0.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn blackhole_score_from_severities(severities: *const u32, len: usize) -> u32 {
    if len == 0 {
        return 100;
    }
    debug_assert!(!severities.is_null());

    let slice = unsafe { std::slice::from_raw_parts(severities, len) };
    let total: i32 = 100 - slice.iter().map(|&code| penalty(code)).sum::<i32>();
    total.clamp(0, 100) as u32
}

/// Sanity-check symbol for confirming the static library linked correctly
/// from Swift before wiring up the real scoring call.
#[unsafe(no_mangle)]
pub extern "C" fn blackhole_ffi_self_test() -> bool {
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_is_perfect_score() {
        let score = unsafe { blackhole_score_from_severities(std::ptr::null(), 0) };
        assert_eq!(score, 100);
    }

    #[test]
    fn matches_report_score_weights() {
        let severities = [3u32, 2, 1]; // High + Medium + Low = 25 + 12 + 5 = 42
        let score = unsafe { blackhole_score_from_severities(severities.as_ptr(), severities.len()) };
        assert_eq!(score, 58);
    }

    #[test]
    fn clamps_at_zero() {
        let severities = [3u32; 10]; // way more than 100 points of penalty
        let score = unsafe { blackhole_score_from_severities(severities.as_ptr(), severities.len()) };
        assert_eq!(score, 0);
    }
}
