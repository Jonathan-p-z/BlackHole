//! Public network exposure check: what a plain outbound HTTP request from
//! this machine reveals about it (public IP, ISP/ASN, approximate
//! location) to literally any site it connects to outside Tor/a VPN.
//!
//! # Why not a browser-fingerprinting service (Cover Your Tracks etc.)
//!
//! Sites like EFF's Cover Your Tracks measure *browser* fingerprint
//! entropy — canvas rendering, WebGL, installed fonts, JS APIs — collected
//! by client-side JavaScript running in a real browser, then scored
//! server-side from that submitted payload. There is no meaningful way for
//! a headless Rust HTTP client to reproduce that (there's nothing for it to
//! submit), and scraping such a service without actually running its JS
//! would just report meaningless/default values. Rather than fabricate
//! that integration, this module checks what a plain-HTTP client *can*
//! honestly expose — your network-level identity — via a small public
//! IP-info JSON API. For a real browser-fingerprint score, run Cover Your
//! Tracks (https://coveryourtracks.eff.org) manually in the browser you
//! actually intend to use.

use crate::report::{Category, Finding, Severity};

const IP_INFO_URL: &str = "https://ipapi.co/json/";

#[derive(serde::Deserialize, Default)]
struct IpInfoResponse {
    ip: Option<String>,
    city: Option<String>,
    region: Option<String>,
    country_name: Option<String>,
    org: Option<String>,
    error: Option<bool>,
    reason: Option<String>,
}

/// Parse a raw IP-info service response and turn it into findings. Pure and
/// synchronous — no network I/O — on purpose: this is the untrusted-input
/// boundary (arbitrary bytes from a third-party service, not necessarily
/// valid JSON or even valid UTF-8) worth unit-testing and fuzzing directly,
/// separate from the HTTP fetch in [`checks`]. Exercised by
/// `fuzz/fuzz_targets/fingerprint_report_parse.rs`.
pub fn parse_report(bytes: &[u8]) -> Vec<Finding> {
    let info: IpInfoResponse = match serde_json::from_slice(bytes) {
        Ok(i) => i,
        Err(e) => {
            return vec![Finding::new(
                Category::Exposure,
                Severity::Info,
                format!("could not parse IP-info response: {e}"),
            )]
        }
    };
    findings_from_ip_info(info)
}

fn findings_from_ip_info(info: IpInfoResponse) -> Vec<Finding> {
    if info.error.unwrap_or(false) {
        return vec![Finding::new(
            Category::Exposure,
            Severity::Info,
            format!(
                "IP-info service declined the request: {}",
                info.reason.unwrap_or_else(|| "unknown reason".to_string())
            ),
        )];
    }

    let ip = info.ip.unwrap_or_else(|| "(unknown)".to_string());
    let location = [info.city, info.region, info.country_name]
        .into_iter()
        .flatten()
        .collect::<Vec<_>>()
        .join(", ");
    let org = info.org.unwrap_or_else(|| "(unknown network operator)".to_string());

    let looks_like_privacy_egress = ["tor", "vpn", "relay", "proxy"]
        .iter()
        .any(|kw| org.to_lowercase().contains(kw));

    let summary = format!("outbound traffic exits as {ip} via {org}{}", if location.is_empty() { String::new() } else { format!(" ({location})") });

    if looks_like_privacy_egress {
        vec![Finding::new(
            Category::Exposure,
            Severity::Info,
            format!("{summary} — looks like a Tor/VPN egress, not your direct ISP"),
        )]
    } else {
        vec![Finding::new(Category::Exposure, Severity::Medium, summary).with_recommendation(
            "any site you connect to directly (outside Tor) sees this IP/ISP/location; use blackhole-core's kill switch for traffic that should stay anonymous",
        )]
    }
}

pub fn checks() -> Vec<Finding> {
    let client = match reqwest::blocking::Client::builder()
        .timeout(std::time::Duration::from_secs(8))
        .user_agent("blackhole-fingerprint")
        .build()
    {
        Ok(c) => c,
        Err(e) => {
            return vec![Finding::new(
                Category::Exposure,
                Severity::Info,
                format!("could not build HTTP client for exposure check: {e}"),
            )]
        }
    };

    let response = match client.get(IP_INFO_URL).send().and_then(|r| r.error_for_status()) {
        Ok(r) => r,
        Err(e) => {
            return vec![Finding::new(
                Category::Exposure,
                Severity::Info,
                format!("could not reach the public IP-info service ({e}); skipping network exposure check"),
            )]
        }
    };

    let bytes = match response.bytes() {
        Ok(b) => b,
        Err(e) => {
            return vec![Finding::new(
                Category::Exposure,
                Severity::Info,
                format!("could not read IP-info response body: {e}"),
            )]
        }
    };

    parse_report(&bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_input_is_reported_not_panicked() {
        let findings = parse_report(b"");
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, Severity::Info);
    }

    #[test]
    fn non_utf8_bytes_are_reported_not_panicked() {
        let findings = parse_report(&[0xff, 0xfe, 0x00, 0xd8, 0x00, 0x00]);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, Severity::Info);
    }

    #[test]
    fn truncated_json_is_reported_not_panicked() {
        let findings = parse_report(br#"{"ip": "1.2.3.4", "org"#);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, Severity::Info);
    }

    #[test]
    fn wrong_json_shape_is_reported_not_panicked() {
        // A JSON array where an object was expected.
        let findings = parse_report(br#"[1, 2, 3]"#);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, Severity::Info);
    }

    #[test]
    fn service_declined_response_is_info_not_medium() {
        let findings = parse_report(br#"{"error": true, "reason": "rate limited"}"#);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, Severity::Info);
        assert!(findings[0].summary.contains("rate limited"));
    }

    #[test]
    fn plain_isp_response_is_medium_with_recommendation() {
        let findings = parse_report(
            br#"{"ip": "203.0.113.5", "city": "Springfield", "region": "IL", "country_name": "US", "org": "Example ISP"}"#,
        );
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, Severity::Medium);
        assert!(findings[0].recommendation.is_some());
        assert!(findings[0].summary.contains("203.0.113.5"));
    }

    #[test]
    fn tor_vpn_org_is_info_not_medium() {
        let findings = parse_report(br#"{"ip": "203.0.113.5", "org": "Some Tor Exit Relay Operator"}"#);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, Severity::Info);
        assert!(findings[0].summary.contains("Tor/VPN egress"));
    }

    #[test]
    fn missing_fields_fall_back_to_placeholders_not_panicked() {
        let findings = parse_report(br#"{}"#);
        assert_eq!(findings.len(), 1);
        assert!(findings[0].summary.contains("(unknown)"));
        assert!(findings[0].summary.contains("(unknown network operator)"));
    }

    #[test]
    fn deeply_nested_json_does_not_panic() {
        // A pathological-but-plausible fuzzer-found shape: valid JSON, wrong
        // types nested where scalars were expected.
        let findings = parse_report(br#"{"ip": {"nested": [1,2,3]}, "org": null}"#);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, Severity::Info);
    }
}
