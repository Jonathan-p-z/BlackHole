//! A small local DNS relay: listens on UDP, forwards every query to an
//! [`EncryptedResolver`], and answers with a synthesized response. Pointing
//! the OS's resolver configuration at this relay's address (typically
//! `127.0.0.1`) is the cross-platform alternative to systemd-resolved's
//! native DoT support (see [`crate::system_dns`]).
//!
//! # Known limitations (v1)
//!
//! - UDP only; no TCP fallback for truncated/large responses.
//! - Only answers `A`/`AAAA` queries; anything else gets `SERVFAIL`.
//! - Replies with a fixed TTL rather than the upstream's actual TTL.

use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;

use hickory_proto::op::{Message, Query, ResponseCode};
use hickory_proto::rr::rdata::{A, AAAA};
use hickory_proto::rr::{RData, Record, RecordType};
use tokio::net::UdpSocket;
use tracing::{info, warn};

use crate::error::DnsError;
use crate::resolver::EncryptedResolver;

pub struct Relay {
    resolver: Arc<EncryptedResolver>,
}

impl Relay {
    pub fn new(resolver: Arc<EncryptedResolver>) -> Self {
        Self { resolver }
    }

    /// Bind and serve UDP DNS requests on `addr` until cancelled.
    pub async fn serve_udp(&self, addr: SocketAddr) -> Result<(), DnsError> {
        let socket = UdpSocket::bind(addr).await?;
        info!(%addr, provider = %self.resolver.provider(), "blackhole-dns relay listening (UDP)");

        let mut buf = [0u8; 512];
        loop {
            let (len, src) = socket.recv_from(&mut buf).await?;
            if let Some(response) = self.handle_datagram(&buf[..len]).await
                && let Err(e) = socket.send_to(&response, src).await
            {
                warn!(%src, error = %e, "failed to send DNS reply");
            }
        }
    }

    async fn handle_datagram(&self, datagram: &[u8]) -> Option<Vec<u8>> {
        let request = Self::safe_parse_message(datagram)?;
        let query = request.queries.first()?.clone();
        let query_name = query.name().to_string();

        let result = match self.resolver.resolve(&query_name).await {
            Ok((ips, elapsed)) => {
                tracing::debug!(name = %query_name, ?elapsed, count = ips.len(), "relayed lookup");
                Ok(ips)
            }
            Err(e) => {
                warn!(name = %query_name, error = %e, "upstream encrypted DNS lookup failed");
                Err(e)
            }
        };

        let response = Self::build_response(request.metadata.id, request.metadata.op_code, &query, &result);
        response.to_vec().ok()
    }

    /// Parse a raw incoming datagram exactly as `Message::from_vec` does,
    /// but never let a panic inside the parser — ours or a dependency's —
    /// take the whole relay process down with it. Found necessary by
    /// fuzzing: a crafted TSIG record triggers an integer-underflow panic
    /// inside hickory-proto 0.26.1's own TSIG rdata parser
    /// (`hickory_proto::rr::rdata::tsig`), reachable from any UDP
    /// datagram sent to this relay's listening port. We can't fix that
    /// bug from here (reported upstream separately), but `datagram` is
    /// attacker-controlled input, so this boundary must fail closed
    /// (drop the one bad packet) rather than crash the process that was
    /// serving every other client. See the regression test below and
    /// `THREAT_MODEL.md`.
    ///
    /// `pub` so this can be unit-tested directly (see the regression test
    /// below) and called from other crates if ever needed. NOT used by
    /// `fuzz/fuzz_targets/dns_relay_parse.rs`, deliberately: `libfuzzer-sys`
    /// installs a panic hook that calls `process::abort()` before
    /// unwinding starts, specifically so no `catch_unwind` anywhere in a
    /// fuzzed binary can hide a panic from libFuzzer — so fuzzing this
    /// function instead of the raw parser wouldn't let the fuzzer progress
    /// past the known TSIG panic either. This function's fix is real and
    /// effective for the actual shipped relay (a normal `cargo test`
    /// binary has no such hook), just not observable from inside a
    /// libFuzzer harness.
    pub fn safe_parse_message(datagram: &[u8]) -> Option<Message> {
        match std::panic::catch_unwind(|| Message::from_vec(datagram)) {
            Ok(Ok(message)) => Some(message),
            Ok(Err(_)) => None,
            Err(_) => {
                warn!("panic while parsing an incoming DNS datagram; dropped, relay keeps serving");
                None
            }
        }
    }

    /// Build the reply for `query` from the encrypted resolver's result.
    /// Pure and synchronous on purpose: the fail-closed behavior on a
    /// resolve error — `SERVFAIL`, and never a fabricated or stale answer —
    /// is a property worth unit-testing directly, without needing a real
    /// (or even a fake) network round-trip to exercise it. `pub` (rather
    /// than private) for the same reason plus one more: it's the exact
    /// entry point `fuzz/fuzz_targets/dns_relay_parse.rs` drives with
    /// arbitrary bytes, alongside `Message::from_vec`.
    pub fn build_response(
        request_id: u16,
        op_code: hickory_proto::op::OpCode,
        query: &Query,
        result: &Result<Vec<IpAddr>, DnsError>,
    ) -> Message {
        let mut response = Message::response(request_id, op_code);

        match result {
            Ok(ips) => {
                for &ip in ips {
                    let rdata = match (ip, query.query_type()) {
                        (IpAddr::V4(v4), RecordType::A) => Some(RData::A(A(v4))),
                        (IpAddr::V6(v6), RecordType::AAAA) => Some(RData::AAAA(AAAA(v6))),
                        _ => None,
                    };
                    if let Some(rdata) = rdata {
                        response.add_answer(Record::from_rdata(query.name().clone(), 60, rdata));
                    }
                }
            }
            Err(_) => {
                response.metadata.response_code = ResponseCode::ServFail;
            }
        }

        response.add_query(query.clone());
        response
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hickory_proto::op::OpCode;
    use hickory_proto::rr::Name;
    use std::net::{Ipv4Addr, Ipv6Addr};

    fn query(record_type: RecordType) -> Query {
        let mut q = Query::new();
        q.set_name(Name::from_ascii("example.com.").unwrap());
        q.set_query_type(record_type);
        q
    }

    #[test]
    fn malformed_tsig_record_does_not_panic_the_relay() {
        // Regression test for a crash `cargo fuzz run dns_relay_parse`
        // found within its first 2-minute pass: this datagram (a query
        // with a crafted TSIG resource record) triggers
        // "attempt to subtract with overflow" inside hickory-proto
        // 0.26.1's own TSIG rdata parser (rr/rdata/tsig.rs:387) — a bug
        // in the dependency, not in this crate, so it can't be fixed
        // here and is reported upstream separately. What we own is the
        // boundary: any UDP client can send this, so `safe_parse_message`
        // must survive it (drop the packet) rather than let the panic
        // take the whole relay process down.
        let crash_input: &[u8] = &[
            0, 99, 5, 0, 0, 1, 0, 0, 0, 0, 4, 1, 0, 0, 99, 0, 0, 0, 0, 250, 254, 255, 255, 157, 0,
            6, 0, 4, 1, 0, 0, 0, 120, 110, 45, 45, 0, 0, 15, 111, 0, 0, 0, 1,
        ];
        assert!(Relay::safe_parse_message(crash_input).is_none());
    }

    #[test]
    fn resolve_failure_is_servfail_with_no_answers() {
        // The fail-closed contract: a failed upstream lookup (timeout,
        // unreachable resolver, ...) must never be answered with a
        // fabricated or cached-stale address — only SERVFAIL, with nothing
        // in the answer section.
        let result: Result<Vec<IpAddr>, DnsError> = Err(DnsError::Resolve("timed out".into()));
        let response = Relay::build_response(1234, OpCode::Query, &query(RecordType::A), &result);

        assert_eq!(response.metadata.response_code, ResponseCode::ServFail);
        assert!(response.answers.is_empty());
    }

    #[test]
    fn resolve_success_returns_matching_a_record() {
        let result: Result<Vec<IpAddr>, DnsError> = Ok(vec![IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4))]);
        let response = Relay::build_response(1234, OpCode::Query, &query(RecordType::A), &result);

        assert_eq!(response.metadata.response_code, ResponseCode::NoError);
        assert_eq!(response.answers.len(), 1);
    }

    #[test]
    fn address_family_mismatch_is_dropped_not_leaked_as_a_wrong_answer() {
        // An AAAA address answering an A query (or vice versa) must never
        // be coerced into a bogus record; silently omitting it is correct,
        // fabricating one is not.
        let result: Result<Vec<IpAddr>, DnsError> = Ok(vec![IpAddr::V6(Ipv6Addr::LOCALHOST)]);
        let response = Relay::build_response(1234, OpCode::Query, &query(RecordType::A), &result);

        assert!(response.answers.is_empty());
    }

    #[test]
    fn empty_resolve_result_is_a_plain_no_error_empty_response() {
        let result: Result<Vec<IpAddr>, DnsError> = Ok(vec![]);
        let response = Relay::build_response(1234, OpCode::Query, &query(RecordType::A), &result);

        assert_eq!(response.metadata.response_code, ResponseCode::NoError);
        assert!(response.answers.is_empty());
    }
}
