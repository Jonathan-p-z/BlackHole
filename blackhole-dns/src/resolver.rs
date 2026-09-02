//! Wrapper around `hickory-resolver` configured to speak only encrypted DNS
//! (DoH or DoT) to a configured, ordered list of resolvers, bypassing the
//! OS stub resolver entirely for our own lookups.
//!
//! Two properties beyond "the wire is encrypted":
//!
//! - **Authenticity**: every resolver in the chain validates DNSSEC
//!   (`ResolverOpts::validate`). Confidentiality alone doesn't stop a
//!   malicious or compromised resolver from lying about the answer;
//!   DNSSEC (where the queried zone has it deployed) lets us catch that.
//!   A `Bogus` proof — the chain of trust says this *should* be signed,
//!   but isn't (or the signature is wrong) — is treated as an error, the
//!   same as any other lookup failure: never returned to the caller as if
//!   it were trustworthy. An `Insecure` proof (the zone legitimately
//!   isn't signed — most of the internet, today) is not an error.
//! - **No single point of failure or trust**: `EncryptedResolver` holds a
//!   priority-ordered list of resolvers. `resolve()` tries them in order
//!   starting from whichever one last succeeded, wrapping around; a
//!   resolver that fails (network error or DNSSEC-bogus) is skipped in
//!   favor of the next, and the switch is logged. The chain only ever
//!   contains encrypted (DoH/DoT) resolvers — there is no code path that
//!   can fall back to an unencrypted one, at any priority.

use std::net::IpAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use hickory_proto::rr::Record;
use hickory_resolver::config::{ResolverConfig, CLOUDFLARE, QUAD9};
use hickory_resolver::Resolver;
use tracing::warn;

use crate::error::DnsError;

/// Well-known public resolvers we know how to speak DoH/DoT to.
/// `Deserialize` (`#[serde(rename_all = "lowercase")]`) so this can be
/// named directly in the `[dns] providers = [...]` config file — see
/// `config.rs` — without a separate shadow enum to keep in sync.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Provider {
    Cloudflare,
    Quad9,
    Mullvad,
}

const CLOUDFLARE_IPS: [IpAddr; 2] = [
    IpAddr::V4(std::net::Ipv4Addr::new(1, 1, 1, 1)),
    IpAddr::V4(std::net::Ipv4Addr::new(1, 0, 0, 1)),
];
const QUAD9_IPS: [IpAddr; 1] = [IpAddr::V4(std::net::Ipv4Addr::new(9, 9, 9, 9))];
const MULLVAD_IPS: [IpAddr; 1] = [IpAddr::V4(std::net::Ipv4Addr::new(194, 242, 2, 2))];

const MULLVAD: hickory_resolver::config::ServerGroup<'static> = hickory_resolver::config::ServerGroup {
    ips: &MULLVAD_IPS,
    server_name: "dns.mullvad.net",
    path: "/dns-query",
};

impl Provider {
    /// IPs this provider answers on, used by leak detection to recognize
    /// "the OS is (correctly) pointed at one of our encrypted resolvers".
    pub fn ip_addrs(self) -> &'static [IpAddr] {
        match self {
            Provider::Cloudflare => &CLOUDFLARE_IPS,
            Provider::Quad9 => &QUAD9_IPS,
            Provider::Mullvad => &MULLVAD_IPS,
        }
    }

    fn server_group(self) -> &'static hickory_resolver::config::ServerGroup<'static> {
        match self {
            Provider::Cloudflare => &CLOUDFLARE,
            Provider::Quad9 => &QUAD9,
            Provider::Mullvad => &MULLVAD,
        }
    }
}

impl std::fmt::Display for Provider {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Provider::Cloudflare => write!(f, "Cloudflare (1.1.1.1)"),
            Provider::Quad9 => write!(f, "Quad9 (9.9.9.9)"),
            Provider::Mullvad => write!(f, "Mullvad (194.242.2.2)"),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Transport {
    Doh,
    Dot,
}

/// Whatever can answer a DNSSEC-validating lookup for a single resolver.
/// Exists so `EncryptedResolver`'s chain/fallback/DNSSEC-rejection logic
/// can be unit-tested against a fake backend, without a real network round
/// trip to a real DoH/DoT resolver.
#[async_trait::async_trait]
trait DohBackend: Send + Sync {
    async fn lookup(&self, name: &str) -> Result<Vec<Record>, DnsError>;
}

#[async_trait::async_trait]
impl DohBackend for hickory_resolver::TokioResolver {
    async fn lookup(&self, name: &str) -> Result<Vec<Record>, DnsError> {
        let lookup = self
            .lookup_ip(name)
            .await
            .map_err(|e| DnsError::Resolve(format!("lookup of '{name}' failed: {e}")))?;
        Ok(lookup.as_lookup().message().answers.clone())
    }
}

/// Reject an answer whose DNSSEC proof is `Bogus` (the chain of trust says
/// it should be signed, but validation failed) rather than accept it
/// silently. `Insecure` (legitimately unsigned zone) and `Secure` both
/// pass; only `Bogus` is treated as a possible attack/tamper indicator.
/// Pure and synchronous on purpose — see `resolver::tests` for direct
/// coverage with hand-built records, no network or fake backend needed.
fn reject_bogus(records: &[Record], name: &str) -> Result<(), DnsError> {
    if let Some(bogus) = records.iter().find(|r| r.proof.is_bogus()) {
        return Err(DnsError::DnssecValidationFailed {
            name: name.to_string(),
            detail: format!("record '{}' has DNSSEC proof Bogus (signature or chain of trust invalid)", bogus.name),
        });
    }
    Ok(())
}

/// A DNS resolver that only ever talks encrypted, DNSSEC-validating DNS,
/// to a priority-ordered list of providers. Used both to serve the local
/// relay and to run leak-detection test queries.
pub struct EncryptedResolver {
    transport: Transport,
    chain: Vec<(Provider, Box<dyn DohBackend>)>,
    /// Index into `chain` of the provider `resolve()` should try first.
    /// Updated to whichever provider most recently succeeded, so a
    /// transient primary failure doesn't force every subsequent query to
    /// re-pay that provider's timeout before falling back again.
    active: AtomicUsize,
}

impl EncryptedResolver {
    /// Build a resolver chain from `providers` in priority order (index 0
    /// tried first). Every resolver in the chain validates DNSSEC.
    pub fn new(providers: &[Provider], transport: Transport) -> Result<Self, DnsError> {
        if providers.is_empty() {
            return Err(DnsError::Resolve(
                "at least one DoH/DoT provider must be configured".to_string(),
            ));
        }

        let mut chain: Vec<(Provider, Box<dyn DohBackend>)> = Vec::with_capacity(providers.len());
        for &provider in providers {
            let config = match transport {
                Transport::Doh => ResolverConfig::https(provider.server_group()),
                Transport::Dot => ResolverConfig::tls(provider.server_group()),
            };

            let mut builder = Resolver::builder_with_config(config, Default::default());
            // DNSSEC: authenticate answers, not just encrypt the wire.
            builder.options_mut().validate = true;
            let inner: hickory_resolver::TokioResolver = builder
                .build()
                .map_err(|e| DnsError::Resolve(format!("failed to build resolver for {provider}: {e}")))?;

            chain.push((provider, Box::new(inner)));
        }

        Ok(Self {
            transport,
            chain,
            active: AtomicUsize::new(0),
        })
    }

    /// Convenience for the common single-provider case (tests, simple
    /// callers that don't need a fallback list).
    pub fn single(provider: Provider, transport: Transport) -> Result<Self, DnsError> {
        Self::new(&[provider], transport)
    }

    /// The provider `resolve()` will try first right now — the most
    /// recently successful one, or the top of the configured priority
    /// list if nothing has failed over yet.
    pub fn provider(&self) -> Provider {
        self.chain[self.active.load(Ordering::Relaxed)].0
    }

    pub fn transport(&self) -> Transport {
        self.transport
    }

    /// Every provider in the configured chain, used by leak detection to
    /// recognize any of them as an expected active OS resolver (relevant
    /// for DoT, where the OS resolver stack itself is pointed at one of
    /// these IPs — DoH-via-relay instead expects loopback, passed
    /// separately as `extra_allowed`).
    pub fn all_provider_ips(&self) -> Vec<IpAddr> {
        self.chain.iter().flat_map(|(p, _)| p.ip_addrs().iter().copied()).collect()
    }

    /// Resolve `name` and report how long it took. Tries the chain in
    /// priority order starting from whichever provider last succeeded
    /// (wrapping around), skipping any that fail — a network error, or a
    /// DNSSEC-bogus answer, are both treated as "this provider failed,
    /// try the next" rather than ever being returned to the caller.
    /// Every provider in the chain is itself always encrypted DoH/DoT:
    /// there is no code path here that can fall back to an unencrypted
    /// resolver, at any priority.
    pub async fn resolve(&self, name: &str) -> Result<(Vec<IpAddr>, Duration), DnsError> {
        let started = Instant::now();
        let start_idx = self.active.load(Ordering::Relaxed);
        let mut last_err: Option<DnsError> = None;

        for offset in 0..self.chain.len() {
            let idx = (start_idx + offset) % self.chain.len();
            let (provider, backend) = &self.chain[idx];

            let outcome = match backend.lookup(name).await {
                Ok(records) => reject_bogus(&records, name).map(|()| records),
                Err(e) => Err(e),
            };

            match outcome {
                Ok(records) => {
                    let ips: Vec<IpAddr> = records.iter().filter_map(|r| r.data.ip_addr()).collect();
                    let previous = self.active.swap(idx, Ordering::Relaxed);
                    if previous != idx {
                        warn!(
                            from = %self.chain[previous].0,
                            to = %provider,
                            "switched DoH/DoT resolver after a failure"
                        );
                    }
                    return Ok((ips, started.elapsed()));
                }
                Err(e) => {
                    warn!(provider = %provider, error = %e, "resolver failed; trying the next configured provider");
                    last_err = Some(e);
                }
            }
        }

        Err(last_err.unwrap_or_else(|| DnsError::Resolve("no DoH/DoT resolvers configured".to_string())))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hickory_proto::dnssec::Proof;
    use hickory_proto::rr::rdata::A;
    use hickory_proto::rr::{Name, RData};
    use std::net::Ipv4Addr;

    fn a_record(proof: Proof, ip: Ipv4Addr) -> Record {
        let mut record = Record::from_rdata(
            Name::from_ascii("example.com.").unwrap(),
            60,
            RData::A(A(ip)),
        );
        record.proof = proof;
        record
    }

    // --- pure `reject_bogus` tests: no network, no fake backend needed ---

    #[test]
    fn secure_record_is_accepted() {
        let records = vec![a_record(Proof::Secure, Ipv4Addr::new(1, 2, 3, 4))];
        assert!(reject_bogus(&records, "example.com").is_ok());
    }

    #[test]
    fn insecure_record_is_accepted_not_treated_as_an_error() {
        // Most of the internet doesn't deploy DNSSEC at all; that must
        // never be conflated with an attack.
        let records = vec![a_record(Proof::Insecure, Ipv4Addr::new(1, 2, 3, 4))];
        assert!(reject_bogus(&records, "example.com").is_ok());
    }

    #[test]
    fn bogus_record_is_rejected() {
        // A corrupted/invalid signature: the chain of trust says this
        // *should* validate and doesn't.
        let records = vec![a_record(Proof::Bogus, Ipv4Addr::new(1, 2, 3, 4))];
        let err = reject_bogus(&records, "example.com").unwrap_err();
        assert!(matches!(err, DnsError::DnssecValidationFailed { .. }));
    }

    #[test]
    fn one_bogus_record_among_others_still_rejects_the_whole_answer() {
        let records = vec![
            a_record(Proof::Secure, Ipv4Addr::new(1, 2, 3, 4)),
            a_record(Proof::Bogus, Ipv4Addr::new(5, 6, 7, 8)),
        ];
        assert!(reject_bogus(&records, "example.com").is_err());
    }

    // --- fallback-chain tests: fake backend, no network ---

    enum FakeBackend {
        Ok(Vec<Record>),
        Fail,
    }

    impl FakeBackend {
        fn ok(ip: Ipv4Addr) -> Self {
            Self::Ok(vec![a_record(Proof::Secure, ip)])
        }

        fn bogus() -> Self {
            Self::Ok(vec![a_record(Proof::Bogus, Ipv4Addr::new(0, 0, 0, 0))])
        }

        fn failing() -> Self {
            Self::Fail
        }
    }

    #[async_trait::async_trait]
    impl DohBackend for FakeBackend {
        async fn lookup(&self, _name: &str) -> Result<Vec<Record>, DnsError> {
            match self {
                Self::Ok(records) => Ok(records.clone()),
                Self::Fail => Err(DnsError::Resolve("simulated network failure".to_string())),
            }
        }
    }

    fn resolver_with(chain: Vec<(Provider, Box<dyn DohBackend>)>) -> EncryptedResolver {
        EncryptedResolver {
            transport: Transport::Doh,
            chain,
            active: AtomicUsize::new(0),
        }
    }

    #[tokio::test]
    async fn healthy_primary_is_used_without_falling_back() {
        let resolver = resolver_with(vec![
            (Provider::Cloudflare, Box::new(FakeBackend::ok(Ipv4Addr::new(1, 1, 1, 1)))),
            (Provider::Quad9, Box::new(FakeBackend::failing())),
        ]);

        let (ips, _) = resolver.resolve("example.com").await.unwrap();
        assert_eq!(ips, vec![IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1))]);
        assert_eq!(resolver.provider(), Provider::Cloudflare);
    }

    #[tokio::test]
    async fn failing_primary_falls_back_to_next_without_returning_its_answer() {
        let resolver = resolver_with(vec![
            (Provider::Cloudflare, Box::new(FakeBackend::failing())),
            (Provider::Quad9, Box::new(FakeBackend::ok(Ipv4Addr::new(9, 9, 9, 9)))),
        ]);

        let (ips, _) = resolver.resolve("example.com").await.unwrap();
        // Only the fallback's answer is ever returned — nothing from the
        // failed primary leaks through.
        assert_eq!(ips, vec![IpAddr::V4(Ipv4Addr::new(9, 9, 9, 9))]);
        assert_eq!(resolver.provider(), Provider::Quad9);
    }

    #[tokio::test]
    async fn dnssec_bogus_primary_falls_back_same_as_a_network_failure() {
        let resolver = resolver_with(vec![
            (Provider::Cloudflare, Box::new(FakeBackend::bogus())),
            (Provider::Quad9, Box::new(FakeBackend::ok(Ipv4Addr::new(9, 9, 9, 9)))),
        ]);

        let (ips, _) = resolver.resolve("example.com").await.unwrap();
        assert_eq!(ips, vec![IpAddr::V4(Ipv4Addr::new(9, 9, 9, 9))]);
        assert_eq!(resolver.provider(), Provider::Quad9);
    }

    #[tokio::test]
    async fn subsequent_queries_start_from_the_provider_that_last_succeeded() {
        let resolver = resolver_with(vec![
            (Provider::Cloudflare, Box::new(FakeBackend::failing())),
            (Provider::Quad9, Box::new(FakeBackend::ok(Ipv4Addr::new(9, 9, 9, 9)))),
        ]);

        resolver.resolve("example.com").await.unwrap();
        assert_eq!(resolver.provider(), Provider::Quad9);

        // Second query: Quad9 (now `active`) is tried first and still
        // works, so it stays the active provider without needing to
        // re-fail Cloudflare first.
        let (ips, _) = resolver.resolve("example.org").await.unwrap();
        assert_eq!(ips, vec![IpAddr::V4(Ipv4Addr::new(9, 9, 9, 9))]);
        assert_eq!(resolver.provider(), Provider::Quad9);
    }

    #[tokio::test]
    async fn all_providers_failing_is_reported_not_silently_swallowed() {
        let resolver = resolver_with(vec![
            (Provider::Cloudflare, Box::new(FakeBackend::failing())),
            (Provider::Quad9, Box::new(FakeBackend::bogus())),
        ]);

        let err = resolver.resolve("example.com").await.unwrap_err();
        // The *last* attempted provider's failure reason is surfaced.
        assert!(matches!(err, DnsError::DnssecValidationFailed { .. }));
    }

    #[test]
    fn empty_provider_list_is_rejected_at_construction() {
        match EncryptedResolver::new(&[], Transport::Doh) {
            Err(DnsError::Resolve(_)) => {}
            other => panic!("expected DnsError::Resolve, got: {}", other.is_ok()),
        }
    }
}
