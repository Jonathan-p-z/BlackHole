import Foundation

/// DNS visibility on iOS is much narrower than on Linux/Windows/Android:
/// there is no public API for a third-party app to read which DNS servers
/// the system is currently configured to use (see README). This type
/// reports the two things that ARE honestly available:
///
/// 1. The DNS this app's own audit tunnel enforces, when it's active
///    (trivially known, since we configured it ourselves).
/// 2. A basic resolution smoke test — does a lookup succeed and how long
///    does it take — which is a diagnostic, not a leak detector. Getting a
///    real "which resolver answered" signal on iOS would require replacing
///    the system resolver from inside a tunnel extension (which is exactly
///    what the audit tunnel does when active), not asking after the fact.
enum DnsInspector {
    struct Result {
        let enforcedByTunnel: String?
        let resolutionSucceeded: Bool
        let resolutionLatencyMs: Int?
    }

    static func check(enforcedResolver: String?, probeHost: String = "example.com") -> Result {
        let start = DispatchTime.now()
        let succeeded = resolves(host: probeHost)
        let elapsedMs = succeeded
            ? Int((DispatchTime.now().uptimeNanoseconds - start.uptimeNanoseconds) / 1_000_000)
            : nil

        return Result(
            enforcedByTunnel: enforcedResolver,
            resolutionSucceeded: succeeded,
            resolutionLatencyMs: elapsedMs
        )
    }

    /// Plain `getaddrinfo` lookup — public API, works with or without a VPN
    /// active, tells us nothing about *which* resolver answered.
    private static func resolves(host: String) -> Bool {
        var hints = addrinfo(
            ai_flags: 0,
            ai_family: AF_UNSPEC,
            ai_socktype: SOCK_STREAM,
            ai_protocol: 0,
            ai_addrlen: 0,
            ai_canonname: nil,
            ai_addr: nil,
            ai_next: nil
        )
        var result: UnsafeMutablePointer<addrinfo>?
        defer { if let result { freeaddrinfo(result) } }

        let status = getaddrinfo(host, nil, &hints, &result)
        return status == 0 && result != nil
    }
}
