import NetworkExtension
import os.log

/// Minimal Packet Tunnel Provider: establishes a real tunnel interface (so
/// the host app's VPN-active/on-demand status checks have something real to
/// observe) but does **not** implement actual packet forwarding.
///
/// # Why forwarding is stubbed, not faked
///
/// Turning the raw IP packets `packetFlow` hands us into real outbound
/// connections means terminating TCP/IP ourselves at the packet level — the
/// tunnel interface's "client" is the device's own kernel network stack, so
/// this extension has to act as the other end of that conversation (answer
/// SYNs, track sequence numbers, reassemble segments) before it can even
/// decide where a byte stream is supposed to go. That's a small userspace
/// TCP/IP stack, not a forwarding loop, and hand-writing one here — in
/// Swift, with no way to compile or test it in this environment — would
/// produce something that *looks* plausible and is very likely subtly
/// broken in ways that only show up on a real device.
///
/// Rather than ship that, this provider stubs `forward(packet:)` with a
/// clear TODO. Two real paths forward, both standard practice among
/// existing iOS VPN apps:
///
/// 1. Link a maintained userspace IP stack — `smoltcp` (Rust) is a good
///    fit given this project already leans on Rust; `lwip` (C) is the
///    older, widely-used alternative many commercial iOS VPN clients embed.
/// 2. If you only need the audit/kill-switch-status behavior (not actual
///    traffic tunneling), keep this stub and do NOT enable
///    `isOnDemandEnabled`/`includeAllNetworks` in `TunnelController` — a
///    "connected" tunnel that drops all traffic is a worse failure mode on
///    a personal device than simply not having the feature yet.
class PacketTunnelProvider: NEPacketTunnelProvider {
    private static let log = OSLog(subsystem: "com.example.BlackHoleAudit.BlackHoleTunnel", category: "tunnel")

    override func startTunnel(options: [String: NSObject]?, completionHandler: @escaping (Error?) -> Void) {
        let settings = NEPacketTunnelNetworkSettings(tunnelRemoteAddress: "127.0.0.1")

        let ipv4 = NEIPv4Settings(addresses: ["10.42.0.2"], subnetMasks: ["255.255.255.0"])
        // Deliberately NOT `NEIPv4Route.default()` yet: since `forward(packet:)`
        // below doesn't forward anything, routing all device traffic here
        // would silently kill all connectivity the moment this tunnel
        // starts. Routing only a documentation-only test range
        // (203.0.113.0/24, RFC 5737 TEST-NET-3 — never used on the real
        // internet) lets the app safely demonstrate "VPN connected" status
        // on a real phone without breaking it. Switch this to
        // `[NEIPv4Route.default()]` only once real forwarding is in place.
        ipv4.includedRoutes = [NEIPv4Route(destinationAddress: "203.0.113.0", subnetMask: "255.255.255.0")]
        settings.ipv4Settings = ipv4

        // Kept in sync with TunnelController.enforcedResolverDescription —
        // update both together if you change this.
        let dns = NEDNSSettings(servers: ["1.1.1.1", "1.0.0.1"])
        dns.matchDomains = [""]
        settings.dnsSettings = dns

        settings.mtu = 1400

        setTunnelNetworkSettings(settings) { [weak self] error in
            if let error {
                os_log("failed to apply tunnel network settings: %{public}@", log: Self.log, type: .error, error.localizedDescription)
                completionHandler(error)
                return
            }
            self?.readLoop()
            completionHandler(nil)
        }
    }

    override func stopTunnel(with reason: NEProviderStopReason, completionHandler: @escaping () -> Void) {
        os_log("tunnel stopping: %{public}d", log: Self.log, type: .info, reason.rawValue)
        completionHandler()
    }

    override func handleAppMessage(_ messageData: Data, completionHandler: ((Data?) -> Void)?) {
        // Reserved for host-app <-> extension IPC (e.g. "how many flows have
        // you forwarded"). Not needed until real forwarding exists.
        completionHandler?(nil)
    }

    private func readLoop() {
        packetFlow.readPackets { [weak self] packets, protocols in
            guard let self else { return }
            for packet in packets {
                self.forward(packet: packet)
            }
            self.readLoop()
        }
    }

    /// See the type-level doc comment: intentionally not implemented.
    private func forward(packet: Data) {
        // TODO: hand `packet` to a real userspace IP stack (smoltcp/lwip)
        // and write its output back via `packetFlow.writePackets`.
    }
}
