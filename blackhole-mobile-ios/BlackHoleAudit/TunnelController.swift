import Foundation
import NetworkExtension
import Combine

/// Owns the `NETunnelProviderManager` configuration for `BlackHoleTunnel`
/// (the Packet Tunnel Provider extension) and exposes its connection status
/// to the UI. This is the closest non-jailbroken equivalent to
/// `blackhole-core`'s `NetworkGuard`: `enable()`/`disable()` here map to
/// starting/stopping the tunnel, and the on-demand rule gives it a
/// fail-closed posture while the tunnel is meant to be running.
@MainActor
final class TunnelController: ObservableObject {
    /// Must match the Packet Tunnel extension target's bundle identifier,
    /// e.g. `com.example.BlackHoleAudit.BlackHoleTunnel` — set this to your
    /// actual extension bundle ID once you've created the Xcode targets.
    private let tunnelBundleId = "com.example.BlackHoleAudit.BlackHoleTunnel"

    @Published private(set) var status: NEVPNStatus = .invalid
    @Published private(set) var lastError: String?

    private var manager: NETunnelProviderManager?
    private var statusObserver: NSObjectProtocol?

    func loadOrCreateConfiguration() async {
        do {
            let managers = try await NETunnelProviderManager.loadAllFromPreferences()
            let existing = managers.first
            let manager = existing ?? NETunnelProviderManager()

            let proto = NETunnelProviderProtocol()
            proto.providerBundleIdentifier = tunnelBundleId
            proto.serverAddress = "blackhole-local-audit-tunnel"
            // Verify in Xcode: `includeAllNetworks` availability/behavior
            // for your deployment target. Without it, some system traffic
            // (and traffic from apps with their own VPN exclusions) can
            // legitimately bypass this tunnel — that's a platform ceiling,
            // not a bug in this controller.
            proto.includeAllNetworks = true

            manager.protocolConfiguration = proto
            manager.localizedDescription = "BlackHole Audit Tunnel"
            manager.isEnabled = true

            // On-demand/fail-closed is left OFF by default. The extension's
            // `forward(packet:)` doesn't actually forward traffic yet (see
            // PacketTunnelProvider.swift), so its routes only cover a
            // documentation-only test range — turning on-demand on now
            // would just make an inert tunnel reconnect itself repeatedly
            // for no benefit. Flip this on once real packet forwarding is
            // implemented AND the tunnel routes the default route.
            manager.onDemandRules = [makeOnDemandRule()]
            manager.isOnDemandEnabled = false

            try await manager.saveToPreferences()
            try await manager.loadFromPreferences()

            self.manager = manager
            observeStatus(of: manager)
            self.status = manager.connection.status
        } catch {
            lastError = "failed to load/create tunnel configuration: \(error.localizedDescription)"
        }
    }

    private func makeOnDemandRule() -> NEOnDemandRule {
        // Connect (and stay connected) whenever any network is reachable.
        // Verify in Xcode which `NEOnDemandRule` subclass and
        // `interfaceTypeMatch` options best match your intended behavior —
        // this is the simplest "always try to be on" rule, not necessarily
        // the strictest fail-closed one available.
        let rule = NEOnDemandRuleConnect()
        rule.interfaceTypeMatch = .any
        return rule
    }

    func start() {
        guard let manager else { return }
        do {
            try manager.connection.startVPNTunnel()
        } catch {
            lastError = "failed to start tunnel: \(error.localizedDescription)"
        }
    }

    func stop() {
        manager?.connection.stopVPNTunnel()
    }

    private func observeStatus(of manager: NETunnelProviderManager) {
        if let statusObserver {
            NotificationCenter.default.removeObserver(statusObserver)
        }
        statusObserver = NotificationCenter.default.addObserver(
            forName: .NEVPNStatusDidChange,
            object: manager.connection,
            queue: .main
        ) { [weak self] _ in
            Task { @MainActor in
                self?.status = manager.connection.status
            }
        }
    }

    /// Human-readable DNS the tunnel enforces when active. Kept in sync
    /// with whatever `PacketTunnelProvider.swift` actually configures —
    /// update both places together.
    var enforcedResolverDescription: String? {
        status == .connected ? "1.1.1.1 / 1.0.0.1 (enforced by BlackHoleTunnel)" : nil
    }
}
