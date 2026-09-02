import SwiftUI
import NetworkExtension

struct ContentView: View {
    @EnvironmentObject private var tunnelController: TunnelController

    @State private var vpnResult = VpnStatusChecker.Result(isActive: false, interfaceNames: [])
    @State private var dnsResult = DnsInspector.Result(enforcedByTunnel: nil, resolutionSucceeded: false, resolutionLatencyMs: nil)
    @State private var refreshTimer: Timer?

    var body: some View {
        NavigationView {
            List {
                Section("VPN") {
                    statusRow(
                        title: "Any VPN active",
                        ok: vpnResult.isActive,
                        detail: vpnResult.isActive
                            ? "interfaces: \(vpnResult.interfaceNames.joined(separator: ", "))"
                            : "no tunnel interface detected"
                    )
                    statusRow(
                        title: "BlackHole audit tunnel",
                        ok: tunnelController.status == .connected,
                        detail: describeStatus(tunnelController.status)
                    )
                    Button(tunnelController.status == .connected ? "Stop audit tunnel" : "Start audit tunnel") {
                        if tunnelController.status == .connected {
                            tunnelController.stop()
                        } else {
                            tunnelController.start()
                        }
                    }
                    if let error = tunnelController.lastError {
                        Text(error).font(.footnote).foregroundColor(.red)
                    }
                }

                Section("DNS") {
                    if let resolver = dnsResult.enforcedByTunnel {
                        statusRow(title: "Enforced resolver", ok: true, detail: resolver)
                    } else {
                        statusRow(
                            title: "System DNS",
                            ok: false,
                            detail: "iOS exposes no public API to read this — see the notice below"
                        )
                    }
                    statusRow(
                        title: "Resolution smoke test",
                        ok: dnsResult.resolutionSucceeded,
                        detail: dnsResult.resolutionLatencyMs.map { "\($0) ms" } ?? "failed"
                    )
                }

                Section("Limits of this app") {
                    Text(
                        "Without jailbreak, iOS gives no third-party app a way to read the system's " +
                        "active DNS servers or to name which app sent traffic outside a VPN tunnel — " +
                        "this app reports what it can honestly observe instead of simulating those checks."
                    )
                    .font(.footnote)

                    Text(
                        "The cellular baseband and iOS's own system services always retain radio access " +
                        "that no third-party app — jailbroken or not — can fully see or block. Airplane " +
                        "mode is the only complete cutoff this device offers."
                    )
                    .font(.footnote)
                    .foregroundColor(.orange)
                }
            }
            .navigationTitle("BlackHole Audit")
            .refreshable { refresh() }
        }
        .onAppear {
            refresh()
            refreshTimer = Timer.scheduledTimer(withTimeInterval: 5, repeats: true) { _ in
                refresh()
            }
        }
        .onDisappear {
            refreshTimer?.invalidate()
        }
    }

    private func refresh() {
        vpnResult = VpnStatusChecker.check()
        dnsResult = DnsInspector.check(enforcedResolver: tunnelController.enforcedResolverDescription)
    }

    private func describeStatus(_ status: NEVPNStatus) -> String {
        switch status {
        case .invalid: return "not configured yet"
        case .disconnected: return "disconnected"
        case .connecting: return "connecting..."
        case .connected: return "connected"
        case .reasserting: return "reasserting..."
        case .disconnecting: return "disconnecting..."
        @unknown default: return "unknown"
        }
    }

    @ViewBuilder
    private func statusRow(title: String, ok: Bool, detail: String) -> some View {
        HStack {
            Circle()
                .fill(ok ? Color.green : Color.red)
                .frame(width: 10, height: 10)
            VStack(alignment: .leading) {
                Text(title)
                Text(detail).font(.caption).foregroundColor(.secondary)
            }
        }
    }
}
