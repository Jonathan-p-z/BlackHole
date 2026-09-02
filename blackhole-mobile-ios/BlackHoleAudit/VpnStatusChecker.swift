import Foundation

/// Detects whether *any* VPN is active on the device, not just one this app
/// manages. iOS provides no public "is a VPN connected" query for arbitrary
/// third-party tunnels, so this uses the same technique several open-source
/// tools rely on: walk the device's network interfaces (public
/// `getifaddrs(3)` API, no entitlement needed) looking for a tunnel-shaped
/// interface name.
enum VpnStatusChecker {
    /// Interface name prefixes iOS uses for VPN/tunnel interfaces. `utun` is
    /// the standard case (IKEv2, WireGuard-style apps, and this app's own
    /// Packet Tunnel Provider all show up as `utun*`); `ppp`/`ipsec` cover
    /// older configuration types still seen on some managed devices.
    private static let tunnelInterfacePrefixes = ["utun", "ppp", "ipsec"]

    struct Result {
        let isActive: Bool
        let interfaceNames: [String]
    }

    static func check() -> Result {
        var interfaceNames: [String] = []

        var ifaddrPointer: UnsafeMutablePointer<ifaddrs>?
        guard getifaddrs(&ifaddrPointer) == 0, let firstAddr = ifaddrPointer else {
            return Result(isActive: false, interfaceNames: [])
        }
        defer { freeifaddrs(ifaddrPointer) }

        var cursor: UnsafeMutablePointer<ifaddrs>? = firstAddr
        while let current = cursor {
            defer { cursor = current.pointee.ifa_next }

            let flags = Int32(current.pointee.ifa_flags)
            let isUp = (flags & IFF_UP) == IFF_UP
            guard isUp else { continue }

            let name = String(cString: current.pointee.ifa_name)
            if tunnelInterfacePrefixes.contains(where: { name.hasPrefix($0) }) {
                if !interfaceNames.contains(name) {
                    interfaceNames.append(name)
                }
            }
        }

        return Result(isActive: !interfaceNames.isEmpty, interfaceNames: interfaceNames)
    }
}
