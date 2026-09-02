# BlackHole Audit: iOS (no jailbreak)

A non-jailbroken iOS counterpart to `blackhole-mobile` Android: audits the
device's network posture using only public `NetworkExtension` APIs, and
optionally runs a local always-on tunnel as a lightweight kill-switch
enforcement point. No jailbreak, no private APIs, no App Store surprises
beyond the normal Network Extension review.

**This source cannot be built or tested in this repo's dev environment** (no
macOS/Xcode available where it was written). It's a complete, careful
first draft for you to drop into an Xcode project and build/test on your own
Mac + iPhone. Treat anything below marked "verify in Xcode" as exactly that.

## What this is (and isn't)

This is an **audit** tool first, matching the Android app's philosophy: it
tells you what your device's network configuration looks like and flags
what it can't fix, rather than pretending to fully lock everything down.

iOS gives third-party apps meaningfully less visibility than Android's
`VpnService` API does:

- **No public API to read the system's configured DNS servers.** Unlike
  Android, there is no App-Store-safe way for a third-party app to ask iOS
  "what DNS servers is the system currently using?". This app reports what
  DNS *our own tunnel* enforces when it's active, plus a best-effort
  resolution check, not a system-wide DNS audit.
- **No public per-app traffic attribution.** iOS has no entitlement-free way
  for a third-party app to say "app X just sent a packet outside the VPN
  tunnel." `NEFilterDataProvider`/`NETransparentProxyProvider` exist but
  require Apple to grant a special entitlement on request, and (for
  Transparent Proxy) a recent iOS version. This app does not depend on
  either, so it cannot name a leaking app the way Android's `VpnService`
  "always-on, block without VPN" combination can.
- **The baseband and iOS itself always retain radio access.** Exactly as
  with the Android app: without jailbreak (and even largely with it, absent
  a hardware-level radio kill switch or a de-Googled/de-Appled build like
  GrapheneOS's Android equivalent; no such option exists for iOS), the
  cellular baseband processor and the OS's own system services can reach
  the network in ways no third-party app can see or block. This app says so
  in the UI; it does not claim otherwise.

## What it does

1. **VPN-active check**: enumerates network interfaces (`getifaddrs`,
   public API) looking for a `utun`/`ipsec`/`ppp` tunnel interface. This
   detects *any* active VPN, not just this app's own, unlike the
   per-provider status APIs.
2. **Audit tunnel** (optional, user-enabled): a minimal
   `NEPacketTunnelProvider` extension that becomes the device's tunnel
   interface. While active:
   - Reports the DNS resolver it enforces (fixed, since we set it).
   - Can be registered with an `NEOnDemandRule` so iOS refuses new
     connections if the tunnel drops: a kill-switch-style fail-closed
     posture, the closest non-jailbroken equivalent to `blackhole-core`'s
     Linux/Windows kill switch.
   - **Packet forwarding in `PacketTunnelProvider.swift` is an MVP
     reference implementation** (basic TCP/UDP flow relay via
     `NWConnection`, no fragmentation/ICMP handling, minimal state
     tracking). It is enough to prove the tunnel end-to-end but needs
     real-device hardening before you trust it as your daily driver.
3. **Radio/baseband disclosure**: a permanent, non-dismissable notice in
   the UI, matching the Android app.

## Project setup (do this in Xcode; none of it can be scripted from here)

1. Create a new Xcode project: App template, Swift, SwiftUI, name it
   `BlackHoleAudit`. Set your own bundle identifier / team.
2. File > New > Target > Network Extension > Packet Tunnel. Name it
   `BlackHoleTunnel`. Xcode wires up the App Group and extension
   entitlements scaffolding for you; accept it.
3. Copy `BlackHoleAudit/*.swift` into the app target, and
   `BlackHoleTunnel/PacketTunnelProvider.swift` into the extension target,
   replacing Xcode's generated stub.
4. In both targets' **Signing & Capabilities**, confirm "Network
   Extensions" capability is present (Xcode adds it automatically for the
   Packet Tunnel target) and add "Personal VPN" to the main app target if
   Xcode doesn't add it for you.
5. Merge `BlackHoleAudit.entitlements` / `BlackHoleTunnel.entitlements`
   into whatever Xcode generated. Don't just overwrite: Xcode adds
   an App Group identifier you'll want to keep and reuse in both files (the
   two targets share config through it).
6. **Verify in Xcode**: `includeAllNetworks` on `NETunnelProviderProtocol`,
   exact `NEOnDemandRule` subclass availability, and minimum iOS deployment
   target: Apple has adjusted Network Extension capabilities across iOS
   releases and Xcode's own API documentation (⌥-click any symbol) is the
   authority here, not this README.
7. Run on a physical iPhone (Network Extensions do not work in the
   Simulator). The first VPN activation prompts the standard iOS "Allow VPN
   configuration" dialog.

## Optional: reusing `blackhole-fingerprint`'s scoring logic via FFI

`../blackhole-mobile-ffi` is a tiny Rust crate exposing a C ABI wrapper
around the same severity-weighted scoring model as
`blackhole-fingerprint/src/report.rs`, so this app's findings can be scored
the same way instead of reimplementing the formula in Swift. Building it
for iOS requires a Mac with `rustup target add aarch64-apple-ios` and
`cargo build --release --target aarch64-apple-ios`, then linking the
resulting `.a` into the Xcode project via a bridging header, none of which
this session can do or verify. Treat it as optional; the app works fine
scoring findings in pure Swift if you'd rather skip the FFI step.

## Distribution

Same tradeoffs as the rest of the project's mobile notes: a paid Apple
Developer account ($99/yr) is the simplest path to a durable personal
install via Xcode; AltStore/Sideloadly work with a free Apple ID but need
re-signing every 7 days; the App Store is possible but a kill-switch-style
VPN app will likely need to explain itself in review under Apple's
anti-fraud VPN policies.

## Legal/ToS note

This app only audits and (optionally) tunnels *your own* device's traffic
locally; it does not touch any third-party service's terms of use. Its
Network Extension entitlement usage must still follow Apple's Developer
Program License Agreement (accurate metadata, no deceptive VPN claims,
functioning privacy policy if you ever distribute it beyond your own
devices).
