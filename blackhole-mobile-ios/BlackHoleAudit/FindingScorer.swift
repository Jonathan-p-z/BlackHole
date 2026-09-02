import Foundation

enum Severity: UInt32 {
    case info = 0
    case low = 1
    case medium = 2
    case high = 3
}

/// Scores findings using the shared Rust logic in `blackhole-mobile-ffi`
/// when it's linked in, falling back to an identical pure-Swift
/// implementation otherwise so the app works without the FFI step (see
/// README.md — the Rust side can't be built for iOS from this repo's dev
/// environment).
///
/// There's no automatic way to detect "is the bridging header's C function
/// actually linked" from Swift, so this is gated on a build setting you
/// define yourself: after linking `libblackhole_mobile_ffi.a` and the
/// bridging header, add `BLACKHOLE_FFI_ENABLED` to the app target's
/// "Active Compilation Conditions" (Swift Compiler - Custom Flags). Until
/// then this always uses the pure-Swift fallback below — delete it once
/// the FFI path is verified working, so there's only one place the
/// weights can drift.
enum FindingScorer {
    static func score(_ severities: [Severity]) -> UInt32 {
#if BLACKHOLE_FFI_ENABLED
        let codes = severities.map { $0.rawValue }
        return codes.withUnsafeBufferPointer { buffer in
            blackhole_score_from_severities(buffer.baseAddress, buffer.count)
        }
#else
        var total = 100
        for severity in severities {
            switch severity {
            case .info: total -= 0
            case .low: total -= 5
            case .medium: total -= 12
            case .high: total -= 25
            }
        }
        return UInt32(max(0, min(100, total)))
#endif
    }
}
