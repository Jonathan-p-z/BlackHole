// Bridging header for blackhole-mobile-ffi (../../blackhole-mobile-ffi).
// Add this file's path to the app target's "Objective-C Bridging Header"
// build setting, and link libblackhole_mobile_ffi.a (built for
// aarch64-apple-ios / aarch64-apple-ios-sim on a Mac) into the target.
// Optional — see README.md. Skip this entirely if you'd rather score
// findings in pure Swift.
#ifndef BlackHoleFFI_h
#define BlackHoleFFI_h

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>

uint32_t blackhole_score_from_severities(const uint32_t *severities, size_t len);
bool blackhole_ffi_self_test(void);

#endif /* BlackHoleFFI_h */
