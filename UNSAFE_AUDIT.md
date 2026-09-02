# `unsafe` audit

Every `unsafe` block in this workspace, as of 2026-08-31. `blackhole-dns`,
`blackhole-dashboard`, and `blackhole-fingerprint` contain zero `unsafe`
code. All 16 blocks below already carry a `// SAFETY: ...` (or `/// #
Safety` for `unsafe fn`) comment explaining the invariant the caller/author
is relying on. This audit's job was to verify that's actually true (it
is), and separately judge whether a safe alternative exists.

## `blackhole-core/src/platform/linux.rs`

| Line | Call | Safe alternative? |
| --- | --- | --- |
| 53 | `libc::getuid()` | Yes, in principle: `rustix::process::getuid()` or `nix::unistd::getuid()` wrap this safely. **Not adopted**: `getuid(2)` takes no arguments, cannot fail, and touches no memory, so there is no invariant for the caller to uphold and the `unsafe` here is a formality rather than a real risk. Pulling in a new dependency (`rustix`/`nix`) to remove one zero-risk `unsafe` block on a single infallible syscall isn't worth the added dependency surface (an extra crate to audit and update). |

## `blackhole-core/src/platform/windows.rs`

All 12 blocks call directly into the Windows Filtering Platform C API
(`Fwpm*0`) via `windows-rs`'s raw FFI bindings, or build a union field with
`std::mem::zeroed()`. **No safe alternative exists for any of these**:
`windows-rs` intentionally exposes WFP as raw, `unsafe` FFI; there is no
safe-Rust wrapper crate for WFP in the ecosystem, and writing one is out of
scope for this project (it would itself just be this same `unsafe` code,
moved). Each has been checked against the invariant its `SAFETY` comment
claims:

| Line | Call | Invariant claimed | Verified |
| --- | --- | --- | --- |
| 106 | `FwpmEngineOpen0` | all pointer args null or valid | yes: `handle` is a fresh local |
| 119 | `FwpmEngineClose0` | `handle` came from a successful `FwpmEngineOpen0` | yes: only call site is `close_engine`, only called with `with_engine`'s handle |
| 162 | `FwpmSubLayerGetByKey0` | `engine` valid, `out` valid out-pointer | yes |
| 165 | `FwpmFreeMemory0` | `out` was allocated by the preceding `FwpmSubLayerGetByKey0` | yes: only reached on that call's success branch |
| 178 | `FwpmFilterDeleteByKey0` (loop) | `engine` valid, `key` one of our own constants | yes: iterates `ALL_FILTER_KEYS` |
| 184 | `FwpmSubLayerDeleteByKey0` | sublayer has no remaining filter referencing it | yes: runs after the filter-deletion loop above |
| 202 | `FwpmSubLayerAdd0` | all pointers in `sublayer` valid for the call | yes: see `providerKey` note below |
| 232, 291 | `std::mem::zeroed()` for `FWPM_ACTION0`'s `Anonymous` union field | zero is a valid bit pattern for a non-callout action | yes: both are `FWP_ACTION_BLOCK`/`FWP_ACTION_PERMIT`, never a callout |
| 301 | `FwpmFilterAdd0` | `filter` and everything it points to valid for the call | yes |
| 316 | `FwpmGetAppIdFromFileName0` | `wide` valid NUL-terminated wide string, `app_id` valid out-pointer | yes |
| 363 | `FwpmFreeMemory0` | `app_id` was allocated by `FwpmGetAppIdFromFileName0` | yes |

**Fixed during this audit, not just reviewed**: `add_sublayer`,
`block_all_filter`, and `permit_filter` originally pointed each struct's
`providerKey: *mut GUID` field at a `let mut provider_key = PROVIDER_KEY`
local. `block_all_filter`/`permit_filter` *return* that struct by value to
a caller that performs the actual `Fwpm*Add0` call later, by which point
the local's stack frame was gone, so the FFI call read through a dangling
pointer (real UB, not just theoretical: `add_sublayer` itself was fine
since it calls `FwpmSubLayerAdd0` before returning). Fixed by pointing all
three at a `static PROVIDER_KEY_STATIC: GUID`, which has one address for
the life of the process. See `blackhole-core/src/platform/windows.rs`
around `PROVIDER_KEY_STATIC`/`provider_key_ptr()`.

## `blackhole-mobile-ffi/src/lib.rs`

| Line | Item | Safe alternative? |
| --- | --- | --- |
| 40-49 | `unsafe extern "C" fn blackhole_score_from_severities`, containing `unsafe { std::slice::from_raw_parts(severities, len) }` | No: this function's entire purpose is to be a C-callable entry point for Swift, taking a raw pointer + length across the FFI boundary; that shape is inherently `unsafe` in Rust. Already documented with a `# Safety` doc comment stating the exact precondition (`severities` valid for `len` reads, or null only if `len == 0`), plus a `debug_assert!(!severities.is_null())` as a best-effort runtime check in debug builds. |
| 54-57 | `unsafe extern "C" fn blackhole_ffi_self_test` | `unsafe` only because of the `extern "C"` FFI export requirement; the function body itself (`true`) does nothing unsafe. No alternative; this is standard for any `#[no_mangle] extern "C"` export. |

## Summary

- 16 `unsafe` blocks/functions total across the workspace, all in
  `blackhole-core` (14) and `blackhole-mobile-ffi` (2).
- 100% already had a `SAFETY`/`# Safety` comment before this audit; all
  were verified against the actual call site rather than taken on faith.
- 1 real bug found and fixed (the `providerKey` use-after-return above):
  not a missing-comment problem, a case where the comment ("all pointers
  valid for the duration of this call") was true for the function that had
  it but not for the two functions that reused the same pattern without
  re-checking it.
- 15 of 16 have no viable safe alternative (WFP and C-ABI FFI are
  inherently `unsafe` in Rust); 1 (`getuid`) has one but isn't worth
  adopting for a zero-risk, infallible, argument-free syscall.
