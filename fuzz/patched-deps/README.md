# Locally patched dependencies (fuzzing only)

`hickory-proto-0.26.1/` is a vendored copy of the upstream crate
(`~/.cargo/registry/src/.../hickory-proto-0.26.1` at the time of copying),
with two lines fixed in `src/rr/rdata/tsig.rs`'s TSIG rdata parser: an
`end_idx - decoder.index()` that panics with "attempt to subtract with
overflow" once `decoder.index()` has advanced past `end_idx`, changed to
`end_idx.saturating_sub(decoder.index())`. Both sites only feed an error
message's `read` field, so saturating to 0 is harmless; it just stops the
panic.

Applied via `fuzz/Cargo.toml`'s `[patch.crates-io]`, scoped to the `fuzz`
crate only (its own standalone `[workspace]`): **the real `blackhole-dns`
binary is unaffected** and still builds against the real, unpatched
`hickory-proto` from crates.io. This exists purely so
`fuzz/fuzz_targets/dns_relay_parse.rs` can get past this one known,
already-triaged, already-regression-tested bug (see
`blackhole-dns/THREAT_MODEL.md`) and keep exploring for new ones, instead
of re-finding the same crash on nearly every run.

**Not a substitute for an upstream fix.** This patch has not been reported
or submitted upstream as of 2026-08-31; do that separately, and remove
this vendor copy (and the `[patch.crates-io]` entry) once a real
`hickory-proto` release includes a fix.

**To regenerate** against a different `hickory-proto` version: delete this
directory, copy the new version's source from the cargo registry cache,
re-apply the same two `saturating_sub` edits in `src/rr/rdata/tsig.rs`
(search for `end_idx -`), and update the version pin in
`fuzz/Cargo.toml`'s `[dependencies]` and `[patch.crates-io]` entries to
match.
