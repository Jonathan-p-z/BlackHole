#!/usr/bin/env bash
# Run cargo-audit against the workspace, using the exceptions documented in
# .cargo/audit.toml (each of which must have a matching entry in
# SECURITY.md). Usable locally (Linux/macOS/Git Bash on Windows) and from
# CI — see .github/workflows/audit.yml for the CI invocation.
set -euo pipefail

cd "$(dirname "${BASH_SOURCE[0]}")/.."

if ! command -v cargo-audit >/dev/null 2>&1; then
    echo "cargo-audit not found; installing..." >&2
    cargo install cargo-audit --locked
fi

cargo audit
