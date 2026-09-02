# Run cargo-audit against the workspace, using the exceptions documented in
# .cargo/audit.toml (each of which must have a matching entry in
# SECURITY.md). Windows PowerShell equivalent of scripts/audit.sh.
$ErrorActionPreference = "Stop"

Set-Location (Join-Path $PSScriptRoot "..")

if (-not (Get-Command cargo-audit -ErrorAction SilentlyContinue)) {
    Write-Host "cargo-audit not found; installing..."
    cargo install cargo-audit --locked
}

cargo audit
