# BlackHole installer (Windows). Builds the workspace from source and
# installs the resulting binaries + a starter config for the current user
# only -- no elevation/Administrator prompt, ever, for this script. Read
# it before running it; it's deliberately short so that's quick to do.
#
# Usage: run from inside a clone of this repo:
#   .\install.ps1
#
# Once this project has public GitHub releases, a winget/Scoop package
# will be documented in README.md instead -- not yet, since no such
# release exists to package (see README's "Installation rapide" section
# for the current state of that).

$ErrorActionPreference = "Stop"

$BinDir = Join-Path $env:USERPROFILE ".local\bin"
# The `directories` crate (what every blackhole-* binary actually reads
# this path from) puts an extra "config" segment under %APPDATA% on
# Windows that it doesn't add on Linux/macOS -- see
# directories-*/src/win.rs's project_dirs_from_path. Keep this in sync
# with config::default_config_path() in blackhole-core/-dns/-fingerprint.
$ConfigDir = Join-Path $env:APPDATA "blackhole\config"
$ConfigFile = Join-Path $ConfigDir "config.toml"

Write-Host "This installs BlackHole for the current user only: compiles the workspace"
Write-Host "with 'cargo build --release', copies the binaries to $BinDir, and drops a"
Write-Host "commented starter config at $ConfigFile if none exists yet. No elevation"
Write-Host "is requested at any point; nothing outside your user profile is touched."
Write-Host ""

if (-not (Get-Command cargo -ErrorAction SilentlyContinue)) {
    Write-Host "error: cargo not found." -ForegroundColor Red
    Write-Host "BlackHole is built from source; install Rust first via https://rustup.rs"
    Write-Host "(this script won't do that for you, so you can see exactly what runs)."
    exit 1
}

$RepoRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location $RepoRoot

Write-Host "Building (this can take a while on first run)..."
cargo build --release --workspace --bins
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

New-Item -ItemType Directory -Force -Path $BinDir | Out-Null
foreach ($bin in @("blackhole-core", "blackhole-dns", "blackhole-dashboard", "blackhole-fingerprint")) {
    $src = Join-Path "target\release" "$bin.exe"
    if (Test-Path $src) {
        Copy-Item $src (Join-Path $BinDir "$bin.exe") -Force
        Write-Host "installed $(Join-Path $BinDir "$bin.exe")"
    }
}

if (-not (Test-Path $ConfigFile)) {
    New-Item -ItemType Directory -Force -Path $ConfigDir | Out-Null
    Copy-Item (Join-Path $RepoRoot "config.example.toml") $ConfigFile
    Write-Host "wrote a starter config to $ConfigFile (see the comments in it -- every setting is optional)"
} else {
    Write-Host "kept your existing config at $ConfigFile (not overwritten)"
}

$userPath = [Environment]::GetEnvironmentVariable("Path", "User")
if ($userPath -notlike "*$BinDir*") {
    Write-Host ""
    Write-Host "note: $BinDir isn't on your user PATH yet. Add it (no elevation needed):"
    Write-Host "  [Environment]::SetEnvironmentVariable('Path', `"`$env:Path;$BinDir`", 'User')"
    Write-Host "then restart your terminal."
}

Write-Host ""
Write-Host "Done. Next: run 'blackhole-core enable' to turn on the kill switch"
Write-Host "(this will ask for elevation itself, when you run it -- not before)."
