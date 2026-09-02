#!/usr/bin/env sh
# BlackHole installer (Linux/macOS). Builds the workspace from source and
# installs the resulting binaries + a starter config for the current user
# only — no root/sudo, ever, for this script. Read it before piping it
# into a shell; it's deliberately short so that's quick to do.
#
# Usage: run from inside a clone of this repo:
#   ./install.sh
#
# Once this project has public GitHub releases, `curl -sSf <url> | sh`
# will be documented in README.md — not yet, since no such release exists
# to fetch (see README's "Installation rapide" section for the current
# state of that).
set -eu

BIN_DIR="${HOME}/.local/bin"
CONFIG_DIR="${HOME}/.config/blackhole"
CONFIG_FILE="${CONFIG_DIR}/config.toml"

echo "This installs BlackHole for the current user only: compiles the workspace"
echo "with 'cargo build --release', copies the binaries to $BIN_DIR, and drops a"
echo "commented starter config at $CONFIG_FILE if none exists yet. No root/sudo"
echo "is used at any point; nothing outside your home directory is touched."
echo

if ! command -v cargo >/dev/null 2>&1; then
    echo "error: cargo not found." >&2
    echo "BlackHole is built from source; install Rust first via https://rustup.rs" >&2
    echo "(this script won't do that for you, so you can see exactly what runs)." >&2
    exit 1
fi

repo_root="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"
cd "$repo_root"

echo "Building (this can take a while on first run)..."
cargo build --release --workspace --bins

mkdir -p "$BIN_DIR"
for bin in blackhole-core blackhole-dns blackhole-dashboard blackhole-fingerprint; do
    src="target/release/$bin"
    if [ -f "$src" ]; then
        cp "$src" "$BIN_DIR/$bin"
        echo "installed $BIN_DIR/$bin"
    fi
done

if [ ! -f "$CONFIG_FILE" ]; then
    mkdir -p "$CONFIG_DIR"
    cp "$repo_root/config.example.toml" "$CONFIG_FILE"
    echo "wrote a starter config to $CONFIG_FILE (see the comments in it — every setting is optional)"
else
    echo "kept your existing config at $CONFIG_FILE (not overwritten)"
fi

case ":$PATH:" in
    *":$BIN_DIR:"*) ;;
    *) echo
       echo "note: $BIN_DIR isn't on your PATH yet. Add this to your shell profile:"
       echo "  export PATH=\"$BIN_DIR:\$PATH\""
       ;;
esac

echo
echo "Done. Next: run 'blackhole-core enable' to turn on the kill switch"
echo "(this will ask for elevation itself, when you run it — not before)."
