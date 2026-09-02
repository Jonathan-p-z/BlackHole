#!/usr/bin/env sh
# One-time setup for a Linux CI VM (or a local Linux/WSL box) that's going
# to run blackhole-chaos. Not run automatically by anything — read it, then
# run it yourself, since it needs sudo. See ../README.md.
set -eu

if [ "$(id -u)" -eq 0 ]; then
    SUDO=""
else
    SUDO="sudo"
fi

echo "Installing blackhole-chaos prerequisites (nftables, iproute2, util-linux)..."
$SUDO apt-get update
$SUDO apt-get install -y nftables iproute2 util-linux

echo
echo "Checking what the test suite actually needs at runtime:"
for bin in nft ip setpriv kill; do
    if command -v "$bin" >/dev/null 2>&1; then
        echo "  ok: $bin -> $(command -v "$bin")"
    else
        echo "  MISSING: $bin (the suite will fail without it)" >&2
    fi
done

echo
echo "Done. Run the suite itself with: sudo -E ./run_chaos_tests.sh (from this directory)"
