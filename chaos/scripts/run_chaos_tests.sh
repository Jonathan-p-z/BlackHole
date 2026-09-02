#!/usr/bin/env sh
# Runs the full blackhole-chaos suite. Must run as root (network
# namespaces, nftables, setuid probes all need it — see
# blackhole_chaos::require_root, which panics with a clear message instead
# of failing confusingly deep into a test if this is skipped).
#
# Usage (from anywhere):
#   sudo -E ./chaos/scripts/run_chaos_tests.sh
#
# -E preserves your normal PATH/cargo env under sudo; without it, `cargo`
# as root often isn't found unless installed system-wide.
set -eu

script_dir="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"
repo_root="$(CDPATH= cd -- "$script_dir/../.." && pwd)"

if [ "$(id -u)" -ne 0 ]; then
    echo "error: must run as root (sudo -E $0)." >&2
    exit 1
fi

for bin in nft ip setpriv; do
    if ! command -v "$bin" >/dev/null 2>&1; then
        echo "error: '$bin' not found — run ./install_prereqs.sh first." >&2
        exit 1
    fi
done

echo "Building the real blackhole-core/blackhole-dns binaries the chaos" \
     "tests exercise directly (scenario 2 and 4)..."
(cd "$repo_root" && cargo build --release -p blackhole-core -p blackhole-dns --bins)

echo
echo "Running the chaos suite (chaos/ is its own standalone workspace, same" \
     "reason as fuzz/ — see chaos/Cargo.toml)..."
# --test-threads=1: each scenario creates its own network namespace and
# uses a unique subnet/id, so this isn't strictly required for correctness,
# but serializing them keeps failures easy to read and avoids piling up
# multiple root-owned namespaces mid-debug if something goes wrong.
(cd "$script_dir/.." && cargo test --release -- --test-threads=1 --nocapture)

echo
echo "All scenarios passed."
