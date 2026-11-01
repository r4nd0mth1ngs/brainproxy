#!/usr/bin/env bash
# The checks CI runs. Use before every commit: scripts/check.sh && git commit ...
set -euo pipefail
cd "$(dirname "$0")/.."
cargo fmt --check
cargo clippy --all-targets -q -- -D warnings
log=$(mktemp "${TMPDIR:-/tmp}/brainproxy-test.XXXXXX")
cargo test -q 2>&1 | tee "$log" | grep -E "^test result" || true
# (`! grep` would not stop the script: set -e ignores negated commands.)
if grep -qE "FAILED|panicked|^error" "$log"; then
    echo "tests failed (see $log)" >&2
    exit 1
fi
python3 -q scripts/test_zap_drift.py
echo "checks passed"
