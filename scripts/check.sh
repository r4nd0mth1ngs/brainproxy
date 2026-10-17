#!/usr/bin/env bash
# The checks CI runs. Use before every commit: scripts/check.sh && git commit ...
set -euo pipefail
cd "$(dirname "$0")/.."
cargo fmt --check
cargo clippy --all-targets -q -- -D warnings
cargo test -q 2>&1 | tee /tmp/brainproxy-test.log | grep -E "^test result" || true
# (`! grep` would not stop the script: set -e ignores negated commands.)
if grep -qE "FAILED|panicked|^error" /tmp/brainproxy-test.log; then
    echo "tests failed (see /tmp/brainproxy-test.log)" >&2
    exit 1
fi
echo "checks passed"
