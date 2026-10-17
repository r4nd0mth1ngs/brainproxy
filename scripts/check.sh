#!/usr/bin/env bash
# The checks CI runs. Use before every commit: scripts/check.sh && git commit ...
set -euo pipefail
cd "$(dirname "$0")/.."
cargo fmt --check
cargo clippy --all-targets -q -- -D warnings
cargo test -q 2>&1 | tee /tmp/brainproxy-test.log | grep -E "^test result" || true
! grep -qE "FAILED|panicked|^error" /tmp/brainproxy-test.log
echo "checks passed"
