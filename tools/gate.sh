#!/bin/bash
# qinjing local gate (owner decision 2026-11-17: CI runs on this machine,
# not on GitHub Actions). The checks every round must pass, in one command.
# Installed as a pre-push hook via .githooks (see AGENTS.md):
#   git config core.hooksPath .githooks
# Steps 1-3 are the zero-dependency Python toolchain; step 4 builds and tests
# the Go dashboard and needs a Go toolchain. Without Go, step 4 is
# loudly skipped (the dashboard DATA is still gated by the selftest in step 3).

set -u
ROOT=$(cd "$(dirname "$0")/.." && pwd)
cd "$ROOT"

fail=0

echo "== gate 1/4: corpus lint =="
python tools/parse.py --validate corpus/qinjing.yaml || fail=1

echo "== gate 2/4: stats =="
python tools/parse.py --stats corpus/qinjing.yaml || fail=1

echo "== gate 3/4: selftest =="
bash tests/selftest.sh || fail=1

echo "== gate 4/4: dashboard (Go build + vet + test) =="
if command -v go >/dev/null 2>&1; then
  (cd dashboard && go build ./... && go vet ./... && go test ./...) || fail=1
else
  echo "WARN: go not found - dashboard build/test SKIPPED (install Go to gate it)"
fi

if [ "$fail" -ne 0 ]; then
  echo "GATE FAILED"
  exit 1
fi
echo "GATE OK"
