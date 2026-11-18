#!/bin/bash
# qinjing local gate (owner decision 2026-11-17: CI runs on this machine,
# not on GitHub Actions). The three checks every round must pass, in one
# command. Installed as a pre-push hook via .githooks (see AGENTS.md):
#   git config core.hooksPath .githooks

set -u
ROOT=$(cd "$(dirname "$0")/.." && pwd)
cd "$ROOT"

fail=0

echo "== gate 1/3: corpus lint =="
python tools/parse.py --validate corpus/qinjing.yaml || fail=1

echo "== gate 2/3: stats =="
python tools/parse.py --stats corpus/qinjing.yaml || fail=1

echo "== gate 3/3: selftest =="
bash tests/selftest.sh || fail=1

if [ "$fail" -ne 0 ]; then
  echo "GATE FAILED"
  exit 1
fi
echo "GATE OK"
