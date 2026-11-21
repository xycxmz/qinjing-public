#!/bin/sh
# Regenerate dashboard data from the corpus, then hot-reload the running
# service (SIGHUP). Run on the host after a corpus update, or from CI.
# The data file is deterministic; regeneration is byte-identical for the same
# corpus, so a no-change refresh is a no-op reload.
set -eu
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
python3 "$ROOT/tools/gen_dashboard_data.py" \
  --out "$ROOT/dashboard/dashboard_data.json"

# Prefer systemd reload (ExecReload sends SIGHUP). Fallback: signal the binary.
if command -v systemctl >/dev/null 2>&1; then
  systemctl reload qinjing-dashboard
else
  pid="$(pgrep -x qinjing-dashboard-linux || true)"
  [ -n "$pid" ] && kill -HUP "$pid"
fi
echo "data refreshed and reload signalled"