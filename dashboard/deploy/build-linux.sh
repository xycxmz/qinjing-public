#!/bin/sh
# Cross-compile the dashboard for linux/amd64. Pure stdlib, CGO off, so this
# works from any host (incl. Windows/MSYS). Output is a deploy artifact and is
# gitignored; commit the script, not the binary.
set -eu
cd "$(dirname "$0")/.."
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -ldflags "-s -w" \
  -o deploy/qinjing-dashboard-linux .
echo "built deploy/qinjing-dashboard-linux"