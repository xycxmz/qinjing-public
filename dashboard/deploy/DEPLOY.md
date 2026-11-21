# Deploying the qinjing dashboard publicly

Repo-side preparation only. **Actual deployment is an infrastructure change and
requires explicit owner authorization and a chosen host/port.** These artifacts
make the service safe to expose; they do not deploy anything.

The dashboard is read-only and serves only public corpus-coverage data
(`dashboard_data.json`, `runs[]` empty). It must never serve synthetic demo data
or real product scores without access control (see GOVERNANCE.md).

## Pre-public checklist

1. TLS + reverse proxy (Caddy/nginx). Keep Go bound to 127.0.0.1; do not expose
   it directly. Caddyfile here gives auto-HTTPS + gzip.
2. Linux binary + service manager (systemd unit or Dockerfile here), restart on
   failure, graceful shutdown (SIGINT/SIGTERM drain; SIGHUP hot-reloads data).
3. Data refresh pipeline: `refresh-data.sh` regenerates from the corpus and
   signals SIGHUP. Wire it to corpus updates / CI.
4. Compliance footer already links LICENSE / NOTICE / GOVERNANCE on the public
   repo; keep it. Run the sensitive scan over what will be served before going
   live (data + binary are derived from the public corpus and are clean).
5. Choose host/port that does not conflict with other services on a shared
   machine; do not disturb unrelated projects.

## Build (linux)

```sh
sh deploy/build-linux.sh        # -> deploy/qinjing-dashboard-linux (gitignored)
```

## systemd

```sh
# useradd -r qinjing; mkdir -p /opt/qinjing/dashboard
# copy qinjing-dashboard-linux + dashboard_data.json there
cp deploy/qinjing-dashboard.service /etc/systemd/system/
systemctl daemon-reload && systemctl enable --now qinjing-dashboard
systemctl reload qinjing-dashboard   # after refresh-data.sh
```

## Docker

```sh
cd dashboard
docker build -f deploy/Dockerfile -t qinjing-dashboard .
docker run -d -p 127.0.0.1:8090:8090 qinjing-dashboard
```

## Refresh

```sh
sh deploy/refresh-data.sh   # regen + SIGHUP (systemctl reload)
```

## Hardening already in the binary

Security headers (CSP script-src 'none', nosniff, DENY frames, no-referrer),
read/write/idle timeouts, graceful shutdown, static long-cache + data no-cache.
Add rate limiting and access logs at the proxy. If real product scores are ever
shown, add authentication first.