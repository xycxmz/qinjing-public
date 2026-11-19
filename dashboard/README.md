# qinjing dashboard

A server-rendered (Go SSR MPA) dashboard for the **qinjing** HIDS evaluation
corpus. It shows the corpus's own **coverage capability** — what it tests and
how much of ATT&CK it covers — and provides a framework for **product scores**
once real-machine runs exist.

## Honesty premise (read this first)

Every number on the coverage pages is a measured property of the **corpus
itself**, derived from the zero-dependency Python toolchain. **No HIDS product
has been run on a real machine yet**, so there are no real product detection
scores. The `runs[]` array in `dashboard_data.json` is empty, and the
**Scores** page shows a "pending real-machine measurement" placeholder.

Synthetic data used to debug the score UI is always labelled
**`SYNTHETIC DEMO — not a real product result`** (red badge + red border) and
is never shipped in `dashboard_data.json`. A score is only real when it comes
from a real run's `scorer --out-json` report.

## Pages

| Route | Panel |
|---|---|
| `/` | Overview: totals, composition, provisioning summary |
| `/coverage` | ATT&CK tactic coverage (covered vs total techniques, cases) |
| `/matrix` | Technique heatmap (case-count overlay) + MITRE Navigator layer |
| `/classes` | Signal-class distribution (52 classes) |
| `/provisioning` | Reference-bench evaluability (52 / 14 / 21 disclosure) |
| `/scores` | Product scores framework (empty until a real run exists) |
| `/layer.json` | ATT&CK Navigator layer (load into Navigator) |
| `/data.json` | The raw dashboard data |

## Run

Requires a Go toolchain (1.26+). Standard library only — no third-party deps.

```sh
# 1. (Re)generate the data from the corpus (Python, zero-dependency):
python ../tools/gen_dashboard_data.py        # writes dashboard_data.json

# 2. Build and run:
go build -o dashboard .
./dashboard --addr 127.0.0.1:8090 --data dashboard_data.json
```

Then open <http://127.0.0.1:8090>.

## Data flow

```
corpus/qinjing.yaml ─┬─ parse.py            ─┐
data/attack-*.txt   ─┼─ attack_coverage.py  ─┼─> gen_dashboard_data.py ─> dashboard_data.json ─> Go dashboard
data/family-registry┘  gen_provisioning.py  ─┘                                                    (this module)
```

`dashboard_data.json` is **deterministic**: no timestamp, stable ordering, so
regeneration is byte-identical. The selftest gate asserts this and reconciles
the key numbers against `parse.py --stats`, coverage and provisioning. The
corpus sha256 + version + ATT&CK version fully identify the data.

## Test

```sh
go test ./...
```

The tests prove the score framework renders correctly and the honesty rules
hold: empty `runs[]` → placeholder (no badge); a synthetic run → labelled
`SYNTHETIC DEMO`; a real run → no badge; an INTERRUPTED run → disclosed as not
publishable; nullable rates render `N/A` (never coerced to 0%); and the
committed `dashboard_data.json` parses with empty runs.

## Hosting

Go SSR needs a server (not GitHub Pages). Deploy on a host like the other
qinjing services; the Go source ships with the public repository. The
"Open in MITRE Navigator" deep-link is constructed from the hosted
`/layer.json` URL at deploy time.