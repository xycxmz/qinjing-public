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
| `/matrix` | Technique heatmap (case-count overlay) + MITRE Navigator layer + uncovered-technique contribution CTA + layer semantics legend |
| `/classes` | Signal-class distribution (52 classes, with anchors + external counterparts) |
| `/cases` | Case catalog (1076 cases): server-side tactic/mode/expect/platform filters, id/name/cmd search, 50-per-page pagination, filtered/total count |
| `/case?id=X` | Case detail, four sections: ATT&CK mapping → command & execution → expected/related signals (anchors + counterparts) → detection & contribution. gap/silent disclosed honestly; unknown id → 404 |
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

For the case catalog the generator also emits `cases[]` (one row
per corpus case, cmd included), `uncovered[]` (matrix techniques with no case,
the gap-contribution targets), and per-class `anchors` (from
`data/vocab-anchors.tsv`) + `counterpart` (the external Sigma/Elastic/Wazuh
correspondence from `data/class-counterparts.tsv`).

**Public safety**: the dashboard is public, so before writing the artifact the
generator runs a sensitive scan (RFC1918 addresses, local repo paths, credential
material) over the serialized bytes and fails loud on any hit. It targets real
secrets, not corpus vocabulary — `grep AKIA`, `BEGIN.*PRIVATE` and sudoers
`NOPASSWD: /bin/bash` lines are legitimate attack content and are excluded. The
selftest re-runs the scan on both the artifact and the served HTML pages.

## Test

```sh
go test ./...
```

The tests prove the score framework renders correctly and the honesty rules
hold: empty `runs[]` → placeholder (no badge); a synthetic run → labelled
`SYNTHETIC DEMO`; a real run → no badge; an INTERRUPTED run → disclosed as not
publishable; nullable rates render `N/A` (never coerced to 0%); and the
committed `dashboard_data.json` parses with empty runs.

The P2 tests prove the catalog and detail behavior through the real mux: the
filter contract (each constraint, combined, empty = exact zero), pagination
boundaries + over-range clamp, catalog counts (1076 / 21 gap / 120 benign),
case-insensitive search, the four detail sections (ATT&CK link, cmd, signal
anchors + counterpart, contribution), gap/silent disclosure, unknown-id 404,
the matrix uncovered-technique CTA + Navigator legend, and uncovered
reconciliation (625, covered + uncovered = 706, disjoint). The selftest
additionally renders these pages over HTTP and scans the served bytes.

## Hosting

Go SSR needs a server (not GitHub Pages). Deploy on a host like the other
qinjing services; the Go source ships with the public repository. The
"Open in MITRE Navigator" deep-link is constructed from the hosted
`/layer.json` URL at deploy time.