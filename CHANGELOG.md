# Changelog

## 2026.11.1 (2026-11-20)

Coverage dashboard and corpus dedup rework. Case count, class count, and
the evaluability disclosure are unchanged (1075 cases / 52 classes /
14 effectively evaluable classes); the corpus sha256 changed with the
rework (6688605d…).

### Added
- `dashboard/`: self-contained Go SSR MPA (coverage, tactic, technique,
  class, and provisioning pages plus a scores placeholder pending
  real-machine runs). `runs[]` ships empty; no synthetic numbers.
- `tools/gen_dashboard_data.py`: deterministic aggregation into
  `dashboard/dashboard_data.json`, schema-gated and byte-identical on
  rerun.
- `tools/dedup.py`: normalized near-duplicate audit caliber (placeholder
  collapse, quoted-string skeleton, intra-class Jaccard) now wired into
  the variant generators.
- `scorer --out-json`: machine-readable report, reconciled by the
  selftest.
- `tools/gate.sh` step 4: Go build, vet, and test for the dashboard
  (loudly skipped without a Go 1.26+ toolchain).

### Changed
- T4 corpus rework: 14 cases reshaped to remove exact-command and
  near-duplicate clusters (timestomp five-case set heterogeneous; seven
  generated exact-duplicate groups cleared). Selftest cleanup literal
  count 85 to 87.

## 2026.11 (2026-11-18)

Initial corpus release with 1075 cases (120 benign + 955 attack).

### Corpus growth
- Base: 108 hand-authored cases (FP01-FP15 + R/E/P/V/D/C/S/L/A/X/M/I/CA-CB-CC/DN series)
- Grok proposal merge: +17 cases (FP16-34 + attack second variants)
- Codex R3 benign merge: +7 cases (FP35-43)
- Variant wave 1 (gen_variants.py): 440 cases across 42 classes
- Variant wave 2 (gen_wave2.py): 102 cases across 18 high-yield classes
- ART import (import_art.py): 80 cases from redcanaryco/atomic-red-team
- Vocabulary expansion r2: 120 cases across 10 new classes
- Variant wave 3 (gen_wave3.py): 52 cases targeting thin classes
- Handwritten new shapes: 12 cases (HW01-12)
- Benign expansion r2: 65 cases (FP57-FP121) across 10 host profiles
- TA0008 lateral-movement round: +2 cases (LT03-LT04, merge-check flow)
  and 3 technique re-tags with matrix-truth backing (VR330/VR331/VR333);
  TA0008 matrix-calibre detectable cases 0 -> 5

### Calibre evolution
- v1: signal-class primary + any-hit fallback (dual column)
- v2: sim-builtin cases enter denominator (owner decision 2026-11-16)
- v2.1: fp-evaluable tier added (benign NOT-RUN exclusion)
- v2.2: two-tier FP denominator (verified + attempt, owner decision 2026-11-18)

### Signal class vocabulary
- Started at 37 classes (xiezhi-derived)
- Expanded to 52 through governance rounds with evidence-based class opening
- Rejected: nfs_taint (no mapping evidence), mail persistence (no clean ATT&CK anchor)

### Toolchain
- tools/parse.py: corpus lint (incl. duplicate-cmd registry gate) + TSV export + stats + cleanup export
- tools/runner.sh: uid-isolated execution with fail-stop, flock, dry-run
- tools/scorer.py: dual-calibre scoring with per-class aggregation, G3 tech-tag, G4 latency
- tools/fpcheck_tight.py: tight-window FP audit with cross-talk discrimination
- tools/gen_variants.py / gen_wave2.py / gen_wave3.py: variant generators
- tools/import_art.py: Atomic Red Team import pipeline
- tools/merge_check.py: proposal merge gate
- tools/adapter_check.py: adapter acceptance layer (O1-O8, A01-A11)
- tools/attack_coverage.py: ATT&CK coverage report + Navigator layer
- tools/anchor_lint.py: vocabulary-technique-matrix three-way check
- tools/family_check.py: family-based split validator

### Infrastructure
- .githooks/pre-push: local CI gate (owner decision: no GitHub Actions)
- benchmark-manifest.json: frozen release identity
- data/attack-enterprise.txt: vendored ATT&CK matrix (attack-stix-data tag v20.1, MITRE custom license - see NOTICE)
- data/secondary-anchors.tsv: curated secondary anchor registry
- data/family-registry.tsv: case family mapping for split validation
  (benign_ops split into 20 role/bin sub-families; hash-order two-pool
  split fill: public 896 / holdout 179 = 16.7%, benign pool 88/32)
- tools/gen_provisioning.py + data/provisioning.tsv: target-host
  provisioning manifest; dual disclosure 52 corpus-level classes /
  14 evaluable on the bare reference bench / 21 service-dependent
