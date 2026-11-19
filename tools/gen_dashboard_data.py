#!/usr/bin/env python
# -*- coding: ascii -*-
"""Dashboard data generator (phase-1 coverage panels).

Aggregates the existing zero-dependency tools into one machine-readable
dashboard_data.json that the Go SSR dashboard renders:

    parse.py            -> totals / impact / mode / expect composition
    attack_coverage.py  -> tactic coverage + technique heatmap + Navigator layer
    gen_provisioning.py -> reference-bench evaluability disclosure

Honesty premise: this file describes the CORPUS's own
coverage capability, which is fully measured today. It carries no product
detection scores - those need real-machine runs (suspended) and live in the
empty runs[] array until then. No synthetic number is ever written here.

Deterministic by design: no wall-clock timestamp, stable ordering, so a
regeneration is byte-identical (the selftest gate asserts this, mirroring
data/provisioning.tsv). The corpus sha256 + version + attack_version fully
identify the data.

Usage:
    gen_dashboard_data.py [--corpus corpus/qinjing.yaml]
                          [--out dashboard/dashboard_data.json]
"""

import argparse
import hashlib
import json
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "tools"))
from parse import (parse_corpus, all_cases, SIGNAL_CLASSES,  # noqa: E402
                   MODE_VALUES, IMPACT_VALUES)
import attack_coverage  # noqa: E402
import gen_provisioning  # noqa: E402


def file_sha256(path):
    with open(path, "rb") as fh:
        return hashlib.sha256(fh.read()).hexdigest()


def build(corpus_path, matrix_path, manifest_path):
    cases = parse_corpus(corpus_path)
    every = all_cases(cases)
    fps = cases["false_positives"]
    atks = cases["attacks"]
    with open(manifest_path, encoding="utf-8") as fh:
        manifest = json.load(fh)
    version, matrix = attack_coverage.load_matrix(matrix_path)
    per_tech = attack_coverage.collect(cases)

    impacts = {name: 0 for name in IMPACT_VALUES}
    modes = {name: 0 for name in MODE_VALUES}
    for case in every:
        if case.get("impact") in impacts:
            impacts[case["impact"]] += 1
        if case.get("mode") in modes:
            modes[case["mode"]] += 1
    attack_expect = {"detectable": 0, "gap": 0}
    for case in atks:
        if case.get("expect") in attack_expect:
            attack_expect[case["expect"]] += 1
    totals = {
        "cases": len(every), "fp": len(fps), "attack": len(atks),
        "classes": len(SIGNAL_CLASSES),
        "impact": impacts, "modes": modes, "attack_expect": attack_expect,
    }

    tactic_coverage = []
    for tactic in attack_coverage.TACTIC_ORDER:
        matrix_techs = {t for t, e in matrix.items() if tactic in e["tactics"]}
        covered = {t for t in per_tech if t in matrix_techs}
        case_count = sum(len(per_tech[t]["ids"]) for t in covered)
        tactic_coverage.append({
            "tactic": tactic, "covered": len(covered),
            "matrix_total": len(matrix_techs), "cases": case_count,
        })

    technique_heatmap = []
    for tid in sorted(per_tech):
        if tid not in matrix:
            continue
        entry = per_tech[tid]
        technique_heatmap.append({
            "techniqueID": tid, "name": matrix[tid]["name"],
            "score": len(entry["ids"]),
            "detectable": entry["detectable"], "gap": entry["gap"],
        })
    navigator_layer = attack_coverage.build_layer(per_tech, matrix, version)

    membership = gen_provisioning.load_class_membership()
    by_id = {c["id"]: c for c in every}
    # Gap cases (expected blind spots) carry no signal class and sit in the
    # gap_no_class family, outside the 52-class table. Disclose the count so
    # the class panel reconciles attack = in-class + no-class and never shows
    # a misleading all-zero gap column (honesty premise).
    in_class = set()
    for klass in SIGNAL_CLASSES:
        in_class.update(cid for cid in membership.get(klass, [])
                        if cid in by_id)
    totals["attack_no_class"] = sum(1 for c in atks if c["id"] not in in_class)
    class_distribution = []
    for klass in sorted(SIGNAL_CLASSES):
        members = [by_id[cid] for cid in membership.get(klass, [])
                   if cid in by_id]
        class_distribution.append({
            "class": klass, "cases": len(members),
            "detectable": sum(1 for c in members
                              if c.get("expect") == "detectable"),
            "gap": sum(1 for c in members if c.get("expect") == "gap"),
        })

    rows = gen_provisioning.build_rows(cases, membership)
    provisioning = {
        "corpus_classes": len(rows),
        "evaluable_ref": sum(1 for r in rows if r["evaluable"] == "yes"),
        "service_dep": sum(1 for r in rows if r["service"] == "yes"),
        "sim_only_classes": [r["class"] for r in rows
                             if r["sim_only"] == "yes"],
        "rows": [{
            "class": r["class"], "cases": r["cases"],
            "evaluable": r["evaluable"] == "yes",
            "service_dep": r["service"] == "yes",
            "sim_only": r["sim_only"] == "yes",
        } for r in rows],
    }

    meta = {
        "corpus_sha256": file_sha256(corpus_path),
        "version": manifest["version"],
        "calibre": manifest["scorer"]["calibre"],
        "attack_version": version.split()[0] if version[0].isdigit()
        else "master",
        "matrix_techniques": len(matrix),
        "techniques_covered": len(technique_heatmap),
        "generated_by": "tools/gen_dashboard_data.py",
    }

    return {
        "meta": meta,
        "totals": totals,
        "tactic_coverage": tactic_coverage,
        "technique_heatmap": technique_heatmap,
        "class_distribution": class_distribution,
        "provisioning": provisioning,
        "navigator_layer": navigator_layer,
        # Served by the Go dashboard at /layer.json; the "Open in MITRE
        # Navigator" deep-link is constructed from the hosted URL at deploy
        # time. Relative path keeps this artifact host-agnostic.
        "navigator_layer_url": "layer.json",
        # Phase 2: real-machine run results (scorer --out-json). Empty until
        # a real run exists; never filled with synthetic data.
        "runs": [],
    }


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--corpus", default=os.path.join(
        ROOT, "corpus", "qinjing.yaml"))
    ap.add_argument("--matrix", default=os.path.join(
        ROOT, "data", "attack-enterprise.txt"))
    ap.add_argument("--manifest", default=os.path.join(
        ROOT, "benchmark-manifest.json"))
    ap.add_argument("--out", default=os.path.join(
        ROOT, "dashboard", "dashboard_data.json"))
    args = ap.parse_args(argv)

    data = build(args.corpus, args.matrix, args.manifest)
    out_dir = os.path.dirname(os.path.abspath(args.out))
    if out_dir and not os.path.isdir(out_dir):
        os.makedirs(out_dir)
    with open(args.out, "w", encoding="ascii", newline="\n") as fh:
        json.dump(data, fh, indent=1)
        fh.write("\n")
    t = data["totals"]
    p = data["provisioning"]
    print("wrote %s" % args.out)
    print("totals: %d cases (%d fp, %d attack), %d classes"
          % (t["cases"], t["fp"], t["attack"], t["classes"]))
    print("coverage: %d/%d techniques, %d tactics"
          % (data["meta"]["techniques_covered"],
             data["meta"]["matrix_techniques"], len(data["tactic_coverage"])))
    print("provisioning: %d corpus / %d evaluable / %d service-dep"
          % (p["corpus_classes"], p["evaluable_ref"], p["service_dep"]))
    print("runs: %d (phase-2 placeholder; no real-machine run yet)"
          % len(data["runs"]))
    return 0


if __name__ == "__main__":
    sys.exit(main())