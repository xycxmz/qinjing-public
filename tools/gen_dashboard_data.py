#!/usr/bin/env python
# -*- coding: ascii -*-
"""Dashboard data generator (phase-1 coverage panels).

Aggregates the existing zero-dependency tools into one machine-readable
dashboard_data.json that the Go SSR dashboard renders:

    parse.py            -> totals / impact / mode / expect composition
    attack_coverage.py  -> tactic coverage + technique heatmap + Navigator layer
    gen_provisioning.py -> reference-bench evaluability disclosure

P2 adds the case catalog: a cases[] array (one row per
corpus case, cmd included) and per-class anchors + external counterparts, so
the dashboard can serve /cases and /case without touching the corpus again.

P1 adds the FP page data: a benign_distribution[] census
of the benign_ops_* subfamilies (from data/family-registry.tsv) and per-class
adapter_rules[] (from the xiezhi / wazuh mapping tables), so /fp can show the
benign corpus and /case can show an expected detection profile. Both are
corpus properties, not product scores; runs[] stays empty.

Honesty premise: this file describes the CORPUS's own
coverage capability, which is fully measured today. It carries no product
detection scores - those need real-machine runs (suspended) and live in the
empty runs[] array until then. No synthetic number is ever written here.

Deterministic by design: no wall-clock timestamp, stable ordering, so a
regeneration is byte-identical (the selftest gate asserts this, mirroring
data/provisioning.tsv). The corpus sha256 + version + attack_version fully
identify the data.

Public-safe by construction: cases[] cmd strings come from the linted corpus
(TEST-NET / example domains / /tmp/qinjing-* only), and a sensitive scan
(internal ranges, local repo paths, credential material) must find zero hits
before the file is written.

Usage:
    gen_dashboard_data.py [--corpus corpus/qinjing.yaml]
                          [--out dashboard/dashboard_data.json]
"""

import argparse
import hashlib
import json
import os
import re
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "tools"))
from parse import (parse_corpus, all_cases, SIGNAL_CLASSES,  # noqa: E402
                   MODE_VALUES, IMPACT_VALUES)
import attack_coverage  # noqa: E402
import gen_provisioning  # noqa: E402

ANCHORS_PATH = os.path.join(ROOT, "data", "vocab-anchors.tsv")
COUNTERPARTS_PATH = os.path.join(ROOT, "data", "class-counterparts.tsv")
REGISTRY_PATH = os.path.join(ROOT, "data", "family-registry.tsv")
ADAPTERS_DIR = os.path.join(ROOT, "adapters")

# Benign sub-family groups (owner decision 6 / docs/11 T3, mapping-notes
# section 34): FP01-FP56 group by operation form, FP57-FP121 by role persona.
# FP53 stays HOLD and occupies no number, so the form group holds 55 cases.
BENIGN_FORM_MAX = 56

# Public-safety scan: the dashboard is public, so the generated
# artifact must never carry an internal address, a local repo path, or real
# credential material. The corpus lint (parse.py cmd_hygiene_errors) already
# restricts cmd targets; this scan is the artifact-level backstop and also
# covers the class counterpart prose in data/class-counterparts.tsv.
INTERNAL_IP_RE = re.compile(
    r"(?<![\d.])(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}"
    r"|192\.168\.\d{1,3}\.\d{1,3}"
    r"|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3})(?![\d.])")
SENSITIVE_SUBSTRINGS = (
    "F:/", "H:/", "C:/", "F:\\", "H:\\", "C:\\",
    "/opensource", "qinjing-private", "Administrator",
)
# Credential material, not credential vocabulary: the corpus legitimately
# greps for AKIA / BEGIN.*PRIVATE / AWS_SECRET strings and writes sudoers
# NOPASSWD: /bin/bash lines, so the scan matches key-shaped values and
# secret assignments (value starts alphanumeric, never a path), not words.
CREDENTIAL_RES = (
    re.compile(r"AKIA[0-9A-Z]{16}"),
    re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----"),
    re.compile(r"(?i)(?:password|passwd|secret|token|api[_-]?key)"
               r"\s*[:=]\s*['\"]?[A-Za-z0-9][A-Za-z0-9/+_-]{7,}"),
)


def sensitive_hits(text):
    """Return every public-safety violation found in text (empty = safe)."""
    hits = ["internal IP %s" % m.group(0)
            for m in INTERNAL_IP_RE.finditer(text)]
    hits.extend("local path %s" % s for s in SENSITIVE_SUBSTRINGS if s in text)
    hits.extend("credential material %s" % r.pattern
                for r in CREDENTIAL_RES if r.search(text))
    return hits


def load_anchors(path):
    """class -> anchor technique ids (data/vocab-anchors.tsv, the same
    authority tools/anchor_lint.py reads)."""
    anchors = {}
    with open(path, encoding="ascii") as fh:
        for line in fh:
            if line.startswith("#") or not line.strip():
                continue
            parts = line.rstrip("\n").split("\t")
            if len(parts) >= 2:
                anchors[parts[0]] = parts[1].split()
    return anchors


def load_counterparts(path):
    """class -> external counterpart prose (data/class-counterparts.tsv,
    column 2; extracted verbatim from the schema doc's section 3 table).
    The registry is the human-read authority for what each signal class
    corresponds to in Sigma/Elastic/Wazuh."""
    counterparts = {}
    with open(path, encoding="utf-8") as fh:
        for line in fh:
            stripped = line.rstrip("\n")
            if not stripped or stripped.startswith("#"):
                continue
            parts = stripped.split("\t")
            if len(parts) >= 2 and parts[0] in SIGNAL_CLASSES:
                counterparts[parts[0]] = parts[1]
    return counterparts


def load_benign_distribution(path, by_id):
    """Benign sub-family census from the family registry's benign rows: one
    row per benign_ops_* subfamily with its group (form / persona), case count
    and up to three representative case ids (registry order, resolved against
    the catalog so every representative links to a real case). Sorted form
    group first, then by descending count, then by name (deterministic)."""
    subs = {}
    with open(path, encoding="ascii") as fh:
        for line in fh:
            if line.startswith("#") or not line.strip():
                continue
            parts = line.rstrip("\n").split("\t")
            if len(parts) < 3 or parts[2] != "benign":
                continue
            cid, sub = parts[0], parts[1]
            group = "form" if int(cid[2:]) <= BENIGN_FORM_MAX else "persona"
            subs.setdefault(sub, {"group": group, "ids": []})["ids"].append(cid)
    rows = []
    for sub, entry in subs.items():
        ids = entry["ids"]
        rows.append({
            "subfamily": sub, "group": entry["group"], "cases": len(ids),
            "examples": [cid for cid in ids[:3] if cid in by_id],
        })
    rows.sort(key=lambda r: (r["group"] != "form", -r["cases"], r["subfamily"]))
    return rows


def load_adapter_rules():
    """class -> [{adapter, rules, execve_classifiers}] from the two adapter
    mapping tables. xiezhi maps seed rule names to classes; wazuh maps native
    rule ids plus a count of execve argv classifiers. Only the count is
    published, not the regexes (those stay in the adapter source)."""
    with open(os.path.join(ADAPTERS_DIR, "xiezhi", "rule_map.json"),
              encoding="utf-8") as fh:
        xiezhi = json.load(fh)
    with open(os.path.join(ADAPTERS_DIR, "wazuh", "rule_map.json"),
              encoding="utf-8") as fh:
        wazuh = json.load(fh)
    with open(os.path.join(ADAPTERS_DIR, "wazuh", "execve_classify.json"),
              encoding="utf-8") as fh:
        execve = json.load(fh)
    xz_by, wz_by, ec_by = {}, {}, {}
    for rule, cls in xiezhi.items():
        xz_by.setdefault(cls, []).append(rule)
    for rule, cls in wazuh.items():
        wz_by.setdefault(cls, []).append(rule)
    for entry in execve:
        ec_by[entry["signal_class"]] = ec_by.get(entry["signal_class"], 0) + 1
    mappings = {}
    for cls in SIGNAL_CLASSES:
        mappings[cls] = [
            {"adapter": "xiezhi", "rules": sorted(xz_by.get(cls, [])),
             "execve_classifiers": 0},
            {"adapter": "wazuh", "rules": sorted(wz_by.get(cls, [])),
             "execve_classifiers": ec_by.get(cls, 0)},
        ]
    return mappings


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

    # Uncovered matrix techniques (gap -> contribution CTA): the
    # pinned matrix minus the covered heatmap, in stable id order.
    uncovered = [{"techniqueID": tid, "name": matrix[tid]["name"]}
                 for tid in sorted(matrix) if tid not in per_tech]

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
    anchors = load_anchors(ANCHORS_PATH)
    counterparts = load_counterparts(COUNTERPARTS_PATH)
    adapter_rules = load_adapter_rules()
    benign_distribution = load_benign_distribution(REGISTRY_PATH, by_id)
    class_distribution = []
    for klass in sorted(SIGNAL_CLASSES):
        members = [by_id[cid] for cid in membership.get(klass, [])
                   if cid in by_id]
        # P0 denominator transparency: split each class by expectation
        # and by execution mode. silent stays 0 (benign cases carry no signal
        # class); sim-missing-bin cases are NOT-RUN on a bare reference bench,
        # so the mode split discloses how much of the class is evaluable.
        expect_breakdown = {"detectable": 0, "gap": 0, "silent": 0}
        mode_breakdown = {name: 0 for name in MODE_VALUES}
        for c in members:
            if c.get("expect") in expect_breakdown:
                expect_breakdown[c["expect"]] += 1
            if c.get("mode") in mode_breakdown:
                mode_breakdown[c["mode"]] += 1
        class_distribution.append({
            "class": klass, "cases": len(members),
            "detectable": expect_breakdown["detectable"],
            "gap": expect_breakdown["gap"],
            "expect_breakdown": expect_breakdown,
            "mode_breakdown": mode_breakdown,
            "anchors": anchors.get(klass, []),
            "counterpart": counterparts.get(klass, ""),
            "adapter_rules": adapter_rules[klass],
        })

    # Case catalog: corpus file order (benign group first, then
    # attacks), one row per case. technique_name resolves through the pinned
    # matrix; NONE / unknown ids carry an empty name, never an invented one.
    case_rows = []
    for case in every:
        tid = case.get("technique", "")
        case_rows.append({
            "id": case["id"], "name": case.get("name", ""),
            "tactic": case.get("tactic", ""), "technique": tid,
            "technique_name": matrix[tid]["name"] if tid in matrix else "",
            "platforms": case.get("platforms", []),
            "mode": case.get("mode", ""), "bin": case.get("bin", ""),
            "expect": case.get("expect", ""),
            "expected_signals": case.get("expected_signals", []),
            "related_signals": case.get("related_signals", []),
            "impact": case.get("impact", ""),
            "bucket": case.get("bucket", "") or "",
            "cmd": case.get("cmd", ""),
            "creates_process": case.get("creates_process") == "true",
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
        "uncovered": uncovered,
        "class_distribution": class_distribution,
        "benign_distribution": benign_distribution,
        "cases": case_rows,
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
    text = json.dumps(data, indent=1) + "\n"
    hits = sensitive_hits(text)
    if hits:
        sys.stderr.write("sensitive scan FAILED (%d hit(s)):\n" % len(hits))
        for hit in hits:
            sys.stderr.write("  %s\n" % hit)
        return 1
    out_dir = os.path.dirname(os.path.abspath(args.out))
    if out_dir and not os.path.isdir(out_dir):
        os.makedirs(out_dir)
    with open(args.out, "w", encoding="ascii", newline="\n") as fh:
        fh.write(text)
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
    print("cases: %d catalog rows, sensitive scan clean" % len(data["cases"]))
    bd = data["benign_distribution"]
    form = sum(r["cases"] for r in bd if r["group"] == "form")
    persona = sum(r["cases"] for r in bd if r["group"] == "persona")
    print("benign distribution: %d subfamilies, %d cases (%d form + %d persona)"
          % (len(bd), form + persona, form, persona))
    print("uncovered: %d matrix techniques (gap contribution targets)"
          % len(data["uncovered"]))
    print("runs: %d (phase-2 placeholder; no real-machine run yet)"
          % len(data["runs"]))
    return 0


if __name__ == "__main__":
    sys.exit(main())
