#!/usr/bin/env python
# -*- coding: ascii -*-
"""ATT&CK matrix coverage report for a qinjing corpus.

Usage:
    attack_coverage.py corpus.yaml [--matrix data/attack-enterprise.txt]
                   [--out-md coverage.md] [--out-layer coverage.json]
                   [--strict]

Coverage counts ATTACK-group cases per technique (benign cases carry no
technique). A technique is covered when at least one attack case cites it;
the per-technique score splits detectable vs gap cases. Also checks that
every cited technique id exists in the vendored matrix (unknown ids are
loud; --strict makes them fatal) and warns when a case's tactic is not one
of the technique's matrix tactics (informational - the tag is a hint, not
an engine key; known deliberate mismatches are recorded in mapping-notes).

--out-layer writes an ATT&CK Navigator layer (score = case count) that can
be loaded at https://mitre-attack.github.io/attack-navigator/ to see the
corpus overlaid on the matrix.
"""

import argparse
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from parse import parse_corpus  # noqa: E402

TACTIC_ORDER = ["TA0043", "TA0042", "TA0001", "TA0002", "TA0003",
                "TA0004", "TA0005", "TA0112", "TA0006", "TA0007",
                "TA0008", "TA0009", "TA0011", "TA0010", "TA0040"]


def load_matrix(path):
    techniques = {}
    version = "unknown"
    with open(path, encoding="ascii") as fh:
        for line in fh:
            if line.startswith("#"):
                if "ATT&CK" in line:
                    version = line.split("ATT&CK", 1)[1].strip(". \n")
                continue
            parts = line.rstrip("\n").split("\t")
            if len(parts) != 3:
                continue
            tid, tactic, name = parts
            entry = techniques.setdefault(tid, {"tactics": set(), "name": name})
            entry["tactics"].add(tactic)
    return version, techniques


def collect(cases):
    per_tech = {}
    for case in cases["attacks"]:
        tid = case.get("technique", "")
        if tid in ("", "NONE"):
            continue
        entry = per_tech.setdefault(tid, {"ids": [], "detectable": 0, "gap": 0})
        entry["ids"].append(case["id"])
        entry["detectable" if case.get("expect") == "detectable" else "gap"] += 1
    return per_tech


def main(argv=None):
    ap = argparse.ArgumentParser(description="ATT&CK coverage report")
    ap.add_argument("corpus")
    ap.add_argument("--matrix",
                    default=os.path.join(os.path.dirname(os.path.dirname(
                        os.path.abspath(__file__))), "data",
                        "attack-enterprise.txt"))
    ap.add_argument("--out-md", default=None)
    ap.add_argument("--out-layer", default=None)
    ap.add_argument("--strict", action="store_true",
                    help="exit 1 on unknown technique ids")
    args = ap.parse_args(argv)

    version, matrix = load_matrix(args.matrix)
    cases = parse_corpus(args.corpus)
    per_tech = collect(cases)

    unknown = sorted(t for t in per_tech if t not in matrix)
    mismatches = []
    for tid, entry in sorted(per_tech.items()):
        if tid not in matrix:
            continue
        for case in cases["attacks"]:
            if case.get("technique") == tid and \
                    case.get("tactic") not in matrix[tid]["tactics"]:
                mismatches.append("%s: %s tagged %s, matrix says %s"
                                  % (case["id"], tid, case["tactic"],
                                     "/".join(sorted(matrix[tid]["tactics"]))))

    tactic_rows = []
    for tactic in TACTIC_ORDER:
        matrix_techs = {t for t, e in matrix.items() if tactic in e["tactics"]}
        covered = {t for t in per_tech if t in matrix_techs}
        case_count = sum(len(per_tech[t]["ids"]) for t in covered)
        tactic_rows.append((tactic, len(matrix_techs), len(covered), case_count))

    covered_total = len([t for t in per_tech if t in matrix])
    print("corpus: %d attack cases citing %d techniques; matrix has %d"
          % (sum(len(e["ids"]) for e in per_tech.values()),
             len(per_tech), len(matrix)))
    print("techniques covered: %d (%.1f%% of matrix)" % (
        covered_total,
        100.0 * covered_total / len(matrix) if matrix else 0.0))
    print("unknown technique ids: %d%s"
          % (len(unknown), (" " + ", ".join(unknown)) if unknown else ""))
    print("tactic mismatches: %d%s"
          % (len(mismatches), (" e.g. " + mismatches[0]) if mismatches else ""))
    for tactic, total, covered, case_count in tactic_rows:
        print("  %s  %3d/%3d techniques  %3d cases" % (tactic, covered, total,
                                                       case_count))

    if args.out_md:
        with open(args.out_md, "w", encoding="utf-8", newline="\n") as fh:
            w = fh.write
            w("# ATT&CK coverage report\n\n")
            w("- corpus: `%s`\n- matrix: %s (ATT&CK %s)\n" %
              (args.corpus, args.matrix, version))
            w("- covered %d/%d matrix techniques; %d unknown ids; %d tactic"
              " mismatches\n" % (covered_total, len(matrix), len(unknown),
                                 len(mismatches)))
            w("\n| Tactic | Covered | Matrix | Cases |\n|---|---|---|---|\n")
            for tactic, total, covered, case_count in tactic_rows:
                w("| %s | %d | %d | %d |\n" % (tactic, covered, total,
                                                case_count))
            w("\n| Technique | Name | Cases | Detectable | Gap |\n")
            w("|---|---|---|---|---|\n")
            for tid in sorted(per_tech):
                entry = per_tech[tid]
                name = matrix[tid]["name"] if tid in matrix else "UNKNOWN ID"
                w("| %s | %s | %s | %d | %d |\n" % (
                    tid, name, ",".join(entry["ids"]),
                    entry["detectable"], entry["gap"]))
            if mismatches:
                w("\n## Tactic mismatches (informational)\n\n")
                for line in mismatches:
                    w("- %s\n" % line)
        print("wrote %s" % args.out_md)

    if args.out_layer:
        layer = {
            "name": "qinjing corpus coverage",
            "versions": {"attack": version.split()[0] if version[0].isdigit()
                         else "master", "navigator": "5.0.0", "layer": "22.1"},
            "domain": "enterprise-attack",
            "description": "Case-count overlay generated by"
                           " tools/attack_coverage.py; scores are the number"
                           " of corpus attack cases per technique.",
            "techniques": [
                {"techniqueID": tid, "score": len(entry["ids"]),
                 "comment": "cases: %s (detectable %d / gap %d)"
                            % (",".join(entry["ids"]), entry["detectable"],
                               entry["gap"])}
                for tid, entry in sorted(per_tech.items()) if tid in matrix],
            "gradient": [
                {"color": "#66b3ff", "minValue": 1, "maxValue": 2},
                {"color": "#1a7f37", "minValue": 3, "maxValue": 5},
                {"color": "#8b1e1e", "minValue": 6, "maxValue": 10}],
            "legendItems": [
                {"label": "1-2 cases", "color": "#66b3ff"},
                {"label": "3-5 cases", "color": "#1a7f37"},
                {"label": "6+ cases", "color": "#8b1e1e"}],
        }
        with open(args.out_layer, "w", encoding="ascii", errors="replace",
                  newline="\n") as fh:
            json.dump(layer, fh, indent=1)
            fh.write("\n")
        print("wrote %s (%d techniques)" % (args.out_layer,
                                            len(layer["techniques"])))

    if unknown and args.strict:
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
