#!/usr/bin/env python
# -*- coding: ascii -*-
"""Vocab-ATT&CK anchor lint (docs/08 P0.6).

Checks the three-layer chain signal-class <-> anchor table
(data/vocab-anchors.tsv) <-> vendored ATT&CK matrix:

L1  the anchor table lists exactly the SIGNAL_CLASSES vocabulary
    (no missing class, no extra class)
L2  every anchor id in the table still exists in the current matrix
    (revocation detector - caught ATT&CK v18 retiring T1488/T1562.x)
L3  every detectable case's technique is an anchor of at least one of its
    expected signal classes, or is on the explicit secondary-anchor list
    below (examples stay examples; secondary anchors are curated)

Usage:
    anchor_lint.py [corpus.yaml]      # defaults to corpus/qinjing.yaml
Exit 1 on any failure.
"""

import os
import re
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "tools"))
from parse import parse_corpus, SIGNAL_CLASSES  # noqa: E402

VOCAB_TABLE = os.path.join(ROOT, "data", "vocab-anchors.tsv")
MATRIX = os.path.join(ROOT, "data", "attack-enterprise.txt")

# Curated secondary anchors live in data/secondary-anchors.tsv (reviewable
# registry, one justification per pair).
SECONDARY_FILE = os.path.join(ROOT, "data", "secondary-anchors.tsv")


def load_secondary():
    pairs = set()
    for line in open(SECONDARY_FILE, encoding="utf-8"):
        if line.startswith("#") or not line.strip():
            continue
        parts = line.rstrip("\n").split("\t")
        if len(parts) >= 2:
            pairs.add((parts[0], parts[1]))
    return pairs


def load_table():
    """Anchor rows from data/vocab-anchors.tsv: one signal class per
    line, anchor technique ids in column 2 (see the header there)."""
    anchors = {}
    for line in open(VOCAB_TABLE, encoding="utf-8"):
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        cells = stripped.split("\t")
        if len(cells) < 2 or cells[0] not in SIGNAL_CLASSES:
            continue
        ids = re.findall(r"T\d{4}(?:\.\d{3})?", cells[1])
        if ids:
            anchors.setdefault(cells[0], set()).update(ids)
    return anchors


def load_matrix_ids():
    ids = set()
    for line in open(MATRIX, encoding="ascii"):
        if line.startswith("#") or not line.strip():
            continue
        ids.add(line.split("\t", 1)[0])
    return ids


def main(argv):
    corpus_path = argv[1] if len(argv) > 1 else os.path.join(
        ROOT, "corpus", "qinjing.yaml")
    problems = []

    table = load_table()
    matrix = load_matrix_ids()

    missing = sorted(SIGNAL_CLASSES - set(table))
    extra = sorted(set(table) - SIGNAL_CLASSES)
    if missing:
        problems.append("L1: classes missing from vocab-anchors table: %s"
                        % ", ".join(missing))
    if extra:
        problems.append("L1: table rows outside the vocabulary: %s"
                        % ", ".join(extra))
    if not missing and not extra:
        print("L1 ok: table lists all %d vocabulary classes" % len(table))

    revoked = sorted({tid for ids in table.values() for tid in ids
                      if tid not in matrix})
    if revoked:
        problems.append("L2: anchors revoked/absent from matrix: %s"
                        % ", ".join(revoked))
    else:
        print("L2 ok: all table anchors exist in the matrix")

    cases = parse_corpus(corpus_path)
    secondary = load_secondary()
    secondary_hits = set()
    for case in cases["attacks"]:
        if case.get("expect") != "detectable":
            continue
        tid = case.get("technique", "")
        expected = case.get("expected_signals", [])
        anchored = any(tid in table.get(klass, ()) for klass in expected)
        if not anchored:
            pair = None
            for klass in expected:
                if (klass, tid) in secondary:
                    pair = (klass, tid)
                    break
            if pair:
                secondary_hits.add(pair)
            else:
                problems.append(
                    "L3: %s technique %s is not an anchor of any expected"
                    " class %s" % (case["id"], tid, "/".join(expected)))
    unused = sorted(secondary - secondary_hits)
    if unused:
        problems.append("L3: registry pairs with no matching case: %s"
                        % ", ".join("%s/%s" % p for p in unused))
    print("L3 ok: %d detectable cases anchored (%d via secondary list)"
          % (sum(1 for c in cases["attacks"]
                 if c.get("expect") == "detectable"),
             len(secondary_hits)))

    for problem in problems:
        print("FAIL " + problem)
    print("anchor lint: %s" % ("FAILED" if problems else "OK"))
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
