#!/usr/bin/env python
# -*- coding: ascii -*-
"""Merge gate for corpus proposals (AGENTS.md review flow, docs/06 spirit).

Splices selected cases from a proposal file into a COPY of the corpus and
runs the full validate gate on that copy. The main corpus is never touched;
what lands where stays a human decision made on green output.

Usage:
    merge_check.py corpus.yaml proposal.yaml --out merged.yaml [--ids A,B]

Without --ids every proposal case is taken. Splice rules (verbatim text
blocks, the HANDOFF-ZCODE discipline): benign blocks append at the end of
false_positives; attack blocks append at end of file in --ids order. Exits
0 only when the merged copy validates, no id collides, and every requested
id existed in the proposal. Also prints the single-class delta so thin-class
effects show before the merge decision.
"""

import argparse
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from parse import parse_lines, validate  # noqa: E402


def blocks(lines):
    """Ordered [(id, section, text-lines)] for one corpus-format file."""
    found = []
    section = None
    current = None
    for line in lines:
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        if not line[:1].isspace() and stripped.endswith(":"):
            if current is not None:
                found.append(current)
                current = None
            section = stripped[:-1]
            continue
        if line.startswith("  - id:"):
            if current is not None:
                found.append(current)
            current = [stripped[5:].strip(), section, [line]]
        elif current is not None:
            current[2].append(line)
    if current is not None:
        found.append(current)
    return found


def single_class_count(cases):
    counts = {}
    for section in ("false_positives", "attacks"):
        for case in cases[section]:
            for signal in case.get("expected_signals", []):
                counts.setdefault(signal, []).append(case["id"])
    return sum(1 for ids in counts.values() if len(ids) == 1)


def main(argv=None):
    ap = argparse.ArgumentParser(description="corpus proposal merge gate")
    ap.add_argument("corpus")
    ap.add_argument("proposal")
    ap.add_argument("--out", required=True,
                    help="where to write the merged copy (never the corpus)")
    ap.add_argument("--ids", default=None,
                    help="comma-separated case ids to take (default: all)")
    args = ap.parse_args(argv)

    if os.path.abspath(args.out) == os.path.abspath(args.corpus):
        sys.stderr.write("refusing to overwrite the corpus itself\n")
        return 2

    corpus_lines = open(args.corpus, encoding="ascii").read().splitlines(True)
    proposal_blocks = blocks(open(args.proposal, encoding="ascii")
                             .read().splitlines(True))
    corpus_ids = {cid for cid, _, _ in blocks(corpus_lines)}

    wanted = [part.strip() for part in args.ids.split(",")] \
        if args.ids else [cid for cid, _, _ in proposal_blocks]
    picked = {cid: (sec, text) for cid, sec, text in proposal_blocks
              if cid in set(wanted)}
    missing = [cid for cid in wanted if cid not in picked]
    if missing:
        sys.stderr.write("proposal lacks requested ids: %s\n"
                         % ", ".join(missing))
        return 1
    clash = [cid for cid in wanted if cid in corpus_ids]
    if clash:
        sys.stderr.write("ids already in the corpus: %s\n" % ", ".join(clash))
        return 1

    fp_blocks = [text for cid, (sec, text) in picked.items()
                 if sec == "false_positives"]
    attack_order = [cid for cid in wanted
                    if picked[cid][0] == "attacks"]

    out = []
    for line in corpus_lines:
        if line.rstrip() == "attacks:" and fp_blocks:
            for text in fp_blocks:
                out.append("\n")
                out.extend(text)
            out.append("\n")
        out.append(line)
    for cid in attack_order:
        out.extend(picked[cid][1])
    merged = "".join(out)

    with open(args.out, "w", encoding="ascii", newline="\n") as fh:
        fh.write(merged)

    before = single_class_count(parse_lines(corpus_lines))
    cases = parse_lines(merged.splitlines())
    errors = validate(cases)
    for error in errors:
        sys.stderr.write("%s\n" % error)
    if errors:
        sys.stderr.write("merged copy FAILED validate; nothing merged\n")
        return 1
    after = single_class_count(cases)
    print("merged: %d cases (%d fp, %d attack)"
          % (len(cases["false_positives"]) + len(cases["attacks"]),
             len(cases["false_positives"]), len(cases["attacks"])))
    print("single-class count: %d -> %d" % (before, after))
    print("validate: OK (copy at %s; corpus untouched)" % args.out)
    return 0


if __name__ == "__main__":
    sys.exit(main())
