#!/usr/bin/env python
# -*- coding: ascii -*-
"""Observation-contract lint (C7).

data/observation-contract.tsv declares, per signal class, the telemetry
surface the class is measured on (the event_source vocabulary of the alert
schema).
The scorer limits a verdict to surfaces the run actually exported: a class
whose surface is absent scores NOT-MEASURED, not MISS. This lint keeps the
contract honest: exact 52-class coverage, tokens within the vocabulary, and
every declared non-execve surface actually exported by the reference adapter
(event_sources.json plus the implicit execve default).

Carrier model mirrors data/vocab-anchors.tsv / tools/anchor_lint.py: the TSV
is authoritative, zero corpus/parse.py changes.
"""

import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from parse import SIGNAL_CLASSES  # noqa: E402

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
TABLE = os.path.join(ROOT, "data", "observation-contract.tsv")
SURFACES = {"execve", "module_load", "bpf_load", "connect", "dns_query",
            "unstated"}


def load_table():
    table = {}
    with open(TABLE, encoding="ascii") as fh:
        for line in fh:
            s = line.strip()
            if not s or s.startswith("#"):
                continue
            cells = s.split("\t")
            if len(cells) >= 2:
                table[cells[0]] = cells[1]
    return table


def main():
    table = load_table()
    problems = []
    missing = sorted(SIGNAL_CLASSES - set(table))
    extra = sorted(set(table) - SIGNAL_CLASSES)
    if missing:
        problems.append("classes without contract: %s" % ", ".join(missing))
    if extra:
        problems.append("unknown classes: %s" % ", ".join(extra))
    for klass, surf in sorted(table.items()):
        if surf not in SURFACES:
            problems.append("%s: unknown surface %r" % (klass, surf))
    with open(os.path.join(ROOT, "adapters", "xiezhi",
                           "event_sources.json"), encoding="ascii") as fh:
        exported = set(json.load(fh).values()) | {"execve"}
    for klass, surf in sorted(table.items()):
        if surf != "execve" and surf not in exported:
            problems.append("%s: surface %s not exported by reference adapter"
                            % (klass, surf))
    if problems:
        for p in problems:
            print("FAIL " + p)
        return 1
    print("observation contract: %d/%d classes covered"
          % (len(table), len(SIGNAL_CLASSES)))
    print("surfaces ok; non-execve declared: %d"
          % sum(1 for v in table.values() if v != "execve"))
    return 0


if __name__ == "__main__":
    sys.exit(main())