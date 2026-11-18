#!/usr/bin/env python
# -*- coding: ascii -*-
"""Family-based split validator (G6+G8).

Reads data/family-registry.tsv and validates that a proposed public/holdout
split doesn't leak families across sets. Also reports family distribution
and sample independence metrics.

Usage:
    family_check.py [--holdout-pct 15] [--split-file split.tsv]

A split file (optional) maps case_id to "public" or "holdout". Without
one, a deterministic hash-based split is generated for inspection.
"""

import argparse
import hashlib
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
REGISTRY = os.path.join(ROOT, "data", "family-registry.tsv")

# docs/11 T3 acceptance: each split side needs >=30 benign cases so both
# FP rates are computable and not one-case-flukes (minimum denominator).
BENIGN_HOLDOUT_MIN = 30


def load_registry():
    entries = []
    for line in open(REGISTRY, encoding="ascii"):
        if line.startswith("#") or not line.strip():
            continue
        parts = line.rstrip("\n").split("\t")
        if len(parts) >= 3:
            entries.append({
                "id": parts[0], "family": parts[1],
                "source": parts[2],
                "pair": parts[3] if len(parts) > 3 else "-",
            })
    return entries


def deterministic_split(entries, holdout_pct):
    """Hash-ordered whole-family fill per pool (docs/11 T3 rebalance).

    Same-family cases never split across sets. Families are ordered by
    (sha256(name), name) inside each pool - benign (source=benign) vs
    attack - and taken whole into the holdout side until the pool target
    is reached: holdout_pct of pool cases for the attack pool, and for
    the benign pool at least the T3 minimum denominator (both sides need
    >=30 benign cases for FP-rate maths; 15% of 120 benign cases is 18,
    below that floor). This replaces the per-family hash threshold,
    whose family granularity put the whole benign face on one side
    (benign public=0 holdout=120) and left the overall share at 23.9%.
    """
    pools = {"benign": {}, "attack": {}}
    for e in entries:
        fam_map = pools["benign" if e["source"] == "benign" else "attack"]
        fam_map.setdefault(e["family"], []).append(e["id"])
    holdout_families = set()
    for pool in sorted(pools):
        fam_map = pools[pool]
        total = sum(len(ids) for ids in fam_map.values())
        target = int(total * holdout_pct / 100)
        if pool == "benign" and target < BENIGN_HOLDOUT_MIN:
            target = BENIGN_HOLDOUT_MIN
        taken = 0
        for fam in sorted(fam_map,
                          key=lambda f: (hashlib.sha256(
                              f.encode()).hexdigest(), f)):
            if taken >= target:
                break
            holdout_families.add(fam)
            taken += len(fam_map[fam])
    family_set = {}
    for fam_map in pools.values():
        for fam, ids in fam_map.items():
            family_set.setdefault(fam, []).extend(ids)
    return holdout_families, family_set


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--holdout-pct", type=int, default=15)
    ap.add_argument("--split-file", default=None)
    ap.add_argument("--regen", action="store_true",
                    help="regenerate family-registry.tsv from corpus")
    args = ap.parse_args()

    entries = load_registry()
    if not entries:
        print("ERROR: registry empty")
        return 1

    if args.split_file:
        assignments = {}
        for line in open(args.split_file, encoding="ascii"):
            parts = line.strip().split("\t")
            if len(parts) == 2:
                assignments[parts[0]] = parts[1]
        public = [e for e in entries if assignments.get(e["id"]) == "public"]
        holdout = [e for e in entries if assignments.get(e["id"]) == "holdout"]
    else:
        holdout_fams, fam_map = deterministic_split(entries, args.holdout_pct)
        holdout_ids = set()
        for fam in holdout_fams:
            holdout_ids.update(fam_map[fam])
        public = [e for e in entries if e["id"] not in holdout_ids]
        holdout = [e for e in entries if e["id"] in holdout_ids]

    # Validate: no family in both sets
    pub_fams = set(e["family"] for e in public)
    hold_fams = set(e["family"] for e in holdout)
    leaks = pub_fams & hold_fams
    if leaks:
        print("VIOLATION: %d families appear in both sets:" % len(leaks))
        for f in sorted(leaks):
            print("  %s" % f)
        return 1

    # Report
    total = len(entries)
    print("Family split report (%d%% holdout target)" % args.holdout_pct)
    print("  total cases: %d" % total)
    print("  total families: %d" % len(pub_fams | hold_fams))
    print("  public: %d cases (%d families)" % (len(public), len(pub_fams)))
    print("  holdout: %d cases (%d families)" % (len(holdout), len(hold_fams)))
    print("  holdout %%: %.1f%% (cases) / %.1f%% (families)" % (
        100.0 * len(holdout) / total if total else 0,
        100.0 * len(hold_fams) / len(pub_fams | hold_fams) if hold_fams else 0))
    ben_pub = sum(1 for e in public if e["source"] == "benign")
    ben_hold = sum(1 for e in holdout if e["source"] == "benign")
    ben_total = ben_pub + ben_hold
    print("  benign pool: public=%d holdout=%d of %d (T3 floor %d)"
          % (ben_pub, ben_hold, ben_total, BENIGN_HOLDOUT_MIN))

    # Source distribution
    src_pub = {}
    src_hold = {}
    for e in public:
        src_pub[e["source"]] = src_pub.get(e["source"], 0) + 1
    for e in holdout:
        src_hold[e["source"]] = src_hold.get(e["source"], 0) + 1
    print("\n  Source distribution:")
    for src in sorted(set(src_pub) | set(src_hold)):
        print("    %-16s public=%d holdout=%d" % (
            src, src_pub.get(src, 0), src_hold.get(src, 0)))

    # Independence warning
    vr_count = sum(1 for e in entries if e["source"].startswith("variant"))
    ar_count = sum(1 for e in entries if e["source"] == "art_import")
    gen_pct = 100.0 * (vr_count + ar_count) / total if total else 0
    if gen_pct > 70:
        print("\n  WARNING: %.1f%% of cases are generated (variant+ART)." % gen_pct)
        print("  Families reduce template-level leakage but cannot")
        print("  eliminate prior exposure. This is a development split,")
        print("  not a blind evaluation set.")

    print("\nSPLIT OK (zero family leakage)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
