#!/usr/bin/env python
# -*- coding: ascii -*-
"""Manifest freshness gate (docs/11 C2): benchmark-manifest.json must freeze
the sha256 of every scoring input it names, and those hashes must match the
working tree. Editing a frozen file without refreezing turns this red, so a
report can always prove which exact bytes produced it.

Usage:
    manifest_check.py [--repo ROOT] [--manifest PATH]

Exit 0 = every frozen hash matches; 1 = stale or unreadable freeze.
"""

import argparse
import hashlib
import json
import os
import sys


def file_sha256(path):
    with open(path, "rb") as fh:
        return hashlib.sha256(fh.read()).hexdigest()


def main(argv=None):
    default_repo = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--repo", default=default_repo)
    ap.add_argument("--manifest", default=None,
                    help="check this manifest file instead of REPO's")
    args = ap.parse_args(argv)
    manifest_path = args.manifest or os.path.join(args.repo,
                                                  "benchmark-manifest.json")
    try:
        with open(manifest_path, encoding="utf-8") as fh:
            manifest = json.load(fh)
    except (OSError, ValueError) as exc:
        print("FAIL manifest unreadable: %s" % exc)
        return 1

    # (label, path inside the repo, frozen sha from the manifest). Paths the
    # manifest itself names (matrix, secondary_anchors) are read from it, so
    # a renamed data file cannot silently drop out of the freeze.
    m_matrix = manifest.get("matrix", {})
    m_adapter = manifest.get("adapter", {})
    m_anchors = manifest.get("secondary_anchors", {})
    entries = [
        ("corpus", "corpus/qinjing.yaml",
         manifest.get("corpus", {}).get("sha256")),
        ("matrix", m_matrix.get("file"), m_matrix.get("sha256")),
        ("scorer", "tools/scorer.py", manifest.get("scorer", {}).get("sha256")),
        ("adapter.rule_map", "adapters/xiezhi/rule_map.json",
         m_adapter.get("rule_map_sha")),
        ("adapter.event_sources", "adapters/xiezhi/event_sources.json",
         m_adapter.get("event_sources_sha")),
        ("secondary_anchors", m_anchors.get("file"), m_anchors.get("sha256")),
    ]

    mismatches = 0
    for label, rel, frozen in entries:
        if not rel or not frozen:
            print("FAIL %-19s manifest entry lacks file or sha256" % label)
            mismatches += 1
            continue
        path = os.path.join(args.repo, rel)
        if not os.path.isfile(path):
            print("FAIL %-19s frozen file missing: %s" % (label, rel))
            mismatches += 1
            continue
        actual = file_sha256(path)
        if actual == frozen:
            print("ok   %-19s %s" % (label, actual[:12]))
        else:
            print("FAIL %-19s manifest %s != actual %s (%s edited without"
                  " refreeze?)" % (label, frozen[:12], actual[:12], rel))
            mismatches += 1
    # C9: fair-config is a frozen declaration (profile + applicable scope),
    # not a file hash; check its presence separately from the sha tally.
    fc = manifest.get("fair_config") or {}
    fc_ok = bool(fc.get("profile") and fc.get("applicable_scope"))
    if fc_ok:
        print("ok   %-19s profile=%s, scope frozen" % ("fair_config",
                                                       fc["profile"]))
    else:
        print("FAIL %-19s missing profile/applicable_scope (C9)"
              % "fair_config")
    print("manifest freshness: %d/%d sha256 match"
          % (len(entries) - mismatches, len(entries)))
    return 1 if (mismatches or not fc_ok) else 0


if __name__ == "__main__":
    sys.exit(main())
