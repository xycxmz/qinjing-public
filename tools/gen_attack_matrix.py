#!/usr/bin/env python
# -*- coding: ascii -*-
"""Regenerate data/attack-enterprise.txt from the official ATT&CK STIX bundle.

Usage:
    gen_attack_matrix.py <enterprise-attack.json> [out.txt]
                         [--attack-version X.Y]

Downloads (upstream mitre-attack/attack-stix-data; MITRE's custom
license applies, NOT the MIT license -- reproduce MITRE's copyright
designation, see NOTICE; e.g. tag v20.1):
    https://raw.githubusercontent.com/mitre-attack/attack-stix-data/<tag>/
    enterprise-attack/enterprise-attack.json

Output: one line per (technique, tactic) pair, "<TID>\\t<TA id>\\t<name>",
active techniques only (revoked/deprecated dropped). Always pass
--attack-version with the release of the tag you downloaded (e.g. 20.1
for tag v20.1); the header records it so coverage reports can cite the
exact ATT&CK release instead of a floating master snapshot.
"""

import argparse
import json
import sys

# Enterprise kill-chain phase name -> ATT&CK tactic id. v19 renamed
# defense-evasion to stealth and split out defense-impairment (TA0112);
# both old and new spellings kept so older STIX snapshots still load.
PHASE_TO_TACTIC = {
    "reconnaissance": "TA0043",
    "resource-development": "TA0042",
    "initial-access": "TA0001",
    "execution": "TA0002",
    "persistence": "TA0003",
    "privilege-escalation": "TA0004",
    "defense-evasion": "TA0005",
    "stealth": "TA0005",
    "defense-impairment": "TA0112",
    "credential-access": "TA0006",
    "discovery": "TA0007",
    "lateral-movement": "TA0008",
    "collection": "TA0009",
    "command-and-control": "TA0011",
    "exfiltration": "TA0010",
    "impact": "TA0040",
}


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("source", help="enterprise-attack.json STIX bundle")
    ap.add_argument("out", nargs="?", default="data/attack-enterprise.txt")
    ap.add_argument("--attack-version", default=None, metavar="X.Y",
                    help="pin the ATT&CK release in the header (20.1 for"
                         " attack-stix-data tag v20.1)")
    args = ap.parse_args(argv)

    with open(args.source, encoding="utf-8") as fh:
        bundle = json.load(fh)

    rows = []
    for obj in bundle.get("objects", []):
        if obj.get("type") != "attack-pattern":
            continue
        if obj.get("revoked") or obj.get("x_mitre_deprecated"):
            continue
        refs = obj.get("external_references") or []
        tid = next((r.get("external_id") for r in refs
                    if r.get("external_id", "").startswith("T")), None)
        if not tid:
            continue
        for phase in obj.get("kill_chain_phases") or []:
            tactic = PHASE_TO_TACTIC.get(phase.get("phase_name"))
            if tactic:
                rows.append((tid, tactic, obj.get("name", "")))

    rows.sort()
    if args.attack_version:
        source_note = " tag v%s, pinned to ATT&CK %s." % (
            args.attack_version, args.attack_version)
        regen_flag = " --attack-version %s" % args.attack_version
    else:
        source_note = (" unpinned master snapshot"
                       " (pass --attack-version).")
        regen_flag = ""
    with open(args.out, "w", encoding="ascii", errors="replace",
              newline="\n") as fh:
        fh.write("# ATT&CK Enterprise technique x tactic pairs (active only).\n")
        fh.write("# Source: mitre-attack/attack-stix-data%s\n" % source_note)
        fh.write("# (c) 2026 The MITRE Corporation. Reproduced and distributed"
                 " with the\n")
        fh.write("# permission of The MITRE Corporation under MITRE's custom"
                 " license\n")
        fh.write("# (not the MIT license; full license text in NOTICE).\n")
        fh.write("# Regenerate: tools/gen_attack_matrix.py"
                 " enterprise-attack.json data/attack-enterprise.txt%s\n"
                 % regen_flag)
        fh.write("# Columns: technique_id\\ttactic_id\\tname\n")
        for tid, tactic, name in rows:
            fh.write("%s\t%s\t%s\n" % (tid, tactic, name))
    print("wrote %d rows for %d techniques (ATT&CK %s) to %s"
          % (len(rows), len({r[0] for r in rows}),
             args.attack_version or "unpinned", args.out))
    return 0


if __name__ == "__main__":
    sys.exit(main())
