#!/usr/bin/env python
# -*- coding: ascii -*-
"""xiezhi alerts dump -> qinjing canonical alerts (reference adapter).

Usage:
    alerts_to_canonical.py alerts.json exec.log out.json [--complete]

alerts.json is a dump of xiezhi /alerts (or a ClickHouse windowed export):
a JSON list of {"ts": ..., "severity": ..., "rule_id": ..., ...}. The
adapter wraps it into the canonical shape (docs/02 section 2):

- rule_id -> signal_class via the table below (corpus/mapping-notes.md
  section 1 is the human-readable twin of this table; keep them in sync);
  unmapped rule ids keep signal_class empty - the scorer still counts them
  in the any-hit fallback column.
- firstseen/* rule ids are dropped: they are context digests, not
  detections, and the upstream scorer already filtered them.
- xiezhi severity is already the canonical enum; severity_native carries it
  with scale "xiezhi".
- host passthrough: dump rows carry agent_id/hostname (the /alerts store
  columns); both land in the canonical host block so the scorer can reject
  foreign-host alerts. Rows without either are counted into fetch metadata
  (host_identified/host_missing) - the scorer then needs --allow-no-host
  and says so in its report.
- fetch.complete: NOT automatic. The adapter cannot see how the dump was
  produced. --complete is the caller asserting the dump came from a
  windowed/untruncated read (the ClickHouse path); without it the wrapper
  is marked incomplete and the scorer will refuse to score it - that
  refusal is the contract working, not a bug.
"""

import argparse
import json
import os
import re
import sys

# O2 (docs/06): the rule -> signal-class mapping is a reviewable in-repo
# file, not code. corpus/mapping-notes.md section 1 is its human-readable
# twin; keep both in sync.
_HERE = os.path.dirname(os.path.abspath(__file__))
with open(os.path.join(_HERE, "rule_map.json"), encoding="ascii") as _fh:
    RULE_TO_SIGNAL = json.load(_fh)
with open(os.path.join(_HERE, "event_sources.json"), encoding="ascii") as _fh:
    # Telemetry a rule rides on (its seed rule's event type); execve rules
    # are the overwhelming default and stay implicit.
    EVENT_SOURCES = json.load(_fh)

# O5 (docs/06): policy unknown_severity=reject - a foreign severity must
# stop the conversion loudly, never silently coerce into the enum.
ALLOWED_SEVERITIES = ("critical", "high", "medium", "low")

# O1 (docs/06): policy naive_timezone=UTC - timestamps without an offset
# are interpreted as UTC and exported with the offset made explicit.
_TS_TZ_RE = re.compile(r"(Z|[+-]\d{2}:?\d{2})$")


def normalize_ts(ts):
    text = str(ts)
    if _TS_TZ_RE.search(text):
        return text
    return text + "+00:00"

TS_FIELD = "ts"


def to_ms(value):
    if value > 10 ** 17:
        return value // 10 ** 6
    if value > 10 ** 15:
        return value // 10 ** 3
    return value


def exec_run_window(path):
    """(run_start_ms, run_end_ms+grace) from the exec log, for the fetch
    window: the adapter has no better source of truth for what the run
    covered."""
    starts = []
    ends = []
    grace_ms = 3500
    for line in open(path, encoding="utf-8"):
        if line.startswith("#") or not line.strip():
            continue
        parts = line.rstrip("\r\n").split("\t")
        if len(parts) < 2:
            continue
        starts.append(to_ms(int(parts[0])))
        ends.append(to_ms(int(parts[1])))
    if not starts:
        raise ValueError("exec log %s has no rows" % path)
    return min(starts), max(ends) + grace_ms


def convert(dump_path, exec_log, out_path, complete):
    with open(dump_path, encoding="utf-8") as fh:
        raw = json.load(fh)
    if not isinstance(raw, list):
        raise ValueError("expected a JSON list of xiezhi alerts")
    lo, hi = exec_run_window(exec_log)
    alerts = []
    unmapped = {}
    dropped = 0
    host_identified = 0
    for alert in raw:
        rule_id = str(alert.get("rule_id", ""))
        if rule_id.startswith("firstseen/"):
            dropped += 1
            continue
        signal = RULE_TO_SIGNAL.get(rule_id)
        if rule_id and signal is None:
            unmapped[rule_id] = unmapped.get(rule_id, 0) + 1
        severity = alert.get("severity", "low")
        if severity not in ALLOWED_SEVERITIES:
            raise ValueError("unknown severity %r (rule %s): must be one of"
                             " %s (policy unknown_severity=reject)"
                             % (severity, rule_id, "/".join(ALLOWED_SEVERITIES)))
        entry = {
            "timestamp": normalize_ts(alert.get(TS_FIELD, "")),
            "event_kind": "alert",
            "rule_id": rule_id,
            "rule_name": rule_id,
            "severity_native": severity,
            "severity_scale": "xiezhi",
            "severity": severity,
            "signal_class": [signal] if signal else [],
            "event_source": EVENT_SOURCES.get(rule_id, "execve"),
            "mitre_attack": [alert["mitre"]] if alert.get("mitre") else [],
            "raw_log": alert.get("argv", ""),
            "event_uid": alert.get("id", ""),
        }
        if entry["mitre_attack"]:
            # Labels pass through from the product's own mitre field; they
            # were not derived from the mapping table (docs/02 label_source).
            entry["label_source"] = "native"
        host_id = str(alert.get("agent_id", "") or "")
        host_name = str(alert.get("hostname", "") or "")
        if host_id or host_name:
            entry["host"] = {"id": host_id, "name": host_name}
            host_identified += 1
        alerts.append(entry)
    wrapper = {
        "fetch": {
            "source": "xiezhi-alerts-dump-v1",
            "window_lo_ms": lo,
            "window_hi_ms": hi,
            "count": len(alerts),
            "complete": bool(complete),
            "host_identified": host_identified,
            "host_missing": len(alerts) - host_identified,
        },
        "alerts": alerts,
    }
    with open(out_path, "w", encoding="utf-8") as fh:
        json.dump(wrapper, fh, indent=1)
        fh.write("\n")
    print("converted %d alerts (dropped %d firstseen, %d unmapped rule ids)"
          % (len(alerts), dropped, len(unmapped)))
    print("host identity: %d/%d alerts carry host (agent_id/hostname)"
          % (host_identified, len(alerts)))
    if len(alerts) > host_identified:
        print("host identity gap: %d alert(s) without host - the scorer"
              " needs --allow-no-host for those (degraded, disclosed)"
              % (len(alerts) - host_identified))
    if unmapped:
        for rule_id in sorted(unmapped):
            print("unmapped: %s x%d" % (rule_id, unmapped[rule_id]))
    if not complete:
        print("fetch.complete=false - scorer will refuse; pass --complete "
              "only for a windowed/untruncated export (CH path)")
    return 0


def main(argv=None):
    ap = argparse.ArgumentParser(description="xiezhi -> canonical adapter")
    ap.add_argument("alerts_json")
    ap.add_argument("exec_log")
    ap.add_argument("out_json")
    ap.add_argument("--complete", action="store_true",
                    help="assert the dump is untruncated (windowed export)")
    args = ap.parse_args(argv)
    try:
        return convert(args.alerts_json, args.exec_log, args.out_json,
                       args.complete)
    except (ValueError, OSError, json.JSONDecodeError) as exc:
        sys.stderr.write("adapter error: %s\n" % exc)
        return 1


if __name__ == "__main__":
    sys.exit(main())
