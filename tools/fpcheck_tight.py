#!/usr/bin/env python
# -*- coding: ascii -*-
"""Tight-window false-positive audit for qinjing runs.

Usage:
    fpcheck_tight.py exec.log alerts.json [tolerance_ms]

alerts.json is the canonical wrapper (same as scorer input). The integrity
gate is hard: fetch.complete must be true, window bounds must be present,
and fetch.count must equal len(alerts). Anything else exits 2: an
unverifiable read must never print "clean" (an empty alerts array with
complete=false once read as a perfect FP score).

For every false-positive case the window is [start - tol, end + tol] - the
tail tolerance matters because a case can run for seconds under the timeout,
so anchoring on start alone would wave through alerts fired mid-case
(upstream R8.4 audit). Any high+ alert inside the window is a violation; for
each violation the same-window attack cases are listed so uid comparison can
separate scheduler cross-talk (same uid bucket) from a real regression.
Each verdict line carries the row's bin_found so a verdict on a binary-less
benign row (argv-visible only) is distinguishable from one that really ran
the tool.

A benign row with bin_found=0 is NOT-RUN (its declared binary was missing,
so the case never ran) and is never judged clean; it is excluded from the
violation count. With no evaluable benign rows at all the tool prints N/A
and exits 0 - "no data" must not read as "zero false positives".

Exit codes: 0 clean or N/A (no evaluable benign rows), 1 violations found,
2 invalid input (integrity gate or unreadable files).
"""

import datetime
import json
import sys

TOL_MS_DEFAULT = 2500
HIGH_PLUS = ("high", "critical")


def to_ms(value):
    if value > 10 ** 17:
        return value // 10 ** 6
    if value > 10 ** 15:
        return value // 10 ** 3
    return value


def alert_ts_ms(ts):
    text = str(ts).strip().replace("Z", "+00:00")
    dt = datetime.datetime.fromisoformat(text)
    if dt.tzinfo is None:
        # Naive timestamps are UTC: ClickHouse exports carry no offset and
        # trusting the local clock of whoever runs this tool once produced
        # different +/-2.5s verdicts on different machines.
        dt = dt.replace(tzinfo=datetime.timezone.utc)
    return int(dt.timestamp() * 1000)


def load_alerts(path):
    with open(path, encoding="utf-8") as fh:
        data = json.load(fh)
    if not isinstance(data, dict) or "fetch" not in data or "alerts" not in data:
        raise ValueError("not a canonical alerts file (need fetch + alerts keys)")
    fetch = data["fetch"]
    problems = []
    if fetch.get("complete") is not True:
        problems.append("fetch.complete is not true - the read may be truncated")
    lo = fetch.get("window_lo_ms")
    hi = fetch.get("window_hi_ms")
    if not isinstance(lo, int) or not isinstance(hi, int) or lo >= hi:
        problems.append("fetch window bounds missing or invalid")
    declared = fetch.get("count")
    if not isinstance(declared, int) or declared != len(data["alerts"]):
        problems.append("fetch.count=%r does not match len(alerts)=%d"
                        % (declared, len(data["alerts"])))
    if problems:
        raise ValueError("; ".join(problems))
    return data["alerts"]


def parse_rows(path):
    rows = []
    for line in open(path, encoding="utf-8"):
        if line.startswith("#") or not line.strip():
            continue
        parts = line.rstrip("\r\n").split("\t")
        if len(parts) < 6:
            continue
        rows.append({"start_ms": to_ms(int(parts[0])),
                     "end_ms": to_ms(int(parts[1])),
                     "id": parts[2], "group": parts[3], "uid": parts[4],
                     "bin": parts[5]})
    return rows


def main(argv):
    if len(argv) < 3 or len(argv) > 4:
        sys.stderr.write(__doc__)
        return 2
    exec_log, alerts_path = argv[1], argv[2]
    tol_ms = int(argv[3]) if len(argv) > 3 else TOL_MS_DEFAULT

    try:
        alerts = load_alerts(alerts_path)
        rows = parse_rows(exec_log)
    except (ValueError, OSError, json.JSONDecodeError) as exc:
        sys.stderr.write("fpcheck input error: %s\n" % exc)
        return 2

    attacks = [r for r in rows if r["group"] != "fp"]
    fp_rows = [r for r in rows if r["group"] == "fp"]
    if not fp_rows:
        print("N/A: no benign rows in exec log - nothing to judge")
        return 0
    evaluable = [r for r in fp_rows if r["bin"] == "1"]
    if not evaluable:
        for row in fp_rows:
            print("%s (bin=0) NOT-RUN" % row["id"])
        print("benign rows: %d (evaluable: 0, not-run: %d)"
              % (len(fp_rows), len(fp_rows)))
        print("N/A: no evaluable benign rows - nothing to judge")
        return 0

    violations = 0
    for row in fp_rows:
        if row["bin"] != "1":
            print("%s (bin=0) NOT-RUN" % row["id"])
            continue
        window = (row["start_ms"] - tol_ms, row["end_ms"] + tol_ms)
        hits = [a for a in alerts
                if window[0] <= alert_ts_ms(a.get("timestamp", "")) <= window[1]
                and a.get("severity") in HIGH_PLUS]
        if hits:
            violations += 1
            print("%s (bin=%s) VIOLATION: %s" % (
                row["id"], row["bin"],
                [(a.get("rule_id"), a.get("severity"), a.get("timestamp"))
                 for a in hits]))
            for alert in hits:
                ts = alert_ts_ms(alert.get("timestamp", ""))
                near = [(r["id"], r["uid"]) for r in attacks
                        if r["start_ms"] - tol_ms <= ts <= r["end_ms"] + tol_ms]
                print("%s detail: fp-uid=%s hit=%s same-window-attacks=%s"
                      % (row["id"], row["uid"],
                         (alert.get("rule_id"), alert.get("severity"),
                          alert.get("timestamp")), near))
        else:
            print("%s (bin=%s) clean" % (row["id"], row["bin"]))
    print("benign rows: %d (evaluable: %d, not-run: %d)"
          % (len(fp_rows), len(evaluable), len(fp_rows) - len(evaluable)))
    print("tight-window(+/-%dms) high+ violations: %d" % (tol_ms, violations))
    return 1 if violations else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
