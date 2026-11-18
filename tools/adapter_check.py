#!/usr/bin/env python
# -*- coding: ascii -*-
"""Adapter acceptance check (docs/06): run one adapter against the shared
boundary fixture pack and audit its obligations O1-O8.

Usage:
    adapter_check.py adapters/<name>

Reads adapters/<name>/adapter.json (command template, mapping table,
policies) and tests/fixture/adapter/<name>/cases.json (raw fixtures and
expectations). Every exit-0 output also passes the global invariants
(fetch.count == len(alerts), window bounds cover the exec log run window),
which credit A03/A04 in the report. Every case runs twice; byte-identical
outputs credit O8 (pure function). Exit 1 on any failed check.
"""

import json
import os
import re
import subprocess
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "tools"))
from parse import SIGNAL_CLASSES  # noqa: E402

TS_OFFSET_RE = re.compile(r"(Z|[+-]\d{2}:?\d{2})$")


def fail(results, key, message):
    results.append((key, False, message))


def pass_(results, key, message):
    results.append((key, True, message))


def exec_run_window(path):
    starts = []
    ends = []
    for line in open(path, encoding="utf-8"):
        if line.startswith("#") or not line.strip():
            continue
        parts = line.rstrip("\r\n").split("\t")
        if len(parts) < 2:
            continue
        value = int(parts[0])
        if value > 10 ** 17:
            value //= 10 ** 6
        elif value > 10 ** 15:
            value //= 10 ** 3
        starts.append(value)
        ends.append(int(parts[1]))
    return min(starts), max(ends) + 3500


def run_case(manifest, adapter_dir, case_dir, case, results):
    tag = case["id"]
    raw = os.path.join(case_dir, case["raw"])
    execlog = os.path.join(case_dir, "adapter-exec.log")
    out1 = os.path.join(case_dir, "_out1.json")
    out2 = os.path.join(case_dir, "_out2.json")
    command = [part.replace("{adapter_dir}", adapter_dir)
               .replace("{raw}", raw).replace("{execlog}", execlog)
               .replace("{out}", out1)
               for part in manifest["command"]] + list(case.get("flags", []))
    proc = subprocess.run(command, capture_output=True, text=True)
    expect = case["expect"]

    if proc.returncode != expect["exit"]:
        fail(results, tag, "exit %d, want %d (stderr: %s)"
             % (proc.returncode, expect["exit"], proc.stderr.strip()[:120]))
        return
    if "stderr_contains" in expect and \
            expect["stderr_contains"] not in proc.stderr:
        fail(results, tag, "stderr lacks %r" % expect["stderr_contains"])
        return
    if expect["exit"] != 0:
        pass_(results, tag, "rejected as expected")
        return

    # O8: same input must give byte-identical output on a second run.
    command2 = [part.replace("{adapter_dir}", adapter_dir)
                .replace("{raw}", raw).replace("{execlog}", execlog)
                .replace("{out}", out2)
                for part in manifest["command"]] + list(case.get("flags", []))
    subprocess.run(command2, capture_output=True, text=True)
    if open(out1, "rb").read() != open(out2, "rb").read():
        fail(results, tag + "/O8", "second run differs from the first")
        return

    with open(out1, encoding="utf-8") as fh:
        wrapper = json.load(fh)
    fetch = wrapper.get("fetch", {})
    alerts = wrapper.get("alerts", [])

    problems = []
    if fetch.get("complete") is not expect.get("complete", None) \
            and "complete" in expect:
        problems.append("complete=%r want %r"
                        % (fetch.get("complete"), expect["complete"]))
    if not isinstance(fetch.get("count"), int) or \
            fetch["count"] != len(alerts):
        problems.append("fetch.count=%r != len(alerts)=%d (A03)"
                        % (fetch.get("count"), len(alerts)))
    lo = fetch.get("window_lo_ms")
    hi = fetch.get("window_hi_ms")
    run_lo, run_hi = exec_run_window(execlog)
    if not isinstance(lo, int) or not isinstance(hi, int) or \
            lo > run_lo or hi < run_hi:
        problems.append("fetch window [%r, %r] does not cover run window"
                        " [%d, %d] (A04)" % (lo, hi, run_lo, run_hi))
    if expect.get("alerts") is not None and len(alerts) != expect["alerts"]:
        problems.append("alerts=%d want %d"
                        % (len(alerts), expect["alerts"]))
    if "host_missing" in expect and \
            fetch.get("host_missing") != expect["host_missing"]:
        problems.append("host_missing=%r want %r"
                        % (fetch.get("host_missing"), expect["host_missing"]))
    for alert in alerts:
        ts = str(alert.get("timestamp", ""))
        if not TS_OFFSET_RE.search(ts):
            problems.append("timestamp without offset: %r (A05/O1)" % ts)
            break
    if "ts_offset_all" in expect and not any(
            str(a.get("timestamp", "")).endswith("+00:00") for a in alerts):
        problems.append("no naive timestamp normalized to +00:00")
    for rule_id in expect.get("signal_empty_rules", []):
        for alert in alerts:
            if alert.get("rule_id") == rule_id and alert.get("signal_class"):
                problems.append("rule %r should carry empty signal_class"
                                % rule_id)
    for rule_id in expect.get("no_host_key_rules", []):
        for alert in alerts:
            if alert.get("rule_id") == rule_id and "host" in alert:
                problems.append("rule %r fabricated a host block" % rule_id)
    for rule_id, want_src in expect.get("event_source_of", {}).items():
        for alert in alerts:
            if alert.get("rule_id") == rule_id and \
                    alert.get("event_source") != want_src:
                problems.append("rule %r event_source=%r want %r"
                                % (rule_id, alert.get("event_source"),
                                   want_src))
    for rule_id, want in expect.get("host_of", {}).items():
        for alert in alerts:
            if alert.get("rule_id") == rule_id:
                host = alert.get("host", {})
                if [host.get("id"), host.get("name")] != want:
                    problems.append("rule %r host=%r want %r"
                                    % (rule_id, host, want))

    if problems:
        fail(results, tag, "; ".join(problems))
    else:
        pass_(results, tag, "ok")


def main(argv):
    if len(argv) != 2:
        sys.stderr.write(__doc__)
        return 2
    adapter_dir = os.path.join(ROOT, argv[1])
    manifest_path = os.path.join(adapter_dir, "adapter.json")
    results = []

    try:
        with open(manifest_path, encoding="utf-8") as fh:
            manifest = json.load(fh)
    except (OSError, json.JSONDecodeError) as exc:
        sys.stderr.write("manifest unreadable: %s\n" % exc)
        return 2
    for field in ("name", "command", "mapping_table"):
        if field not in manifest:
            sys.stderr.write("manifest lacks %r\n" % field)
            return 2

    # Static: mapping table must exist and stay inside the 38-class vocab.
    table_path = os.path.join(adapter_dir, manifest["mapping_table"])
    try:
        with open(table_path, encoding="utf-8") as fh:
            table = json.load(fh)
    except (OSError, json.JSONDecodeError) as exc:
        fail(results, "S3/O2", "mapping table unreadable: %s" % exc)
        table = {}
    outside = sorted({v for v in table.values() if v not in SIGNAL_CLASSES})
    if outside:
        fail(results, "S3/O2", "mapping table outside vocab: %s"
             % ", ".join(outside))
    else:
        pass_(results, "S3/O2", "mapping table in vocab (%d rules)"
              % len(table))

    name = manifest["name"]
    case_dir = os.path.join(ROOT, "tests", "fixture", "adapter", name)
    try:
        with open(os.path.join(case_dir, "cases.json"), encoding="utf-8") as fh:
            cases = json.load(fh)
    except (OSError, json.JSONDecodeError) as exc:
        sys.stderr.write("cases.json unreadable: %s\n" % exc)
        return 2

    for case in cases:
        run_case(manifest, adapter_dir, case_dir, case, results)

    for _, ok, message in results:
        print("%s %-8s %s" % ("PASS" if ok else "FAIL", "", message))
    failed = sum(1 for _, ok, _ in results if not ok)
    print("adapter %s: %d checks, %d failed" % (name, len(results), failed))
    for leftover in ("_out1.json", "_out2.json"):
        path = os.path.join(case_dir, leftover)
        if os.path.exists(path):
            os.remove(path)
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
