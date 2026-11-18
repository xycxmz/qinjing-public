#!/usr/bin/env python
# -*- coding: ascii -*-
"""qinjing scorer: attribute canonical alerts to corpus cases, print report.

Usage:
    scorer.py corpus.yaml exec.log alerts.json [--min-severity high]
              [--grace-ms 3500] [--out report.md] [--allow-no-host]

alerts.json is the canonical wrapper (docs/02 section 2): {"fetch": {...},
"alerts": [...]}. The fetch gate is hard: fetch.complete must be true and the
fetch window must cover the whole run window (first case start through last
case end + grace). Anything else exits 1 - a truncated read must never score
silently (lesson 1 of the evaluation-calibre doc).

Attribution identity gates (docs/04 D8): events whose event_kind is not
"alert" are counted as stray telemetry and alerts whose host disagrees with
the exec log's host= header are stray(foreign host). Alerts with no host
identity are stray(no host identity) unless --allow-no-host explicitly
accepts a single-host legacy export (the report then says so and is not
comparable across products).

Exit code is 0 for a normal report (misses are findings, not tool failures)
and for SUBSET runs (explicit --only subset, banner disclosed). 1 means a
contract violation (bad fetch, unreadable inputs, unknown case ids in the
exec log) or an INTERRUPTED run: no END trailer, missing or duplicate rows,
or a plan that disagrees with the corpus (docs/04 D6) - the matrix stays in
the report for debugging but the statistics are suppressed.
"""

import argparse
import datetime
import hashlib
import json
import os
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from parse import parse_corpus  # noqa: E402

SEV_ORDER = {"low": 1, "medium": 2, "high": 3, "critical": 4}
GRACE_MS_DEFAULT = 3500  # pipeline latency: intent poll + batch flush
STRAY_MARGIN_MS = 60000
CLAIM_BACK_MS = 500


def file_sha256(path):
    """Content hash of one input file, so a report can prove which bytes
    produced it (docs/05 D9): the alerts file is exactly the place historic
    retouching would change a score, so it is hashed like the rest."""
    with open(path, "rb") as fh:
        return hashlib.sha256(fh.read()).hexdigest()


def in_denominator(row):
    """Calibre v2 (owner decision 2026-11-16): a case counts when its tool
    really execve'd (bin_found=1) OR when it is pure shell builtin - bash
    builtins always exist, ran inside the wrapper, and stay argv-visible on
    every target. Only a declared binary that is missing keeps a case out
    of every denominator."""
    return row["bin_found"] == "1" or row["case"]["mode"] == "sim-builtin"

# Optional runner-injected attribution marker: "# qj:<caseid>:<runtag>"
# riding the same argv element as the command. A marker only counts when its
# runtag equals this run's tag - back-to-back runs share the host but never
# the tag, so a stale alert from the previous round cannot claim a case.
MARKER_RE = re.compile(r"\bqj:([A-Z]{1,3}\d{1,2}):(\d{9,16})\b")


def to_ms(value):
    """Normalize a runner timestamp by magnitude (ns/us/ms eras).

    >>> to_ms(1763300000000000000)
    1763300000000
    >>> to_ms(1763300000000000)
    1763300000000
    >>> to_ms(1763300000000)
    1763300000000
    """
    if value > 10 ** 17:
        return value // 10 ** 6
    if value > 10 ** 15:
        return value // 10 ** 3
    return value


def alert_ts_ms(ts):
    """RFC3339-with-offset alert timestamp to epoch ms; naive means UTC.

    >>> alert_ts_ms("2026-11-16T08:00:00Z")
    1794816000000
    >>> alert_ts_ms("2026-11-16 08:00:00")
    1794816000000
    >>> alert_ts_ms("2026-11-16T09:00:00+01:00")
    1794816000000
    """
    text = str(ts).strip().replace("Z", "+00:00")
    dt = datetime.datetime.fromisoformat(text)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=datetime.timezone.utc)
    return int(dt.timestamp() * 1000)


def parse_exec_log(path):
    header = {}
    endinfo = None
    rows = []
    with open(path, "r") as fh:
        for line in fh:
            line = line.rstrip("\r\n")
            if not line:
                continue
            if line.startswith("#"):
                if line.startswith("# QINJING-END"):
                    endinfo = {}
                    for token in line.split():
                        if "=" in token and not token.startswith("#"):
                            key, _, value = token.partition("=")
                            endinfo[key] = value
                    continue
                # Values may contain spaces (distro PRETTY_NAME); split on
                # " key=" boundaries instead of plain whitespace.
                body = line.lstrip("#").strip()
                for token in re.split(r" (?=[A-Za-z_]+=)", body):
                    if "=" in token:
                        key, _, value = token.partition("=")
                        header[key] = value
                continue
            parts = line.split("\t")
            if len(parts) < 7:
                continue
            rows.append({
                "start_ms": to_ms(int(parts[0])),
                "end_ms": to_ms(int(parts[1])),
                "id": parts[2],
                "group": parts[3],
                "uid": parts[4],
                "bin_found": parts[5],
                "rc": parts[6],
                "cmd": parts[7] if len(parts) > 7 else "",
            })
    if not rows:
        raise ValueError("exec log %s has no case rows" % path)
    rows.sort(key=lambda r: r["start_ms"])
    return header, rows, endinfo


def classify_run(header, endinfo, rows, corpus_ids):
    """Reconcile the frozen plan against the executed rows (docs/04 D6).

    COMPLETE: END line present, no missing/duplicate rows, plan aligned with
    the corpus (or the declared subset), runner transport_fail=0. SUBSET:
    the same checks against an explicitly declared --only subset. Anything
    else is INTERRUPTED - the report keeps its matrix but no statistics.
    """
    problems = []
    ids = [row["id"] for row in rows]
    counts = {}
    for rid in ids:
        counts[rid] = counts.get(rid, 0) + 1
    dup_detail = ["%s (x%d)" % (rid, counts[rid])
                  for rid in sorted(counts) if counts[rid] > 1]
    transport = sum(1 for row in rows if row["rc"] == "255")
    plan_raw = header.get("plan", "")
    plan = int(plan_raw) if plan_raw.isdigit() else None
    subset_raw = header.get("subset", "")

    if endinfo is None:
        problems.append("no END line (run killed or pre-freeze log format)")
    if plan is None:
        problems.append("plan header missing (pre-freeze log format, "
                        "plan not frozen)")

    missing_ids = []
    if subset_raw:
        declared = [s for s in subset_raw.split(",") if s]
        planned = plan if plan is not None else len(declared)
        if plan is not None and plan != len(declared):
            problems.append("plan=%s but subset declares %d id(s)"
                            % (plan_raw, len(declared)))
        if set(ids) != set(declared):
            problems.append("executed id set does not match declared "
                            "subset (%s)" % subset_raw)
        elif len(ids) != len(declared):
            problems.append("duplicate ids inside the declared subset")
        missing_ids = [rid for rid in declared if rid not in counts]
    else:
        planned = plan if plan is not None else len(corpus_ids)
        if plan is not None and plan != len(corpus_ids):
            problems.append("plan=%d but corpus has %d case(s)"
                            % (plan, len(corpus_ids)))
        if plan is not None and len(rows) != plan:
            problems.append("rows %d != plan %d (%d missing)"
                            % (len(rows), plan, plan - len(rows)))
        missing_ids = [rid for rid in corpus_ids if rid not in counts]
    if dup_detail:
        problems.append("duplicate id(s): %s" % ", ".join(
            d.split(" ")[0] for d in dup_detail))
    if endinfo is not None:
        fail_raw = endinfo.get("transport_fail", "0")
        if fail_raw.isdigit() and int(fail_raw) > 0:
            problems.append("runner reported transport_fail=%s in END line"
                            % fail_raw)

    recon = {
        "planned": planned,
        "executed": len(rows),
        "missing": len(missing_ids),
        "dup": len(rows) - len(counts),
        "transport": transport,
    }
    if problems:
        kind = "INTERRUPTED"
    elif subset_raw:
        kind = "SUBSET"
    else:
        kind = "COMPLETE"
    return {"kind": kind, "problems": problems, "recon": recon,
            "missing_ids": missing_ids, "dup_detail": dup_detail}


def load_alerts(path, run_start_ms, run_end_ms):
    with open(path, "r") as fh:
        data = json.load(fh)
    if not isinstance(data, dict) or "fetch" not in data or "alerts" not in data:
        raise ValueError("%s: not a canonical alerts file "
                         "(need fetch + alerts keys)" % path)
    fetch = data["fetch"]
    if fetch.get("complete") is not True:
        raise ValueError("fetch.complete is not true - the read may be "
                         "truncated; fix the adapter instead of scoring "
                         "partial data")
    declared = fetch.get("count")
    if not isinstance(declared, int) or declared != len(data["alerts"]):
        raise ValueError("fetch.count=%r does not match len(alerts)=%d - "
                         "the read is inconsistent with its own manifest"
                         % (declared, len(data["alerts"])))
    lo = int(fetch.get("window_lo_ms", 0))
    hi = int(fetch.get("window_hi_ms", 0))
    if lo > run_start_ms or hi < run_end_ms:
        raise ValueError("fetch window [%d, %d] does not cover run window "
                         "[%d, %d]" % (lo, hi, run_start_ms, run_end_ms))
    return fetch, data["alerts"]


def build_report(corpus_path, log_path, alerts_path, min_severity,
                 grace_ms, allow_no_host=False, verbose=False):
    cases = parse_corpus(corpus_path)
    by_id = {}
    for group in ("false_positives", "attacks"):
        for case in cases[group]:
            by_id[case["id"]] = case
    header, rows, endinfo = parse_exec_log(log_path)

    unknown = [row for row in rows if row["id"] not in by_id]
    if unknown:
        for row in unknown:
            sys.stderr.write("exec log id %r not in corpus\n" % row["id"])
        raise ValueError("exec log references %d unknown case id(s)"
                         % len(unknown))
    run_class = classify_run(header, endinfo, rows, list(by_id))

    for row in rows:
        row["case"] = by_id[row["id"]]
        row["observed"] = []
    for i, row in enumerate(rows):
        nxt = rows[i + 1]["start_ms"] if i + 1 < len(rows) else None
        # Grace extends into the next case's window; the claim-back scan
        # below returns a late alert to the case that expected its signal.
        row["window_end_ms"] = (nxt + grace_ms) if nxt is not None \
            else row["end_ms"] + grace_ms

    run_start_ms = rows[0]["start_ms"]
    run_end_ms = rows[-1]["window_end_ms"]

    run_tag = None
    for row in rows:
        found = MARKER_RE.search(row["cmd"])
        if found:
            run_tag = found.group(2)
            break
    rows_by_id = {row["id"]: row for row in rows}

    fetch, alerts = load_alerts(alerts_path, run_start_ms, run_end_ms)

    attributed = []
    stray = []
    marker_hits = 0
    basis_counts = {"marker": 0, "expected-window": 0, "in-progress": 0,
                    "first-covering": 0, "late-claimed": 0}
    ambiguous = []
    nohost_admitted = 0
    run_host = header.get("host", "")
    for alert in alerts:
        ts_ms = alert_ts_ms(alert.get("timestamp", ""))
        alert["_ts_ms"] = ts_ms
        if ts_ms < run_start_ms - STRAY_MARGIN_MS or \
           ts_ms > run_end_ms + STRAY_MARGIN_MS:
            stray.append((alert, "outside run window (pre-existing noise)"))
            continue
        # Identity gates before any window logic (D8): telemetry is not a
        # detection, a foreign host's alert is not this run's evidence, and
        # a hostless alert only scores under an explicit degraded grant.
        if alert.get("event_kind") != "alert":
            stray.append((alert, "stray(telemetry)"))
            continue
        host_block = alert.get("host")
        if not isinstance(host_block, dict):
            host_block = {}
        host_ids = {str(v) for v in (host_block.get("name"),
                                     host_block.get("id")) if v}
        if not host_ids:
            if not allow_no_host:
                stray.append((alert, "stray(no host identity)"))
                continue
            nohost_admitted += 1
        elif run_host and run_host not in host_ids:
            stray.append((alert, "stray(foreign host: %s)"
                          % str(host_block.get("name")
                                or host_block.get("id"))))
            continue
        holder = None
        basis = None
        covering = []
        if run_tag:
            text = " ".join(
                [str(alert.get("raw_log", ""))] +
                [str(part) for part in
                 (alert.get("process") or {}).get("argv") or []])
            found = MARKER_RE.search(text)
            if found and found.group(2) == run_tag and \
                    found.group(1) in rows_by_id:
                holder = rows_by_id[found.group(1)]
                marker_hits += 1
                basis = "marker"
        if holder is None:
            covering = [row for row in rows
                        if row["start_ms"] - CLAIM_BACK_MS <= ts_ms
                        <= row["window_end_ms"]]
            inprog = None
            for row in covering:
                if row["start_ms"] <= ts_ms:
                    inprog = row
            for row in reversed(covering):
                expected = row["case"].get("expected_signals", [])
                classes = alert.get("signal_class", [])
                if expected and set(expected) & set(classes):
                    holder = row
                    # In-span match vs claim-back of a late arrival past
                    # the case's own end (still no free HIT outside the
                    # run window - those stayed stray above).
                    basis = "expected-window" if ts_ms <= row["end_ms"] \
                        else "late-claimed"
                    break
            if holder is None:
                holder = inprog if inprog is not None else \
                    (covering[0] if covering else None)
                if holder is not None:
                    basis = "in-progress" if inprog is not None \
                        else "first-covering"
        if holder is None:
            stray.append((alert, "late (after run window)"
                          if ts_ms > run_end_ms else "before first case"))
            continue
        if basis != "marker":
            competing = [row["id"] for row in covering
                         if row["case"].get("expected_signals")
                         and set(row["case"]["expected_signals"])
                         & set(alert.get("signal_class", []))]
            if len(competing) > 1:
                # Same-second overlap the window model cannot resolve: keep
                # the current attribution, disclose the ambiguity.
                ambiguous.append((alert, holder["id"], competing))
        attributed.append((alert, holder))
        holder["observed"].append(alert)
        basis_counts[basis] += 1

    verdicts = {}
    anyhit = {}
    for row in rows:
        case = row["case"]
        expected = case.get("expected_signals", [])
        obs_classes = []
        for alert in row["observed"]:
            for klass in alert.get("signal_class", []):
                if klass not in obs_classes:
                    obs_classes.append(klass)
        highish = [a for a in row["observed"]
                   if SEV_ORDER.get(a.get("severity"), 0)
                   >= SEV_ORDER[min_severity]]
        if row["rc"] == "255":
            # ssh-layer failure semantics (runner.sh): the command never
            # reached the target, so the row proves nothing and leaves
            # every denominator, any-hit included (D7).
            verdicts[row["id"]] = "RUN-INVALID (transport)"
            anyhit[row["id"]] = False
            continue
        anyhit[row["id"]] = bool(highish)

        if case["group"] == "fp":
            if not in_denominator(row):
                # Symmetric to the attack side: a benign case whose declared
                # binary is missing never ran, so it is not evidence of
                # anything - least of all of being clean (the C-Q2 gap).
                verdicts[row["id"]] = "NOT-RUN (bin=0)"
            elif highish:
                verdicts[row["id"]] = "FALSE POSITIVE"
            elif row["observed"]:
                verdicts[row["id"]] = "noise (below %s)" % min_severity
            else:
                verdicts[row["id"]] = "clean"
            continue
        if case["expect"] == "gap":
            verdicts[row["id"]] = "UNEXPECTED-HIT" if row["observed"] \
                else "gap (no signal)"
            continue
        hit = [s for s in expected if s in obs_classes]
        if not in_denominator(row):
            # Declared binary missing (mode != sim-builtin): the case never
            # ran; keep it out of every denominator even if an alert landed
            # in its window. sim-builtin rows passed above - they ran.
            verdicts[row["id"]] = "NOT-RUN (bin=0)"
        elif len(hit) == len(expected) and expected:
            verdicts[row["id"]] = "HIT"
        elif hit:
            verdicts[row["id"]] = "PARTIAL (%d/%d)" % (len(hit), len(expected))
        else:
            verdicts[row["id"]] = "MISS"

    out = []
    w = out.append
    w("# qinjing benchmark report")
    w("")
    w("- corpus: `%s`" % corpus_path)
    w("- corpus-sha256: %s" % file_sha256(corpus_path))
    w("- exec log: `%s`" % log_path)
    w("- exec-log-sha256: %s" % file_sha256(log_path))
    w("- alerts-sha256: %s" % file_sha256(alerts_path))
    w("- cases: %d (%d fp + %d attack)"
      % (len(cases["false_positives"]) + len(cases["attacks"]),
         len(cases["false_positives"]), len(cases["attacks"])))
    if header.get("start"):
        w("- run: host=%s isolate=%s sleep=%s timeout=%s"
          % (header.get("host", "?"), header.get("isolate", "?"),
             header.get("sleep", "?"), header.get("timeout", "?")))
        if header.get("kernel") or header.get("distro"):
            w("- target: kernel=%s distro=%s"
              % (header.get("kernel", "?"), header.get("distro", "?")))
    if run_class["kind"] == "SUBSET":
        w("- run: SUBSET(%s) - statistics cover the declared subset only"
          % header.get("subset", "?"))
    w("- fetch: source=%s window=[%s, %s] count=%s complete=%s"
      % (fetch.get("source", "?"), fetch.get("window_lo_ms", "?"),
         fetch.get("window_hi_ms", "?"), len(alerts), fetch.get("complete")))
    w("- calibre: min_severity=%s grace_ms=%d "
      "v2.2(sim-builtin counted; fp verified+attempt tiers)"
      % (min_severity, grace_ms))
    matrix_path = os.path.join(
        os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
        "data", "attack-enterprise.txt")
    if os.path.exists(matrix_path):
        with open(matrix_path, encoding="ascii") as fh:
            for header in fh:
                if header.startswith("# Source:") and "ATT&CK" in header:
                    w("- attack_matrix: %s"
                      % header.split("ATT&CK", 1)[1].strip(". \n"))
                    break
    w("- alerts analyzed: %d attributed, %d stray"
      % (len(attributed), len(stray)))
    if stray:
        reason_counts = {}
        for _, why in stray:
            reason_counts[why] = reason_counts.get(why, 0) + 1
        w("- stray reasons: %s" % ", ".join(
            "%s=%d" % (why, reason_counts[why])
            for why in sorted(reason_counts)))
    if run_tag:
        w("- attribution: %d by marker, %d by window (run tag %s)"
          % (marker_hits, len(attributed) - marker_hits, run_tag))
    if nohost_admitted:
        w("- attribution: no-host (degraded) - %d alert(s) carried no host"
          " identity; single-host legacy export only, not for cross-product"
          " main-column comparison" % nohost_admitted)
    w("- attribution basis: marker=%d, expected-window=%d, in-progress=%d,"
      " first-covering=%d, late-claimed=%d"
      % (basis_counts["marker"], basis_counts["expected-window"],
         basis_counts["in-progress"], basis_counts["first-covering"],
         basis_counts["late-claimed"]))
    w("- ambiguous attributions: %d" % len(ambiguous))
    for alert, holder_id, competing in ambiguous[:10]:
        w("- ambiguous: %s -> %s ambiguous(%s)"
          % (alert.get("timestamp"), holder_id, ",".join(competing)))

    attack_rows = [r for r in rows if r["case"]["group"] == "attack"]
    fp_rows = [r for r in rows if r["case"]["group"] == "fp"]

    # Per-case matrix is behind --verbose at 1000+ scale (S5).
    if verbose:
        w("")
        w("## Detection matrix (attack cases)")
        w("")
        w("| ID | Tactic | Tech | Mode | Command | Expected signals |"
          " Observed | Verdict | AnyHit |")
        w("|---|---|---|---|---|---|---|---|---|")
        for row in attack_rows:
            case = row["case"]
            cmd = case["cmd"] if len(case["cmd"]) <= 48 \
                else case["cmd"][:45] + "..."
            bucket = case.get("bucket", "")
            cid = row["id"] + (" *" + bucket if bucket else "")
            obs = []
            for alert in row["observed"]:
                for klass in alert.get("signal_class", []):
                    if klass not in obs:
                        obs.append(klass)
            w("| %s | %s | %s | %s | `%s` | %s | %s | %s | %s |"
              % (cid, case["tactic"], case["technique"], case["mode"],
                 cmd, ", ".join(case.get("expected_signals", [])) or "-",
                 ", ".join(obs) or "-", verdicts[row["id"]],
                 "yes" if anyhit[row["id"]] else "-"))
        w("")
        w("(%d attack cases; use --verbose to see this table)"
          % len(attack_rows))

    w("")
    w("## False-positive group (benign ops, must stay below %s)"
      % min_severity)
    w("")
    w("| ID | Command | Observed | Verdict |")
    w("|---|---|---|---|")
    for row in fp_rows:
        case = row["case"]
        cmd = case["cmd"] if len(case["cmd"]) <= 48 \
            else case["cmd"][:45] + "..."
        seens = []
        for alert in row["observed"]:
            tag = "%s(%s)" % (alert.get("rule_id", "?"),
                              alert.get("severity", "?"))
            if tag not in seens:
                seens.append(tag)
        w("| %s | `%s` | %s | %s |"
          % (row["id"], cmd, ", ".join(seens) or "-",
             verdicts[row["id"]]))

    chains = {}
    for row in attack_rows:
        bucket = row["case"].get("bucket", "")
        if bucket:
            chains.setdefault(bucket, []).append(row)
    if chains:
        w("")
        w("## Kill-chain accumulation (shared buckets)")
        w("")
        w("| Chain | Chain verdict | Steps detected | Expected union |")
        w("|---|---|---|---|")
        for name in sorted(chains):
            expected_union = []
            observed_union = []
            for row in chains[name]:
                for klass in row["case"].get("expected_signals", []):
                    if klass not in expected_union:
                        expected_union.append(klass)
                for alert in row["observed"]:
                    for klass in alert.get("signal_class", []):
                        if klass not in observed_union:
                            observed_union.append(klass)
            covered = [k for k in expected_union if k in observed_union]
            steps_hit = sum(1 for row in chains[name]
                            if verdicts[row["id"]] == "HIT")
            if expected_union and len(covered) == len(expected_union):
                chain_verdict = "HIT"
            elif covered:
                chain_verdict = "PARTIAL (%d/%d classes)" % (len(covered),
                                                             len(expected_union))
            elif expected_union:
                chain_verdict = "MISS (0/%d classes)" % len(expected_union)
            else:
                chain_verdict = "N/A"
            w("| %s | %s | %d/%d | %s |"
              % (name, chain_verdict, steps_hit, len(chains[name]),
                 ", ".join(expected_union) or "-"))
        w("")
        w("Chain verdicts use class-union semantics (docs/05 D12): the union")
        w("of expected classes must appear in the union of attributed classes.")
        w("A (host, uid)-aggregating product collapses these steps into one alert")
        w("and still scores chain HIT, while the per-case rows below can carry")
        w("debt the chain row does not.")
        w("")
        w("| Chain | Case | Expected | Verdict | AnyHit |")
        w("|---|---|---|---|---|")
        for name in sorted(chains):
            for row in chains[name]:
                w("| %s | %s | %s | %s | %s |"
                  % (name, row["id"],
                     ", ".join(row["case"].get("expected_signals", [])) or "-",
                     verdicts[row["id"]],
                     "yes" if anyhit[row["id"]] else "-"))

    if run_class["kind"] == "INTERRUPTED":
        w("")
        w("## run: INTERRUPTED - not publishable")
        w("")
        for problem in run_class["problems"]:
            w("- problem: %s" % problem)
        recon = run_class["recon"]
        w("")
        w("| planned | executed | missing | duplicate | transport_invalid |")
        w("|---|---|---|---|---|")
        w("| %s | %d | %d | %d | %d |"
          % (recon["planned"], recon["executed"], recon["missing"],
             recon["dup"], recon["transport"]))
        if run_class["missing_ids"]:
            w("")
            w("- missing ids: %s" % ", ".join(run_class["missing_ids"]))
        if run_class["dup_detail"]:
            w("- duplicate ids: %s" % ", ".join(run_class["dup_detail"]))
    else:
        runnable = [r for r in attack_rows
                    if in_denominator(r) and r["rc"] != "255"]
        notrun = len(attack_rows) - len(runnable)
        builtin_den = [r for r in runnable
                       if r["case"]["mode"] == "sim-builtin"]
        det = [r for r in runnable if r["case"]["expect"] == "detectable"]
        transport_rows = sum(1 for r in attack_rows if r["rc"] == "255")

        def rate(num, den):
            if not den:
                return "N/A"
            return "%d/%d = %.0f%%" % (num, den, 100.0 * num / den)

        det_hit = [r for r in det if verdicts[r["id"]] in ("HIT",)
                   or verdicts[r["id"]].startswith("PARTIAL")]
        det_strict = [r for r in det if verdicts[r["id"]] == "HIT"]
        det_any = [r for r in det if anyhit[r["id"]]]
        fp_evaluable = [r for r in fp_rows
                        if in_denominator(r) and r["rc"] != "255"]
        fp_notrun = len(fp_rows) - len(fp_evaluable)
        fp_viol = [r for r in fp_evaluable
                   if verdicts[r["id"]] == "FALSE POSITIVE"]

        # Two-tier FP denominator (calibre v2.2): verified operations
        # (rc matches declared verify_rc) are the primary tier; attempts
        # with non-matching rc are diagnostic; FP counts in all tiers.
        fp_verified = []
        fp_attempt = []
        fp_legacy = []
        for r in fp_evaluable:
            verify = r["case"].get("verify_rc")
            if verify is None or verify == "":
                fp_legacy.append(r)
            elif str(r.get("rc", "")) == str(verify):
                fp_verified.append(r)
            else:
                fp_attempt.append(r)
        fp_viol_verified = [r for r in fp_verified
                             if verdicts[r["id"]] == "FALSE POSITIVE"]

        w("")
        w("## Statistics")
        w("")
        w("- attack cases: %d isolated+chain (not-run excluded: %d;"
          " builtin in denominator: %d)"
          % (len(attack_rows), notrun, len(builtin_den)))
        if transport_rows:
            w("- transport-invalid rows (rc=255): %d excluded from every"
              " denominator" % transport_rows)
        w("- benign cases: %d (evaluable: %d; not-run: %d;"
          " verified: %d, attempt-only: %d, legacy: %d)"
          % (len(fp_rows), len(fp_evaluable), fp_notrun,
             len(fp_verified), len(fp_attempt), len(fp_legacy)))
        w("- detection rate (>=1 expected signal): **%s** of detectable"
          % rate(len(det_hit), len(det)))
        w("- detection rate (all expected, strict): %s"
          % rate(len(det_strict), len(det)))
        w("- any-hit rate (fallback calibre, no signal mapping needed): %s"
          % rate(len(det_any), len(det)))
        w("- FP rate on verified operations (v2.2 primary): %s"
          % rate(len(fp_viol_verified), len(fp_verified)))
        w("- FP rate on all attempts (v2.1 fallback): %s"
          % rate(len(fp_viol), len(fp_evaluable)))

        # Per-signal-class summary (S5 + G4 latency + G3 tech-tag).
        # A class counts as detected only when it appears in the attributed
        # alerts' signal_class sets; every evaluated instance is detected or
        # missed, so each row reconciles as Cases = Detected + Missed
        # (docs/03) - a PARTIAL case's undetected expected class counts as
        # Missed here instead of landing in no column. Tech-tag counts only
        # detections whose alert carried the case's technique id under a
        # native label_source: adapter- or reviewer-supplied labels do not
        # measure the product's own tagging quality (docs/02). Latency =
        # alert_ts - case_start for matching alerts (attribution-window
        # proxy, not true MTTD since the canonical timestamp may be
        # event/alert/ingest time).
        class_stats = {}
        for row in runnable:
            case = row["case"]
            observed_classes = set()
            tagged_classes = set()
            case_tech = case.get("technique", "")
            for alert in row["observed"]:
                ts = alert.get("_ts_ms", 0)
                tech_here = case_tech and \
                    alert.get("label_source") == "native" and \
                    case_tech in alert.get("mitre_attack", [])
                for klass in alert.get("signal_class", []):
                    observed_classes.add(klass)
                    if tech_here:
                        tagged_classes.add(klass)
                    if klass in case.get("expected_signals", []):
                        latency = ts - row["start_ms"]
                        if latency >= 0:
                            e2 = class_stats.setdefault(klass,
                                                        {"n": 0, "hit": 0,
                                                         "miss": 0,
                                                         "latencies": [],
                                                         "tagged": 0})
                            e2["latencies"].append(latency)
            for klass in case.get("expected_signals", []):
                entry = class_stats.setdefault(klass,
                                               {"n": 0, "hit": 0,
                                                "miss": 0, "latencies": [],
                                                "tagged": 0})
                entry["n"] += 1
                if klass in observed_classes:
                    entry["hit"] += 1
                else:
                    entry["miss"] += 1
                if klass in tagged_classes:
                    entry["tagged"] += 1
        w("")
        w("| Signal class | Cases | Detected | Missed | Hit rate |"
          " Med lat (ms) | Tech-tag |")
        w("|---|---|---|---|---|---|---|")
        for klass in sorted(class_stats, key=lambda k: -class_stats[k]["n"]):
            e = class_stats[klass]
            pct = "%.0f%%" % (100.0 * e["hit"] / e["n"]) if e["n"] else "-"
            lats = e.get("latencies", [])
            med_lat = int(sorted(lats)[len(lats) // 2]) if lats else None
            tagged = e.get("tagged", 0)
            tagged_pct = ("%d/%d" % (tagged, e["n"])) if tagged else "-"
            w("| %s | %d | %d | %d | %s | %s | %s |"
              % (klass, e["n"], e["hit"], e["miss"], pct,
                 med_lat if med_lat is not None else "-",
                 tagged_pct))

        def tactic_table(key, title):
            stats = {}
            for row in runnable:
                case = row["case"]
                entry = stats.setdefault(case[key],
                                         {"n": 0, "det": 0, "sig": 0,
                                          "any": 0})
                entry["n"] += 1
                if case["expect"] == "detectable":
                    entry["det"] += 1
                    verdict = verdicts[row["id"]]
                    if verdict == "HIT" or verdict.startswith("PARTIAL"):
                        entry["sig"] += 1
                    if anyhit[row["id"]]:
                        entry["any"] += 1
            w("")
            w("| %s | Cases | Detectable | Detected | AnyHit |" % title)
            w("|---|---|---|---|---|")
            for name in sorted(stats):
                entry = stats[name]
                w("| %s | %d | %d | %d | %d |"
                  % (name, entry["n"], entry["det"], entry["sig"],
                     entry["any"]))

        tactic_table("tactic", "Tactic")
        tactic_table("technique", "Technique")

        sev_count = {}
        for alert, _ in attributed:
            sev = alert.get("severity", "?")
            sev_count[sev] = sev_count.get(sev, 0) + 1
        w("")
        w("Alert severity distribution (attributed): "
          + (", ".join("%s=%d" % (k, sev_count[k])
                       for k in sorted(sev_count,
                                       key=lambda s: -SEV_ORDER.get(s, 0)))
             if sev_count else "none"))
        src_count = {}
        for alert, _ in attributed:
            source = alert.get("event_source") or "unstated"
            src_count[source] = src_count.get(source, 0) + 1
        w("Detections by event source (attributed): "
          + (", ".join("%s=%d" % (k, src_count[k])
                       for k in sorted(src_count, key=lambda s: -src_count[s]))
             if src_count else "none"))

    if stray:
        w("")
        w("## Stray alerts (excluded from scoring)")
        w("")
        for alert, why in stray[:20]:
            w("- %s %s %s: %s" % (alert.get("timestamp"),
                                  alert.get("severity"),
                                  alert.get("rule_id"), why))
    w("")
    w("## Reading notes")
    w("")
    w("- AnyHit counts any attributed alert at >=%s severity: use it when"
      % min_severity)
    w("  the adapter cannot map product rules to signal classes; the main")
    w("  verdict requires the expected signal class to appear.")
    w("- NOT-RUN (bin=0) cases are excluded from every rate: the target")
    w("  lacked the binary, so the case measured the environment, not the")
    w("  detector.")
    return "\n".join(out) + "\n", run_class["kind"]


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("corpus")
    ap.add_argument("exec_log")
    ap.add_argument("alerts")
    ap.add_argument("--min-severity", choices=sorted(SEV_ORDER),
                    default="high")
    ap.add_argument("--grace-ms", type=int, default=GRACE_MS_DEFAULT)
    ap.add_argument("--out", default=None,
                    help="write the report here instead of stdout")
    ap.add_argument("--verbose", action="store_true",
                    help="show the per-case detection matrix table")
    ap.add_argument("--allow-no-host", action="store_true",
                    help="score hostless alerts too (single-host legacy "
                         "export; the report discloses the degraded "
                         "attribution and is not cross-product comparable)")
    args = ap.parse_args(argv)
    try:
        report, run_kind = build_report(args.corpus, args.exec_log,
                                        args.alerts, args.min_severity,
                                        args.grace_ms,
                                        allow_no_host=args.allow_no_host,
                                        verbose=args.verbose)
    except (ValueError, OSError, json.JSONDecodeError) as exc:
        sys.stderr.write("scorer error: %s\n" % exc)
        return 1
    if args.out:
        with open(args.out, "w") as fh:
            fh.write(report)
        print("wrote %s" % args.out)
    else:
        sys.stdout.write(report)
    return 1 if run_kind == "INTERRUPTED" else 0


if __name__ == "__main__":
    sys.exit(main())
