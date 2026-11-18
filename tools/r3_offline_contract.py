"""Synthetic pre-labelled alert contracts for Qinjing R3, not HIDS detections.

Run: python -B tools/r3_offline_contract.py --repo /path/to/qinjing
Reads trusted local scorer/corpus. No runner, shell command, adapter, host,
network or result files. Log rows and alerts exist only in memory.
"""

import argparse
import builtins
import io
import json
import sys
from pathlib import Path
from unittest.mock import patch


CASES = {
    "WS01": "webshell_write",
    "GP02": "linker_hijack",
    "CT01": "container_escape",
    "SH01": "shell_config_persistence",
}
T0 = 1893456000000  # 2030-01-01 00:00:00Z; unrelated to actual collection
LOG = "fixture://qj-contract/row"
ALERTS = "fixture://qj-contract/alerts"


def check(ok, description):
    if not ok:
        raise AssertionError(description)


def score(scorer, corpus, case_id, alerts, *, group="attack", bin_found=1, rc=0,
          **fetch_overrides):
    # bin_found is a fictional input to exercise denominator logic, NOT an
    # assertion about tools/behaviour on any machine. The optional cmd field
    # is absent. A single-row SUBSET isolates the attribution window.
    log = (f"# QINJING start={T0} host=node-fixture plan=1 subset={case_id}\n"
           f"{T0}\t{T0 + 1000}\t{case_id}\t{group}\t1000\t{bin_found}\t{rc}\n"
           "# QINJING-END rows=1 transport_fail=0 rc=0\n")
    fetch = dict(source="synthetic-contract-only", complete=True,
                 count=len(alerts), window_lo_ms=T0, window_hi_ms=T0 + 4500)
    fetch.update(fetch_overrides)
    inputs = {LOG: log, ALERTS: json.dumps({"fetch": fetch, "alerts": alerts})}

    def read_only(path, mode="r", *args, **kwargs):
        if mode not in ("r", "rb"):
            raise AssertionError("Unexpected write attempted by scorer")
        if path not in inputs:
            return builtins.open(path, mode, *args, **kwargs)
        raw = inputs[path]
        return io.BytesIO(raw.encode("utf-8")) if mode == "rb" else io.StringIO(raw)

    # Route only two fake input names to memory; the real scorer, its parser,
    # its published corpus and its ATT&CK version metadata remain unmodified.
    with patch.object(scorer, "open", read_only, create=True):
        return scorer.build_report(str(corpus), LOG, ALERTS, "high", 3500,
                                  verbose=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo", required=True, type=Path)
    root = parser.parse_args().repo.resolve()
    sys.dont_write_bytecode = True
    sys.path.insert(0, str(root / "tools"))
    import scorer

    check(Path(scorer.__file__).resolve() == (root / "tools/scorer.py").resolve(),
          "Unexpected scorer module")
    corpus = root / "corpus/qinjing.yaml"
    cases = {c["id"]: c for c in scorer.parse_corpus(str(corpus))["attacks"]}
    results = guards = 0
    labels = list(CASES.values())
    for i, (case_id, label) in enumerate(CASES.items()):
        real = cases[case_id]
        check(real["expect"] == "detectable" and real["expected_signals"] == [label],
              f"{case_id}: published case/class contract changed")
        right = dict(timestamp="2030-01-01T00:00:00.500Z", event_kind="alert",
                     host={"name": "node-fixture"}, severity="high", signal_class=[label])
        other = labels[(i + 1) % len(labels)]
        scenarios = (
            # scenario, alerts, observed labels, verdict, anyhit, stray reason
            ("right", [right], label, "HIT", "yes", None),
            ("right-low", [dict(right, severity="low")], label, "HIT", "-", None),
            ("wrong-high", [dict(right, signal_class=[other])], other, "MISS", "yes", None),
            ("unmapped-high", [dict(right, signal_class=[])], "-", "MISS", "yes", None),
            ("empty", [], "-", "MISS", "-", None),
            ("telemetry", [dict(right, event_kind="telemetry")], "-", "MISS", "-", "stray(telemetry)"),
            ("foreign", [dict(right, host={"name": "other-fixture"})], "-", "MISS", "-", "stray(foreign host: other-fixture)"),
            ("hostless", [dict(right, host={})], "-", "MISS", "-", "stray(no host identity)"),
            ("outside", [dict(right, timestamp="2030-01-01T00:02:00Z")], "-", "MISS", "-", "outside run window (pre-existing noise)"),
        )
        for name, alerts, observed, verdict, anyhit, stray in scenarios:
            # The outside-run control assumes an adapter fetched a broader
            # window and returned an actual event within that declared window.
            overrides = {"window_hi_ms": T0 + 120000} if name == "outside" else {}
            report, kind = score(scorer, corpus, case_id, alerts, **overrides)
            context = f"{case_id}:{name}"
            lines = [l for l in report.splitlines() if l.startswith(f"| {case_id} |")]
            check(kind == "SUBSET" and len(lines) == 1, context + ": subset/row")
            # Parse from the right so literal pipes in the displayed corpus
            # command (never run or printed here) cannot move the verdict.
            cells = [v.strip() for v in lines[0].rstrip("|").rsplit("|", 4)[-4:]]
            check(cells == [label, observed, verdict, anyhit], context + ": matrix")
            excluded = int(stray is not None)
            check(f"- alerts analyzed: {len(alerts)-excluded} attributed, {excluded} stray" in report,
                  context + ": attribution count")
            if stray:
                check(f"- stray reasons: {stray}=1" in report, context + ": exclusion reason")
            results += 1
        for overrides, error in [
            ({"complete": False}, "fetch.complete"),
            ({"count": 0}, "fetch.count"),
            ({"window_hi_ms": T0 + 1000}, "does not cover run window"),
        ]:
            try:
                score(scorer, corpus, case_id, [right], **overrides)
            except ValueError as exc:
                check(error in str(exc), f"{case_id}: unexpected manifest error: {exc}")
            else:
                raise AssertionError(f"{case_id}: malformed manifest accepted: {overrides}")
            guards += 1
    fp_contracts = observations = 0
    fp01 = next(c for c in scorer.parse_corpus(str(corpus))["false_positives"]
                if c["id"] == "FP01")
    verify = fp01.get("verify_rc")
    # No actual FP01 action took place in any of these rows. Nonzero process
    # exits stay observational so a subsequent evidence-aware scorer is not
    # forced to reproduce the current false sense of a clean benign run.
    for bin_found, rc, required in [(1, 0, "clean"), (0, 0, "NOT-RUN (bin=0)"),
                                    (1, 1, None), (1, 124, None)]:
        report, kind = score(scorer, corpus, "FP01", [], group="fp", bin_found=bin_found, rc=rc)
        rows = [r for r in report.splitlines() if r.startswith("| FP01 |")]
        verdict = rows[0].rstrip("|").rsplit("|", 1)[-1].strip() if len(rows) == 1 else "(no unique row)"
        den = next((r for r in report.splitlines() if r.startswith("- benign cases:")), "(no statistics)")
        if required is not None:
            check(kind == "SUBSET" and verdict == required, f"FP01 bin={bin_found}, rc={rc}: {verdict}")
            # Calibre v2.2 widened the benign denominator line to
            # evaluable/not-run plus the verified / attempt-only / legacy
            # tier counts; mirror the tier split from the declared
            # verify_rc instead of trusting any hardcoded tier.
            expected_den = 1 if bin_found else 0
            if not bin_found:
                tiers = (0, 0, 0)
            elif verify is None or verify == "":
                tiers = (0, 0, 1)
            elif str(rc) == str(verify):
                tiers = (1, 0, 0)
            else:
                tiers = (0, 1, 0)
            check(f"evaluable: {expected_den}; not-run: {1-expected_den}; "
                  f"verified: {tiers[0]}, attempt-only: {tiers[1]}, "
                  f"legacy: {tiers[2]}" in den,
                  f"FP01 bin={bin_found}, rc={rc}: {den}")
            fp_contracts += 1
        else:
            observations += 1
            print(f"OBS (non-gating; fabricated run) FP01 bin={bin_found} rc={rc}: "
                  f"kind={kind}; verdict={verdict}; {den}")
    print(f"PASS [synthetic canonical -> scorer only]: {len(CASES)} existing signal classes; "
          f"{results} matrix scenarios + {guards} fetch rejections + {fp_contracts} FP controls"
          f" = {results + guards + fp_contracts} contracts; {observations} separate observations.")
    print("No detector, adapter or host was tested. No live coverage or FP claims.")


if __name__ == "__main__":
    main()
