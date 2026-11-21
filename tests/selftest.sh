#!/bin/bash
# qinjing toolchain selftest: synthetic exec log + canonical alerts must
# produce every verdict exactly once, and the contract gates must fire.
# Every check greps for an expected literal - no empty-pass assertions.

set -u
ROOT=$(cd "$(dirname "$0")/.." && pwd)
FIX="$ROOT/tests/fixture"
TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT

fails=0
check() {
  local desc="$1" got="$2" want="$3"
  if [ "$got" = "$want" ]; then
    echo "PASS: $desc"
  else
    echo "FAIL: $desc (got '$got' want '$want')"
    fails=$((fails + 1))
  fi
}
check_grep() {
  local desc="$1" pattern="$2" file="$3"
  if grep -Fq -- "$pattern" "$file"; then
    echo "PASS: $desc"
  else
    echo "FAIL: $desc (pattern '$pattern' not found in $file)"
    fails=$((fails + 1))
  fi
}
check_not_grep() {
  local desc="$1" pattern="$2" file="$3"
  if grep -Fq -- "$pattern" "$file"; then
    echo "FAIL: $desc (pattern '$pattern' unexpectedly found in $file)"
    fails=$((fails + 1))
  else
    echo "PASS: $desc"
  fi
}

echo "== fixture corpus lints =="
check "mini.yaml validates" \
  "$("$ROOT/tools/parse.py" --validate "$FIX/mini.yaml" 2>&1)" \
  "validate: OK, 8 cases (2 fp, 6 attack)"

echo "== runner syntax =="
bash -n "$ROOT/tools/runner.sh"
check "runner.sh passes bash -n" "$?" "0"

echo "== doctests =="
python3 -m doctest "$ROOT/tools/parse.py" "$ROOT/tools/scorer.py" 2>&1
check "parse+scorer doctests" "$?" "0"

echo "== scorer: complete fetch =="
REPORT="$TMP/report.md"
python3 "$ROOT/tools/scorer.py" "$FIX/mini.yaml" "$FIX/exec.log" \
  "$FIX/alerts-complete.json" --verbose --out "$REPORT" >/dev/null 2>"$TMP/scorer.err"
check "scorer exit code" "$?" "0"
check_grep "report head carries the attack-matrix version" \
  "- attack_matrix:" "$REPORT"
check_grep "report head carries target kernel/distro" \
  "- target: kernel=5.99-test distro=Test OS 7" "$REPORT"
check_grep "per-class summary shows PARTIAL-affected class as undetected" \
  "| net_recon_local | 1 | 0 |" "$REPORT"
check_grep "per-class summary unaffected class stays detected" \
  "| net_scan_external | 1 | 1 |" "$REPORT"
check_grep "C3: PARTIAL-missing class counts as Missed, row reconciles" \
  "| net_recon_local | 1 | 0 | 1 | 0% | - | - |" "$REPORT"
check_grep "C4: native label keeps Tech-tag on the detected class" \
  "| net_scan_external | 1 | 1 | 0 | 100% | 500 | 1/1 |" "$REPORT"
check_grep "C4: zero-detection class carries no Tech-tag credit" \
  "| net_recon_local | 1 | 0 | 1 | 0% | - | - |" "$REPORT"
check_grep "v2.2 tier split disclosed (verified/attempt/legacy)" \
  "verified: 0, attempt-only: 0, legacy: 2" "$REPORT"
check_grep "v2.2 primary FP rate line present" \
  "FP rate on verified operations" "$REPORT"
check_grep "v2.2 fallback FP rate line present" \
  "FP rate on all attempts (v2.1 fallback)" "$REPORT"
check_grep "event-source tally present" \
  "Detections by event source (attributed): unstated=6, execve=1" "$REPORT"

check_grep "T01 carries two expected signals" \
  "net_scan_external, net_recon_local" "$REPORT"
check_grep "T01 partial verdict" "PARTIAL (1/2)" "$REPORT"
check_grep "T02 full hit" "| HIT | yes |" "$REPORT"
check_grep "T03 miss" "| MISS | - |" "$REPORT"
check_grep "T04 not-run despite attributed alert" "NOT-RUN (bin=0)" "$REPORT"
check_grep "G01 unexpected hit" "| UNEXPECTED-HIT | - |" "$REPORT"
check_grep "F01 false positive" "| FALSE POSITIVE |" "$REPORT"
check_grep "F02 below-threshold noise" "noise (below high)" "$REPORT"
check_grep "signal rate 3/4" \
  "detection rate (>=1 expected signal): **3/4 = 75%** of detectable" "$REPORT"
check_grep "strict rate 2/4" \
  "detection rate (all expected, strict): 2/4 = 50%" "$REPORT"
check_grep "any-hit rate 3/4" \
  "any-hit rate (fallback calibre, no signal mapping needed): 3/4 = 75%" "$REPORT"
check_grep "not-run excluded from denominator" "not-run excluded: 1" "$REPORT"
check_grep "builtin denominator disclosure" "builtin in denominator: 2" "$REPORT"
check_grep "attribution counts" "alerts analyzed: 7 attributed, 1 stray" "$REPORT"
python3 - "$REPORT" >"$TMP/t05check.out" 2>&1 <<'PYEOF'
import sys

for line in open(sys.argv[1], encoding="utf-8"):
    if line.startswith("| T05 "):
        print("t05-hit" if "| HIT |" in line else "t05-not-hit")
        break
else:
    print("t05-row-missing")
PYEOF
check "sim-builtin counts despite bin=0" \
  "$(cat "$TMP/t05check.out")" "t05-hit"
check_grep "stray reason listed" "outside run window (pre-existing noise)" "$REPORT"

echo "== scorer: --out-json machine-readable report (dashboard U1) =="
JSONREP="$TMP/report.json"
python3 "$ROOT/tools/scorer.py" "$FIX/mini.yaml" "$FIX/exec.log" \
  "$FIX/alerts-complete.json" --out-json "$JSONREP" >"$TMP/json.out" 2>"$TMP/json.err"
check "scorer --out-json exits 0" "$?" "0"
check_grep "--out-json names the written file" "wrote " "$TMP/json.out"
python3 - "$JSONREP" "$FIX/mini.yaml" >"$TMP/jsoncheck.out" 2>&1 <<'PYEOF'
import hashlib
import json
import sys

data = json.load(open(sys.argv[1], encoding="utf-8"))
csha = hashlib.sha256(open(sys.argv[2], "rb").read()).hexdigest()
bad = []
m = data["meta"]
if m["corpus_sha256"] != csha:
    bad.append("corpus_sha256 mismatch")
if m["calibre"] != "v2.2" or m["run_kind"] != "COMPLETE":
    bad.append("meta calibre/run_kind")
if data["totals"] != {"cases": 8, "fp": 2, "attack": 6}:
    bad.append("totals %s" % data["totals"])
d = data["detection"]
if (d["detectable"], d["hit"], d["strict"], d["anyhit"], d["notrun"]) != (4, 3, 2, 3, 1):
    bad.append("detection counts %s" % d)
if (d["signal_rate"], d["strict_rate"], d["anyhit_rate"]) != (0.75, 0.5, 0.75):
    bad.append("detection rates")
f = data["fp"]
if (f["verified"], f["attempt"], f["legacy"], f["violations"]) != (0, 0, 2, 1):
    bad.append("fp tiers %s" % f)
if f["attempt_rate"] != 0.5 or f["verified_rate"] is not None:
    bad.append("fp rates")
for row in data["per_class"]:
    if row["cases"] != row["detected"] + row["missed"]:
        bad.append("per_class equation %s" % row["class"])
by_class = {r["class"]: r for r in data["per_class"]}
nse = by_class.get("net_scan_external", {})
if (nse.get("detected"), nse.get("median_latency_ms"), nse.get("tech_tagged")) != (1, 500, 1):
    bad.append("net_scan_external row %s" % nse)
if by_class.get("net_recon_local", {}).get("detected") != 0:
    bad.append("net_recon_local must be undetected")
if not data.get("by_tactic") or not data.get("by_technique"):
    bad.append("by_tactic/by_technique empty")
print("json-ok" if not bad else "json-broken: " + "; ".join(bad))
PYEOF
check "--out-json reconciles with the markdown report" \
  "$(cat "$TMP/jsoncheck.out")" "json-ok"

echo "== scorer: incomplete fetch must refuse =="
python3 "$ROOT/tools/scorer.py" "$FIX/mini.yaml" "$FIX/exec.log" \
  "$FIX/alerts-incomplete.json" >"$TMP/inc.out" 2>"$TMP/inc.err"
check "scorer exits 1 on complete=false" "$?" "1"
check_grep "refusal names the fetch contract" "fetch.complete is not true" "$TMP/inc.err"

python3 - "$ROOT/tools/scorer.py" "$FIX" >"$TMP/win.out" 2>"$TMP/win.err" <<'PYEOF'
import json
import sys
import tempfile
import os

scorer, fix = sys.argv[1], sys.argv[2]
data = json.load(open(os.path.join(fix, "alerts-complete.json"), encoding="utf-8"))
data["fetch"]["window_hi_ms"] = 1794818010000
with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as fh:
    json.dump(data, fh)
    path = fh.name
os.system("%s %s %s %s %s" % (sys.executable, scorer,
                              os.path.join(fix, "mini.yaml"),
                              os.path.join(fix, "exec.log"), path))
PYEOF
check_grep "refusal names the window gap" "does not cover run window" "$TMP/win.err"

echo "== fpcheck tight window =="
python3 "$ROOT/tools/fpcheck_tight.py" "$FIX/exec.log" \
  "$FIX/alerts-complete.json" >"$TMP/fp.out" 2>&1
check "fpcheck exits 1 on violation" "$?" "1"
check_grep "F01 flagged with bin annotation" "F01 (bin=1) VIOLATION" "$TMP/fp.out"
check_grep "one violation" "violations: 1" "$TMP/fp.out"
check_grep "crosstalk detail: no same-window attacks" "same-window-attacks=[]" "$TMP/fp.out"
check_grep "F02 clean with bin annotation" "F02 (bin=1) clean" "$TMP/fp.out"

echo "== integrity gates (refuse unverifiable reads) =="
python3 "$ROOT/tools/fpcheck_tight.py" "$FIX/exec.log" \
  "$FIX/alerts-incomplete.json" >"$TMP/fpbad.out" 2>"$TMP/fpbad.err"
check "fpcheck exits 2 on incomplete fetch" "$?" "2"
check_grep "fpcheck refusal names completeness" \
  "fetch.complete is not true" "$TMP/fpbad.err"

python3 "$ROOT/tools/scorer.py" "$FIX/mini.yaml" "$FIX/exec.log" \
  "$FIX/alerts-countbad.json" >"$TMP/cb.out" 2>"$TMP/cb.err"
check "scorer exits 1 on count mismatch" "$?" "1"
check_grep "scorer refusal names the manifest mismatch" \
  "does not match len(alerts)" "$TMP/cb.err"

python3 "$ROOT/tools/fpcheck_tight.py" "$FIX/exec-noFp.log" \
  "$FIX/alerts-complete.json" >"$TMP/nofp.out" 2>&1
check "fpcheck exits 0 with no benign rows" "$?" "0"
check_grep "N/A stated explicitly" "N/A: no benign rows" "$TMP/nofp.out"

echo "== xiezhi reference adapter =="
CANON="$TMP/canonical.json"
python3 "$ROOT/adapters/xiezhi/alerts_to_canonical.py" \
  "$FIX/xiezhi-dump.json" "$FIX/exec.log" "$CANON" >"$TMP/adp.out" 2>&1
check "adapter exit code" "$?" "0"
check "adapter conversion summary" \
  "$(grep -F 'converted 3 alerts (dropped 1 firstseen, 0 unmapped rule ids)' \
    "$TMP/adp.out" >/dev/null && echo ok)" "ok"
check_grep "fetch window from exec log" '"window_lo_ms": 1794818001000' "$CANON"
check_not_grep "firstseen dropped from output" '"rule_id": "firstseen/' "$CANON"
python3 - "$CANON" >"$TMP/mapcheck.out" 2>&1 <<'PYEOF'
import json
import sys

data = json.load(open(sys.argv[1], encoding="utf-8"))
by_rule = {a["rule_id"]: a for a in data["alerts"]}
ok = (len(data["alerts"]) == 3
      and "firstseen/host-alpha" not in by_rule
      and by_rule["exec-recon-nmap"]["signal_class"] == ["net_scan_external"]
      and by_rule["intent/reverse_shell"]["signal_class"] == ["reverse_shell"]
      and by_rule["exec-cred-shadow-read"]["severity"] == "critical"
      and data["fetch"]["complete"] is False)
print("mapping-ok" if ok else "mapping-broken")
PYEOF
check "signal mapping table applied" "$(cat "$TMP/mapcheck.out")" "mapping-ok"

python3 "$ROOT/tools/scorer.py" "$FIX/mini.yaml" "$FIX/exec.log" "$CANON" \
  >"$TMP/adpscore.out" 2>"$TMP/adpscore.err"
check "scorer refuses incomplete adapter output" "$?" "1"

python3 "$ROOT/adapters/xiezhi/alerts_to_canonical.py" \
  "$FIX/xiezhi-dump.json" "$FIX/exec.log" "$CANON" --complete >/dev/null 2>&1
python3 "$ROOT/tools/scorer.py" "$FIX/mini.yaml" "$FIX/exec.log" "$CANON" \
  >"$TMP/adpscore2.out" 2>&1
check "scorer accepts complete adapter output" "$?" "0"

echo "== marker attribution =="
REPORT2="$TMP/report2.md"
python3 "$ROOT/tools/scorer.py" "$FIX/mini.yaml" "$FIX/exec-marked.log" \
  "$FIX/alerts-marked.json" --verbose --out "$REPORT2" >/dev/null 2>&1
check "marker scorer exit code" "$?" "0"
check_grep "attribution split note" "attribution: 1 by marker, 1 by window" "$REPORT2"
check_grep "stale-tag marker fell back to window (T02 still HIT)" \
  "detection rate (all expected, strict): 2/4 = 50%" "$REPORT2"
python3 - "$REPORT2" >"$TMP/mkcheck.out" 2>&1 <<'PYEOF'
import sys

for line in open(sys.argv[1], encoding="utf-8"):
    if line.startswith("| T03 "):
        print("t03-hit" if "| HIT |" in line else "t03-not-hit")
        break
else:
    print("t03-row-missing")
PYEOF
check "marker claimed T03 out of its own window" \
  "$(cat "$TMP/mkcheck.out")" "t03-hit"

row_verdict() {
  python3 - "$1" "$2" <<'PYEOF'
import sys

want_id, path = sys.argv[1], sys.argv[2]
for line in open(path, encoding="utf-8"):
    if line.startswith("| %s " % want_id) or line.startswith("| %s *" % want_id):
        cells = [c.strip() for c in line.strip().strip("|").split("|")]
        print("%s | %s" % (cells[-2], cells[-1]) if len(cells) > 4
              else cells[-1])
        break
else:
    print("row-missing")
PYEOF
}

echo "== D5: benign evaluable set (fp bin=0 is NOT-RUN, not clean) =="
Q2REPORT="$TMP/q2report.md"
python3 "$ROOT/tools/scorer.py" "$FIX/mini.yaml" "$FIX/q2-exec.log" \
  "$FIX/q2-alerts.json" --verbose --out "$Q2REPORT" >/dev/null 2>"$TMP/q2.err"
check "q2 scorer exits 0 (complete run, nothing evaluable)" "$?" "0"
check "q2 F01 is NOT-RUN, not a false clean" \
  "$(row_verdict F01 "$Q2REPORT")" "NOT-RUN (bin=0)"
check_grep "q2 benign evaluable count is zero" \
  "benign cases: 1 (evaluable: 0; not-run: 1;" "$Q2REPORT"
check_grep "q2 FP rate is N/A, not 0/0=0%" \
  "FP rate on all attempts (v2.1 fallback): N/A" "$Q2REPORT"
check_grep "calibre stamp is v2.1" \
  "v2.2(sim-builtin counted; fp verified+attempt tiers)" "$Q2REPORT"

python3 "$ROOT/tools/fpcheck_tight.py" "$FIX/q2-exec.log" \
  "$FIX/q2-alerts.json" >"$TMP/q2fp.out" 2>&1
check "q2 fpcheck exits 0 (nothing evaluable)" "$?" "0"
check_grep "q2 fpcheck marks bin=0 row NOT-RUN" "F01 (bin=0) NOT-RUN" "$TMP/q2fp.out"
check_grep "q2 fpcheck states N/A for the whole group" \
  "N/A: no evaluable benign rows" "$TMP/q2fp.out"

echo "== D6: plan freeze and run reconciliation =="
R3A="$TMP/r3a.md"
python3 "$ROOT/tools/scorer.py" "$FIX/mini.yaml" "$FIX/r3-onlyT01.log" \
  "$FIX/alerts-complete.json" --verbose --out "$R3A" >/dev/null 2>&1
check "r3a (7 of 8 rows missing) exits 1" "$?" "1"
check_grep "r3a interrupted banner" \
  "run: INTERRUPTED - not publishable" "$R3A"
check_grep "r3a reconciliation table carries missing count" \
  "| 8 | 1 | 7 | 0 | 0 |" "$R3A"
check_grep "r3a missing ids listed" \
  "- missing ids: F01, F02, T02, T03, T04, T05, G01" "$R3A"
check_not_grep "r3a statistics suppressed" "## Statistics" "$R3A"

R3B="$TMP/r3b.md"
python3 "$ROOT/tools/scorer.py" "$FIX/mini.yaml" "$FIX/r3-dupT02.log" \
  "$FIX/alerts-complete.json" --verbose --out "$R3B" >/dev/null 2>&1
check "r3b (T02 duplicated) exits 1" "$?" "1"
check_grep "r3b duplicate ids disclosed" "- duplicate ids: T02 (x2)" "$R3B"
check_grep "r3b reconciliation table" "| 8 | 9 | 0 | 1 | 0 |" "$R3B"

R3C="$TMP/r3c.md"
python3 "$ROOT/tools/scorer.py" "$FIX/mini.yaml" "$FIX/exec-noFp.log" \
  "$FIX/alerts-complete.json" --verbose --out "$R3C" >/dev/null 2>&1
check "pre-freeze log format (no plan/END) exits 1" "$?" "1"
check_grep "pre-freeze refusal names the missing plan header" \
  "plan header missing (pre-freeze log format, plan not frozen)" "$R3C"

echo "== D6: explicit subset runs =="
Q4A="$TMP/q4a.md"
python3 "$ROOT/tools/scorer.py" "$FIX/mini.yaml" "$FIX/q4.log" \
  "$FIX/q4-a.json" --verbose --out "$Q4A" >/dev/null 2>&1
check "q4a subset run exits 0" "$?" "0"
check_grep "q4a subset banner names the declared set" \
  "run: SUBSET(T02)" "$Q4A"
check "q4a T02 still HIT (regression control)" \
  "$(row_verdict T02 "$Q4A")" "HIT | yes"
check_grep "q4a FP rate N/A (benign not in subset)" \
  "FP rate on all attempts (v2.1 fallback): N/A" "$Q4A"

echo "== D7: transport-failed rows =="
Q4D="$TMP/q4d.md"
python3 "$ROOT/tools/scorer.py" "$FIX/mini.yaml" "$FIX/q4-d.log" \
  "$FIX/q4-d.json" --verbose --out "$Q4D" >/dev/null 2>&1
check "q4d rc=255 row still a scorable complete run" "$?" "0"
check "q4d verdict is RUN-INVALID and out of any-hit" \
  "$(row_verdict T02 "$Q4D")" "RUN-INVALID (transport) | -"
check_grep "q4d excluded from the any-hit denominator" \
  "any-hit rate (fallback calibre, no signal mapping needed): N/A" "$Q4D"
check_grep "q4d transport count disclosed" \
  "transport-invalid rows (rc=255): 1" "$Q4D"

echo "== D8: attribution identity gates =="
Q4B="$TMP/q4b.md"
python3 "$ROOT/tools/scorer.py" "$FIX/mini.yaml" "$FIX/q4.log" \
  "$FIX/q4-b.json" --verbose --out "$Q4B" >/dev/null 2>&1
check "q4b exits 0 (stray is a finding, not a failure)" "$?" "0"
check_grep "q4b foreign host alert becomes stray" \
  "stray(foreign host: other-host)" "$Q4B"
check "q4b T02 downgrades to MISS" "$(row_verdict T02 "$Q4B")" "MISS | -"

Q4C="$TMP/q4c.md"
python3 "$ROOT/tools/scorer.py" "$FIX/mini.yaml" "$FIX/q4.log" \
  "$FIX/q4-c.json" --verbose --out "$Q4C" >/dev/null 2>&1
check_grep "q4c telemetry event becomes stray" "stray(telemetry)" "$Q4C"
check "q4c T02 downgrades to MISS" "$(row_verdict T02 "$Q4C")" "MISS | -"
check_grep "q4c stray reasons counted" "stray(telemetry)=1" "$Q4C"

NH="$TMP/nohost.md"
python3 "$ROOT/tools/scorer.py" "$FIX/mini.yaml" "$FIX/q4.log" \
  "$FIX/q4-nohost.json" --verbose --out "$NH" >/dev/null 2>&1
check_grep "hostless alert defaults to stray" \
  "stray(no host identity)" "$NH"
check "hostless default keeps T02 MISS" "$(row_verdict T02 "$NH")" "MISS | -"
NHD="$TMP/nohost-degraded.md"
python3 "$ROOT/tools/scorer.py" "$FIX/mini.yaml" "$FIX/q4.log" \
  "$FIX/q4-nohost.json" --allow-no-host --verbose --out "$NHD" >/dev/null 2>&1
check "allow-no-host degraded run exits 0" "$?" "0"
check_grep "degraded mode disclosed in report head" \
  "attribution: no-host (degraded)" "$NHD"
check "degraded mode attributes the alert" \
  "$(row_verdict T02 "$NHD")" "HIT | yes"

echo "== D8: attribution basis and ambiguity =="
AMB="$TMP/amb.md"
python3 "$ROOT/tools/scorer.py" "$FIX/mini.yaml" "$FIX/q4-amb.log" \
  "$FIX/q4-amb.json" --verbose --out "$AMB" >/dev/null 2>&1
check "amb run exits 0" "$?" "0"
check_grep "ambiguous attribution counted" "ambiguous attributions: 1" "$AMB"
check_grep "ambiguous annotation names the competing cases" \
  "ambiguous(T01,T02)" "$AMB"
check "amb main column keeps current attribution (T02 HIT)" \
  "$(row_verdict T02 "$AMB")" "HIT | yes"
check_grep "basis distribution line" \
  "attribution basis: marker=0, expected-window=0, in-progress=0, first-covering=0, late-claimed=1" "$AMB"
check_grep "marker report carries basis line" \
  "attribution basis: marker=1, expected-window=1, in-progress=0, first-covering=0, late-claimed=0" "$REPORT2"

echo "== runner plan freeze (source contract; real runs are Linux-only) =="
check_grep "runner header freezes plan" 'plan=%s' "$ROOT/tools/runner.sh"
check_grep "runner header declares subset" 'subset=%s' "$ROOT/tools/runner.sh"
check_grep "runner writes END trailer" \
  '# QINJING-END rows=%s transport_fail=%s rc=%s' "$ROOT/tools/runner.sh"
check_grep "runner reserves rc=255 for transport (local remap)" \
  'rc=254' "$ROOT/tools/runner.sh"
check_grep "runner remaps a command-own 255 on the remote side too" \
  'exit 254' "$ROOT/tools/runner.sh"

echo "== D8: adapter host passthrough =="
check_grep "fetch metadata counts host identity" \
  '"host_identified": 2' "$CANON"
check_grep "adapter summarizes host coverage" \
  "host identity: 2/3 alerts carry host" "$TMP/adp.out"
python3 - "$CANON" >"$TMP/hostcheck.out" 2>&1 <<'PYEOF'
import json
import sys

data = json.load(open(sys.argv[1], encoding="utf-8"))
by_rule = {a["rule_id"]: a for a in data["alerts"]}
ok = (by_rule["exec-recon-nmap"]["host"] == {"id": "h1", "name": "selftest"}
      and by_rule["exec-cred-shadow-read"]["host"]["name"] == "selftest"
      and "host" not in by_rule["intent/reverse_shell"]
      and data["fetch"]["host_identified"] == 2
      and data["fetch"]["host_missing"] == 1)
print("host-ok" if ok else "host-broken")
PYEOF
check "adapter passes host through, counts the gap" \
  "$(cat "$TMP/hostcheck.out")" "host-ok"

echo "== D9: report self-hashing (docs/05) =="
sha_of() {
  python3 -c "import hashlib, sys; print(hashlib.sha256(open(sys.argv[1], 'rb').read()).hexdigest())" "$1"
}
CSHA=$(sha_of "$FIX/mini.yaml")
LSHA=$(sha_of "$FIX/exec.log")
ASHA=$(sha_of "$FIX/alerts-complete.json")
check_grep "report head carries corpus content hash" \
  "- corpus-sha256: $CSHA" "$REPORT"
check_grep "report head carries exec log content hash" \
  "- exec-log-sha256: $LSHA" "$REPORT"
check_grep "report head carries alerts content hash" \
  "- alerts-sha256: $ASHA" "$REPORT"
check_grep "report head carries parsed case counts" \
  "- cases: 8 (2 fp + 6 attack)" "$REPORT"
check "stats first line is the corpus hash" \
  "$("$ROOT/tools/parse.py" --stats "$FIX/mini.yaml" | head -1)" \
  "corpus_sha256: $CSHA"

echo "== D10: domain and side-effect path lint =="
hy() {
  local cmd="$1" impact="${2:-none}"
  python3 - "$ROOT/tools/parse.py" "$cmd" "$impact" <<'PYEOF'
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(sys.argv[1])))
import parse

errors = parse.cmd_hygiene_errors(sys.argv[2], sys.argv[3])
print("\n".join(errors) if errors else "ok")
PYEOF
}
check "domain lint passes reserved suffix .example" \
  "$(hy 'dig AXFR e.example')" "ok"
check "domain lint passes example.com itself" \
  "$(hy 'dig +short example.com A')" "ok"
check "domain lint flags real TLD host" \
  "$(hy 'dig AXFR evil.com')" \
  "non-TEST domain evil.com (allowed: example.com/org/net, suffixes .example/.invalid/.test/.localhost)"
check "qinjing tmp write passes at any impact" \
  "$(hy 'echo x > /tmp/qinjing-a' none)" "ok"
check "other tmp write target is flagged" \
  "$(hy 'echo x > /tmp/evil')" \
  "non-qinjing /tmp write target /tmp/evil (side-effect paths must live under /tmp/qinjing-*)"
check "system write with impact=none is an annotation contradiction" \
  "$(hy 'echo x >> /etc/cron.d/x' none)" \
  "system write /etc/cron.d/x but impact=none (need temporary or destructive)"
check "same system write passes with impact=temporary" \
  "$(hy 'echo x >> /etc/cron.d/x' temporary)" "ok"
check "cp destination flagged, read operand not" \
  "$(hy 'cp /etc/hosts /tmp/x' none)" \
  "non-qinjing /tmp write target /tmp/x (side-effect paths must live under /tmp/qinjing-*)"
check "cp of system file into qinjing tmp passes" \
  "$(hy 'cp /etc/hosts /tmp/qinjing-copy' none)" "ok"
check "python -m dotted module path is not a hostname" \
  "$(hy 'printf x | python3 -I -B -m json.tool')" "ok"
check "python -m http.server module path passes the same way" \
  "$(hy 'python3 -m http.server')" "ok"
check "scheme-separated subdomain still passes after the -m fix" \
  "$(hy 'curl http://c2.tun.example.com/x')" "ok"
check "main corpus passes the hygiene lint" \
  "$("$ROOT/tools/parse.py" --validate "$ROOT/corpus/qinjing.yaml" 2>&1)" \
  "validate: OK, 1076 cases (120 fp, 956 attack)"

echo "== T1: duplicate-cmd gate (docs/11, owner decision 5) =="
python3 - "$ROOT/tools/parse.py" "$ROOT/corpus/qinjing.yaml" >"$TMP/dupgate.out" 2>&1 <<'PYEOF'
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(sys.argv[1])))
import parse

cases = parse.parse_corpus(sys.argv[2])
live = {}
for section in ("false_positives", "attacks"):
    for case in cases[section]:
        cmd = case.get("cmd", "")
        if cmd:
            live.setdefault(cmd, set()).add(case.get("id"))
live = frozenset((cmd, frozenset(ids)) for cmd, ids in live.items()
                 if len(ids) > 1)
decision5 = [cmd for cmd, ids in parse.DUPLICATE_CMD_REGISTRY
             if ids in (frozenset(("FP66", "VR079")),
                        frozenset(("FP111", "VR641")),
                        frozenset(("FP113", "VR643")))]
ok = parse.duplicate_cmd_errors(cases) == [] and \
    parse.DUPLICATE_CMD_REGISTRY == live
print("dup-gate-ok" if ok else "dup-gate-red")
print("registry-groups: %d" % len(parse.DUPLICATE_CMD_REGISTRY))
print("decision5-pairs: %d" % len(decision5))
PYEOF
check "main corpus: every duplicate group registered, registry exact" \
  "$(grep -F 'dup-gate-' "$TMP/dupgate.out" | head -1)" "dup-gate-ok"
check "registry carries six designed groups" \
  "$(grep -F 'registry-groups:' "$TMP/dupgate.out")" "registry-groups: 6"
check "owner decision 5 pairs registered" \
  "$(grep -F 'decision5-pairs:' "$TMP/dupgate.out")" "decision5-pairs: 3"
python3 - "$ROOT/tools/parse.py" >"$TMP/dupprobe.out" 2>&1 <<'PYEOF'
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(sys.argv[1])))
import parse


def probe(lines):
    return parse.duplicate_cmd_errors(parse.parse_lines(lines))


unregistered = probe([
    "false_positives:",
    "  - id: Z01",
    "    cmd: 'last -x'",
    "attacks:",
    "  - id: Z02",
    "    cmd: 'last -x'",
    ])
inflated = probe([
    "false_positives:",
    "  - id: FP05",
    "    cmd: 'ps aux'",
    "attacks:",
    "  - id: S01",
    "    cmd: 'ps aux'",
    "  - id: S02",
    "    cmd: 'ps aux'",
    ])
ok_unregistered = len(unregistered) == 1 and "not registered" in unregistered[0]
ok_inflated = len(inflated) == 1 and "not registered" in inflated[0]
print("unregistered-dup-rejected" if ok_unregistered
      else "unregistered-dup-missed: %s" % unregistered)
print("third-case-breaks-registration" if ok_inflated
      else "inflated-group-accepted: %s" % inflated)
PYEOF
check "unregistered same-cmd pair rejected" \
  "$(grep -F 'unregistered-dup-' "$TMP/dupprobe.out")" \
  "unregistered-dup-rejected"
check "exact-group match enforced (a third case on a registered cmd fails)" \
  "$(grep -F 'third-case-' "$TMP/dupprobe.out")" \
  "third-case-breaks-registration"

echo "== D11: cleanup fields drive the sweep =="
# 104 = 87 (85 migrated + VR549/VR550 from the docs/11 T4 reshapes) + 17
# real-mode local scratch writes that gained cleanup in the docs/11 T6
# idempotency round (VR118/124/135/213/259/269/364/365/368/369/370/372/389/
# 515/516/518/565). The T6 lint in parse.py --validate now fails any real
# case with a local /tmp/qinjing-* write and no cleanup.
check "cleanup export lists the migrated cases" \
  "$("$ROOT/tools/parse.py" --cleanup "$ROOT/corpus/qinjing.yaml" | wc -l | tr -d ' ')" \
  "104"
check_grep "FP09 carries its artifact cleanup" \
  "cleanup: rm -f /tmp/qinjing-backup.tar.gz" "$ROOT/corpus/qinjing.yaml"
check_grep "L04 cleans both key artifacts in one rm" \
  "cleanup: rm -f /tmp/qinjing-key /tmp/qinjing-key.pub" "$ROOT/corpus/qinjing.yaml"
check_grep "runner sweep is driven by corpus cleanup fields" \
  "--cleanup" "$ROOT/tools/runner.sh"
check_not_grep "runner sweep has no handwritten qinjing- paths left" \
  "rm -f /tmp/qinjing-" "$ROOT/tools/runner.sh"
python3 - "$ROOT/tools/parse.py" >"$TMP/cleanlint.out" 2>&1 <<'PYEOF'
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(sys.argv[1])))
import parse

cases = parse.parse_lines([
    "attacks:",
    "  - id: K99",
    "    tactic: TA0003",
    "    technique: NONE",
    "    name: cleanup lint probe",
    "    platforms: [linux]",
    "    cmd: 'echo hi'",
    "    bin: '-'",
    "    creates_process: false",
    "    mode: sim-builtin",
    "    expected_signals: []",
    "    related_signals: []",
    "    expect: gap",
    "    impact: none",
    "    cleanup: rm -rf /etc/passwd",
    ])
errors = parse.validate(cases)
print("cleanup-lint-fires" if errors and "cleanup" in errors[0]
      else "cleanup-lint-missing")
PYEOF
check "cleanup values are linted to the rm -f qinjing shape" \
  "$(cat "$TMP/cleanlint.out")" "cleanup-lint-fires"
python3 - "$ROOT/tools/parse.py" >"$TMP/cleansub.out" 2>&1 <<'PYEOF'
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(sys.argv[1])))
import parse


def cleanup_case(value):
    return parse.parse_lines([
        "attacks:",
        "  - id: K98",
        "    tactic: TA0003",
        "    technique: NONE",
        "    name: cleanup subpath probe",
        "    platforms: [linux]",
        "    cmd: 'echo hi'",
        "    bin: '-'",
        "    creates_process: false",
        "    mode: sim-builtin",
        "    expected_signals: []",
        "    related_signals: []",
        "    expect: gap",
        "    impact: none",
        "    cleanup: " + value,
        ])


ok_sub = not parse.validate(cleanup_case(
    "rm -f /tmp/qinjing-gitrepo1/.git/hooks/pre-commit"))
bad_dotdot = any("cleanup" in e for e in parse.validate(cleanup_case(
    "rm -f /tmp/qinjing-x/../../etc/passwd")))
bad_dot = any("cleanup" in e for e in parse.validate(cleanup_case(
    "rm -f /tmp/qinjing-x/./y")))
print("cleanup-subpath-ok" if ok_sub and bad_dotdot and bad_dot
      else "cleanup-subpath-broken")
PYEOF
check "cleanup allows scratch subpaths, rejects traversal segments" \
  "$(cat "$TMP/cleansub.out")" "cleanup-subpath-ok"
python3 - "$ROOT/tools/parse.py" >"$TMP/scratchlint.out" 2>&1 <<'PYEOF'
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(sys.argv[1])))
import parse


def scratch_case(cid, cmd, impact, cleanup=None):
    lines = [
        "attacks:",
        "  - id: " + cid,
        "    tactic: TA0006",
        "    technique: NONE",
        "    name: scratch lint probe",
        "    platforms: [linux]",
        "    cmd: '" + cmd + "'",
        "    bin: cp",
        "    creates_process: true",
        "    mode: real",
        "    expected_signals: []",
        "    related_signals: []",
        "    expect: gap",
        "    impact: " + impact,
        ]
    if cleanup is not None:
        lines.append("    cleanup: " + cleanup)
    return parse.parse_lines(lines)


def fires(cases):
    return any("scratch write" in e for e in parse.validate(cases))


bad_real = fires(scratch_case(
    "K97", "cp /etc/shadow /tmp/qinjing-probe", "temporary"))
cleaned = not fires(scratch_case(
    "K96", "cp /etc/shadow /tmp/qinjing-probe", "temporary",
    "rm -f /tmp/qinjing-probe"))
remote_exempt = not fires(scratch_case(
    "K95", 'ssh user@203.0.113.9 "cat > /tmp/qinjing-remote"', "none"))
tee_source_exempt = not fires(scratch_case(
    "K94", "tee -a /root/.ssh/authorized_keys < /tmp/qinjing-src.pub",
    "destructive"))
print("scratch-lint-ok" if bad_real and cleaned and remote_exempt
      and tee_source_exempt else "scratch-lint-broken")
PYEOF
check "T6 lint: real local scratch write needs cleanup; remote/tee-source exempt" \
  "$(cat "$TMP/scratchlint.out")" "scratch-lint-ok"

echo "== T7: benign verify_rc contract (docs/11 T7/F8, 2026-11-21 target rc) =="
python3 - "$ROOT" >"$TMP/t7decl.out" 2>&1 <<'PYEOF'
import os
import sys

root = sys.argv[1]
sys.path.insert(0, os.path.join(root, "tools"))
import parse

cases = parse.parse_corpus(os.path.join(root, "corpus", "qinjing.yaml"))
fp = {c["id"]: c for c in cases["false_positives"]}
bad = []
# curl probes: no listener on the reference bench -> measured rc 7.
for cid in ("FP04", "FP116", "FP117", "FP118"):
    if fp[cid].get("verify_rc") != "7":
        bad.append(cid + " verify_rc!=7")
    if fp[cid].get("mode") != "real":
        bad.append(cid + " mode!=real")
# nc probes: nc absent from the reference image -> sim-missing-bin (NOT-RUN
# there); verify_rc stays 0 (the successful-run contract, inert when bin=0).
for cid in ("FP20", "FP119", "FP120"):
    if fp[cid].get("mode") != "sim-missing-bin":
        bad.append(cid + " mode!=sim-missing-bin")
    if fp[cid].get("bin") != "nc":
        bad.append(cid + " bin!=nc")
    if fp[cid].get("verify_rc") != "0":
        bad.append(cid + " verify_rc!=0")
# FP117 must expose curl's rc through the head pipeline.
if "set -o pipefail;" not in fp["FP117"]["cmd"]:
    bad.append("FP117 missing pipefail")
print("t7-decl-ok" if not bad else "t7-decl-broken: " + ",".join(bad))
PYEOF
check "T7 declarations: curl probes verify_rc 7, nc probes sim-missing-bin, FP117 pipefail" \
  "$(cat "$TMP/t7decl.out")" "t7-decl-ok"
T7REP="$TMP/t7.md"
python3 "$ROOT/tools/scorer.py" "$ROOT/corpus/qinjing.yaml" "$FIX/t7-exec.log" \
  "$FIX/t7-alerts.json" --out "$T7REP" >/dev/null 2>"$TMP/t7.err"
check "T7 reference-bench subset run exits 0" "$?" "0"
check_grep "T7 subset banner names the seven probes" \
  "run: SUBSET(FP04,FP20,FP116,FP117,FP118,FP119,FP120)" "$T7REP"
check_grep "T7 curl probes verified (rc7 matches), nc probes NOT-RUN" \
  "benign cases: 7 (evaluable: 4; not-run: 3; verified: 4, attempt-only: 0, legacy: 0)" "$T7REP"
check_grep "T7 verified-tier FP rate defined (0/4, not the pre-fix N/A)" \
  "FP rate on verified operations (v2.2 primary): 0/4 = 0%" "$T7REP"

echo "== D12: chain-level verdicts =="
chain_row_verdict() {
  python3 - "$1" "$2" <<'PYEOF'
import sys

want_id, path = sys.argv[1], sys.argv[2]
prefix = "| chain-T | %s |" % want_id
for line in open(path, encoding="utf-8"):
    if line.startswith(prefix):
        cells = [c.strip() for c in line.strip().strip("|").split("|")]
        print("%s | %s" % (cells[-2], cells[-1]))
        break
else:
    print("row-missing")
PYEOF
}
AGG="$TMP/chain-agg.md"
python3 "$ROOT/tools/scorer.py" "$FIX/chain.yaml" "$FIX/chain.log" \
  "$FIX/chain-agg.json" --verbose --out "$AGG" >/dev/null 2>&1
check "aggregated chain run exits 0" "$?" "0"
check_grep "single aggregated alert yields chain HIT with step debt count" \
  "| chain-T | HIT | 1/3 |" "$AGG"
check "per-case debt stays visible under aggregation (K2 MISS)" \
  "$(chain_row_verdict K2 "$AGG")" "MISS | -"
check_grep "chain section carries the aggregation warning" \
  "collapses these steps into one alert" "$AGG"
PART="$TMP/chain-partial.md"
python3 "$ROOT/tools/scorer.py" "$FIX/chain.yaml" "$FIX/chain.log" \
  "$FIX/chain-partial.json" --verbose --out "$PART" >/dev/null 2>&1
check "partial chain run exits 0" "$?" "0"
check_grep "missing expected class yields chain PARTIAL with class counts" \
  "| chain-T | PARTIAL (2/3 classes) | 2/3 |" "$PART"
check "partial chain still shows the missing step as MISS" \
  "$(chain_row_verdict K3 "$PART")" "MISS | -"
ZERO="$TMP/chain-zero.md"
python3 "$ROOT/tools/scorer.py" "$FIX/chain.yaml" "$FIX/chain.log" \
  "$FIX/chain-zero.json" --verbose --out "$ZERO" >/dev/null 2>&1
check "zero-coverage chain run exits 0" "$?" "0"
check_grep "zero coverage yields chain MISS with class counts" \
  "| chain-T | MISS (0/3 classes) | 0/3 |" "$ZERO"
check_not_grep "no chain section when the corpus has no buckets" \
  "Kill-chain accumulation" "$REPORT"

echo "== C3: per-class reconciliation equation (docs/11) =="
python3 - "$REPORT" "$AGG" "$PART" "$ZERO" >"$TMP/eqcheck.out" 2>&1 <<'PYEOF'
import sys

bad = []
for path in sys.argv[1:]:
    in_table = False
    rows = 0
    for line in open(path, encoding="utf-8"):
        if line.startswith("| Signal class |"):
            in_table = True
            continue
        if in_table:
            if not line.startswith("|"):
                break
            cells = [c.strip() for c in line.strip().strip("|").split("|")]
            if cells[0].startswith("---"):
                continue
            rows += 1
            if int(cells[1]) != int(cells[2]) + int(cells[3]):
                bad.append("%s: %s Cases=%s Detected=%s Missed=%s"
                           % (path.replace("\\", "/").split("/")[-1], cells[0],
                              cells[1], cells[2], cells[3]))
    if not rows:
        bad.append("%s: no per-class table found" % path)
print("equation-ok" if not bad else "equation-broken: " + "; ".join(bad))
PYEOF
check "per-class rows reconcile Cases = Detected + Missed" \
  "$(cat "$TMP/eqcheck.out")" "equation-ok"

echo "== C4: label_source contract (docs/11) =="
ADPLBL="$TMP/alerts-adapter-label.json"
ADPREP="$TMP/report-adapter-label.md"
python3 - "$FIX/alerts-complete.json" "$ADPLBL" <<'PYEOF'
import json
import sys

src, dst = sys.argv[1], sys.argv[2]
data = json.load(open(src, encoding="utf-8"))
for alert in data["alerts"]:
    if alert.get("mitre_attack"):
        alert["label_source"] = "adapter"
with open(dst, "w", newline="\n") as fh:
    json.dump(data, fh, indent=1)
    fh.write("\n")
PYEOF
python3 "$ROOT/tools/scorer.py" "$FIX/mini.yaml" "$FIX/exec.log" \
  "$ADPLBL" --verbose --out "$ADPREP" >/dev/null 2>&1
check "adapter-label run exits 0" "$?" "0"
check_grep "adapter-supplied labels keep detection but drop Tech-tag" \
  "| net_scan_external | 1 | 1 | 0 | 100% | 500 | - |" "$ADPREP"

echo "== adapter acceptance layer (docs/06) =="
python3 "$ROOT/tools/adapter_check.py" adapters/xiezhi >"$TMP/adpchk.out" 2>&1
check "adapter_check exit code" "$?" "0"
check_grep "acceptance reports zero failures" \
  "adapter xiezhi: 10 checks, 0 failed" "$TMP/adpchk.out"
check_grep "O2 static evidence (mapping in vocab)" \
  "mapping table in vocab (53 rules)" "$TMP/adpchk.out"

echo "== proposal merge gate =="
MERGED="$TMP/merged-mini.yaml"
python3 "$ROOT/tools/merge_check.py" "$FIX/mini.yaml" \
  "$FIX/mini-proposal.yaml" --out "$MERGED" >"$TMP/mg.out" 2>"$TMP/mg.err"
check "merge gate exit code" "$?" "0"
check_grep "merge gate reports merged counts" \
  "merged: 10 cases (3 fp, 7 attack)" "$TMP/mg.out"
check_grep "single-class delta reported" \
  "single-class count: 6 -> 5" "$TMP/mg.out"
python3 "$ROOT/tools/merge_check.py" "$MERGED" \
  "$FIX/mini-proposal.yaml" --out "$TMP/mg2.yaml" >/dev/null 2>"$TMP/mg2.err"
check "duplicate ids rejected" "$?" "1"
check_grep "duplicate refusal names the ids" \
  "ids already in the corpus: M90, M91" "$TMP/mg2.err"
python3 "$ROOT/tools/merge_check.py" "$FIX/mini.yaml" \
  "$FIX/mini-proposal.yaml" --ids M91 --out "$TMP/mg3.yaml" >/dev/null 2>&1
check "attack-only merge gate exit code" "$?" "0"
python3 - "$FIX/mini.yaml" "$TMP/mg3.yaml" >"$TMP/mg3seam.out" 2>&1 <<'PYEOF'
import sys
a = open(sys.argv[1], newline="").read()
b = open(sys.argv[2], newline="").read()
print("seam-identical" if a[:a.index("attacks:")] == b[:b.index("attacks:")]
      else "seam-drifted")
PYEOF
check "attack-only merge leaves the fp/attacks seam untouched" \
  "$(cat "$TMP/mg3seam.out")" "seam-identical"

echo "== ATT&CK coverage =="
python3 "$ROOT/tools/attack_coverage.py" "$FIX/mini.yaml" \
  --out-layer "$TMP/cov.json" >"$TMP/cov.out" 2>&1
check "coverage exit code" "$?" "0"
check_grep "mini covers 6 techniques" "techniques covered: 6" "$TMP/cov.out"
check_grep "no unknown ids on mini" "unknown technique ids: 0" "$TMP/cov.out"
check_grep "no tactic mismatches on mini" "tactic mismatches: 0" "$TMP/cov.out"
python3 - "$TMP/cov.json" >"$TMP/covj.out" 2>&1 <<'PYEOF'
import json
import sys

d = json.load(open(sys.argv[1], encoding="ascii"))
ok = (d["domain"] == "enterprise-attack"
      and len(d["techniques"]) == 6
      and all(t["score"] >= 1 for t in d["techniques"]))
print("layer-ok" if ok else "layer-broken")
PYEOF
check "navigator layer valid with 6 scored techniques" \
  "$(cat "$TMP/covj.out")" "layer-ok"

echo "== T2: TA0008 matrix-calibre detectable cases (docs/11) =="
python3 - "$ROOT" >"$TMP/ta8.out" 2>&1 <<'PYEOF'
import os
import sys

sys.path.insert(0, os.path.join(sys.argv[1], "tools"))
import attack_coverage
import parse

root = sys.argv[1]
version, matrix = attack_coverage.load_matrix(
    os.path.join(root, "data", "attack-enterprise.txt"))
cases = parse.parse_corpus(os.path.join(root, "corpus", "qinjing.yaml"))
per_tech = attack_coverage.collect(cases)
ta8 = {t for t, e in matrix.items() if "TA0008" in e["tactics"]}
detectable = sum(e["detectable"] for t, e in per_tech.items() if t in ta8)
total = sum(len(e["ids"]) for t, e in per_tech.items() if t in ta8)
mism = sum(1 for tid, entry in per_tech.items() if tid in matrix
           for c in cases["attacks"]
           if c.get("technique") == tid and
           c.get("tactic") not in matrix[tid]["tactics"])
print("ta0008-detectable: %d" % detectable)
print("ta0008-total: %d" % total)
print("tactic-mismatches: %d" % mism)
PYEOF
check "TA0008 detectable >= 3 cases by technique field (was 0 pre-T2)" \
  "$(grep -F 'ta0008-detectable:' "$TMP/ta8.out")" "ta0008-detectable: 5"
check "TA0008 case count grew 3 -> 8" \
  "$(grep -F 'ta0008-total:' "$TMP/ta8.out")" "ta0008-total: 8"
check "tactic mismatch count unchanged at 1 (L02 legacy anchor)" \
  "$(grep -F 'tactic-mismatches:' "$TMP/ta8.out")" "tactic-mismatches: 1"

echo "== runner pre-flight / dry-run =="
QINJING_DRY_RUN=1 bash "$ROOT/tools/runner.sh" "$FIX/mini.yaml" >"$TMP/dry.out" 2>&1
check "dry-run exit code" "$?" "0"
check_grep "dry-run prints the plan" "PLAN: 8 case(s)" "$TMP/dry.out"
check_grep "dry-run discloses missing binaries" "missing binaries" "$TMP/dry.out"
check_grep "dry-run executes nothing" "DRY RUN complete; nothing executed" "$TMP/dry.out"

echo "== anchor lint =="
python3 "$ROOT/tools/anchor_lint.py" "$ROOT/corpus/qinjing.yaml" >"$TMP/al.out" 2>&1
check "anchor lint exit code" "$?" "0"
check_grep "L2 revocation check clean" \
  "L2 ok: all table anchors exist in the matrix" "$TMP/al.out"
check_grep "secondary registry fully used" "23 via secondary list" "$TMP/al.out"

echo "== R3 offline contract suite (docs/11 C1 gate) =="
python3 -I -B "$ROOT/tools/r3_offline_contract.py" --repo "$ROOT" \
  >"$TMP/r3c.out" 2>"$TMP/r3c.err"
check "R3 offline contract suite exits 0" "$?" "0"
check_grep "R3 contract summary line" \
  "= 50 contracts; 2 separate observations." "$TMP/r3c.out"
check_grep "R3 contract scope disclaimer" \
  "No detector, adapter or host was tested." "$TMP/r3c.out"

echo "== manifest freshness gate (docs/11 C2) =="
python3 "$ROOT/tools/manifest_check.py" --repo "$ROOT" >"$TMP/mf.out" 2>&1
check "manifest freshness gate exits 0" "$?" "0"
check_grep "all frozen hashes match the working tree" \
  "manifest freshness: 6/6 sha256 match" "$TMP/mf.out"
python3 - "$ROOT/benchmark-manifest.json" "$TMP/bad-manifest.json" <<'PYEOF'
import json
import sys

src, dst = sys.argv[1], sys.argv[2]
manifest = json.load(open(src, encoding="utf-8"))
manifest["scorer"]["sha256"] = "0" * 64
with open(dst, "w", newline="\n") as fh:
    json.dump(manifest, fh, indent=2)
    fh.write("\n")
PYEOF
python3 "$ROOT/tools/manifest_check.py" --repo "$ROOT" \
  --manifest "$TMP/bad-manifest.json" >"$TMP/mfbad.out" 2>&1
check "stale manifest must turn the gate red" "$?" "1"
check_grep "stale failure names the drifted file" \
  "FAIL scorer" "$TMP/mfbad.out"

echo "== family split gate (docs/11 phase A / G8, T3 rebalance) =="
# Literals frozen against the 2026.11 post-T3 split (owner decision 6:
# benign_ops split into 20 sub-families, hash-order two-pool fill).
python3 "$ROOT/tools/family_check.py" >"$TMP/fam.out" 2>&1
check "family split validator exits 0" "$?" "0"
check_grep "registry covers every case" \
  "  total cases: 1076" "$TMP/fam.out"
check_grep "family count after benign sub-family split" \
  "  total families: 73" "$TMP/fam.out"
check_grep "public side size" \
  "  public: 897 cases (59 families)" "$TMP/fam.out"
check_grep "holdout side size" \
  "  holdout: 179 cases (14 families)" "$TMP/fam.out"
check_grep "benign pool straddles the split (T3: both sides >=30)" \
  "benign pool: public=88 holdout=32 of 120 (T3 floor 30)" "$TMP/fam.out"
check_grep "zero family leakage" \
  "SPLIT OK (zero family leakage)" "$TMP/fam.out"

echo "== T5: provisioning manifest (docs/11) =="
python3 "$ROOT/tools/gen_provisioning.py" --out "$TMP/prov.tsv" \
  "$ROOT/corpus/qinjing.yaml" >"$TMP/prov.out" 2>&1
check "provisioning generator exit code" "$?" "0"
check "committed tsv is byte-identical to regeneration" \
  "$(cmp -s "$ROOT/data/provisioning.tsv" "$TMP/prov.tsv" && echo same)" \
  "same"
check_grep "dual disclosure: corpus-level class count" \
  "classes (corpus-level): 52" "$TMP/prov.out"
check_grep "dual disclosure: reference-bench evaluable count" \
  "evaluable on reference bench: 14 classes" "$TMP/prov.out"
check_grep "service-dependent classes counted separately" \
  "service-dependent classes: 21" "$TMP/prov.out"
check_grep "sim-only classes named honestly" \
  "sim-only classes: 5 (at_job_persistence, cloud_cluster_recon" \
  "$TMP/prov.out"
check_grep "sim-only tsv row carries flag and install gap" \
  "$(printf 'at_job_persistence\t13\tat,batch\t13\tyes')" \
  "$ROOT/data/provisioning.tsv"
check_grep "evaluable tsv row shows zero gap" \
  "$(printf 'sudoers_change\t16\tchmod,install,sed,sudo,tee,visudo\t0\tno\tyes\tno\t-')" \
  "$ROOT/data/provisioning.tsv"

echo "== U2: dashboard data generator =="
DD="$TMP/dashboard_data.json"
python3 "$ROOT/tools/gen_dashboard_data.py" --out "$DD" >"$TMP/dd.out" 2>&1
check "dashboard data generator exit code" "$?" "0"
check "committed dashboard_data.json is byte-identical to regeneration" \
  "$(cmp -s "$ROOT/dashboard/dashboard_data.json" "$DD" && echo same)" "same"
check_grep "generator discloses empty runs placeholder" \
  "runs: 0 (phase-2 placeholder; no real-machine run yet)" "$TMP/dd.out"
check_grep "generator discloses catalog rows + clean sensitive scan" \
  "cases: 1076 catalog rows, sensitive scan clean" "$TMP/dd.out"
check_grep "generator discloses uncovered gap targets" \
  "uncovered: 625 matrix techniques (gap contribution targets)" "$TMP/dd.out"
check_grep "generator discloses benign distribution census" \
  "benign distribution: 20 subfamilies, 120 cases (55 form + 65 persona)" "$TMP/dd.out"
python3 - "$DD" "$ROOT" >"$TMP/ddcheck.out" 2>&1 <<'PYEOF'
import hashlib
import json
import os
import sys

sys.path.insert(0, os.path.join(sys.argv[2], "tools"))
import parse

data = json.load(open(sys.argv[1], encoding="utf-8"))
root = sys.argv[2]
cases = parse.parse_corpus(os.path.join(root, "corpus", "qinjing.yaml"))
csha = hashlib.sha256(open(os.path.join(root, "corpus", "qinjing.yaml"),
                           "rb").read()).hexdigest()
bad = []
m, t, p = data["meta"], data["totals"], data["provisioning"]
if m["corpus_sha256"] != csha:
    bad.append("meta corpus_sha256 != corpus hash")
if (m["version"], m["calibre"], m["attack_version"]) != ("2026.11", "v2.2", "20.1"):
    bad.append("meta version/calibre/attack_version %s" % m)
if (t["cases"], t["fp"], t["attack"], t["classes"]) != (1076, 120, 956, 52):
    bad.append("totals %s" % t)
if t["cases"] != len(parse.all_cases(cases)) or t["fp"] != len(cases["false_positives"]):
    bad.append("totals drift from parse")
if t["impact"] != {"none": 581, "temporary": 160, "destructive": 335}:
    bad.append("impact composition %s" % t["impact"])
if t["attack_no_class"] != 21:
    bad.append("attack_no_class %s" % t["attack_no_class"])
cd = data["class_distribution"]
if len(cd) != 52:
    bad.append("class_distribution rows %d" % len(cd))
for r in cd:
    if r["cases"] != r["detectable"] + r["gap"]:
        bad.append("class equation %s" % r["class"])
if sum(r["cases"] for r in cd) + t["attack_no_class"] != t["attack"]:
    bad.append("class + no-class != attack")
# P0 (docs/16): per-class denominator transparency. expect_breakdown reconciles
# to cases (silent=0, benign cases carry no class); mode_breakdown reconciles to
# cases and aggregates to the corpus in-class mode split (bare-bench NOT-RUN
# risk = sim-missing-bin).
agg_mode = {"real": 0, "sim-missing-bin": 0, "sim-builtin": 0}
for r in cd:
    eb = r.get("expect_breakdown", {})
    mb = r.get("mode_breakdown", {})
    if eb.get("detectable", 0) + eb.get("gap", 0) + eb.get("silent", 0) != r["cases"]:
        bad.append("expect_breakdown != cases %s" % r["class"])
    if eb.get("detectable") != r["detectable"] or eb.get("gap") != r["gap"] or eb.get("silent") != 0:
        bad.append("expect_breakdown drift %s" % r["class"])
    if sum(mb.get(k, 0) for k in agg_mode) != r["cases"]:
        bad.append("mode_breakdown != cases %s" % r["class"])
    for k in agg_mode:
        agg_mode[k] += mb.get(k, 0)
if agg_mode != {"real": 538, "sim-missing-bin": 286, "sim-builtin": 111}:
    bad.append("aggregate mode_breakdown %s" % agg_mode)
if len(data["tactic_coverage"]) != 15:
    bad.append("tactic_coverage rows %d" % len(data["tactic_coverage"]))
hm = data["technique_heatmap"]
if len(hm) != m["techniques_covered"] or len(hm) != 81:
    bad.append("heatmap count %d" % len(hm))
for r in hm:
    if r["score"] < 1 or r["detectable"] + r["gap"] != r["score"]:
        bad.append("heatmap row %s" % r["techniqueID"])
nl = data["navigator_layer"]
if (nl["domain"], nl["versions"]["attack"], len(nl["techniques"])) != ("enterprise-attack", "20.1", 81):
    bad.append("navigator_layer shape")
if (p["corpus_classes"], p["evaluable_ref"], p["service_dep"]) != (52, 14, 21):
    bad.append("provisioning numbers %s" % p)
if len(p["sim_only_classes"]) != 5 or len(p["rows"]) != 52:
    bad.append("provisioning sim_only/rows")
if data["runs"] != []:
    bad.append("runs must stay empty (no real-machine run yet)")
# P2 (docs/16): case catalog + class anchors/counterparts + public safety.
cat = data["cases"]
every = parse.all_cases(cases)
if len(cat) != 1076 or len(cat) != t["cases"]:
    bad.append("cases catalog count %d" % len(cat))
if [c["id"] for c in cat] != [c["id"] for c in every]:
    bad.append("cases catalog order != corpus order")
if len({c["id"] for c in cat}) != len(cat):
    bad.append("cases catalog duplicate ids")
need = {"id", "name", "tactic", "technique", "technique_name", "platforms",
        "mode", "bin", "expect", "expected_signals", "related_signals",
        "impact", "bucket", "cmd", "creates_process"}
byid = {c["id"]: c for c in every}
for c in cat:
    if set(c) != need:
        bad.append("case fields %s" % c["id"]); break
    if not isinstance(c["creates_process"], bool):
        bad.append("creates_process not bool %s" % c["id"]); break
    src = byid[c["id"]]
    if c["cmd"] != src.get("cmd", "") or c["expect"] != src.get("expect"):
        bad.append("case cmd/expect drift %s" % c["id"]); break
    if c["technique_name"] and c["technique"] == "NONE":
        bad.append("NONE technique carries a name %s" % c["id"]); break
gap_rows = [c for c in cat if c["expect"] == "gap"]
if len(gap_rows) != 21 or any(c["expected_signals"] for c in gap_rows):
    bad.append("gap cases must be 21 with empty expected_signals")
if sum(1 for c in cat if c["expect"] == "silent") != 120:
    bad.append("silent case count")
anch = {}
for line in open(os.path.join(root, "data", "vocab-anchors.tsv"),
                 encoding="ascii"):
    if line.startswith("#") or not line.strip():
        continue
    p = line.rstrip("\n").split("\t")
    if len(p) >= 2:
        anch[p[0]] = p[1].split()
for r in cd:
    if not r["anchors"] or not r["counterpart"]:
        bad.append("class anchors/counterpart empty %s" % r["class"])
    if r["anchors"] != anch.get(r["class"]):
        bad.append("anchors drift from vocab-anchors.tsv %s" % r["class"])
unc = data["uncovered"]
if len(unc) != 625:
    bad.append("uncovered count %d" % len(unc))
if len(hm) + len(unc) != m["matrix_techniques"]:
    bad.append("covered + uncovered != matrix")
covered_ids = {r["techniqueID"] for r in hm}
for r in unc:
    if r["techniqueID"] in covered_ids or not r["name"]:
        bad.append("uncovered row %s" % r["techniqueID"]); break
# P1 (docs/16): benign distribution reconciles with the family registry
# (20 benign_ops_* subfamilies, 120 cases, form 55 / persona 65), and the
# per-class adapter rule mappings reconcile with the adapter tables.
bd = data.get("benign_distribution")
if not bd:
    bad.append("benign_distribution missing")
else:
    reg, reg_group = {}, {}
    for line in open(os.path.join(root, "data", "family-registry.tsv"),
                     encoding="ascii"):
        if line.startswith("#") or not line.strip():
            continue
        p = line.rstrip("\n").split("\t")
        if len(p) >= 3 and p[2] == "benign":
            reg[p[1]] = reg.get(p[1], 0) + 1
            g = "form" if int(p[0][2:]) <= 56 else "persona"
            reg_group.setdefault(p[1], set()).add(g)
    if len(bd) != 20 or len(reg) != 20:
        bad.append("benign subfamily count %d/%d" % (len(bd), len(reg)))
    if sum(r["cases"] for r in bd) != 120 or t["fp"] != 120:
        bad.append("benign distribution sum != 120")
    form = sum(r["cases"] for r in bd if r["group"] == "form")
    persona = sum(r["cases"] for r in bd if r["group"] == "persona")
    if (form, persona) != (55, 65):
        bad.append("benign group split %d/%d" % (form, persona))
    if {r["subfamily"] for r in bd} != set(reg):
        bad.append("benign subfamily set != registry")
    cat_ids = {c["id"] for c in cat}
    for r in bd:
        if not r["subfamily"].startswith("benign_ops_"):
            bad.append("subfamily prefix %s" % r["subfamily"])
        if r["cases"] != reg.get(r["subfamily"]):
            bad.append("subfamily count drift %s" % r["subfamily"])
        if reg_group.get(r["subfamily"]) != {r["group"]}:
            bad.append("subfamily group mismatch %s" % r["subfamily"])
        if not 1 <= len(r["examples"]) <= 3:
            bad.append("examples length %s" % r["subfamily"])
        if not set(r["examples"]) <= cat_ids:
            bad.append("examples not in catalog %s" % r["subfamily"])
xz = json.load(open(os.path.join(root, "adapters", "xiezhi",
                                 "rule_map.json"), encoding="utf-8"))
wz = json.load(open(os.path.join(root, "adapters", "wazuh",
                                 "rule_map.json"), encoding="utf-8"))
ec = json.load(open(os.path.join(root, "adapters", "wazuh",
                                 "execve_classify.json"), encoding="utf-8"))
xz_by, wz_by, ec_by = {}, {}, {}
for rule, cls in xz.items():
    xz_by.setdefault(cls, []).append(rule)
for rule, cls in wz.items():
    wz_by.setdefault(cls, []).append(rule)
for e in ec:
    ec_by[e["signal_class"]] = ec_by.get(e["signal_class"], 0) + 1
for r in cd:
    ar = r.get("adapter_rules")
    if not ar:
        bad.append("adapter_rules missing %s" % r["class"]); continue
    by_adapter = {a["adapter"]: a for a in ar}
    if set(by_adapter) != {"xiezhi", "wazuh"}:
        bad.append("adapter set %s" % r["class"]); continue
    if sorted(by_adapter["xiezhi"]["rules"]) != sorted(xz_by.get(r["class"], [])):
        bad.append("xiezhi rules drift %s" % r["class"])
    if sorted(by_adapter["wazuh"]["rules"]) != sorted(wz_by.get(r["class"], [])):
        bad.append("wazuh rules drift %s" % r["class"])
    if by_adapter["wazuh"]["execve_classifiers"] != ec_by.get(r["class"], 0):
        bad.append("execve classifiers drift %s" % r["class"])
import gen_dashboard_data as gdd
hits = gdd.sensitive_hits(open(sys.argv[1], encoding="utf-8").read())
if hits:
    bad.append("sensitive scan hits %s" % hits[:3])
if not gdd.sensitive_hits("password=Sup3rSecret123 10.238.0.5 F:/repo"):
    bad.append("sensitive scan is vacuous (must fire on planted material)")
print("dd-ok" if not bad else "dd-broken: " + "; ".join(bad))
PYEOF
check "dashboard data reconciles with corpus + coverage + provisioning" \
  "$(cat "$TMP/ddcheck.out")" "dd-ok"

echo "== C6/C11: statistical disclosure + latency honesty (docs/11) =="
CJSON="$TMP/c11.json"
python3 "$ROOT/tools/scorer.py" "$FIX/mini.yaml" "$FIX/exec.log" \
  "$FIX/alerts-complete.json" --out-json "$CJSON" --out "$TMP/c11.md" >/dev/null 2>&1
check "scorer C11 exit code" "$?" "0"
check_grep "disclosure section present" "### Statistical disclosure" "$TMP/c11.md"
check_grep "no natural total score disclosed" "No natural total score" "$TMP/c11.md"
check_grep "latency HIT-subset + negative drop disclosed" \
  "negative latencies dropped: 0" "$TMP/c11.md"
check_grep "0-FP not zero-width disclosed" "zero-width interval" "$TMP/c11.md"
python3 - "$CJSON" "$ROOT" "$FIX" >"$TMP/c11check.out" 2>&1 <<'PYEOF'
import json, sys, datetime, tempfile, os
sys.path.insert(0, os.path.join(sys.argv[2], "tools"))
import scorer, stats
d = json.load(open(sys.argv[1], encoding="utf-8"))
bad = []
if d["detection"].get("signal_ci95") is None: bad.append("signal_ci95")
if d["fp"].get("attempt_upper95") is None: bad.append("attempt_upper95")
if d.get("aggregation", {}).get("total_score") is not None: bad.append("total_score")
if not all("latency_n" in r and "hit_ci95" in r for r in d["per_class"]):
    bad.append("per_class latency_n/hit_ci95")
if round(stats.upper_bound(0, 120) * 100, 2) != 2.47: bad.append("0/120 upper")
hdr, rows, end = scorer.parse_exec_log(os.path.join(sys.argv[3], "q4.log"))
t02 = [r for r in rows if r["id"] == "T02"][0]
data = json.load(open(os.path.join(sys.argv[3], "q4-a.json"), encoding="utf-8"))
ms = t02["start_ms"] - 100
for a in data["alerts"]:
    a["timestamp"] = datetime.datetime.fromtimestamp(
        ms / 1000, datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.") + "%03dZ" % (ms % 1000)
p = tempfile.NamedTemporaryFile("w", suffix=".json", delete=False)
json.dump(data, p); p.close()
j = {}
rep, kind = scorer.build_report(os.path.join(sys.argv[3], "mini.yaml"),
                                os.path.join(sys.argv[3], "q4.log"),
                                p.name, "high", 3500, json_out=j)
os.unlink(p.name)
if j["latency"]["negative_dropped"] != 1: bad.append("negative_dropped != 1")
if "negative latencies dropped: 1" not in rep: bad.append("neg disclosure")
print("c11-ok" if not bad else "c11-broken: " + "; ".join(bad))
PYEOF
check "C11 intervals + C6 negative-latency counter" \
  "$(cat "$TMP/c11check.out")" "c11-ok"
check_grep "pre-C12 log disclosed not-recorded" "order_sha=not-recorded" "$TMP/c11.md"

echo "== C9/C12: fair-config freeze + run state/order/reset (docs/11) =="
check_grep "runner header freezes order hash" 'order_sha=%s' "$ROOT/tools/runner.sh"
check_grep "runner header declares seed/state/round/reset/log_loss" \
  'seed=none order_sha=%s state=cold round=1 reset=%s log_loss=na' "$ROOT/tools/runner.sh"
C12REP="$TMP/c12.md"
python3 "$ROOT/tools/scorer.py" "$FIX/mini.yaml" "$FIX/exec-c12.log" \
  "$FIX/alerts-complete.json" --out "$C12REP" --out-json "$TMP/c12.json" >/dev/null 2>&1
check "scorer C12 fixture exit code" "$?" "0"
check_grep "run state disclosed with order hash" "order_sha=abc123def456" "$C12REP"
check_grep "run state cold + reset disclosed" "state=cold round=1 reset=87" "$C12REP"
python3 - "$TMP/c12.json" "$ROOT" >"$TMP/c12check.out" 2>&1 <<'PYEOF'
import json, sys
d = json.load(open(sys.argv[1], encoding="utf-8"))
rs = d["meta"]["run_state"]
m = json.load(open(sys.argv[2] + "/benchmark-manifest.json", encoding="utf-8"))
bad = []
if rs["order_sha"] != "abc123def456": bad.append("order_sha")
if rs["state"] != "cold" or rs["reset"] != "87": bad.append("state/reset")
fc = m.get("fair_config", {})
if not fc.get("profile") or not fc.get("applicable_scope"): bad.append("fair_config")
print("c12-ok" if not bad else "c12-broken: " + "; ".join(bad))
PYEOF
check "C12 run_state JSON + C9 fair_config present" \
  "$(cat "$TMP/c12check.out")" "c12-ok"
check_grep "manifest_check reports fair_config ok" "fair_config" "$TMP/mf.out"
python3 - "$ROOT/benchmark-manifest.json" "$TMP/nofc.json" <<'PYEOF'
import json, sys
m = json.load(open(sys.argv[1], encoding="utf-8"))
m.pop("fair_config", None)
json.dump(m, open(sys.argv[2], "w", encoding="utf-8"))
PYEOF
python3 "$ROOT/tools/manifest_check.py" --repo "$ROOT" \
  --manifest "$TMP/nofc.json" >"$TMP/nofc.out" 2>&1
check "missing fair_config turns gate red" "$?" "1"
check_grep "fair_config failure named" "FAIL fair_config" "$TMP/nofc.out"

echo "== C7/C6: observation contract + time fields (docs/11) =="
python3 "$ROOT/tools/observation_lint.py" >"$TMP/obs.out" 2>&1
check "observation lint exit code" "$?" "0"
check_grep "observation contract covers 52 classes" \
  "observation contract: 52/52 classes covered" "$TMP/obs.out"
C7REP="$TMP/c7.md"
python3 "$ROOT/tools/scorer.py" "$FIX/c7.yaml" "$FIX/c7.log" \
  "$FIX/alerts-c7.json" --verbose --out "$C7REP" --out-json "$TMP/c7.json" >/dev/null 2>&1
check "scorer C7 fixture exit code" "$?" "0"
check "KM01 not-measured (module_load unexported)" \
  "$(row_verdict KM01 "$C7REP")" "NOT-MEASURED (module_load) | -"
check "EX01 still HIT (execve exported)" \
  "$(row_verdict EX01 "$C7REP")" "HIT | yes"
check_grep "not-measured disclosure" "not-measured: 1" "$C7REP"
check_grep "C6 clock domain disclosed" "clock domain: source_event_time" "$C7REP"
python3 - "$TMP/c7.json" >"$TMP/c7check.out" 2>&1 <<'PYEOF'
import json, sys
d = json.load(open(sys.argv[1], encoding="utf-8"))
bad = []
if d["detection"]["not_measured"] != 1: bad.append("not_measured")
if d["detection"]["detectable"] != 1 or d["detection"]["hit"] != 1:
    bad.append("measured-only denominator")
if d["latency"]["clock_domains"] != ["source_event_time"]: bad.append("clock_domains")
km = [r for r in d["per_class"] if r["class"] == "kernel_module_load"][0]
if km["not_measured"] != 1 or \
        km["cases"] != km["detected"] + km["missed"] + km["not_measured"]:
    bad.append("km reconcile")
ex = [r for r in d["per_class"] if r["class"] == "net_scan_external"][0]
if ex["median_latency_ms"] != 500: bad.append("C6 source_event_time latency")
print("c7-ok" if not bad else "c7-broken: " + "; ".join(bad))
PYEOF
check "C7 not_measured exclusion + C6 source_event_time latency" \
  "$(cat "$TMP/c7check.out")" "c7-ok"

echo "== C8: process identity adapter + strict view (xiezhi delivery) =="
python3 - "$ROOT" "$FIX" "$TMP" >"$TMP/c8ad.out" 2>&1 <<'PYEOF'
import json, os, sys, io, contextlib
root, fix, tmp = sys.argv[1], sys.argv[2], sys.argv[3]
sys.path.insert(0, os.path.join(root, "adapters", "xiezhi"))
import alerts_to_canonical as ad
raw = [
 {"ts": "2026-11-16T08:33:22Z", "ts_ms": 1794818002000, "severity": "high",
  "rule_id": "exec-recon-nmap", "agent_id": "h1", "hostname": "selftest",
  "mitre": "T1046",
  "process": {"pid": 100, "ppid": 1, "uid": 0, "exe": "/usr/bin/nmap",
              "comm": "nmap", "argv": ["nmap", "-sS"], "auid": -1}},
 {"ts": "2026-11-16T08:33:23Z", "ts_ms": 1794818003000, "severity": "low",
  "rule_id": "deadman/agent_offline", "agent_id": "h1", "hostname": "selftest"},
]
rp = os.path.join(tmp, "c8raw.json"); json.dump(raw, open(rp, "w"))
op = os.path.join(tmp, "c8canon.json")
with contextlib.redirect_stdout(io.StringIO()):
    ad.convert(rp, os.path.join(fix, "exec.log"), op, True)
by = {a["rule_id"]: a for a in json.load(open(op))["alerts"]}
bad = []
p = by["exec-recon-nmap"].get("process")
if not p or p.get("pid") != 100 or p.get("comm") != "nmap":
    bad.append("execve process mapped")
if p and "auid" in p: bad.append("auid -1 must be dropped")
if by["exec-recon-nmap"]["raw_log"] != "nmap -sS": bad.append("raw_log argv join")
if not by["exec-recon-nmap"]["event_uid"]: bad.append("event_uid ack key")
if by["deadman/agent_offline"].get("process") is not None:
    bad.append("non-execve must lack process")
print("c8ad-ok" if not bad else "c8ad-broken: " + "; ".join(bad))
PYEOF
check "adapter maps process (O6/O7, auid unset dropped)" \
  "$(cat "$TMP/c8ad.out")" "c8ad-ok"
C8REP="$TMP/c8.md"
python3 "$ROOT/tools/scorer.py" "$FIX/c8.yaml" "$FIX/c8.log" \
  "$FIX/alerts-c8.json" --out "$C8REP" --out-json "$TMP/c8.json" >/dev/null 2>&1
check "scorer C8 fixture exit code" "$?" "0"
check_grep "strict process view header" "### Strict process view (C8" "$C8REP"
check_grep "coherence counts" "coherent=1 incoherent=1 unattributable=1" "$C8REP"
python3 - "$TMP/c8.json" >"$TMP/c8check.out" 2>&1 <<'PYEOF'
import json, sys
d = json.load(open(sys.argv[1], encoding="utf-8"))
sp = d["strict_process"]; bad = []
if (sp["coherent"], sp["incoherent"], sp["unattributable"]) != (1, 1, 1):
    bad.append("counts")
if sp["auid_available"] is not False: bad.append("auid_available")
if d["detection"]["hit"] != 3: bad.append("primary verdicts unchanged")
print("c8-ok" if not bad else "c8-broken: " + "; ".join(bad))
PYEOF
check "C8 strict view buckets + primary unchanged" \
  "$(cat "$TMP/c8check.out")" "c8-ok"

echo "== G3: detection quality tiers (MITRE-style, docs/13) =="
G3REP="$TMP/g3.md"
python3 "$ROOT/tools/scorer.py" "$FIX/g3.yaml" "$FIX/g3.log" \
  "$FIX/alerts-g3.json" --out "$G3REP" --out-json "$TMP/g3.json" >/dev/null 2>&1
check "scorer G3 fixture exit code" "$?" "0"
check_grep "tiers header" "### Detection quality tiers (G3" "$G3REP"
check_grep "overall tier counts" "technique=1 tactic=1 general=1 none=0" "$G3REP"
python3 - "$TMP/g3.json" >"$TMP/g3check.out" 2>&1 <<'PYEOF'
import json, sys
d = json.load(open(sys.argv[1], encoding="utf-8"))
t = d["tiers"]["totals"]; bad = []
if (t["technique"], t["tactic"], t["general"], t["none"]) != (1, 1, 1, 0):
    bad.append("tier totals")
if d["detection"]["hit"] != 3: bad.append("verdicts unchanged")
print("g3-ok" if not bad else "g3-broken: " + "; ".join(bad))
PYEOF
check "G3 tiers technique/tactic/general + verdicts unchanged" \
  "$(cat "$TMP/g3check.out")" "g3-ok"

echo "== G5: CALDERA/stockpile chain import proposal (docs/13) =="
python3 - "$ROOT" >"$TMP/cal.out" 2>&1 <<'PYEOF'
import sys, os
root = sys.argv[1]
sys.path.insert(0, os.path.join(root, "tools"))
from parse import parse_lines, validate
text = open(os.path.join(root, "tests", "fixture", "caldera",
                         "caldera-import-r1.yaml"),
            encoding="ascii").read()
cases = parse_lines(text.splitlines())
bad = []
if validate(cases): bad.append("validate")
atk = cases["attacks"]
if len(atk) != 3: bad.append("count")
if sum(1 for c in atk if c.get("bucket") == "chain-CAL1") != 2:
    bad.append("chain bucket")
if sum(1 for c in atk if c["expect"] == "detectable") != 2:
    bad.append("detectable")
print("cal-ok" if not bad else "cal-broken: " + "; ".join(bad))
PYEOF
check "caldera chain proposal validates + chain bucket" \
  "$(cat "$TMP/cal.out")" "cal-ok"

echo "== P2: dashboard HTTP surface =="
# Render the real SSR pages over HTTP and assert the user-observable behavior:
# catalog counts/filter/search/pagination, detail four sections + 404, gap CTA,
# and a sensitive scan of the served bytes. Needs Go (same guard as gate 4);
# without Go the data gates above still run and this section skips loudly.
if command -v go >/dev/null 2>&1; then
  P2BIN="$TMP/dash-p2.exe"
  (cd "$ROOT/dashboard" && go build -o "$P2BIN" .) >"$TMP/p2build.log" 2>&1
  check "P2 dashboard binary builds" "$?" "0"
  P2PORT=21399
  "$P2BIN" --addr "127.0.0.1:$P2PORT" \
    --data "$ROOT/dashboard/dashboard_data.json" >"$TMP/p2srv.log" 2>&1 &
  P2PID=$!
  P2B="http://127.0.0.1:$P2PORT"
  ready=no
  for _ in 1 2 3 4 5 6 7 8 9 10; do
    if [ "$(curl -s --noproxy '*' -o /dev/null -w '%{http_code}' "$P2B/healthz")" = "200" ]; then
      ready=yes; break
    fi
    sleep 0.3
  done
  check "P2 server reaches healthz" "$ready" "yes"
  curl -s --noproxy '*' "$P2B/cases" >"$TMP/p2-cases.html"
  curl -s --noproxy '*' "$P2B/cases?expect=gap" >"$TMP/p2-gap.html"
  curl -s --noproxy '*' "$P2B/cases?tactic=BENIGN" >"$TMP/p2-benign.html"
  curl -s --noproxy '*' "$P2B/cases?q=NMAP" >"$TMP/p2-search.html"
  curl -s --noproxy '*' "$P2B/cases?q=zzznomatch" >"$TMP/p2-empty.html"
  curl -s --noproxy '*' "$P2B/cases?page=2" >"$TMP/p2-page2.html"
  curl -s --noproxy '*' "$P2B/case?id=E01" >"$TMP/p2-e01.html"
  curl -s --noproxy '*' "$P2B/case?id=S01" >"$TMP/p2-s01.html"
  curl -s --noproxy '*' "$P2B/matrix" >"$TMP/p2-matrix.html"
  curl -s --noproxy '*' "$P2B/scores" >"$TMP/p2-scores.html"
  curl -s --noproxy '*' "$P2B/scores?lang=zh" >"$TMP/p2-scores-zh.html"
  curl -s --noproxy '*' "$P2B/coverage" >"$TMP/p2-coverage.html"
  curl -s --noproxy '*' "$P2B/" >"$TMP/p2-overview.html"
  curl -s --noproxy '*' "$P2B/classes" >"$TMP/p2-classes.html"
  curl -s --noproxy '*' "$P2B/fp" >"$TMP/p2-fp.html"
  curl -s --noproxy '*' "$P2B/fp?lang=zh" >"$TMP/p2-fp-zh.html"
  curl -s --noproxy '*' "$P2B/case?id=FP01" >"$TMP/p2-fp01.html"
  curl -s --noproxy '*' "$P2B/case?id=E01&lang=zh" >"$TMP/p2-e01-zh.html"
  p2nope=$(curl -s --noproxy '*' -o /dev/null -w '%{http_code}' "$P2B/case?id=NOPE")
  p2fpcode=$(curl -s --noproxy '*' -o /dev/null -w '%{http_code}' "$P2B/fp")
  kill "$P2PID" 2>/dev/null
  wait "$P2PID" 2>/dev/null
  check_grep "catalog full count badge 1076" 'tag count">1076' "$TMP/p2-cases.html"
  check_grep "catalog filter expect=gap narrows to 21" 'tag count">21' "$TMP/p2-gap.html"
  check_grep "catalog filter tactic=BENIGN narrows to 120" 'tag count">120' "$TMP/p2-benign.html"
  check_grep "catalog search case-insensitive (q=NMAP)" 'nmap' "$TMP/p2-search.html"
  check_grep "catalog empty search renders no-match row" 'No cases match the current filter.' "$TMP/p2-empty.html"
  check_not_grep "catalog page 2 drops the first case FP01" '>FP01<' "$TMP/p2-page2.html"
  check_grep "detail renders ATT&CK technique link" 'attack.mitre.org/techniques/T1059.004/' "$TMP/p2-e01.html"
  check_grep "detail renders signal-class counterpart" 'Sigma curl pipe shell' "$TMP/p2-e01.html"
  check_grep "detail gap case discloses coverage hole" 'gap — no signal class' "$TMP/p2-s01.html"
  check "detail unknown id returns 404" "$p2nope" "404"
  check_grep "matrix gap CTA links public issues" 'github.com/xycxmz/qinjing-public/issues' "$TMP/p2-matrix.html"
  check_grep "matrix lists uncovered techniques" 'Uncovered techniques' "$TMP/p2-matrix.html"
  check_grep "matrix Navigator semantics legend" 'Navigator layer semantics' "$TMP/p2-matrix.html"
  python3 - "$TMP" "$ROOT" >"$TMP/p2scan.out" 2>&1 <<'PYEOF'
import glob
import os
import sys

sys.path.insert(0, os.path.join(sys.argv[2], "tools"))
import gen_dashboard_data as gdd

bad = []
for p in sorted(glob.glob(os.path.join(sys.argv[1], "p2-*.html"))):
    hits = gdd.sensitive_hits(open(p, encoding="utf-8").read())
    if hits:
        bad.append("%s: %s" % (os.path.basename(p), hits[:2]))
print("p2-scan-clean" if not bad else "p2-scan-broken: " + "; ".join(bad))
PYEOF
  check "served P2 pages pass sensitive scan" "$(cat "$TMP/p2scan.out")" "p2-scan-clean"
  # P0 (docs/16): statistical honesty disclosure on the committed-data pages.
  # The methodology panel + G3 tier palette/semantic axis are framework-ready
  # (render with zero runs); the census banner separates coverage from detection.
  check_grep "scores methodology panel renders with empty runs" 'Statistical methodology' "$TMP/p2-scores.html"
  check_grep "scores discloses Clopper-Pearson exact intervals" 'Clopper-Pearson' "$TMP/p2-scores.html"
  check_grep "scores discloses independence limitation" 'Independence limitation' "$TMP/p2-scores.html"
  check_grep "scores discloses no total score" 'No total score' "$TMP/p2-scores.html"
  check_grep "scores G3 tier palette legend present" 'tier-technique' "$TMP/p2-scores.html"
  check_grep "scores specificity semantic axis present" 'More specific' "$TMP/p2-scores.html"
  check_grep "scores empty state stays pending (no run)" 'Pending real-machine measurement' "$TMP/p2-scores.html"
  check_grep "zh scores methodology renders Chinese" '统计方法论' "$TMP/p2-scores-zh.html"
  check_grep "overview census banner present" 'Coverage is not a detection rate.' "$TMP/p2-overview.html"
  check_grep "coverage census banner present" 'Coverage is not a detection rate.' "$TMP/p2-coverage.html"
  check_grep "coverage denominator disclosed as census" 'coverage census, not a detection denominator' "$TMP/p2-coverage.html"
  check_grep "classes mode-breakdown denominator banner" 'Denominator transparency.' "$TMP/p2-classes.html"
  check_grep "classes shows sim-missing-bin NOT-RUN risk" 'NOT-RUN on a bare reference bench' "$TMP/p2-classes.html"
  check_not_grep "committed scores page renders no synthetic run badge" 'demo-badge' "$TMP/p2-scores.html"
  check_not_grep "committed empty scores renders no scatter SVG" '<svg' "$TMP/p2-scores.html"
  check_grep "committed scores shows FPR heatmap section" 'FPR heatmap' "$TMP/p2-scores.html"
  check_grep "committed scores heatmap honest empty state" 'activates when a real run is scored' "$TMP/p2-scores.html"

  # P3 (docs/16): reproducibility + version governance framework. The
  # cross-version incomparability banner and the methodology panels are
  # framework-ready (render with zero runs); the archive toggle and the
  # per-run evidence links stay absent until a run exists.
  check_grep "scores cross-version incomparability banner" 'Runs are comparable only within the same version and environment.' "$TMP/p2-scores.html"
  check_grep "scores banner pins the benchmark versions" 'Versions are pinned' "$TMP/p2-scores.html"
  check_grep "scores banner cites the input sha triple" 'exec-log-sha256' "$TMP/p2-scores.html"
  check_grep "scores reproducibility methodology panel" 'Reproducibility and the input triple' "$TMP/p2-scores.html"
  check_grep "scores reproducibility cites docs/03 D9" 'docs/03 D9' "$TMP/p2-scores.html"
  check_grep "scores version governance methodology panel" 'Version governance and archiving' "$TMP/p2-scores.html"
  check_grep "scores archive policy retire not delete" 'archived, not deleted' "$TMP/p2-scores.html"
  check_grep "scores label source methodology panel" 'Label source' "$TMP/p2-scores.html"
  check_grep "scores label source Tech-tag native only" 'Tech-tag column counts native labels only' "$TMP/p2-scores.html"
  check_grep "scores run modifiers methodology panel" 'Run modifiers' "$TMP/p2-scores.html"
  check_grep "scores modifiers name Configuration Change" 'Configuration Change' "$TMP/p2-scores.html"
  check_grep "scores cost and latency methodology panel" 'Cost and latency' "$TMP/p2-scores.html"
  check_not_grep "committed empty scores renders no archive toggle" 'Show archived runs' "$TMP/p2-scores.html"
  check_not_grep "committed empty scores renders no evidence links" 'Raw evidence' "$TMP/p2-scores.html"
  check_grep "zh scores cross-version banner renders Chinese" '仅同版本同环境' "$TMP/p2-scores-zh.html"
  check_grep "zh scores reproducibility methodology renders Chinese" '复现与输入三元组' "$TMP/p2-scores-zh.html"

  # P1 (docs/16): the standalone /fp page. Benign distribution reconciles to
  # 120 (form 55 / persona 65), the tight-window methodology panel is live with
  # zero runs, the tradeoff carries the FP03 precedent, and the violation table
  # stays an honest empty state until a real run exists.
  check "fp page returns 200" "$p2fpcode" "200"
  check_grep "fp benign total badge 120" 'tag count">120' "$TMP/p2-fp.html"
  check_grep "fp form group subtotal 55" 'tag count">55' "$TMP/p2-fp.html"
  check_grep "fp persona group subtotal 65" 'tag count">65' "$TMP/p2-fp.html"
  check_grep "fp lists a form subfamily" 'benign_ops_devbuild' "$TMP/p2-fp.html"
  check_grep "fp lists a persona subfamily" 'benign_ops_sysadmin' "$TMP/p2-fp.html"
  check_grep "fp representative case links to detail" '/case?id=FP01' "$TMP/p2-fp.html"
  check_grep "fp methodology discloses the 2500ms tail window" '2500' "$TMP/p2-fp.html"
  check_grep "fp methodology discloses the high+ gate" 'high and critical' "$TMP/p2-fp.html"
  check_grep "fp methodology discloses the verify_rc tiers" 'verify_rc' "$TMP/p2-fp.html"
  check_grep "fp methodology discloses fp-uid cross-talk check" 'fp-uid' "$TMP/p2-fp.html"
  check_grep "fp methodology discloses bin=0 NOT-RUN" 'bin_found=0' "$TMP/p2-fp.html"
  check_grep "fp methodology discloses the integrity gate" 'fetch.complete' "$TMP/p2-fp.html"
  check_grep "fp tradeoff illustrates calibre A cost abstractly" 'Calibre A tradeoff' "$TMP/p2-fp.html"
  check_grep "fp tradeoff explains medium flags benign FP" 'FALSE POSITIVE' "$TMP/p2-fp.html"
  check_not_grep "fp page publishes no real product measurement" 'Wazuh 4.14.10' "$TMP/p2-fp.html"
  check_grep "fp tradeoff links the scores scatter" '/scores' "$TMP/p2-fp.html"
  check_grep "fp differentiation names ART and CALDERA" 'CALDERA' "$TMP/p2-fp.html"
  check_grep "fp violation table honest empty state" 'No real-machine run yet.' "$TMP/p2-fp.html"
  check_not_grep "committed fp page renders no synthetic badge" 'demo-badge' "$TMP/p2-fp.html"
  check_grep "zh fp renders Chinese methodology" '紧窗误报方法论' "$TMP/p2-fp-zh.html"
  check_grep "zh fp renders Chinese distribution heading" '良性语料分布' "$TMP/p2-fp-zh.html"

  # P1 (docs/16): /case detection evidence. The expected detection profile
  # maps each expected class to its adapter rules; the G3 tier legend and the
  # scorer per-case follow-up disclosure render with zero runs; benign and gap
  # cases are handled honestly.
  check_grep "case evidence section heading" '5. Detection evidence' "$TMP/p2-e01.html"
  check_grep "case expected detection profile" 'Expected detection profile' "$TMP/p2-e01.html"
  check_grep "case profile lists the xiezhi seed rule" 'exec-curl-pipe-shell' "$TMP/p2-e01.html"
  check_grep "case profile lists execve argv classifiers" 'execve argv' "$TMP/p2-e01.html"
  check_grep "case evidence G3 tier legend" 'tier-technique' "$TMP/p2-e01.html"
  check_grep "case evidence scorer per-case follow-up" 'scorer --out-json' "$TMP/p2-e01.html"
  check_grep "case evidence links scores per-class table" '/scores' "$TMP/p2-e01.html"
  check_grep "benign case evidence links fp methodology" 'Benign case: a correct HIDS' "$TMP/p2-fp01.html"
  check_grep "benign case evidence links /fp" 'href="/fp"' "$TMP/p2-fp01.html"
  check_grep "gap case evidence discloses no mapping" 'no adapter mapping applies' "$TMP/p2-s01.html"
  check_grep "zh case evidence renders Chinese heading" '检测证据' "$TMP/p2-e01-zh.html"

  # P0 SYNTHETIC chart rendering (docs/16 C5/C6). A test-only fixture injects
  # synthetic runs into a COPY of the committed data written under $TMP (never
  # the shipped artifact), served by a separate instance. This proves the
  # scatter SVG + FPR heatmap render and are labelled SYNTHETIC, while the
  # shipped runs[] stays empty and the public pages carry no synthetic data.
  python3 - "$ROOT/dashboard/dashboard_data.json" "$TMP/synthetic_data.json" >"$TMP/syn.out" 2>&1 <<'PYEOF'
import json, sys
data = json.load(open(sys.argv[1], encoding="utf-8"))
sha = data["meta"]["corpus_sha256"]
def run(rid, product, hit, viol, arate, fpr_a, fpr_b):
    return {
        "run_id": rid, "product": product, "timestamp": "2026-11-21T00:00:00Z",
        "synthetic": True,
        "meta": {"corpus_sha256": sha, "calibre": "v2.2", "min_severity": "high",
                 "grace_ms": 3500, "run_kind": "COMPLETE", "host": "selftest",
                 "target_kernel": "5.99-test", "target_distro": "Test OS 7"},
        "totals": data["totals"],
        "detection": {"detectable": 100, "hit": hit, "strict": hit - 10,
                      "anyhit": hit + 5, "notrun": 0, "transport_invalid": 0,
                      "not_measured": 0, "signal_rate": hit / 100.0,
                      "strict_rate": (hit - 10) / 100.0, "anyhit_rate": (hit + 5) / 100.0,
                      "signal_ci95": [0.7, 0.9]},
        "fp": {"evaluable": 120, "verified": 100, "attempt": 20, "legacy": 0,
               "violations": viol, "violations_verified": viol - 2,
               "verified_rate": (viol - 2) / 100.0, "attempt_rate": arate,
               "attempt_upper95": arate + 0.04},
        "per_class": [
            {"class": "net_scan_external", "cases": 10, "detected": 9, "missed": 1,
             "not_measured": 0, "median_latency_ms": 500, "tech_tagged": 8,
             "latency_n": 9, "negative_dropped": 0, "hit_ci95": [0.55, 0.99], "fpr": fpr_a},
            {"class": "archive_staging", "cases": 8, "detected": 5, "missed": 3,
             "not_measured": 0, "median_latency_ms": 800, "tech_tagged": 4,
             "latency_n": 5, "negative_dropped": 0, "hit_ci95": [0.3, 0.9], "fpr": fpr_b},
            {"class": "download_and_execute", "cases": 10, "detected": 8, "missed": 2,
             "not_measured": 0, "median_latency_ms": 600, "tech_tagged": 6,
             "latency_n": 8, "negative_dropped": 0, "hit_ci95": [0.5, 0.95], "fpr": 0.0}],
        "by_tactic": [], "by_technique": [],
        "latency": {"subset": "HIT-only", "negative_dropped": 0,
                    "calibre": "attribution-window proxy, not MTTD"},
        "aggregation": {"micro_signal_rate": hit / 100.0, "macro_signal_rate": 0.75,
                        "total_score": None, "note": "no natural total score"},
        "strict_process": {"coherent": hit, "incoherent": 0, "unattributable": 0,
                           "auid_available": False, "note": "coherence cross-check"},
        "tiers": {"totals": {"technique": 50, "tactic": 20, "general": 10, "none": 0},
                  "per_class": [
                      {"class": "net_scan_external", "technique": 7, "tactic": 2, "general": 1, "none": 0},
                      {"class": "archive_staging", "technique": 3, "tactic": 2, "general": 0, "none": 0},
                      {"class": "download_and_execute", "technique": 6, "tactic": 2, "general": 0, "none": 0}],
                  "note": "additive"},
        "artifact_report": "artifacts/%s/report.md" % rid,
        "artifact_exec_log": "artifacts/%s/exec.log" % rid,
        "artifact_alerts": "artifacts/%s/alerts.json" % rid,
        "version": "2026.11", "deprecated": False,
        "label_source_counts": {"native": hit, "adapter": 5, "reviewer": 2},
        "modifiers": ["Configuration Change"], "duration_ms": 123456,
    }
archived = run("syn-003", "SYNTHETIC-ARCHIVED", 50, 8, 0.08, 0.10, 0.30)
archived["deprecated"] = True
archived["modifiers"] = ["Delayed"]
data["runs"] = [run("syn-001", "SYNTHETIC-A", 80, 6, 0.05, 0.02, 0.25),
                run("syn-002", "SYNTHETIC-B", 60, 12, 0.10, 0.08, 0.40),
                archived]
with open(sys.argv[2], "w", encoding="ascii", newline="\n") as fh:
    json.dump(data, fh, indent=1)
print("syn-fixture-written")
PYEOF
  check "SYNTHETIC fixture written to TMP only" "$(cat "$TMP/syn.out")" "syn-fixture-written"
  check "shipped artifact runs[] stays empty after fixture" \
    "$(python3 -I -c 'import json,sys;print(len(json.load(open(sys.argv[1],encoding="utf-8"))["runs"]))' "$ROOT/dashboard/dashboard_data.json")" "0"
  P0PORT=21400
  "$P2BIN" --addr "127.0.0.1:$P0PORT" --data "$TMP/synthetic_data.json" >"$TMP/p0srv.log" 2>&1 &
  P0PID=$!
  P0B="http://127.0.0.1:$P0PORT"
  p0ready=no
  for _ in 1 2 3 4 5 6 7 8 9 10; do
    if [ "$(curl -s --noproxy '*' -o /dev/null -w '%{http_code}' "$P0B/healthz")" = "200" ]; then
      p0ready=yes; break
    fi
    sleep 0.3
  done
  check "SYNTHETIC server reaches healthz" "$p0ready" "yes"
  curl -s --noproxy '*' "$P0B/scores" >"$TMP/p0-syn-scores.html"
  curl -s --noproxy '*' "$P0B/scores?lang=zh" >"$TMP/p0-syn-scores-zh.html"
  curl -s --noproxy '*' "$P0B/scores?show_deprecated=1" >"$TMP/p0-syn-scores-dep.html"
  curl -s --noproxy '*' "$P0B/fp" >"$TMP/p0-syn-fp.html"
  curl -s --noproxy '*' "$P0B/case?id=E01" >"$TMP/p0-syn-e01.html"
  kill "$P0PID" 2>/dev/null
  wait "$P0PID" 2>/dev/null
  check_grep "SYNTHETIC scatter renders an SVG plot" '<svg' "$TMP/p0-syn-scores.html"
  check_grep "SYNTHETIC scatter plots run points" '<circle' "$TMP/p0-syn-scores.html"
  check_grep "SYNTHETIC scatter labels the product" 'SYNTHETIC-A' "$TMP/p0-syn-scores.html"
  check_grep "SYNTHETIC run carries the demo badge" 'demo-badge' "$TMP/p0-syn-scores.html"
  check_grep "SYNTHETIC FPR heatmap renders the matrix" 'fpr-heatmap' "$TMP/p0-syn-scores.html"
  check_grep "SYNTHETIC heatmap sorts worst class first" 'archive_staging' "$TMP/p0-syn-scores.html"
  check_grep "SYNTHETIC heatmap uses directional bands" 'fpr-3' "$TMP/p0-syn-scores.html"
  check_grep "zh SYNTHETIC scores renders Chinese charts" 'FPR 热力图' "$TMP/p0-syn-scores-zh.html"
  check_grep "SYNTHETIC fp violation table activates" 'Real-machine FP violations' "$TMP/p0-syn-fp.html"
  check_grep "SYNTHETIC fp table labels the product" 'SYNTHETIC-A' "$TMP/p0-syn-fp.html"
  check_grep "SYNTHETIC fp run carries the demo badge" 'demo-badge' "$TMP/p0-syn-fp.html"
  check_grep "SYNTHETIC fp table renders the attempt rate" '>5%</td>' "$TMP/p0-syn-fp.html"
  check_not_grep "SYNTHETIC fp drops the empty state" 'No real-machine run yet.' "$TMP/p0-syn-fp.html"
  check_grep "SYNTHETIC case evidence activates class-level table" 'Class-level detection from runs' "$TMP/p0-syn-e01.html"
  check_grep "SYNTHETIC case evidence renders the expected class" 'download_and_execute' "$TMP/p0-syn-e01.html"
  check_grep "SYNTHETIC case evidence carries the demo badge" 'demo-badge' "$TMP/p0-syn-e01.html"
  check_grep "SYNTHETIC case evidence renders the tier split" '6/2/0/0' "$TMP/p0-syn-e01.html"

  # P3 (docs/16): the SYNTHETIC fixture exercises the run-card enhancements
  # (evidence links, version group, modifier tag, label source, duration) and
  # the deprecated-hide framework. The archived run is hidden by default and
  # revealed by ?show_deprecated=1; the shipped runs[] stays empty throughout.
  check_grep "SYNTHETIC run card links the raw report" 'artifacts/syn-001/report.md' "$TMP/p0-syn-scores.html"
  check_grep "SYNTHETIC run card links the exec log" 'artifacts/syn-001/exec.log' "$TMP/p0-syn-scores.html"
  check_grep "SYNTHETIC run card links the alerts" 'artifacts/syn-001/alerts.json' "$TMP/p0-syn-scores.html"
  check_grep "SYNTHETIC evidence region heading" 'Raw evidence' "$TMP/p0-syn-scores.html"
  check_grep "SYNTHETIC run history grouped by version" 'Version 2026.11' "$TMP/p0-syn-scores.html"
  check_grep "SYNTHETIC run card shows a modifier tag" 'Configuration Change' "$TMP/p0-syn-scores.html"
  check_grep "SYNTHETIC run card shows label source counts" 'native=' "$TMP/p0-syn-scores.html"
  check_grep "SYNTHETIC run card shows the run duration" '123.5 s' "$TMP/p0-syn-scores.html"
  check_grep "SYNTHETIC archive banner offers the toggle" 'Show archived runs' "$TMP/p0-syn-scores.html"
  check_not_grep "SYNTHETIC archived run hidden by default" 'SYNTHETIC-ARCHIVED' "$TMP/p0-syn-scores.html"
  check_grep "SYNTHETIC show_deprecated reveals the archived run" 'SYNTHETIC-ARCHIVED' "$TMP/p0-syn-scores-dep.html"
  check_grep "SYNTHETIC archived run carries the archived badge" 'archived-badge' "$TMP/p0-syn-scores-dep.html"
  check_grep "zh SYNTHETIC scores renders Chinese P3 methodology" '复现与输入三元组' "$TMP/p0-syn-scores-zh.html"
  python3 - "$TMP" "$ROOT" >"$TMP/p0scan.out" 2>&1 <<'PYEOF'
import glob, os, sys
sys.path.insert(0, os.path.join(sys.argv[2], "tools"))
import gen_dashboard_data as gdd
bad = []
for p in sorted(glob.glob(os.path.join(sys.argv[1], "p0-syn-*.html"))):
    hits = gdd.sensitive_hits(open(p, encoding="utf-8").read())
    if hits:
        bad.append("%s: %s" % (os.path.basename(p), hits[:2]))
# The fixture itself must be public-safe too.
hits = gdd.sensitive_hits(open(os.path.join(sys.argv[1], "synthetic_data.json"), encoding="utf-8").read())
if hits:
    bad.append("synthetic_data.json: %s" % hits[:2])
print("p0-scan-clean" if not bad else "p0-scan-broken: " + "; ".join(bad))
PYEOF
  check "SYNTHETIC served pages + fixture pass sensitive scan" "$(cat "$TMP/p0scan.out")" "p0-scan-clean"
else
  echo "WARN: go not found - P2 dashboard HTTP checks SKIPPED (install Go to gate them)"
fi

echo ""
if [ "$fails" -eq 0 ]; then
  echo "SELFTEST OK (0 failures)"
  exit 0
fi
echo "SELFTEST FAILED: $fails failure(s)"
exit 1
