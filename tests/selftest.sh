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
  "validate: OK, 1075 cases (120 fp, 955 attack)"

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
# 87 = 85 migrated + VR549/VR550: the T4 dedup reshapes turned those two
# deletes into artifact-producing forms (dd overwrite, shred -n 1), so each
# gained the rm -f cleanup its data_destruction siblings already carry.
check "cleanup export lists the migrated cases" \
  "$("$ROOT/tools/parse.py" --cleanup "$ROOT/corpus/qinjing.yaml" | wc -l | tr -d ' ')" \
  "87"
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
  "  total cases: 1075" "$TMP/fam.out"
check_grep "family count after benign sub-family split" \
  "  total families: 73" "$TMP/fam.out"
check_grep "public side size" \
  "  public: 896 cases (59 families)" "$TMP/fam.out"
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

echo "== dashboard data generator =="
DD="$TMP/dashboard_data.json"
python3 "$ROOT/tools/gen_dashboard_data.py" --out "$DD" >"$TMP/dd.out" 2>&1
check "dashboard data generator exit code" "$?" "0"
check "committed dashboard_data.json is byte-identical to regeneration" \
  "$(cmp -s "$ROOT/dashboard/dashboard_data.json" "$DD" && echo same)" "same"
check_grep "generator discloses empty runs placeholder" \
  "runs: 0 (phase-2 placeholder; no real-machine run yet)" "$TMP/dd.out"
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
if (t["cases"], t["fp"], t["attack"], t["classes"]) != (1075, 120, 955, 52):
    bad.append("totals %s" % t)
if t["cases"] != len(parse.all_cases(cases)) or t["fp"] != len(cases["false_positives"]):
    bad.append("totals drift from parse")
if t["impact"] != {"none": 580, "temporary": 160, "destructive": 335}:
    bad.append("impact composition %s" % t["impact"])
if t["attack_no_class"] != 20:
    bad.append("attack_no_class %s" % t["attack_no_class"])
cd = data["class_distribution"]
if len(cd) != 52:
    bad.append("class_distribution rows %d" % len(cd))
for r in cd:
    if r["cases"] != r["detectable"] + r["gap"]:
        bad.append("class equation %s" % r["class"])
if sum(r["cases"] for r in cd) + t["attack_no_class"] != t["attack"]:
    bad.append("class + no-class != attack")
if len(data["tactic_coverage"]) != 15:
    bad.append("tactic_coverage rows %d" % len(data["tactic_coverage"]))
hm = data["technique_heatmap"]
if len(hm) != m["techniques_covered"] or len(hm) != 80:
    bad.append("heatmap count %d" % len(hm))
for r in hm:
    if r["score"] < 1 or r["detectable"] + r["gap"] != r["score"]:
        bad.append("heatmap row %s" % r["techniqueID"])
nl = data["navigator_layer"]
if (nl["domain"], nl["versions"]["attack"], len(nl["techniques"])) != ("enterprise-attack", "20.1", 80):
    bad.append("navigator_layer shape")
if (p["corpus_classes"], p["evaluable_ref"], p["service_dep"]) != (52, 14, 21):
    bad.append("provisioning numbers %s" % p)
if len(p["sim_only_classes"]) != 5 or len(p["rows"]) != 52:
    bad.append("provisioning sim_only/rows")
if data["runs"] != []:
    bad.append("runs must stay empty (no real-machine run yet)")
print("dd-ok" if not bad else "dd-broken: " + "; ".join(bad))
PYEOF
check "dashboard data reconciles with corpus + coverage + provisioning" \
  "$(cat "$TMP/ddcheck.out")" "dd-ok"

echo ""
if [ "$fails" -eq 0 ]; then
  echo "SELFTEST OK (0 failures)"
  exit 0
fi
echo "SELFTEST FAILED: $fails failure(s)"
exit 1
