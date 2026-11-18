#!/bin/bash
# qinjing runner: execute every corpus case on the target Linux host and
# write the exec log that scorer.py turns into the detection report.
#
# Usage:  ./runner.sh [corpus.yaml] [--only id1,id2]
#
#   --only  explicit subset run: execute just the listed case ids. The exec
#           log header then carries subset=<ids> and the scorer reports
#           SUBSET (statistics cover the declared set only).
#
# Plan freeze + END trailer (docs/04 D6): the header line records plan=<n>
# (row count frozen from parse.py --tsv before the first case runs) and a
# normal or trapped exit appends "# QINJING-END rows=<m> transport_fail=<k>
# rc=<code>". A missing END line is itself interruption evidence (kill -9).
# An ssh-wrapped case that dies with rc=255 never reached the target: the
# row is NOT written, transport_fail is bumped, and the D6 reconciliation
# in scorer.py flags the missing row.
#
# Env:
#   QINJING_EXEC_LOG  default /tmp/qinjing-exec.log
#   QINJING_SLEEP     seconds between cases, default 2. Keeps per-case
#                     attribution clean (alert timestamps have 1s
#                     granularity) and leaves headroom under per-rule rate
#                     limiters; cases hitting the SAME signal class must be
#                     spaced >=5s or interleaved with other cases, otherwise
#                     a rate-limited alert lands in the neighbor's window.
#   QINJING_ISOLATE   default 1: attack cases run under per-case throwaway
#                     uids (setpriv), so per-uid aggregation buckets stay
#                     per-case and chain groups get one shared uid each.
#                     The BENIGN group always runs as root (owner decision
#                     2026-11-16): its job is argv noise from real system
#                     operations, so the target MUST be a disposable VM.
#                     0 = smoke mode: everything as root, guarded writes
#                     (cron, sudoers, authorized_keys) really land - loud
#                     warning, disposable VM only.
#                     With ISOLATE=1 a missing setpriv ABORTS the run; there
#                     is no silent root fallback.
#   QINJING_TIMEOUT   per-case timeout seconds, default 10.
#   QINJING_MARKER    default 0. 1 = append "# qj:<caseid>:<runtag>" to the
#                     executed string (a bash comment in the SAME argv
#                     element), letting the scorer attribute alerts by exact
#                     marker instead of time window. Off by default because a
#                     downstream product rule with an end-of-string anchor
#                     could stop matching on the suffix; enable only when you
#                     know your detector tolerates it. The exec log records
#                     the executed string, marker included.
#   QINJING_SSH_KEY   session-tree isolation: each case runs in its own ssh
#                     localhost session (independent FORK tree), because
#                     tree-keyed buckets co-bucket every case that shares
#                     the runner's tree; setsid does NOT help (the FORK edge
#                     is recorded at fork time and reparenting never removes
#                     it). Unset = loud fallback to the runner's own tree.
#
# Every case runs as: timeout N setpriv --reuid=UID ... bash -c "<cmd>"
# The full command string lands in ONE argv element - the only shape in
# which per-element matchers see multi-token patterns. Missing binaries
# fail with "command not found" after execve, which is still a detectable
# event with no side effect; that is the sim-missing-bin mode working as
# designed, not a failure.

set -u

DIR=$(cd "$(dirname "$0")" && pwd)
CORPUS=""
ONLY=""
while [ $# -gt 0 ]; do
  case "$1" in
    --only)
      if [ $# -lt 2 ]; then
        echo "ERROR: --only needs a comma-separated case id list" >&2
        exit 1
      fi
      ONLY=$2
      shift 2
      ;;
    --only=*)
      ONLY=${1#--only=}
      shift
      ;;
    *)
      if [ -n "$CORPUS" ]; then
        echo "ERROR: unexpected argument: $1" >&2
        exit 1
      fi
      CORPUS=$1
      shift
      ;;
  esac
done
CORPUS=${CORPUS:-$DIR/../corpus/qinjing.yaml}
LOG=${QINJING_EXEC_LOG:-/tmp/qinjing-exec.log}
SLEEP=${QINJING_SLEEP:-2}
ISOLATE=${QINJING_ISOLATE:-1}
TMO=${QINJING_TIMEOUT:-10}
MARKER=${QINJING_MARKER:-0}

if ! command -v python3 >/dev/null 2>&1; then
  echo "ERROR: python3 required (scorer/parse are python3-only)" >&2
  exit 1
fi
PY=python3

if [ ! -r "$CORPUS" ]; then
  echo "ERROR: corpus not readable: $CORPUS" >&2
  exit 1
fi
if ! "$PY" "$DIR/parse.py" --validate "$CORPUS"; then
  echo "ERROR: corpus lint failed, refusing to run" >&2
  exit 1
fi

# Freeze the plan before anything runs: subset ids deduped in given order,
# then the row count that goes into the header. An empty plan is a refusal,
# not a zero-case run.
if [ -n "$ONLY" ]; then
  ONLY=$(printf '%s' "$ONLY" | tr -d ' ' | awk '{
    n = split($0, a, ","); out = ""
    for (i = 1; i <= n; i++)
      if (a[i] != "" && (out == "" || index("," out ",", "," a[i] ",") == 0))
        out = (out == "" ? a[i] : out "," a[i])
    print out
  }')
  PLAN_TSV=$("$PY" "$DIR/parse.py" --tsv "$CORPUS" | awk -F'\t' -v only="$ONLY" '
    BEGIN { n = split(only, want, ","); for (i = 1; i <= n; i++) keep[want[i]] = 1 }
    keep[$2]')
else
  PLAN_TSV=$("$PY" "$DIR/parse.py" --tsv "$CORPUS")
fi
PLAN=$(printf '%s\n' "$PLAN_TSV" | awk 'NF { n++ } END { print n + 0 }')
if [ "$PLAN" -eq 0 ]; then
  echo "ERROR: plan is empty (--only matched no cases or corpus has none)" >&2
  exit 1
fi

# Pre-flight: which declared binaries are missing on this target? Diagnose
# only - the runner never installs anything (Codex R1 red line). Their
# cases will score NOT-RUN (docs/03 section 1).
MISSING=$(printf '%s\n' "$PLAN_TSV" | awk -F'\t' '
  $4 != "-" && $4 != "" && !seen[$4]++ { print $4 }' | \
  while IFS= read -r b; do command -v "$b" >/dev/null 2>&1 || printf '%s ' "$b"; done)
echo "PLAN: $PLAN case(s) from $CORPUS"
if [ -n "$MISSING" ]; then
  echo "missing binaries (their cases score NOT-RUN): $MISSING"
else
  echo "missing binaries: none"
fi
if [ "${QINJING_DRY_RUN:-0}" = "1" ]; then
  echo "DRY RUN complete; nothing executed, no lock taken, log untouched."
  exit 0
fi

# One run per host at a time: the pre-clean sweep and the shared /tmp/qinjing-*
# side-effect paths are not safe against a concurrent runner.
exec 9>/tmp/qinjing.lock
if command -v flock >/dev/null 2>&1; then
  flock -n 9 || {
    echo "ERROR: another qinjing run holds /tmp/qinjing.lock" >&2
    exit 1
  }
else
  echo "WARNING: flock not found - concurrent-run protection is off" >&2
fi

if [ "$ISOLATE" = "1" ] && ! command -v setpriv >/dev/null 2>&1; then
  echo "ERROR: QINJING_ISOLATE=1 needs setpriv and it is missing;" >&2
  echo "       refusing to fall back to root. Set QINJING_ISOLATE=0 only" >&2
  echo "       if you explicitly accept a root smoke run on a disposable VM." >&2
  exit 1
fi
if [ "$ISOLATE" = "0" ]; then
  echo "WARNING: QINJING_ISOLATE=0 smoke mode - cases run as root; guarded" 2>&1
  echo "         writes (cron/sudoers/authorized_keys) really happen" 2>&1
fi

SSH_WRAP=0
if [ -n "${QINJING_SSH_KEY:-}" ] && \
   ssh -n -o BatchMode=yes -o ConnectTimeout=3 -i "$QINJING_SSH_KEY" \
      root@127.0.0.1 true 2>/dev/null; then
  SSH_WRAP=1
else
  echo "WARNING: QINJING_SSH_KEY unset or unreachable - every case shares the" 2>&1
  echo "         runner session tree; per-case buckets are NOT isolated" 2>&1
fi

# Never silently truncate a previous run's log on the default path; archiving
# it (or pointing QINJING_EXEC_LOG elsewhere) is an explicit human act.
if [ -z "${QINJING_EXEC_LOG:-}" ] && [ -s "$LOG" ]; then
  echo "ERROR: $LOG already has content from an earlier run; refusing to" >&2
  echo "       truncate it. Archive it or set QINJING_EXEC_LOG explicitly." >&2
  exit 1
fi

# Stale artifacts from earlier runs would satisfy prereq probes (e.g. an old
# keypair making the keygen case a no-op), so sweep every corpus side-effect
# path before starting. Safe under the run lock above. The artifact list
# lives in the corpus itself (docs/05 D11): every case's cleanup field,
# exported by parse.py --cleanup and linted by --validate to one "rm -f"
# whose operands are /tmp/qinjing- paths only. Still handwritten because no corpus case
# creates them: qinjing-impact-dir (I03 removes it mid-run, FP30/FP32 only
# probe it), qinjing-immutable-test (D06 chattr needs an existing file),
# and the dot-prefixed probe targets .qinjing-beacon (cron/setcap bait,
# referenced only) and .qinjing-evil-cron (P02 crontab input, referenced
# only).
mkdir -p /tmp/qinjing-impact-dir
: > /tmp/qinjing-immutable-test 2>/dev/null || true
rm -f /tmp/.qinjing-beacon /tmp/.qinjing-evil-cron
while IFS=$'\t' read -r _qj_id _qj_cleanup; do
  [ -n "$_qj_cleanup" ] || continue
  bash -c "$_qj_cleanup"
done < <("$PY" "$DIR/parse.py" --cleanup "$CORPUS")

: > "$LOG"
RUN_TAG=$(( $(date +%s%N) / 1000000 ))
if [ -n "$ONLY" ]; then
  printf '# QINJING start=%s host=%s isolate=%s sleep=%s timeout=%s marker=%s plan=%s subset=%s kernel=%s distro=%s\n' \
    "$RUN_TAG" "$(hostname)" "$ISOLATE" "$SLEEP" "$TMO" "$MARKER" "$PLAN" "$ONLY" \
    "$(uname -r 2>/dev/null || echo unknown)" \
    "$({ . /etc/os-release 2>/dev/null && echo "${PRETTY_NAME:-unknown}"; } || echo unknown)" >> "$LOG"
else
  printf '# QINJING start=%s host=%s isolate=%s sleep=%s timeout=%s marker=%s plan=%s kernel=%s distro=%s\n' \
    "$RUN_TAG" "$(hostname)" "$ISOLATE" "$SLEEP" "$TMO" "$MARKER" "$PLAN" \
    "$(uname -r 2>/dev/null || echo unknown)" \
    "$({ . /etc/os-release 2>/dev/null && echo "${PRETTY_NAME:-unknown}"; } || echo unknown)" >> "$LOG"
fi

# END trailer on every exit path from here on: normal completion, set -u
# failure, or a signal that bash turns into exit (kill -9 cannot be caught;
# the missing trailer is the interruption evidence). Armed after the header
# so pre-run refusals never append to a previous run's log.
ROWS=0
TRANSPORT_FAIL=0
END_WRITTEN=0
write_end() {
  [ "$END_WRITTEN" = "1" ] && return 0
  printf '# QINJING-END rows=%s transport_fail=%s rc=%s\n' \
    "$ROWS" "$TRANSPORT_FAIL" "$1" >> "$LOG"
  END_WRITTEN=1
}
trap 'write_end $?' EXIT
trap 'exit 130' INT
trap 'exit 143' TERM HUP

# Per-run uid offset: buckets keyed on uid fire their first crossing once
# per 10-minute window, so back-to-back runs reusing static uids would
# silence each other's second round. Rotating by epoch-minute staggers any
# two adjacent runs apart.
UID_OFFSET=$(( ($(date +%s) / 60 % 40) * 120 ))

uid_for() {
  case "$1" in
    # benign group stays root by owner decision (header: disposable VM only)
    fp)      echo 0 ;;
    chain-A) echo $((5001 + UID_OFFSET)) ;;
    chain-B) echo $((5002 + UID_OFFSET)) ;;
    chain-C) echo $((5003 + UID_OFFSET)) ;;
    *)       echo $((3000 + UID_OFFSET + $2)) ;;
  esac
}

seq_no=0
while IFS=$'\t' read -r grp cid bucket bin cmd; do
  [ -n "$cid" ] || continue
  seq_no=$((seq_no + 1))
  uid=$(uid_for "$grp" "$seq_no")
  if [ "$bin" != "-" ] && [ -n "$bin" ] && command -v "$bin" >/dev/null 2>&1; then
    found=1
  else
    found=0
  fi
  if [ "$MARKER" = "1" ]; then
    run_cmd="$cmd # qj:$cid:$RUN_TAG"
  else
    run_cmd="$cmd"
  fi
  start=$(( $(date +%s%N) / 1000000 ))
  # rc 255 is reserved for the transport layer. The corpus has ssh/scp client
  # cases (IA01 is mode real) whose own legitimate exit on a refusing peer is
  # 255, so a command-own 255 is remapped to 254 on both paths below; only
  # the ssh wrapper's own failure reaches rc=255 and the transport check.
  if [ "$SSH_WRAP" = "1" ]; then
    qcmd=$(printf '%q' "$run_cmd")
    if [ "$ISOLATE" = "1" ] && [ "$uid" != "0" ]; then
      ssh -n -o BatchMode=yes -o ConnectTimeout=5 -i "$QINJING_SSH_KEY" \
        root@127.0.0.1 \
        "timeout $TMO setpriv --reuid=$uid --regid=$uid --clear-groups bash -c $qcmd; r=\$?; [ \"\$r\" -eq 255 ] && exit 254; exit \$r" \
        >/dev/null 2>&1
    else
      ssh -n -o BatchMode=yes -o ConnectTimeout=5 -i "$QINJING_SSH_KEY" \
        root@127.0.0.1 "timeout $TMO bash -c $qcmd; r=\$?; [ \"\$r\" -eq 255 ] && exit 254; exit \$r" >/dev/null 2>&1
    fi
    rc=$?
    if [ "$rc" = "255" ]; then
      TRANSPORT_FAIL=$((TRANSPORT_FAIL + 1))
      echo "[$cid] TRANSPORT FAIL (ssh rc=255) - row not written"
      sleep "$SLEEP"
      continue
    fi
  elif [ "$ISOLATE" = "1" ] && [ "$uid" != "0" ]; then
    timeout "$TMO" setpriv --reuid="$uid" --regid="$uid" --clear-groups \
      bash -c "$run_cmd" >/dev/null 2>&1
    rc=$?
  else
    timeout "$TMO" bash -c "$run_cmd" >/dev/null 2>&1
    rc=$?
  fi
  if [ "$rc" = "255" ]; then
    rc=254
  fi
  end=$(( $(date +%s%N) / 1000000 ))
  printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' \
    "$start" "$end" "$cid" "$grp" "$uid" "$found" "$rc" "$run_cmd" >> "$LOG"
  ROWS=$((ROWS + 1))
  echo "[$cid] group=$grp uid=$uid bin_found=$found rc=$rc"
  sleep "$SLEEP"
done < <(printf '%s\n' "$PLAN_TSV")

write_end 0
echo ""
echo "Executed $seq_no cases. Waiting 5s for the detection chain to digest..."
sleep 5
echo "DONE. exec log: $LOG"
echo "Next: run your adapter, then tools/scorer.py $CORPUS $LOG alerts.json"
