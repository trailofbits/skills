#!/usr/bin/env bash
# Trigger eval for the property-based-testing skill.
#
# Implements the loop from agentskills.io/skill-creation/optimizing-descriptions:
# run each labelled query against a real Claude Code session with the plugin
# loaded, record whether the skill was invoked, and compare the trigger rate
# against the query's `should_trigger` label.
#
# Each evals-extra/*.md file carries `query` and `should_trigger` frontmatter — the
# same format `claude plugin eval` consumes. Queries run against fixture/, a
# small repo whose files the queries refer to, so the model is deciding on a
# coherent request rather than hunting for paths that do not exist.
#
# The fixture is copied to a tempdir outside the plugin before each run. Run it
# in place and the model's own filesystem exploration walks up into the skill
# directory and reads SKILL.md as an ordinary file — it then has the guidance
# without ever calling the Skill tool, and every query scores a false negative.
#
# Invocation is stochastic. A single run per query reports noise as signal: the
# Echidna query scored 0/1 on one sweep and invoked the skill on the very next
# identical run. Three runs and a >1/2 threshold is the spec's recommendation
# and the default here; RUNS=1 is a smoke test, not a measurement.
#
# One session per query per run, so the sweep is (queries x RUNS) sessions — the
# count is printed on startup rather than quoted here, because a number written into
# prose stops being true the first time a query is added or removed. Dispatched in
# waves of JOBS: an eval nobody is willing to wait for does not get run.
#
# Usage:
#   ./run.sh              # 3 runs per query
#   RUNS=1 ./run.sh       # smoke test
#   JOBS=1 ./run.sh       # serial, for debugging a single session
#   ONLY=04 ./run.sh      # just the queries whose filename matches
#
# A session that crashes or times out is NOT a non-trigger. Every query still runs
# and every result is still reported, but one failed session invalidates the sweep
# — a crash absorbed by the floor's leeway would report a harness failure as a
# passing score.
#
# Exit codes:
#   0  every query met its expectation and every session returned a verdict
#   1  regression: fewer queries passed than EXPECT_PASS
#   2  harness failure: no queries discovered, or a malformed eval file
#   3  invalid: at least one session crashed, timed out, or returned nothing

set -euo pipefail

here="$(cd "$(dirname "$0")" && pwd)"
# PLUGIN_DIR points the sweep at a different copy of the plugin — used to score an
# older SKILL.md against the current one without touching the working tree.
plugin_root="${PLUGIN_DIR:-$(cd "$here/.." && pwd)}"
skill_id="property-based-testing"
# Pinned, not inherited. Trigger rate is a property of a description *and* a model,
# so a result recorded without one is not comparable to the next one.
model="${MODEL:-opus}"
runs="${RUNS:-3}"
only="${ONLY:-}"
jobs_n="${JOBS:-4}"
# Overridable so --self-test can drive the classifier with a stub binary instead of
# spending a whole sweep of real sessions to find out whether it still tells a crash
# from a miss.
claude_bin="${CLAUDE_BIN:-claude}"
# 600, not 300. Measured session latency moves a lot with API load: median 78s on one
# sweep and 158s on the next, with a tail at 292s. At 300s that second sweep spent four
# sessions on timeouts and invalidated itself; the cap has to sit well clear of the
# slowest plausible session or ordinary slowness reads as a harness failure.
timeout_s="${TIMEOUT_S:-600}"
# The model explores before it decides, so the Skill call lands several turns in.
# A tight cap scores "did not reach the decision" as "decided not to trigger".
#
# 200, and deliberately unreachable rather than tuned. At 14 this cap fired on five
# of the eight sessions in one sample that ran to completion, all at num_turns=15,
# silently truncating the measurement it exists to protect.
#
# The three sessions ever observed finishing naturally took 18, 20 and 18 turns at
# ~10.5s/turn, so `timeout 600` binds first at roughly 57 turns and this never fires
# in ordinary operation. It is kept rather than dropped because it bounds the one
# failure the timeout cannot see: a fast tight loop, where turns complete in a second
# instead of ten and the wall clock never notices. At the ~$0.054/turn those sessions
# cost, 200 turns is roughly $11 for a runaway session instead of unbounded — a floor,
# since per-turn cost climbs as context grows.
#
# 10x a max-of-three-observations, not a tight fit. A snug cap derived from n=3 is
# what produced the truncation above; the multiplier is absorbing that uncertainty.
turns="${TURNS:-200}"
threshold_num=1
threshold_den=2 # trigger rate must exceed 1/2

# Through uv, like the rest of the repo: a bare `python3` is rejected by the
# modern-python plugin's shim (#207). Reassigned by --self-test.
py_run=(uv run --no-project python3)

# uv is needed by --self-test itself, which drives the detectors, so it is checked
# here. The claude CLI is not: the self-test swaps $claude_bin for a stub, and that
# check sits below the --self-test dispatch so the assertions stay runnable on a
# machine that has never installed the real CLI. That is what makes them free enough
# for `make check` to depend on.
command -v uv >/dev/null || {
  echo "uv not found — needed to run the JSON detectors" >&2
  exit 2
}

workdir="$(mktemp -d)"
resdir="$(mktemp -d)"
# DELIBERATELY NOT IN THE TRAP. Every session's raw stdout and stderr lands here and
# stays after the run — two sweeps produced ten undiagnosable failures because the
# captures were deleted the moment they had been classified. Its path is printed at
# the start as well as the end, so an aborted run still tells you where to look.
artdir="${ARTIFACT_DIR:-$(mktemp -d)}"
mkdir -p "$artdir"
trap 'rm -rf "$workdir" "$resdir"' EXIT
cp -R "$here/fixture/." "$workdir/"

# Pulls the CLI's own error text out of a stream-json stdout capture.
#
# This exists because of a wrong guess that cost two sweeps. `--output-format
# stream-json` reports failures in the final `result` record on STDOUT — subtype
# plus a human-readable message — and says nothing on stderr. Capturing stderr and
# reading only that produced seven `crash:rc1` notes with empty details, which is
# indistinguishable from having discarded stderr in the first place.
extract_error() {
  [ -s "$1" ] || return 0
  "${py_run[@]}" -c '
import json, sys
best = ""
for line in sys.stdin:
    line = line.strip()
    if not line:
        continue
    try:
        d = json.loads(line)
    except ValueError:
        continue
    if d.get("type") == "result" or d.get("is_error"):
        sub = str(d.get("subtype") or "")
        msg = d.get("result") or d.get("error") or ""
        if isinstance(msg, (dict, list)):
            msg = json.dumps(msg)
        best = " ".join(p for p in (sub, str(msg)) if p and p != "success")
print(best)
' <"$1" 2>/dev/null || true
}

# Echoes `yes`, `no`, or `error:<detail>`. Split out of check_triggered so the
# detector can run BEFORE the exit-status ladder — see the ordering note there.
#
# THE VERDICT IS A PRINTED TOKEN, NOT AN EXIT STATUS. `no` is the one verdict the
# aggregator treats as a measurement, so a detector that could not run must be
# distinguishable from a model that declined — and an exit status cannot carry that:
# python3's own failure status is 1, exactly what the detector returns for "not
# found". A broken interpreter therefore scored every positive session as a clean
# negative, and the sweep read as a recall regression.
skill_invoked() {
  local out
  [ -s "$1" ] || {
    echo "no"
    return
  }
  # stderr folded in: it is what names the reason when the interpreter is what failed.
  out="$("${py_run[@]}" -c '
import json, sys
for line in sys.stdin:
    line = line.strip()
    if not line:
        continue
    try:
        d = json.loads(line)
    except ValueError:
        continue
    for c in (d.get("message") or {}).get("content") or []:
        if isinstance(c, dict) and c.get("type") == "tool_use" and c.get("name") == "Skill":
            if "'"$skill_id"'" in json.dumps(c.get("input") or {}):
                print("yes")
                sys.exit(0)
print("no")
' <"$1" 2>&1)" || true

  case "$out" in
    yes | no) printf '%s\n' "$out" ;;
    *) printf 'error:%s\n' "$(printf '%s' "$out" | tr '\n' ' ' | cut -c1-40)" ;;
  esac
}

# Echoes one of: yes | no | timeout | crash:<detail>, where a failure verdict may
# carry a trailing ": <message>" taken from the session's own error reporting. The
# token before that colon is a fixed vocabulary the self-test pins; the message
# after it is free text bound for the NOTE column.
#
# $2 is an artifact path prefix. Given one, the raw stdout and stderr are written
# there and KEPT — that is the whole point, and it is what makes a failure
# diagnosable after the sweep has finished. Without one (the self-test's unit
# calls) they go to temp files and are removed.
#
# The session's exit status is captured separately from the detector rather than
# piped into it. Piped, a session that crashed, timed out or got rate-limited
# produced no Skill call and so scored identically to a model that considered the
# skill and declined it — a silent zero that reads as a recall regression and,
# worse, still counts toward a passing score. `no` now means the model decided;
# anything else means we did not get a measurement.
check_triggered() {
  local query="$1" prefix="${2:-}" out err rc=0 result detail keep=1 verdict detector_note=""
  if [ -n "$prefix" ]; then
    out="$prefix.stdout.json"
    err="$prefix.stderr"
  else
    out="$(mktemp)"
    err="$(mktemp)"
    keep=0
  fi

  # stdin comes from /dev/null because the sessions run as backgrounded subshells.
  # Four of them inheriting one stdin makes the CLI wait 3s for input that never
  # arrives ("no stdin data received in 3s"). That warning was real; removing it did
  # not reduce the crash count, so it was never the cause — but the redirect is
  # right regardless and the 3s per session is worth not paying.
  timeout "$timeout_s" "$claude_bin" -p "$query" \
    --plugin-dir "$plugin_root" \
    --model "$model" \
    --output-format stream-json --verbose \
    --max-turns "$turns" \
    --permission-mode plan \
    --disallowed-tools Agent \
    </dev/null >"$out" 2>"$err" || rc=$?

  # ORDERING IS LOAD-BEARING. The detector runs first because an invocation is
  # positive and final: nothing later in the session can un-call the skill, so a
  # `yes` stands however the process ended. Only the ABSENCE of a call depends on
  # the session having run to a decision, which is what the failure ladder below
  # protects.
  #
  # This was inverted originally — exit status was consulted first — and it threw
  # away every session that invoked the skill and then hit --max-turns. That loss
  # is not random: the queries needing the most exploration are both the likeliest
  # to reach the cap and the ones whose positive evidence matters most, so the
  # inversion quietly depressed recall on exactly the queries under study.
  verdict="$(skill_invoked "$out")"
  if [ "$verdict" = "yes" ]; then
    result="yes"
  elif [ "$rc" -eq 124 ]; then
    # GNU timeout(1) reserves 124 for "the command hit the limit".
    result="timeout"
  elif [ "$rc" -eq 130 ] || [ "$rc" -eq 137 ] || [ "$rc" -eq 143 ]; then
    # SIGINT / SIGKILL / SIGTERM — an operator or the OOM killer, not the model.
    result="crash:signal$((rc - 128))"
  elif [ "$rc" -ne 0 ]; then
    result="crash:rc$rc"
  elif [ ! -s "$out" ]; then
    # stream-json always emits an init record, so a clean exit with no output at
    # all is a failed session wearing a success status.
    result="crash:nooutput"
  elif [ "$verdict" != "no" ]; then
    # The session itself was healthy and the detector was not. Anything but a
    # failure verdict here scores a broken harness as data.
    result="crash:detector"
    detector_note="${verdict#error:}"
  else
    result="no"
  fi

  # Attached only to failure verdicts, so `yes`/`no` keep the exact values the
  # aggregator switches on and the self-test asserts. Flattened to one line and
  # truncated because several runs' notes concatenate into one table cell — the
  # untruncated text is in the artifact files.
  #
  # stdout first, stderr second: stdout is where the CLI reports its own errors,
  # and stderr is where a process that died before emitting any JSON will have
  # said so. A timeout usually yields neither, because it was killed mid-stream;
  # its partial stdout is in the artifacts and shows how far it got.
  case "$result" in
    yes | no) ;;
    *)
      # The detector's own message wins when it is the thing that failed: a healthy
      # session has no error record for extract_error to find, so without this the
      # NOTE column would say `crash:detector` and nothing about why.
      detail="$detector_note"
      [ -n "$detail" ] || detail="$(extract_error "$out")"
      if [ -z "$detail" ]; then
        detail="$(grep -E '[^[:space:]]' "$err" 2>/dev/null | tail -1 || true)"
      fi
      detail="$(printf '%s' "$detail" |
        sed -e 's/[[:cntrl:]]/ /g' -e 's/  */ /g' -e 's/^ *//' -e 's/ *$//' |
        cut -c1-60 | sed -e 's/ *$//')"
      if [ -n "$detail" ]; then
        result="$result: $detail"
      fi
      ;;
  esac

  [ "$keep" -eq 1 ] || rm -f "$out" "$err"
  printf '%s\n' "$result"
}

# Proves the classifier still separates "the model declined" from "we got no answer",
# and that a failed session cannot be laundered into a passing score. Uses a stub
# binary, so it costs nothing and can run in CI. Mirrors the repo validator's
# --self-test: it fails if it runs fewer assertions than it should.
self_test() {
  local asserts=0 fails=0 d stub got rc

  check() {
    local label="$1" want="$2" got="$3"
    asserts=$((asserts + 1))
    if [ "$got" = "$want" ]; then
      echo "  ok   $label (got $got)"
    else
      echo "  FAIL $label (want $want, got $got)"
      fails=$((fails + 1))
    fi
  }

  d="$(mktemp -d)"
  stub="$d/claude"
  cat >"$stub" <<'SH'
#!/usr/bin/env bash
skill='{"message":{"content":[{"type":"tool_use","name":"Skill","input":{"skill":"property-based-testing:property-based-testing"}}]}}'
other='{"message":{"content":[{"type":"tool_use","name":"Skill","input":{"skill":"unrelated-plugin:other"}}]}}'
text='{"message":{"content":[{"type":"text","text":"here is my answer"}]}}'
case "${STUB_MODE:-}" in
  trigger) echo "$skill" ;;
  otherskill) echo "$other" ;;
  notrigger) echo "$text" ;;
  nooutput) exit 0 ;;
  crash) echo "$text"; exit 42 ;;
  # Two stderr lines, so the classifier has to pick the last non-empty one rather
  # than the first, and a tab to prove the flattening.
  crashmsg) echo "$text"; printf 'starting up\n\tauth failed: token expired\n' >&2; exit 1 ;;
  # The shape the real CLI actually uses: failure reported in the final result
  # record on stdout, nothing on stderr at all.
  errresult)
    echo "$text"
    echo '{"type":"result","subtype":"error_during_execution","is_error":true,"result":"api error: overloaded"}'
    exit 1
    ;;
  # Invoked the skill, THEN ran out of turns — the real shape observed in the wild.
  # The invocation is what the eval measures and it already happened.
  triggercrash)
    echo "$skill"
    echo '{"type":"result","subtype":"error_max_turns","is_error":true}'
    exit 1
    ;;
  # Succeeds, but says something on stderr — the real CLI does exactly this.
  warnonly) echo "$text"; echo 'Warning: no stdin data received in 3s' >&2 ;;
  hang) sleep 30 ;;
  # Crash only on the staking query; answer every other one without the skill.
  selective)
    for a in "$@"; do
      case "$a" in *staking*) echo "$text"; exit 42 ;; esac
    done
    echo "$text"
    ;;
  *) echo "stub: unknown STUB_MODE" >&2; exit 99 ;;
esac
SH
  chmod +x "$stub"

  # Unit: one session at a time, straight through the classifier. `self` is the
  # script's own path: the end-to-end cases below re-execute it, and `$0` alone is
  # only a runnable command when the caller happened to pass a path with a slash in
  # it — `bash run.sh --self-test` from this directory made all four exit 127.
  local self="$here/run.sh"
  claude_bin="$stub"
  timeout_s=2

  export STUB_MODE=trigger
  got="$(check_triggered q)"
  check "skill invoked -> yes" yes "$got"

  export STUB_MODE=notrigger
  got="$(check_triggered q)"
  check "model answered without the skill -> no" no "$got"

  export STUB_MODE=otherskill
  got="$(check_triggered q)"
  check "a different skill does not count -> no" no "$got"

  export STUB_MODE=crash
  got="$(check_triggered q)"
  check "nonzero exit -> crash, not a miss" "crash:rc42" "$got"

  export STUB_MODE=nooutput
  got="$(check_triggered q)"
  check "clean exit with no output -> crash" "crash:nooutput" "$got"

  # The point of capturing stderr at all: a crash has to arrive with the message
  # that explains it. Last non-empty line, tab flattened to a space.
  export STUB_MODE=crashmsg
  got="$(check_triggered q)"
  check "crash carries the last stderr line" "crash:rc1: auth failed: token expired" "$got"

  # ...and a session that succeeds while warning on stderr must stay exactly `no`.
  # The aggregator switches on the literal strings yes/no, so appending a message
  # here would silently reclassify every warning-emitting session as unparseable.
  export STUB_MODE=warnonly
  got="$(check_triggered q)"
  check "stderr on a successful session is not appended" no "$got"

  # The one that matters most: the real CLI reports errors on stdout, not stderr.
  # Reading stderr alone is what left seven real crashes with empty notes.
  export STUB_MODE=errresult
  got="$(check_triggered q)"
  check "crash detail read from the stdout result record" \
    "crash:rc1: error_during_execution api error: overloaded" "$got"

  # Precedence: an invocation outranks a nonzero exit. Scoring this as a crash
  # discarded real positive evidence, biased against the queries that explore most.
  export STUB_MODE=triggercrash
  got="$(check_triggered q)"
  check "skill invoked then out of turns -> yes, not crash" yes "$got"

  # Artifacts have to survive the call, or none of the above is diagnosable later.
  export STUB_MODE=crashmsg
  got="$(check_triggered q "$d/keepme")"
  if [ -s "$d/keepme.stdout.json" ] && [ -s "$d/keepme.stderr" ]; then
    got="kept"
  else
    got="lost: stdout=$([ -s "$d/keepme.stdout.json" ] && echo y || echo n) stderr=$([ -s "$d/keepme.stderr" ] && echo y || echo n)"
  fi
  check "raw stdout and stderr are retained when given a prefix" kept "$got"

  export STUB_MODE=hang
  got="$(check_triggered q)"
  check "session over the limit -> timeout" timeout "$got"

  # The bug this whole token-vs-exit-status design exists to prevent: a healthy
  # session whose detector could not run must be a failure, never a negative
  # verdict. An interpreter shim did exactly this and scored every positive `no`.
  export STUB_MODE=trigger
  py_run=(/nonexistent/python3)
  got="$(check_triggered q)"
  py_run=(uv run --no-project python3)
  case "$got" in crash:detector*) got="crash:detector" ;; esac
  check "detector that cannot run -> crash:detector, not no" crash:detector "$got"

  # End to end: the exit code is what CI reads, so assert on that directly.
  # A crash must invalidate (3) even though it would otherwise look like a miss.
  rc=0
  STUB_MODE=crash CLAUDE_BIN="$stub" TIMEOUT_S=2 RUNS=1 JOBS=4 \
    "$self" >/dev/null 2>&1 || rc=$?
  check "sweep with crashed sessions exits 3 (invalid)" 3 "$rc"

  # ...and a sweep that merely scores badly must stay distinguishable from that.
  rc=0
  STUB_MODE=notrigger CLAUDE_BIN="$stub" TIMEOUT_S=2 RUNS=1 JOBS=4 \
    "$self" >/dev/null 2>&1 || rc=$?
  check "clean sweep below the floor exits 1 (regression)" 1 "$rc"

  # The case that motivated all of this, tested as a matched pair. Both runs answer
  # every query without the skill and so score identically (8 of 15 met — the
  # negatives); the only difference is that one crashes on the staking query.
  #
  # The control has to be here. Invalidation short-circuits ahead of the floor check,
  # so the exit-3 assertion below holds whether or not the floor was met — on its own
  # it cannot tell "invalidation beat a passing floor" from "the floor was failing
  # anyway". The control pins the floor as genuinely met at this score. If the query
  # mix ever drifts enough to change that, the control fails loudly and tells you to
  # retune EXPECT_PASS, instead of the pair silently stopping testing precedence.
  rc=0
  STUB_MODE=notrigger CLAUDE_BIN="$stub" TIMEOUT_S=2 RUNS=1 JOBS=4 EXPECT_PASS=8 \
    "$self" >/dev/null 2>&1 || rc=$?
  check "control: this score clears a floor of 8" 0 "$rc"

  rc=0
  STUB_MODE=selective CLAUDE_BIN="$stub" TIMEOUT_S=2 RUNS=1 JOBS=4 EXPECT_PASS=8 \
    "$self" >/dev/null 2>&1 || rc=$?
  check "same score + one crashed query -> invalid, not a pass" 3 "$rc"

  # The CLI preflight lives below the --self-test dispatch so these assertions run on
  # a machine without the real binary. Moving it there is only safe if a real sweep
  # still refuses to start without one, so pin that: the risk on the next edit is the
  # check being deleted rather than moved, which would turn a typo'd CLAUDE_BIN into
  # 45 crash:rc127 sessions instead of an immediate exit.
  rc=0
  CLAUDE_BIN=/nonexistent/claude TIMEOUT_S=2 RUNS=1 JOBS=1 \
    "$self" >/dev/null 2>&1 || rc=$?
  check "a real sweep with no CLI still exits 2" 2 "$rc"

  unset STUB_MODE
  rm -rf "$d"

  echo
  if [ "$asserts" -lt 17 ]; then
    echo "self-test ran $asserts assertions, expected 17 — the self-test is broken" >&2
    exit 2
  fi
  [ "$fails" -eq 0 ] || {
    echo "$fails self-test assertion(s) failed" >&2
    exit 1
  }
  echo "run.sh self-test passed ($asserts assertions)"
}

if [ "${1:-}" = "--self-test" ]; then
  self_test
  exit 0
fi

# Below the dispatch on purpose — see the uv check at the top. A real sweep still
# refuses to start without its binary, and the self-test's child sweeps pass
# CLAUDE_BIN=<stub>, so they validate that stub here like any other run.
command -v "$claude_bin" >/dev/null || {
  echo "claude CLI not found: $claude_bin" >&2
  exit 2
}

bases=()
expects=()
queries=()

for f in "$here"/*.md; do
  [ -e "$f" ] || continue
  base="$(basename "$f" .md)"
  [ -n "$only" ] && [[ "$base" != *"$only"* ]] && continue

  query="$(
    "${py_run[@]}" - "$f" <<'PY'
import re, sys
t = open(sys.argv[1]).read()
m = re.search(r'^---\n(.*?)\n---', t, re.S)
if not m:
    sys.exit("no frontmatter")
fm = m.group(1)
q = re.search(r'^query:\s*"(.*)"\s*$', fm, re.M)
if not q:
    sys.exit("no query field")
print(q.group(1))
PY
  )"
  expect="$(grep -oE '^should_trigger:[[:space:]]*(true|false)' "$f" | awk '{print $2}')"
  [ -n "$expect" ] || {
    echo "$base: missing should_trigger" >&2
    exit 2
  }

  bases+=("$base")
  expects+=("$expect")
  queries+=("$query")
done

# Waves of jobs_n rather than `wait -n`, which needs bash 4.3 — macOS still
# ships 3.2 as /bin/bash and this has to run wherever the CLI does.
#
# Progress goes to stderr per wave. The table cannot be printed until every session
# lands, so without this the script sits silent for tens of minutes and reads as hung.
total=$((${#bases[@]} * runs))
done_n=0
echo "dispatching $total session(s), $jobs_n at a time" >&2
echo "artifacts: $artdir" >&2

pending=0
for i in "${!bases[@]}"; do
  for r in $(seq 1 "$runs"); do
    (
      # The subshell's own stderr goes to a file too. Without this, a failure in
      # `cd`, in check_triggered, or in the result write itself produced
      # `crash:subshell` with the explanation printed into a backgrounded
      # subshell's stderr, which nothing was reading.
      exec 2>>"$artdir/${bases[$i]}.$r.harness.stderr"
      # Never let the subshell die silently — an absent result file is itself
      # scored as a failed session below, but writing the reason is better.
      st="$(cd "$workdir" && check_triggered "${queries[$i]}" "$artdir/${bases[$i]}.$r")" ||
        st="crash:subshell"
      printf '%s\n' "${st:-crash:empty}" >"$resdir/${bases[$i]}.$r"
    ) &
    pending=$((pending + 1))
    if [ "$pending" -ge "$jobs_n" ]; then
      wait
      done_n=$((done_n + pending))
      pending=0
      echo "  $done_n/$total sessions complete" >&2
    fi
  done
done
wait
# The last wave is short whenever jobs_n does not divide the session total. It was
# always collected and scored; without this it was just never counted, so the progress
# line stopped one short and looked like a lost session in the one harness that must
# never appear to lose one.
if [ "$pending" -gt 0 ]; then
  done_n=$((done_n + pending))
  echo "  $done_n/$total sessions complete" >&2
fi

inspected=0
failed=0
broken=0
printf 'model=%s runs=%s plugin=%s\n' "$model" "$runs" "$plugin_root"
printf '%-34s %-8s %-8s %-8s %s\n' QUERY EXPECT RATE RESULT NOTE
printf -- '--------------------------------------------------------------------------------\n'

for i in "${!bases[@]}"; do
  base="${bases[$i]}"
  expect="${expects[$i]}"
  hits=0
  bad_n=0
  note=""

  for r in $(seq 1 "$runs"); do
    st="$(cat "$resdir/$base.$r" 2>/dev/null)" || st=""
    case "$st" in
      yes) hits=$((hits + 1)) ;;
      no) ;;
      # Anything else is a session that never produced a verdict. A missing file
      # means the subshell itself died before it could write one.
      "")
        bad_n=$((bad_n + 1))
        note="${note:+$note, }noresult"
        ;;
      *)
        bad_n=$((bad_n + 1))
        note="${note:+$note, }$st"
        ;;
    esac
  done

  broken=$((broken + bad_n))
  inspected=$((inspected + 1))

  # pass when (hits/runs > 1/2) matches the expectation
  if [ $((hits * threshold_den)) -gt $((runs * threshold_num)) ]; then
    actual=true
  else
    actual=false
  fi
  if [ "$actual" = "$expect" ]; then
    result="ok"
  else
    result="FAIL"
    failed=$((failed + 1))
  fi

  # A query with a failed session has an unknown denominator, so its rate is not a
  # measurement whichever side of the threshold it landed on. Say so rather than
  # printing a verdict the data cannot support.
  [ "$bad_n" -gt 0 ] && result="INVALID"

  printf '%-34s %-8s %-8s %-8s %s\n' "$base" "$expect" "$hits/$runs" "$result" "$note"
done

printf -- '--------------------------------------------------------------------------------\n'
if [ "$inspected" -eq 0 ]; then
  echo "no queries inspected — discovery is broken, not a clean result" >&2
  exit 2
fi

passed=$((inspected - failed))
echo "$passed/$inspected passed, $broken/$((inspected * runs)) session(s) failed"
echo "artifacts (raw stdout + stderr per session, kept): $artdir"

# A failed session invalidates the sweep outright, before any score is consulted.
# Otherwise a crash counts as a non-trigger and is absorbed by the floor's leeway:
# 10 queries x 3 runs against a floor of 27 tolerates 3 misses, so a query that
# crashed all three times still totals 27 and reports a pass. That is a harness
# failure being laundered into a green result, which is the one outcome this eval
# exists to prevent. Exit 3 keeps it distinguishable from a real regression (1)
# and from broken discovery (2).
if [ "$broken" -gt 0 ]; then
  echo "run INVALID: $broken session(s) never returned a verdict — see NOTE column." >&2
  echo "Scores above are reported for the surviving sessions but are not a measurement." >&2
  # The NOTE column is truncated to keep the table readable. Name the full captures
  # so diagnosing a failure is reading a file rather than reproducing the sweep.
  echo "Raw capture for each failed session:" >&2
  for i in "${!bases[@]}"; do
    for r in $(seq 1 "$runs"); do
      st="$(cat "$resdir/${bases[$i]}.$r" 2>/dev/null)" || st=""
      case "$st" in
        yes | no) ;;
        *) echo "  $artdir/${bases[$i]}.$r.stdout.json (+ .stderr)" >&2 ;;
      esac
    done
  done
  exit 3
fi

# Two positives do not reach the threshold today (04, 07 — see README). A
# suite that is red on every run gets ignored and then deleted, so the gate is a
# floor rather than perfection: it fails on a *regression* below the recorded
# score. Raise the floor when you improve the description; never lower it to go
# green. Only meaningful on a full sweep — ONLY= scores a subset.
if [ -n "$only" ]; then
  exit 0
fi
floor="${EXPECT_PASS:-13}"
if [ "$passed" -lt "$floor" ]; then
  echo "regression: $passed passed, floor is $floor" >&2
  exit 1
fi
