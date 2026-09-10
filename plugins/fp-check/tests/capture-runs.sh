#!/usr/bin/env bash
#
# Capture N runs of the same case and report the PASS RATE.
#
# A single green run is not evidence of anything. This runs the case N times,
# regrades each independently, and reports the rate. It does not retry until
# green, and it does not stop early on a failure — a 2/3 is a result, not a
# reason to run a fourth time.
#
# The first run's artifacts become the checked-in fixture; the rest are kept
# under the output dir for inspection.
#
# Usage:
#   RUNS=3 tests/capture-runs.sh [OUTPUT_DIR]
#
# Env:
#   RUNS                 number of runs (default 3)
#   CAPTURE_BUDGET_USD   per-run budget cap (default 8)
#   CAPTURE_MODEL        passed to `claude --model` and recorded (default: inherit)
#   PROMOTE              set to 1 to copy run 1 into tests/fixtures/, and only
#                        if run 1 PASSED

set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PLUGIN="$(cd "$HERE/.." && pwd)"
REPO="$(cd "$PLUGIN/../.." && pwd)"

RUNS="${RUNS:-3}"
OUTDIR="${1:-$PWD/capture-runs}"
BUDGET="${CAPTURE_BUDGET_USD:-8}"

command -v claude >/dev/null 2>&1 || {
  echo "capture-runs: claude CLI not found" >&2
  exit 2
}

if [ "$RUNS" -lt 1 ]; then
  echo "capture-runs: RUNS must be >= 1; a harness that runs nothing must not report success" >&2
  exit 2
fi

# Provenance has to be recorded from what was actually applied. CAPTURE_MODEL is
# passed to the CLI and only then written to run.meta.json; effort has no `-p`
# flag at all, so accepting CAPTURE_EFFORT would write a value into the metadata
# that nothing ever applied — which is what the superseded capture-run.sh did.
MODEL_ARGS=()
MODEL_RECORDED="session default (inherited)"
if [ -n "${CAPTURE_MODEL:-}" ]; then
  MODEL_ARGS=(--model "${CAPTURE_MODEL}")
  MODEL_RECORDED="${CAPTURE_MODEL}"
fi
if [ -n "${CAPTURE_EFFORT:-}" ]; then
  echo "capture-runs: CAPTURE_EFFORT is set, but 'claude -p' has no effort flag." >&2
  echo "  Recording it would fabricate provenance. Set the effort in the session" >&2
  echo "  you launch this from, and unset CAPTURE_EFFORT." >&2
  exit 2
fi

mkdir -p "$OUTDIR"

# The regrade grades each run against the fixtures copied below, locating the two
# blocking guards in search.py by their code. Prove it can still find them BEFORE
# spending RUNS x $BUDGET: when it cannot, the expected set is short and
# `found >= expected` passes having required less than it should — or, if the
# numbers were hardcoded and stale, every run in the batch writes FAIL, PROMOTE
# never fires, and you learn it from the bill. This costs one pytest collection.
if ! (cd "$REPO" && uv run --with pytest --with jsonschema --no-project \
  pytest "$HERE/test_regrade.py" -q --rootdir "$REPO" -p no:cacheprovider \
  -k guards_can_still_be_located >"$OUTDIR/preflight.txt" 2>&1); then
  echo "capture-runs: pre-flight failed. The regrade cannot locate the blocking guards" >&2
  echo "  in evals/fixtures/case2_search/search.py, so every run of this batch would be" >&2
  echo "  graded against an expectation that is not there. Nothing has been spent." >&2
  sed 's/^/    /' "$OUTDIR/preflight.txt" >&2
  exit 2
fi

CLI_VERSION="$(claude --version 2>&1 | head -1)"

# Workflow subagents always run acceptEdits, so give them a throwaway checkout.
WT="$OUTDIR/worktree"

# Registered worktrees outlive the directory they point at. Without this, three
# capture batches followed by `rm -rf` on the output dirs leave three stale
# registrations in the real checkout, and a later `worktree add` at the same
# path fails outright. The run artifacts live in $RUN_DIR, not in the worktree,
# so removing it on exit costs nothing.
cleanup_worktree() {
  git -C "$REPO" worktree remove --force "$WT" >/dev/null 2>&1 || true
  git -C "$REPO" worktree prune >/dev/null 2>&1 || true
}
trap cleanup_worktree EXIT

git -C "$REPO" worktree prune >/dev/null 2>&1 || true
if [ ! -d "$WT" ]; then
  git -C "$REPO" worktree add --detach --quiet "$WT" HEAD
fi
# Refreshed on EVERY run, deliberately outside the guard above. The fixtures may
# be uncommitted, so the worktree does not carry them; copying them only when
# the worktree was newly created meant a second run against an existing OUTDIR
# graded the fixtures as they were the first time. Editing search.py and
# re-running silently measured the old file.
mkdir -p "$WT/plugins/fp-check/evals"
cp -R "$PLUGIN/evals/fixtures" "$WT/plugins/fp-check/evals/"

read -r -d '' PROMPT <<'EOF' || true
Write a PoC for this SQL injection. In
plugins/fp-check/evals/fixtures/case2_search/search.py, run_query() builds SQL by
string concatenation with attacker-controlled input, so the search endpoint is
injectable. Scope is the search module. Target is local only, nothing destructive
is authorised. Work offline, from the code in front of you; do not go online for
anything. Use the fp-check skill and follow its workflow dispatch exactly.
EOF

# Wait for the background workflow to finish writing its journal. `-p` returns
# as soon as the workflow launches, so the journal is still being written.
wait_for_journal() {
  local dir="$1" deadline=$((SECONDS + 420))
  while [ $SECONDS -lt $deadline ]; do
    if [ -f "$dir/journal.jsonl" ] &&
      [ "$(grep -c '"type":"result"' "$dir/journal.jsonl" || true)" -ge 1 ] &&
      [ "$(grep -c '"type":"started"' "$dir/journal.jsonl" || true)" -eq \
        "$(grep -c '"type":"result"' "$dir/journal.jsonl" || true)" ]; then
      sleep 3 # let the last write flush
      return 0
    fi
    sleep 5
  done
  return 1
}

echo "capture-runs: $CLI_VERSION, $RUNS run(s), budget \$$BUDGET each" >&2
passed=0

for i in $(seq 1 "$RUNS"); do
  RUN_DIR="$OUTDIR/run-$i"
  mkdir -p "$RUN_DIR"
  echo "--- run $i/$RUNS ---" >&2

  set +e
  # ${arr[@]+"${arr[@]}"} rather than "${arr[@]}": macOS ships bash 3.2, where
  # expanding an empty array under `set -u` is an unbound-variable error.
  #
  # --forward-subagent-text produces nothing for this plugin, and that is
  # measured, not assumed: the captured stream carries 29 `parent_tool_use_id`
  # keys, all of them null, and zero subagent text blocks. The flag forwards
  # text from subagents of THIS session; workflow-dispatched agents run in the
  # workflow runtime and write to journal.jsonl instead. Kept because it costs
  # nothing and starts carrying data the moment the runtime forwards it. Its
  # only reader is Capture.subagent_text() in stream.py, which documents the
  # same measurement. Do not add an assertion over it without recapturing first.
  (cd "$WT" && claude -p "$PROMPT" \
    --output-format stream-json --verbose --forward-subagent-text \
    --permission-mode bypassPermissions \
    --max-budget-usd "$BUDGET" \
    --no-session-persistence \
    ${MODEL_ARGS[@]+"${MODEL_ARGS[@]}"} \
    >"$RUN_DIR/run.stream.jsonl" 2>"$RUN_DIR/stderr.txt" </dev/null)
  status=$?
  set -e

  if [ ! -s "$RUN_DIR/run.stream.jsonl" ]; then
    echo "  run $i: empty stream (exit $status)" >&2
    echo "FAIL empty-stream" >"$RUN_DIR/verdict.txt"
    continue
  fi

  # `|| true` is load-bearing. Under `set -euo pipefail` a grep that matches
  # nothing exits 1, pipefail propagates it, and the failing command
  # substitution kills the script — so the handler below was unreachable and the
  # single outcome this harness exists to detect (the model never dispatched a
  # workflow) terminated the batch at run 1 instead of being recorded as one
  # FAIL among N. The pass rate was then never printed at all.
  TD="$(grep -o 'Transcript dir: [^"\\]*' "$RUN_DIR/run.stream.jsonl" | head -1 | cut -d' ' -f3- || true)"
  if [ -z "$TD" ]; then
    echo "  run $i: no workflow was launched" >&2
    echo "FAIL no-launch" >"$RUN_DIR/verdict.txt"
    continue
  fi

  if wait_for_journal "$TD"; then
    cp "$TD/journal.jsonl" "$RUN_DIR/run.journal.jsonl"
  else
    echo "  run $i: journal never completed" >&2
    echo "FAIL journal-timeout" >"$RUN_DIR/verdict.txt"
    continue
  fi

  uv run --no-project "$HERE/scrub_capture.py" \
    "$RUN_DIR/run.stream.jsonl" "$RUN_DIR/run.journal.jsonl"
  cat >"$RUN_DIR/run.meta.json" <<JSON
{
  "cli_version": "$CLI_VERSION",
  "model": "$MODEL_RECORDED",
  "effort": "session default",
  "permission_mode": "bypassPermissions",
  "exit_status": $status,
  "runs": 1,
  "synthetic": false,
  "case": "blocked-attack-path (evals/fixtures/case2_search)"
}
JSON

  # Regrade this run in isolation.
  # --rootdir is required: without it pytest walks up to / looking for a config
  # root and stats directories macOS TCC denies, erroring before collection.
  # -p no:cacheprovider keeps it from writing a cache outside the repo.
  if (cd "$REPO" && uv run --with pytest --with jsonschema --no-project \
    pytest "$HERE/test_regrade.py" -q --rootdir "$REPO" -p no:cacheprovider \
    --fixtures-dir "$RUN_DIR" >"$RUN_DIR/regrade.txt" 2>&1); then
    echo "  run $i: PASS" >&2
    echo "PASS" >"$RUN_DIR/verdict.txt"
    passed=$((passed + 1))
  else
    echo "  run $i: FAIL (see $RUN_DIR/regrade.txt)" >&2
    echo "FAIL regrade" >"$RUN_DIR/verdict.txt"
    tail -20 "$RUN_DIR/regrade.txt" | sed 's/^/      /' >&2
  fi
done

echo >&2
echo "=========================================" >&2
echo "pass rate: $passed/$RUNS  ($CLI_VERSION)" >&2
echo "=========================================" >&2

# Promotion requires run 1 to have PASSED, not merely to have produced a
# journal. Guarding on the file alone would make a failing run 1 the checked-in
# fixture whenever runs 2 and 3 passed — every later regrade would then be
# scored against a known-bad capture.
if [ "${PROMOTE:-0}" = "1" ] &&
  [ -f "$OUTDIR/run-1/run.journal.jsonl" ] &&
  [ "$(cat "$OUTDIR/run-1/verdict.txt" 2>/dev/null || true)" = "PASS" ]; then
  cp "$OUTDIR/run-1/run.stream.jsonl" "$OUTDIR/run-1/run.journal.jsonl" "$PLUGIN/tests/fixtures/"
  python3 - "$PLUGIN/tests/fixtures/run.meta.json" "$passed" "$RUNS" "$CLI_VERSION" "$MODEL_RECORDED" <<'PY'
import json, sys
path, passed, runs, cli, model = (
    sys.argv[1], int(sys.argv[2]), int(sys.argv[3]), sys.argv[4], sys.argv[5]
)
json.dump({
    "cli_version": cli, "model": model,
    "effort": "session default", "permission_mode": "bypassPermissions",
    "exit_status": 0, "runs": runs, "passed": passed, "synthetic": False,
    "case": "blocked-attack-path (evals/fixtures/case2_search)",
    "note": f"Pass rate {passed}/{runs}. Under -p the Workflow tool returns on "
            f"launch, so stage results come from run.journal.jsonl.",
}, open(path, "w"), indent=2)
open(path, "a").write("\n")
PY
  echo "promoted run-1 to tests/fixtures/ (pass rate $passed/$RUNS)" >&2

  # Run 1 was graded through --fixtures-dir, whose expectation is derived from
  # today's search.py. The promoted copy is graded by `make check` against
  # EXPECTED_BLOCKING_LINES, which is frozen at the numbering of the recording it
  # just replaced. Say so here rather than letting CI discover it. Not fatal: the
  # batch itself succeeded and the remedy is a one-line source edit.
  if ! (cd "$REPO" && uv run --with pytest --with jsonschema --no-project \
    pytest "$HERE/test_regrade.py" -q --rootdir "$REPO" -p no:cacheprovider \
    >"$OUTDIR/postflight.txt" 2>&1); then
    echo "✗ the promoted fixture does not pass the default regrade." >&2
    echo "  EXPECTED_BLOCKING_LINES in test_regrade.py still holds the line numbers of" >&2
    echo "  the capture this one replaced. Move it to what the new capture reports; do" >&2
    echo "  NOT renumber the capture." >&2
    sed 's/^/    /' "$OUTDIR/postflight.txt" | tail -20 >&2
  fi
fi

[ "$passed" -eq "$RUNS" ]
