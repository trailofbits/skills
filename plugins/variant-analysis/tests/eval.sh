#!/usr/bin/env bash
# Variant-analysis eval: run each fixture codebase through Claude twice — once
# with the /variant-analysis:variants workflow, once with the skill alone — and
# score both against ground truth.
#
# NOT named run_*.sh on purpose. `make shell-suites` and CI execute every
# plugins/*/tests/*/run_*.sh they find; this one spawns dozens of subagents and
# costs real money, so it must stay out of that net. run_fixtures.sh is the
# CI-safe half.
#
# Usage:
#   ./eval.sh                          # all codebases, both modes, 1 run each
#   ./eval.sh --codebase gradio        # one codebase (see ground-truth.json for names)
#   ./eval.sh --mode workflow          # skip the baseline
#   ./eval.sh --mode "workflow baseline"  # both, explicitly (quote the pair)
#   ./eval.sh --runs 3                 # repeat for a variance estimate
#   ./eval.sh --strict-decoy           # also require the decoy in the ruled-out section
#   ./eval.sh --keep                   # keep the work dir even when the eval passes
#
# The work dir is deleted on a passing run unless --keep is given. A failing run
# always keeps it: that is when the transcripts are worth reading. A dir given
# with --out is never deleted.

set -euo pipefail

command -v uv >/dev/null 2>&1 || {
  echo "uv is required (https://docs.astral.sh/uv/)" >&2
  exit 1
}

TESTS_DIR="$(cd "$(dirname "$0")" && pwd)"
PLUGIN_DIR="$(cd "$TESTS_DIR/.." && pwd)"
GROUND_TRUTH="$TESTS_DIR/ground-truth.json"

CODEBASES=""
MODES="workflow baseline"
RUNS=1
KEEP=0
MODEL=""
STRICT_DECOY=0
OUT_DIR="${TMPDIR:-/tmp}/variant-analysis-eval.$$"
OUT_GIVEN=0

# Print the leading comment block as usage. Walks to the first non-comment line
# rather than a hardcoded range, which silently spilled `set -euo pipefail` and
# the variable block into --help every time the header changed length.
usage() {
  awk 'NR > 1 && /^#/ { sub(/^# ?/, ""); print; next } NR > 1 { exit }' "$0"
}

while [ $# -gt 0 ]; do
  case "$1" in
    --codebase)
      CODEBASES="$2"
      shift 2
      ;;
    --mode)
      MODES="$2"
      shift 2
      ;;
    --runs)
      RUNS="$2"
      shift 2
      ;;
    --model)
      MODEL="$2"
      shift 2
      ;;
    --keep)
      KEEP=1
      shift
      ;;
    --strict-decoy)
      STRICT_DECOY=1
      shift
      ;;
    --out)
      OUT_DIR="$2"
      OUT_GIVEN=1
      shift 2
      ;;
    -h | --help)
      usage
      exit 0
      ;;
    *)
      echo "unknown option: $1" >&2
      exit 2
      ;;
  esac
done

# Reject an unknown mode rather than falling through build_prompt's else branch.
# `--mode wokflow` used to run the BASELINE prompt, tag the rows "wokflow", and
# then pass summarize.py a summary with no workflow rows — a typo that scored a
# green baseline-vs-nothing run as a success.
HAS_WORKFLOW=0
for mode in $MODES; do
  case "$mode" in
    workflow) HAS_WORKFLOW=1 ;;
    baseline) ;;
    *)
      echo "unknown mode: $mode (expected 'workflow', 'baseline', or both)" >&2
      exit 2
      ;;
  esac
done

command -v claude >/dev/null || {
  echo "claude CLI not found on PATH" >&2
  exit 2
}
command -v jq >/dev/null || {
  echo "jq not found on PATH" >&2
  exit 2
}

if [ -z "$CODEBASES" ]; then
  CODEBASES="$(jq -r '.codebases[].name' "$GROUND_TRUTH")"
fi

STRICT_FLAG=""
if [ "$STRICT_DECOY" -eq 1 ]; then
  STRICT_FLAG="--strict-decoy"
fi

mkdir -p "$OUT_DIR"
SUMMARY="$OUT_DIR/summary.jsonl"
: >"$SUMMARY"

echo "eval output: $OUT_DIR"
echo

# Fail fast if the fixtures drifted — otherwise the whole run measures nothing.
uv run --no-project "$TESTS_DIR/verify_fixtures.py" >"$OUT_DIR/fixtures.log" 2>&1 || {
  echo "fixture verification failed; see $OUT_DIR/fixtures.log" >&2
  exit 1
}

build_prompt() {
  # $1 = mode, $2 = seed bug text, $3 = absolute report path
  if [ "$1" = "workflow" ]; then
    cat <<EOF
/variant-analysis:variants

Hunt for variants of this known bug in the current directory:

$2

Set the report output to $3
EOF
  else
    cat <<EOF
Find all variants of this known bug in the current directory:

$2

Use the variant-analysis skill's methodology. Do NOT use the
/variant-analysis:variants workflow — work through it directly.

Write your findings to $3, following the structure of the variant report
template: a '## Findings' section with one entry per confirmed variant giving
its file and line, and a '## False Positive Patterns' section listing what you
examined and ruled out.
EOF
  fi
}

for name in $CODEBASES; do
  entry="$(jq -r --arg n "$name" '.codebases[] | select(.name == $n)' "$GROUND_TRUTH")"
  if [ -z "$entry" ]; then
    echo "unknown codebase: $name" >&2
    exit 2
  fi
  src="$TESTS_DIR/$(echo "$entry" | jq -r '.path')"
  seed="$(echo "$entry" | jq -r '.seed_bug')"

  for mode in $MODES; do
    run=1
    while [ "$run" -le "$RUNS" ]; do
      work="$OUT_DIR/$name/$mode/run$run"
      mkdir -p "$work"

      printf '%-14s %-9s run %s ... ' "$name" "$mode" "$run"

      # Run IN the checkout rather than a copy: the fixture is ~283 MB, and
      # duplicating it per run costs more than the eval. The report is written to
      # an absolute path under $work instead, so nothing lands in the tree, and
      # the fixture is re-verified after every run to catch an agent that edited
      # the code it was asked to audit.
      #
      # CLAUDE_CODE_PRINT_BG_WAIT_CEILING_MS=0: workflows run in the BACKGROUND,
      # so `claude -p` returns as soon as the main turn ends and by default gives
      # up on background tasks after 600s — "Background tasks still running after
      # 600s; terminating". The report then never lands and the run scores
      # ungradeable even though the hunt was working fine. 0 waits indefinitely.
      set +e
      (
        cd "$src" || exit 127
        export CLAUDE_CODE_PRINT_BG_WAIT_CEILING_MS=0
        # shellcheck disable=SC2086
        build_prompt "$mode" "$seed" "$work/REPORT.md" | claude -p \
          --plugin-dir "$PLUGIN_DIR" \
          --permission-mode bypassPermissions \
          --output-format json \
          ${MODEL:+--model "$MODEL"} \
          >"$work/transcript.json" 2>"$work/claude.err"
      )
      claude_rc=$?
      set -e

      # Did the run mutate the codebase it was auditing? Silent drift would make
      # every later run in this sweep grade against different code.
      if ! uv run --no-project "$TESTS_DIR/verify_fixtures.py" >"$work/fixture-after.log" 2>&1; then
        echo "FIXTURE DRIFTED after this run — see $work/fixture-after.log" >&2
        echo "  restore with: ./setup-gradio.sh --force" >&2
        exit 1
      fi

      if [ "$claude_rc" -ne 0 ]; then
        echo "claude exited $claude_rc (see $work/claude.err)"
        printf '{"codebase":"%s","mode":"%s","run":%s,"gradeable":false,"error":"claude exit %s"}\n' \
          "$name" "$mode" "$run" "$claude_rc" >>"$SUMMARY"
        run=$((run + 1))
        continue
      fi

      set +e
      # shellcheck disable=SC2086  # $STRICT_FLAG is a bare flag or empty, by design
      uv run --no-project "$TESTS_DIR/score.py" \
        --report "$work/REPORT.md" \
        --codebase "$name" \
        --ground-truth "$GROUND_TRUTH" \
        $STRICT_FLAG \
        >"$work/score.json" 2>"$work/score.err"
      score_rc=$?
      set -e

      if [ "$score_rc" -ge 2 ]; then
        echo "ungradeable ($(jq -r '.error // "no report"' "$work/score.json" 2>/dev/null))"
      else
        tp=$(jq -r '.true_positives' "$work/score.json")
        fp=$(jq -r '.false_positives' "$work/score.json")
        recall=$(jq -r '.non_seed_recall' "$work/score.json")
        dec=$(jq -r 'if .decoy_examined_and_ruled_out then "ruled-out" elif .decoy_reported_as_real then "REPORTED" else "unseen" end' "$work/score.json")
        printf 'tp=%s fp=%s new=%s decoy=%s\n' "$tp" "$fp" "$recall" "$dec"
      fi

      jq -c --arg c "$name" --arg m "$mode" --argjson r "$run" \
        '. + {codebase:$c, mode:$m, run:$r}' \
        "$work/score.json" >>"$SUMMARY" 2>/dev/null ||
        printf '{"codebase":"%s","mode":"%s","run":%s,"gradeable":false}\n' \
          "$name" "$mode" "$run" >>"$SUMMARY"

      run=$((run + 1))
    done
  done
done

echo
echo "=== summary ==="
# set +e: a failing eval is a normal outcome here, not a reason to abort before
# reporting where the artifacts landed.
set +e
if [ "$HAS_WORKFLOW" -eq 1 ]; then
  uv run --no-project "$TESTS_DIR/summarize.py" "$SUMMARY"
else
  uv run --no-project "$TESTS_DIR/summarize.py" --baseline-only "$SUMMARY"
fi
rc=$?
set -e

echo
if [ "$KEEP" -eq 1 ] || [ "$rc" -ne 0 ] || [ "$OUT_GIVEN" -eq 1 ]; then
  echo "work dir kept at $OUT_DIR"
else
  # Only ever removes a directory this script created under $TMPDIR. A --out path
  # belongs to the caller and is left alone.
  rm -rf "$OUT_DIR"
  echo "work dir removed (pass --keep to inspect it)"
fi

exit $rc
