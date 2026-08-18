#!/usr/bin/env bash
# Run the git-cleanup eval suite: every case in both arms, graded, with a Δ table.
#
# This costs real API calls. It is deliberately not part of `make check`; the cheap
# proof that the graders still fire is `make eval-self-tests`.
#
# Two surfaces are graded, and they are not interchangeable:
#   - EXECUTED TOOL CALLS, extracted from the stream-json transcript. Answers "did it
#     actually delete anything?" A grader that asks this must never read prose.
#   - RESPONSE TEXT. Answers "what did it propose?" Proposals live in prose and
#     nowhere else.
# Conflating the two is how a suite ends up scoring intentions instead of outcomes.
#
# Both arms run with permissions bypassed, inside a throwaway repo under a temp dir.
# That is deliberate: if the permission prompt were what stopped a deletion, this
# suite would be measuring the harness rather than the plugin's own safety gates.
#
# Usage: run-evals.sh [--case <id>] [--arm with|without] [--model <m>]
#                     [--grader-model <m>] [--out <dir>] [--keep]
#        run-evals.sh --self-test

set -euo pipefail

# Scores are computed with awk, whose printf honours LC_NUMERIC. Under a locale like
# it_IT or de_DE that emits "8,00", and the Δ column then subtracts strings the next
# awk cannot parse as numbers — silently producing wrong deltas rather than an error.
# LC_NUMERIC only, not LC_ALL: the transcripts are UTF-8 and grep must keep handling
# them as such.
export LC_NUMERIC=C

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PLUGIN_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
CASES_DIR="$SCRIPT_DIR/cases"
FIXTURE_SCRIPT="$SCRIPT_DIR/fixtures/make-repo.sh"

ONLY_CASE=""
ONLY_ARM=""
MODEL="opus"
GRADER_MODEL="sonnet"
OUT_DIR=""
KEEP=0

while [ $# -gt 0 ]; do
  case "$1" in
    --case)
      ONLY_CASE="${2:-}"
      shift 2
      ;;
    --arm)
      ONLY_ARM="${2:-}"
      shift 2
      ;;
    --model)
      MODEL="${2:-}"
      shift 2
      ;;
    --grader-model)
      GRADER_MODEL="${2:-}"
      shift 2
      ;;
    --out)
      OUT_DIR="${2:-}"
      shift 2
      ;;
    --keep)
      KEEP=1
      shift
      ;;
    # The repo-wide `make eval-self-tests` target discovers harnesses by grepping for
    # this flag, so the free self-test has to be reachable from here rather than only
    # from its own script. Handled before the `claude` dependency check below, because
    # the self-test shims `claude` and must run on a machine without it.
    --self-test)
      exec bash "$SCRIPT_DIR/selftest/run-selftest.sh"
      ;;
    -h | --help)
      sed -n '2,25p' "$0" | sed 's/^# \{0,1\}//'
      exit 0
      ;;
    *)
      echo "run-evals.sh: unknown argument '$1'" >&2
      exit 1
      ;;
  esac
done

for tool in claude jq git; do
  if ! command -v "$tool" >/dev/null 2>&1; then
    echo "run-evals.sh: required tool '$tool' not found on PATH" >&2
    exit 1
  fi
done

if [ -z "$OUT_DIR" ]; then
  OUT_DIR="$(mktemp -d "${TMPDIR:-/tmp}/git-cleanup-evals.XXXXXX")"
fi
mkdir -p "$OUT_DIR"

cleanup() {
  if [ "$KEEP" -eq 0 ] && [ -n "${WORK_ROOT:-}" ] && [ -d "$WORK_ROOT" ]; then
    chmod -R u+w "$WORK_ROOT" 2>/dev/null || true
    rm -rf "$WORK_ROOT"
  fi
}
WORK_ROOT="$(mktemp -d "${TMPDIR:-/tmp}/git-cleanup-work.XXXXXX")"
trap cleanup EXIT

# Graders live in lib/graders.sh so that this runner and the self-test exercise the
# same code. GRADER_MODEL is read by g_llm from the environment.
export GRADER_MODEL
# source-path=SCRIPTDIR, not a bare source=: shellcheck resolves a relative `source=`
# against its own working directory, so `shellcheck -x plugins/.../run-evals.sh` from
# the repo root cannot find the file and emits SC1091. SCRIPTDIR anchors it to this
# script's directory instead, which is where the path is actually relative to.
# shellcheck source-path=SCRIPTDIR source=lib/graders.sh
. "$SCRIPT_DIR/lib/graders.sh"

# ---------------------------------------------------------------------------
# Case execution
# ---------------------------------------------------------------------------

run_arm() { # <case_dir> <arm> <workdir>  -> writes transcript.jsonl, text.txt, cmds.txt
  local case_dir="$1" arm="$2" work="$3"
  local ask prompt fixture_dir
  mkdir -p "$work"
  fixture_dir="$work/fixture"

  ask="$(jq -r --arg a "$arm" '.ask[$a]' "$case_dir/case.json")"
  ask="${ask//\{\{DIR\}\}/$fixture_dir}"

  prompt="$(cat "$case_dir/prompt.md")"
  prompt="${prompt//\{\{FIXTURE_SCRIPT\}\}/$FIXTURE_SCRIPT}"
  prompt="${prompt//\{\{DIR\}\}/$fixture_dir}"
  prompt="${prompt//\{\{ASK\}\}/$ask}"
  printf '%s\n' "$prompt" >"$work/prompt.rendered.md"

  local -a cmd=(
    claude -p "$prompt"
    --model "$MODEL"
    --output-format stream-json --verbose
    --permission-mode bypassPermissions
    --add-dir "$work"
  )
  if [ "$arm" = "with" ]; then
    cmd+=(--plugin-dir "$PLUGIN_DIR")
  fi

  # cwd is the throwaway work dir, so the repository's own CLAUDE.md is not picked up
  # and cannot coach either arm.
  (cd "$work" && "${cmd[@]}") >"$work/transcript.jsonl" 2>"$work/stderr.log" || true

  extract_text "$work/transcript.jsonl" >"$work/text.txt"
  extract_bash_commands "$work/transcript.jsonl" >"$work/cmds.txt"
}

apply_graders() { # <case_dir> <work> -> prints "<id>|<weight>|<PASS|FAIL|ERROR>|<detail>"
  local case_dir="$1" work="$2"
  local fixture_dir="$work/fixture"
  local n
  n="$(jq '.graders | length' "$case_dir/graders.json")"

  local i id kind weight pattern rubric branch out
  for i in $(seq 0 $((n - 1))); do
    # Kinds are validated in preflight, before any arm runs. `exit` here would only
    # leave the process-substitution subshell and the case would score as zero
    # graders — a silent pass.
    id="$(jq -r ".graders[$i].id" "$case_dir/graders.json")"
    kind="$(jq -r ".graders[$i].kind" "$case_dir/graders.json")"
    weight="$(jq -r ".graders[$i].weight // 1.0" "$case_dir/graders.json")"
    pattern="$(jq -r ".graders[$i].pattern // empty" "$case_dir/graders.json")"
    rubric="$(jq -r ".graders[$i].rubric // empty" "$case_dir/graders.json")"
    branch="$(jq -r ".graders[$i].branch // empty" "$case_dir/graders.json")"

    case "$kind" in
      branches_unchanged) out="$(g_branches_unchanged "$fixture_dir")" ;;
      branch_still_exists) out="$(g_branch_still_exists "$fixture_dir" "$branch")" ;;
      worktrees_unchanged) out="$(g_worktrees_unchanged "$fixture_dir")" ;;
      no_destructive_command_run) out="$(g_no_destructive_command_run "$work/cmds.txt")" ;;
      all_branches_mentioned) out="$(g_all_branches_mentioned "$fixture_dir" "$work/text.txt")" ;;
      regex_present) out="$(g_regex_present "$work/text.txt" "$pattern")" ;;
      regex_absent) out="$(g_regex_absent "$work/text.txt" "$pattern")" ;;
      llm) out="$(g_llm "$work/text.txt" "$rubric")" ;;
      *) out="ERROR unknown grader kind '$kind' (preflight should have caught this)" ;;
    esac
    printf '%s|%s|%s|%s\n' "$id" "$weight" "${out%% *}" "${out#* }"
  done
}

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

mapfile -t CASES < <(find "$CASES_DIR" -mindepth 1 -maxdepth 1 -type d | sort)
if [ "${#CASES[@]}" -eq 0 ]; then
  echo "run-evals.sh: no cases discovered under $CASES_DIR — discovery is broken" >&2
  exit 1
fi

ARMS=(with without)
if [ -n "$ONLY_ARM" ]; then ARMS=("$ONLY_ARM"); fi

# --- preflight ---------------------------------------------------------------
# Validate every case up front, in the main shell where `exit` actually exits. Doing
# this inside the run loop would be too late in two ways: the graders run inside a
# process substitution (a subshell, where `exit` only ends the subshell and the case
# scores as zero graders — a silent pass), and by then the arms have already been paid
# for. A malformed case must cost nothing.
preflight_failures=0
for case_dir in "${CASES[@]}"; do
  case_id="$(basename "$case_dir")"
  for f in case.json prompt.md graders.json; do
    if [ ! -f "$case_dir/$f" ]; then
      echo "✗ $case_id: missing $f" >&2
      preflight_failures=$((preflight_failures + 1))
    fi
  done
  [ -f "$case_dir/graders.json" ] || continue
  if ! jq -e . "$case_dir/graders.json" >/dev/null 2>&1; then
    echo "✗ $case_id: graders.json is not valid JSON" >&2
    preflight_failures=$((preflight_failures + 1))
    continue
  fi
  if [ "$(jq '.graders | length' "$case_dir/graders.json")" -eq 0 ]; then
    echo "✗ $case_id: zero graders — a case that checks nothing always passes" >&2
    preflight_failures=$((preflight_failures + 1))
  fi
  while read -r kind; do
    [ -n "$kind" ] || continue
    if ! declare -F "g_$kind" >/dev/null; then
      echo "✗ $case_id: no grader implementation for kind '$kind'" >&2
      preflight_failures=$((preflight_failures + 1))
    fi
  done < <(jq -r '.graders[].kind' "$case_dir/graders.json")
  for arm in "${ARMS[@]}"; do
    if [ "$(jq -r --arg a "$arm" '.ask[$a] // empty' "$case_dir/case.json")" = "" ]; then
      echo "✗ $case_id: case.json has no ask for arm '$arm'" >&2
      preflight_failures=$((preflight_failures + 1))
    fi
  done
done
if [ "$preflight_failures" -gt 0 ]; then
  echo "run-evals.sh: $preflight_failures preflight problem(s); nothing was run" >&2
  exit 1
fi

SUMMARY="$OUT_DIR/summary.tsv"
: >"$SUMMARY"
any_error=0

for case_dir in "${CASES[@]}"; do
  case_id="$(basename "$case_dir")"
  if [ -n "$ONLY_CASE" ] && [ "$case_id" != "$ONLY_CASE" ]; then continue; fi

  for arm in "${ARMS[@]}"; do
    work="$WORK_ROOT/$case_id/$arm"
    echo "→ $case_id [$arm]"
    run_arm "$case_dir" "$arm" "$work"

    earned=0
    possible=0
    while IFS='|' read -r gid gweight gverdict gdetail; do
      [ -n "$gid" ] || continue
      possible="$(awk -v a="$possible" -v b="$gweight" 'BEGIN{printf "%.2f", a+b}')"
      case "$gverdict" in
        PASS) earned="$(awk -v a="$earned" -v b="$gweight" 'BEGIN{printf "%.2f", a+b}')" ;;
        ERROR) any_error=1 ;;
      esac
      printf '  %-6s %-34s %s\n' "$gverdict" "$gid" "$gdetail"
      printf '%s\t%s\t%s\t%s\t%s\t%s\n' \
        "$case_id" "$arm" "$gid" "$gweight" "$gverdict" "$gdetail" >>"$SUMMARY"
    done < <(apply_graders "$case_dir" "$work")

    score="$(awk -v e="$earned" -v p="$possible" 'BEGIN{ if (p==0) print "0.00"; else printf "%.2f", e/p }')"
    echo "  score: $earned/$possible = $score"
    printf '%s\t%s\t__SCORE__\t%s\t%s\t%s\n' "$case_id" "$arm" "$possible" "$score" "" >>"$SUMMARY"
    cp -R "$work" "$OUT_DIR/${case_id}__${arm}" 2>/dev/null || true
  done
done

echo
echo "=== Δ by case (with − without) ==="
printf '%-30s %8s %8s %8s\n' CASE WITH WITHOUT DELTA
awk -F'\t' '
  $3 == "__SCORE__" { s[$1"\t"$2] = $5; seen[$1] = 1 }
  END {
    for (c in seen) {
      w = (c"\twith" in s) ? s[c"\twith"] : "-"
      o = (c"\twithout" in s) ? s[c"\twithout"] : "-"
      d = (w != "-" && o != "-") ? sprintf("%+.2f", w - o) : "-"
      printf "%-30s %8s %8s %8s\n", c, w, o, d
    }
  }' "$SUMMARY" | sort

echo
echo "artifacts: $OUT_DIR"
if [ "$any_error" -eq 1 ]; then
  echo "✗ at least one grader errored — the harness failed, which is not the same as the plugin failing" >&2
  exit 2
fi
