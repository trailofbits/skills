#!/usr/bin/env bash
# Eval runner for the writing-lean-proofs plugin (review flow).
#
# Each case gives a Lean fixture with known planted flaws (and known
# non-flaws) to a headless claude run prompted for a review, then grades
# the review transcript against the case rubric with an LLM judge, plus a
# deterministic check that the reviewer did not rewrite the fixture.
set -euo pipefail

EVALS_DIR="$(cd "$(dirname "$0")" && pwd)"
PLUGIN_DIR="$(dirname "$EVALS_DIR")"
SKILL_SRC="$PLUGIN_DIR/skills/writing-lean-proofs"
GRADE_PROMPT="$EVALS_DIR/grade-prompt.md"
PERMISSION_MODE="${EVAL_PERMISSION_MODE:-acceptEdits}"

usage() {
  cat <<'EOF'
usage: run.sh [--arm skill|baseline|both] [--self-test] [case ...]

Runs review-flow evals for the writing-lean-proofs skill.

  --arm        which arm(s) to run: with the skill installed ("skill"),
               without it ("baseline"), or both (default). Comparing the
               two arms measures the skill's uplift.
  --self-test  grade a canned bad review against case 01's rubric and
               assert the grader fails it on every criterion; runs no
               reviewer. Proves the grader still detects its target.
  case         case directory names under evals/cases (default: all)

Environment:
  EVAL_MODEL             model for both the reviewer and the grader
                         (default: your claude CLI default)
  EVAL_PERMISSION_MODE   permission mode for the reviewer run (default:
                         acceptEdits — edits must be POSSIBLE for the
                         no-rewrite check to be meaningful)

Results land in evals/results/<timestamp>/<arm>/<case>/.
EOF
}

MODEL_ARGS=()
if [ -n "${EVAL_MODEL:-}" ]; then
  MODEL_ARGS=(--model "$EVAL_MODEL")
fi

# grade_review <rubric> <fixture-dir> <transcript> <outdir>
# Writes <outdir>/grades.json; fails on empty transcript, zero rubric
# criteria, or a verdict count that does not match the rubric.
grade_review() {
  local rubric="$1" fixdir="$2" transcript="$3" outdir="$4"
  local n_criteria
  n_criteria=$(grep -c '^- id:' "$rubric" || true)
  if [ "$n_criteria" -eq 0 ]; then
    echo "error: rubric has zero criteria: $rubric" >&2
    return 1
  fi
  if [ ! -s "$transcript" ]; then
    echo "error: empty review transcript: $transcript" >&2
    return 1
  fi

  local prompt_file="$outdir/grader-prompt.md"
  {
    cat "$GRADE_PROMPT"
    printf '\n## Rubric\n\n'
    cat "$rubric"
    printf '\n## Reviewed files\n'
    local f
    for f in "$fixdir"/*.lean; do
      printf '\n### %s\n\n```lean\n' "$(basename "$f")"
      cat "$f"
      printf '```\n'
    done
    printf '\n## Review transcript to grade\n\n'
    cat "$transcript"
  } >"$prompt_file"

  claude -p "$(cat "$prompt_file")" ${MODEL_ARGS[@]+"${MODEL_ARGS[@]}"} >"$outdir/grader-raw.txt"

  python3 - "$outdir/grader-raw.txt" "$outdir/grades.json" "$n_criteria" <<'PY'
import json, re, sys

raw = open(sys.argv[1]).read()
match = re.search(r"\[.*\]", raw, re.S)
if not match:
    sys.exit("error: no JSON array in grader output")
grades = json.loads(match.group(0))
expected = int(sys.argv[3])
if len(grades) != expected:
    sys.exit(f"error: grader returned {len(grades)} verdicts, rubric has {expected} criteria")
for g in grades:
    if not isinstance(g.get("id"), str) or not g["id"]:
        sys.exit(f"error: missing criterion id in {g!r}")
    if g.get("verdict") not in ("pass", "fail"):
        sys.exit(f"error: bad verdict in {g!r}")
with open(sys.argv[2], "w") as f:
    json.dump(grades, f, indent=2)
passed = sum(1 for g in grades if g["verdict"] == "pass")
print(f"{passed}/{expected} criteria passed")
PY
}

# checksum_tree <dir> — stable fingerprint of the .lean files in a tree.
checksum_tree() {
  (cd "$1" && find . -name '*.lean' -exec cksum {} \; | sort)
}

# run_case <case-dir> <arm> <outdir>
run_case() {
  local case_dir="$1" arm="$2" outdir="$3"
  local case_name
  case_name=$(basename "$case_dir")
  mkdir -p "$outdir"

  local work
  work=$(mktemp -d)
  cp -R "$case_dir/input/." "$work/"
  if [ "$arm" = "skill" ]; then
    mkdir -p "$work/.claude/skills"
    cp -R "$SKILL_SRC" "$work/.claude/skills/writing-lean-proofs"
  fi

  checksum_tree "$work" >"$outdir/cksum.before"

  echo "[$arm/$case_name] running reviewer..."
  local prompt
  prompt=$(cat "$case_dir/prompt.md")
  (cd "$work" && claude -p "$prompt" ${MODEL_ARGS[@]+"${MODEL_ARGS[@]}"} \
    --permission-mode "$PERMISSION_MODE") >"$outdir/transcript.md"

  checksum_tree "$work" >"$outdir/cksum.after"
  if diff -q "$outdir/cksum.before" "$outdir/cksum.after" >/dev/null; then
    echo "pass" >"$outdir/no-rewrite.txt"
  else
    echo "fail" >"$outdir/no-rewrite.txt"
    diff "$outdir/cksum.before" "$outdir/cksum.after" >>"$outdir/no-rewrite.txt" || true
  fi
  rm -rf "$work"

  echo "[$arm/$case_name] grading..."
  grade_review "$case_dir/rubric.md" "$case_dir/input" \
    "$outdir/transcript.md" "$outdir"
  echo "[$arm/$case_name] no-rewrite: $(head -n 1 "$outdir/no-rewrite.txt")"
}

self_test() {
  local outdir
  outdir=$(mktemp -d)
  echo "[self-test] grading canned bad review against case 01 rubric..."
  grade_review "$EVALS_DIR/cases/01-definitions-review/rubric.md" \
    "$EVALS_DIR/cases/01-definitions-review/input" \
    "$EVALS_DIR/selftest/bad-review.md" "$outdir"
  python3 - "$outdir/grades.json" <<'PY'
import json, sys

grades = json.load(open(sys.argv[1]))
if not grades:
    sys.exit("error: self-test graded zero criteria")
passes = [g["id"] for g in grades if g["verdict"] == "pass"]
if passes:
    sys.exit(
        "error: self-test FAILED — the canned bad review misses every planted "
        f"flaw and commits every forbidden move, yet the grader passed it on: {passes}"
    )
print(f"self-test OK: grader failed the bad review on all {len(grades)} criteria")
PY
  rm -rf "$outdir"
}

ARM="both"
SELF_TEST=0
CASES=()
while [ $# -gt 0 ]; do
  case "$1" in
    --arm)
      ARM="$2"
      shift 2
      ;;
    --self-test)
      SELF_TEST=1
      shift
      ;;
    -h | --help)
      usage
      exit 0
      ;;
    -*)
      echo "unknown option: $1" >&2
      usage >&2
      exit 1
      ;;
    *)
      CASES+=("$1")
      shift
      ;;
  esac
done

if [ "$SELF_TEST" -eq 1 ]; then
  self_test
  exit 0
fi

case "$ARM" in
  skill | baseline | both) ;;
  *)
    echo "invalid --arm: $ARM" >&2
    exit 1
    ;;
esac

if [ ${#CASES[@]} -eq 0 ]; then
  while IFS= read -r d; do
    CASES+=("$(basename "$d")")
  done < <(find "$EVALS_DIR/cases" -mindepth 1 -maxdepth 1 -type d | sort)
fi
if [ ${#CASES[@]} -eq 0 ]; then
  echo "error: no eval cases found under $EVALS_DIR/cases" >&2
  exit 1
fi

ARMS=()
if [ "$ARM" = "both" ]; then ARMS=(baseline skill); else ARMS=("$ARM"); fi

STAMP=$(date +%Y%m%d-%H%M%S)
RESULTS="$EVALS_DIR/results/$STAMP"
RAN=0

for arm in "${ARMS[@]}"; do
  for c in "${CASES[@]}"; do
    case_dir="$EVALS_DIR/cases/$c"
    if [ ! -d "$case_dir" ]; then
      echo "error: no such case: $c" >&2
      exit 1
    fi
    run_case "$case_dir" "$arm" "$RESULTS/$arm/$c"
    RAN=$((RAN + 1))
  done
done

if [ "$RAN" -eq 0 ]; then
  echo "error: ran zero cases" >&2
  exit 1
fi

echo
echo "=== Summary ($RESULTS) ==="
python3 - "$RESULTS" <<'PY'
import json, os, sys

root = sys.argv[1]
rows = 0
for arm in sorted(os.listdir(root)):
    arm_dir = os.path.join(root, arm)
    if not os.path.isdir(arm_dir):
        continue
    for case in sorted(os.listdir(arm_dir)):
        case_dir = os.path.join(arm_dir, case)
        grades_path = os.path.join(case_dir, "grades.json")
        if not os.path.isfile(grades_path):
            continue
        grades = json.load(open(grades_path))
        passed = sum(1 for g in grades if g["verdict"] == "pass")
        rewrite = open(os.path.join(case_dir, "no-rewrite.txt")).readline().strip()
        failed = [g["id"] for g in grades if g["verdict"] == "fail"]
        detail = f"  failed: {', '.join(failed)}" if failed else ""
        print(f"{arm:9s} {case:28s} {passed}/{len(grades)}  no-rewrite:{rewrite}{detail}")
        rows += 1
if rows == 0:
    sys.exit("error: summary found zero graded cases")
PY
