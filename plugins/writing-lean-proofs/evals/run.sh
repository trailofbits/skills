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

# validate_grades <grader-output> <rubric> <grades-output>
# Rejects malformed JSON and any id set/order that differs from the rubric.
validate_grades() {
  python3 - "$1" "$2" "$3" <<'PY'
from collections import Counter
import json
from pathlib import Path
import re
import sys

raw_path = Path(sys.argv[1])
rubric_path = Path(sys.argv[2])
output_path = Path(sys.argv[3])

expected_ids = re.findall(
    r"^- id:\s*([^\s]+)\s*$",
    rubric_path.read_text(encoding="utf-8"),
    re.MULTILINE,
)
if not expected_ids:
    sys.exit(f"error: rubric has zero criteria: {rubric_path}")
duplicate_expected = sorted(
    criterion_id for criterion_id, count in Counter(expected_ids).items() if count > 1
)
if duplicate_expected:
    sys.exit(f"error: rubric has duplicate criterion ids: {duplicate_expected}")

try:
    grades = json.loads(raw_path.read_text(encoding="utf-8"))
except json.JSONDecodeError as error:
    sys.exit(f"error: grader output is not exactly one JSON value: {error}")
if not isinstance(grades, list):
    sys.exit("error: grader output must be a JSON array")

required_keys = {"id", "verdict", "evidence"}
for index, grade in enumerate(grades):
    if not isinstance(grade, dict):
        sys.exit(f"error: verdict {index} is not an object: {grade!r}")
    if set(grade) != required_keys:
        sys.exit(f"error: verdict {index} has wrong keys: {sorted(grade)}")
    if not isinstance(grade["id"], str) or not grade["id"]:
        sys.exit(f"error: missing criterion id in verdict {index}: {grade!r}")
    if grade["verdict"] not in ("pass", "fail"):
        sys.exit(f"error: bad verdict in {grade!r}")
    if not isinstance(grade["evidence"], str) or not grade["evidence"].strip():
        sys.exit(f"error: missing evidence in {grade!r}")

actual_ids = [grade["id"] for grade in grades]
duplicate_actual = sorted(
    criterion_id for criterion_id, count in Counter(actual_ids).items() if count > 1
)
if duplicate_actual:
    sys.exit(f"error: grader returned duplicate criterion ids: {duplicate_actual}")
if actual_ids != expected_ids:
    sys.exit(
        "error: grader criterion ids/order differ from rubric: "
        f"expected {expected_ids}, got {actual_ids}"
    )

output_path.write_text(json.dumps(grades, indent=2) + "\n", encoding="utf-8")
passed = sum(grade["verdict"] == "pass" for grade in grades)
print(f"{passed}/{len(expected_ids)} criteria passed")
PY
}

check_plugin_state() {
  python3 - "$1" <<'PY'
import json
from pathlib import Path
import re
import sys

state_path = Path(sys.argv[1])
try:
    plugins = json.loads(state_path.read_text(encoding="utf-8"))
except json.JSONDecodeError as error:
    sys.exit(f"error: invalid plugin-list JSON: {error}")
if not isinstance(plugins, list):
    sys.exit("error: plugin-list JSON must be an array")
for plugin in plugins:
    if not isinstance(plugin, dict):
        sys.exit(f"error: plugin-list entry is not an object: {plugin!r}")
    if not plugin.get("enabled"):
        continue
    install_path = plugin.get("installPath")
    if not isinstance(install_path, str):
        continue
    root = Path(install_path)
    skill_files = list(root.glob("skills/*/SKILL.md"))
    if (root / "SKILL.md").is_file():
        skill_files.append(root / "SKILL.md")
    for skill_file in skill_files:
        text = skill_file.read_text(encoding="utf-8", errors="replace")
        if re.search(r"^name:\s*['\"]?writing-lean-proofs['\"]?\s*$", text, re.MULTILINE):
            sys.exit(
                "error: enabled plugin supplies writing-lean-proofs: "
                f"{plugin.get('id', install_path)}"
            )
PY
}

# Reject an installed copy of the skill even though --setting-sources project
# excludes user skills. This turns a CLI isolation regression into a loud
# preflight failure instead of a silently contaminated baseline.
check_isolation_preconditions() {
  local config_dir="${CLAUDE_CONFIG_DIR:-$HOME/.claude}"
  if [ -e "$config_dir/skills/writing-lean-proofs" ]; then
    echo "error: user-level writing-lean-proofs skill found under $config_dir/skills" >&2
    echo "use a clean CLAUDE_CONFIG_DIR with working authentication for this eval" >&2
    return 1
  fi

  local plugin_state
  plugin_state=$(mktemp)
  if ! claude plugin list --json >"$plugin_state"; then
    rm -f "$plugin_state"
    echo "error: cannot inspect enabled Claude plugins; isolation is unverified" >&2
    return 1
  fi
  if ! check_plugin_state "$plugin_state"; then
    rm -f "$plugin_state"
    return 1
  fi
  rm -f "$plugin_state"
}

# Mirror of the baseline contamination backstop, for the skill arm.
#
# `cp -R` succeeding proves the skill is on disk; it does not prove the CLI
# *discovered* it. If project-skill discovery under --setting-sources project
# ever changes (project skills move to another source, .claude/skills grows a
# manifest requirement), the copy still succeeds, the skill-arm reviewer runs
# bare, and both arms score identically — which is indistinguishable from the
# true negative "the skill provides no uplift", the one conclusion this suite
# exists to measure. One canary call per run, in the layout run_case_body
# stages, asking the CLI directly what it can see.
check_skill_discovery() {
  local work answer rc=0
  work=$(mktemp -d)
  mkdir -p "$work/.claude/skills"
  if cp -R "$SKILL_SRC" "$work/.claude/skills/writing-lean-proofs"; then
    echo "[preflight] checking project-skill discovery..."
    if answer=$(cd "$work" && claude -p \
      'List the name of every skill available to you, one per line, and nothing else.' \
      ${MODEL_ARGS[@]+"${MODEL_ARGS[@]}"} \
      --setting-sources project \
      --permission-mode "$PERMISSION_MODE"); then
      printf '%s' "$answer" | grep -qi "writing-lean-proofs" || rc=1
    else
      rc=1
    fi
  else
    rc=1
  fi
  rm -rf "$work"
  if [ "$rc" -ne 0 ]; then
    echo "error: the CLI did not report writing-lean-proofs as an available skill" >&2
    echo "under --setting-sources project; the skill arm would run bare and score" >&2
    echo "like the baseline, reporting a false 'no uplift'. Check skill discovery." >&2
    return 1
  fi
}

# grade_review <rubric> <fixture-dir> <transcript> <outdir>
# Writes <outdir>/grades.json; fails on empty transcript, zero rubric
# criteria, malformed output, or criterion ids that do not exactly match.
grade_review() {
  local rubric="$1" fixdir="$2" transcript="$3" outdir="$4"
  mkdir -p "$outdir"
  local n_criteria
  # Same shape as the Python capture below (^- id:\s*([^\s]+)\s*$). A looser
  # pattern here would count a malformed line like `- id: foo bar` that the
  # capture drops, and the run would fail later with an id-mismatch diff
  # instead of pointing at the rubric line.
  n_criteria=$(grep -cE '^- id:[[:space:]]*[^[:space:]]+[[:space:]]*$' "$rubric" || true)
  if [ "$n_criteria" -eq 0 ]; then
    echo "error: rubric has zero criteria: $rubric" >&2
    return 1
  fi
  if [ ! -s "$transcript" ]; then
    echo "error: empty review transcript: $transcript" >&2
    return 1
  fi
  local lean_files=("$fixdir"/*.lean)
  if [ ! -e "${lean_files[0]}" ]; then
    echo "error: fixture has zero .lean files: $fixdir" >&2
    return 1
  fi

  local prompt_file="$outdir/grader-prompt.md"
  {
    cat "$GRADE_PROMPT"
    printf '\n## Rubric\n\n'
    cat "$rubric"
    printf '\n## Reviewed files\n'
    local f
    for f in "${lean_files[@]}"; do
      printf '\n### %s\n\n```lean\n' "$(basename "$f")"
      cat "$f"
      printf '```\n'
    done
    printf '\n## Review transcript to grade\n\n'
    cat "$transcript"
  } >"$prompt_file"

  local grader_work
  grader_work=$(mktemp -d)
  if ! (cd "$grader_work" && claude -p "$(cat "$prompt_file")" \
    ${MODEL_ARGS[@]+"${MODEL_ARGS[@]}"} --setting-sources project) \
    >"$outdir/grader-raw.txt"; then
    rm -r "$grader_work"
    echo "error: grader invocation failed" >&2
    return 1
  fi
  rm -r "$grader_work"

  validate_grades "$outdir/grader-raw.txt" "$rubric" "$outdir/grades.json"
}

# checksum_tree <dir> — stable fingerprint of the fixture .lean files in a
# tree. Excludes .claude/ so the skill-arm's copied skill never enters the
# fingerprint and both arms fingerprint the same file set.
# Fails when it finds zero files: an empty fingerprint would make the
# no-rewrite check pass vacuously.
checksum_tree() {
  local n
  n=$(cd "$1" && find . -path ./.claude -prune -o -name '*.lean' -type f -print | wc -l | tr -d ' ')
  if [ "$n" -eq 0 ]; then
    echo "error: no .lean files under $1 — no-rewrite check would inspect nothing" >&2
    return 1
  fi
  (cd "$1" && find . -path ./.claude -prune -o -name '*.lean' -type f -exec cksum {} \; | sort)
}

# run_case_body <case-dir> <arm> <outdir> <work>
# The working half of run_case, factored out so run_case can remove the
# scratch tree on every path. Several steps here return early (fixture and
# skill copies, both checksums, the reviewer call, the contamination check),
# and a transient auth failure across every case and arm would otherwise
# leave one fixture copy — plus a full skill copy on the skill arm — per
# case under /tmp.
run_case_body() {
  local case_dir="$1" arm="$2" outdir="$3" work="$4"
  local case_name
  case_name=$(basename "$case_dir")

  cp -R "$case_dir/input/." "$work/" || return 1
  if [ "$arm" = "skill" ]; then
    mkdir -p "$work/.claude/skills"
    cp -R "$SKILL_SRC" "$work/.claude/skills/writing-lean-proofs" || return 1
    if [ ! -s "$work/.claude/skills/writing-lean-proofs/SKILL.md" ]; then
      echo "error: skill arm staged no SKILL.md under $work/.claude/skills" >&2
      return 1
    fi
  fi

  checksum_tree "$work" >"$outdir/cksum.before" || return 1

  # --setting-sources project isolates both arms from user-level config:
  # without it, a globally installed writing-lean-proofs skill/plugin would
  # silently contaminate the baseline arm.
  echo "[$arm/$case_name] running reviewer..."
  local prompt
  prompt=$(cat "$case_dir/prompt.md")
  (cd "$work" && claude -p "$prompt" ${MODEL_ARGS[@]+"${MODEL_ARGS[@]}"} \
    --setting-sources project \
    --permission-mode "$PERMISSION_MODE") >"$outdir/transcript.md" || return 1

  checksum_tree "$work" >"$outdir/cksum.after" || return 1

  # Runtime check on the isolation guard: if the baseline reviewer talks
  # about this skill, --setting-sources isolation has failed and the
  # control arm is contaminated.
  if [ "$arm" = "baseline" ] && grep -qi "writing-lean-proofs" "$outdir/transcript.md"; then
    echo "error: baseline transcript mentions writing-lean-proofs — control arm contaminated" >&2
    return 1
  fi
  if diff -q "$outdir/cksum.before" "$outdir/cksum.after" >/dev/null; then
    echo "pass" >"$outdir/no-rewrite.txt"
  else
    echo "fail" >"$outdir/no-rewrite.txt"
    diff "$outdir/cksum.before" "$outdir/cksum.after" >>"$outdir/no-rewrite.txt" || true
  fi

  echo "[$arm/$case_name] grading..."
  if ! grade_review "$case_dir/rubric.md" "$case_dir/input" \
    "$outdir/transcript.md" "$outdir"; then
    echo "[$arm/$case_name] grading FAILED (artifacts in $outdir)" >&2
    return 1
  fi
  echo "[$arm/$case_name] no-rewrite: $(head -n 1 "$outdir/no-rewrite.txt")"
}

# run_case <case-dir> <arm> <outdir>
run_case() {
  local case_dir="$1" arm="$2" outdir="$3"
  local work rc=0
  mkdir -p "$outdir"
  work=$(mktemp -d)
  run_case_body "$case_dir" "$arm" "$outdir" "$work" || rc=$?
  rm -rf "$work"
  return "$rc"
}

grader_validation_self_test() {
  local outdir="$1/validator"
  local rubric="$EVALS_DIR/cases/01-definitions-review/rubric.md"
  mkdir -p "$outdir"
  python3 - "$rubric" "$outdir" <<'PY'
import json
from pathlib import Path
import re
import sys

rubric = Path(sys.argv[1]).read_text(encoding="utf-8")
outdir = Path(sys.argv[2])
criterion_ids = re.findall(r"^- id:\s*([^\s]+)\s*$", rubric, re.MULTILINE)
if not criterion_ids:
    sys.exit("error: validator self-test rubric has zero criteria")

def grades(ids):
    return [
        {"id": criterion_id, "verdict": "pass", "evidence": "self-test"}
        for criterion_id in ids
    ]

(outdir / "good.json").write_text(json.dumps(grades(criterion_ids)), encoding="utf-8")
duplicates = criterion_ids.copy()
duplicates[-1] = criterion_ids[0]
(outdir / "duplicate.json").write_text(json.dumps(grades(duplicates)), encoding="utf-8")
reordered = list(reversed(criterion_ids))
(outdir / "reordered.json").write_text(json.dumps(grades(reordered)), encoding="utf-8")
unknown = criterion_ids.copy()
unknown[-1] = "not-in-rubric"
(outdir / "unknown.json").write_text(json.dumps(grades(unknown)), encoding="utf-8")

plugin_root = outdir / "collision-plugin"
skill_file = plugin_root / "skills" / "writing-lean-proofs" / "SKILL.md"
skill_file.parent.mkdir(parents=True)
skill_file.write_text(
    "---\nname: writing-lean-proofs\ndescription: collision fixture\n---\n",
    encoding="utf-8",
)
plugin = {"id": "collision@test", "enabled": True, "installPath": str(plugin_root)}
(outdir / "enabled-plugin.json").write_text(json.dumps([plugin]), encoding="utf-8")
plugin["enabled"] = False
(outdir / "disabled-plugin.json").write_text(json.dumps([plugin]), encoding="utf-8")
PY

  validate_grades "$outdir/good.json" "$rubric" "$outdir/good-grades.json"
  local bad_case
  for bad_case in duplicate reordered unknown; do
    if validate_grades "$outdir/$bad_case.json" "$rubric" \
      "$outdir/$bad_case-grades.json" >"$outdir/$bad_case.out" \
      2>"$outdir/$bad_case.err"; then
      echo "error: validator accepted $bad_case criterion ids" >&2
      return 1
    fi
    if [ ! -s "$outdir/$bad_case.err" ]; then
      echo "error: validator rejected $bad_case ids without a diagnostic" >&2
      return 1
    fi
  done
  if check_plugin_state "$outdir/enabled-plugin.json" \
    >"$outdir/enabled-plugin.out" 2>"$outdir/enabled-plugin.err"; then
    echo "error: isolation checker accepted an enabled colliding plugin" >&2
    return 1
  fi
  if [ ! -s "$outdir/enabled-plugin.err" ]; then
    echo "error: isolation checker rejected collision without a diagnostic" >&2
    return 1
  fi
  check_plugin_state "$outdir/disabled-plugin.json"
  echo "self-test OK: grader schema and plugin-isolation guards reject bad fixtures"
}

# Two-sided grader self-test against case 01's rubric: the canned bad
# review must fail every criterion (catches a permissive judge) and the
# canned good review must pass every criterion (catches an over-strict
# judge). A judge that answers unconditionally in either direction fails
# exactly one of the two.
self_test() {
  local outdir
  outdir=$(mktemp -d)
  echo "[self-test] artifacts: $outdir (kept on failure for debugging)"

  grader_validation_self_test "$outdir"

  # The preflight runs here rather than at the top of the script so the
  # offline half above — the schema, isolation-fixture and rubric checks,
  # which make no model call — stays runnable on a machine with no `claude`
  # on PATH and no authentication. That is exactly where you want it: a
  # tests/ suite in CI. Everything below this line does call the grader.
  check_isolation_preconditions

  echo "[self-test] grading canned bad review against case 01 rubric..."
  grade_review "$EVALS_DIR/cases/01-definitions-review/rubric.md" \
    "$EVALS_DIR/cases/01-definitions-review/input" \
    "$EVALS_DIR/selftest/bad-review.md" "$outdir/bad"
  python3 - "$outdir/bad/grades.json" <<'PY'
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

  echo "[self-test] grading canned good review against case 01 rubric..."
  grade_review "$EVALS_DIR/cases/01-definitions-review/rubric.md" \
    "$EVALS_DIR/cases/01-definitions-review/input" \
    "$EVALS_DIR/selftest/good-review.md" "$outdir/good"
  python3 - "$outdir/good/grades.json" <<'PY'
import json, sys

grades = json.load(open(sys.argv[1]))
if not grades:
    sys.exit("error: self-test graded zero criteria")
fails = [g["id"] for g in grades if g["verdict"] == "fail"]
if fails:
    sys.exit(
        "error: self-test FAILED — the canned good review hits every planted "
        f"flaw and commits no forbidden move, yet the grader failed it on: {fails}"
    )
print(f"self-test OK: grader passed the good review on all {len(grades)} criteria")
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

check_isolation_preconditions

case "$ARM" in
  skill | baseline | both) ;;
  *)
    echo "invalid --arm: $ARM" >&2
    exit 1
    ;;
esac

if [ "$ARM" = "skill" ] || [ "$ARM" = "both" ]; then
  check_skill_discovery
fi

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

STAMP=$(date +%Y%m%d-%H%M%S)-$$
RESULTS="$EVALS_DIR/results/$STAMP"
RAN=0

CASE_FAILURES=0
REWRITE_FAILURES=0
for arm in "${ARMS[@]}"; do
  for c in "${CASES[@]}"; do
    case_dir="$EVALS_DIR/cases/$c"
    if [ ! -d "$case_dir" ]; then
      echo "error: no such case: $c" >&2
      exit 1
    fi
    # A failed case (reviewer or grader error) is recorded and the run
    # continues, so one malformed judge response cannot discard the
    # results of every other case; we exit non-zero after the summary.
    if ! run_case "$case_dir" "$arm" "$RESULTS/$arm/$c"; then
      echo "[$arm/$c] case FAILED to run or grade" >&2
      CASE_FAILURES=$((CASE_FAILURES + 1))
    elif [ "$(head -n 1 "$RESULTS/$arm/$c/no-rewrite.txt")" != "pass" ]; then
      # The no-rewrite check has to be able to fail the run. Counting it only
      # in the summary would mean that a reviewer which starts applying its
      # own fixes under --permission-mode acceptEdits rewrites every fixture,
      # prints no-rewrite:fail on every line, and still exits 0 — so CI and
      # any scripted use would read the run as green.
      echo "[$arm/$c] reviewer rewrote the fixture" >&2
      REWRITE_FAILURES=$((REWRITE_FAILURES + 1))
    fi
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

STATUS=0
if [ "$CASE_FAILURES" -gt 0 ]; then
  echo "error: $CASE_FAILURES case(s) failed to run or grade" >&2
  STATUS=1
fi
if [ "$REWRITE_FAILURES" -gt 0 ]; then
  echo "error: $REWRITE_FAILURES case(s) had the fixture rewritten by the reviewer" >&2
  STATUS=1
fi
exit "$STATUS"
