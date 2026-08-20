#!/usr/bin/env bash
# With/without-v2 ablation: runs the eval cases against this plugin (arm A) and against
# the v1.1.0 stop-hook plugin checked out from git (arm B), then prints the scorecard.
# Paid and manual — see README.md in this directory before running.
set -euo pipefail

usage() {
  echo "usage: run.sh --baseline-ref <ref> [--expect-version V] [--runs N] [--case NAME] [--judge-model M]" >&2
  exit 2
}

RUNS=3
CASE=""
JUDGE="sonnet"
BASELINE_REF=""
EXPECT_VERSION="1.1.0"
while [ $# -gt 0 ]; do
  case "$1" in
    --baseline-ref)
      BASELINE_REF=${2:?}
      shift 2
      ;;
    --runs)
      RUNS=${2:?}
      shift 2
      ;;
    --case)
      CASE=${2:?}
      shift 2
      ;;
    --judge-model)
      JUDGE=${2:?}
      shift 2
      ;;
    --expect-version)
      EXPECT_VERSION=${2:?}
      shift 2
      ;;
    *) usage ;;
  esac
done
[ -n "$BASELINE_REF" ] || usage

for tool in claude git jq uv; do
  command -v "$tool" >/dev/null 2>&1 || {
    echo "run.sh: $tool not found" >&2
    exit 1
  }
done

HERE="$(cd "$(dirname "$0")" && pwd)"
PLUGIN_DIR="$(cd "$HERE/../.." && pwd)"
REPO_ROOT="$(git -C "$PLUGIN_DIR" rev-parse --show-toplevel)"
STAMP=$(date +%Y%m%d-%H%M%S)
OUT="$HERE/results/$STAMP"
mkdir -p "$OUT"

# The baseline ref must actually be v1.1.0 — measuring against the wrong baseline is
# worse than not measuring.
BASE_VERSION=$(git -C "$REPO_ROOT" show "$BASELINE_REF:plugins/skill-improver/.claude-plugin/plugin.json" | jq -r .version)
if [ "$BASE_VERSION" != "$EXPECT_VERSION" ]; then
  echo "run.sh: $BASELINE_REF carries skill-improver $BASE_VERSION, not $EXPECT_VERSION — pass the right commit or --expect-version" >&2
  exit 1
fi

# Arm B: the old plugin, with THIS suite's cases grafted in (cases and graders are
# harness-side, not plugin content, so both arms answer the same questions).
#
# Case directories and grader files get NEUTRAL names in the graft. Measured incident:
# the old plugin's own SKILL.md walks its plugin root looking for its setup script, the
# listing enumerated the grafted eval tree, and grader filenames alone read as
# instructions (trap-name-kept, decoy-byte-identical, guarantee-byte-identical...) —
# ten of fifteen baseline runs were contaminated. Real case names still come from each
# case.yaml `name:` field, so reports are unaffected; reading a grader body or case.yaml
# is still caught by the contamination gate's content markers.
ARM_B="$OUT/arm-b-plugin"
mkdir -p "$ARM_B"
git -C "$REPO_ROOT" archive "$BASELINE_REF" plugins/skill-improver | tar -x -C "$ARM_B" --strip-components=1
mkdir -p "$ARM_B/skill-improver/evals"
i=0
for c in "$HERE"/../*/; do
  name=$(basename "$c")
  { [ "$name" = "ablation" ] || [ "$name" = "results" ]; } && continue
  i=$((i + 1))
  dest="$ARM_B/skill-improver/evals/c$i"
  cp -R "$c" "$dest"
  rm -f "$dest/verify-pins.sh"
  j=0
  for g in "$dest"/graders/*.md; do
    j=$((j + 1))
    mv "$g" "$dest/graders/r$j.md"
  done
done
cp "$HERE/../.gitignore" "$ARM_B/skill-improver/evals/.gitignore"

# The grafted case.yamls name fixture reviewer plugins by path (../../tests/fixtures/…);
# the old plugin's archive predates them, so carry this tree's copies over or every
# case fails to load in arm B.
mkdir -p "$ARM_B/skill-improver/tests"
rm -rf "$ARM_B/skill-improver/tests/fixtures"
cp -R "$PLUGIN_DIR/tests/fixtures" "$ARM_B/skill-improver/tests/fixtures"

EVAL_ARGS=(--runs "$RUNS" --judge-model "$JUDGE" --scaffold --keep-temp --no-publish --threshold 0)
[ -n "$CASE" ] && EVAL_ARGS+=(--case "$CASE")

echo "=== arm A (v2, this tree) ==="
(cd "$PLUGIN_DIR" && CLAUDE_CODE_WALNUT_SPIRE=1 claude plugin eval . "${EVAL_ARGS[@]}" --json "$OUT/arm-a.json")
uv run --no-project "$HERE/../check_contamination.py" "$OUT/arm-a.json"

echo "=== arm B ($EXPECT_VERSION @ $BASELINE_REF) ==="
(cd "$ARM_B/skill-improver" && CLAUDE_CODE_WALNUT_SPIRE=1 claude plugin eval . "${EVAL_ARGS[@]}" --json "$OUT/arm-b.json")
# --allow-listing: the old plugin's own file search lists the (neutralized) eval tree.
uv run --no-project "$HERE/../check_contamination.py" --allow-listing "$OUT/arm-b.json"

uv run --no-project "$HERE/scorecard.py" \
  --arm-a-json "$OUT/arm-a.json" --arm-a-results "$PLUGIN_DIR/evals/results" \
  --arm-b-json "$OUT/arm-b.json" --arm-b-results "$ARM_B/skill-improver/evals/results" \
  --collector "$PLUGIN_DIR/scripts/collect_metrics.py" |
  tee "$OUT/SCORECARD.md"

echo "scorecard: $OUT/SCORECARD.md — paste it into the PR"
