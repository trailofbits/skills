#!/usr/bin/env bash
# Two halves. The first proves validate_report.py still rejects the analysis
# errors it exists to catch — run it any time, it needs no model and no network.
# The second runs the eval case end to end and asserts the agent's own report
# passes that same validator.
#
#   DETERMINISTIC_ONLY=1 tests/smoke-test.sh   # first half only
#   ANTHROPIC_API_KEY=... tests/smoke-test.sh  # both
set -euo pipefail

tests_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
plugin_dir="$(cd "$tests_dir/.." && pwd)"
validator="$tests_dir/validate_report.py"
fixture_dir="$tests_dir/fixtures"
work="$(mktemp -d "${TMPDIR:-/tmp}/mutation-testing-smoke.XXXXXX")"

cleanup() {
  status=$?
  if [[ "${KEEP_ARTIFACTS:-0}" == "1" || "$status" -ne 0 ]]; then
    echo "artifacts: $work"
  else
    rm -rf "$work"
  fi
}
trap cleanup EXIT

# A report that gets the line-37 equivalence split right.
uv run --no-project python3 "$validator" "$fixture_dir/good-report.md"

# Both ways of getting it wrong must be rejected, and for the stated reason —
# an --expect-fail that passes for an incidental reason proves nothing.
both="$(uv run --no-project python3 "$validator" "$fixture_dir/broken-filters-both.md" --expect-fail)"
echo "$both"
grep -q 'balance >= 0. is listed as an equivalent mutant' <<<"$both" || {
  echo "error: broken-filters-both.md was rejected, but not for filtering '>= 0' as equivalent" >&2
  exit 1
}

neither="$(uv run --no-project python3 "$validator" "$fixture_dir/broken-filters-neither.md" --expect-fail)"
echo "$neither"
grep -q 'balance != 0. is not listed as an equivalent mutant' <<<"$neither" || {
  echo "error: broken-filters-neither.md was rejected, but not for missing the '!= 0' equivalent" >&2
  exit 1
}

if [[ "${DETERMINISTIC_ONLY:-0}" == "1" ]]; then
  echo "PASS: mutation-testing deterministic validation (1 good report accepted, 2 broken rejected)"
  exit 0
fi

command -v claude >/dev/null 2>&1 || {
  echo "error: Claude Code 2.1.220+ is required for the semantic smoke" >&2
  exit 2
}
[[ -n "${ANTHROPIC_API_KEY:-}" ]] || {
  echo "error: ANTHROPIC_API_KEY must be set — the eval sandbox gets a fresh HOME and" >&2
  echo "       config dir, so it does not inherit an interactive login." >&2
  echo "       Run with DETERMINISTIC_ONLY=1 to skip this half." >&2
  exit 2
}

# Keep each sandbox under this run so report discovery cannot pick up another
# evaluation's artifacts. This smoke checks one arm and does not measure uplift.
mkdir -p "$work/sandboxes"
TMPDIR="$work/sandboxes/" claude plugin eval "$plugin_dir" \
  --case weak-suite-analysis --runs "${RUNS:-1}" --threshold 1 \
  --ablation none --no-publish \
  --model "${MODEL:-sonnet}" --judge-model "${JUDGE_MODEL:-sonnet}" \
  --allow-tools Write --keep-temp \
  --max-cost-usd "${MAX_COST_USD:-10}" \
  --output-dir "$work/eval-results" \
  --json "$work/eval-result.json"

uv run --no-project python3 - "$work/eval-result.json" <<'PY'
import json
import sys

result = json.loads(open(sys.argv[1]).read())
agg = result.get("aggregates", {})
if result.get("partial") is not False:
    sys.exit("error: eval run was partial (cost ceiling or abort)")
if agg.get("casesTotal", 0) < 1:
    sys.exit("error: eval matched no cases")
if agg.get("casesPassed") != agg.get("casesTotal") or agg.get("overallScore") != 1:
    sys.exit(f"error: eval below threshold: {json.dumps(agg)}")
print(f"eval result: {agg['casesPassed']}/{agg['casesTotal']} cases passed at score 1.0")
PY

# The graders scored the report; now hold it to the deterministic assertion too.
# The sandbox cwd is under $TMPDIR because of --keep-temp.
find "$work/sandboxes" -type f -name mutation-testing-report.md -print0 >"$work/reports.list"
report_count=0
while IFS= read -r -d '' report; do
  echo "→ validating agent report: $report"
  uv run --no-project python3 "$validator" "$report"
  report_count=$((report_count + 1))
done <"$work/reports.list"
if [[ "$report_count" -eq 0 ]]; then
  echo "error: --keep-temp left no mutation-testing-report.md to validate" >&2
  exit 1
fi
echo "PASS: mutation-testing smoke ($report_count agent report(s) validated)"
