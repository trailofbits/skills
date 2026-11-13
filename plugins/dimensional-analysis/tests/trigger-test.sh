#!/usr/bin/env bash
# Measure how reliably the dimensional-analysis skill activates, per request phrasing.
#
#   ROUNDS=3 ./trigger-test.sh              # all phrasings
#   ROUNDS=5 CASES=trigger-audit ./trigger-test.sh
#
# Activation is read off disk, not from a judge: Phase 1 persists
# DIMENSIONAL_UNITS.md and DIMENSIONAL_SCOPE.json, and nothing else writes them.
# A run that analyses the code by hand produces neither.
#
# Fixtures stage to /tmp because arithmetic-scanner post-filters any path
# containing /tests/, which would leave the scanner with zero files.
set -euo pipefail

tests_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
plugin_dir="$(cd "$tests_dir/.." && pwd)"
fixture="$tests_dir/fixtures/trigger/src"
work="/tmp/dimensional-analysis-trigger"
results="/tmp/dimensional-analysis-trigger-results"

rounds="${ROUNDS:-3}"
read -r -a cases <<<"${CASES:-trigger-explicit trigger-annotate trigger-audit trigger-oblique}"

if [[ ! "$rounds" =~ ^[1-9][0-9]*$ ]] || [[ "${#cases[@]}" -eq 0 ]]; then
  echo "error: at least one case and a positive integer ROUNDS are required" >&2
  exit 2
fi

command -v uv >/dev/null 2>&1 || {
  echo "error: uv is required" >&2
  exit 2
}

command -v claude >/dev/null 2>&1 || {
  echo "error: Claude Code is required" >&2
  exit 2
}

rm -rf "$results"
mkdir -p "$results"

# Run one case once against pristine fixtures. Echoes "fired", "quiet", or "crashed".
run_once() {
  local case_name="$1" round="$2"
  local out="$results/$case_name/round$round"
  mkdir -p "$out"

  rm -rf "$work"
  mkdir -p "$work/contracts"
  cp -R "$fixture/." "$work/contracts/"

  # The harness exit code is irrelevant here: --threshold 0, and activation is
  # read off disk below.
  CLAUDE_CODE_WALNUT_SPIRE=1 claude plugin eval "$plugin_dir" \
    --model "${MODEL:-sonnet}" --ablation none \
    --case "$case_name" --runs 1 --threshold 0 \
    --max-cost-usd "${MAX_COST_USD:-3}" --allow-tools Bash Write Edit \
    --output-dir "$out" --json "$out/eval-result.json" >"$out/harness.log" 2>&1 || true

  cp -R "$work" "$out/work" 2>/dev/null || true

  # An arm that never ran is not evidence either way; report it separately so it
  # cannot be silently counted as a non-activation.
  if uv run --no-project python3 - "$out/eval-result.json" <<'PY'; then
import json, sys
try:
    run = json.load(open(sys.argv[1]))["cases"][0]["arms"]["with"][0]
except Exception:
    sys.exit(0)
sys.exit(0 if (run.get("error") and not run.get("costUsd")) else 1)
PY
    echo crashed
    return 0
  fi

  # Search recursively: the skill writes these to whatever it treats as the project
  # root, which is the directory named in the request, not necessarily $work.
  if find "$work" -maxdepth 3 -name 'DIMENSIONAL_UNITS.md' -o -maxdepth 3 \
    -name 'DIMENSIONAL_SCOPE.json' | grep -q .; then
    echo fired
  else
    echo quiet
  fi
}

printf '%-20s %-8s %s\n' CASE RATE DETAIL
valid_runs=0
for case_name in "${cases[@]}"; do
  fired=0
  crashed=0
  detail=""
  for round in $(seq 1 "$rounds"); do
    verdict="$(run_once "$case_name" "$round")"
    case "$verdict" in
      fired) fired=$((fired + 1)) ;;
      crashed) crashed=$((crashed + 1)) ;;
    esac
    detail+="${verdict:0:1}"
  done
  valid=$((rounds - crashed))
  valid_runs=$((valid_runs + valid))
  if [[ "$valid" -eq 0 ]]; then
    printf '%-20s %-8s %s (all runs crashed)\n' "$case_name" "n/a" "$detail"
  else
    printf '%-20s %-8s %s (%s/%s valid)\n' \
      "$case_name" "$fired/$valid" "$detail" "$valid" "$rounds"
  fi
done

echo
echo "f=fired  q=quiet  c=crashed   artifacts: $results"
if [[ "$valid_runs" -eq 0 ]]; then
  echo "error: no valid trigger runs completed" >&2
  exit 1
fi
