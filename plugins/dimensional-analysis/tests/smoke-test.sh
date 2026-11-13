#!/usr/bin/env bash
# Smoke test for the dimensional-analysis plugin.
#
#   DETERMINISTIC_ONLY=1 ./smoke-test.sh   # free: validator self-test only
#   ./smoke-test.sh                        # paid: also runs the semantic eval
#
# The eval work dir is a fixed path outside the repo on purpose. The plugin's
# arithmetic-scanner post-filters any path containing /tests/, so fixtures
# analysed in place would be excluded and the run would score a vacuous pass.
set -euo pipefail

tests_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
plugin_dir="$(cd "$tests_dir/.." && pwd)"
fixture_dir="$tests_dir/fixtures"
validator="$tests_dir/validate_findings.py"
work="/tmp/dimensional-analysis-eval"
results="/tmp/dimensional-analysis-eval-results"

command -v uv >/dev/null 2>&1 || {
  echo "error: uv is required" >&2
  exit 2
}

# Build a work dir containing pristine contracts plus the supplied findings file.
stage() {
  local dest="$1" findings="$2"
  rm -rf "$dest"
  mkdir -p "$dest/contracts"
  cp -R "$fixture_dir/src/." "$dest/contracts/"
  [[ -n "$findings" ]] && cp "$findings" "$dest/findings.json"
  return 0
}

# Add a dimensional annotation to every in-scope source, simulating a real run.
annotate() {
  local dest="$1" file
  for file in MarginVault.sol UniV3Oracle.sol AssetRegistry.sol InterestIndex.sol \
    StakingRewards.sol libraries/FixedPointMath.sol libraries/PriceLib.sol; do
    printf '\n// D18{tok} annotation added by the annotation pass\n' >>"$dest/contracts/$file"
  done
}

# Assert the validator exits non-zero for a work dir it must reject.
expect_reject() {
  local label="$1" dir="$2"
  if uv run --no-project python3 "$validator" "$dir" >/dev/null 2>&1; then
    echo "FAIL: validator accepted $label; it must reject it" >&2
    exit 1
  fi
  echo "pass: validator rejects $label"
}

selftest_dir="$(mktemp -d "${TMPDIR:-/tmp}/dim-selftest.XXXXXX")"

# Keep artifacts whenever the run fails: a failed eval is exactly when the
# transcript and grader verdicts are worth reading.
cleanup() {
  status=$?
  if [[ "${KEEP_ARTIFACTS:-0}" == "1" || "$status" -ne 0 ]]; then
    echo "artifacts: $selftest_dir" >&2
    [[ -d "$results" ]] && echo "eval results: $results" >&2
    [[ -d "$work" ]] && echo "work dir: $work" >&2
  else
    rm -rf "$selftest_dir"
  fi
  return 0
}
trap cleanup EXIT

echo "== validator self-test =="

good="$selftest_dir/good"
stage "$good" "$fixture_dir/selftest/findings-complete.json"
annotate "$good"
uv run --no-project python3 "$validator" "$good"

missing_bug="$selftest_dir/missing-bug"
stage "$missing_bug" "$fixture_dir/selftest/findings-complete.json"
annotate "$missing_bug"
uv run --no-project python3 - "$missing_bug/findings.json" <<'PY'
import json, sys
path = sys.argv[1]
report = json.loads(open(path).read())
report["findings"] = [f for f in report["findings"] if f["id"] != "DIM-005"]
open(path, "w").write(json.dumps(report))
PY
expect_reject "a report missing planted bug DIM-E" "$missing_bug"

false_positive="$selftest_dir/false-positive"
stage "$false_positive" "$fixture_dir/selftest/findings-complete.json"
annotate "$false_positive"
uv run --no-project python3 - "$false_positive/findings.json" <<'PY'
import json, sys
path = sys.argv[1]
report = json.loads(open(path).read())
report["findings"].append({
    "id": "DIM-099", "severity": "HIGH", "type": "dimension_mismatch",
    "location": {"file": "StakingRewards.sol", "line": 58, "function": "rewardPerToken"},
    "description": "D36 intermediate in rewardPerToken.",
})
open(path, "w").write(json.dumps(report))
PY
expect_reject "a false positive in the control contract" "$false_positive"

tolerated_fp="$selftest_dir/tolerated-fp"
stage "$tolerated_fp" "$fixture_dir/selftest/findings-complete.json"
annotate "$tolerated_fp"
uv run --no-project python3 - "$tolerated_fp/findings.json" <<'PY'
import json, sys
path = sys.argv[1]
report = json.loads(open(path).read())
report["findings"].append({
    "id": "DIM-098", "severity": "LOW", "type": "rounding",
    "location": {"file": "StakingRewards.sol", "line": 111, "function": "notifyRewardAmount"},
    "description": "reward / duration truncates; dimensionally correct but leaves dust.",
})
open(path, "w").write(json.dumps(report))
PY
if uv run --no-project python3 "$validator" "$tolerated_fp" >/dev/null 2>&1; then
  echo "pass: validator tolerates a LOW finding in the control contract"
else
  echo "FAIL: validator rejected a tolerated LOW control finding" >&2
  exit 1
fi

# Annotations are reported, not gated: a complete findings report passes even with
# no annotations at all. Asserted explicitly so a future edit cannot silently
# restore the gate.
unannotated="$selftest_dir/unannotated"
stage "$unannotated" "$fixture_dir/selftest/findings-complete.json"
if uv run --no-project python3 "$validator" "$unannotated" >/dev/null 2>&1; then
  echo "pass: validator accepts a complete report with no annotations"
else
  echo "FAIL: validator gated on annotations; only recall and blocking FPs should gate" >&2
  exit 1
fi

empty="$selftest_dir/empty"
stage "$empty" ""
annotate "$empty"
printf '{"findings": []}\n' >"$empty/findings.json"
expect_reject "a report with zero findings" "$empty"

no_report="$selftest_dir/no-report"
stage "$no_report" ""
annotate "$no_report"
expect_reject "a run that wrote no findings.json" "$no_report"

echo "PASS: validator self-test (3 accepts, 4 rejects)"

# A zero-round aggregation must not produce a vacuous pass.
if uv run --no-project python3 "$tests_dir/summarize_arms.py" "$selftest_dir" 0; then
  echo "FAIL: aggregation accepted zero rounds" >&2
  exit 1
fi
echo "pass: aggregation rejects zero rounds"

for arm in with without; do
  mkdir -p "$selftest_dir/round1/$arm"
  echo pass >"$selftest_dir/round1/$arm/deterministic"
done
uv run --no-project python3 "$tests_dir/summarize_arms.py" "$selftest_dir" 1

if ROUNDS=0 bash "$tests_dir/trigger-test.sh"; then
  echo "FAIL: trigger harness accepted zero rounds" >&2
  exit 1
fi
echo "pass: trigger harness rejects zero rounds"

if [[ "${DETERMINISTIC_ONLY:-0}" == "1" ]]; then
  exit 0
fi

command -v claude >/dev/null 2>&1 || {
  echo "error: Claude Code 2.1.219+ is required for the semantic eval" >&2
  exit 2
}

echo "== semantic eval =="

# Do NOT use --ablation, and do NOT use --runs > 1. Both arms and every run share
# one work dir, and the harness re-stages neither. Arms run sequentially with the
# plugin arm first, so a baseline arm inherits the plugin's annotated sources and
# reports that it "confirmed the existing annotations" — a measured delta of zero
# that is pure contamination. Instead: one single-run invocation per arm per
# round, with pristine fixtures staged before each, and the delta computed here.
#
# The baseline target is a directory holding only evals/ — no plugin.json, so the
# harness resolves the suite with nothing to load. The plugin arm targets the
# working tree by path, never by name: the trailofbits marketplace
# resolves to GitHub, which would eval remote HEAD instead of local changes.

rm -rf "$results"
mkdir -p "$results"

baseline_target="$results/baseline-target"
mkdir -p "$baseline_target"
cp -R "$plugin_dir/evals" "$baseline_target/"

# Run one isolated single-run arm. Writes score/status files into its own dir.
run_arm() {
  local label="$1" target="$2" round="$3"
  local out="$results/round$round/$label"
  mkdir -p "$out"

  stage "$work" ""

  local status=0
  CLAUDE_CODE_WALNUT_SPIRE=1 claude plugin eval "$target" \
    --model "${MODEL:-sonnet}" --ablation none \
    --case planted-bugs --runs 1 --threshold 1 \
    --max-cost-usd "${MAX_COST_USD:-15}" --allow-tools Bash Write Edit \
    --output-dir "$out" --json "$out/eval-result.json" >"$out/harness.log" 2>&1 || status=$?
  echo "$status" >"$out/eval-status"

  # Archive this arm's artifacts before the next arm re-stages over them.
  cp -R "$work" "$out/work" 2>/dev/null || true

  if uv run --no-project python3 "$validator" "$work" >"$out/deterministic.log" 2>&1; then
    echo pass >"$out/deterministic"
  else
    echo fail >"$out/deterministic"
  fi

  printf '  %-8s round %s: eval-exit=%s deterministic=%s\n' \
    "$label" "$round" "$status" "$(cat "$out/deterministic")"
}

rounds="${ROUNDS:-1}"
for round in $(seq 1 "$rounds"); do
  run_arm with "$plugin_dir" "$round"
  run_arm without "$baseline_target" "$round"
done

echo "== delta =="
uv run --no-project python3 "$tests_dir/summarize_arms.py" "$results" "$rounds"
