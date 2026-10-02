#!/usr/bin/env bash
# Run the deterministic analysis/output part of a CodeQL scan in one shell.
# Building a database remains the existing /static-analysis:codeql-build workflow.
set -euo pipefail

script_dir=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)
database=
output_dir=
language=
mode=run-all
third_party_packs=
max_error_ratio=5
quality_reason=
threads=0
timeout=
rerun=false
declare -a threat_models=() model_packs=() additional_packs=()

usage() {
  cat <<'EOF'
usage: codeql_pipeline.sh --database DB --language LANGUAGE [options]

options:
  --out DIR                 Results directory; auto-increments when omitted
  --mode run-all|important-only
  --third-party-packs "PACK ..."
  --threat-model NAME       May be repeated
  --model-pack PACK         May be repeated
  --additional-pack DIR     May be repeated
  --max-error-ratio PERCENT Explicitly approved extraction-error threshold
  --quality-reason TEXT    Required when overriding the default threshold
  --threads INTEGER        CodeQL threads (default 0)
  --timeout SECONDS         Per-query timeout
  --rerun                   Re-evaluate cached CodeQL results
EOF
}

while (($#)); do
  case "$1" in
    --database)
      database=${2:?missing database}
      shift 2
      ;;
    --out)
      output_dir=${2:?missing output directory}
      shift 2
      ;;
    --language)
      language=${2:?missing language}
      shift 2
      ;;
    --mode)
      mode=${2:?missing mode}
      shift 2
      ;;
    --third-party-packs)
      third_party_packs=${2:?missing packs}
      shift 2
      ;;
    --threat-model)
      threat_models+=("${2:?missing threat model}")
      shift 2
      ;;
    --model-pack)
      model_packs+=("${2:?missing model pack}")
      shift 2
      ;;
    --additional-pack)
      additional_packs+=("${2:?missing additional pack}")
      shift 2
      ;;
    --max-error-ratio)
      max_error_ratio=${2:?missing threshold}
      shift 2
      ;;
    --quality-reason)
      quality_reason=${2:?missing approval reason}
      shift 2
      ;;
    --threads)
      threads=${2:?missing thread count}
      shift 2
      ;;
    --timeout)
      timeout=${2:?missing timeout}
      shift 2
      ;;
    --rerun)
      rerun=true
      shift
      ;;
    -h | --help)
      usage
      exit 0
      ;;
    *)
      echo "unknown argument: $1" >&2
      usage >&2
      exit 2
      ;;
  esac
done

[[ -n "$database" && -n "$language" ]] || {
  usage >&2
  exit 2
}
case "$mode" in run-all | important-only) ;; *)
  echo "invalid mode: $mode" >&2
  exit 2
  ;;
esac

[[ "$max_error_ratio" =~ ^[0-9]+([.][0-9]+)?$ && "$threads" =~ ^-?[0-9]+$ && (-z "$timeout" || "$timeout" =~ ^[0-9]+$) ]] || {
  echo "invalid numeric threshold, threads, or timeout" >&2
  exit 2
}
if [[ "$max_error_ratio" != 5 && -z "$quality_reason" ]]; then
  echo "a threshold override requires --quality-reason documenting user approval" >&2
  exit 2
fi
output_dir=$("$script_dir/resolve_output_dir.sh" "$output_dir")
lock="$output_dir/.codeql-run.lock"
mkdir "$lock" || {
  echo "another pipeline owns $lock; inspect it before retrying" >&2
  exit 2
}
attempt=
finish() {
  local code=$?
  if ((code != 0)); then
    jq -n --arg attempt "$attempt" --argjson code "$code" \
      '{status:"failed",attempt:$attempt,exit_code:$code}' >"$output_dir/run-status.json"
  fi
  rmdir "$lock"
  exit "$code"
}
trap finish EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
mkdir -p "$output_dir/.attempts"
attempt=$(mktemp -d "$output_dir/.attempts/run.XXXXXX")
previous="$attempt/previous"
mkdir "$previous"
# Preserve every previous artifact, but never leave it advertised as this run's result.
for name in raw results rulesets.txt quality.json summary.json report.json; do
  if [[ -e "$output_dir/$name" || -L "$output_dir/$name" ]]; then
    mv "$output_dir/$name" "$previous/$name"
  fi
done
jq -n --arg attempt "$attempt" '{status:"running",attempt:$attempt}' >"$output_dir/run-status.json"
raw_dir="$attempt/raw"
results_dir="$attempt/results"
mkdir -p "$raw_dir" "$results_dir"

if ! codeql resolve database -- "$database" >/dev/null; then
  echo "ERROR: not a usable CodeQL database: $database" >&2
  exit 1
fi

if uv run --no-project "$script_dir/check_db_quality.py" "$database" --format=json \
  --max-error-ratio "$max_error_ratio" >"$attempt/quality.json"; then
  :
else
  quality_status=$?
  echo "ERROR: database quality gate failed; see $attempt/quality.json and stderr." >&2
  exit "$quality_status"
fi

OUTPUT_DIR="$attempt" CODEQL_LANG="$language" INSTALLED_THIRD_PARTY_PACKS="$third_party_packs" \
  "$script_dir/generate_suite.sh" "$mode"
suite_file="$raw_dir/$mode.qls"

# Keep the selections alongside the complete SARIF, as the manual workflow does.
{
  printf '# CodeQL Analysis — Selected Query Packs\n'
  printf '# Generated: %s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  printf '# Scan mode: %s\n# Database: %s\n# Language: %s\n' "$mode" "$database" "$language"
  printf '# Quality threshold: %s%%\n# Approval reason: %s\n' "$max_error_ratio" "${quality_reason:-default threshold}"
  printf '\n## Query packs:\ncodeql/%s-queries\n' "$language"
  # The suite generator accepts this same whitespace-separated pack list.
  # shellcheck disable=SC2086
  for value in $third_party_packs; do
    printf '%s\n' "$value"
  done
  printf '\n## Model packs:\n'
  if [[ -n "${model_packs[*]-}" ]]; then
    printf '%s\n' "${model_packs[@]}"
  else
    printf 'None\n'
  fi
  printf '\n## Additional pack directories:\n'
  if [[ -n "${additional_packs[*]-}" ]]; then
    printf '%s\n' "${additional_packs[@]}"
  else
    printf 'None\n'
  fi
  printf '\n## Threat models:\n'
  if [[ -n "${threat_models[*]-}" ]]; then
    printf '%s\n' "${threat_models[@]}"
  else
    printf 'default (remote)\n'
  fi
} >"$attempt/rulesets.txt"

analysis_args=()
[[ -z "$timeout" ]] || analysis_args+=(--timeout "$timeout")
[[ "$rerun" == false ]] || analysis_args+=(--rerun)
for value in "${threat_models[@]+"${threat_models[@]}"}"; do
  analysis_args+=(--threat-model "$value")
done
for value in "${model_packs[@]+"${model_packs[@]}"}"; do
  analysis_args+=(--model-packs "$value")
done
for value in "${additional_packs[@]+"${additional_packs[@]}"}"; do
  analysis_args+=(--additional-packs "$value")
done

codeql database analyze "$database" \
  --format=sarif-latest \
  --output="$raw_dir/results.sarif" \
  --threads="$threads" \
  ${analysis_args[@]+"${analysis_args[@]}"} \
  -- "$suite_file"

if [[ "$mode" == important-only ]]; then
  uv run --no-project "$script_dir/process_results.py" important-filter \
    "$raw_dir/results.sarif" "$results_dir/results.sarif"
else
  cp "$raw_dir/results.sarif" "$results_dir/results.sarif"
fi

uv run --no-project "$script_dir/process_results.py" summary "$results_dir/results.sarif" \
  >"$attempt/summary.json"
uv run --no-project "$script_dir/process_results.py" summary "$results_dir/results.sarif" --details \
  >"$attempt/report.json"
for name in raw results rulesets.txt quality.json summary.json report.json; do
  mv "$attempt/$name" "$output_dir/$name"
done
jq -n --arg attempt "$attempt" '{status:"complete",attempt:$attempt,exit_code:0}' >"$output_dir/run-status.json"
printf 'output_dir=%s\nsummary=%s\n' "$output_dir" "$output_dir/summary.json"
