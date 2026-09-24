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

output_dir=$("$script_dir/resolve_output_dir.sh" "$output_dir")
raw_dir="$output_dir/raw"
results_dir="$output_dir/results"
mkdir -p "$raw_dir" "$results_dir"

if ! codeql resolve database -- "$database" >/dev/null; then
  echo "ERROR: not a usable CodeQL database: $database" >&2
  exit 1
fi

if ! uv run --no-project "$script_dir/check_db_quality.py" "$database" --format=json >"$output_dir/quality.json"; then
  echo "ERROR: database quality gate failed; see $output_dir/quality.json and stderr." >&2
  exit 1
fi

OUTPUT_DIR="$output_dir" CODEQL_LANG="$language" INSTALLED_THIRD_PARTY_PACKS="$third_party_packs" \
  "$script_dir/generate_suite.sh" "$mode"
suite_file="$raw_dir/$mode.qls"

# Keep the selections alongside the complete SARIF, as the manual workflow does.
{
  printf '# CodeQL Analysis — Selected Query Packs\n'
  printf '# Generated: %s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  printf '# Scan mode: %s\n# Database: %s\n# Language: %s\n' "$mode" "$database" "$language"
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
} >"$output_dir/rulesets.txt"

analysis_args=()
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
  --threads=0 \
  ${analysis_args[@]+"${analysis_args[@]}"} \
  -- "$suite_file"

if [[ "$mode" == important-only ]]; then
  uv run --no-project "$script_dir/process_results.py" important-filter \
    "$raw_dir/results.sarif" "$results_dir/results.sarif"
else
  cp "$raw_dir/results.sarif" "$results_dir/results.sarif"
fi

uv run --no-project "$script_dir/process_results.py" summary "$results_dir/results.sarif" \
  >"$output_dir/summary.json"
printf 'output_dir=%s\nsummary=%s\n' "$output_dir" "$output_dir/summary.json"
