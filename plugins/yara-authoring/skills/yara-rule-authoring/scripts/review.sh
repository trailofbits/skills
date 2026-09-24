#!/usr/bin/env bash
set -euo pipefail

if [[ $# -ne 1 ]]; then
  printf 'usage: %s RULE_OR_DIRECTORY\n' "$0" >&2
  exit 2
fi

if ! command -v jq >/dev/null; then
  printf 'error: jq is required to write the review JSON\n' >&2
  exit 2
fi

target=$1
script_dir=$(cd "$(dirname "$0")" && pwd)
work_dir=$(mktemp -d)
trap 'rm -rf -- "$work_dir"' EXIT

run() {
  local name=$1 status=0
  shift
  "$@" >"$work_dir/$name.out" 2>&1 || status=$?
  printf '%s' "$status" >"$work_dir/$name.status"
}

yr_check=(yr check)
yr_format=(yr fmt --check)
if [[ -d $target ]]; then
  yr_check+=(--recursive)
  yr_format+=(--recursive)
fi

run yr_check "${yr_check[@]}" -- "$target"
run yr_format "${yr_format[@]}" -- "$target"
run lint uv run --quiet "$script_dir/yara_lint.py" --json -- "$target"
run atoms uv run --quiet "$script_dir/atom_analyzer.py" -- "$target"

jq -n \
  --arg target "$target" \
  --rawfile yr_check "$work_dir/yr_check.out" \
  --rawfile yr_format "$work_dir/yr_format.out" \
  --rawfile lint "$work_dir/lint.out" \
  --rawfile atoms "$work_dir/atoms.out" \
  --argjson yr_check_status "$(<"$work_dir/yr_check.status")" \
  --argjson yr_format_status "$(<"$work_dir/yr_format.status")" \
  --argjson lint_status "$(<"$work_dir/lint.status")" \
  --argjson atoms_status "$(<"$work_dir/atoms.status")" \
  '{target: $target, checks: {
    yr_check: {status: $yr_check_status, output: $yr_check},
    yr_format: {status: $yr_format_status, output: $yr_format},
    lint: {status: $lint_status, output: $lint},
    atoms: {status: $atoms_status, output: $atoms}
  }}'

if [[ $(<"$work_dir/yr_check.status") -ne 0 || $(<"$work_dir/yr_format.status") -ne 0 || $(<"$work_dir/lint.status") -ne 0 || $(<"$work_dir/atoms.status") -ne 0 ]]; then
  exit 1
fi
