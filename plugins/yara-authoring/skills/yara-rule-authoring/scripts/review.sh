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

version=$(jq --version)
if [[ ! $version =~ ^jq-([0-9]+)\.([0-9]+) ]] || ((BASH_REMATCH[1] < 1 || (BASH_REMATCH[1] == 1 && BASH_REMATCH[2] < 6))); then
  printf 'error: jq 1.6 or later is required (found %s)\n' "$version" >&2
  exit 2
fi

target=$1
script_dir=$(CDPATH='' cd -- "$(dirname "$0")" && pwd)
work_dir=$(mktemp -d)
trap 'rm -rf -- "$work_dir"' EXIT

input_error=''
if [[ ! -e $target ]]; then
  input_error="input does not exist: $target"
elif [[ ! -r $target ]]; then
  input_error="input is not readable: $target"
elif [[ -f $target && ! -s $target ]]; then
  input_error="input file is empty: $target"
elif [[ -d $target ]]; then
  find_target=$target
  [[ $find_target == /* ]] || find_target=./$find_target
  if ! find "$find_target" -type f \( -name '*.yar' -o -name '*.yara' \) -print -quit >"$work_dir/inputs" 2>"$work_dir/input-error"; then
    input_error="cannot enumerate rule input: $(<"$work_dir/input-error")"
  elif [[ ! -s $work_dir/inputs ]]; then
    input_error="no .yar or .yara files found: $target; nothing was inspected"
  fi
elif [[ ! -f $target ]]; then
  input_error="input is neither a regular file nor a directory: $target"
fi

run() {
  local name=$1 status=0
  shift
  if [[ -n $input_error ]]; then
    printf 'Check not run. Input error: %s\n' "$input_error" >"$work_dir/$name.out"
    status=2
  else
    "$@" >"$work_dir/$name.out" 2>&1 || status=$?
  fi
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
run atoms uv run --quiet "$script_dir/atom_analyzer.py" --no-color -- "$target"

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
