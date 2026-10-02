#!/usr/bin/env bash
# Generate a safe starting dictionary. Review format-specific tokens afterwards.
set -euo pipefail

usage() {
  echo "usage: $0 {header|binary|man} SOURCE [--backend libfuzzer|afl++]" >&2
  exit 2
}

[[ $# -eq 2 || $# -eq 4 ]] || usage
mode=$1
source=$2
script_dir=$(CDPATH='' cd -- "$(dirname "$0")" && pwd)
backend=libfuzzer
if [[ $# -eq 4 ]]; then
  [[ $3 == --backend && ($4 == libfuzzer || $4 == afl++) ]] || usage
  backend=$4
fi

case "$mode" in
  header)
    [[ -f "$source" ]] || {
      echo "not a file: $source" >&2
      exit 2
    }
    uv run --no-project "$script_dir/c-to-dict.py" --source "$source" --backend "$backend"
    ;;
  binary)
    [[ -f "$source" ]] || {
      echo "not a file: $source" >&2
      exit 2
    }
    strings -n 2 <"$source" | uv run --no-project "$script_dir/c-to-dict.py" --byte-lines --backend "$backend"
    ;;
  man)
    command -v man >/dev/null || {
      echo "man is not installed" >&2
      exit 2
    }
    command -v col >/dev/null || {
      echo "col is not installed" >&2
      exit 2
    }
    man "$source" | col -b |
      grep -Eo -- '(^|[[:space:]])--?[A-Za-z0-9][A-Za-z0-9_-]*' |
      awk '{$1=$1; print}' |
      uv run --no-project "$script_dir/c-to-dict.py" --byte-lines --backend "$backend"
    ;;
  *) usage ;;
esac
