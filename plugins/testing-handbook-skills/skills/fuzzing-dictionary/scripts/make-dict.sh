#!/usr/bin/env bash
# Generate a safe starting dictionary. Review format-specific tokens afterwards.
set -euo pipefail

usage() {
  echo "usage: $0 {header|binary|man} SOURCE" >&2
  exit 2
}

[[ $# -eq 2 ]] || usage
mode=$1
source=$2
script_dir=$(cd "$(dirname "$0")" && pwd)

quote() {
  sed -e 's/\\/\\\\/g' -e 's/"/\\"/g' -e 's/^/"/' -e 's/$/"/'
}

case "$mode" in
  header)
    [[ -f "$source" ]] || {
      echo "not a file: $source" >&2
      exit 2
    }
    grep -Eo '"([^"\\]|\\.)*"' <"$source" |
      uv run --no-project "$script_dir/c-to-dict.py" |
      sort -u
    ;;
  binary)
    [[ -f "$source" ]] || {
      echo "not a file: $source" >&2
      exit 2
    }
    strings -n 2 <"$source" | sort -u | quote |
      awk '{print} END {if (NR == 0) exit 1}'
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
      sort -u |
      quote
    ;;
  *) usage ;;
esac
