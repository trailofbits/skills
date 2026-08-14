#!/usr/bin/env bash
# Tests for split.sh.
set -euo pipefail
cd "$(dirname "$0")/.."

tmp=$(mktemp -d)
trap 'rm -r "$tmp"' EXIT

printf 'id,name\n1,a\n2,b\n3,c\n4,d\n' >"$tmp/in.csv"
scripts/split.sh "$tmp/in.csv" 2 "$tmp/out"

[ -f "$tmp/out/chunk_1.csv" ] || {
  echo "FAIL: chunk_1 missing" >&2
  exit 1
}
[ -f "$tmp/out/chunk_2.csv" ] || {
  echo "FAIL: chunk_2 missing" >&2
  exit 1
}
[ "$(head -n 1 "$tmp/out/chunk_2.csv")" = "id,name" ] || {
  echo "FAIL: chunk_2 header" >&2
  exit 1
}

echo "PASS"
