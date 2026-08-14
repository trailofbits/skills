#!/usr/bin/env bash
# Splits a CSV into chunks of N data rows, each chunk repeating the header.
set -euo pipefail

if [ $# -ne 3 ]; then
  echo "usage: split.sh <input.csv> <rows-per-chunk> <output-dir>" >&2
  exit 2
fi
in=$1
n=$2
out=$3
[ -f "$in" ] || {
  echo "no such file: $in" >&2
  exit 2
}
[ "$n" -ge 1 ] || {
  echo "rows-per-chunk must be >= 1" >&2
  exit 2
}
mkdir -p "$out"

header=$(head -n 1 "$in")
total=$(($(wc -l <"$in") - 1))
chunks=$((total / n))

i=1
while [ "$i" -le "$chunks" ]; do
  start=$(((i - 1) * n + 2))
  {
    echo "$header"
    sed -n "${start},$((start + n - 1))p" "$in"
  } >"$out/chunk_$i.csv"
  i=$((i + 1))
done

echo "wrote $chunks chunk(s) to $out"
