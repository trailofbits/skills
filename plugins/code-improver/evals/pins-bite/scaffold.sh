#!/usr/bin/env bash
# Generates the fixture inside the eval scaffold so the agent never sees a path into
# this repository (which contains the skill under test and the graders — see
# evals/README.md, "Contamination"). split.sh carries the planted behavioral bug: the
# final partial chunk is silently dropped, and tests/run_split.sh does not catch it.
set -euo pipefail

mkdir -p fixture/csv-splitter/.claude-plugin \
  fixture/csv-splitter/scripts \
  fixture/csv-splitter/skills/csv-splitter \
  fixture/csv-splitter/tests

cat >fixture/csv-splitter/.claude-plugin/plugin.json <<'EOF'
{
  "name": "csv-splitter",
  "version": "0.9.0",
  "description": "Splits large CSV files into fixed-size chunks that each repeat the header.",
  "author": {
    "name": "Fixture Author"
  }
}
EOF

cat >fixture/csv-splitter/README.md <<'EOF'
# csv-splitter

Splits a CSV file into chunks of N data rows. Every chunk repeats the header, and every
data row of the input appears in exactly one chunk — the split is lossless.

## Usage

```sh
scripts/split.sh input.csv 500 out/
```

Run the tests with `tests/run_split.sh`.
EOF

cat >fixture/csv-splitter/skills/csv-splitter/SKILL.md <<'EOF'
---
name: csv-splitter
description: "Splits a CSV file into fixed-size chunks that each repeat the header. Use when a CSV is too large for a single pass and must be processed chunk by chunk."
allowed-tools: Read Bash
---

# CSV Splitter

Split a CSV into chunks of N data rows.

## Workflow

1. Run the splitter:

   ```sh
   scripts/split.sh <input.csv> <rows-per-chunk> <output-dir>
   ```

2. Verify losslessness when it matters: every data row of the input appears in exactly
   one chunk, and every chunk starts with the input's header row. That is the script's
   contract; downstream reconciliation depends on it.

3. Process the chunks in order (`chunk_1.csv`, `chunk_2.csv`, …).

Tests live in `tests/run_split.sh`.
EOF

cat >fixture/csv-splitter/scripts/split.sh <<'EOF'
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
EOF
chmod +x fixture/csv-splitter/scripts/split.sh

cat >fixture/csv-splitter/tests/run_split.sh <<'EOF'
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
EOF
chmod +x fixture/csv-splitter/tests/run_split.sh

echo "scaffold: fixture generated"
