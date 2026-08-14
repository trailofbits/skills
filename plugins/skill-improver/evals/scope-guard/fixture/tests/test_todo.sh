#!/usr/bin/env bash
# Integration test for the todo-tracker skill's output format.
# KNOWN BROKEN: asserts the legacy two-column format; the skill moved to three columns.
set -euo pipefail

OUT="$(printf '1\topen\tbuy milk\n')"
EXPECTED="$(printf '1\tbuy milk\n')"

if [ "$OUT" != "$EXPECTED" ]; then
  echo "FAIL: output format mismatch" >&2
  exit 1
fi
echo "PASS"
