#!/usr/bin/env bash
# The executable half of the pins-bite case, run MANUALLY after an eval run (graders
# cannot execute code): pick one `fixed` ledger entry, revert that finding's file to the
# baseline, run the fixture's test suite, and require it to go RED. A pin that stays
# green against the pre-fix code is exactly the vacuous-guard failure this case exists
# to catch.
#
#   ./verify-pins.sh <run-workspace-root> [skill-name]
#
# Works on a copy: the workspace is left untouched.
set -euo pipefail

WS=${1:?usage: verify-pins.sh <run-workspace-root> [skill-name]}
NAME=${2:-csv-splitter}
LEDGER="$WS/.code-improver/$NAME/ledger.json"

for tool in jq git; do
  command -v "$tool" >/dev/null 2>&1 || {
    echo "verify-pins.sh: $tool not found" >&2
    exit 1
  }
done
[ -f "$LEDGER" ] || {
  echo "verify-pins.sh: no ledger at $LEDGER — nothing to verify is a FAIL" >&2
  exit 1
}

BASE_SHA=$(jq -r '.baseline.sha // empty' "$LEDGER")
[ -n "$BASE_SHA" ] || {
  echo "verify-pins.sh: ledger records no baseline sha" >&2
  exit 1
}

# Behavioral fixed findings only: pins are required where the file is executable.
# (head -1, not mapfile: macOS ships bash 3.2. One sample per invocation, logged —
# no silent sampling.)
FIRST=$(jq -r '.findings[] | select(.status == "fixed") | select(.file | test("scripts/|hooks/|commands/")) | .id + "\t" + .file' "$LEDGER" | head -1)
if [ -z "$FIRST" ]; then
  echo "verify-pins.sh: zero behavioral fixed findings in the ledger — nothing was pinned, FAIL" >&2
  exit 1
fi

ID=${FIRST%%$'\t'*}
FILE=${FIRST##*$'\t'}
echo "verifying pin for: $ID (reverting $FILE to $BASE_SHA)"

TMP=$(mktemp -d)
trap 'rm -r "$TMP"' EXIT
cp -R "$WS/." "$TMP/"

git -C "$TMP" show "$BASE_SHA:$FILE" >"$TMP/$FILE" 2>/dev/null ||
  {
    echo "verify-pins.sh: $FILE not present at baseline — cannot revert" >&2
    exit 1
  }

SUITE="$TMP/fixture/$NAME/tests/run_split.sh"
[ -f "$SUITE" ] || SUITE=$(find "$TMP/fixture" -name 'run_*.sh' -path '*/tests/*' | head -1)
if [ ! -f "$SUITE" ]; then
  echo "verify-pins.sh: no test suite found under $TMP/fixture" >&2
  exit 1
fi

echo "running $SUITE against the reverted tree — it must FAIL"
if bash "$SUITE"; then
  echo "PIN DID NOT BITE: the suite passed against pre-fix code. The fix for $ID is unpinned. FAIL" >&2
  exit 1
fi
echo "PASS: the pin bites — the suite goes red against the pre-fix code"
