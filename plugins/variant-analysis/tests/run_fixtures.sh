#!/usr/bin/env bash
# Fixture integrity check for the variant-analysis eval.
#
# Deterministic, offline, free. This is the suite `make shell-suites` and CI
# discover via `find plugins -type f -path '*/tests/*' -name 'run_*.sh'`, so it
# must stay cheap and must never call Claude. The eval that does call Claude is
# eval.sh, deliberately named so discovery skips it.
#
# Invokes verify_fixtures.py as a file rather than piping to `python3 -`: the
# modern-python plugin's shim intercepts stdin form and fails for reasons that
# have nothing to do with the code under test (#207).

set -euo pipefail

TESTS_DIR="$(cd "$(dirname "$0")" && pwd)"

echo "→ variant-analysis fixtures"
python3 "$TESTS_DIR/verify_fixtures.py"

echo "→ grader self-test"
python3 "$TESTS_DIR/score.py" --self-test

echo "→ aggregator self-test"
python3 "$TESTS_DIR/summarize.py" --self-test

# The workflow is the only JavaScript in this repo and nothing in CI parses it, so a
# syntax error would surface only inside a paid eval.sh run. `node --check` is free and
# offline. Skipped rather than failed where node is absent: this suite must stay green on
# a machine that has no reason to have it.
echo "→ workflow syntax"
if command -v node >/dev/null 2>&1; then
  # Copied to .mjs first. The file's first statement is `export const meta`, and
  # `node --check` on a .js file only accepts that on a Node new enough to detect module
  # syntax (~22.7+); older Nodes reject valid workflows with "Unexpected token 'export'".
  # The extension removes the ambiguity, so this does not depend on the runner's Node.
  MJS="$(mktemp -t variants.XXXXXX).mjs"
  trap 'rm -f "$MJS"' EXIT
  cp "$TESTS_DIR/../workflows/variants.js" "$MJS"
  node --check "$MJS"
  echo "  ✓ workflows/variants.js parses"
else
  echo "  - node not on PATH; skipping"
fi
