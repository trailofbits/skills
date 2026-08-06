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

# The workflow is not standalone-valid JS in either module system: the runtime
# executes it as an async function body (so top-level `return` is legal) and
# separately reads the `export const meta`. `node --check` cannot model that —
# .js/CJS rejects the export, .mjs/ESM rejects the return. So reproduce the
# runtime's shape: demote `export` to a plain declaration and parse the source
# as an AsyncFunction body. Syntax check only; nothing is executed.
echo "→ workflow syntax"
if command -v node >/dev/null 2>&1; then
  node -e '
    const fs = require("fs");
    const src = fs.readFileSync(process.argv[1], "utf8");
    const body = src.replace(/^export[ \t]+(?=const|let|var|function|async|class)/gm, "");
    const AsyncFunction = Object.getPrototypeOf(async function () {}).constructor;
    try {
      new AsyncFunction(body);
      console.log("  ✓ workflows/variants.js parses");
    } catch (e) {
      console.error("  ✗ workflows/variants.js: " + e.message);
      process.exit(1);
    }
  ' "$TESTS_DIR/../workflows/variants.js"
else
  echo "  - node not on PATH; skipping"
fi
