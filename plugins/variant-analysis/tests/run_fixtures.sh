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
