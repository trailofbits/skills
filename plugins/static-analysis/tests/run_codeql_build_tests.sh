#!/usr/bin/env bash
# Wrapper so CI's run_*.sh discovery picks up the codeql-build harness; without it a guard
# removed from codeql-build.js reaches main with CI green. --self-test is a separate invocation
# because it mutates the workflow and requires every mutation to turn a scenario red.
set -euo pipefail

PLUGIN_ROOT="$(cd "$(dirname "$0")/.." && pwd)"

# Fail, do not skip: a missing interpreter must not read as a clean run.
if ! command -v node >/dev/null 2>&1; then
  echo "run_codeql_build_tests.sh: node not found — required to run this suite" >&2
  exit 1
fi

node "$PLUGIN_ROOT/tests/codeql_build_harness.js" "$PLUGIN_ROOT/workflows/codeql-build.js"
node "$PLUGIN_ROOT/tests/codeql_build_harness.js" "$PLUGIN_ROOT/workflows/codeql-build.js" --self-test
