#!/usr/bin/env bash
# Wrapper so CI's shell-suite discovery (find … -name 'run_*.sh') picks these up.
# Without it the harness and the coverage check run only when someone remembers to,
# and a category added to CATEGORIES without its references/<id>.json aborts every
# real run with corpus-unreadable while CI stays green.
set -euo pipefail

PLUGIN_ROOT="$(cd "$(dirname "$0")/.." && pwd)"

# Fail, do not skip: a missing interpreter must not read as a clean run.
if ! command -v node >/dev/null 2>&1; then
  echo "run_seeds.sh: node not found — required to run these suites" >&2
  exit 1
fi

node "$PLUGIN_ROOT/tests/harness.js" "$PLUGIN_ROOT/workflows/audit.js"
node "$PLUGIN_ROOT/tests/harness.js" "$PLUGIN_ROOT/workflows/audit.js" --self-test
node "$PLUGIN_ROOT/tests/seed-coverage.js" "$PLUGIN_ROOT"
