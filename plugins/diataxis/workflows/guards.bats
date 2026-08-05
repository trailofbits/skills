#!/usr/bin/env bats
# Proves document.js still aborts on the inputs its guards exist to catch.
#
# The first test runs the guard harness. The rest neutralize one guard at a
# time and assert the harness NOTICES — without them, a harness that had
# quietly stopped exercising anything would keep reporting that every scenario
# passed, forever, which is the exact failure mode this repo's validator
# self-test exists to prevent.

HARNESS="${BATS_TEST_DIRNAME}/guard-harness.js"
SCRIPT="${BATS_TEST_DIRNAME}/document.js"

setup() {
  if ! command -v node >/dev/null 2>&1; then
    skip "node is not installed"
  fi
  MUTANT_DIR="$(mktemp -d)"
  export MUTANT_DIR
}

teardown() {
  [[ -n "$MUTANT_DIR" ]] && rm -rf "$MUTANT_DIR"
}

# Copy document.js with one guard condition replaced by `false`, so the guard
# is present but can never fire. Prints the mutant's path.
mutate() {
  local needle="$1"
  local mutant="${MUTANT_DIR}/document.js"
  # Fail loudly if the needle is gone: a mutation that matches nothing produces
  # an unmutated copy, and the test below would then "pass" for the wrong reason.
  grep -qF "$needle" "$SCRIPT" || {
    echo "mutation target not found in document.js: $needle" >&2
    return 1
  }
  MUTATE_NEEDLE="$needle" node -e '
    const fs = require("fs");
    const src = fs.readFileSync(process.argv[1], "utf8");
    const out = src.replace(process.env.MUTATE_NEEDLE, "false");
    if (out === src) { console.error("replacement was a no-op"); process.exit(1); }
    fs.writeFileSync(process.argv[2], out);
  ' "$SCRIPT" "$mutant" || return 1
  echo "$mutant"
}

@test "every guard scenario passes against the real workflow" {
  run node "$HARNESS"
  [[ $status -eq 0 ]]
  [[ "$output" == *"all 23 guard scenarios passed"* ]]
}

@test "harness catches a neutralized commit-SHA guard" {
  local mutant
  mutant="$(mutate '!framework.sourceCommit || framework.sourceCommit.length < 7')"
  run node "$HARNESS" --script "$mutant"
  [[ $status -ne 0 ]]
  [[ "$output" == *"answered from memory"* ]]
}

@test "harness catches a neutralized rst-file-count guard" {
  local mutant
  mutant="$(mutate '!(framework.rstFilesRead >= 8)')"
  run node "$HARNESS" --script "$mutant"
  [[ $status -ne 0 ]]
  [[ "$output" == *"Partial read"* || "$output" == *"partial read"* ]]
}

@test "harness catches a neutralized zero-source-files guard" {
  local mutant
  mutant="$(mutate '!(survey.inventory.sourceFileCount > 0)')"
  run node "$HARNESS" --script "$mutant"
  [[ $status -ne 0 ]]
  [[ "$output" == *"Zero source files"* || "$output" == *"zero source files"* ]]
}

@test "harness catches a neutralized empty-quadrant guard" {
  local mutant
  mutant="$(mutate 'writerFailed.length + writerEmpty.length === WRITERS.length')"
  run node "$HARNESS" --script "$mutant"
  [[ $status -ne 0 ]]
  [[ "$output" == *"All quadrants empty"* || "$output" == *"all quadrants empty"* ]]
}

@test "harness fails when scenarios are removed rather than passing silently" {
  local mutant="${MUTANT_DIR}/guard-harness.js"
  # Raise the declared count above the number defined: the same shape as
  # deleting scenarios, and it must be caught rather than ignored.
  sed -E 's/^const EXPECTED_SCENARIOS = [0-9]+$/const EXPECTED_SCENARIOS = 99/' "$HARNESS" >"$mutant"
  grep -q 'EXPECTED_SCENARIOS = 99' "$mutant"
  # --script is required: the mutant lives in a temp dir, so its default
  # sibling lookup for document.js would fail before the count check runs.
  run node "$mutant" --script "$SCRIPT"
  [[ $status -ne 0 ]]
  [[ "$output" == *"Scenarios were removed"* ]]
}

@test "the workflow meta block is a pure literal with four phases" {
  run node -e '
    const fs = require("fs");
    const src = fs.readFileSync(process.argv[1], "utf8").replace("export const meta", "const meta");
    const vm = require("vm");
    const ctx = { module: {} };
    vm.createContext(ctx);
    // Evaluate only the meta block, so a non-literal value (a variable, a call,
    // a template interpolation) throws here rather than at workflow load time.
    const end = src.indexOf("\n}\n");
    new vm.Script(src.slice(0, end + 2) + ";module.exports = meta;").runInContext(ctx);
    const meta = ctx.module.exports;
    if (meta.name !== "document") throw new Error("meta.name must be document, got " + meta.name);
    if (!meta.description) throw new Error("meta.description is required");
    if (meta.phases.length !== 4) throw new Error("expected 4 phases, got " + meta.phases.length);
  ' "$SCRIPT"
  [[ $status -eq 0 ]]
}
