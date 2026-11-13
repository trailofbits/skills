#!/usr/bin/env bats

setup() {
  SCRIPT="$BATS_TEST_DIRNAME/../evals/run.sh"
  export CALLS_LOG="$BATS_TEST_TMPDIR/claude-calls"
  export CLAUDE_CONFIG_DIR="$BATS_TEST_TMPDIR/claude-config"
  mkdir -p "$BATS_TEST_TMPDIR/bin" "$CLAUDE_CONFIG_DIR"
  cat >"$BATS_TEST_TMPDIR/bin/claude" <<'SH'
#!/bin/sh
printf '%s\n' "$1" >> "$CALLS_LOG"
if [ "$1" = plugin ]; then
  printf '[]\n'
  exit 0
fi
exit 97
SH
  chmod +x "$BATS_TEST_TMPDIR/bin/claude"
  export PATH="$BATS_TEST_TMPDIR/bin:$PATH"
}

@test "ordinary self-test runs offline without invoking Claude" {
  run uv run --no-project bash "$SCRIPT" --self-test
  [ "$status" -eq 0 ]
  [[ "$output" == *"grader schema and plugin-isolation guards reject bad fixtures"* ]]
  [ ! -e "$CALLS_LOG" ]
}

@test "live self-test remains explicit and reaches the grader" {
  run uv run --no-project bash "$SCRIPT" --self-test-live
  [ "$status" -ne 0 ]
  [ "$(wc -l <"$CALLS_LOG" | tr -d ' ')" -eq 2 ]
  [[ "$(head -n 1 "$CALLS_LOG")" == "plugin" ]]
  [[ "$(tail -n 1 "$CALLS_LOG")" == "-p" ]]
}
