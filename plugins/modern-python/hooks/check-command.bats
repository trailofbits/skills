#!/usr/bin/env bats

setup() {
  HOOK="$BATS_TEST_DIRNAME/check-command.sh"
  export PLUGIN_ROOT="${BATS_TEST_DIRNAME%/hooks}"
  export CLAUDE_PLUGIN_ROOT="$PLUGIN_ROOT"
  command -v jq
  command -v shfmt
  command -v uv
}

check_command() {
  jq -n --arg command "$1" '{hook_event_name:"PreToolUse",tool_name:"Bash",tool_input:{command:$command}}' | bash "$HOOK"
}

@test "Codex denies direct legacy invocations and suggests uv" {
  local command
  for command in \
    'python' \
    'cd src && python3 app.py' \
    '/usr/bin/python3 -W error app.py' \
    'command python3 -u -m pip install rich' \
    'env MODE=test pip3 install rich' \
    'echo $(python3 app.py)' \
    'pipx run ruff' \
    'uv pip sync requirements.txt'; do
    run check_command "$command"
    [[ "$status" -eq 0 ]]
    jq -e '.hookSpecificOutput | .hookEventName == "PreToolUse" and .permissionDecision == "deny" and (.permissionDecisionReason | contains("uv"))' <<<"$output"
  done
}

@test "Codex leaves valid calls and shell data alone" {
  local command
  for command in \
    'uv run --with PyYAML python quick_validate.py' \
    'python3 -u -c "print(1)"' \
    'python3 -m http.server' \
    'python3 --version' \
    'pytest --version' \
    'command -v python3' \
    '.venv/bin/python app.py' \
    'uv pip install --project / --directory /tmp/environment item' \
    'uv pip install --target=/tmp/environment item' \
    'echo "&&" python3 example.py' \
    $'python3 - <<\'END\'\nprint(1)\nEND' \
    $'cat <<\'END\'\npython3 example.py\nEND'; do
    run check_command "$command"
    [[ "$status" -eq 0 ]]
    [[ -z "$output" ]]
  done
}

@test "Codex checks the command after expanded env assignments" {
  local command
  for command in \
    'env PROJECT_ROOT="$PWD" python3 app.py' \
    'env "PROJECT_ROOT=$PWD" pip install rich'; do
    run check_command "$command"
    [[ "$status" -eq 0 ]]
    jq -e '.hookSpecificOutput.permissionDecision == "deny"' <<<"$output"
  done

  run check_command 'env PROJECT_ROOT="$PWD" uv run python app.py'
  [[ "$status" -eq 0 ]]
  [[ -z "$output" ]]
}

@test "Codex leaves conditional alternatives and uncalled function bodies alone" {
  local command
  for command in \
    'if command -v uv; then uv run python app.py; else python3 app.py; fi' \
    'case "$RUNNER" in uv) uv run python app.py;; *) python3 app.py;; esac' \
    'uv run python app.py || python3 app.py' \
    'unused() { python3 app.py; }; printf "%s\n" ready'; do
    run check_command "$command"
    [[ "$status" -eq 0 ]]
    [[ -z "$output" ]]
  done

  run check_command 'unused() { python3 never.py; }; python3 app.py'
  [[ "$status" -eq 0 ]]
  jq -e '.hookSpecificOutput.permissionDecision == "deny"' <<<"$output"
}

@test "Claude Code keeps the shim path instead of using Codex command checking" {
  unset PLUGIN_ROOT
  run check_command 'python3 example.py'
  [[ "$status" -eq 0 ]]
  [[ -z "$output" ]]
}
