#!/usr/bin/env bash
set -euo pipefail

plugin=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
hook="$plugin/hooks/block-large-sarif-read.sh"
work=$(mktemp -d "${TMPDIR:-/tmp}/sarif-read-hook.XXXXXX")
trap 'rm -rf "$work"' EXIT
small="$work/small.sarif"
boundary="$work/boundary.sarif"
large="$work/large.sarif"
mixed_case="$work/large.SaRiF"
other="$work/large.json"
sarif_json="$work/large.sarif.json"
printf '{}' >"$small"
truncate -s 204800 "$boundary"
truncate -s 204801 "$large"
truncate -s 204801 "$mixed_case"
truncate -s 204801 "$other"
truncate -s 204801 "$sarif_json"

run_hook() { jq -n --arg path "$1" '{tool_input:{file_path:$path}}' | "$hook"; }

assert_allow() {
  local output
  output=$(run_hook "$1")
  [[ -z "$output" ]]
}
assert_allow "$small"
assert_allow "$boundary"
assert_allow "$other"
assert_allow "$work/missing.sarif"
empty=$(printf '{}' | "$hook")
[[ -z "$empty" ]]
status=0
printf 'invalid json' | "$hook" 2>/dev/null || status=$?
[[ $status -eq 2 ]]
configured=$(jq -er '.hooks.PreToolUse[] | select(.matcher == "Read") | .hooks[] | select(.type == "command") | .command' "$plugin/hooks/hooks.json")
[[ "$configured" == "bash \"\${CLAUDE_PLUGIN_ROOT:-.}/hooks/block-large-sarif-read.sh\"" ]]
jq -n --arg path "$large" '{tool_input:{file_path:$path}}' |
  CLAUDE_PLUGIN_ROOT="$plugin" bash -c "$configured" |
  jq -e '.hookSpecificOutput.permissionDecision == "deny"' >/dev/null
run_hook "$sarif_json" | jq -e '.hookSpecificOutput.permissionDecision == "deny"' >/dev/null
run_hook "$large" | jq -e '.hookSpecificOutput.permissionDecision == "deny" and (.hookSpecificOutput.permissionDecisionReason | contains("sarif-parsing helper"))' >/dev/null
run_hook "$mixed_case" | jq -e '.hookSpecificOutput.permissionDecision == "deny"' >/dev/null
run_hook "$large" | jq -e --arg helper "$plugin/skills/sarif-parsing/resources/sarif_helpers.py" '.hookSpecificOutput.permissionDecisionReason | contains($helper)' >/dev/null
# Missing jq is fail-closed, not a silent bypass. Only cat is needed before the guard.
mkdir "$work/no-jq"
ln -s "$(command -v cat)" "$work/no-jq/cat"
status=0
printf '{}' | PATH="$work/no-jq" /bin/bash "$hook" 2>/dev/null || status=$?
[[ $status -eq 2 ]]
jq -n --arg path "$large" '{tool_input:{file_path:$path,offset:1,limit:1}}' | "$hook" |
  jq -e '.hookSpecificOutput.permissionDecision == "deny"' >/dev/null
printf 'PASS large SARIF Read gate\n'
