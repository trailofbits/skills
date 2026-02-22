#!/usr/bin/env bash
set -euo pipefail

# Parse command from JSON input
cmd=$(jq -r '.tool_input.command // empty' 2>/dev/null) || exit 0
[[ -z "$cmd" ]] && exit 0

# Fast path: skip if not a gh command
if ! [[ $cmd =~ (^|[[:space:];|&])gh[[:space:]] ]]; then
  exit 0
fi

# Skip if not gh repo clone
if ! [[ $cmd =~ gh[[:space:]]+repo[[:space:]]+clone[[:space:]] ]]; then
  exit 0
fi

# Extract the target directory from "gh repo clone <repo> [<dir>] [-- <gitflags>...]"
rest="${cmd#*gh repo clone }"

# Skip the repo argument (first token after "gh repo clone")
read -r _repo remaining <<< "$rest"
[[ -z "${remaining:-}" ]] && exit 0

# Get the target directory (next token)
read -r target _ <<< "$remaining"

# No target dir or git passthrough separator
[[ "$target" == "--" || "$target" == -* ]] && exit 0

# Strip surrounding quotes
target="${target#\"}"
target="${target%\"}"
target="${target#\'}"
target="${target%\'}"

# Check if target resolves to a temp-like path
temp_pattern='(/tmp/|/var/folders/|\$TMPDIR|\${TMPDIR)'
target_is_temp=false
if [[ $target =~ $temp_pattern ]]; then
  target_is_temp=true
elif [[ $target == \$* ]]; then
  # Target is a variable reference — check the full command for temp paths
  if [[ $cmd =~ $temp_pattern ]]; then
    target_is_temp=true
  fi
fi

$target_is_temp || exit 0

# Allow if the command references CLAUDE_SESSION_ID (session-scoped path)
if [[ $cmd =~ CLAUDE_SESSION_ID ]]; then
  exit 0
fi

# Allow if the path contains the actual session ID value (expanded variable)
if [[ -n "${CLAUDE_SESSION_ID:-}" ]] && [[ $cmd =~ gh-clones-${CLAUDE_SESSION_ID} ]]; then
  exit 0
fi

# Deny: cloning to a temp path without session scoping
jq -n --arg reason "Clone to a session-scoped directory instead: \`\${TMPDIR:-/tmp}/gh-clones-\${CLAUDE_SESSION_ID}/<repo-name>\`. Do NOT invent paths like /tmp/claude/gh-clones/ — they conflict across sessions and won't be cleaned up." \
  '{"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"deny","permissionDecisionReason":$reason}}'
