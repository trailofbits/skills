#!/bin/bash

# Skill Improver Stop Hook
# Continues the improvement loop until completion criteria met

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# shellcheck source=../scripts/lib.sh disable=SC1091
source "$SCRIPT_DIR/scripts/lib.sh"

# Read hook input from stdin
HOOK_INPUT=$(cat)

STATE_DIR=".claude"

# Find all active sessions
shopt -s nullglob
ACTIVE_SESSIONS=("$STATE_DIR"/skill-improver.*.local.md)
shopt -u nullglob

if [[ ${#ACTIVE_SESSIONS[@]} -eq 0 ]]; then
  exit 0
fi

# Read stop_hook_active to detect re-entrant hook invocations.
# When true, Claude Code is already continuing from a previous block.
STOP_HOOK_ACTIVE=$(echo "$HOOK_INPUT" |
  jq -r '.stop_hook_active // false')

TRANSCRIPT_PATH=$(echo "$HOOK_INPUT" | jq -r '.transcript_path')

if [[ ! -f "$TRANSCRIPT_PATH" ]]; then
  echo "Warning: Transcript not found" >&2
  exit 0
fi

# Find the session that was started in this transcript.
# Uses grep (works on both JSON array and JSONL formats).
MATCHING_SESSION=""

for session_file in "${ACTIVE_SESSIONS[@]}"; do
  sid=$(extract_session_id "$session_file")
  if grep -q "Session ID: $sid" "$TRANSCRIPT_PATH" 2>/dev/null; then
    MATCHING_SESSION="$session_file"
    break
  fi
done

if [[ -z "$MATCHING_SESSION" ]]; then
  exit 0
fi

STATE_FILE="$MATCHING_SESSION"

SESSION_ID=$(parse_field "$STATE_FILE" "session_id")
ITERATION=$(parse_field "$STATE_FILE" "iteration")
MAX_ITERATIONS=$(parse_field "$STATE_FILE" "max_iterations")
SKILL_PATH=$(parse_field "$STATE_FILE" "skill_path")
SKILL_NAME=$(parse_field "$STATE_FILE" "skill_name")

# Validate numeric fields
if [[ ! "$ITERATION" =~ ^[0-9]+$ ]] ||
  [[ ! "$MAX_ITERATIONS" =~ ^[0-9]+$ ]]; then
  echo "Warning: State file corrupted" >&2
  trash "$STATE_FILE"
  exit 0
fi

# Log re-entrant invocations for debugging
if [[ "$STOP_HOOK_ACTIVE" == "true" ]]; then
  echo "Note: stop_hook_active=true, iteration=$ITERATION" >&2
fi

# Check max iterations
if [[ "$ITERATION" -ge "$MAX_ITERATIONS" ]]; then
  echo "Skill improver: Max iterations ($MAX_ITERATIONS) reached."
  echo "   Session: $SESSION_ID"
  echo "   Skill: $SKILL_NAME"
  echo "   Total iterations: $ITERATION"
  trash "$STATE_FILE"
  exit 0
fi

# Extract last assistant message for completion detection.
# Uses --slurp to handle JSONL transcript format.
LAST_OUTPUT=$(jq -rs '
  [ .[] | select(
      .role == "assistant" or
      (.message // empty | .role) == "assistant"
    )
  ] |
  if length == 0 then ""
  else last |
    (if .message then .message else . end) |
    .content | map(select(.type == "text"))
    | map(.text) | join("\n")
  end
' "$TRANSCRIPT_PATH" 2>/dev/null || echo "")

# Empty output: continue the loop — tool-only responses are legitimate
if [[ -z "$LAST_OUTPUT" ]]; then
  echo "Warning: Empty assistant output, continuing loop" >&2
fi

# Check for explicit completion marker.
# Whole-line match avoids false positives from quoted documentation.
if echo "$LAST_OUTPUT" | grep -qx '<skill-improvement-complete>'; then
  echo "Skill improver: Improvement complete!"
  echo "   Session: $SESSION_ID"
  echo "   Skill: $SKILL_NAME"
  echo "   Total iterations: $ITERATION"
  trash "$STATE_FILE"
  exit 0
fi

# Detect skill-reviewer agent errors to avoid burning iterations
if echo "$LAST_OUTPUT" | grep -qiE \
  'subagent.*(not found|unavailable)|skill-reviewer.*(not found|unavailable)|plugin-dev.*(not installed|not found|missing)'; then
  echo "Skill improver: skill-reviewer agent not available." >&2
  echo "   Session: $SESSION_ID" >&2
  echo "   Install the plugin-dev plugin and retry." >&2
  trash "$STATE_FILE"
  exit 0
fi

# Continue loop
NEXT_ITERATION=$((ITERATION + 1))

# Update iteration in state file atomically
TEMP_FILE="${STATE_FILE}.tmp.$$"
trap 'rm -f "$TEMP_FILE"' EXIT
sed "s/^iteration: .*/iteration: ${NEXT_ITERATION}/" \
  "$STATE_FILE" >"$TEMP_FILE"
mv "$TEMP_FILE" "$STATE_FILE"
trap - EXIT

# Build continuation prompt (methodology details are in SKILL.md)
PROMPT="Continue improving the skill at: $SKILL_PATH

Iteration $NEXT_ITERATION / $MAX_ITERATIONS (Session: $SESSION_ID)

Follow the skill-improver methodology. Fix critical/major issues, evaluate minor issues. Output <skill-improvement-complete> on its own line when done.

The skill-reviewer agent is available via the Task tool with subagent_type='plugin-dev:skill-reviewer'"

SYSTEM_MSG="Skill Improver iteration $NEXT_ITERATION/$MAX_ITERATIONS | Session: $SESSION_ID | Target: $SKILL_NAME"

jq -n \
  --arg prompt "$PROMPT" \
  --arg msg "$SYSTEM_MSG" \
  '{
    "decision": "block",
    "reason": $prompt,
    "systemMessage": $msg
  }'

exit 0
