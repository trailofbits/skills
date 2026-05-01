#!/bin/bash

# Cancel active skill-improver loop

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lib.sh disable=SC1091
source "$SCRIPT_DIR/lib.sh"

SESSION_ID="${1:-}"
STATE_DIR=".claude"

# Validate session ID format if provided
if [[ -n "$SESSION_ID" ]] &&
  [[ ! "$SESSION_ID" =~ ^[0-9]{14}-[a-fA-F0-9]{8}$ ]]; then
  echo "Error: Invalid session ID format: $SESSION_ID" >&2
  echo "Expected format: YYYYMMDDHHMMSS-XXXXXXXX" >&2
  exit 1
fi

print_cancelled() {
  local sid="$1" name="$2" iter="$3"
  echo "Skill improver cancelled."
  echo ""
  echo "   Session: $sid"
  echo "   Skill: ${name:-unknown}"
  echo "   Completed iterations: $((${iter:-1} - 1))"
  echo ""
  echo "   Changes made during the loop are preserved."
}

# Find all active sessions
shopt -s nullglob
ACTIVE_SESSIONS=("$STATE_DIR"/skill-improver.*.local.md)
shopt -u nullglob

if [[ ${#ACTIVE_SESSIONS[@]} -eq 0 ]]; then
  echo "No active skill-improver sessions found."
  exit 0
fi

# Cancel specific session
if [[ -n "$SESSION_ID" ]]; then
  STATE_FILE=".claude/skill-improver.${SESSION_ID}.local.md"

  if [[ ! -f "$STATE_FILE" ]]; then
    echo "Error: Session '$SESSION_ID' not found." >&2
    echo "" >&2
    echo "Active sessions:" >&2
    for sf in "${ACTIVE_SESSIONS[@]}"; do
      sid=$(extract_session_id "$sf")
      skill=$(parse_field "$sf" "skill_name")
      echo "  - $sid (${skill:-unknown})" >&2
    done
    exit 1
  fi

  iter=$(parse_field "$STATE_FILE" "iteration")
  name=$(parse_field "$STATE_FILE" "skill_name")
  trash "$STATE_FILE"
  print_cancelled "$SESSION_ID" "$name" "$iter"
  exit 0
fi

# No session ID — cancel single session or list multiple
if [[ ${#ACTIVE_SESSIONS[@]} -eq 1 ]]; then
  STATE_FILE="${ACTIVE_SESSIONS[0]}"
  sid=$(extract_session_id "$STATE_FILE")
  iter=$(parse_field "$STATE_FILE" "iteration")
  name=$(parse_field "$STATE_FILE" "skill_name")
  trash "$STATE_FILE"
  print_cancelled "$sid" "$name" "$iter"
else
  echo "Multiple active skill-improver sessions found."
  echo ""
  echo "Please specify which session to cancel:"
  echo ""
  for sf in "${ACTIVE_SESSIONS[@]}"; do
    sid=$(extract_session_id "$sf")
    skill=$(parse_field "$sf" "skill_name")
    iter=$(parse_field "$sf" "iteration")
    max_iter=$(parse_field "$sf" "max_iterations")
    echo "  $sid"
    echo "    Skill: ${skill:-unknown}"
    echo "    Progress: iteration ${iter:-?} / ${max_iter:-?}"
    echo ""
  done
  echo "Usage: /cancel-skill-improver <SESSION_ID>"
fi
