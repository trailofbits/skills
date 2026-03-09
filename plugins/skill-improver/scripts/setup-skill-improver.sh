#!/bin/bash

# Skill Improver Setup Script
# Creates state file for in-session skill improvement loop

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lib.sh disable=SC1091
source "$SCRIPT_DIR/lib.sh"

readonly DEFAULT_MAX_ITERATIONS=20

# Parse arguments
SKILL_PATH=""
MAX_ITERATIONS="$DEFAULT_MAX_ITERATIONS"

while [[ $# -gt 0 ]]; do
  case $1 in
    --max-iterations)
      if [[ -z "${2:-}" ]]; then
        echo "Error: --max-iterations requires a number argument" >&2
        exit 1
      fi
      if ! [[ "$2" =~ ^[0-9]+$ ]]; then
        echo "Error: --max-iterations must be a positive integer, got: $2" >&2
        exit 1
      fi
      MAX_ITERATIONS="$2"
      shift 2
      ;;
    *)
      if [[ -z "$SKILL_PATH" ]]; then
        SKILL_PATH="$1"
      else
        echo "Error: Unexpected argument: $1" >&2
        exit 1
      fi
      shift
      ;;
  esac
done

# Validate skill path
if [[ -z "$SKILL_PATH" ]]; then
  echo "Error: No skill path provided" >&2
  echo "" >&2
  echo "   Usage: /skill-improver <SKILL_PATH>" >&2
  echo "" >&2
  echo "   Examples:" >&2
  echo "     /skill-improver ./plugins/my-plugin/skills/my-skill" >&2
  echo "     /skill-improver ./skills/my-skill/SKILL.md" >&2
  exit 1
fi

# Resolve to absolute path
if [[ ! "$SKILL_PATH" = /* ]]; then
  SKILL_PATH="$(pwd)/$SKILL_PATH"
fi

# If path is SKILL.md, use its directory
if [[ "$SKILL_PATH" == */SKILL.md ]]; then
  SKILL_DIR="$(dirname "$SKILL_PATH")"
  SKILL_FILE="$SKILL_PATH"
else
  SKILL_DIR="$SKILL_PATH"
  SKILL_FILE="$SKILL_PATH/SKILL.md"
fi

# Verify skill exists
if [[ ! -f "$SKILL_FILE" ]]; then
  echo "Error: SKILL.md not found at $SKILL_FILE" >&2
  echo "" >&2
  echo "The path provided does not contain a SKILL.md file." >&2
  echo "Claude should resolve skill names to paths before calling this script." >&2
  exit 1
fi

# Pre-flight: check that plugin-dev is installed (provides skill-reviewer).
# Best-effort — the stop hook also detects missing skill-reviewer at runtime.
PLUGIN_DEV_FOUND=false
for search_dir in \
  "${CLAUDE_PLUGIN_ROOT:-}/../plugin-dev" \
  "$HOME/.claude/plugins/plugin-dev" \
  "$HOME/.claude-code/plugins/plugin-dev"; do
  if [[ -d "$search_dir/.claude-plugin" ]]; then
    PLUGIN_DEV_FOUND=true
    break
  fi
done

if [[ "$PLUGIN_DEV_FOUND" != "true" ]]; then
  echo "Error: plugin-dev plugin not found." >&2
  echo "" >&2
  echo "skill-improver requires the plugin-dev plugin" >&2
  echo "(provides the skill-reviewer agent)." >&2
  echo "" >&2
  echo "Install plugin-dev and try again." >&2
  exit 1
fi

# Extract skill name from SKILL.md frontmatter
SKILL_NAME=$(parse_field "$SKILL_FILE" "name")
if [[ -z "$SKILL_NAME" ]]; then
  SKILL_NAME="unknown"
fi

# Generate unique session ID
SESSION_ID="$(date +%Y%m%d%H%M%S)-$(uuidgen 2>/dev/null |
  cut -c1-8 || openssl rand -hex 4)"

# Create state directory
mkdir -p .claude

STATE_FILE=".claude/skill-improver.${SESSION_ID}.local.md"

# Write state file atomically
TEMP_FILE="${STATE_FILE}.tmp.$$"
trap 'rm -f "$TEMP_FILE"' EXIT

cat >"$TEMP_FILE" <<EOF
---
session_id: "$SESSION_ID"
iteration: 1
max_iterations: $MAX_ITERATIONS
skill_path: "$SKILL_DIR"
skill_name: "$SKILL_NAME"
---
EOF

mv "$TEMP_FILE" "$STATE_FILE"
trap - EXIT

cat <<EOF
Skill Improver activated!

Session ID: $SESSION_ID
Target skill: $SKILL_NAME
Skill path: $SKILL_DIR
Iteration: 1 / $MAX_ITERATIONS

To cancel: /cancel-skill-improver $SESSION_ID
To monitor: cat $STATE_FILE

Starting review...
EOF
