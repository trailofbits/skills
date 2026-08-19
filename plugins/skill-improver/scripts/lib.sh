#!/bin/bash

# Shared utilities for skill-improver plugin.
# Keys must be literal alphanumeric/underscore strings.

# Parse a YAML frontmatter field from a markdown file.
# Usage: parse_field <file> <key>
parse_field() {
  local file="$1" key="$2"
  sed -n '/^---$/,/^---$/{
    /^'"$key"':/{ s/'"$key"': *//; s/^["'"'"']//; s/["'"'"']$//; p; q; }
  }' "$file" 2>/dev/null || echo ""
}

# Extract session ID from a state file path.
# Usage: extract_session_id <filepath>
extract_session_id() {
  basename "$1" | sed 's/skill-improver\.\(.*\)\.local\.md/\1/'
}

# Remove a plugin-owned state file. Prefers trash (recoverable) and
# falls back to rm -f when trash is missing (stock Linux) or fails
# (network/secondary volumes, sandboxed hooks): callers run under
# `set -e`, and an aborted removal leaves the state file armed — the
# #244 infinite-loop bug.
# Not named `trash` — `command -v` resolves shell functions, so a
# same-named wrapper would call itself instead of the binary.
# Usage: remove_state_file <filepath>
remove_state_file() {
  if command -v trash >/dev/null 2>&1 && trash "$1"; then
    return
  fi
  rm -f -- "$1"
}
