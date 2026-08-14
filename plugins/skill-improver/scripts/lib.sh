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

# Remove a plugin-owned state file. Prefers trash (recoverable) but
# falls back to rm: trash ships with trash-cli/Homebrew and is absent
# on stock Linux, where `set -e` would abort the caller mid-script.
# Not named `trash` — `command -v` resolves shell functions, so a
# same-named wrapper would always take the trash branch and still die.
# Usage: remove_state_file <filepath>
remove_state_file() {
  if command -v trash >/dev/null 2>&1; then
    trash "$1"
  else
    rm -f -- "$1"
  fi
}
