#!/usr/bin/env bash
set -euo pipefail

# SessionStart hook: persist session_id as CLAUDE_SESSION_ID env var.
# This makes $CLAUDE_SESSION_ID available in all subsequent Bash tool calls,
# used by clone paths like $TMPDIR/gh-clones-$CLAUDE_SESSION_ID/ to scope
# temp directories per session.

session_id=$(jq -r '.session_id // empty' 2>/dev/null) || exit 0
[[ -z "$session_id" ]] && exit 0

# Validate session_id is alphanumeric/hyphens/underscores to prevent shell injection
# when the value is written into an export statement that gets sourced.
if ! [[ "$session_id" =~ ^[a-zA-Z0-9_-]+$ ]]; then
  echo "gh-cli: invalid session_id format, skipping" >&2
  exit 0
fi

if [[ -z "${CLAUDE_ENV_FILE:-}" ]]; then
  echo "gh-cli: CLAUDE_ENV_FILE not set; session-scoped clones will not work" >&2
  exit 0
fi

# As in setup-shims.sh: SessionStart re-fires on resume and compact, so append
# only when this session does not already carry the line.
env_line="export CLAUDE_SESSION_ID=\"$session_id\""
if ! grep -qxF -- "$env_line" "$(dirname "$CLAUDE_ENV_FILE")"/*.sh 2>/dev/null; then
  echo "$env_line" >>"$CLAUDE_ENV_FILE" || {
    echo "gh-cli: failed to write CLAUDE_SESSION_ID to CLAUDE_ENV_FILE ($CLAUDE_ENV_FILE)" >&2
    exit 1
  }
fi
