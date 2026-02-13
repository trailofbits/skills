#!/usr/bin/env bash
set -euo pipefail

# SessionStart hook: persist session_id as CLAUDE_SESSION_ID env var.
# This makes $CLAUDE_SESSION_ID available in all subsequent Bash tool calls,
# used by clone paths like $TMPDIR/gh-clones-$CLAUDE_SESSION_ID/ to scope
# temp directories per session.

session_id=$(jq -r '.session_id // empty' 2>/dev/null) || exit 0
[[ -z "$session_id" ]] && exit 0

if [[ -n "${CLAUDE_ENV_FILE:-}" ]]; then
	echo "export CLAUDE_SESSION_ID=\"$session_id\"" >>"$CLAUDE_ENV_FILE"
fi

exit 0
