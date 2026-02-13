#!/usr/bin/env bash
set -euo pipefail

# SessionEnd hook: clean up cloned repos for this session only.
# Each session clones into $TMPDIR/gh-clones-<session_id>/, so concurrent
# sessions never interfere with each other.

session_id=$(jq -r '.session_id // empty' 2>/dev/null) || exit 0
[[ -z "$session_id" ]] && exit 0

# Clean up the session-scoped clone directory
rm -rf "${TMPDIR:-/tmp}"/gh-clones-"$session_id" 2>/dev/null

exit 0
