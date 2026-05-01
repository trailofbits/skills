#!/usr/bin/env bash
set -euo pipefail

# SessionEnd hook: clean up cloned repos for this session only.
# Each session clones into $TMPDIR/gh-clones-<session_id>/, so concurrent
# sessions never interfere with each other.

session_id=$(jq -r '.session_id // empty' 2>/dev/null) || exit 0
[[ -z "$session_id" ]] && exit 0

# Validate session_id format before using in path
if ! [[ "$session_id" =~ ^[a-zA-Z0-9_-]+$ ]]; then
  echo "gh-cli: invalid session_id format, skipping cleanup" >&2
  exit 0
fi

# rm -rf is intentional: these are ephemeral temp clones, not user data.
# trash(1) is inappropriate for temp directory cleanup.
clone_dir="${TMPDIR:-/tmp}/gh-clones-${session_id}"
if [[ -d "$clone_dir" ]]; then
  rm -rf "$clone_dir"
fi
