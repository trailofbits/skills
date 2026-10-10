#!/usr/bin/env bash
set -euo pipefail

# SessionStart hook: prepend shims directory to PATH so that bare
# gh invocations are intercepted with anti-pattern checks.

# Guard: only activate when gh is available
if ! command -v gh &>/dev/null; then
  echo "gh-cli: gh not found on PATH; shims will not be installed" >&2
  exit 0
fi

# Guard: CLAUDE_ENV_FILE must be set by the runtime
if [[ -z "${CLAUDE_ENV_FILE:-}" ]]; then
  echo "gh-cli: CLAUDE_ENV_FILE not set; shims will not be installed" >&2
  exit 0
fi

shims_dir="$(cd "$(dirname "$0")/shims" && pwd)" || {
  echo "gh-cli: shims directory not found" >&2
  exit 1
}

if [[ ! -x "${shims_dir}/gh" ]]; then
  echo "gh-cli: shims/gh not found or not executable" >&2
  exit 1
fi

# SessionStart fires on startup, resume and compact, so this hook can run many
# times in one session. Appending unconditionally piles up duplicate exports
# until the runtime's ~8 KB concatenated env is cut mid-line and every Bash call
# in the session fails. Write the line only if this session does not have it yet.
env_line="export PATH=\"${shims_dir}:\${PATH}\""
if ! grep -qxF -- "$env_line" "$(dirname "$CLAUDE_ENV_FILE")"/*.sh 2>/dev/null; then
  echo "$env_line" >>"$CLAUDE_ENV_FILE" || {
    echo "gh-cli: failed to write to CLAUDE_ENV_FILE ($CLAUDE_ENV_FILE)" >&2
    exit 1
  }
fi
