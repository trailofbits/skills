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

echo "export PATH=\"${shims_dir}:\${PATH}\"" >>"$CLAUDE_ENV_FILE" || {
  echo "gh-cli: failed to write to CLAUDE_ENV_FILE ($CLAUDE_ENV_FILE)" >&2
  exit 1
}
