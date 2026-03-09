#!/usr/bin/env bash
set -euo pipefail

# SessionStart hook: prepend shims directory to PATH so that bare
# python/pip/pipx/uv-pip invocations are intercepted with uv suggestions.
#
# `uv run` is unaffected because it prepends its managed virtualenv's
# bin/ to PATH, shadowing the shims.

# Guard: only activate when uv is available
command -v uv &>/dev/null || exit 0

# Guard: CLAUDE_ENV_FILE must be set by the runtime
if [[ -z "${CLAUDE_ENV_FILE:-}" ]]; then
  echo "modern-python: CLAUDE_ENV_FILE not set; shims will not be installed" >&2
  exit 0
fi

shims_dir="$(cd "$(dirname "$0")/shims" && pwd)" || {
  echo "modern-python: shims directory not found" >&2
  exit 1
}

echo "export PATH=\"${shims_dir}:\${PATH}\"" >>"$CLAUDE_ENV_FILE"
