#!/usr/bin/env bash
set -euo pipefail

# SessionStart hook: prepend shims directory to PATH so that bare
# python/pip/uv-pip invocations are intercepted with uv suggestions.
#
# `uv run` is unaffected because it prepends its managed virtualenv's
# bin/ to PATH, shadowing the shims.

# Guard: only activate when uv is available
command -v uv &>/dev/null || exit 0

shims_dir="$(cd "$(dirname "$0")/shims" && pwd)"

echo "export PATH=\"${shims_dir}:\${PATH}\"" >>"$CLAUDE_ENV_FILE"
