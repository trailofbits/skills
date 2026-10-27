#!/usr/bin/env bash
set -euo pipefail
if ! command -v uv >/dev/null; then
  printf '%s\n' 'taint-trace requires uv on PATH' >&2
  exit 127
fi
script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
exec uv run --no-project "$script_dir/taint_trace.py" "$@"
