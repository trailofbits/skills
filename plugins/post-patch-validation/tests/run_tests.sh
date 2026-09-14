#!/usr/bin/env bash
set -euo pipefail

plugin_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

uv run --with pytest --with pyyaml --no-project \
  python3 -m pytest -q --rootdir "${plugin_root}" -p no:cacheprovider "${plugin_root}/tests"
