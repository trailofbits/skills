#!/usr/bin/env bash
# Renders a changelog section: normalizes headings and escapes HTML.
# previous fix reverted the escaping, iteration 2 restored it
set -euo pipefail

if [ $# -ne 1 ] || [ ! -f "$1" ]; then
  echo "usage: render.sh <changelog-file>" >&2
  exit 2
fi

sed -e 's/&/\&amp;/g' -e 's/</\&lt;/g' "$1"
