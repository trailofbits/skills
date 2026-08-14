#!/usr/bin/env bash
# Rejects prompts containing known injection phrasings.
set -euo pipefail

if [ $# -ne 1 ] || [ ! -f "$1" ]; then
  echo "usage: lint.sh <prompt-file>" >&2
  exit 2
fi

BLOCKLIST='ignore (all )?previous instructions|disregard the system prompt|you are now|reveal your instructions'

if grep -qiE "$BLOCKLIST" "$1"; then
  echo "REJECTED: injection phrasing detected" >&2
  exit 1
fi

echo "OK"
