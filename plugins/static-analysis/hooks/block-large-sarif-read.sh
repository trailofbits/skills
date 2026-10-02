#!/usr/bin/env bash
# Deny raw Read on SARIF files over 200 KiB, including line-limited calls:
# a single line of minified JSON can exceed the limit.
set -euo pipefail

input=$(cat)
if ! command -v jq >/dev/null 2>&1; then
  printf 'SARIF Read guard requires jq; install jq before retrying.\n' >&2
  exit 2
fi
if ! path=$(jq -er '.tool_input.file_path // "" | strings' <<<"$input"); then
  printf 'SARIF Read guard could not parse hook input; retry with valid JSON.\n' >&2
  exit 2
fi
shopt -s nocasematch
case "$path" in
  *.sarif | *.sarif.json) ;;
  *) exit 0 ;;
esac
[[ -f "$path" ]] || exit 0

bytes=$(wc -c <"$path" | tr -d '[:space:]')
((bytes > 204800)) || exit 0

plugin_root=${CLAUDE_PLUGIN_ROOT:-$(CDPATH='' cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)}
helper="$plugin_root/skills/sarif-parsing/resources/sarif_helpers.py"
jq -n --arg path "$path" --argjson bytes "$bytes" --arg helper "$helper" \
  '{hookSpecificOutput:{hookEventName:"PreToolUse",permissionDecision:"deny",permissionDecisionReason:("Do not Read " + $path + " (" + ($bytes|tostring) + " bytes), even with line limits. Use the sarif-parsing helper: uv run --no-project " + ($helper|@sh) + " summary " + ($path|@sh) + ". Or extract a needed record to a small file before Read.")}}'
