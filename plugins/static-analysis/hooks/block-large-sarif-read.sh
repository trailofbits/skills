#!/usr/bin/env bash
# Deny raw Read on SARIF files over 200 KiB, including line-limited calls:
# a single line of minified JSON can exceed the limit.
set -euo pipefail

input=$(cat)
path=$(jq -r '.tool_input.file_path // empty' <<<"$input") || exit 0
shopt -s nocasematch
case "$path" in
  *.sarif) ;;
  *) exit 0 ;;
esac
[[ -f "$path" ]] || exit 0

bytes=$(wc -c <"$path" | tr -d '[:space:]')
((bytes > 204800)) || exit 0

jq -n --arg path "$path" --argjson bytes "$bytes" \
  '{hookSpecificOutput:{hookEventName:"PreToolUse",permissionDecision:"deny",permissionDecisionReason:("Do not Read " + $path + " (" + ($bytes|tostring) + " bytes), even with line limits. Use the sarif-parsing helper summary/filter/dedupe/diff commands for compact output, or extract the needed record to a small file before Read.")}}'
