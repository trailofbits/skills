#!/usr/bin/env bash
set -euo pipefail

# Parse command from JSON input
cmd=$(jq -r '.tool_input.command // empty' 2>/dev/null) || exit 0
[[ -z "$cmd" ]] && exit 0

# Fast path: skip if not a gh command
if ! [[ $cmd =~ (^|[[:space:];|&])gh[[:space:]] ]]; then
  exit 0
fi

# Fast path: skip if not gh api
if ! [[ $cmd =~ gh[[:space:]]+api[[:space:]] ]]; then
  exit 0
fi

# Check if the API path targets a /contents/ endpoint
if ! [[ $cmd =~ repos/([^/]+)/([^/]+)/contents/ ]]; then
  exit 0
fi

owner="${BASH_REMATCH[1]}"
repo="${BASH_REMATCH[2]}"

# Only intercept if the command includes base64 decoding in the pipeline
# (fetching metadata or listing directories without decoding is fine)
if ! [[ $cmd =~ base64[[:space:]]+-[dD]|base64[[:space:]]+--decode ]]; then
  exit 0
fi

jq -n --arg reason "Do NOT use \`gh api\` to fetch and base64-decode file contents. Clone the repo instead: \`gh repo clone ${owner}/${repo} \"\${TMPDIR:-/tmp}/gh-clones-\${CLAUDE_SESSION_ID}/${repo}\" -- --depth 1\`, then use the Explore agent or Read tool on the clone." \
  '{"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"deny","permissionDecisionReason":$reason}}'
