#!/usr/bin/env bash
set -euo pipefail

# Fast exit if gh not installed
command -v gh &>/dev/null || exit 0

# Parse command from JSON input
cmd=$(jq -r '.tool_input.command // empty' 2>/dev/null) || exit 0
[[ -z "$cmd" ]] && exit 0

# Skip if already using gh CLI
if [[ $cmd =~ (^|[[:space:];|&])gh[[:space:]] ]]; then
  exit 0
fi

# Skip git commands (git clone, git remote, etc. legitimately use github URLs)
if [[ $cmd =~ (^|[[:space:];|&])git[[:space:]] ]]; then
  exit 0
fi

# Only intercept commands that use curl or wget
if ! [[ $cmd =~ (^|[[:space:];|&])(curl|wget)[[:space:]] ]]; then
  exit 0
fi

# Check if the curl/wget targets a GitHub URL
github_pattern='https?://(github\.com|api\.github\.com|raw\.githubusercontent\.com|gist\.github\.com)/'
if ! [[ $cmd =~ $github_pattern ]]; then
  exit 0
fi

# Build a contextual suggestion
suggestion="Use \`gh api\` or other \`gh\` subcommands instead of curl/wget for GitHub URLs"

if [[ $cmd =~ api\.github\.com/repos/([^/]+)/([^/]+)/releases ]]; then
  suggestion="Use \`gh release list --repo ${BASH_REMATCH[1]}/${BASH_REMATCH[2]}\` or \`gh api repos/${BASH_REMATCH[1]}/${BASH_REMATCH[2]}/releases/latest\` instead"
elif [[ $cmd =~ api\.github\.com/repos/([^/]+)/([^/]+)/pulls ]]; then
  suggestion="Use \`gh pr list --repo ${BASH_REMATCH[1]}/${BASH_REMATCH[2]}\` instead"
elif [[ $cmd =~ api\.github\.com/repos/([^/]+)/([^/]+)/issues ]]; then
  suggestion="Use \`gh issue list --repo ${BASH_REMATCH[1]}/${BASH_REMATCH[2]}\` instead"
elif [[ $cmd =~ api\.github\.com/([^[:space:]\"\']+) ]]; then
  suggestion="Use \`gh api ${BASH_REMATCH[1]}\` instead"
elif [[ $cmd =~ github\.com/([^/]+)/([^/]+)/archive/ ]]; then
  suggestion="Use \`gh release download --repo ${BASH_REMATCH[1]}/${BASH_REMATCH[2]}\` instead"
elif [[ $cmd =~ raw\.githubusercontent\.com/([^/]+)/([^/]+)/[^/]+/([^[:space:]\"\']+) ]]; then
  suggestion="Use \`gh api repos/${BASH_REMATCH[1]}/${BASH_REMATCH[2]}/contents/${BASH_REMATCH[3]}\` instead"
fi

jq -n --arg reason "${suggestion}. The gh CLI uses your authenticated GitHub token and works with private repos." \
  '{"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"deny","permissionDecisionReason":$reason}}'
