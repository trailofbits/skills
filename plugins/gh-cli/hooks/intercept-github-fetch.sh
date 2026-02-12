#!/usr/bin/env bash
set -euo pipefail

# Fast exit if gh not installed
command -v gh &>/dev/null || exit 0

# Parse URL from JSON input
url=$(jq -r '.tool_input.url // empty' 2>/dev/null) || exit 0
[[ -z "$url" ]] && exit 0

# Strip protocol to get host/path
stripped="${url#http://}"
stripped="${stripped#https://}"

# Extract hostname and path
host="${stripped%%/*}"
path="${stripped#*/}"
# ${var#*/} returns the original string when there's no slash,
# so path == host means the URL had no path component (e.g. "https://github.com")
[[ "$path" == "$host" ]] && path=""

[[ -z "$host" ]] && exit 0

# Skip non-GitHub domains (including github.io — those are regular websites)
case "$host" in
  github.com | api.github.com | raw.githubusercontent.com | gist.github.com) ;;
  *) exit 0 ;;
esac

suggestion=""

case "$host" in
  api.github.com)
    # Check for specific API patterns
    if [[ $path =~ ^repos/([^/]+)/([^/]+)/pulls ]]; then
      suggestion="Use \`gh pr list --repo ${BASH_REMATCH[1]}/${BASH_REMATCH[2]}\` or \`gh pr view\` instead"
    elif [[ $path =~ ^repos/([^/]+)/([^/]+)/issues ]]; then
      suggestion="Use \`gh issue list --repo ${BASH_REMATCH[1]}/${BASH_REMATCH[2]}\` or \`gh issue view\` instead"
    elif [[ $path =~ ^repos/([^/]+)/([^/]+)/releases ]]; then
      suggestion="Use \`gh release list --repo ${BASH_REMATCH[1]}/${BASH_REMATCH[2]}\` or \`gh api ${path}\` instead"
    elif [[ $path =~ ^repos/([^/]+)/([^/]+)/actions ]]; then
      suggestion="Use \`gh run list --repo ${BASH_REMATCH[1]}/${BASH_REMATCH[2]}\` or \`gh api ${path}\` instead"
    else
      suggestion="Use \`gh api ${path}\` instead"
    fi
    ;;
  raw.githubusercontent.com)
    # raw.githubusercontent.com/{owner}/{repo}/{ref}/{path}
    if [[ $path =~ ^([^/]+)/([^/]+)/[^/]+/(.+) ]]; then
      suggestion="Use \`gh api repos/${BASH_REMATCH[1]}/${BASH_REMATCH[2]}/contents/${BASH_REMATCH[3]}\` instead"
    else
      suggestion="Use \`gh api\` to fetch raw file contents instead"
    fi
    ;;
  gist.github.com)
    suggestion="Use \`gh gist view\` instead"
    ;;
  github.com)
    # Skip non-repo paths (single-segment paths are site pages, not repos)
    # e.g. github.com/settings, github.com/notifications, github.com/login
    if [[ -z "$path" ]] || ! [[ $path =~ / ]]; then
      exit 0
    fi
    # Match specific resource patterns before the generic {owner}/{repo} catch-all
    if [[ $path =~ ^([^/]+)/([^/]+)/pull/([0-9]+) ]]; then
      suggestion="Use \`gh pr view ${BASH_REMATCH[3]} --repo ${BASH_REMATCH[1]}/${BASH_REMATCH[2]}\` instead"
    elif [[ $path =~ ^([^/]+)/([^/]+)/issues/([0-9]+) ]]; then
      suggestion="Use \`gh issue view ${BASH_REMATCH[3]} --repo ${BASH_REMATCH[1]}/${BASH_REMATCH[2]}\` instead"
    elif [[ $path =~ ^([^/]+)/([^/]+)/releases/download/ ]]; then
      suggestion="Use \`gh release download --repo ${BASH_REMATCH[1]}/${BASH_REMATCH[2]}\` instead"
    elif [[ $path =~ ^([^/]+)/([^/]+)/blob/ ]]; then
      suggestion="Use \`gh api repos/${BASH_REMATCH[1]}/${BASH_REMATCH[2]}/contents/...\` or clone and use Read tool instead"
    elif [[ $path =~ ^([^/]+)/([^/]+)/tree/([^/]+)/(.*) ]]; then
      suggestion="Use \`gh api repos/${BASH_REMATCH[1]}/${BASH_REMATCH[2]}/contents/${BASH_REMATCH[4]}?ref=${BASH_REMATCH[3]}\` instead"
    elif [[ $path =~ ^([^/]+)/([^/]+) ]]; then
      suggestion="Use \`gh repo view ${BASH_REMATCH[1]}/${BASH_REMATCH[2]}\` instead"
    else
      suggestion="Use the \`gh\` CLI instead"
    fi
    ;;
esac

[[ -z "$suggestion" ]] && exit 0

jq -n --arg reason "${suggestion}. The gh CLI uses your authenticated GitHub token and works with private repos." \
  '{"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"deny","permissionDecisionReason":$reason}}'
