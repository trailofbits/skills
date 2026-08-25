#!/usr/bin/env bash
set -euo pipefail

# Fast exit if gh not installed
command -v gh &>/dev/null || exit 0

# WebFetch passes a single `url`; MCP fetch tools (Exa's web_fetch_exa and
# friends) pass a `urls` array and can batch several URLs into one call. Read
# both shapes so a batched fetch cannot slip a GitHub URL past the hook.
# `urls` is listed twice on purpose: the type filter keeps it when a server
# declares it as a bare string, and `arrays` unpacks it when it is a list.
# Only these two fields are read — WebFetch's `prompt` is deliberately not
# scanned, or a prompt that merely mentions a GitHub URL would false-deny.
urls=$(jq -r '[.tool_input.url?, .tool_input.urls?, (.tool_input.urls? | arrays | .[])]
  | map(select(type == "string" and . != ""))
  | .[]' 2>/dev/null) || exit 0
[[ -z "$urls" ]] && exit 0

# Clone-instead-of-fetch guidance, which several URL shapes share verbatim.
clone_hint() {
  local owner="$1" repo="$2"
  local target="\"\${TMPDIR:-/tmp}/gh-clones-\${CLAUDE_SESSION_ID}/${repo}\""
  echo "Use \`gh repo clone ${owner}/${repo} ${target} -- --depth 1\`, then use the Explore agent on the clone. Do NOT use \`gh api\` to fetch and base64-decode file contents — clone the repo instead"
}

clone_hint_generic() {
  echo "Use \`gh repo clone\` to a temp directory, then use the Explore agent on the clone. Do NOT use \`gh api\` to fetch and base64-decode file contents — clone the repo instead"
}

suggest_api() {
  local path="$1"
  if [[ $path =~ ^repos/([^/]+)/([^/]+)/pulls ]]; then
    echo "Use \`gh pr list --repo ${BASH_REMATCH[1]}/${BASH_REMATCH[2]}\` or \`gh pr view\` instead"
  elif [[ $path =~ ^repos/([^/]+)/([^/]+)/issues ]]; then
    echo "Use \`gh issue list --repo ${BASH_REMATCH[1]}/${BASH_REMATCH[2]}\` or \`gh issue view\` instead"
  elif [[ $path =~ ^repos/([^/]+)/([^/]+)/contents ]]; then
    clone_hint "${BASH_REMATCH[1]}" "${BASH_REMATCH[2]}"
  elif [[ $path =~ ^repos/([^/]+)/([^/]+)/releases ]]; then
    echo "Use \`gh release list --repo ${BASH_REMATCH[1]}/${BASH_REMATCH[2]}\` or \`gh api ${path}\` instead"
  elif [[ $path =~ ^repos/([^/]+)/([^/]+)/actions ]]; then
    echo "Use \`gh run list --repo ${BASH_REMATCH[1]}/${BASH_REMATCH[2]}\` or \`gh api ${path}\` instead"
  else
    echo "Use \`gh api ${path}\` instead"
  fi
}

suggest_raw() {
  # raw.githubusercontent.com/{owner}/{repo}/{ref}/{path}
  local path="$1"
  if [[ $path =~ ^([^/]+)/([^/]+)/[^/]+/(.+) ]]; then
    clone_hint "${BASH_REMATCH[1]}" "${BASH_REMATCH[2]}"
  else
    clone_hint_generic
  fi
}

suggest_github_com() {
  local path="$1"
  # Skip non-repo paths (single-segment paths are site pages, not repos)
  # e.g. github.com/settings, github.com/notifications, github.com/login
  if [[ -z "$path" ]] || ! [[ $path =~ / ]]; then
    return 0
  fi
  # Match specific resource patterns before the generic {owner}/{repo} catch-all
  if [[ $path =~ ^([^/]+)/([^/]+)/pull/([0-9]+) ]]; then
    echo "Use \`gh pr view ${BASH_REMATCH[3]} --repo ${BASH_REMATCH[1]}/${BASH_REMATCH[2]}\` instead"
  elif [[ $path =~ ^([^/]+)/([^/]+)/issues/([0-9]+) ]]; then
    echo "Use \`gh issue view ${BASH_REMATCH[3]} --repo ${BASH_REMATCH[1]}/${BASH_REMATCH[2]}\` instead"
  elif [[ $path =~ ^([^/]+)/([^/]+)/releases/download/ ]]; then
    echo "Use \`gh release download --repo ${BASH_REMATCH[1]}/${BASH_REMATCH[2]}\` instead"
  elif [[ $path =~ ^([^/]+)/([^/]+)/(blob|tree)/ ]]; then
    clone_hint "${BASH_REMATCH[1]}" "${BASH_REMATCH[2]}"
  elif [[ $path =~ ^([^/]+)/([^/]+) ]]; then
    echo "Use \`gh repo view ${BASH_REMATCH[1]}/${BASH_REMATCH[2]}\` instead"
  else
    echo "Use the \`gh\` CLI instead"
  fi
}

# Echo a gh CLI suggestion for a GitHub URL, or nothing if the URL should pass.
suggest_for_url() {
  local url="$1" stripped host path

  # Strip protocol to get host/path
  stripped="${url#http://}"
  stripped="${stripped#https://}"

  # Strip query string and fragment before parsing
  stripped="${stripped%%\?*}"
  stripped="${stripped%%#*}"

  # Extract hostname and path
  host="${stripped%%/*}"
  path="${stripped#*/}"
  # ${var#*/} returns the original string when there's no slash,
  # so path == host means the URL had no path component (e.g. "https://github.com")
  [[ "$path" == "$host" ]] && path=""

  [[ -z "$host" ]] && return 0

  # Skip non-GitHub domains (including github.io — those are regular websites)
  case "$host" in
    api.github.com) suggest_api "$path" ;;
    raw.githubusercontent.com) suggest_raw "$path" ;;
    gist.github.com) echo "Use \`gh gist view\` instead" ;;
    github.com) suggest_github_com "$path" ;;
    *) return 0 ;;
  esac
}

# A tool call is atomic, so one offending URL denies the whole call. Label each
# suggestion with its URL when the call carried more than one, so the model can
# tell which of a batch was the problem.
url_count=$(printf '%s\n' "$urls" | wc -l)
reason=""
while IFS= read -r url; do
  suggestion="$(suggest_for_url "$url")"
  [[ -z "$suggestion" ]] && continue
  if [[ $url_count -gt 1 ]]; then
    suggestion="${url}: ${suggestion}"
  fi
  reason="${reason:+${reason}
}${suggestion}"
done <<<"$urls"

[[ -z "$reason" ]] && exit 0

# One suggestion reads as a sentence; several read as a list, so the closing
# note gets its own line rather than trailing only the last entry.
closing="The gh CLI uses your authenticated GitHub token and works with private repos."
if [[ "$reason" == *$'\n'* ]]; then
  reason="${reason}
${closing}"
else
  reason="${reason}. ${closing}"
fi

jq -n --arg reason "$reason" \
  '{"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"deny","permissionDecisionReason":$reason}}'
