#!/usr/bin/env bash
set -euo pipefail

# Fast exit if gh not installed
command -v gh &>/dev/null || exit 0

# Parse command from JSON input
cmd=$(jq -r '.tool_input.command // empty' 2>/dev/null) || exit 0
[[ -z "$cmd" ]] && exit 0

# A heredoc body is content being written to a file, not something this command
# runs. Matching it denies `cat > f <<'EOF' ... EOF` whenever the file content
# happens to mention curl and a GitHub URL, on a command that fetches nothing.
# Match the command with heredoc bodies removed instead.
cmd_matched="$(printf '%s\n' "$cmd" | awk 'BEGIN { in_hd = 0; strip = 0; sq = sprintf("%c", 39); dq = sprintf("%c", 34) }
{
  if (in_hd) {
    line = $0
    if (strip) sub(/^\t+/, "", line)
    if (line == delim) in_hd = 0
    next
  }
  print
  rest = $0
  hit = 0
  while (match(rest, /<<-?[ \t]*[^ \t;|&]+/)) {
    op = substr(rest, RSTART, RLENGTH)
    strip = (substr(op, 3, 1) == "-") ? 1 : 0
    d = op
    sub(/^<<-?[ \t]*/, "", d)
    if (substr(d, 1, 1) == sq || substr(d, 1, 1) == dq) d = substr(d, 2)
    if (substr(d, length(d), 1) == sq || substr(d, length(d), 1) == dq) d = substr(d, 1, length(d) - 1)
    rest = substr(rest, RSTART + RLENGTH)
    hit = 1
  }
  if (hit) { delim = d; in_hd = 1 } else { delim = "" }
}
')"

# Only intercept commands that use curl or wget
if ! [[ $cmd_matched =~ (^|[[:space:];|&])(curl|wget)[[:space:]] ]]; then
  # No curl/wget — skip gh and git commands without further checks
  exit 0
fi

# Check if the curl/wget targets a GitHub URL
github_pattern='https?://(github\.com|api\.github\.com|raw\.githubusercontent\.com|gist\.github\.com)/'
if ! [[ $cmd_matched =~ $github_pattern ]]; then
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
elif [[ $cmd =~ api\.github\.com/repos/([^/]+)/([^/]+)/actions ]]; then
  suggestion="Use \`gh run list --repo ${BASH_REMATCH[1]}/${BASH_REMATCH[2]}\` instead"
elif [[ $cmd =~ api\.github\.com/repos/([^/]+)/([^/]+)/contents ]]; then
  suggestion="Use \`gh repo clone ${BASH_REMATCH[1]}/${BASH_REMATCH[2]} \"\${TMPDIR:-/tmp}/gh-clones-\${CLAUDE_SESSION_ID}/${BASH_REMATCH[2]}\" -- --depth 1\`, then use the Explore agent on the clone. Do NOT use \`gh api\` to fetch and base64-decode file contents — clone the repo instead"
elif [[ $cmd =~ api\.github\.com/([^[:space:]\"\']+) ]]; then
  suggestion="Use \`gh api ${BASH_REMATCH[1]}\` instead"
elif [[ $cmd =~ github\.com/([^/]+)/([^/]+)/releases/download/ ]]; then
  suggestion="Use \`gh release download --repo ${BASH_REMATCH[1]}/${BASH_REMATCH[2]}\` instead"
elif [[ $cmd =~ github\.com/([^/]+)/([^/]+)/archive/ ]]; then
  suggestion="Use \`gh release download --repo ${BASH_REMATCH[1]}/${BASH_REMATCH[2]}\` instead"
elif [[ $cmd =~ raw\.githubusercontent\.com/([^/]+)/([^/]+)/[^/]+/([^[:space:]\"\']+) ]]; then
  suggestion="Use \`gh repo clone ${BASH_REMATCH[1]}/${BASH_REMATCH[2]} \"\${TMPDIR:-/tmp}/gh-clones-\${CLAUDE_SESSION_ID}/${BASH_REMATCH[2]}\" -- --depth 1\`, then use the Explore agent on the clone. Do NOT use \`gh api\` to fetch and base64-decode file contents — clone the repo instead"
elif [[ $cmd =~ gist\.github\.com/ ]]; then
  suggestion="Use \`gh gist view\` instead"
fi

jq -n --arg reason "${suggestion}. The gh CLI uses your authenticated GitHub token and works with private repos." \
  '{"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"deny","permissionDecisionReason":$reason}}'
