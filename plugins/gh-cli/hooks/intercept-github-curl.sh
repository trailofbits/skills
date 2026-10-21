#!/usr/bin/env bash
set -euo pipefail

# Fast exit if gh not installed
command -v gh &>/dev/null || exit 0

# Parse command from JSON input
cmd=$(jq -r '.tool_input.command // empty' 2>/dev/null) || exit 0
[[ -z "$cmd" ]] && exit 0

# A heredoc body is normally content being written to a file, not something this
# command runs, so matching it denies `cat > f <<'EOF' ... EOF` whenever the file
# content happens to mention curl and a GitHub URL on a command that fetches
# nothing. Two shapes are not inert and must keep being matched:
#
#   * an interpreted heredoc -- `bash <<'EOF' ... EOF` -- where the body *is* the
#     script that runs, quoted delimiter or not;
#   * an unquoted delimiter, where the shell expands the body, so `$(curl ...)`
#     and backticks execute even though the text looks like file content.
#
# Match the command with only the inert bodies removed.
cmd_matched="$(printf '%s\n' "$cmd" | awk 'BEGIN {
  in_hd = 0; strip = 0; keep = 0; quoted = 0
  sq = sprintf("%c", 39); dq = sprintf("%c", 34)
  n = split("bash sh dash zsh ksh mksh ash python python3 perl ruby node php lua", p, " ")
  for (i = 1; i <= n; i++) interp[p[i]] = 1
  skip["sudo"] = 1; skip["env"] = 1; skip["command"] = 1; skip["exec"] = 1
  skip["nice"] = 1; skip["time"] = 1; skip["nohup"] = 1; skip["doas"] = 1
}
{
  if (in_hd) {
    line = $0
    if (strip) sub(/^\t+/, "", line)
    if (line == delim) { in_hd = 0; next }
    if (keep) { print; next }
    # An unquoted delimiter expands the body, so a substitution runs. Rewrite the
    # delimiters to spaces before matching, because the curl/wget test below needs a
    # whitespace or list separator in front of the command and `$(curl` has neither.
    if (!quoted && line ~ /\$\(|`|\$\{/) {
      gsub(/\$\(/, " ", line)
      gsub(/\$\{/, " ", line)
      gsub(/`/, " ", line)
      gsub(/[)(}{]/, " ", line)
      print line
    }
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
    quoted = 0
    if (substr(d, 1, 1) == sq || substr(d, 1, 1) == dq) { quoted = 1; d = substr(d, 2) }
    if (substr(d, length(d), 1) == sq || substr(d, length(d), 1) == dq) { quoted = 1; d = substr(d, 1, length(d) - 1) }
    rest = substr(rest, RSTART + RLENGTH)
    hit = 1
  }
  keep = 0
  if (hit) {
    delim = d
    in_hd = 1
    head = $0
    sub(/<<.*$/, "", head)
    cnt = split(head, tok, /[ \t]+/)
    for (i = 1; i <= cnt; i++) {
      if (tok[i] == "") continue
      if (tok[i] ~ /^[A-Za-z_][A-Za-z0-9_]*=/) continue
      if (skip[tok[i]]) continue
      if (interp[tok[i]]) keep = 1
      break
    }
  } else { delim = "" }
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
