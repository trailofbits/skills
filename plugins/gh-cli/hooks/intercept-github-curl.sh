#!/usr/bin/env bash
set -euo pipefail

# Fast exit if gh not installed
command -v gh &>/dev/null || exit 0

# Parse command from JSON input
cmd=$(jq -r '.tool_input.command // empty' 2>/dev/null) || exit 0
[[ -z "$cmd" ]] && exit 0

# Only intercept commands that use curl or wget.
#
# The preceding-character class used to be [[:space:];|&], which accepted only
# line start, whitespace, ';', '|' and '&'. Anything else in front of `curl`
# skipped the hook entirely:
#
#   ver=$(curl -s .../releases/latest)   '(' — by far the most common form
#   bash -c "curl ..."                   '"'
#   ssh host "curl ..."                  '"'
#   /usr/bin/curl ...                    '/'
#   `curl ...`                           backtick
#   wget2 -qO- ...                       binary name is not exactly "wget"
#
# Treating any non-identifier character as a word boundary keeps real
# compounds (mycurl, curl.sh) out while catching all of the above. The cost is
# that `echo "curl https://github.com/..." > notes.txt` now reaches the URL
# scan and is denied although it only writes text — a deliberate trade, since
# command substitution is everyday usage and echoing a curl string is rare.
if ! [[ $cmd =~ (^|[^A-Za-z0-9_.-])(curl|wget2?)([[:space:]]|$) ]]; then
  # No curl/wget — skip gh and git commands without further checks
  exit 0
fi

# Cheap bail-out before any scrubbing. This hook runs on every Bash call, and
# a command with no mention of GitHub cannot have a GitHub target.
#
# Note how loose this is: the bare word "github", case-folded, with braces and
# percent-encoding removed first. It runs before normalisation, so it cannot
# assume the host is spelled literally — API.GITHUB.COM, api.github.{com} and
# api%2Egithub%2Ecom all reach GitHub, and a stricter test let all three out
# here before anything else ran.
probe="${cmd,,}"
probe="${probe//\{/}"
probe="${probe//\}/}"
probe="${probe//%2e/.}"
if [[ "$probe" != *github* ]]; then
  exit 0
fi

# Narrow the command down to what curl/wget is actually fetching.
#
# Testing the whole command string for "contains a GitHub URL" denies commands
# that never fetch from GitHub at all:
#
#   cat > s.sh <<EOF ... curl https://api.github.com/... ... EOF
#       authoring a script, not fetching
#   curl https://example.com/x  # see https://github.com/o/r/issues/1
#       the fetch goes to example.com; GitHub is only named in a comment
#   curl "https://r.jina.ai/?url=https://github.com/o/r/pulls"
#       the host is the reader service, not GitHub
#
# So: drop heredoc bodies and comments, then keep only the URLs whose *host*
# is GitHub.
#
# Deliberately NOT narrowed to the text following curl/wget. Splitting the
# command at ; | & to find "the curl part" loses URLs behind a quoted flag
# value containing one of those characters, and misses
#   U=https://api.github.com/...; curl "$U"
# entirely. Scanning every URL in the command keeps the original coverage;
# the host check alone is what removes the false positives.
#
# Comment stripping is quote-aware, or a '#' inside a quoted header value
# would truncate the line and hide the real target. An unterminated heredoc
# falls back to the raw command rather than silently swallowing the rest.
scrubbed=$(printf '%s\n' "$cmd" | awk '
  function strip_comment(s,   i, c, n, q, out) {
    q = ""; n = length(s)
    for (i = 1; i <= n; i++) {
      c = substr(s, i, 1)
      # Inside double quotes a backslash escapes the next character, so a
      # \" must not be read as the closing quote.
      if (q == "\"" && c == "\\" && i < n) {
        out = out c substr(s, i + 1, 1)
        i++
        continue
      }
      if (q == "") {
        if (c == "\"" || c == "'\''") { q = c }
        else if (c == "#" && (i == 1 || substr(s, i - 1, 1) ~ /[ \t]/)) { break }
      } else if (c == q) { q = "" }
      out = out c
    }
    return out
  }
  inhd {
    if ($0 ~ "^[[:space:]]*" delim "[[:space:]]*$") { inhd = 0 }
    next
  }
  {
    line = $0
    probe = line
    # More than one heredoc opened on a line needs a delimiter queue. Rather
    # than half-track it, bail out and let the caller scan the raw command.
    if (gsub(/<<-?[[:space:]]*['\''"]?[A-Za-z_]/, "&", probe) > 1) { exit 3 }
    # `cat > f <<EOF` WRITES the body; `bash <<EOF` EXECUTES it. Stripping
    # both let a heredoc-fed shell fetch anything. If the command word is an
    # interpreter, keep the body and scan it.
    runs_body = (line ~ /^[[:space:]]*(sudo[[:space:]]+)?(env[[:space:]]+)?(bash|sh|zsh|ksh|dash|python3?|perl|ruby|node)([[:space:]]|$)/)
    if (!runs_body && match(line, /<<-?[[:space:]]*['\''"]?[A-Za-z_][A-Za-z0-9_]*/)) {
      tag = substr(line, RSTART, RLENGTH)
      gsub(/^<<-?[[:space:]]*['\''"]?/, "", tag)
      delim = tag; inhd = 1
    }
    print strip_comment(line)
  }
  END { if (inhd) exit 3 }
') || scrubbed="$cmd"

# Normalise before extraction. All three forms below reach GitHub in practice
# (verified 200) but were invisible to a literal pattern:
#   api.github.{com}      curl's own URL globbing, expanded by curl
#   api%2Egithub%2Ecom    percent-encoded host
#   github.com.           trailing dot (a valid FQDN)
norm=$(printf '%s' "$scrubbed" | sed -E 's/%2[eE]/./g; s/[{}]//g')

# Two passes, and the order is the whole point.
#
# Pass 1 takes complete URLs with a scheme. It has to run first, or pass 2
# picks an embedded github.com out of ANOTHER host's query string —
# https://r.jina.ai/?url=https://github.com/... has r.jina.ai as its host, and
# seeing github.com there is exactly the false positive this hook removed.
full=$(printf '%s\n' "$norm" | grep -oE 'https?://[^[:space:]"'\''`)]+' || true)

# Pass 2 runs on what is LEFT once pass 1's matches are cut out, so it catches
# schemeless forms — `curl -sL github.com/o/r/archive/x.tgz` works fine — and
# a host held in a variable (`H=api.github.com; curl "https://$H/..."`),
# without ever looking inside someone else's URL.
rest=$(printf '%s\n' "$norm" | sed -E 's#https?://[^[:space:]"'\''`)]+##g')
bare=$(printf '%s\n' "$rest" |
  grep -oiE '[A-Za-z0-9._-]*github(usercontent)?\.com\.?(:[0-9]+)?(/[^[:space:]"'\''`)]*)?' ||
  true)

targets="${full}
${bare}"

[[ -z "${targets//[[:space:]]/}" ]] && exit 0

# A suffix rule rather than a four-entry list. The list was missing
# codeload.github.com (what GitHub's own "Download ZIP" points at),
# www.github.com, gist.githubusercontent.com and objects.githubusercontent.com
# — all verified to serve real repository content.
is_github_host() {
  case "$1" in
    github.com | *.github.com | githubusercontent.com | *.githubusercontent.com) return 0 ;;
  esac
  return 1
}

gh_targets=""
while IFS= read -r url; do
  [[ -z "$url" ]] && continue
  host="${url#*://}"
  host="${host%%/*}"
  host="${host%%\?*}"
  host="${host##*@}" # userinfo
  host="${host%%:*}" # port
  host="${host,,}"   # DNS is case-insensitive; API.GITHUB.COM answered 200
  host="${host%.}"   # trailing dot
  if is_github_host "$host"; then
    # Re-emit with the NORMALISED host so the suggestion patterns below match
    # a host that was uppercased or carried a trailing dot.
    rawhost="${url#*://}"
    rawhost="${rawhost%%/*}"
    path="${url#*://}"
    if [[ "$path" == "$rawhost" ]]; then path=""; else path="/${path#*/}"; fi
    gh_targets="${gh_targets:+${gh_targets}
}https://${host}${path}"
  fi
done <<<"$targets"

[[ -z "$gh_targets" ]] && exit 0

# From here on, match against the GitHub targets only — never the whole command.
cmd="$gh_targets"

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
