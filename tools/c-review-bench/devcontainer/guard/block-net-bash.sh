#!/usr/bin/env bash
# PreToolUse on Bash: deny any command that can open a network connection.
#
# Matched on the FIRST token of each shell segment, the same rule the benchmark's own
# anti-cheat scanner uses, so `grep -rn curl src/` and a file named wget-notes.txt stay
# allowed while `FOO=1 wget https://...` and `cc -c a.c && curl ...` do not. Runner
# wrappers are stripped so `uv run python` presents as `python`.
#
# The segment scan is awk, not a shell loop: the first version used
# `[ $# -eq 0 ] && continue` inside a `while read` under `set -e`, which returns non-zero
# whenever the test fails and killed the subshell after the first segment. It caught
# `curl ...` and missed `cc -c a.c && curl ...`, i.e. it half-worked, which is the worst
# way for a guard to fail. Both directions are covered by tests/test_anticheat.py, which
# runs this script for real.
set -uo pipefail
payload=$(cat)
cmd=$(printf '%s' "$payload" | jq -r '.tool_input.command // empty' 2>/dev/null) || exit 0
[[ -z "$cmd" ]] && exit 0
log="${CREVIEW_GUARD_LOG:-/dev/null}"

deny() {
  printf '%s\tBLOCKED\tBash\t%s\n' "$(date -u +%FT%TZ)" "$(printf '%s' "$cmd" | tr '\n' ' ' | head -c 300)" >>"$log"
  echo "BLOCKED: '$1' can reach the network. This repository is reviewed offline: consult no upstream, no repository, no advisory and no package index. Base every conclusion on the code in front of you, citing path:line." >&2
  exit 2
}

# No binary needed at all.
printf '%s' "$cmd" | grep -qE '/dev/(tcp|udp)/' && deny "/dev/tcp"
# An interpreter plus a call that opens a connection. An interpreter alone is not evidence.
printf '%s' "$cmd" | grep -qE 'urlopen|urlretrieve|requests\.(get|post|head)|httpx\.|socket\.(create_connection|connect)|http\.client|Net::HTTP|URI\.open|fetch\(' &&
  deny "an inline network call"

# Command and process substitution hide a whole command inside another one, and the awk
# below skips any token containing `=` — so `SRC=$(curl -s http://x)` and `bash <(curl …)`
# presented no matchable command name at all and were allowed straight through. Rewriting
# every paren and backtick to a segment separator makes the inner command a segment head in
# its own right.
#
# Both forms are scanned, not one instead of the other: the rewrite also cuts the OUTER
# command in two, and the `git` rule below is the one rule that needs more than the segment
# head — it scans the segment's remaining tokens for the subcommand. `git -C $(pwd) clone`
# rewrites to a `git -C $` segment and a `clone` segment, and neither is a hit. RS splits on
# newline, so appending the rewrite scans the union of both readings.
hit=$(printf '%s\n%s' "$cmd" "$(printf '%s' "$cmd" | sed 's/[`()]/;/g')" | awk '
  BEGIN { RS = "[;&|\n]+" }
  {
    n = split($0, t, /[ \t]+/)
    i = 1
    while (i <= n) {
      if (t[i] == "" || t[i] ~ /=/ || t[i] ~ /^-/ ) { i++; continue }
      if (t[i] ~ /^(uv|uvx|poetry|pipenv|nohup|env|time|sudo|xargs|command|run|then|do|else|fi|done)$/) { i++; continue }
      # A shell is a quoting layer, exactly as SHELL_WRAPPERS is in lib/anticheat.py: the
      # head of `bash -c "curl …"` is `bash`, which is in none of the lists below, so the
      # fetch was allowed. Skipping the wrapper (and the `-c`, already skipped as a flag)
      # makes the payload the segment head in its own right.
      if (t[i] ~ /^(sh|bash|zsh|dash|ksh|ash)$/) { i++; continue }
      break
    }
    if (i > n) next
    # Quotes strip AFTER the path strip: `bash -c "curl …"` heads on `"curl`, and
    # `"/usr/bin/curl"` leaves a trailing quote once the directory is gone.
    b = t[i]; sub(/^.*\//, "", b); gsub(/[\047"]/, "", b)
    if (b ~ /^(curl|wget|nc|ncat|netcat|ssh|scp|sftp|ftp|telnet|rsync|aria2c|httpie|http|lynx|w3m|links|fetch)$/) { print b; exit }
    if (b ~ /^(pip|pip3|npm|npx|yarn|pnpm|cargo|gem|brew|apt|apt-get)$/) { print b; exit }
    if (b == "git") {
      # Every token, not just the first non-flag one: `git -C /tmp clone` puts a
      # directory between the flag and the subcommand, and stopping at the first
      # non-flag token read that directory as the subcommand and allowed the clone.
      # Exact matches only, so `git log --oneline` and `git diff -- remote.c` pass.
      for (j = i + 1; j <= n; j++) {
        if (t[j] ~ /^(clone|fetch|pull|remote|ls-remote|submodule)$/) { print "git " t[j]; exit }
      }
    }
  }')
[[ -n "$hit" ]] && deny "$hit"
exit 0
