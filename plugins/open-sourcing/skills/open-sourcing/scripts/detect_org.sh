#!/usr/bin/env bash
# Detects whether the current repository belongs to an organization with an
# additional guidance profile in references/. Prints the profile name
# ("trailofbits" or "generic") to stdout.
set -euo pipefail

TOB_ORGS='trailofbits|lifting-bits|crytic'

remote_matches_tob() {
  git remote -v 2>/dev/null | grep -qiE "github\.com[:/](${TOB_ORGS})/"
}

commits_match_tob() {
  git log --format='%ae%n%ce' -n 200 2>/dev/null | grep '@trailofbits\.com$' >/dev/null
}

main() {
  if ! git rev-parse --is-inside-work-tree >/dev/null 2>&1; then
    echo "error: not inside a git repository" >&2
    exit 1
  fi

  if remote_matches_tob || commits_match_tob; then
    echo "trailofbits"
  else
    echo "generic"
  fi
}

main "$@"
