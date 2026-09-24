#!/usr/bin/env bash
set -euo pipefail

plugin=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
hook="$plugin/hooks/block-large-sarif-read.sh"
work=$(mktemp -d "${TMPDIR:-/tmp}/sarif-read-hook.XXXXXX")
trap 'rm -rf "$work"' EXIT
small="$work/small.sarif"
boundary="$work/boundary.sarif"
large="$work/large.sarif"
mixed_case="$work/large.SaRiF"
other="$work/large.json"
printf '{}' >"$small"
truncate -s 204800 "$boundary"
truncate -s 204801 "$large"
truncate -s 204801 "$mixed_case"
truncate -s 204801 "$other"

run_hook() { jq -n --arg path "$1" '{tool_input:{file_path:$path}}' | "$hook"; }

[[ -z $(run_hook "$small") ]]
[[ -z $(run_hook "$boundary") ]]
[[ -z $(run_hook "$other") ]]
[[ -z $(run_hook "$work/missing.sarif") ]]
[[ -z $(printf '{}' | "$hook") ]]
[[ -z $(printf 'invalid json' | "$hook" 2>/dev/null) ]]
run_hook "$large" | jq -e '.hookSpecificOutput.permissionDecision == "deny" and (.hookSpecificOutput.permissionDecisionReason | contains("sarif-parsing helper"))' >/dev/null
run_hook "$mixed_case" | jq -e '.hookSpecificOutput.permissionDecision == "deny"' >/dev/null
jq -n --arg path "$large" '{tool_input:{file_path:$path,offset:1,limit:1}}' | "$hook" |
  jq -e '.hookSpecificOutput.permissionDecision == "deny"' >/dev/null
printf 'PASS large SARIF Read gate\n'
