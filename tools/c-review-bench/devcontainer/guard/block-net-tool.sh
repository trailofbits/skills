#!/usr/bin/env bash
# PreToolUse: deny WebFetch / WebSearch outright.
#
# Exists because instruction does not hold. On 2026-08-05 two of c-review's hunters
# fetched upstream zlib through a prominent EVIDENCE_RULE and then declared they had
# done it. A prohibition the model can read is a prohibition the model can weigh; a
# hook is not.
#
# Every block is logged. A hook that silently never fires would let a run be reported
# as "network blocked" while nothing was blocked, which is the failure this whole
# exercise is about.
set -euo pipefail
payload=$(cat)
tool=$(printf '%s' "$payload" | jq -r '.tool_name // empty' 2>/dev/null) || exit 0
[[ -z "$tool" ]] && exit 0
log="${CREVIEW_GUARD_LOG:-/dev/null}"
case "$tool" in
  WebFetch | WebSearch)
    printf '%s\tBLOCKED\t%s\t%s\n' "$(date -u +%FT%TZ)" "$tool" \
      "$(printf '%s' "$payload" | jq -c '.tool_input' 2>/dev/null | head -c 300)" >>"$log"
    echo "BLOCKED: $tool is not available. This repository is reviewed offline: reach no network, and base every conclusion on the code in front of you." >&2
    exit 2
    ;;
esac
exit 0
