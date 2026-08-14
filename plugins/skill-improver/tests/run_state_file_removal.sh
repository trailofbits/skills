#!/usr/bin/env bash
# Regression suite for state-file removal (issue #244), discovered by CI's run_*.sh glob.
#
# `trash` comes from trash-cli/Homebrew and is absent on stock Linux distros.
# Because every script runs under `set -e`, calling it used to abort the stop
# hook on the completion path (so the loop could never terminate) and broke
# /cancel-skill-improver. Each scenario runs with a curated stub PATH that
# provably lacks `trash`, so the suite is hermetic on any machine.
set -uo pipefail

PLUGIN_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
readonly EXPECTED_ASSERTIONS=8

command -v jq >/dev/null 2>&1 || {
  echo "run_state_file_removal.sh: jq not found — required" >&2
  exit 1
}

PASS=0
FAIL=0
ok() {
  if [ "$1" = "0" ]; then
    PASS=$((PASS + 1))
  else
    FAIL=$((FAIL + 1))
    echo "  FAIL: $2" >&2
  fi
}
contains() {
  case "$1" in
    *"$2"*) PASS=$((PASS + 1)) ;;
    *)
      FAIL=$((FAIL + 1))
      echo "  FAIL: $3" >&2
      ;;
  esac
}
absent() {
  if [ ! -e "$1" ]; then
    PASS=$((PASS + 1))
  else
    FAIL=$((FAIL + 1))
    echo "  FAIL: $2" >&2
  fi
}

# Stub PATH holding everything the scripts call, except trash
STUB="$(mktemp -d)"
WORK="$(mktemp -d)"
trap 'rm -rf "$STUB" "$WORK"' EXIT
for tool in dirname cat jq grep sed basename mv rm; do
  ln -s "$(command -v "$tool")" "$STUB/$tool"
done

SID="20260814120000-abcd1234"
STATE_FILE="$WORK/.claude/skill-improver.$SID.local.md"

make_state_file() {
  mkdir -p "$WORK/.claude"
  cat >"$STATE_FILE" <<EOF
---
session_id: "$SID"
iteration: 2
max_iterations: 20
skill_path: "/tmp/some-skill"
skill_name: "some-skill"
---
EOF
}

echo "cancel script without trash on PATH"
make_state_file
out=$(cd "$WORK" && PATH="$STUB" "$PLUGIN_ROOT/scripts/cancel-skill-improver.sh" 2>&1)
ok $? "cancel exits 0 without trash"
contains "$out" "cancelled" "cancel prints confirmation"
absent "$STATE_FILE" "cancel removes the state file"

echo "stop hook completion path without trash on PATH"
make_state_file
transcript="$WORK/transcript.jsonl"
cat >"$transcript" <<EOF
{"message":{"role":"user","content":[{"type":"text","text":"Session ID: $SID"}]}}
{"message":{"role":"assistant","content":[{"type":"text","text":"All fixed.\n<skill-improvement-complete>"}]}}
EOF
input=$(printf '{"stop_hook_active": false, "transcript_path": "%s"}' "$transcript")
out=$(cd "$WORK" && PATH="$STUB" "$PLUGIN_ROOT/hooks/stop-hook.sh" <<<"$input" 2>&1)
ok $? "stop hook exits 0 without trash"
contains "$out" "Improvement complete" "stop hook prints completion"
absent "$STATE_FILE" "stop hook removes the state file"

echo "remove_state_file prefers trash when available"
make_state_file
cat >"$STUB/trash" <<'EOF'
#!/bin/bash
echo "$1" >>"${TRASH_LOG:?}"
rm -f -- "$1"
EOF
chmod +x "$STUB/trash"
TRASH_LOG="$WORK/trash.log"
out=$(cd "$WORK" && PATH="$STUB" TRASH_LOG="$TRASH_LOG" \
  "$PLUGIN_ROOT/scripts/cancel-skill-improver.sh" 2>&1)
ok $? "cancel exits 0 with trash present"
grep -q "skill-improver.$SID.local.md" "$TRASH_LOG" 2>/dev/null
ok $? "trash received the state file"

TOTAL=$((PASS + FAIL))
if [ "$TOTAL" -ne "$EXPECTED_ASSERTIONS" ]; then
  echo "FAIL: expected $EXPECTED_ASSERTIONS assertions, ran $TOTAL" >&2
  exit 1
fi
echo "$PASS/$TOTAL assertions passed"
[ "$FAIL" -eq 0 ]
