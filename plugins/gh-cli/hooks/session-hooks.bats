#!/usr/bin/env bats
# Tests for persist-session-id.sh and cleanup-clones.sh hooks

PERSIST_HOOK="${BATS_TEST_DIRNAME}/persist-session-id.sh"
CLEANUP_HOOK="${BATS_TEST_DIRNAME}/cleanup-clones.sh"

# =============================================================================
# persist-session-id.sh
# =============================================================================

@test "persist: exits silently on invalid JSON" {
  run bash -c 'echo "not json" | "$1"' _ "$PERSIST_HOOK"
  [[ $status -eq 0 ]]
}

@test "persist: exits silently on empty JSON" {
  run bash -c 'echo "{}" | "$1"' _ "$PERSIST_HOOK"
  [[ $status -eq 0 ]]
}

@test "persist: exits silently when session_id is empty" {
  run bash -c 'echo "{\"session_id\":\"\"}" | "$1"' _ "$PERSIST_HOOK"
  [[ $status -eq 0 ]]
}

@test "persist: warns when CLAUDE_ENV_FILE is unset" {
  run bash -c 'unset CLAUDE_ENV_FILE; echo "{\"session_id\":\"abc-123\"}" | "$1" 2>&1' _ "$PERSIST_HOOK"
  [[ $status -eq 0 ]]
  [[ "$output" == *"CLAUDE_ENV_FILE not set"* ]]
}

@test "persist: writes export to CLAUDE_ENV_FILE when set" {
  local tmpfile
  tmpfile="$(mktemp)"
  run bash -c 'CLAUDE_ENV_FILE="$1" && export CLAUDE_ENV_FILE && echo "{\"session_id\":\"test-session-42\"}" | "$2"' _ "$tmpfile" "$PERSIST_HOOK"
  [[ $status -eq 0 ]]
  grep -q 'export CLAUDE_SESSION_ID="test-session-42"' "$tmpfile"
  rm -f "$tmpfile"
}

@test "persist: rejects session_id with shell metacharacters" {
  local tmpfile
  tmpfile="$(mktemp)"
  run bash -c 'CLAUDE_ENV_FILE="$1" && export CLAUDE_ENV_FILE && echo "{\"session_id\":\"; rm -rf /\"}" | "$2" 2>&1' _ "$tmpfile" "$PERSIST_HOOK"
  [[ $status -eq 0 ]]
  [[ "$output" == *"invalid session_id format"* ]]
  # File should be empty — nothing written
  [[ ! -s "$tmpfile" ]]
  rm -f "$tmpfile"
}

# =============================================================================
# cleanup-clones.sh
# =============================================================================

@test "cleanup: exits silently on invalid JSON" {
  run bash -c 'echo "not json" | "$1"' _ "$CLEANUP_HOOK"
  [[ $status -eq 0 ]]
}

@test "cleanup: exits silently on empty JSON" {
  run bash -c 'echo "{}" | "$1"' _ "$CLEANUP_HOOK"
  [[ $status -eq 0 ]]
}

@test "cleanup: exits silently when session_id is empty" {
  run bash -c 'echo "{\"session_id\":\"\"}" | "$1"' _ "$CLEANUP_HOOK"
  [[ $status -eq 0 ]]
}

@test "cleanup: rejects session_id with shell metacharacters" {
  run bash -c 'echo "{\"session_id\":\"; rm -rf /\"}" | "$1" 2>&1' _ "$CLEANUP_HOOK"
  [[ $status -eq 0 ]]
  [[ "$output" == *"invalid session_id format"* ]]
}

@test "cleanup: removes session-scoped clone directory" {
  local tmpdir
  tmpdir="$(mktemp -d)"
  mkdir -p "${tmpdir}/gh-clones-test-session-99/some-repo"
  echo "dummy" >"${tmpdir}/gh-clones-test-session-99/some-repo/file.txt"
  run bash -c 'TMPDIR="$1" && export TMPDIR && echo "{\"session_id\":\"test-session-99\"}" | "$2"' _ "$tmpdir" "$CLEANUP_HOOK"
  [[ $status -eq 0 ]]
  [[ ! -d "${tmpdir}/gh-clones-test-session-99" ]]
  rm -rf "$tmpdir"
}

@test "cleanup: no error when clone directory does not exist" {
  local tmpdir
  tmpdir="$(mktemp -d)"
  run bash -c 'TMPDIR="$1" && export TMPDIR && echo "{\"session_id\":\"nonexistent-session\"}" | "$2"' _ "$tmpdir" "$CLEANUP_HOOK"
  [[ $status -eq 0 ]]
  rm -rf "$tmpdir"
}
