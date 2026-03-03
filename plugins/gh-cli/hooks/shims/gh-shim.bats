#!/usr/bin/env bats
# Tests for gh PATH shim

bats_require_minimum_version 1.5.0

SHIM="${BATS_TEST_DIRNAME}/gh"

setup() {
  # Create a fake gh binary that echoes its args
  FAKE_GH_DIR="$(mktemp -d)"
  printf '#!/usr/bin/env bash\necho "REAL_GH_CALLED $*"\n' >"$FAKE_GH_DIR/gh"
  chmod +x "$FAKE_GH_DIR/gh"

  SHIM_DIR="$(cd "$(dirname "$SHIM")" && pwd)"
  export ORIG_PATH="$PATH"
  export PATH="${SHIM_DIR}:${FAKE_GH_DIR}:${PATH}"

  unset CLAUDE_SESSION_ID 2>/dev/null || true
}

teardown() {
  rm -rf "$FAKE_GH_DIR"
  export PATH="$ORIG_PATH"
}

# Helper to run the shim and capture both stdout and stderr
run_shim() {
  run bash -c '"$0" "$@" 2>&1' "$SHIM" "$@"
}

assert_passthrough() {
  if [[ $status -ne 0 ]]; then
    echo "Expected exit 0 (passthrough), got exit $status"
    echo "Output: $output"
    return 1
  fi
  if [[ "$output" != *"REAL_GH_CALLED"* ]]; then
    echo "Expected passthrough to real gh"
    echo "Output: $output"
    return 1
  fi
}

assert_blocked() {
  if [[ $status -ne 1 ]]; then
    echo "Expected exit 1 (blocked), got exit $status"
    echo "Output: $output"
    return 1
  fi
  if [[ "$output" != *"ERROR"* ]]; then
    echo "Expected ERROR in output"
    echo "Output: $output"
    return 1
  fi
}

# =============================================================================
# Passthrough tests
# =============================================================================

@test "shim: passes through bare gh (no arguments)" {
  run_shim
  assert_passthrough
}

@test "shim: passes through gh pr list" {
  run_shim pr list
  assert_passthrough
}

@test "shim: passes through gh issue view" {
  run_shim issue view 123
  assert_passthrough
}

@test "shim: passes through gh api repos/.../releases" {
  run_shim api repos/owner/repo/releases/latest
  assert_passthrough
}

@test "shim: passes through gh repo view" {
  run_shim repo view owner/repo
  assert_passthrough
}

@test "shim: passes through gh api repos/.../pulls" {
  run_shim api repos/owner/repo/pulls
  assert_passthrough
}

@test "shim: passes through gh api repos/.../commits" {
  run_shim api repos/owner/repo/commits
  assert_passthrough
}

@test "shim: passes through gh api repos/.../issues" {
  run_shim api repos/owner/repo/issues
  assert_passthrough
}

# =============================================================================
# API contents deny tests
# =============================================================================

@test "shim: blocks gh api repos/.../contents/file.txt" {
  run_shim api repos/owner/repo/contents/file.txt --jq '.content'
  assert_blocked
}

@test "shim: blocks gh api repos/.../contents/ with jq name filter" {
  run_shim api repos/owner/repo/contents/src --jq '.[].name'
  assert_blocked
}

@test "shim: blocks gh api repos/.../contents/ with raw accept header" {
  run_shim api repos/owner/repo/contents/file.md -H "Accept: application/vnd.github.raw+json"
  assert_blocked
}

@test "shim: blocks gh api repos/.../contents/ regardless of arg order" {
  run_shim api --jq '.content' repos/owner/repo/contents/file.txt
  assert_blocked
}

@test "shim: blocks gh api contents with --paginate" {
  run_shim api repos/owner/repo/contents/src --paginate --jq '.[].name'
  assert_blocked
}

@test "shim: blocks gh api contents for deep paths" {
  run_shim api repos/apple/container/contents/Sources/Services/main.swift
  assert_blocked
}

@test "shim: blocks gh api contents with query parameters" {
  run_shim api "repos/owner/repo/contents/file.py?ref=develop"
  assert_blocked
}

# =============================================================================
# API contents allow tests (non-contents endpoints pass through)
# =============================================================================

@test "shim: allows gh api repos/.../releases" {
  run_shim api repos/owner/repo/releases
  assert_passthrough
}

@test "shim: allows gh api repos/.../pulls with jq" {
  run_shim api repos/owner/repo/pulls --jq '.[].title'
  assert_passthrough
}

@test "shim: allows gh api rate_limit" {
  run_shim api rate_limit
  assert_passthrough
}

@test "shim: allows gh api graphql" {
  run_shim api graphql -f query='{ viewer { login } }'
  assert_passthrough
}

# =============================================================================
# Clone path deny tests
# =============================================================================

@test "shim: blocks clone to /tmp/repos/r" {
  run_shim repo clone owner/repo /tmp/repos/repo
  assert_blocked
}

@test "shim: blocks clone to /tmp/claude/gh-clones/r" {
  run_shim repo clone owner/repo /tmp/claude/gh-clones/repo
  assert_blocked
}

@test "shim: blocks clone to /var/folders/.../r" {
  run_shim repo clone owner/repo /var/folders/xx/yy/T/gh-clones/repo
  assert_blocked
}

@test "shim: blocks clone to /private/tmp/r" {
  run_shim repo clone owner/repo /private/tmp/repos/repo
  assert_blocked
}

@test "shim: blocks clone to /tmp/ without CLAUDE_SESSION_ID" {
  unset CLAUDE_SESSION_ID 2>/dev/null || true
  run_shim repo clone owner/repo /tmp/gh-clones-someid/repo
  assert_blocked
}

@test "shim: blocks clone with wrong session ID in path" {
  export CLAUDE_SESSION_ID="correct-session"
  run_shim repo clone owner/repo /tmp/gh-clones-wrong-session/repo
  assert_blocked
}

@test "shim: blocks clone to /tmp/ even when short flags precede the target path" {
  run_shim repo clone -u upstream owner/repo /tmp/repos/repo
  assert_blocked
}

@test "shim: blocks clone to /tmp/ even when long flags precede the target path" {
  run_shim repo clone --upstream-remote-name upstream owner/repo /tmp/repos/repo
  assert_blocked
}

# =============================================================================
# Clone path allow tests
# =============================================================================

@test "shim: allows clone without target dir" {
  run_shim repo clone owner/repo
  assert_passthrough
}

@test "shim: allows clone to relative path" {
  run_shim repo clone owner/repo ./local-clone
  assert_passthrough
}

@test "shim: allows clone to home directory" {
  run_shim repo clone owner/repo ~/projects/repo
  assert_passthrough
}

@test "shim: allows clone with only git flags" {
  run_shim repo clone owner/repo -- --depth 1
  assert_passthrough
}

@test "shim: allows clone to session-scoped temp path" {
  export CLAUDE_SESSION_ID="test-session-abc"
  run_shim repo clone owner/repo /tmp/gh-clones-test-session-abc/repo
  assert_passthrough
}

@test "shim: allows canonical clone pattern from docs (session path + -- --depth 1)" {
  export CLAUDE_SESSION_ID="test-session-abc"
  run_shim repo clone owner/repo /tmp/gh-clones-test-session-abc/repo -- --depth 1
  assert_passthrough
}

@test "shim: allows clone to absolute non-temp path" {
  run_shim repo clone owner/repo /home/user/repos/repo
  assert_passthrough
}

@test "shim: allows clone to path containing tmp but not starting with /tmp/" {
  run_shim repo clone owner/repo /home/user/tmp/repo
  assert_passthrough
}

@test "shim: allows clone to session-scoped /var/folders/ path" {
  export CLAUDE_SESSION_ID="test-session-abc"
  run_shim repo clone owner/repo /var/folders/xx/yy/T/gh-clones-test-session-abc/repo
  assert_passthrough
}

# =============================================================================
# Suggestion quality
# =============================================================================

@test "shim: api contents deny suggests clone" {
  run_shim api repos/owner/repo/contents/file.txt
  assert_blocked
  [[ "$output" == *"gh repo clone owner/repo"* ]]
}

@test "shim: api contents deny suggests session-scoped path" {
  run_shim api repos/owner/repo/contents/file.txt
  assert_blocked
  [[ "$output" == *"CLAUDE_SESSION_ID"* ]]
}

@test "shim: api contents deny suggests --depth 1" {
  run_shim api repos/owner/repo/contents/file.txt
  assert_blocked
  [[ "$output" == *"--depth 1"* ]]
}

@test "shim: api contents deny extracts correct owner/repo" {
  run_shim api repos/apple/container/contents/Sources/main.swift
  assert_blocked
  [[ "$output" == *"gh repo clone apple/container"* ]]
}

@test "shim: clone deny suggests CLAUDE_SESSION_ID" {
  run_shim repo clone owner/repo /tmp/gh-clones/repo
  assert_blocked
  [[ "$output" == *"CLAUDE_SESSION_ID"* ]]
}

@test "shim: clone deny warns against invented paths" {
  run_shim repo clone owner/repo /tmp/gh-clones/repo
  assert_blocked
  [[ "$output" == *"Do NOT invent paths"* ]]
}

# =============================================================================
# Real gh not found
# =============================================================================

@test "shim: exits 127 when real gh not found" {
  # Build PATH without any gh binary (skip fake gh dir and dirs with real gh)
  local path_without_gh=""
  local IFS=:
  for dir in $ORIG_PATH; do
    [[ "$dir" == "$FAKE_GH_DIR" ]] && continue
    [[ -x "$dir/gh" ]] && continue
    path_without_gh="${path_without_gh:+${path_without_gh}:}$dir"
  done
  export PATH="${SHIM_DIR}:${path_without_gh}"
  run -127 bash -c '"$0" "$@" 2>&1' "$SHIM" pr list
}
