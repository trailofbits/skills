#!/usr/bin/env bats
# Tests for intercept-gh-clone-path.sh hook

load test_helper

# =============================================================================
# Early Exit Tests
# =============================================================================

@test "clone-path: exits silently on invalid JSON input" {
  run bash -c 'echo "not json" | '"'$CLONE_HOOK'"
  assert_allow
}

@test "clone-path: exits silently on empty JSON" {
  run bash -c 'echo "{}" | '"'$CLONE_HOOK'"
  assert_allow
}

@test "clone-path: exits silently when command is empty string" {
  run bash -c 'echo "{\"tool_input\":{\"command\":\"\"}}" | '"'$CLONE_HOOK'"
  assert_allow
}

@test "clone-path: exits silently when command field is missing" {
  run bash -c 'echo "{\"tool_input\":{}}" | '"'$CLONE_HOOK'"
  assert_allow
}

# =============================================================================
# Allow: Non-gh commands (fast path)
# =============================================================================

@test "clone-path: allows non-gh commands" {
  run_clone_hook "ls -la"
  assert_allow
}

@test "clone-path: allows curl commands" {
  run_clone_hook "curl https://example.com"
  assert_allow
}

@test "clone-path: allows git clone (not gh)" {
  run_clone_hook "git clone https://github.com/owner/repo /tmp/repos/repo"
  assert_allow
}

# =============================================================================
# Allow: gh commands that are not repo clone
# =============================================================================

@test "clone-path: allows gh pr list" {
  run_clone_hook "gh pr list --repo owner/repo"
  assert_allow
}

@test "clone-path: allows gh api" {
  run_clone_hook "gh api repos/owner/repo"
  assert_allow
}

@test "clone-path: allows gh issue view" {
  run_clone_hook "gh issue view 123"
  assert_allow
}

@test "clone-path: allows gh repo view (not clone)" {
  run_clone_hook "gh repo view owner/repo"
  assert_allow
}

@test "clone-path: allows gh release download" {
  run_clone_hook "gh release download --repo owner/repo"
  assert_allow
}

# =============================================================================
# Allow: gh repo clone without target dir or to non-temp paths
# =============================================================================

@test "clone-path: allows clone without target dir" {
  run_clone_hook "gh repo clone owner/repo"
  assert_allow
}

@test "clone-path: allows clone with only git flags" {
  run_clone_hook "gh repo clone owner/repo -- --depth 1"
  assert_allow
}

@test "clone-path: allows clone to current-relative dir" {
  run_clone_hook "gh repo clone owner/repo ./local-clone"
  assert_allow
}

@test "clone-path: allows clone to home directory" {
  run_clone_hook "gh repo clone owner/repo ~/projects/repo"
  assert_allow
}

@test "clone-path: allows clone to absolute non-temp path" {
  run_clone_hook "gh repo clone owner/repo /home/user/repos/repo"
  assert_allow
}

# =============================================================================
# Allow: gh repo clone with session-scoped temp path
# =============================================================================

@test "clone-path: allows clone with CLAUDE_SESSION_ID variable reference" {
  run_clone_hook 'gh repo clone owner/repo "${TMPDIR:-/tmp}/gh-clones-${CLAUDE_SESSION_ID}/repo" -- --depth 1'
  assert_allow
}

@test "clone-path: allows clone with TMPDIR and CLAUDE_SESSION_ID" {
  run_clone_hook 'gh repo clone owner/repo "$TMPDIR/gh-clones-${CLAUDE_SESSION_ID}/repo" -- --depth 1'
  assert_allow
}

@test "clone-path: allows compound command with session-scoped variable" {
  run_clone_hook 'clonedir="$TMPDIR/gh-clones-${CLAUDE_SESSION_ID}" && mkdir -p "$clonedir" && gh repo clone owner/repo "$clonedir/repo" -- --depth 1'
  assert_allow
}

@test "clone-path: allows expanded session ID in path" {
  run_clone_hook_with_session 'gh repo clone owner/repo "/tmp/gh-clones-test-session-abc/repo" -- --depth 1' "test-session-abc"
  assert_allow
}

# =============================================================================
# Deny: gh repo clone to non-session-scoped temp paths
# =============================================================================

@test "clone-path: denies clone to /tmp/claude/gh-clones/" {
  run_clone_hook "gh repo clone owner/repo /tmp/claude/gh-clones/repo"
  assert_deny
}

@test "clone-path: denies clone to /tmp/claude/gh-clones/ with git flags" {
  run_clone_hook "gh repo clone owner/repo /tmp/claude/gh-clones/repo -- --depth 1"
  assert_deny
}

@test "clone-path: denies clone to /tmp/gh-clones/" {
  run_clone_hook "gh repo clone owner/repo /tmp/gh-clones/repo"
  assert_deny
}

@test "clone-path: denies clone to /tmp/repos/" {
  run_clone_hook "gh repo clone owner/repo /tmp/repos/repo"
  assert_deny
}

@test "clone-path: denies clone to /var/folders temp path" {
  run_clone_hook "gh repo clone owner/repo /var/folders/xx/yy/T/gh-clones/repo"
  assert_deny
}

@test "clone-path: denies compound command with non-scoped temp variable" {
  run_clone_hook 'clonedir="/tmp/claude/gh-clones" && mkdir -p "$clonedir" && gh repo clone owner/repo "$clonedir/repo"'
  assert_deny
}

@test "clone-path: denies clone to TMPDIR without session ID" {
  run_clone_hook 'gh repo clone owner/repo "$TMPDIR/gh-clones/repo"'
  assert_deny
}

# =============================================================================
# Deny: suggestion quality
# =============================================================================

@test "clone-path: deny message suggests session-scoped path" {
  run_clone_hook "gh repo clone owner/repo /tmp/gh-clones/repo"
  assert_deny
  assert_suggestion_contains "CLAUDE_SESSION_ID"
}

@test "clone-path: deny message warns against invented paths" {
  run_clone_hook "gh repo clone owner/repo /tmp/gh-clones/repo"
  assert_deny
  assert_suggestion_contains "Do NOT invent paths"
}
