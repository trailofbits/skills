#!/usr/bin/env bats
# Tests for intercept-gh-api-contents.sh hook

load test_helper

# =============================================================================
# Early Exit Tests
# =============================================================================

@test "api-contents: exits silently on invalid JSON input" {
  run bash -c 'echo "not json" | '"'$API_CONTENTS_HOOK'"
  assert_allow
}

@test "api-contents: exits silently on empty JSON" {
  run bash -c 'echo "{}" | '"'$API_CONTENTS_HOOK'"
  assert_allow
}

@test "api-contents: exits silently when command is empty string" {
  run bash -c 'echo "{\"tool_input\":{\"command\":\"\"}}" | '"'$API_CONTENTS_HOOK'"
  assert_allow
}

@test "api-contents: exits silently when command field is missing" {
  run bash -c 'echo "{\"tool_input\":{}}" | '"'$API_CONTENTS_HOOK'"
  assert_allow
}

# =============================================================================
# Allow: Non-gh commands
# =============================================================================

@test "api-contents: allows non-gh commands" {
  run_api_contents_hook "ls -la"
  assert_allow
}

@test "api-contents: allows curl commands" {
  run_api_contents_hook "curl https://api.github.com/repos/owner/repo/contents/README.md"
  assert_allow
}

@test "api-contents: allows git commands" {
  run_api_contents_hook "git clone https://github.com/owner/repo.git"
  assert_allow
}

# =============================================================================
# Allow: gh commands that are not gh api
# =============================================================================

@test "api-contents: allows gh pr list" {
  run_api_contents_hook "gh pr list --repo owner/repo"
  assert_allow
}

@test "api-contents: allows gh repo clone" {
  run_api_contents_hook "gh repo clone owner/repo /tmp/foo"
  assert_allow
}

@test "api-contents: allows gh repo view" {
  run_api_contents_hook "gh repo view owner/repo"
  assert_allow
}

# =============================================================================
# Allow: gh api without /contents/ endpoint
# =============================================================================

@test "api-contents: allows gh api to releases endpoint" {
  run_api_contents_hook "gh api repos/owner/repo/releases/latest"
  assert_allow
}

@test "api-contents: allows gh api to pulls endpoint" {
  run_api_contents_hook "gh api repos/owner/repo/pulls --jq '.[].title'"
  assert_allow
}

@test "api-contents: allows gh api to commits endpoint" {
  run_api_contents_hook "gh api repos/owner/repo/commits"
  assert_allow
}

@test "api-contents: allows gh api to issues endpoint" {
  run_api_contents_hook "gh api repos/owner/repo/issues"
  assert_allow
}

# =============================================================================
# Allow: gh api /contents/ without base64 decoding (metadata/listing)
# =============================================================================

@test "api-contents: allows gh api contents without base64 (directory listing)" {
  run_api_contents_hook "gh api repos/owner/repo/contents/src"
  assert_allow
}

@test "api-contents: allows gh api contents with jq but no base64" {
  run_api_contents_hook "gh api repos/owner/repo/contents/src --jq '.[].name'"
  assert_allow
}

@test "api-contents: allows gh api contents for file metadata" {
  run_api_contents_hook "gh api repos/owner/repo/contents/README.md --jq '.sha'"
  assert_allow
}

# =============================================================================
# Deny: gh api /contents/ with base64 decoding
# =============================================================================

@test "api-contents: denies gh api contents piped to base64 -d" {
  run_api_contents_hook "gh api repos/owner/repo/contents/README.md --jq '.content' | base64 -d"
  assert_deny
}

@test "api-contents: denies gh api contents piped to base64 --decode" {
  run_api_contents_hook "gh api repos/owner/repo/contents/src/main.py --jq '.content' | base64 --decode"
  assert_deny
}

@test "api-contents: denies gh api contents with base64 -D (macOS uppercase)" {
  run_api_contents_hook "gh api repos/owner/repo/contents/file.txt --jq '.content' | base64 -D"
  assert_deny
}

@test "api-contents: denies the exact pattern from the issue" {
  run_api_contents_hook "gh api repos/apple/container/contents/Sources/Services/ContainerSandboxService/Server/SandboxService.swift --jq '.content' 2>&1 | base64 -d 2>&1 | grep -B 5 -A 20 'sandbox'"
  assert_deny
}

@test "api-contents: denies gh api contents with stderr redirect and base64" {
  run_api_contents_hook "gh api repos/owner/repo/contents/deep/path/file.rs --jq '.content' 2>/dev/null | base64 -d"
  assert_deny
}

@test "api-contents: denies compound command with gh api contents and base64" {
  run_api_contents_hook "gh api repos/owner/repo/contents/config.yaml --jq '.content' | base64 -d > /tmp/config.yaml"
  assert_deny
}

# =============================================================================
# Deny: suggestion quality
# =============================================================================

@test "api-contents: deny message suggests gh repo clone" {
  run_api_contents_hook "gh api repos/owner/repo/contents/file.txt --jq '.content' | base64 -d"
  assert_deny
  assert_suggestion_contains "gh repo clone owner/repo"
}

@test "api-contents: deny message includes session-scoped path" {
  run_api_contents_hook "gh api repos/owner/repo/contents/file.txt --jq '.content' | base64 -d"
  assert_deny
  assert_suggestion_contains "CLAUDE_SESSION_ID"
}

@test "api-contents: deny message includes shallow clone flag" {
  run_api_contents_hook "gh api repos/owner/repo/contents/file.txt --jq '.content' | base64 -d"
  assert_deny
  assert_suggestion_contains "--depth 1"
}

@test "api-contents: deny message extracts correct owner/repo" {
  run_api_contents_hook "gh api repos/apple/container/contents/Sources/main.swift --jq '.content' | base64 -d"
  assert_deny
  assert_suggestion_contains "gh repo clone apple/container"
}
