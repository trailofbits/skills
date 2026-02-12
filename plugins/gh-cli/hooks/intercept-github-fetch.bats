#!/usr/bin/env bats
# Tests for intercept-github-fetch.sh hook

load test_helper

# =============================================================================
# Early Exit Tests
# =============================================================================

@test "fetch: exits silently when gh is not available" {
  run_fetch_hook_no_gh "https://github.com/owner/repo"
  assert_allow
}

@test "fetch: exits silently on invalid JSON input" {
  run bash -c 'echo "not json" | '"'$FETCH_HOOK'"
  assert_allow
}

@test "fetch: exits silently on empty JSON" {
  run bash -c 'echo "{}" | '"'$FETCH_HOOK'"
  assert_allow
}

@test "fetch: exits silently when url is empty string" {
  run bash -c 'echo "{\"tool_input\":{\"url\":\"\"}}" | '"'$FETCH_HOOK'"
  assert_allow
}

@test "fetch: exits silently when url field is missing" {
  run bash -c 'echo "{\"tool_input\":{}}" | '"'$FETCH_HOOK'"
  assert_allow
}

# =============================================================================
# Allow: Non-GitHub URLs
# =============================================================================

@test "fetch: allows non-GitHub URLs" {
  run_fetch_hook "https://docs.anthropic.com/en/docs/claude-code/plugins"
  assert_allow
}

@test "fetch: allows github.io URLs (GitHub Pages)" {
  run_fetch_hook "https://tree-sitter.github.io/tree-sitter/"
  assert_allow
}

@test "fetch: allows other github.io subdomains" {
  run_fetch_hook "https://pages.github.io/some-project/"
  assert_allow
}

@test "fetch: allows random domains" {
  run_fetch_hook "https://dev.to/some-article"
  assert_allow
}

@test "fetch: allows pypi.org" {
  run_fetch_hook "https://pypi.org/project/requests/"
  assert_allow
}

@test "fetch: allows stackoverflow" {
  run_fetch_hook "https://stackoverflow.com/questions/12345"
  assert_allow
}

# =============================================================================
# Deny: github.com
# =============================================================================

@test "fetch: denies github.com repo page" {
  run_fetch_hook "https://github.com/j178/prek"
  assert_deny
  assert_suggestion_contains "gh repo view j178/prek"
}

@test "fetch: denies github.com action repo page" {
  run_fetch_hook "https://github.com/actions/create-github-app-token"
  assert_deny
  assert_suggestion_contains "gh repo view actions/create-github-app-token"
}

@test "fetch: denies github.com template repo" {
  run_fetch_hook "https://github.com/trailofbits/cookiecutter-python"
  assert_deny
  assert_suggestion_contains "gh repo view trailofbits/cookiecutter-python"
}

@test "fetch: denies github.com blob URL with gh api suggestion" {
  run_fetch_hook "https://github.com/owner/repo/blob/main/src/index.js"
  assert_deny
  assert_suggestion_contains "gh api repos/owner/repo/contents"
}

# =============================================================================
# Deny: api.github.com
# =============================================================================

@test "fetch: denies api.github.com releases endpoint" {
  run_fetch_hook "https://api.github.com/repos/astral-sh/python-build-standalone/releases/latest"
  assert_deny
  assert_suggestion_contains "gh release list --repo astral-sh/python-build-standalone"
}

@test "fetch: denies api.github.com pulls endpoint" {
  run_fetch_hook "https://api.github.com/repos/owner/repo/pulls"
  assert_deny
  assert_suggestion_contains "gh pr list --repo owner/repo"
}

@test "fetch: denies api.github.com issues endpoint" {
  run_fetch_hook "https://api.github.com/repos/owner/repo/issues"
  assert_deny
  assert_suggestion_contains "gh issue list --repo owner/repo"
}

@test "fetch: denies api.github.com actions endpoint" {
  run_fetch_hook "https://api.github.com/repos/owner/repo/actions/runs"
  assert_deny
  assert_suggestion_contains "gh run list --repo owner/repo"
}

@test "fetch: denies generic api.github.com with gh api suggestion" {
  run_fetch_hook "https://api.github.com/repos/owner/repo/commits"
  assert_deny
  assert_suggestion_contains "gh api repos/owner/repo/commits"
}

# =============================================================================
# Deny: raw.githubusercontent.com
# =============================================================================

@test "fetch: denies raw.githubusercontent.com" {
  run_fetch_hook "https://raw.githubusercontent.com/astral-sh/uv/main/README.md"
  assert_deny
  assert_suggestion_contains "gh api repos/astral-sh/uv/contents/README.md"
}

@test "fetch: denies raw.githubusercontent.com nested path" {
  run_fetch_hook "https://raw.githubusercontent.com/owner/repo/main/src/lib/utils.py"
  assert_deny
  assert_suggestion_contains "gh api repos/owner/repo/contents/src/lib/utils.py"
}

# =============================================================================
# Deny: gist.github.com
# =============================================================================

@test "fetch: denies gist.github.com" {
  run_fetch_hook "https://gist.github.com/user/abc123"
  assert_deny
  assert_suggestion_contains "gh gist view"
}

# =============================================================================
# Suggestion quality
# =============================================================================

@test "fetch: deny message mentions authenticated token" {
  run_fetch_hook "https://github.com/owner/repo"
  assert_deny
  assert_suggestion_contains "authenticated GitHub token"
}

@test "fetch: deny message mentions private repos" {
  run_fetch_hook "https://github.com/owner/repo"
  assert_deny
  assert_suggestion_contains "private repos"
}
