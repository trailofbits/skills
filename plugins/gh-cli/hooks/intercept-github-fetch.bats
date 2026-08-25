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

@test "fetch: denies github.com blob URL with clone suggestion" {
  run_fetch_hook "https://github.com/owner/repo/blob/main/src/index.js"
  assert_deny
  assert_suggestion_contains "gh repo clone owner/repo"
}

@test "fetch: denies github.com tree URL with clone suggestion" {
  run_fetch_hook "https://github.com/owner/repo/tree/main/src/lib"
  assert_deny
  assert_suggestion_contains "gh repo clone owner/repo"
}

@test "fetch: allows github.com site pages (single segment path)" {
  run_fetch_hook "https://github.com/settings"
  assert_allow
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

@test "fetch: denies raw.githubusercontent.com with clone suggestion" {
  run_fetch_hook "https://raw.githubusercontent.com/astral-sh/uv/main/README.md"
  assert_deny
  assert_suggestion_contains "gh repo clone astral-sh/uv"
}

@test "fetch: denies raw.githubusercontent.com nested path with clone suggestion" {
  run_fetch_hook "https://raw.githubusercontent.com/owner/repo/main/src/lib/utils.py"
  assert_deny
  assert_suggestion_contains "gh repo clone owner/repo"
}

@test "fetch: clone suggestion includes session-scoped path and shallow clone" {
  run_fetch_hook "https://raw.githubusercontent.com/astral-sh/uv/main/README.md"
  assert_deny
  assert_suggestion_contains "CLAUDE_SESSION_ID"
  assert_suggestion_contains "--depth 1"
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

# =============================================================================
# Anti-pattern warning: gh api .../contents/ fallback
# =============================================================================

@test "fetch: blob URL denial warns against gh api contents fallback" {
  run_fetch_hook "https://github.com/owner/repo/blob/main/src/index.js"
  assert_deny
  assert_suggestion_contains "Do NOT use"
  assert_suggestion_contains "base64-decode file contents"
}

@test "fetch: tree URL denial warns against gh api contents fallback" {
  run_fetch_hook "https://github.com/owner/repo/tree/main/src/lib"
  assert_deny
  assert_suggestion_contains "Do NOT use"
  assert_suggestion_contains "base64-decode file contents"
}

@test "fetch: api.github.com/repos/.../contents/ warns against gh api contents" {
  run_fetch_hook "https://api.github.com/repos/owner/repo/contents/README.md"
  assert_deny
  assert_suggestion_contains "gh repo clone"
  assert_suggestion_contains "Do NOT use"
  assert_suggestion_contains "base64-decode file contents"
}

@test "fetch: raw.githubusercontent.com denial warns against gh api contents fallback" {
  run_fetch_hook "https://raw.githubusercontent.com/owner/repo/main/README.md"
  assert_deny
  assert_suggestion_contains "Do NOT use"
  assert_suggestion_contains "base64-decode file contents"
}

# =============================================================================
# MCP fetch tools: `urls` array input
# =============================================================================

@test "fetch: exits silently on empty urls array" {
  run bash -c 'echo "{\"tool_input\":{\"urls\":[]}}" | '"'$FETCH_HOOK'"
  assert_allow
}

@test "fetch: allows a urls array of non-GitHub URLs" {
  run_fetch_hook_urls "https://pypi.org/project/requests/" "https://dev.to/some-article"
  assert_allow
}

@test "fetch: denies a single-element urls array" {
  run_fetch_hook_urls "https://github.com/j178/prek"
  assert_deny
  assert_suggestion_contains "gh repo view j178/prek"
}

@test "fetch: single-element urls array omits the URL prefix" {
  run_fetch_hook_urls "https://github.com/j178/prek"
  assert_deny
  assert_suggestion_starts_with "Use "
}

@test "fetch: denies a batch when only one URL is GitHub" {
  run_fetch_hook_urls "https://pypi.org/project/requests/" "https://github.com/astral-sh/uv"
  assert_deny
  assert_suggestion_contains "gh repo view astral-sh/uv"
}

@test "fetch: batched denial labels the offending URL" {
  run_fetch_hook_urls "https://pypi.org/project/requests/" "https://github.com/astral-sh/uv"
  assert_deny
  assert_suggestion_contains "https://github.com/astral-sh/uv: Use "
}

@test "fetch: batched denial reports every offending URL" {
  run_fetch_hook_urls "https://github.com/owner/repo/blob/main/x.js" "https://api.github.com/repos/owner/repo/issues"
  assert_deny
  assert_suggestion_contains "gh repo clone owner/repo"
  assert_suggestion_contains "gh issue list --repo owner/repo"
}

@test "fetch: url and urls in the same payload are both checked" {
  run bash -c 'jq -n '"'"'{"tool_input":{"url":"https://example.com","urls":["https://gist.github.com/user/abc123"]}}'"'"' | '"'$FETCH_HOOK'"
  assert_deny
  assert_suggestion_contains "gh gist view"
}

@test "fetch: checks a string-valued urls field" {
  run bash -c 'echo "{\"tool_input\":{\"urls\":\"https://github.com/owner/repo\"}}" | '"'$FETCH_HOOK'"
  assert_deny
  assert_suggestion_contains "gh repo view owner/repo"
}

@test "fetch: allows a non-GitHub string-valued urls field" {
  run bash -c 'echo "{\"tool_input\":{\"urls\":\"https://pypi.org/project/requests/\"}}" | '"'$FETCH_HOOK'"
  assert_allow
}

@test "fetch: ignores non-string entries in urls" {
  run bash -c 'jq -n '"'"'{"tool_input":{"urls":[null,42,""]}}'"'"' | '"'$FETCH_HOOK'"
  assert_allow
}
