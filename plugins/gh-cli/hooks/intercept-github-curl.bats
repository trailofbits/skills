#!/usr/bin/env bats
# Tests for intercept-github-curl.sh hook

load test_helper

# =============================================================================
# Early Exit Tests
# =============================================================================

@test "curl: exits silently when gh is not available" {
  run_curl_hook_no_gh "curl https://api.github.com/repos/owner/repo"
  assert_allow
}

@test "curl: exits silently on invalid JSON input" {
  run bash -c 'echo "not json" | '"'$CURL_HOOK'"
  assert_allow
}

@test "curl: exits silently on empty JSON" {
  run bash -c 'echo "{}" | '"'$CURL_HOOK'"
  assert_allow
}

@test "curl: exits silently when command is empty string" {
  run bash -c 'echo "{\"tool_input\":{\"command\":\"\"}}" | '"'$CURL_HOOK'"
  assert_allow
}

@test "curl: exits silently when command field is missing" {
  run bash -c 'echo "{\"tool_input\":{}}" | '"'$CURL_HOOK'"
  assert_allow
}

# =============================================================================
# Allow: Already using gh CLI
# =============================================================================

@test "curl: allows gh pr list" {
  run_curl_hook "gh pr list --repo owner/repo"
  assert_allow
}

@test "curl: allows gh api" {
  run_curl_hook "gh api repos/owner/repo/releases/latest"
  assert_allow
}

@test "curl: allows gh issue view" {
  run_curl_hook "gh issue view 123 --repo owner/repo"
  assert_allow
}

@test "curl: allows gh repo view" {
  run_curl_hook "gh repo view owner/repo"
  assert_allow
}

# =============================================================================
# Allow: git commands
# =============================================================================

@test "curl: allows git clone with github URL" {
  run_curl_hook "git clone git@github.com:owner/repo.git"
  assert_allow
}

@test "curl: allows git clone https" {
  run_curl_hook "git clone https://github.com/owner/repo.git"
  assert_allow
}

@test "curl: allows git remote add" {
  run_curl_hook "git remote add origin git@github.com:owner/repo.git"
  assert_allow
}

@test "curl: allows git push" {
  run_curl_hook "git push origin main"
  assert_allow
}

# =============================================================================
# Allow: Non-curl/wget commands
# =============================================================================

@test "curl: allows grep mentioning github" {
  run_curl_hook "grep github.com README.md"
  assert_allow
}

@test "curl: allows echo with github URL" {
  run_curl_hook 'echo "Visit https://github.com/owner/repo for more info"'
  assert_allow
}

@test "curl: allows ls command" {
  run_curl_hook "ls -la"
  assert_allow
}

@test "curl: allows python command" {
  run_curl_hook "uv run python3 script.py"
  assert_allow
}

# =============================================================================
# Allow: Non-GitHub curl/wget
# =============================================================================

@test "curl: allows curl to non-GitHub URL" {
  run_curl_hook "curl https://example.com/api/data"
  assert_allow
}

@test "curl: allows curl to pypi" {
  run_curl_hook "curl https://pypi.org/pypi/requests/json"
  assert_allow
}

@test "curl: allows wget to non-GitHub URL" {
  run_curl_hook "wget https://example.com/file.tar.gz"
  assert_allow
}

@test "curl: allows curl to localhost" {
  run_curl_hook "curl http://localhost:8080/api/health"
  assert_allow
}

# =============================================================================
# Deny: curl to GitHub API
# =============================================================================

@test "curl: denies curl to api.github.com releases" {
  run_curl_hook 'curl -s "https://api.github.com/repos/astral-sh/python-build-standalone/releases/latest" | head -200'
  assert_deny
  assert_suggestion_contains "gh release list --repo astral-sh/python-build-standalone"
}

@test "curl: denies curl to api.github.com pulls" {
  run_curl_hook 'curl -H "Authorization: token ghp_xxx" https://api.github.com/repos/owner/repo/pulls'
  assert_deny
  assert_suggestion_contains "gh pr list --repo owner/repo"
}

@test "curl: denies curl to api.github.com issues" {
  run_curl_hook "curl https://api.github.com/repos/owner/repo/issues"
  assert_deny
  assert_suggestion_contains "gh issue list --repo owner/repo"
}

@test "curl: denies curl to generic api.github.com endpoint" {
  run_curl_hook "curl https://api.github.com/repos/owner/repo/commits"
  assert_deny
  assert_suggestion_contains "gh api"
}

# =============================================================================
# Deny: curl/wget to github.com
# =============================================================================

@test "curl: denies wget to github.com archive" {
  run_curl_hook "wget https://github.com/owner/repo/archive/refs/tags/v1.0.tar.gz"
  assert_deny
  assert_suggestion_contains "gh release download --repo owner/repo"
}

@test "curl: denies curl to raw.githubusercontent.com with clone suggestion" {
  run_curl_hook "curl https://raw.githubusercontent.com/owner/repo/main/README.md"
  assert_deny
  assert_suggestion_contains "gh repo clone owner/repo"
}

@test "curl: denies curl to gist.github.com" {
  run_curl_hook "curl https://gist.github.com/user/abc123"
  assert_deny
  assert_suggestion_contains "gh gist view"
}

# =============================================================================
# Deny: piped curl commands
# =============================================================================

@test "curl: denies curl piped to head" {
  run_curl_hook 'curl -s https://api.github.com/repos/owner/repo/releases | head -50'
  assert_deny
}

@test "curl: denies curl piped to jq" {
  run_curl_hook 'curl -s https://api.github.com/repos/owner/repo/releases | jq ".[0].tag_name"'
  assert_deny
}

# =============================================================================
# Deny: curl with various flags
# =============================================================================

@test "curl: denies curl with -s flag" {
  run_curl_hook "curl -s https://api.github.com/repos/owner/repo"
  assert_deny
}

@test "curl: denies curl with -L flag" {
  run_curl_hook "curl -L https://github.com/owner/repo/releases/download/v1.0/binary"
  assert_deny
}

@test "curl: denies curl with multiple flags" {
  run_curl_hook 'curl -sL -H "Accept: application/json" https://api.github.com/repos/owner/repo'
  assert_deny
}

# =============================================================================
# Suggestion quality
# =============================================================================

@test "curl: deny message mentions authenticated token" {
  run_curl_hook "curl https://api.github.com/repos/owner/repo"
  assert_deny
  assert_suggestion_contains "authenticated GitHub token"
}

@test "curl: deny message mentions private repos" {
  run_curl_hook "curl https://api.github.com/repos/owner/repo"
  assert_deny
  assert_suggestion_contains "private repos"
}

# =============================================================================
# Deny: compound commands containing curl to GitHub
# =============================================================================

@test "curl: denies curl to github.com even when gh appears later in compound command" {
  run_curl_hook "curl https://api.github.com/repos/owner/repo/contents/f && gh version"
  assert_deny
}

@test "curl: denies curl to github.com even when git appears later in compound command" {
  run_curl_hook "curl https://raw.githubusercontent.com/o/r/main/f ; git status"
  assert_deny
}

# =============================================================================
# Anti-pattern warning: gh api .../contents/ fallback
# =============================================================================

@test "curl: api.github.com/repos/.../contents/ suggests clone instead of gh api" {
  run_curl_hook "curl https://api.github.com/repos/owner/repo/contents/README.md"
  assert_deny
  assert_suggestion_contains "gh repo clone"
  assert_suggestion_contains "Do NOT use"
  assert_suggestion_contains "base64-decode file contents"
}

@test "curl: raw.githubusercontent.com denial warns against gh api contents fallback" {
  run_curl_hook "curl https://raw.githubusercontent.com/owner/repo/main/README.md"
  assert_deny
  assert_suggestion_contains "Do NOT use"
  assert_suggestion_contains "base64-decode file contents"
}

# =============================================================================
# Heredoc bodies are file content, not commands (#333)
# =============================================================================
#
# The hook matched its two regexes against the whole tool_input.command, so
# writing a workflow file whose *content* mentions curl and a GitHub URL was
# denied even though the command never fetches anything.

@test "curl: allows a quoted heredoc whose body mentions curl and a GitHub URL" {
  run_curl_hook "cat > .github/workflows/scan.yml <<'EOF'
      - run: curl -sSfL https://github.com/aquasecurity/trivy/releases/download/v0.50.0/trivy.tar.gz | tar xz
EOF"
  assert_allow
}

@test "curl: allows an unquoted heredoc whose body mentions curl and a GitHub URL" {
  run_curl_hook "cat > /tmp/notes.md <<EOF
see curl https://github.com/owner/repo/archive/main.tar.gz for the tarball
EOF"
  assert_allow
}

@test "curl: allows a tab-stripped heredoc whose body mentions curl and a GitHub URL" {
  run_curl_hook "cat > /tmp/f <<-EOF
	curl https://github.com/owner/repo/archive/main.tar.gz
	EOF"
  assert_allow
}

@test "curl: allows a heredoc body mentioning wget to api.github.com" {
  run_curl_hook "cat > /tmp/f.sh <<'EOF'
wget https://api.github.com/repos/owner/repo/pulls
EOF"
  assert_allow
}

# The fix must not become an escape hatch: a real fetch after the body ends is
# still a real fetch.

@test "curl: still denies a real curl after a heredoc body ends" {
  run_curl_hook "cat > /tmp/f <<'EOF'
curl https://github.com/owner/repo/archive/main.tar.gz
EOF
curl -sSfL https://api.github.com/repos/owner/repo/pulls"
  assert_deny
}

@test "curl: still denies a real wget after a heredoc body ends" {
  run_curl_hook "cat <<EOF > /tmp/x
nothing to see https://github.com/owner/repo
EOF
wget https://github.com/owner/repo/archive/t.zip"
  assert_deny
}

@test "curl: still denies curl on the same line as the heredoc opener" {
  run_curl_hook "curl -sSfL https://github.com/owner/repo/archive/main.tar.gz | tee /tmp/f"
  assert_deny
}
