#!/usr/bin/env bats
# Tests for the PreToolUse matchers in hooks.json.
#
# The hook scripts are well covered, but nothing exercised the matcher that
# decides whether they run at all — so a matcher that fires on nothing would
# still pass every other suite in this directory. These tests read the matcher
# out of hooks.json and check it against real tool names.
#
# Claude Code evaluates a matcher containing regex metacharacters as an
# unanchored JavaScript regular expression. `grep -E` is likewise unanchored,
# and these patterns use only constructs common to both.

setup() {
  HOOKS_JSON="${BATS_TEST_DIRNAME}/hooks.json"
  FETCH_MATCHER=$(jq -r '.hooks.PreToolUse[]
    | select(.hooks[].command | contains("intercept-github-fetch.sh"))
    | .matcher' "$HOOKS_JSON")
  BASH_MATCHER=$(jq -r '.hooks.PreToolUse[]
    | select(.hooks[].command | contains("intercept-github-curl.sh"))
    | .matcher' "$HOOKS_JSON")
}

# A matcher that failed to parse would be empty, and an empty pattern matches
# every tool name — which would make every assertion below pass vacuously.
assert_matcher_nonempty() {
  if [[ -z "$1" ]]; then
    echo "Matcher not found in $HOOKS_JSON — every match assertion would pass vacuously"
    return 1
  fi
}

assert_matches() {
  local pattern="$1" tool="$2"
  assert_matcher_nonempty "$pattern" || return 1
  if ! printf '%s\n' "$tool" | grep -Eq "$pattern"; then
    echo "Expected matcher '$pattern' to match tool '$tool'"
    return 1
  fi
}

refute_matches() {
  local pattern="$1" tool="$2"
  assert_matcher_nonempty "$pattern" || return 1
  if printf '%s\n' "$tool" | grep -Eq "$pattern"; then
    echo "Expected matcher '$pattern' NOT to match tool '$tool'"
    return 1
  fi
}

# =============================================================================
# The matchers are present at all
# =============================================================================

@test "matcher: hooks.json is valid JSON" {
  run jq -e . "$HOOKS_JSON"
  [[ $status -eq 0 ]]
}

@test "matcher: fetch hook has a matcher" {
  assert_matcher_nonempty "$FETCH_MATCHER"
}

@test "matcher: bash hook has a matcher" {
  assert_matcher_nonempty "$BASH_MATCHER"
}

# =============================================================================
# Built-in tools
# =============================================================================

@test "matcher: fetch matcher matches WebFetch" {
  assert_matches "$FETCH_MATCHER" "WebFetch"
}

@test "matcher: bash matcher matches Bash" {
  assert_matches "$BASH_MATCHER" "Bash"
}

@test "matcher: fetch matcher does not match Bash" {
  refute_matches "$FETCH_MATCHER" "Bash"
}

@test "matcher: fetch matcher does not match Read" {
  refute_matches "$FETCH_MATCHER" "Read"
}

@test "matcher: fetch matcher does not match WebSearch" {
  refute_matches "$FETCH_MATCHER" "WebSearch"
}

# =============================================================================
# MCP tools that retrieve a URL — these are the ones the hook exists for
# =============================================================================

@test "matcher: fetch matcher matches Exa web_fetch_exa" {
  assert_matches "$FETCH_MATCHER" "mcp__exa__web_fetch_exa"
}

@test "matcher: fetch matcher matches a bare fetch server" {
  assert_matches "$FETCH_MATCHER" "mcp__fetch__fetch"
}

@test "matcher: fetch matcher matches Firecrawl scrape" {
  assert_matches "$FETCH_MATCHER" "mcp__firecrawl__firecrawl_scrape"
}

@test "matcher: fetch matcher matches Firecrawl batch scrape" {
  assert_matches "$FETCH_MATCHER" "mcp__firecrawl__firecrawl_batch_scrape"
}

@test "matcher: fetch matcher matches a crawl tool" {
  assert_matches "$FETCH_MATCHER" "mcp__exa__crawling_exa"
}

@test "matcher: fetch matcher matches Tavily extract" {
  assert_matches "$FETCH_MATCHER" "mcp__tavily__tavily_extract"
}

# =============================================================================
# MCP tools that do not retrieve a URL — no reason to run the hook
# =============================================================================

@test "matcher: fetch matcher does not match Exa search" {
  refute_matches "$FETCH_MATCHER" "mcp__exa__web_search_exa"
}

@test "matcher: fetch matcher does not match context7 docs query" {
  refute_matches "$FETCH_MATCHER" "mcp__context7__query-docs"
}

@test "matcher: fetch matcher does not match a Slack reader" {
  refute_matches "$FETCH_MATCHER" "mcp__slack__slack_read_channel"
}
