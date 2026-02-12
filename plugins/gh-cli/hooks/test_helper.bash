#!/usr/bin/env bash
# Test helper functions for gh-cli BATS tests
# shellcheck disable=SC2154  # status/output are BATS-provided variables
# shellcheck disable=SC2016  # Single quotes for jq filter are intentional

# Paths to the hook scripts under test
FETCH_HOOK="${BATS_TEST_DIRNAME}/intercept-github-fetch.sh"
CURL_HOOK="${BATS_TEST_DIRNAME}/intercept-github-curl.sh"

# Run the WebFetch hook with a URL
# Usage: run_fetch_hook "https://github.com/owner/repo"
run_fetch_hook() {
  local url="$1"
  run bash -c 'jq -n --arg url "$1" '"'"'{"tool_input":{"url":$url,"prompt":"test"}}'"'"' | "$2"' _ "$url" "$FETCH_HOOK"
}

# Run the Bash hook with a command
# Usage: run_curl_hook "curl https://api.github.com/..."
run_curl_hook() {
  local cmd="$1"
  run bash -c 'jq -n --arg cmd "$1" '"'"'{"tool_input":{"command":$cmd}}'"'"' | "$2"' _ "$cmd" "$CURL_HOOK"
}

# Run hook without gh available (for testing early exit)
run_fetch_hook_no_gh() {
  local url="$1"
  run env PATH=/usr/bin:/bin bash -c 'jq -n --arg url "$1" '"'"'{"tool_input":{"url":$url,"prompt":"test"}}'"'"' 2>/dev/null | "$2"' _ "$url" "$FETCH_HOOK"
}

run_curl_hook_no_gh() {
  local cmd="$1"
  run env PATH=/usr/bin:/bin bash -c 'jq -n --arg cmd "$1" '"'"'{"tool_input":{"command":$cmd}}'"'"' 2>/dev/null | "$2"' _ "$cmd" "$CURL_HOOK"
}

# Assert the hook allowed the action (exit 0, no output)
assert_allow() {
  if [[ $status -ne 0 ]]; then
    echo "Expected exit 0 (allow), got exit $status"
    echo "Output: $output"
    return 1
  fi
  if [[ -n "$output" ]]; then
    echo "Expected no output (allow), got:"
    echo "$output"
    return 1
  fi
}

# Assert the hook denied the action (JSON output with deny decision)
assert_deny() {
  if [[ $status -ne 0 ]]; then
    echo "Expected exit 0 with deny JSON, got exit $status"
    echo "Output: $output"
    return 1
  fi
  if [[ -z "$output" ]]; then
    echo "Expected deny JSON output, got empty"
    return 1
  fi
  if ! echo "$output" | jq -e '.hookSpecificOutput.permissionDecision == "deny"' >/dev/null 2>&1; then
    echo "Expected permissionDecision: deny"
    echo "Output: $output"
    return 1
  fi
}

# Assert the suggestion contains expected text
# Usage: assert_suggestion_contains "gh repo view"
assert_suggestion_contains() {
  local expected="$1"
  local reason
  reason=$(echo "$output" | jq -r '.hookSpecificOutput.permissionDecisionReason // empty' 2>/dev/null)
  if [[ -z "$reason" ]]; then
    echo "No permissionDecisionReason found in output"
    echo "Output: $output"
    return 1
  fi
  if [[ "$reason" != *"$expected"* ]]; then
    echo "Expected suggestion to contain: $expected"
    echo "Got: $reason"
    return 1
  fi
}
