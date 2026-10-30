#!/usr/bin/env bats
load test_helper

@test "fetch variants normalize authority, preserve case-sensitive API path" {
  for url in 'HTTPS://API.GITHUB.COM/repos/Owner/Repo/git/ref/heads/FeatureABC' 'https://api.github.com:443/repos/Owner/Repo/git/ref/heads/FeatureABC'; do
    run_fetch_hook "$url"
    assert_deny || return 1
    assert_suggestion_contains 'gh api repos/Owner/Repo/git/ref/heads/FeatureABC' || return 1
  done
}

@test "fetch authority variants deny GitHub and allow lookalikes" {
  for url in 'HTTPS://GITHUB.COM/Owner/Repo' 'https://GitHub.com:443/Owner/Repo'; do
    run_fetch_hook "$url"
    assert_deny || return 1
  done
  for url in 'https://github.com.example.org/Owner/Repo' 'https://github.io/Owner/Repo' 'https://github.com:443'; do
    run_fetch_hook "$url"
    assert_allow || return 1
  done
}
