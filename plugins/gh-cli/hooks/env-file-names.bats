#!/usr/bin/env bats

@test "persist dedupes repeated fires with a non-sh env file" {
  local env_dir env_file
  env_dir="$(mktemp -d)"
  env_file="$env_dir/session-env"
  for _ in 1 2 3; do
    run bash -c 'printf "%s\n" '\''{"session_id":"test-session"}'\'' | CLAUDE_ENV_FILE="$1" bash "$2"' _ "$env_file" "$BATS_TEST_DIRNAME/persist-session-id.sh"
    [[ $status -eq 0 ]] || return 1
  done
  local count
  count="$(wc -l <"$env_file" | tr -d ' ')"
  rm -rf "$env_dir"
  [[ "$count" -eq 1 ]]
}

@test "setup dedupes repeated fires with a non-sh env file" {
  local env_dir env_file
  env_dir="$(mktemp -d)"
  env_file="$env_dir/session-env"
  for _ in 1 2 3; do
    run env CLAUDE_ENV_FILE="$env_file" bash "$BATS_TEST_DIRNAME/setup-shims.sh"
    [[ $status -eq 0 ]] || return 1
  done
  local count
  count="$(wc -l <"$env_file" | tr -d ' ')"
  rm -rf "$env_dir"
  [[ "$count" -eq 1 ]]
}
