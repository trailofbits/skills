#!/usr/bin/env bats
# Tests for pipx PATH shim

SHIM="${BATS_TEST_DIRNAME}/pipx"

@test "exits non-zero for pipx install" {
  run "$SHIM" install black
  [[ $status -ne 0 ]]
  [[ "$output" == *"uv tool install"* ]]
}

@test "exits non-zero for pipx uninstall" {
  run "$SHIM" uninstall black
  [[ $status -ne 0 ]]
  [[ "$output" == *"uv tool uninstall"* ]]
}

@test "exits non-zero for pipx run" {
  run "$SHIM" run black
  [[ $status -ne 0 ]]
  [[ "$output" == *"uvx"* ]]
}

@test "exits non-zero for pipx upgrade" {
  run "$SHIM" upgrade black
  [[ $status -ne 0 ]]
  [[ "$output" == *"uv tool upgrade"* ]]
}

@test "exits non-zero for pipx inject" {
  run "$SHIM" inject black click
  [[ $status -ne 0 ]]
  [[ "$output" == *"uv tool install --with"* ]]
}

@test "exits non-zero for pipx list" {
  run "$SHIM" list
  [[ $status -ne 0 ]]
  [[ "$output" == *"uv tool list"* ]]
}

@test "exits non-zero for pipx upgrade-all" {
  run "$SHIM" upgrade-all
  [[ $status -ne 0 ]]
  [[ "$output" == *"uv tool upgrade --all"* ]]
}

@test "exits non-zero for pipx ensurepath" {
  run "$SHIM" ensurepath
  [[ $status -ne 0 ]]
  [[ "$output" == *"uv tool update-shell"* ]]
}

@test "exits non-zero for bare pipx" {
  run "$SHIM"
  [[ $status -ne 0 ]]
  [[ "$output" == *"uv tool"* ]]
}

@test "exits non-zero for unknown pipx subcommand" {
  run "$SHIM" completions
  [[ $status -ne 0 ]]
  [[ "$output" == *"uv tool"* ]]
}
