#!/usr/bin/env bats
# Tests for pip/pip3 PATH shim

SHIM="${BATS_TEST_DIRNAME}/pip"

@test "exits non-zero for pip install" {
  run "$SHIM" install requests
  [[ $status -ne 0 ]]
  [[ "$output" == *"uv add"* ]]
}

@test "suggests uv run --with for one-off usage" {
  run "$SHIM" install requests
  [[ "$output" == *"uv run --with"* ]]
}

@test "exits non-zero for pip uninstall" {
  run "$SHIM" uninstall requests
  [[ $status -ne 0 ]]
  [[ "$output" == *"uv remove"* ]]
}

@test "exits non-zero for pip freeze" {
  run "$SHIM" freeze
  [[ $status -ne 0 ]]
  [[ "$output" == *"uv export"* ]]
}

@test "exits non-zero for bare pip" {
  run "$SHIM"
  [[ $status -ne 0 ]]
  [[ "$output" == *"uv"* ]]
}

@test "exits non-zero for pip show" {
  run "$SHIM" show requests
  [[ $status -ne 0 ]]
  [[ "$output" == *"uv"* ]]
}

@test "works when invoked as pip3 via symlink" {
  run "${BATS_TEST_DIRNAME}/pip3" install foo
  [[ $status -ne 0 ]]
  [[ "$output" == *"uv add"* ]]
}
