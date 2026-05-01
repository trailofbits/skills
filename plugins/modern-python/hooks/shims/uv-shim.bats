#!/usr/bin/env bats
# Tests for uv PATH shim
# Requires: nix shell nixpkgs#uv -c bats ...

SHIM="${BATS_TEST_DIRNAME}/uv"

setup() {
  command -v uv &>/dev/null || skip "uv not available — run via: nix shell nixpkgs#uv -c bats ..."
}

@test "exits non-zero for uv pip install" {
  run "$SHIM" pip install requests
  [[ $status -ne 0 ]]
  [[ "$output" == *"uv add"* ]]
}

@test "exits non-zero for uv pip sync" {
  run "$SHIM" pip sync
  [[ $status -ne 0 ]]
  [[ "$output" == *"uv sync"* ]]
}

@test "exits non-zero for uv pip freeze" {
  run "$SHIM" pip freeze
  [[ $status -ne 0 ]]
  [[ "$output" == *"legacy"* ]]
}

@test "suggests uv remove for uv pip uninstall" {
  run "$SHIM" pip uninstall foo
  [[ $status -ne 0 ]]
  [[ "$output" == *"uv remove"* ]]
}

@test "passes through to real uv for non-pip subcommands" {
  run "$SHIM" --version
  [[ $status -eq 0 ]]
  [[ "$output" == *"uv"* ]]
}

@test "exits 127 with error when real uv is not found" {
  # Include /usr/bin for coreutils but exclude dirs with a real uv
  local path_no_uv="${BATS_TEST_DIRNAME}:/usr/bin:/bin"
  run env PATH="$path_no_uv" "$SHIM" --version
  [[ $status -eq 127 ]]
  [[ "$output" == *"real uv binary not found"* ]]
}
