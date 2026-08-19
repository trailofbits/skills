#!/usr/bin/env bats
# Tests for uv PATH shim
# Requires: nix shell nixpkgs#uv -c bats ...

bats_require_minimum_version 1.5.0

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

# `uv pip` carrying one of these is a tool building an environment it owns, not a person
# managing project dependencies — `uv add` is not the advice it needs. prek installs
# every hook this way, and refusing it broke `git commit` in any repo whose hooks need a
# Python environment. See #207.
@test "allows uv pip when --directory says a tool owns the environment" {
  run "$SHIM" pip list --directory /tmp
  [[ "$output" != *"legacy interface"* ]]
}

@test "allows uv pip when --project says a tool owns the environment" {
  run "$SHIM" pip install --project / --help
  [[ "$output" != *"legacy interface"* ]]
}

@test "allows uv pip when --target says a tool owns the environment" {
  run "$SHIM" pip install --target /tmp/nowhere --help
  [[ "$output" != *"legacy interface"* ]]
}

# `uv pip install --help` documents `-t, --target <TARGET>`, so the short form has to be
# exempt too — otherwise the same install is allowed or refused depending on spelling.
@test "allows uv pip when the short -t names the target" {
  run "$SHIM" pip install -t /tmp/nowhere --help
  [[ "$output" != *"legacy interface"* ]]
}

@test "exits 127 with error when real uv is not found" {
  # Include /usr/bin for coreutils but exclude dirs with a real uv.
  # `run -127` declares the expected status, which is what this asserts; without it
  # bats warns (BW01) that a 127 looks like a command that was not found by accident.
  local path_no_uv="${BATS_TEST_DIRNAME}:/usr/bin:/bin"
  run -127 env PATH="$path_no_uv" "$SHIM" --version
  [[ "$output" == *"real uv binary not found"* ]]
}
