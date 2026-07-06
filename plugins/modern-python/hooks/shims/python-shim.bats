#!/usr/bin/env bats
# Tests for python/python3 PATH shim

SHIM="${BATS_TEST_DIRNAME}/python"

@test "exits non-zero for bare python" {
  run "$SHIM"
  [[ $status -ne 0 ]]
  [[ "$output" == *"uv run python"* ]]
}

@test "exits non-zero for python script.py" {
  run "$SHIM" script.py
  [[ $status -ne 0 ]]
  [[ "$output" == *"uv run python script.py"* ]]
}

@test "exits non-zero for python -c" {
  run "$SHIM" -c 'print(1)'
  [[ $status -ne 0 ]]
  [[ "$output" == *"uv run python"* ]]
}

@test "exits non-zero for python -m pytest" {
  run "$SHIM" -m pytest
  [[ $status -ne 0 ]]
  [[ "$output" == *"uv run python -m pytest"* ]]
}

@test "exits non-zero for python -m pip install" {
  run "$SHIM" -m pip install requests
  [[ $status -ne 0 ]]
  [[ "$output" == *"uv add"* ]]
  [[ "$output" == *"uv remove"* ]]
}

@test "suggests uv run python -m <module> for arbitrary modules" {
  run "$SHIM" -m http.server
  [[ $status -ne 0 ]]
  [[ "$output" == *"uv run python -m http.server"* ]]
}

@test "works when invoked as python3 via symlink" {
  run "${BATS_TEST_DIRNAME}/python3"
  [[ $status -ne 0 ]]
  [[ "$output" == *'instead of `python3'* ]]
}

# `uv run python3` resolves the command via PATH and hits this shim again
# outside a project, so the suggestion must use the exact name `python`,
# which uv executes directly via its resolved interpreter.
@test "suggests exact 'uv run python', not python3, when invoked as python3" {
  run "${BATS_TEST_DIRNAME}/python3" script.py
  [[ $status -ne 0 ]]
  [[ "$output" == *'Use `uv run python script.py`'* ]]
  [[ "$output" != *"uv run python3"* ]]
}

@test "suggests exact 'uv run python -m', not python3, for modules" {
  run "${BATS_TEST_DIRNAME}/python3" -m http.server
  [[ $status -ne 0 ]]
  [[ "$output" == *'Use `uv run python -m http.server`'* ]]
  [[ "$output" != *"uv run python3"* ]]
}

@test "python3 -m pip suggests uv add" {
  run "${BATS_TEST_DIRNAME}/python3" -m pip install foo
  [[ $status -ne 0 ]]
  [[ "$output" == *"uv add"* ]]
}
