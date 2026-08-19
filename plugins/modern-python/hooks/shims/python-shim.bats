#!/usr/bin/env bats
# Tests for python/python3 PATH shim

bats_require_minimum_version 1.5.0

SHIM="${BATS_TEST_DIRNAME}/python"
SHIM3="${BATS_TEST_DIRNAME}/python3"

# Pass-through cases need to reach a real interpreter. /usr/bin holds python3 on both
# macOS and the CI image, and pinning PATH to it keeps the test off any shim that
# happens to be installed on the machine running this — including an older copy of
# this very shim, which would otherwise answer instead of the real binary.
REAL_PATH="/usr/bin:/bin"

real_python3_or_skip() {
  [[ -x /usr/bin/python3 ]] || skip "no /usr/bin/python3 to pass through to"
}

# --------------------------------------------------------------- still intercepted

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

@test "exits non-zero for python -m pip install" {
  run "$SHIM" -m pip install requests
  [[ $status -ne 0 ]]
  [[ "$output" == *"uv add"* ]]
  [[ "$output" == *"uv remove"* ]]
}

@test "python3 -m pip suggests uv add" {
  run "$SHIM3" -m pip install foo
  [[ $status -ne 0 ]]
  [[ "$output" == *"uv add"* ]]
}

@test "works when invoked as python3 via symlink" {
  run "$SHIM3"
  [[ $status -ne 0 ]]
  [[ "$output" == *'instead of `python3'* ]]
}

# The suggestion must use the exact name `python`, never `python3`; see
# the header comment in ./python for the full rationale.
@test "suggests exact 'uv run python', not python3, when invoked as python3" {
  run "$SHIM3" script.py
  [[ $status -ne 0 ]]
  [[ "$output" == *"Use \`uv run python script.py\`"* ]]
  [[ "$output" != *"uv run python3"* ]]
}

@test "bare invocation suggests uv run python without trailing space" {
  run "$SHIM"
  [[ $status -ne 0 ]]
  [[ "$output" == *"Use \`uv run python\` instead of \`python\`"* ]]
}

# %q output can differ across bash versions, so build the expectation with
# the same requoting the shim uses, after checking it actually escapes.
@test "suggestion requotes a script path so it stays copy-paste runnable" {
  run "$SHIM" 'my script.py'
  [[ $status -ne 0 ]]
  quoted="$(printf '%q' 'my script.py')"
  [[ "$quoted" != 'my script.py' ]]
  [[ "$output" == *"Use \`uv run python $quoted\`"* ]]
}

# ------------------------------------------------------------- deliberately allowed
#
# None of these resolves a script against a project's dependencies, which is the thing
# `uv run` exists to do, so redirecting them was wrong. See #207 and ./python's header.

@test "python -c runs the code instead of refusing" {
  real_python3_or_skip
  run env PATH="$REAL_PATH" "$SHIM3" -c 'print(1+1)'
  [[ $status -eq 0 ]]
  [[ "$output" == "2" ]]
}

@test "python -m <module> reaches the module instead of refusing" {
  real_python3_or_skip
  run env PATH="$REAL_PATH" "$SHIM3" -m json.tool --help
  [[ $status -eq 0 ]]
  [[ "$output" == *"json.tool"* ]]
}

@test "python - reads the program from stdin" {
  real_python3_or_skip
  run bash -c "echo 'print(3+3)' | env PATH='$REAL_PATH' '$SHIM3' -"
  [[ $status -eq 0 ]]
  [[ "$output" == "6" ]]
}

# An interpreter flag before the mode selector must not change the decision: `-u -c` is
# the same invocation as `-c`. Reading only $1 made the answer depend on argument order.

@test "an interpreter flag before -c does not resurrect the refusal" {
  real_python3_or_skip
  run env PATH="$REAL_PATH" "$SHIM3" -u -c 'print(1+1)'
  [[ $status -eq 0 ]]
  [[ "$output" == "2" ]]
}

@test "a value-taking interpreter flag before -c is stepped over correctly" {
  real_python3_or_skip
  run env PATH="$REAL_PATH" "$SHIM3" -X utf8 -c 'print(1+1)'
  [[ $status -eq 0 ]]
  [[ "$output" == "2" ]]
}

@test "a flag before a script path still refuses" {
  run "$SHIM3" -u script.py
  [[ $status -ne 0 ]]
  [[ "$output" == *"uv run python"* ]]
}

@test "a flag before -m pip still refuses" {
  run "$SHIM3" -u -m pip install foo
  [[ $status -ne 0 ]]
  [[ "$output" == *"uv add"* ]]
}

@test "exits 127 with error when the real interpreter is not found" {
  # A PATH holding the shim and nothing else cannot test this: the shebang is
  # `/usr/bin/env bash`, so env exits 127 looking for bash and the shim never runs —
  # the right status for the wrong reason. Give it bash and no python3.
  local only_bash="$BATS_TEST_TMPDIR/only-bash"
  mkdir -p "$only_bash"
  ln -sf "$(command -v bash)" "$only_bash/bash"
  [[ ! -x "$only_bash/python3" ]]

  run -127 env PATH="${BATS_TEST_DIRNAME}:$only_bash" "$SHIM3" -c 'print(1)'
  [[ "$output" == *"real python3 binary not found"* ]]
}
