#!/usr/bin/env bats
# Tests for python/python3 PATH shim

SHIM="${BATS_TEST_DIRNAME}/python"

setup() {
  # `uv run` sets UV in the environment of commands it launches, and the shim
  # keys its passthrough off that variable.  Unset it (and the shim's exec
  # guard) so these tests behave the same whether or not the suite itself is
  # running under uv.
  unset UV MODERN_PYTHON_SHIM_PID
}

teardown() {
  [[ -z "${workdir:-}" ]] || rm -rf "$workdir"
}

# Create a fake interpreter named $1 inside $workdir and echo its dir.
# The fake prints its own name and arguments, then exits 42, so tests can
# verify argument forwarding and exit-code propagation.
make_fake_interpreter() {
  local dir
  dir="$workdir/real"
  mkdir -p "$dir"
  cat >"$dir/$1" <<'EOF'
#!/usr/bin/env bash
echo "FAKE ${0##*/}: $*"
exit 42
EOF
  chmod +x "$dir/$1"
  echo "$dir"
}

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
  [[ "$output" == *"uv run python3"* ]]
}

@test "python3 -m pip suggests uv add" {
  run "${BATS_TEST_DIRNAME}/python3" -m pip install foo
  [[ $status -ne 0 ]]
  [[ "$output" == *"uv add"* ]]
}

@test "passes through to real python when UV is set (uv run context)" {
  workdir="$(mktemp -d)"
  fakedir="$(make_fake_interpreter python)"
  # Shims dir stays first on PATH to prove the shim skips its own directory.
  run env UV=/usr/local/bin/uv PATH="${BATS_TEST_DIRNAME}:${fakedir}:/usr/bin:/bin" \
    "$SHIM" script.py --flag
  [[ $status -eq 42 ]]
  [[ "$output" == "FAKE python: script.py --flag" ]]
}

@test "passes through when invoked as python3 via symlink with UV set" {
  workdir="$(mktemp -d)"
  fakedir="$(make_fake_interpreter python3)"
  run env UV=/usr/local/bin/uv PATH="${BATS_TEST_DIRNAME}:${fakedir}:/usr/bin:/bin" \
    "${BATS_TEST_DIRNAME}/python3" -c 'print(1)'
  [[ $status -eq 42 ]]
  [[ "$output" == "FAKE python3: -c print(1)" ]]
}

@test "skips its own directory under an aliased spelling (symlinked PATH entry)" {
  workdir="$(mktemp -d)"
  fakedir="$(make_fake_interpreter python)"
  ln -s "$BATS_TEST_DIRNAME" "$workdir/alias"
  run env UV=/usr/local/bin/uv \
    PATH="$workdir/alias:${BATS_TEST_DIRNAME}:${fakedir}:/usr/bin:/bin" \
    "$SHIM" script.py
  [[ $status -eq 42 ]]
  [[ "$output" == "FAKE python: script.py" ]]
}

@test "errors distinctly when UV is set but no real interpreter is on PATH" {
  # PATH holds only the shims dir plus the tools the shim itself needs
  # (bash for its `env bash` shebang, basename from coreutils); /usr/bin
  # must stay off PATH because CI runners ship /usr/bin/python3.
  workdir="$(mktemp -d)"
  mkdir -p "$workdir/tools"
  ln -s "$(command -v bash)" "$workdir/tools/bash"
  ln -s "$(command -v basename)" "$workdir/tools/basename"
  run env UV=/usr/local/bin/uv PATH="${BATS_TEST_DIRNAME}:$workdir/tools" \
    "$SHIM" script.py
  [[ $status -eq 127 ]]
  [[ "$output" == *"no real python was found on PATH"* ]]
}

@test "does not exec-loop when a second shim copy is on PATH" {
  # Two distinct copies of the shim (e.g. two plugin cache versions) used to
  # be able to exec each other forever; the PID guard must break the cycle.
  workdir="$(mktemp -d)"
  mkdir -p "$workdir/copy" "$workdir/tools"
  cp "$SHIM" "$workdir/copy/python"
  chmod +x "$workdir/copy/python"
  ln -s "$(command -v bash)" "$workdir/tools/bash"
  ln -s "$(command -v basename)" "$workdir/tools/basename"
  run timeout 5 env UV=/usr/local/bin/uv \
    PATH="${BATS_TEST_DIRNAME}:$workdir/copy:$workdir/tools" \
    "$SHIM" script.py
  [[ $status -eq 127 ]]
  [[ "$output" == *"no real python was found on PATH"* ]]
}

@test "python -m pip stays blocked even when UV is set" {
  workdir="$(mktemp -d)"
  fakedir="$(make_fake_interpreter python)"
  run env UV=/usr/local/bin/uv PATH="${BATS_TEST_DIRNAME}:${fakedir}:/usr/bin:/bin" \
    "$SHIM" -m pip install requests
  [[ $status -eq 1 ]]
  [[ "$output" == *"uv add"* ]]
  [[ "$output" == *"uv remove"* ]]
  [[ "$output" != *"FAKE"* ]]
}
