#!/usr/bin/env bats
# Tests for setup-shims.sh SessionStart hook

SETUP_SCRIPT="${BATS_TEST_DIRNAME}/setup-shims.sh"

setup() {
  export CLAUDE_ENV_FILE
  CLAUDE_ENV_FILE="$(mktemp)"
  # Create a fake gh so the guard passes
  FAKE_BIN="$(mktemp -d)"
  echo '#!/usr/bin/env bash' >"$FAKE_BIN/gh"
  chmod +x "$FAKE_BIN/gh"
  export FAKE_BIN
  export ORIG_PATH="$PATH"
}

teardown() {
  rm -f "$CLAUDE_ENV_FILE"
  rm -rf "$FAKE_BIN"
}

@test "exits with error when CLAUDE_ENV_FILE is not set" {
  run env -u CLAUDE_ENV_FILE PATH="${FAKE_BIN}:${ORIG_PATH}" \
    bash "$SETUP_SCRIPT" 2>&1
  [[ $status -eq 1 ]]
  [[ "$output" == *"CLAUDE_ENV_FILE not set"* ]]
}

@test "exits gracefully when gh is not available" {
  local path_without_gh=""
  local IFS=:
  for dir in $ORIG_PATH; do
    [[ "$dir" == "$FAKE_BIN" ]] && continue
    [[ -x "$dir/gh" ]] && continue
    path_without_gh="${path_without_gh:+${path_without_gh}:}$dir"
  done
  # Use absolute bash path since filtering gh may remove /usr/bin from PATH
  local bash_path
  bash_path="$(command -v bash)"
  run env PATH="$path_without_gh" CLAUDE_ENV_FILE="$CLAUDE_ENV_FILE" \
    "$bash_path" "$SETUP_SCRIPT" 2>&1
  [[ $status -eq 0 ]]
  [[ ! -s "$CLAUDE_ENV_FILE" ]]
  [[ "$output" == *"gh not found on PATH"* ]]
}

@test "writes PATH export to CLAUDE_ENV_FILE" {
  run env PATH="${FAKE_BIN}:${ORIG_PATH}" bash "$SETUP_SCRIPT"
  [[ $status -eq 0 ]]
  grep -q 'export PATH=' "$CLAUDE_ENV_FILE"
}

@test "shims dir appears in PATH export" {
  env PATH="${FAKE_BIN}:${ORIG_PATH}" bash "$SETUP_SCRIPT"
  local shims_dir
  shims_dir="$(cd "${BATS_TEST_DIRNAME}/shims" && pwd)"
  grep -q "$shims_dir" "$CLAUDE_ENV_FILE"
}

@test "shims dir is an absolute path" {
  env PATH="${FAKE_BIN}:${ORIG_PATH}" bash "$SETUP_SCRIPT"
  local line
  line="$(cat "$CLAUDE_ENV_FILE")"
  [[ "$line" =~ export\ PATH=\"/ ]]
}

@test "exits with error when shims/gh is not executable" {
  local tmpdir
  tmpdir="$(mktemp -d)"
  cp "$SETUP_SCRIPT" "$tmpdir/setup-shims.sh"
  mkdir -p "$tmpdir/shims"
  # Create a non-executable gh file
  echo '#!/usr/bin/env bash' >"$tmpdir/shims/gh"
  run env PATH="${FAKE_BIN}:${ORIG_PATH}" CLAUDE_ENV_FILE="$CLAUDE_ENV_FILE" \
    bash "$tmpdir/setup-shims.sh" 2>&1
  [[ $status -ne 0 ]]
  [[ "$output" == *"shims/gh not found or not executable"* ]]
  rm -rf "$tmpdir"
}

@test "exits with error when shims directory is missing" {
  local tmpdir
  tmpdir="$(mktemp -d)"
  cp "$SETUP_SCRIPT" "$tmpdir/setup-shims.sh"
  run env PATH="${FAKE_BIN}:${ORIG_PATH}" CLAUDE_ENV_FILE="$CLAUDE_ENV_FILE" \
    bash "$tmpdir/setup-shims.sh" 2>&1
  [[ $status -ne 0 ]]
  [[ "$output" == *"shims directory not found"* ]]
  rm -rf "$tmpdir"
}

@test "appends to existing CLAUDE_ENV_FILE content" {
  echo 'export FOO=bar' >"$CLAUDE_ENV_FILE"
  env PATH="${FAKE_BIN}:${ORIG_PATH}" bash "$SETUP_SCRIPT"
  grep -q 'export FOO=bar' "$CLAUDE_ENV_FILE"
  grep -q 'export PATH=' "$CLAUDE_ENV_FILE"
}
