#!/usr/bin/env bash
# validate_rust_toolchain.sh — Preflight check for Rust zeroize-audit prerequisites.
#
# Validates that all tools required by the Rust analysis pipeline are available
# and functional. Outputs a JSON status report.
#
# Exit codes:
#   0  all required tools available (warnings may still be present)
#   1  at least one required tool is missing
#   2  argument error

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

usage() {
  cat <<'EOF'
Usage:
  validate_rust_toolchain.sh [options]

Options:
  --manifest <Cargo.toml>  Check that the manifest exists and the crate builds
  --json                   Output machine-readable JSON (default: human-readable)
  --help                   Show this help text

Checks (required):
  - cargo on PATH
  - cargo +nightly available
  - uv on PATH (for Python analysis scripts)

Checks (optional, warning only):
  - rustfilt on PATH (for symbol demangling)
  - cargo-expand on PATH (for macro expansion debugging)

If --manifest is provided, additionally:
  - Manifest file exists
  - cargo check passes for the crate
EOF
}

die_arg() {
  echo "validate_rust_toolchain.sh: $*" >&2
  exit 2
}

MANIFEST=""
JSON_OUTPUT=false

while [[ $# -gt 0 ]]; do
  case "$1" in
    --manifest)
      [[ -n "${2-}" ]] || die_arg "missing value for --manifest"
      MANIFEST="$2"
      shift 2
      ;;
    --json)
      JSON_OUTPUT=true
      shift
      ;;
    --help | -h)
      usage
      exit 0
      ;;
    *)
      die_arg "unknown argument: $1"
      ;;
  esac
done

# ---------------------------------------------------------------------------
# Tool checks
# ---------------------------------------------------------------------------

declare -A TOOL_STATUS
declare -A TOOL_VERSION
ERRORS=()
WARNINGS=()

check_tool() {
  local name="$1"
  local required="$2"
  local cmd="${3:-$name}"

  if command -v "$cmd" &>/dev/null; then
    TOOL_STATUS["$name"]="present"
    local ver
    # Use a separate variable so we can distinguish a version-check failure
    # (e.g. shared-library missing) from the tool simply not being on PATH.
    if ver=$("$cmd" --version 2>/dev/null | head -1); then
      TOOL_VERSION["$name"]="$ver"
    else
      TOOL_VERSION["$name"]="(version check failed)"
      WARNINGS+=("$name is present but '--version' failed — tool may be broken")
    fi
  else
    if [[ "$required" == "true" ]]; then
      TOOL_STATUS["$name"]="missing"
      ERRORS+=("$name is required but not found on PATH")
    else
      TOOL_STATUS["$name"]="missing"
      WARNINGS+=("$name is not found on PATH (optional: ${4:-enhanced analysis})")
    fi
  fi
}

check_tool "cargo" "true"
check_tool "uv" "true"
check_tool "rustfilt" "false" "rustfilt" "Rust symbol demangling in assembly analysis"
check_tool "cargo-expand" "false" "cargo-expand" "macro expansion debugging"

# Check cargo +nightly
NIGHTLY_STATUS="unavailable"
NIGHTLY_VERSION="unknown"
if [[ "${TOOL_STATUS[cargo]}" == "present" ]]; then
  if cargo +nightly --version &>/dev/null 2>&1; then
    NIGHTLY_STATUS="available"
    NIGHTLY_VERSION=$(cargo +nightly --version 2>/dev/null | head -1 || echo "unknown")
  else
    NIGHTLY_STATUS="unavailable"
    ERRORS+=("cargo +nightly is required but the nightly toolchain is not installed (run: rustup toolchain install nightly)")
  fi
fi

# Check that emit/analysis scripts exist
declare -A SCRIPT_STATUS
REQUIRED_SCRIPTS=(
  "emit_rust_mir.sh"
  "emit_rust_ir.sh"
  "emit_rust_asm.sh"
)
OPTIONAL_SCRIPTS=(
  "diff_rust_mir.sh"
  "scripts/check_mir_patterns.py"
  "scripts/check_llvm_patterns.py"
  "scripts/check_rust_asm.py"
  "scripts/semantic_audit.py"
  "scripts/find_dangerous_apis.py"
)

for script in "${REQUIRED_SCRIPTS[@]}"; do
  if [[ -f "$SCRIPT_DIR/$script" ]]; then
    SCRIPT_STATUS["$script"]="present"
  else
    SCRIPT_STATUS["$script"]="missing"
    ERRORS+=("required script $script not found at $SCRIPT_DIR/$script")
  fi
done

for script in "${OPTIONAL_SCRIPTS[@]}"; do
  if [[ -f "$SCRIPT_DIR/$script" ]]; then
    SCRIPT_STATUS["$script"]="present"
  else
    SCRIPT_STATUS["$script"]="missing"
    WARNINGS+=("optional script $script not found at $SCRIPT_DIR/$script")
  fi
done

# Check manifest and crate build (if requested)
MANIFEST_STATUS="not_checked"
BUILD_STATUS="not_checked"
if [[ -n "$MANIFEST" ]]; then
  if [[ -f "$MANIFEST" ]]; then
    MANIFEST_STATUS="present"
    if [[ "$NIGHTLY_STATUS" == "available" ]]; then
      cargo_err=$(mktemp) || {
        ERRORS+=("mktemp failed — cannot capture cargo output")
        cargo_err="/dev/null"
      }
      if cargo +nightly check --manifest-path "$MANIFEST" 2>"$cargo_err"; then
        BUILD_STATUS="pass"
      else
        BUILD_STATUS="fail"
        # Include up to 20 lines of cargo output so callers can diagnose
        # the failure without re-running manually.
        cargo_snippet=$(head -20 "$cargo_err" 2>/dev/null | tr '\n' ' ')
        ERRORS+=("cargo check failed for $MANIFEST: ${cargo_snippet:-see stderr}")
      fi
      rm -f "$cargo_err"
    else
      BUILD_STATUS="skipped"
      WARNINGS+=("cargo check skipped (nightly not available)")
    fi
  else
    MANIFEST_STATUS="missing"
    ERRORS+=("manifest not found: $MANIFEST")
  fi
fi

# ---------------------------------------------------------------------------
# Output
# ---------------------------------------------------------------------------

OVERALL_STATUS="ready"
[[ ${#ERRORS[@]} -gt 0 ]] && OVERALL_STATUS="blocked"

if [[ "$JSON_OUTPUT" == true ]]; then
  # Build tool statuses as JSON
  TOOLS_JSON="{"
  first=true
  for name in cargo uv rustfilt cargo-expand; do
    [[ "$first" == true ]] && first=false || TOOLS_JSON+=","
    TOOLS_JSON+="\"$name\":{\"status\":\"${TOOL_STATUS[$name]:-unknown}\",\"version\":\"${TOOL_VERSION[$name]:-unknown}\"}"
  done
  TOOLS_JSON+="}"

  # Build script statuses as JSON
  SCRIPTS_JSON="{"
  first=true
  for script in "${REQUIRED_SCRIPTS[@]}" "${OPTIONAL_SCRIPTS[@]}"; do
    [[ "$first" == true ]] && first=false || SCRIPTS_JSON+=","
    SCRIPTS_JSON+="\"$script\":\"${SCRIPT_STATUS[$script]:-unknown}\""
  done
  SCRIPTS_JSON+="}"

  # Build errors/warnings arrays using Python for correct JSON escaping.
  # The sed-based approach only escaped double quotes but not backslashes,
  # newlines, or control characters — all of which can appear in cargo output.
  _json_str_array() {
    # Read lines from stdin, emit a JSON array of properly escaped strings.
    python3 -c '
import json, sys
items = [l.rstrip("\n") for l in sys.stdin]
print(json.dumps(items))
'
  }
  ERRORS_JSON=$(printf '%s\n' "${ERRORS[@]+"${ERRORS[@]}"}" | _json_str_array)
  WARNINGS_JSON=$(printf '%s\n' "${WARNINGS[@]+"${WARNINGS[@]}"}" | _json_str_array)

  cat <<EOF
{
  "status": "$OVERALL_STATUS",
  "tools": $TOOLS_JSON,
  "nightly": {"status": "$NIGHTLY_STATUS", "version": "$NIGHTLY_VERSION"},
  "scripts": $SCRIPTS_JSON,
  "manifest": {"status": "$MANIFEST_STATUS", "build": "$BUILD_STATUS"},
  "errors": $ERRORS_JSON,
  "warnings": $WARNINGS_JSON
}
EOF
else
  echo "=== Rust Toolchain Validation ==="
  echo ""
  echo "Tools:"
  for name in cargo uv rustfilt cargo-expand; do
    status="${TOOL_STATUS[$name]:-unknown}"
    version="${TOOL_VERSION[$name]:-}"
    if [[ "$status" == "present" ]]; then
      echo "  [OK]   $name ($version)"
    else
      echo "  [MISS] $name"
    fi
  done
  echo ""
  echo "Nightly: $NIGHTLY_STATUS ($NIGHTLY_VERSION)"
  echo ""
  echo "Scripts:"
  for script in "${REQUIRED_SCRIPTS[@]}"; do
    status="${SCRIPT_STATUS[$script]:-unknown}"
    if [[ "$status" == "present" ]]; then
      echo "  [OK]   $script"
    else
      echo "  [MISS] $script (required)"
    fi
  done
  for script in "${OPTIONAL_SCRIPTS[@]}"; do
    status="${SCRIPT_STATUS[$script]:-unknown}"
    if [[ "$status" == "present" ]]; then
      echo "  [OK]   $script"
    else
      echo "  [MISS] $script (optional)"
    fi
  done

  if [[ -n "$MANIFEST" ]]; then
    echo ""
    echo "Manifest: $MANIFEST ($MANIFEST_STATUS)"
    echo "Build:    $BUILD_STATUS"
  fi

  if [[ ${#ERRORS[@]} -gt 0 ]]; then
    echo ""
    echo "ERRORS:"
    for err in "${ERRORS[@]}"; do
      echo "  - $err"
    done
  fi
  if [[ ${#WARNINGS[@]} -gt 0 ]]; then
    echo ""
    echo "WARNINGS:"
    for warn in "${WARNINGS[@]}"; do
      echo "  - $warn"
    done
  fi
  echo ""
  echo "Overall: $OVERALL_STATUS"
fi

[[ "$OVERALL_STATUS" == "ready" ]]
