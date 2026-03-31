#!/usr/bin/env bash
# emit_rust_mir.sh — Emit Rust MIR for zeroize analysis.
#
# Exit codes:
#   0  success
#   1  build/output failure
#   2  argument error

set -euo pipefail

usage() {
  cat <<'EOF'
Usage:
  emit_rust_mir.sh --manifest <Cargo.toml> --out <path> [options] [-- <extra cargo rustc args>]

Options:
  --manifest <file>        Cargo manifest path (required)
  --out <path>             Output .mir file or directory (required)
  --opt <O0|O1|O2|O3>      Opt level (default: O0)
  --crate <pkg>            Workspace package (-p)
  --bin <target>           Build only a specific bin target
  --lib                    Build only the lib target
  --help                   Show this help text

Examples:
  emit_rust_mir.sh --manifest Cargo.toml --opt O0 --out /tmp/crate.O0.mir
  emit_rust_mir.sh --manifest Cargo.toml --out /tmp/zeroize_mir
EOF
}

die_arg() {
  echo "emit_rust_mir.sh: $*" >&2
  exit 2
}

die_run() {
  echo "emit_rust_mir.sh: $*" >&2
  exit 1
}

require_value() {
  local opt="$1"
  local val="${2-}"
  [[ -n "$val" ]] || die_arg "missing value for ${opt}"
}

MANIFEST=""
OUT=""
OPT="O0"
CRATE=""
BIN_TARGET=""
LIB_TARGET=false
EXTRA_ARGS=()

while [[ $# -gt 0 ]]; do
  case "$1" in
    --manifest)
      require_value "$1" "${2-}"
      MANIFEST="$2"
      shift 2
      ;;
    --out)
      require_value "$1" "${2-}"
      OUT="$2"
      shift 2
      ;;
    --opt)
      require_value "$1" "${2-}"
      OPT="$2"
      shift 2
      ;;
    --crate)
      require_value "$1" "${2-}"
      CRATE="$2"
      shift 2
      ;;
    --bin)
      require_value "$1" "${2-}"
      BIN_TARGET="$2"
      shift 2
      ;;
    --lib)
      LIB_TARGET=true
      shift
      ;;
    --help | -h)
      usage
      exit 0
      ;;
    --)
      shift
      EXTRA_ARGS=("$@")
      break
      ;;
    *)
      die_arg "unknown argument: $1"
      ;;
  esac
done

[[ -n "$MANIFEST" ]] || die_arg "--manifest is required"
[[ -n "$OUT" ]] || die_arg "--out is required"
[[ -f "$MANIFEST" ]] || die_run "manifest not found: $MANIFEST"
[[ -n "$BIN_TARGET" && "$LIB_TARGET" == true ]] && die_arg "--bin and --lib are mutually exclusive"

case "$OPT" in
  O0) LEVEL="0" ;;
  O1) LEVEL="1" ;;
  O2) LEVEL="2" ;;
  O3) LEVEL="3" ;;
  *) die_arg "unsupported opt level: $OPT (use O0, O1, O2, O3)" ;;
esac

OUT_IS_FILE=false
if [[ "$OUT" == *.mir ]]; then
  OUT_IS_FILE=true
  mkdir -p "$(dirname "$OUT")"
else
  mkdir -p "$OUT"
fi

CARGO_ARGS=(+nightly rustc --manifest-path "$MANIFEST")
[[ -n "$CRATE" ]] && CARGO_ARGS+=("-p" "$CRATE")
[[ -n "$BIN_TARGET" ]] && CARGO_ARGS+=("--bin" "$BIN_TARGET")
[[ "$LIB_TARGET" == true ]] && CARGO_ARGS+=("--lib")

TARGET_DIR="${TMPDIR:-/tmp}/zeroize_rust_mir_${LEVEL}_$$"
rm -rf "$TARGET_DIR"
mkdir -p "$TARGET_DIR"

echo "=== emit_rust_mir.sh ==="
echo "manifest: $MANIFEST"
echo "opt:      $OPT"
echo "target:   $TARGET_DIR"
echo "output:   $OUT"

if ! CARGO_TARGET_DIR="$TARGET_DIR" cargo "${CARGO_ARGS[@]}" \
  "${EXTRA_ARGS[@]+"${EXTRA_ARGS[@]}"}" \
  -- --emit=mir -C opt-level="$LEVEL"; then
  die_run "cargo rustc failed for opt=${OPT}"
fi

declare -a MIR_FILES=()
while IFS= read -r file; do
  MIR_FILES+=("$file")
done < <(find "$TARGET_DIR" -type f -name "*.mir" | LC_ALL=C sort)

[[ "${#MIR_FILES[@]}" -gt 0 ]] || die_run "no .mir files found under $TARGET_DIR"

if [[ "$OUT_IS_FILE" == true ]]; then
  : >"$OUT"
  for file in "${MIR_FILES[@]}"; do
    cat "$file" >>"$OUT"
  done
  [[ -s "$OUT" ]] || die_run "emitted MIR is empty: $OUT"
else
  cp "${MIR_FILES[@]}" "$OUT/"
fi
