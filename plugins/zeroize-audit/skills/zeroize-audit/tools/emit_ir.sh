#!/usr/bin/env bash
set -euo pipefail

# Emit LLVM IR for a given translation unit.
#
# Usage:
#   emit_ir.sh --cc clang --src path/to/file.c --out /tmp/file.ll --opt O2 -- <extra compile args>
#
# Notes:
# - Use `--` to pass through extra include/define flags.
# - We intentionally do not attempt to parse compile_commands.json here.
#   Your runner should extract the TU command and pass flags after `--`.

usage() {
  echo "Usage: $0 --src <file> --out <out.ll> [--cc clang] [--opt O0|O1|O2|O3|Os|Oz] -- <extra args>" >&2
}

CC="clang"
SRC=""
OUT=""
OPT="O0"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --cc)
      CC="$2"
      shift 2
      ;;
    --src)
      SRC="$2"
      shift 2
      ;;
    --out)
      OUT="$2"
      shift 2
      ;;
    --opt)
      OPT="$2"
      shift 2
      ;;
    --)
      shift
      break
      ;;
    *)
      echo "Unknown arg: $1" >&2
      usage
      exit 2
      ;;
  esac
done

if [[ -z "$SRC" || -z "$OUT" ]]; then
  usage
  exit 2
fi

# Normalize OPT -> clang flag
case "$OPT" in
  O0 | O1 | O2 | O3 | Os | Oz) ;;
  *)
    echo "Invalid --opt: $OPT" >&2
    usage
    exit 2
    ;;
esac

# Extra args after --
EXTRA=("$@")

# Ensure output dir exists
mkdir -p "$(dirname "$OUT")"

# Emit IR
"$CC" "-$OPT" -S -emit-llvm "$SRC" -o "$OUT" ${EXTRA[@]+"${EXTRA[@]}"}

echo "OK: wrote IR to $OUT"
