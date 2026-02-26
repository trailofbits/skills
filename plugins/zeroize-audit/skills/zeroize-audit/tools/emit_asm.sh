#!/usr/bin/env bash
set -euo pipefail

# Emit assembly for a given translation unit.
#
# Usage:
#   emit_asm.sh --cc clang --src path/to/file.c --out /tmp/file.s --opt O2 -- <extra compile args>

usage() {
  echo "Usage: $0 --src <file> --out <out.s> [--cc clang] [--opt O0|O1|O2|O3|Os|Oz] -- <extra args>" >&2
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

case "$OPT" in
  O0 | O1 | O2 | O3 | Os | Oz) ;;
  *)
    echo "Invalid --opt: $OPT" >&2
    usage
    exit 2
    ;;
esac

EXTRA=("$@")
mkdir -p "$(dirname "$OUT")"

"$CC" "-$OPT" -S "$SRC" -o "$OUT" ${EXTRA[@]+"${EXTRA[@]}"}

echo "OK: wrote asm to $OUT"
