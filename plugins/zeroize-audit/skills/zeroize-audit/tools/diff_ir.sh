#!/usr/bin/env bash
set -euo pipefail

# Normalize and diff LLVM IR across one or more optimization levels.
#
# Usage (two-file, backward-compatible):
#   diff_ir.sh <O0.ll> <O2.ll>
#
# Usage (multi-level — recommended):
#   diff_ir.sh <O0.ll> <O1.ll> <O2.ll> [<O3.ll> ...]
#
# Output:
# - Prints a unified diff for each pair of adjacent files.
# - For 3+ files, also prints a WIPE PATTERN SUMMARY identifying the first
#   optimization level at which zeroization patterns disappear.
# - Returns exit code 0 if all files are identical, 1 if any diffs found.
#
# Wipe patterns detected in the summary:
#   llvm.memset, volatile, explicit_bzero, sodium_memzero, OPENSSL_cleanse,
#   SecureZeroMemory, memset_s, store i8 0, store i64 0, store i32 0

usage() {
  echo "Usage: $0 <baseline.ll> <file2.ll> [<file3.ll> ...]" >&2
}

if [[ $# -lt 2 ]]; then
  usage
  exit 2
fi

for f in "$@"; do
  if [[ ! -f "$f" ]]; then
    echo "Missing file: $f" >&2
    exit 2
  fi
done

norm() {
  # Remove comments and metadata noise that changes frequently.
  # Keep it simple and safe: do NOT rewrite semantics, only strip obviously noisy lines.
  sed -E \
    -e 's/;.*$//' \
    -e '/^\s*$/d' \
    -e '/^source_filename = /d' \
    -e '/^target datalayout = /d' \
    -e '/^target triple = /d' \
    -e '/^!llvm\./d' \
    -e '/^!DIGlobalVariable/d' \
    -e '/^!DICompileUnit/d' \
    -e '/^!DIFile/d' \
    -e '/^!DISubprogram/d' \
    -e '/^!DILocation/d' \
    -e '/^!DI.*$/d'
}

has_wipe_pattern() {
  # Return 0 (true) if the file contains any zeroization pattern.
  grep -qE \
    'llvm\.memset|volatile|explicit_bzero|sodium_memzero|OPENSSL_cleanse|SecureZeroMemory|memset_s|store i8 0|store i64 0|store i32 0' \
    "$1"
}

# ---------------------------------------------------------------------------
# Normalize all input files into temp files.
# ---------------------------------------------------------------------------
FILES=("$@")
NUM_FILES=${#FILES[@]}

TMPDIR_BASE="$(mktemp -d -t za-ir-XXXXXX)"
trap 'rm -rf "$TMPDIR_BASE"' EXIT

NORMFILES=()
for i in "${!FILES[@]}"; do
  tmp="$TMPDIR_BASE/norm_${i}.ll"
  norm <"${FILES[$i]}" >"$tmp"
  NORMFILES+=("$tmp")
done

# ---------------------------------------------------------------------------
# Two-file mode: backward-compatible, single diff, no summary.
# ---------------------------------------------------------------------------
if [[ $NUM_FILES -eq 2 ]]; then
  diff_rc=0
  diff -u "${NORMFILES[0]}" "${NORMFILES[1]}" || diff_rc=$?
  if [[ $diff_rc -eq 2 ]]; then
    echo "diff_ir.sh: diff failed (internal error)" >&2
    exit 1
  fi
  exit $diff_rc
fi

# ---------------------------------------------------------------------------
# Multi-file mode: pairwise diffs between adjacent files + wipe summary.
# ---------------------------------------------------------------------------
any_diff=0

for ((i = 0; i < NUM_FILES - 1; i++)); do
  j=$((i + 1))
  A_LABEL="$(basename "${FILES[$i]}")"
  B_LABEL="$(basename "${FILES[$j]}")"
  echo "=== DIFF File $((i + 1)) ($A_LABEL) vs File $((j + 1)) ($B_LABEL) ==="
  if ! diff -u "${NORMFILES[$i]}" "${NORMFILES[$j]}"; then
    any_diff=1
  fi
  echo ""
done

# ---------------------------------------------------------------------------
# Wipe pattern summary: identify first file where wipe disappears.
# ---------------------------------------------------------------------------
echo "=== WIPE PATTERN SUMMARY ==="
first_absent=-1
for i in "${!NORMFILES[@]}"; do
  LABEL="$(basename "${FILES[$i]}")"
  if has_wipe_pattern "${NORMFILES[$i]}"; then
    echo "  File $((i + 1)) ($LABEL): WIPE PRESENT"
  else
    echo "  File $((i + 1)) ($LABEL): WIPE ABSENT"
    if [[ $first_absent -eq -1 ]]; then
      first_absent=$i
    fi
  fi
done

if [[ $first_absent -ne -1 ]]; then
  LABEL="$(basename "${FILES[$first_absent]}")"
  echo ""
  echo "  First disappearance at File $((first_absent + 1)) ($LABEL)."
  echo "  Evidence: OPTIMIZED_AWAY_ZEROIZE — wipe present at lower opt level(s) but absent here."
else
  echo ""
  echo "  Wipe patterns present at all opt levels analyzed."
fi

exit $any_diff
