#!/usr/bin/env bash
# diff_rust_mir.sh — Normalize and diff Rust MIR across optimization levels.
#
# Compares MIR output from different optimization levels to detect zeroize-
# related transformations: drop glue removal, StorageDead elimination, and
# zeroize call elimination.
#
# Exit codes:
#   0  all files are identical after normalization
#   1  at least one diff found (or wipe patterns disappeared)
#   2  argument error
#
# Usage (two-file, backward-compatible):
#   diff_rust_mir.sh <O0.mir> <O2.mir>
#
# Usage (multi-level — recommended):
#   diff_rust_mir.sh <O0.mir> <O1.mir> <O2.mir> [<O3.mir> ...]
#
# Output:
# - Unified diff for each pair of adjacent files.
# - For 3+ files, a ZEROIZE PATTERN SUMMARY identifying the first opt level
#   at which patterns disappear.
#
# Wipe patterns detected:
#   zeroize::, Zeroize::zeroize, volatile_set_memory, drop_in_place,
#   StorageDead for sensitive locals, ptr::write_bytes

set -euo pipefail

usage() {
  cat <<'EOF'
Usage:
  diff_rust_mir.sh <baseline.mir> <file2.mir> [<file3.mir> ...]

Compares Rust MIR files across optimization levels. Normalizes away noisy
metadata (source locations, scope info, storage annotations) and diffs
the semantic content. Detects disappearance of zeroize-related patterns.

Examples:
  diff_rust_mir.sh crate.O0.mir crate.O2.mir
  diff_rust_mir.sh crate.O0.mir crate.O1.mir crate.O2.mir crate.O3.mir
EOF
}

if [[ $# -lt 2 ]]; then
  usage
  exit 2
fi

for f in "$@"; do
  if [[ ! -f "$f" ]]; then
    echo "diff_rust_mir.sh: missing file: $f" >&2
    exit 2
  fi
done

# ---------------------------------------------------------------------------
# Normalization: strip noisy metadata that changes between opt levels
# but is semantically irrelevant for zeroize analysis.
# ---------------------------------------------------------------------------
norm() {
  sed -E \
    -e '/^\/\/ WARNING:/d' \
    -e '/^\/\/ MIR for/d' \
    -e 's/scope [0-9]+ at [^ ]+:[0-9]+:[0-9]+/scope N at <loc>/g' \
    -e 's/at [^ ]+\.rs:[0-9]+:[0-9]+/at <loc>/g' \
    -e 's/\/\/ .*$//g' \
    -e '/^\s*$/d'
}

# ---------------------------------------------------------------------------
# Pattern detection: Rust MIR zeroize-related constructs
# ---------------------------------------------------------------------------
has_zeroize_pattern() {
  grep -qE \
    'zeroize::|Zeroize::zeroize|volatile_set_memory|ptr::write_bytes|drop_in_place.*[Kk]ey|drop_in_place.*[Ss]ecret|drop_in_place.*[Pp]assword|drop_in_place.*[Tt]oken|drop_in_place.*[Nn]once|drop_in_place.*[Ss]eed|drop_in_place.*[Pp]riv|Zeroizing|ZeroizeOnDrop' \
    "$1"
}

has_drop_glue() {
  grep -qE 'drop_in_place|drop\(_[0-9]+\)' "$1"
}

# shellcheck disable=SC2329,SC2317 # invoked indirectly by agent prompts
has_storage_dead_sensitive() {
  grep -qE 'StorageDead\(_[0-9]+\)' "$1" &&
    grep -qE '(key|secret|password|token|nonce|seed|priv|master|credential)' "$1"
}

# ---------------------------------------------------------------------------
# Setup
# ---------------------------------------------------------------------------
FILES=("$@")
NUM_FILES=${#FILES[@]}

TMPDIR_BASE="$(mktemp -d -t za-mir-XXXXXX)"
trap 'rm -rf "$TMPDIR_BASE"' EXIT

NORMFILES=()
for i in "${!FILES[@]}"; do
  tmp="$TMPDIR_BASE/norm_${i}.mir"
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
    echo "diff_rust_mir.sh: diff failed (internal error)" >&2
    exit 1
  fi
  exit $diff_rc
fi

# ---------------------------------------------------------------------------
# Multi-file mode: pairwise diffs + zeroize pattern summary.
# ---------------------------------------------------------------------------
any_diff=0

for ((i = 0; i < NUM_FILES - 1; i++)); do
  j=$((i + 1))
  A_LABEL="$(basename "${FILES[$i]}")"
  B_LABEL="$(basename "${FILES[$j]}")"
  echo "=== DIFF File $((i + 1)) ($A_LABEL) vs File $((j + 1)) ($B_LABEL) ==="
  if ! diff -u --label "$A_LABEL" --label "$B_LABEL" \
    "${NORMFILES[$i]}" "${NORMFILES[$j]}"; then
    any_diff=1
  fi
  echo ""
done

# ---------------------------------------------------------------------------
# Zeroize pattern summary
# ---------------------------------------------------------------------------
echo "=== ZEROIZE PATTERN SUMMARY ==="
first_absent=-1
for i in "${!NORMFILES[@]}"; do
  LABEL="$(basename "${FILES[$i]}")"
  if has_zeroize_pattern "${NORMFILES[$i]}"; then
    echo "  File $((i + 1)) ($LABEL): ZEROIZE CALLS PRESENT"
  else
    echo "  File $((i + 1)) ($LABEL): ZEROIZE CALLS ABSENT"
    if [[ $first_absent -eq -1 ]]; then
      first_absent=$i
    fi
  fi
done
echo ""

# ---------------------------------------------------------------------------
# Drop glue summary
# ---------------------------------------------------------------------------
echo "=== DROP GLUE SUMMARY ==="
first_drop_absent=-1
for i in "${!NORMFILES[@]}"; do
  LABEL="$(basename "${FILES[$i]}")"
  if has_drop_glue "${NORMFILES[$i]}"; then
    echo "  File $((i + 1)) ($LABEL): DROP GLUE PRESENT"
  else
    echo "  File $((i + 1)) ($LABEL): DROP GLUE ABSENT"
    if [[ $first_drop_absent -eq -1 ]]; then
      first_drop_absent=$i
    fi
  fi
done
echo ""

# ---------------------------------------------------------------------------
# Verdict
# ---------------------------------------------------------------------------
if [[ $first_absent -ne -1 ]]; then
  LABEL="$(basename "${FILES[$first_absent]}")"
  echo "WARNING: Zeroize patterns first disappear at File $((first_absent + 1)) ($LABEL)."
  echo "  Evidence: OPTIMIZED_AWAY_ZEROIZE — zeroize calls present at lower opt level(s) but absent here."
  any_diff=1
elif [[ $first_drop_absent -ne -1 ]]; then
  LABEL="$(basename "${FILES[$first_drop_absent]}")"
  echo "WARNING: Drop glue first disappears at File $((first_drop_absent + 1)) ($LABEL)."
  echo "  Evidence: Drop glue present at lower opt level(s) but absent here — sensitive type drop may be inlined or elided."
  any_diff=1
else
  echo "OK: Zeroize patterns and drop glue present at all opt levels analyzed."
fi

exit $any_diff
