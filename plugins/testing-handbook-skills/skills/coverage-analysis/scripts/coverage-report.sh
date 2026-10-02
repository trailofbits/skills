#!/usr/bin/env bash
# coverage-report.sh — replay a corpus against an instrumented binary and write every report.
#
#   coverage-report.sh --binary FUZZ_EXEC --corpus DIR [--corpus DIR...] --out OUTDIR
#                      [--ignore REGEX] [--isolate] [--top N] [--no-html]
#
# Writes into OUTDIR (all of it is kept; the console prints only a summary):
#   profiles/*.profraw, merged.profdata      raw and merged LLVM profiles
#   coverage.json                             full `llvm-cov export` (files, functions, totals,
#                                             regions, branches) — the machine-readable record
#   coverage.lcov                             lcov export for genhtml / other tools
#   report.txt                                `llvm-cov report` per-file table
#   html/                                     `llvm-cov show -format=html` report
#   crashes.txt                               (--isolate only) one line per crashing input
#   summary.txt                               the console summary below
#
# Console summary: totals (lines/functions/regions/branches), the N least-covered functions
# (default 20), and the crash count. Query the rest with coverage-query.py; never read
# coverage.json or the HTML into a conversation.
#
# Tools: llvm-profdata and llvm-cov from PATH, or LLVM_PROFDATA/LLVM_COV, or `xcrun` on macOS.
set -euo pipefail

binary="" out="" ignore="" isolate=0 top=20 html=1
corpora=()
while [[ $# -gt 0 ]]; do
  case "$1" in
    --binary)
      binary=$2
      shift 2
      ;;
    --corpus)
      corpora+=("$2")
      shift 2
      ;;
    --out)
      out=$2
      shift 2
      ;;
    --ignore)
      ignore=$2
      shift 2
      ;;
    --isolate)
      isolate=1
      shift
      ;;
    --top)
      top=$2
      shift 2
      ;;
    --no-html)
      html=0
      shift
      ;;
    -h | --help)
      sed -n '2,24p' "$0"
      exit 0
      ;;
    *)
      echo "coverage-report.sh: unknown argument $1" >&2
      exit 2
      ;;
  esac
done
[[ -n $binary && -n $out && ${#corpora[@]} -gt 0 ]] || {
  echo "usage: coverage-report.sh --binary FUZZ_EXEC --corpus DIR [--corpus DIR...] --out OUTDIR [--ignore REGEX] [--isolate] [--top N] [--no-html]" >&2
  exit 2
}
[[ -x $binary ]] || {
  echo "coverage-report.sh: binary not executable: $binary" >&2
  exit 2
}
for c in "${corpora[@]}"; do
  [[ -d $c ]] || {
    echo "coverage-report.sh: corpus directory not found: $c" >&2
    exit 2
  }
done

find_tool() {
  local override=$1 name=$2
  if [[ -n ${!override:-} ]]; then
    echo "${!override}"
    return
  fi
  if command -v "$name" >/dev/null 2>&1; then
    command -v "$name"
    return
  fi
  if command -v xcrun >/dev/null 2>&1 && xcrun -f "$name" >/dev/null 2>&1; then
    xcrun -f "$name"
    return
  fi
  echo "coverage-report.sh: $name not found (install LLVM tools, or set $override)" >&2
  exit 2
}
profdata=$(find_tool LLVM_PROFDATA llvm-profdata)
llvmcov=$(find_tool LLVM_COV llvm-cov)

mkdir -p "$out/profiles"
rm -f "$out"/profiles/*.profraw "$out/crashes.txt"
status=0
if [[ $isolate -eq 1 ]]; then
  # %m: the profile runtime merges every child's counters into one file under a lock, so a
  # crashing child simply contributes nothing (plain %p is resolved once in the parent and the
  # children would overwrite each other).
  LLVM_PROFILE_FILE="$out/profiles/input-%m.profraw" "$binary" --isolate --crash-log "$out/crashes.txt" "${corpora[@]}" || status=$?
else
  LLVM_PROFILE_FILE="$out/profiles/corpus.profraw" "$binary" "${corpora[@]}" || status=$?
fi
if [[ $status -eq 2 || $status -eq 3 ]]; then
  echo "coverage-report.sh: the runtime did not replay the corpus (exit $status); no coverage was measured" >&2
  exit "$status"
fi
if [[ $isolate -eq 0 && $status -ne 0 ]]; then
  echo "coverage-report.sh: the binary exited with $status while replaying in-process; a crashing input probably lost the profile. Rerun with --isolate." >&2
  exit 4
fi
shopt -s nullglob
raws=("$out"/profiles/*.profraw)
shopt -u nullglob
[[ ${#raws[@]} -gt 0 ]] || {
  echo "coverage-report.sh: no .profraw written; is the binary built with -fprofile-instr-generate -fcoverage-mapping?" >&2
  exit 4
}
"$profdata" merge -sparse "${raws[@]}" -o "$out/merged.profdata"

ignore_args=()
[[ -n $ignore ]] && ignore_args=(-ignore-filename-regex="$ignore")
"$llvmcov" export "$binary" -instr-profile="$out/merged.profdata" ${ignore_args[@]+"${ignore_args[@]}"} >"$out/coverage.json"
"$llvmcov" export "$binary" -instr-profile="$out/merged.profdata" ${ignore_args[@]+"${ignore_args[@]}"} -format=lcov >"$out/coverage.lcov"
"$llvmcov" report "$binary" -instr-profile="$out/merged.profdata" ${ignore_args[@]+"${ignore_args[@]}"} >"$out/report.txt"
if [[ $html -eq 1 ]]; then
  rm -rf "$out/html"
  "$llvmcov" show "$binary" -instr-profile="$out/merged.profdata" ${ignore_args[@]+"${ignore_args[@]}"} -format=html -output-dir "$out/html" >/dev/null
fi

crashes=0
if [[ -f $out/crashes.txt ]]; then crashes=$(wc -l <"$out/crashes.txt" | tr -d ' '); fi
here=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
{
  echo "coverage report: $out"
  echo "binary: $binary"
  echo "corpus: ${corpora[*]}  (isolated replay: $([[ $isolate -eq 1 ]] && echo yes || echo no))"
  echo "crashing inputs: $crashes$([[ $crashes -gt 0 ]] && echo "  (listed in crashes.txt; their coverage is NOT included)")"
  echo
  uv run --no-project "$here/coverage-query.py" --json "$out/coverage.json" totals
  echo
  echo "least-covered functions (top $top; query the rest with coverage-query.py):"
  uv run --no-project "$here/coverage-query.py" --json "$out/coverage.json" functions --uncovered-first --limit "$top"
  echo
  echo "artifacts: coverage.json coverage.lcov report.txt$([[ $html -eq 1 ]] && echo " html/index.html") merged.profdata"
} | tee "$out/summary.txt"
exit 0
