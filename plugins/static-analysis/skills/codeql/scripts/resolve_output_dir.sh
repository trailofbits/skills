#!/usr/bin/env bash
# Resolve the one directory used by a CodeQL run.
# Usage: resolve_output_dir.sh [requested-directory]
set -euo pipefail

if [[ ${1:-} == "-h" || ${1:-} == "--help" ]]; then
  echo "usage: resolve_output_dir.sh [requested-directory]"
  exit 0
fi

requested=${1:-}
if [[ -n "$requested" ]]; then
  output_dir=$requested
else
  base=static_analysis_codeql
  index=1
  while [[ -e "${base}_${index}" ]]; do
    ((index += 1))
  done
  output_dir="${base}_${index}"
fi

mkdir -p "$output_dir"
cd "$output_dir"
pwd -P
