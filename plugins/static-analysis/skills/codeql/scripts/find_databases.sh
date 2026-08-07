#!/usr/bin/env bash
# Print every real CodeQL database under the given roots, one path per line.
#
#   find_databases.sh [root ...]      # defaults to "$OUTPUT_DIR" then "."
#
# Callers build their own array from this output, in their own block: an array does not
# survive into a later Bash call, and an empty one reads as "no database".
#
# `codeql resolve database` is the filter that matters. The codeql-database.yml marker is
# written before the build finishes, so a failed build leaves one a bare `find` would take.
set -uo pipefail

if [ "$#" -eq 0 ]; then
  set -- "${OUTPUT_DIR:-.}" "."
fi

seen=""
for root in "$@"; do
  [ -d "$root" ] || continue
  # Absolute physical path first: $OUTPUT_DIR is usually inside ".", so searched as written
  # one database surfaces twice under two spellings and defeats the dedup below.
  root=$(cd "$root" 2>/dev/null && pwd -P) || continue
  while IFS= read -r marker; do
    db=$(dirname "$marker")
    case "$seen" in
      *"|$db|"*) continue ;;
    esac
    if codeql resolve database -- "$db" >/dev/null 2>&1; then
      seen="$seen|$db|"
      printf '%s\n' "$db"
    fi
  done < <(find "$root" -maxdepth 3 -name codeql-database.yml -not -path '*/.*' 2>/dev/null)
done
