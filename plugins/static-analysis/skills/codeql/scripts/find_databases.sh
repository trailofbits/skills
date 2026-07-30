#!/usr/bin/env bash
# Print every real CodeQL database under the given roots, one path per line.
#
#   find_databases.sh [root ...]      # defaults to "$OUTPUT_DIR" then "."
#
# Each markdown block runs in a fresh shell, so a bash array built by a discovery loop in
# one block is gone by the time another block reads it — `${#FOUND_DBS[@]}` comes back
# empty and the run concludes there is no database. Callers run this and build their own
# array from the output, in their own block.
#
# `codeql resolve database` is the filter that matters: `codeql database create` writes
# the codeql-database.yml marker before the build finishes, so a failed build leaves one
# behind and a bare `find` reports it as a database.
set -uo pipefail

if [ "$#" -eq 0 ]; then
  set -- "${OUTPUT_DIR:-.}" "."
fi

seen=""
for root in "$@"; do
  [ -d "$root" ] || continue
  # Resolve to an absolute physical path first. Callers pass "$OUTPUT_DIR" and ".", and
  # $OUTPUT_DIR is usually inside "." — searched as written, the same database surfaces
  # once as /abs/out/codeql.db and once as ./out/codeql.db, defeating the dedup below and
  # offering the user the same database twice.
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
