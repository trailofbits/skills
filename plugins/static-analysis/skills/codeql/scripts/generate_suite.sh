#!/usr/bin/env bash
# Write the query suite for one scan mode, and prove it resolves to at least one query.
#
#   generate_suite.sh run-all|important-only
#
# Reads OUTPUT_DIR, CODEQL_LANG, and INSTALLED_THIRD_PARTY_PACKS from the environment;
# writes $OUTPUT_DIR/raw/<mode>.qls.
#
# The modes differ only in header entries and include filters; everything else was
# duplicated across two reference docs, where `make shell` could not see it.
set -euo pipefail

MODE="${1:-}"
case "$MODE" in
  run-all | important-only) ;;
  *)
    echo "usage: generate_suite.sh run-all|important-only" >&2
    exit 2
    ;;
esac

# Before the first heredoc: unset, ${CODEQL_LANG} names the pack `codeql/-queries`, and the
# broken suite is on disk for a later step to pick up.
: "${CODEQL_LANG:?ERROR: CODEQL_LANG must be set before generating the suite}"
: "${OUTPUT_DIR:?ERROR: OUTPUT_DIR must be set}"
INSTALLED_THIRD_PARTY_PACKS="${INSTALLED_THIRD_PARTY_PACKS:-}"

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
RAW_DIR="$OUTPUT_DIR/raw"
mkdir -p "$RAW_DIR"
SUITE_FILE="$RAW_DIR/$MODE.qls"

# Unquoted heredocs here: ${CODEQL_LANG} must expand.
if [ "$MODE" = run-all ]; then
  cat >"$SUITE_FILE" <<HEADER
- description: Run-all — the security-and-quality and security-experimental suites from all installed packs, not every query in them; see run-all-suite.md
- import: codeql-suites/${CODEQL_LANG}-security-and-quality.qls
  from: codeql/${CODEQL_LANG}-queries
- import: codeql-suites/${CODEQL_LANG}-security-experimental.qls
  from: codeql/${CODEQL_LANG}-queries
HEADER
else
  cat >"$SUITE_FILE" <<HEADER
- description: Important-only — security vulnerabilities, medium-high confidence
- queries: .
  from: codeql/${CODEQL_LANG}-queries
HEADER
fi

# Word splitting is the point: the variable holds a space-separated pack list.
# shellcheck disable=SC2086
for PACK in $INSTALLED_THIRD_PARTY_PACKS; do
  cat >>"$SUITE_FILE" <<PACK_ENTRY
- queries: .
  from: ${PACK}
PACK_ENTRY
done

# Quoted heredocs below: these are literal, nothing to expand.
if [ "$MODE" = run-all ]; then
  # Minimal filtering — select alert queries and nothing else.
  cat >>"$SUITE_FILE" <<'FILTERS'
- include:
    kind:
      - problem
      - path-problem
FILTERS
else
  # Security tag required. High and very-high run at any severity; medium is narrowed
  # after the run by the security-severity filter in run-analysis Step 5.
  cat >>"$SUITE_FILE" <<'FILTERS'
- include:
    kind:
      - problem
      - path-problem
    precision:
      - high
      - very-high
    tags contain:
      - security
- include:
    kind:
      - problem
      - path-problem
    precision:
      - medium
    tags contain:
      - security
FILTERS
fi

cat >>"$SUITE_FILE" <<'SHARED_FILTERS'
- exclude:
    deprecated: //
- exclude:
    tags contain:
      - modeleditor
      - modelgenerator
SHARED_FILTERS

# Fails on zero resolved queries, a CodeQL error, or malformed output. Not
# `codeql resolve queries | wc -l`, which reports wc's status whatever CodeQL did.
#
# Delete an unverified suite: left on disk it is indistinguishable from a good one, and
# run-analysis Step 4 derives the same path and would pick it up.
if ! uv run "$SCRIPT_DIR/verify_query_suite.py" "$SUITE_FILE"; then
  rm -f "$SUITE_FILE"
  echo "Removed $SUITE_FILE: it did not resolve to any queries." >&2
  exit 1
fi

echo "Suite generated: $SUITE_FILE"
