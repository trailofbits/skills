#!/usr/bin/env bash
set -euo pipefail

SKILL_DIR="$(cd "$(dirname "$0")/../skills/offsec-reference" && pwd)"
SKILL_MD="$SKILL_DIR/SKILL.md"
ERRORS=0

# Check frontmatter
head -5 "$SKILL_MD" | grep -q "^name:" || { echo "FAIL: Missing name field"; ERRORS=$((ERRORS+1)); }
head -5 "$SKILL_MD" | grep -q "^description:" || { echo "FAIL: Missing description field"; ERRORS=$((ERRORS+1)); }

# Every file/dir in the routing table must exist in references/
# Table rows start with "| `filename`"
grep -oE '^\| `[a-z0-9-]+\.md`|^\| `[a-z0-9-]+/`' "$SKILL_MD" | grep -oE '[a-z0-9-]+\.md|[a-z0-9-]+/' | while read -r ref; do
  if [ ! -e "$SKILL_DIR/references/$ref" ]; then
    echo "FAIL: Missing references/$ref"
    exit 1
  fi
done || ERRORS=$((ERRORS+1))

# Count total reference items
REF_COUNT=$(find "$SKILL_DIR/references" -maxdepth 1 \( -name "*.md" -o -type d \) ! -path "$SKILL_DIR/references" | wc -l | tr -d ' ')

if [ "$ERRORS" -gt 0 ]; then
  echo "FAILED: $ERRORS error(s)"
  exit 1
fi

echo "offsec-reference: all checks passed ($REF_COUNT reference items)"
