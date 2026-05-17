#!/usr/bin/env bash
set -euo pipefail

SKILL_DIR="$(cd "$(dirname "$0")/../skills/ptest" && pwd)"
SKILL_MD="$SKILL_DIR/SKILL.md"
ERRORS=0

# Check frontmatter
head -5 "$SKILL_MD" | grep -q "^name:" || { echo "FAIL: Missing name field"; ERRORS=$((ERRORS+1)); }
head -5 "$SKILL_MD" | grep -q "^description:" || { echo "FAIL: Missing description field"; ERRORS=$((ERRORS+1)); }

# All required phase files must exist
PHASES="recon-passive recon-active enumeration attack-surface vuln-assessment exploit post-exploit report escalate-finding"
for phase in $PHASES; do
  if [ ! -f "$SKILL_DIR/references/$phase.md" ]; then
    echo "FAIL: Missing references/$phase.md"
    ERRORS=$((ERRORS+1))
  fi
done

if [ "$ERRORS" -gt 0 ]; then
  echo "FAILED: $ERRORS error(s)"
  exit 1
fi

echo "ptest: all checks passed ($(echo $PHASES | wc -w | tr -d ' ') phase files)"
