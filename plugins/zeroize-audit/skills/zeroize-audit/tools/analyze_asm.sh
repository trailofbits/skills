#!/usr/bin/env bash
set -euo pipefail

# Analyze assembly for secret exposure patterns.
#
# Usage:
#   analyze_asm.sh --asm path/to/file.s --symbol secret_func --out /tmp/analysis.json
#
# Detects:
# - Register spills to stack (movq/movdqa %reg, -offset(%rbp/%rsp))
# - Stack allocations that may retain secrets
# - Missing red-zone clearing
# - Secrets in callee-saved registers pushed to stack

usage() {
  echo "Usage: $0 --asm <file.s> --out <analysis.json> [--symbol <func_name>]" >&2
}

json_escape() {
  local s="$1"
  s="${s//\\/\\\\}"
  s="${s//\"/\\\"}"
  s="${s//$'\n'/\\n}"
  s="${s//$'\t'/\\t}"
  printf '%s' "$s"
}

ASM=""
SYMBOL=""
OUT=""

while [[ $# -gt 0 ]]; do
  case "$1" in
    --asm)
      ASM="$2"
      shift 2
      ;;
    --symbol)
      SYMBOL="$2"
      shift 2
      ;;
    --out)
      OUT="$2"
      shift 2
      ;;
    *)
      echo "Unknown arg: $1" >&2
      usage
      exit 2
      ;;
  esac
done

if [[ -z "$ASM" || -z "$OUT" ]]; then
  usage
  exit 2
fi

if [[ ! -f "$ASM" ]]; then
  echo "Assembly file not found: $ASM" >&2
  exit 2
fi

# Extract function boundaries if symbol specified
START_LINE=1
END_LINE=$(wc -l <"$ASM")

if [[ -n "$SYMBOL" ]]; then
  # Find function start/end
  START_LINE=$(grep -n "^${SYMBOL}:" "$ASM" | head -1 | cut -d: -f1 || echo "")
  if [[ -z "$START_LINE" ]]; then
    echo "WARNING: symbol '${SYMBOL}' not found in $ASM; analyzing full file" >&2
    START_LINE=1
  fi
  # Find next function or end of file
  END_LINE=$(tail -n +"$((START_LINE + 1))" "$ASM" | grep -n "^[a-zA-Z_][a-zA-Z0-9_]*:" | head -1 | cut -d: -f1 || echo "$(($(wc -l <"$ASM") - START_LINE + 1))")
  END_LINE=$((START_LINE + END_LINE - 1))
fi

# Extract function body
FUNC_ASM=$(sed -n "${START_LINE},${END_LINE}p" "$ASM")

# Detect patterns
REGISTER_SPILLS=()
STACK_STORES=()
CALLEE_SAVED_PUSHES=()
STACK_SIZE=0
RED_ZONE_CLEARED=false

# Parse assembly
while IFS= read -r line; do
  # Skip comments and empty lines
  [[ "$line" =~ ^[[:space:]]*# ]] && continue
  [[ -z "${line// /}" ]] && continue

  # Detect stack allocation (subq $size, %rsp)
  if [[ "$line" =~ subq[[:space:]]+\$([0-9]+),[[:space:]]*%rsp ]]; then
    STACK_SIZE="${BASH_REMATCH[1]}"
  fi

  # Detect register spills to stack (movq/movdqa/movaps %reg, -offset(%rsp/%rbp))
  if [[ "$line" =~ (movq|movdqa|movaps|movups|vmovdqa|vmovaps)[[:space:]]+%([a-z0-9]+),[[:space:]]*-([0-9]+)\(%(rsp|rbp)\) ]]; then
    REG="${BASH_REMATCH[2]}"
    OFFSET="${BASH_REMATCH[3]}"
    BASE="${BASH_REMATCH[4]}"
    REGISTER_SPILLS+=("{\"register\": \"$REG\", \"offset\": -$OFFSET, \"base\": \"$BASE\", \"line\": \"$(json_escape "$line")\"}")
  fi

  # Detect stores to stack (mov* reg/imm, -offset(%rsp/%rbp))
  if [[ "$line" =~ mov[a-z]*[[:space:]]+[^,]+,[[:space:]]*-([0-9]+)\(%(rsp|rbp)\) ]]; then
    OFFSET="${BASH_REMATCH[1]}"
    BASE="${BASH_REMATCH[2]}"
    STACK_STORES+=("{\"offset\": -$OFFSET, \"base\": \"$BASE\", \"line\": \"$(json_escape "$line")\"}")
  fi

  # Detect callee-saved register pushes (pushq %rbx/%r12/%r13/%r14/%r15/%rbp)
  if [[ "$line" =~ pushq[[:space:]]+%(rbx|r12|r13|r14|r15|rbp) ]]; then
    REG="${BASH_REMATCH[1]}"
    CALLEE_SAVED_PUSHES+=("{\"register\": \"$REG\", \"line\": \"$(json_escape "$line")\"}")
  fi

  # Detect red-zone clearing (movq $0, -offset(%rsp) for offset <= 128)
  if [[ "$line" =~ movq[[:space:]]+\$0,[[:space:]]*-([0-9]+)\(%rsp\) ]]; then
    OFFSET="${BASH_REMATCH[1]}"
    if [[ "$OFFSET" -le 128 ]]; then
      RED_ZONE_CLEARED=true
    fi
  fi

done <<<"$FUNC_ASM"

# Generate JSON report
mkdir -p "$(dirname "$OUT")"

cat >"$OUT" <<EOF
{
  "asm_file": "$ASM",
  "symbol": "$SYMBOL",
  "analysis": {
    "stack_size": $STACK_SIZE,
    "red_zone_cleared": $RED_ZONE_CLEARED,
    "register_spills": [
      $(
  IFS=,
  echo "${REGISTER_SPILLS[*]}"
)
    ],
    "stack_stores": [
      $(
  IFS=,
  echo "${STACK_STORES[*]}"
)
    ],
    "callee_saved_pushes": [
      $(
  IFS=,
  echo "${CALLEE_SAVED_PUSHES[*]}"
)
    ]
  },
  "warnings": []
}
EOF

# Validate JSON output
if command -v jq &>/dev/null; then
  if ! jq empty "$OUT" 2>/dev/null; then
    echo "ERROR: generated JSON is malformed: $OUT" >&2
    exit 1
  fi
fi

# Add warnings based on findings
WARNINGS=()

if [[ ${#REGISTER_SPILLS[@]} -gt 0 ]]; then
  WARNINGS+=("{\"type\": \"REGISTER_SPILL\", \"message\": \"Found ${#REGISTER_SPILLS[@]} register spill(s) to stack. Spilled values may contain secrets.\"}")
fi

if [[ $STACK_SIZE -gt 0 ]] && [[ "$RED_ZONE_CLEARED" == "false" ]]; then
  WARNINGS+=("{\"type\": \"STACK_RETENTION\", \"message\": \"Stack frame (${STACK_SIZE} bytes) may retain secrets after function return. Consider clearing red-zone.\"}")
fi

if [[ ${#CALLEE_SAVED_PUSHES[@]} -gt 0 ]]; then
  WARNINGS+=("{\"type\": \"CALLEE_SAVED_SPILL\", \"message\": \"Callee-saved registers pushed to stack. If they contain secrets, stack will retain them.\"}")
fi

# Update JSON with warnings
if [[ ${#WARNINGS[@]} -gt 0 ]]; then
  WARNINGS_JSON=$(
    IFS=,
    echo "${WARNINGS[*]}"
  )
  if command -v jq &>/dev/null; then
    TMP=$(mktemp)
    jq ".warnings = [$WARNINGS_JSON]" "$OUT" >"$TMP" && mv "$TMP" "$OUT"
  else
    echo "WARNING: jq not found; warnings could not be added to output" >&2
  fi
fi

echo "OK: assembly analysis written to $OUT"
