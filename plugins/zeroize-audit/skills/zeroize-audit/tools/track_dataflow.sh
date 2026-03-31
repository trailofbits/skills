#!/usr/bin/env bash
set -euo pipefail

# Track data-flow of sensitive variables to detect untracked copies.
#
# Usage:
#   track_dataflow.sh --src path/to/file.c --config config.yaml --out /tmp/dataflow.json
#
# Detects:
# - memcpy/memmove of sensitive buffers
# - Struct assignments (potential copies)
# - Function arguments passed by value
# - Return by value (secrets in return values)

usage() {
  echo "Usage: $0 --src <file> --out <analysis.json> [--config <config.yaml>]" >&2
}

json_escape() {
  local s="$1"
  s="${s//\\/\\\\}"
  s="${s//\"/\\\"}"
  s="${s//$'\n'/\\n}"
  s="${s//$'\t'/\\t}"
  printf '%s' "$s"
}

SRC=""
CONFIG=""
OUT=""

while [[ $# -gt 0 ]]; do
  case "$1" in
    --src)
      SRC="$2"
      shift 2
      ;;
    --config)
      CONFIG="$2"
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

if [[ -z "$SRC" || -z "$OUT" ]]; then
  usage
  exit 2
fi

if [[ ! -f "$SRC" ]]; then
  echo "Source file not found: $SRC" >&2
  exit 2
fi

# Load sensitive name patterns from config (if provided)
SENSITIVE_PATTERN="(secret|key|seed|priv|private|sk|shared_secret|nonce|token|pwd|pass)"
if [[ -n "$CONFIG" ]] && [[ -f "$CONFIG" ]]; then
  # Extract patterns from YAML (POSIX-compatible, no grep -P)
  PATTERNS=$(grep -A 20 "^sensitive_name_regex:" "$CONFIG" | sed -n 's/.*"\([^"]*\)".*/\1/p' | head -1 || echo "")
  if [[ -n "$PATTERNS" ]]; then
    SENSITIVE_PATTERN="$PATTERNS"
  else
    echo "WARNING: config file provided but no patterns extracted from $CONFIG" >&2
  fi
fi

# Arrays to collect findings
MEMCPY_COPIES=()
STRUCT_ASSIGNS=()
FUNC_ARGS=()
RETURN_VALUES=()
RETURN_RE='return[[:space:]]+([a-zA-Z_][a-zA-Z0-9_]*)[[:space:]]*;'
CALL_RE='([a-zA-Z_][a-zA-Z0-9_]*)[[:space:]]*\(([^)]*)\)'

# Parse source code
LINE_NUM=0
IN_FUNCTION=""

while IFS= read -r line; do
  ((LINE_NUM++))

  # Skip comments (simple heuristic)
  [[ "$line" =~ ^[[:space:]]*// ]] && continue
  [[ "$line" =~ ^[[:space:]]*\* ]] && continue

  # Track function boundaries
  if [[ "$line" =~ ^[a-zA-Z_][a-zA-Z0-9_]*[[:space:]]+([a-zA-Z_][a-zA-Z0-9_]*)[[:space:]]*\( ]]; then
    IN_FUNCTION="${BASH_REMATCH[1]}"
  fi

  # Detect memcpy/memmove of sensitive data
  if [[ "$line" =~ (memcpy|memmove)[[:space:]]*\([^,]*,[[:space:]]*([a-zA-Z_][a-zA-Z0-9_]*) ]]; then
    FUNC="${BASH_REMATCH[1]}"
    SRC_VAR="${BASH_REMATCH[2]}"
    if [[ "$SRC_VAR" =~ $SENSITIVE_PATTERN ]]; then
      MEMCPY_COPIES+=("{\"line\": $LINE_NUM, \"function\": \"$FUNC\", \"variable\": \"$SRC_VAR\", \"context\": \"$(json_escape "$line")\"}")
    fi
  fi

  # Detect struct assignments (potential copies)
  if [[ "$line" =~ ([a-zA-Z_][a-zA-Z0-9_]*)[[:space:]]*=[[:space:]]*\*([a-zA-Z_][a-zA-Z0-9_]*) ]]; then
    DEST="${BASH_REMATCH[1]}"
    MATCH_SRC="${BASH_REMATCH[2]}"
    if [[ "$MATCH_SRC" =~ $SENSITIVE_PATTERN ]] || [[ "$DEST" =~ $SENSITIVE_PATTERN ]]; then
      STRUCT_ASSIGNS+=("{\"line\": $LINE_NUM, \"dest\": \"$DEST\", \"source\": \"$MATCH_SRC\", \"context\": \"$(json_escape "$line")\"}")
    fi
  fi

  # Detect return by value
  if [[ "$line" =~ $RETURN_RE ]]; then
    RET_VAR="${BASH_REMATCH[1]}"
    if [[ "$RET_VAR" =~ $SENSITIVE_PATTERN ]]; then
      RETURN_VALUES+=("{\"line\": $LINE_NUM, \"function\": \"$IN_FUNCTION\", \"variable\": \"$RET_VAR\", \"context\": \"$(json_escape "$line")\"}")
    fi
  fi

  # Detect function calls with sensitive arguments (simple heuristic)
  if [[ "$line" =~ $CALL_RE ]]; then
    CALLED_FUNC="${BASH_REMATCH[1]}"
    ARGS="${BASH_REMATCH[2]}"
    # Check if any argument matches sensitive pattern
    if [[ "$ARGS" =~ $SENSITIVE_PATTERN ]]; then
      # Extract variable names from arguments
      for arg in ${ARGS//,/ }; do
        arg="${arg#"${arg%%[! ]*}"}" # trim leading spaces
        arg="${arg%"${arg##*[! ]}"}" # trim trailing spaces
        if [[ "$arg" =~ ^[a-zA-Z_][a-zA-Z0-9_]*$ ]] && [[ "$arg" =~ $SENSITIVE_PATTERN ]]; then
          FUNC_ARGS+=("{\"line\": $LINE_NUM, \"called_function\": \"$CALLED_FUNC\", \"argument\": \"$arg\", \"context\": \"$(json_escape "$line")\"}")
        fi
      done
    fi
  fi

done <"$SRC"

# Generate JSON report
mkdir -p "$(dirname "$OUT")"

cat >"$OUT" <<EOF
{
  "source_file": "$SRC",
  "sensitive_pattern": "$SENSITIVE_PATTERN",
  "findings": {
    "memcpy_copies": [
      $(
  IFS=,
  echo "${MEMCPY_COPIES[*]}"
)
    ],
    "struct_assignments": [
      $(
  IFS=,
  echo "${STRUCT_ASSIGNS[*]}"
)
    ],
    "function_arguments": [
      $(
  IFS=,
  echo "${FUNC_ARGS[*]}"
)
    ],
    "return_values": [
      $(
  IFS=,
  echo "${RETURN_VALUES[*]}"
)
    ]
  },
  "summary": {
    "total_copies": $((${#MEMCPY_COPIES[@]} + ${#STRUCT_ASSIGNS[@]} + ${#FUNC_ARGS[@]} + ${#RETURN_VALUES[@]})),
    "memcpy_count": ${#MEMCPY_COPIES[@]},
    "struct_assign_count": ${#STRUCT_ASSIGNS[@]},
    "func_arg_count": ${#FUNC_ARGS[@]},
    "return_value_count": ${#RETURN_VALUES[@]}
  }
}
EOF

# Validate JSON output
if command -v jq &>/dev/null; then
  if ! jq empty "$OUT" 2>/dev/null; then
    echo "ERROR: generated JSON is malformed: $OUT" >&2
    exit 1
  fi
fi

echo "OK: data-flow analysis written to $OUT"
