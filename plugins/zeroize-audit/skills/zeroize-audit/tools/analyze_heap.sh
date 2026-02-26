#!/usr/bin/env bash
set -euo pipefail

# Analyze heap allocations for security issues with sensitive data.
#
# Usage:
#   analyze_heap.sh --src path/to/file.c --config config.yaml --out /tmp/heap_analysis.json
#
# Detects:
# - malloc/calloc/realloc for sensitive variables (should use secure allocators)
# - Missing mlock/madvise for sensitive heaps
# - Secure allocator usage (approved patterns)

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

# Load patterns from config
SENSITIVE_PATTERN="(secret|key|seed|priv|private|sk|shared_secret|nonce|token|pwd|pass)"
SECURE_ALLOC_FUNCS="(OPENSSL_secure_malloc|OPENSSL_secure_zalloc|sodium_malloc|sodium_allocarray|SecureAlloc)"

if [[ -n "$CONFIG" ]] && [[ -f "$CONFIG" ]]; then
  # Extract patterns from YAML (POSIX-compatible, no grep -P)
  SENS_PAT=$(grep -A 20 "^sensitive_name_regex:" "$CONFIG" | sed -n 's/.*"\([^"]*\)".*/\1/p' | head -1 || echo "")
  if [[ -n "$SENS_PAT" ]]; then
    SENSITIVE_PATTERN="$SENS_PAT"
  fi

  SEC_FUNCS=$(grep -A 20 "^secure_heap_alloc_funcs:" "$CONFIG" | sed -n 's/.*- "\([^"]*\)".*/\1/p' | tr '\n' '|' | sed 's/|$//')
  if [[ -n "$SEC_FUNCS" ]]; then
    SECURE_ALLOC_FUNCS="($SEC_FUNCS)"
  elif [[ -z "$SENS_PAT" ]]; then
    echo "WARNING: config file provided but no patterns extracted from $CONFIG" >&2
  fi
fi

# Arrays to collect findings
INSECURE_ALLOCS=()
SECURE_ALLOCS=()
MISSING_MLOCK=()
MISSING_MADVISE=()
MADVISE_RE='madvise[[:space:]]*\(([a-zA-Z_][a-zA-Z0-9_]*)[^)]*MADV_(DONTDUMP|DONTFORK|WIPEONFORK)'

# Track allocated pointers to check for mlock/madvise
declare -A ALLOCATED_PTRS

LINE_NUM=0

while IFS= read -r line; do
  ((LINE_NUM++))

  # Skip comments
  [[ "$line" =~ ^[[:space:]]*// ]] && continue
  [[ "$line" =~ ^[[:space:]]*\* ]] && continue

  # Detect insecure allocations
  if [[ "$line" =~ ([a-zA-Z_][a-zA-Z0-9_]*)[[:space:]]*=[[:space:]]*(malloc|calloc|realloc)[[:space:]]*\( ]]; then
    PTR="${BASH_REMATCH[1]}"
    ALLOC_FUNC="${BASH_REMATCH[2]}"

    if [[ "$PTR" =~ $SENSITIVE_PATTERN ]]; then
      INSECURE_ALLOCS+=("{\"line\": $LINE_NUM, \"pointer\": \"$PTR\", \"allocator\": \"$ALLOC_FUNC\", \"severity\": \"high\", \"context\": \"$(json_escape "$line")\"}")
      ALLOCATED_PTRS["$PTR"]="insecure:$LINE_NUM"
    fi
  fi

  # Detect secure allocations
  if [[ "$line" =~ ([a-zA-Z_][a-zA-Z0-9_]*)[[:space:]]*=[[:space:]]*($SECURE_ALLOC_FUNCS)[[:space:]]*\( ]]; then
    PTR="${BASH_REMATCH[1]}"
    ALLOC_FUNC="${BASH_REMATCH[2]}"

    SECURE_ALLOCS+=("{\"line\": $LINE_NUM, \"pointer\": \"$PTR\", \"allocator\": \"$ALLOC_FUNC\", \"context\": \"$(json_escape "$line")\"}")
    ALLOCATED_PTRS["$PTR"]="secure:$LINE_NUM"
  fi

  # Detect mlock usage
  if [[ "$line" =~ mlock[2]?[[:space:]]*\(([a-zA-Z_][a-zA-Z0-9_]*) ]]; then
    PTR="${BASH_REMATCH[1]}"
    if [[ -n "${ALLOCATED_PTRS[$PTR]:-}" ]]; then
      ALLOCATED_PTRS["$PTR"]="${ALLOCATED_PTRS[$PTR]}:mlocked"
    fi
  fi

  # Detect madvise usage
  if [[ "$line" =~ $MADVISE_RE ]]; then
    PTR="${BASH_REMATCH[1]}"
    if [[ -n "${ALLOCATED_PTRS[$PTR]:-}" ]]; then
      ALLOCATED_PTRS["$PTR"]="${ALLOCATED_PTRS[$PTR]}:madvised"
    fi
  fi

done <"$SRC"

# Check for missing protections
for PTR in "${!ALLOCATED_PTRS[@]}"; do
  INFO="${ALLOCATED_PTRS[$PTR]}"

  if [[ "$INFO" =~ ^insecure: ]]; then
    LINE="${INFO#insecure:}"
    LINE="${LINE%%:*}"

    if [[ ! "$INFO" =~ mlocked ]]; then
      MISSING_MLOCK+=("{\"line\": $LINE, \"pointer\": \"$PTR\", \"recommendation\": \"Add mlock() to prevent swapping to disk\"}")
    fi

    if [[ ! "$INFO" =~ madvised ]]; then
      MISSING_MADVISE+=("{\"line\": $LINE, \"pointer\": \"$PTR\", \"recommendation\": \"Add madvise(MADV_DONTDUMP) to exclude from core dumps\"}")
    fi
  fi
done

# Generate JSON report
mkdir -p "$(dirname "$OUT")"

cat >"$OUT" <<EOF
{
  "source_file": "$SRC",
  "findings": {
    "insecure_allocations": [
      $(
  IFS=,
  echo "${INSECURE_ALLOCS[*]}"
)
    ],
    "secure_allocations": [
      $(
  IFS=,
  echo "${SECURE_ALLOCS[*]}"
)
    ],
    "missing_mlock": [
      $(
  IFS=,
  echo "${MISSING_MLOCK[*]}"
)
    ],
    "missing_madvise": [
      $(
  IFS=,
  echo "${MISSING_MADVISE[*]}"
)
    ]
  },
  "summary": {
    "insecure_alloc_count": ${#INSECURE_ALLOCS[@]},
    "secure_alloc_count": ${#SECURE_ALLOCS[@]},
    "missing_protection_count": $((${#MISSING_MLOCK[@]} + ${#MISSING_MADVISE[@]}))
  },
  "recommendations": [
    "Replace malloc/calloc/realloc with OPENSSL_secure_malloc/sodium_malloc for sensitive data",
    "Use mlock() to prevent sensitive memory from being swapped to disk",
    "Use madvise(MADV_DONTDUMP) to exclude sensitive memory from core dumps",
    "Use madvise(MADV_WIPEONFORK) to zero memory in child processes after fork"
  ]
}
EOF

# Validate JSON output
if command -v jq &>/dev/null; then
  if ! jq empty "$OUT" 2>/dev/null; then
    echo "ERROR: generated JSON is malformed: $OUT" >&2
    exit 1
  fi
fi

echo "OK: heap analysis written to $OUT"
