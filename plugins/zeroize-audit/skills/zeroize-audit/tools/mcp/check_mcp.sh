#!/usr/bin/env bash
set -euo pipefail

# Probe for Serena MCP server availability.
#
# Usage:
#   check_mcp.sh
#   check_mcp.sh --compile-db compile_commands.json

usage() {
  echo "Usage: $0 [--compile-db compile_commands.json]" >&2
}

COMPILE_DB=""

while [[ $# -gt 0 ]]; do
  case "$1" in
    --compile-db)
      COMPILE_DB="$2"
      shift 2
      ;;
    *)
      echo "Unknown arg: $1" >&2
      usage
      exit 2
      ;;
  esac
done

missing=()
if ! command -v "uvx" >/dev/null 2>&1; then
  missing+=("uvx")
fi

compile_db_status="not_checked"
if [[ -n "$COMPILE_DB" ]]; then
  if [[ -f "$COMPILE_DB" ]]; then
    compile_db_status="present"
  else
    compile_db_status="missing"
  fi
fi

if [[ ${#missing[@]} -eq 0 ]]; then
  cat <<EOF
{
  "mcp_available": true,
  "mcp_server": "serena",
  "uvx_present": true,
  "compile_db_status": "${compile_db_status}",
  "missing_tools": []
}
EOF
  exit 0
fi

missing_json=$(printf '"%s",' "${missing[@]}" | sed 's/,$//')

cat <<EOF
{
  "mcp_available": false,
  "mcp_server": "serena",
  "compile_db_status": "${compile_db_status}",
  "missing_tools": [${missing_json}],
  "message": "Serena MCP server unavailable (uvx not found); advanced findings must be downgraded to needs_review."
}
EOF
exit 1
