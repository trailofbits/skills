#!/usr/bin/env bash
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/../../../.." && pwd)"

PHASE1="$REPO_ROOT/plugins/zeroize-audit/skills/zeroize-audit/workflows/phase-1-source-analysis.md"
PHASE2="$REPO_ROOT/plugins/zeroize-audit/skills/zeroize-audit/workflows/phase-2-compiler-analysis.md"
ASSEMBLER="$REPO_ROOT/plugins/zeroize-audit/agents/4-report-assembler.md"

python3 - "$PHASE1" "$PHASE2" "$ASSEMBLER" <<'PY'
import pathlib
import sys

try:
    phase1 = pathlib.Path(sys.argv[1]).read_text()
    phase2 = pathlib.Path(sys.argv[2]).read_text()
    assembler = pathlib.Path(sys.argv[3]).read_text()
except FileNotFoundError as e:
    print(f"Error: {e}", file=sys.stderr)
    sys.exit(1)

assert "Wave 2a" in phase1 and "Wave 2b" in phase1, "Phase 1 missing parallel source waves"
assert "Wave 3" in phase2 and "Wave 3R" in phase2, "Phase 2 missing mixed-language compiler waves"
assert "rust-compiler-analysis/" in assembler, "Report assembler missing Rust compiler ingestion"
assert "F-RUST-MIR-NNNN" in assembler and "F-RUST-IR-NNNN" in assembler and "F-RUST-ASM-NNNN" in assembler, \
    "Report assembler missing Rust namespace mappings"

print("Mixed-language orchestration smoke checks passed.")
PY
