#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")" && pwd)"
SCRIPT_DIR="$ROOT_DIR/../../skills/zeroize-audit/tools/scripts"
FIXTURES_DIR="$ROOT_DIR/fixtures"
OUT_DIR="$(mktemp -d "${TMPDIR:-/tmp}/zeroize-rust-regression-XXXXXXXX")"
trap 'rm -rf "$OUT_DIR"' EXIT
trap 'echo "run_smoke.sh: FAILED at line $LINENO" >&2' ERR

uv run "$SCRIPT_DIR/check_mir_patterns.py" \
  --mir "$FIXTURES_DIR/sample.mir" \
  --secrets "$FIXTURES_DIR/secrets.json" \
  --out "$OUT_DIR/mir-findings.json"

# Negative: clean MIR → 0 findings
uv run "$SCRIPT_DIR/check_mir_patterns.py" \
  --mir "$FIXTURES_DIR/sample_clean.mir" \
  --secrets "$FIXTURES_DIR/secrets.json" \
  --out "$OUT_DIR/mir-clean-findings.json"

uv run "$SCRIPT_DIR/check_llvm_patterns.py" \
  --o0 "$FIXTURES_DIR/sample.O0.ll" \
  --o1 "$FIXTURES_DIR/sample.O1.ll" \
  --o2 "$FIXTURES_DIR/sample.O2.ll" \
  --out "$OUT_DIR/ir-findings.json"

uv run "$SCRIPT_DIR/check_rust_asm.py" \
  --asm "$FIXTURES_DIR/sample.s" \
  --secrets "$FIXTURES_DIR/secrets.json" \
  --out "$OUT_DIR/asm-findings.json"

# AArch64 [EXPERIMENTAL]: separate fixture exercising AArch64 backend
uv run "$SCRIPT_DIR/check_rust_asm.py" \
  --asm "$FIXTURES_DIR/sample_aarch64.s" \
  --secrets "$FIXTURES_DIR/secrets.json" \
  --out "$OUT_DIR/asm-aarch64-findings.json"

# x86-64 leaf function: red-zone STACK_RETENTION
uv run "$SCRIPT_DIR/check_rust_asm.py" \
  --asm "$FIXTURES_DIR/sample_leaf_x86.s" \
  --secrets "$FIXTURES_DIR/secrets.json" \
  --out "$OUT_DIR/asm-leaf-findings.json"

# Negative: non-sensitive function → 0 ASM findings
uv run "$SCRIPT_DIR/check_rust_asm.py" \
  --asm "$FIXTURES_DIR/sample_clean.s" \
  --secrets "$FIXTURES_DIR/secrets.json" \
  --out "$OUT_DIR/asm-clean-findings.json"

# find_dangerous_apis.py: positive fixture (all B1–B10 patterns in sensitive context)
uv run "$SCRIPT_DIR/find_dangerous_apis.py" \
  --src "$FIXTURES_DIR/dangerous_apis_src" \
  --out "$OUT_DIR/dapi-pos-findings.json"

# find_dangerous_apis.py negative: no dangerous patterns → 0 findings
uv run "$SCRIPT_DIR/find_dangerous_apis.py" \
  --src "$FIXTURES_DIR/safe_src" \
  --out "$OUT_DIR/dapi-neg-findings.json"

# semantic_audit.py: positive fixture (PARTIAL_WIPE + MISSING_SOURCE_ZEROIZE)
uv run "$SCRIPT_DIR/semantic_audit.py" \
  --rustdoc "$FIXTURES_DIR/semantic_positive.rustdoc.json" \
  --cargo-toml "$FIXTURES_DIR/semantic_zeroize.Cargo.toml" \
  --out "$OUT_DIR/sem-pos-findings.json"

# semantic_audit.py negative: no sensitive types → 0 findings
uv run "$SCRIPT_DIR/semantic_audit.py" \
  --rustdoc "$FIXTURES_DIR/semantic_negative.rustdoc.json" \
  --out "$OUT_DIR/sem-neg-findings.json"

python3 - \
  "$OUT_DIR/mir-findings.json" \
  "$OUT_DIR/mir-clean-findings.json" \
  "$OUT_DIR/ir-findings.json" \
  "$OUT_DIR/asm-findings.json" \
  "$OUT_DIR/asm-aarch64-findings.json" \
  "$OUT_DIR/asm-leaf-findings.json" \
  "$OUT_DIR/asm-clean-findings.json" \
  "$OUT_DIR/dapi-pos-findings.json" \
  "$OUT_DIR/dapi-neg-findings.json" \
  "$OUT_DIR/sem-pos-findings.json" \
  "$OUT_DIR/sem-neg-findings.json" <<'PY'
import json
import sys


def load_json(path):
    try:
        with open(path) as f:
            return json.load(f)
    except FileNotFoundError:
        print(f"smoke: output file missing: {path}", file=sys.stderr)
        sys.exit(1)
    except json.JSONDecodeError as e:
        print(f"smoke: invalid JSON in {path}: {e}", file=sys.stderr)
        sys.exit(1)


(mir_path, mir_clean_path, ir_path,
 asm_path, asm_a64_path, asm_leaf_path, asm_clean_path,
 dapi_pos_path, dapi_neg_path,
 sem_pos_path, sem_neg_path) = sys.argv[1:]

mir       = load_json(mir_path)
mir_clean = load_json(mir_clean_path)
ir        = load_json(ir_path)
asm       = load_json(asm_path)
a64       = load_json(asm_a64_path)
asm_leaf  = load_json(asm_leaf_path)
asm_clean = load_json(asm_clean_path)
dapi_pos  = load_json(dapi_pos_path)
dapi_neg  = load_json(dapi_neg_path)
sem_pos   = load_json(sem_pos_path)
sem_neg   = load_json(sem_neg_path)

def categories(rows):
    return {row.get("category") for row in rows if isinstance(row, dict)}

mir_cats      = categories(mir)
ir_cats       = categories(ir)
asm_cats      = categories(asm)
a64_cats      = categories(a64)
asm_leaf_cats = categories(asm_leaf)
dapi_pos_cats = categories(dapi_pos)
sem_pos_cats  = categories(sem_pos)

# ---------------------------------------------------------------------------
# Minimum count assertions (guard against silent detector regressions)
# ---------------------------------------------------------------------------
assert len(mir) >= 5, f"MIR smoke: expected >= 5 findings, got {len(mir)}"
assert len(ir) >= 4, f"IR smoke: expected >= 4 findings, got {len(ir)}"
assert len(asm) >= 2, f"ASM smoke: expected >= 2 findings, got {len(asm)}"
assert len(a64) >= 2, f"AArch64 smoke: expected >= 2 findings, got {len(a64)}"
assert len(asm_leaf) >= 1, f"ASM leaf smoke: expected >= 1 findings, got {len(asm_leaf)}"
assert len(dapi_pos) >= 10, f"DangerousAPI smoke: expected >= 10 findings, got {len(dapi_pos)}"
assert len(sem_pos) >= 2, f"Semantic smoke: expected >= 2 findings, got {len(sem_pos)}"

# ---------------------------------------------------------------------------
# MIR assertions
# ---------------------------------------------------------------------------

# MIR: closure capture of sensitive local → SECRET_COPY
assert "SECRET_COPY" in mir_cats, f"MIR smoke: expected SECRET_COPY, got: {mir_cats}"
# MIR: yield + Err path + drop without StorageDead → NOT_ON_ALL_PATHS
assert "NOT_ON_ALL_PATHS" in mir_cats, f"MIR smoke: expected NOT_ON_ALL_PATHS, got: {mir_cats}"
# MIR: drop_in_place_secret lacks zeroize call → MISSING_SOURCE_ZEROIZE
assert "MISSING_SOURCE_ZEROIZE" in mir_cats, f"MIR smoke: expected MISSING_SOURCE_ZEROIZE, got: {mir_cats}"

# MIR: resume/unwind path with sensitive local → MISSING_SOURCE_ZEROIZE (medium)
assert any(
    r.get("category") == "MISSING_SOURCE_ZEROIZE" and "resume" in (r.get("detail") or "").lower()
    for r in mir
), "MIR smoke: expected MISSING_SOURCE_ZEROIZE for resume/unwind path"
# MIR: medium-severity branch (drop without return keyword)
assert any(
    r.get("severity") == "medium" and r.get("category") == "MISSING_SOURCE_ZEROIZE"
    for r in mir
), "MIR smoke: expected medium-severity MISSING_SOURCE_ZEROIZE"
# MIR: aggregate move of secret into non-Zeroizing type → SECRET_COPY (medium)
assert any(
    r.get("category") == "SECRET_COPY" and "PlainBuffer" in (r.get("detail") or "")
    for r in mir
), "MIR smoke: expected SECRET_COPY from aggregate move into non-Zeroizing type"
# MIR: FFI call with secret local → SECRET_COPY (high)
assert any(
    r.get("category") == "SECRET_COPY" and "ffi" in (r.get("detail") or "").lower()
    for r in mir
), "MIR smoke: expected SECRET_COPY from FFI call with secret argument"

# MIR negative: no sensitive names → 0 findings
assert len(mir_clean) == 0, \
    f"MIR negative smoke: expected 0 findings for clean fixture, got {len(mir_clean)}: {mir_clean}"

# ---------------------------------------------------------------------------
# LLVM IR assertions
# ---------------------------------------------------------------------------

# IR: volatile store count drops O0→O2 and non-volatile memset at O2 → OPTIMIZED_AWAY_ZEROIZE
assert "OPTIMIZED_AWAY_ZEROIZE" in ir_cats, f"IR smoke: expected OPTIMIZED_AWAY_ZEROIZE, got: {ir_cats}"
# IR: %secret_val loaded and passed to @callee / returned → REGISTER_SPILL
assert "REGISTER_SPILL" in ir_cats, f"IR smoke: expected REGISTER_SPILL, got: {ir_cats}"
# IR: severity check — these are value-in-register findings → medium
assert any(r.get("severity") == "medium" for r in ir if r.get("category") == "REGISTER_SPILL"), \
    "IR smoke: expected medium-severity REGISTER_SPILL for value-in-register findings"
# IR: by-value aggregate argument passing → SECRET_COPY
assert "SECRET_COPY" in ir_cats, f"IR smoke: expected SECRET_COPY from by-value aggregate pass, got: {ir_cats}"
# IR: alloca with lifetime.end but no volatile store → STACK_RETENTION
assert "STACK_RETENTION" in ir_cats, \
    f"IR smoke: expected STACK_RETENTION from alloca+lifetime.end without volatile store, got: {ir_cats}"

# ---------------------------------------------------------------------------
# x86-64 ASM assertions
# ---------------------------------------------------------------------------

# x86-64 ASM: %r12 (callee-saved) spilled in SecretKey_wipe → REGISTER_SPILL (high)
assert "REGISTER_SPILL" in asm_cats, f"ASM smoke: expected REGISTER_SPILL, got: {asm_cats}"
assert any(r.get("severity") == "high" for r in asm if r.get("category") == "REGISTER_SPILL"), \
    "ASM smoke: expected high-severity callee-saved spill"
# x86-64 ASM: subq $64,%rsp + retq + no zero-stores → STACK_RETENTION
assert "STACK_RETENTION" in asm_cats, f"ASM smoke: expected STACK_RETENTION, got: {asm_cats}"

# x86-64 leaf ASM: red-zone usage without zeroing → STACK_RETENTION
assert "STACK_RETENTION" in asm_leaf_cats, \
    f"x86 leaf smoke: expected STACK_RETENTION for red-zone usage, got: {asm_leaf_cats}"

# ASM negative: non-sensitive function → 0 findings
assert len(asm_clean) == 0, \
    f"ASM negative smoke: expected 0 findings for clean fixture, got {len(asm_clean)}: {asm_clean}"

# ---------------------------------------------------------------------------
# AArch64 ASM assertions
# ---------------------------------------------------------------------------

# AArch64 ASM [EXPERIMENTAL]: stp x29/x30 frame + no str xzr → STACK_RETENTION
assert "STACK_RETENTION" in a64_cats, f"AArch64 smoke: expected STACK_RETENTION, got: {a64_cats}"
# AArch64 ASM [EXPERIMENTAL]: str x19 (callee-saved) → REGISTER_SPILL (high, x19-specific)
assert "REGISTER_SPILL" in a64_cats, f"AArch64 smoke: expected REGISTER_SPILL, got: {a64_cats}"
assert any(
    r.get("severity") == "high" and "x19" in (r.get("detail") or "")
    for r in a64 if r.get("category") == "REGISTER_SPILL"
), "AArch64 smoke: expected high-severity REGISTER_SPILL specifically for x19 callee-saved"

# ---------------------------------------------------------------------------
# find_dangerous_apis.py assertions
# ---------------------------------------------------------------------------

# B1: mem::forget
assert any(
    "forget" in (r.get("detail") or "").lower() for r in dapi_pos
), "DangerousAPI smoke: expected mem::forget finding"
# B2: ManuallyDrop::new
assert any(
    "manuallydrop" in (r.get("detail") or "").lower() for r in dapi_pos
), "DangerousAPI smoke: expected ManuallyDrop::new finding"
# B3: Box::leak
assert any(
    "leak" in (r.get("detail") or "").lower() for r in dapi_pos
), "DangerousAPI smoke: expected Box::leak finding"
# B4: mem::uninitialized
assert any(
    "uninitialized" in (r.get("detail") or "").lower() for r in dapi_pos
), "DangerousAPI smoke: expected mem::uninitialized finding"
# B5: Box::into_raw
assert any(
    "into_raw" in (r.get("detail") or "").lower() for r in dapi_pos
), "DangerousAPI smoke: expected Box::into_raw finding"
# B6: ptr::write_bytes
assert any(
    r.get("category") == "OPTIMIZED_AWAY_ZEROIZE"
    and "write_bytes" in (r.get("detail") or "").lower() for r in dapi_pos
), "DangerousAPI smoke: expected OPTIMIZED_AWAY_ZEROIZE for ptr::write_bytes"
# B7: mem::transmute
assert any(
    "transmute" in (r.get("detail") or "").lower() for r in dapi_pos
), "DangerousAPI smoke: expected mem::transmute finding"
# B8: mem::take
assert any(
    "take" in (r.get("detail") or "").lower() for r in dapi_pos
), "DangerousAPI smoke: expected mem::take finding"
# B9: slice::from_raw_parts
assert any(
    "from_raw_parts" in (r.get("detail") or "").lower() for r in dapi_pos
), "DangerousAPI smoke: expected slice::from_raw_parts finding"
# B10: async .await with secret local
assert any(
    r.get("category") == "NOT_ON_ALL_PATHS"
    and "await" in (r.get("detail") or "").lower() for r in dapi_pos
), "DangerousAPI smoke: expected NOT_ON_ALL_PATHS for async .await"

# Negative: no dangerous patterns → 0 findings
assert len(dapi_neg) == 0, \
    f"DangerousAPI negative smoke: expected 0 findings, got {len(dapi_neg)}: {dapi_neg}"

# ---------------------------------------------------------------------------
# semantic_audit.py assertions
# ---------------------------------------------------------------------------

# Positive: Drop impl with unverified body → PARTIAL_WIPE
assert "PARTIAL_WIPE" in sem_pos_cats, \
    f"Semantic smoke: expected PARTIAL_WIPE, got: {sem_pos_cats}"
# Positive: SecretToken has no Drop/Zeroize → MISSING_SOURCE_ZEROIZE
assert "MISSING_SOURCE_ZEROIZE" in sem_pos_cats, \
    f"Semantic smoke: expected MISSING_SOURCE_ZEROIZE, got: {sem_pos_cats}"

# Negative: PublicData has no sensitive name → 0 findings
assert len(sem_neg) == 0, \
    f"Semantic negative smoke: expected 0 findings for clean fixture, got {len(sem_neg)}: {sem_neg}"

print("Rust regression smoke checks passed.")
PY
