#!/usr/bin/env python3
# /// script
# requires-python = ">=3.11"
# dependencies = []
# ///
"""
check_llvm_patterns.py — LLVM IR comparison for Rust dead-store-elimination findings.

Reads LLVM IR files emitted by emit_rust_ir.sh (required: O0 and O2; optional: O1/O3) and detects:
- Volatile store count drop O0→O2  (OPTIMIZED_AWAY_ZEROIZE)
- Non-volatile llvm.memset on secret-sized range  (OPTIMIZED_AWAY_ZEROIZE)
- alloca with @llvm.lifetime.end but no store volatile  (STACK_RETENTION)
- Secret alloca present at O0 but absent at O2 (SROA/mem2reg)  (OPTIMIZED_AWAY_ZEROIZE)
- Secret value in argument registers at call site  (REGISTER_SPILL)

Usage:
    uv run check_llvm_patterns.py --o0 <file.O0.ll> --o2 <file.O2.ll> --out <findings.json>
    uv run check_llvm_patterns.py \
        --o0 <file.O0.ll> --o1 <file.O1.ll> --o2 <file.O2.ll> --o3 <file.O3.ll> \
        --out <findings.json>

Exit codes:
    0  — ran successfully (findings may be empty)
    1  — input file not found
    2  — argument error
"""

import argparse
import json
import re
import sys
from pathlib import Path

# ---------------------------------------------------------------------------
# Secret-sized alloca sizes (bytes) — common cryptographic key sizes
# ---------------------------------------------------------------------------

SECRET_ALLOCA_SIZES = {16, 24, 32, 48, 64, 96, 128}

# Sensitive variable name pattern (matches LLVM SSA names)
SENSITIVE_SSA_RE = re.compile(
    r"(?i)%(\w*(?:key|secret|password|token|nonce|seed|priv|master|credential)\w*)"
)

# ---------------------------------------------------------------------------
# Finding counter
# ---------------------------------------------------------------------------

_finding_counter = [0]


def make_finding(
    category: str,
    severity: str,
    detail: str,
    file: str,
    line: int,
    symbol: str = "",
    confidence: str = "likely",
) -> dict:
    _finding_counter[0] += 1
    fid = f"F-RUST-IR-{_finding_counter[0]:04d}"
    return {
        "id": fid,
        "language": "rust",
        "category": category,
        "severity": severity,
        "confidence": confidence,
        "detail": detail,
        "symbol": symbol,
        "location": {"file": file, "line": line},
        "evidence": [{"source": "llvm_ir", "detail": detail}],
    }


# ---------------------------------------------------------------------------
# IR helpers
# ---------------------------------------------------------------------------


def count_volatile_stores(ir_text: str) -> int:
    return len(re.findall(r"\bstore volatile\b", ir_text))


def extract_volatile_stores_by_target(ir_text: str) -> dict[str, int]:
    """
    Return volatile-store counts keyed by the destination symbol.
    Example matches:
      store volatile i8 0, ptr %key
      store volatile i32 0, i32* %buf
    """
    stores: dict[str, int] = {}
    vol_re = re.compile(r"\bstore volatile\b[^,]*,\s*(?:ptr|i\d+\*)\s+%([\w\.\-]+)")
    for m in vol_re.finditer(ir_text):
        name = m.group(1)
        stores[name] = stores.get(name, 0) + 1
    return stores


def extract_allocas(ir_text: str) -> dict[str, int]:
    """
    Return {alloca_name: size_bytes} for fixed-size byte array allocas.
    Matches: %name = alloca [N x i8]
    """
    alloca_re = re.compile(r"%(\w+)\s*=\s*alloca\s+\[(\d+)\s*x\s*i8\]")
    allocas: dict[str, int] = {}
    for m in alloca_re.finditer(ir_text):
        allocas[m.group(1)] = int(m.group(2))
    return allocas


def extract_lifetime_ends(ir_text: str) -> set[str]:
    """Return set of alloca names referenced in @llvm.lifetime.end calls."""
    lifetime_re = re.compile(r"call void @llvm\.lifetime\.end[^(]*\([^,]+,\s*(?:ptr|i8\*)\s+%(\w+)")
    return {m.group(1) for m in lifetime_re.finditer(ir_text)}


def extract_volatile_store_targets(ir_text: str) -> set[str]:
    """Return set of symbols that receive volatile stores."""
    return set(extract_volatile_stores_by_target(ir_text).keys())


def find_nonvolatile_memsets(ir_text: str) -> list[tuple[int, str]]:
    """
    Return (lineno, line) for non-volatile @llvm.memset calls.
    Volatile variant is @llvm.memset.element.unordered.atomic or has i1 true volatile flag.
    """
    results: list[tuple[int, str]] = []
    memset_re = re.compile(r"call void @llvm\.memset\.")
    volatile_flag_re = re.compile(r"i1\s+true")  # old-style volatile flag in args

    for lineno, line in enumerate(ir_text.splitlines(), start=1):
        if not memset_re.search(line):
            continue
        # Skip if it's the volatile atomic variant
        if "unordered.atomic" in line:
            continue
        # Skip if volatile flag (i1 true) is present in args
        if volatile_flag_re.search(line):
            continue
        results.append((lineno, line.strip()))
    return results


def find_secret_returns(ir_text: str) -> list[tuple[int, str]]:
    """
    Detect returns of secret-named SSA values.
    Returns (lineno, symbol_without_percent).
    """
    results: list[tuple[int, str]] = []
    ret_re = re.compile(
        r"\bret\s+[^%]*%(\w*(?:key|secret|password|token|nonce|seed|priv|master|credential)\w*)",
        re.IGNORECASE,
    )
    for lineno, line in enumerate(ir_text.splitlines(), start=1):
        m = ret_re.search(line)
        if m:
            results.append((lineno, m.group(1)))
    return results


def find_secret_aggregate_passes(ir_text: str) -> list[tuple[int, str]]:
    """
    Detect call sites that appear to pass aggregate values containing secret-named
    symbols by value. This is heuristic and intentionally conservative.
    Returns (lineno, argument_snippet).
    """
    results: list[tuple[int, str]] = []
    call_re = re.compile(r"\bcall\s+\S+\s+@\w+\s*\(([^)]*)\)")
    for lineno, line in enumerate(ir_text.splitlines(), start=1):
        m = call_re.search(line)
        if not m:
            continue
        args = m.group(1)
        if re.search(
            r"%\w*(?:key|secret|password|token|nonce|seed|priv|master|credential)\w*",
            args,
            re.IGNORECASE,
        ) and ("{" in args or "byval" in args):
            results.append((lineno, args[:120]))
    return results


def find_arg_load_calls(ir_text: str) -> list[tuple[int, str, str]]:
    """
    Detect: %secret_val = load ... %secret_alloca  followed by a call that uses %secret_val.
    Returns (lineno, varname, callee).
    """
    results: list[tuple[int, str, str]] = []
    lines = ir_text.splitlines()

    load_re = re.compile(
        r"(%\w*(?:key|secret|password|token|nonce|seed)\w*)\s*=\s*load\b", re.IGNORECASE
    )
    call_re = re.compile(r"call\s+\S+\s+(@\w+)\s*\(([^)]*)\)")

    loaded_vars: dict[str, int] = {}  # varname → lineno
    define_re = re.compile(r"^define\s")

    for lineno, line in enumerate(lines, start=1):
        # Reset tracked loads at each LLVM IR function boundary to avoid
        # cross-function false positives (I17).
        if define_re.match(line):
            loaded_vars.clear()
            continue

        # Track loads of sensitive-named SSA values
        m = load_re.search(line)
        if m:
            loaded_vars[m.group(1)] = lineno
            continue

        # Check call sites
        mc = call_re.search(line)
        if not mc:
            continue
        callee = mc.group(1)
        if "zeroize" in callee.lower() or "memset" in callee.lower():
            continue
        args = mc.group(2)
        for varname, _load_lineno in loaded_vars.items():
            if varname in args:
                results.append((lineno, varname.lstrip("%"), callee))

    return results


# ---------------------------------------------------------------------------
# Main analysis
# ---------------------------------------------------------------------------


def analyze(level_to_ir: dict[str, tuple[str, str]]) -> list[dict]:
    """Analyze LLVM IR files for zeroization issues.

    Precondition: ``level_to_ir`` must contain at least ``"O0"`` and ``"O2"``
    keys — if either is absent the function returns an empty list with no
    diagnostic.  The CLI always satisfies this; library callers must ensure it.
    """
    findings: list[dict] = []
    if "O0" not in level_to_ir or "O2" not in level_to_ir:
        return findings

    o0_file, o0_text = level_to_ir["O0"]
    o2_file, o2_text = level_to_ir["O2"]

    # --- 1. Global volatile store count drop O0 → O2 ---
    o0_vol_count = count_volatile_stores(o0_text)
    o2_vol_count = count_volatile_stores(o2_text)

    if o0_vol_count > o2_vol_count:
        diff = o0_vol_count - o2_vol_count
        # line=0 is used for file-level findings that cannot be attributed to a
        # single source line (I18).  Downstream consumers should treat line 0
        # as "file-level / unknown line".
        findings.append(
            make_finding(
                "OPTIMIZED_AWAY_ZEROIZE",
                "high",
                f"Volatile store count dropped from {o0_vol_count} (O0) to {o2_vol_count} (O2) "
                f"— {diff} volatile wipe(s) eliminated by dead-store elimination",
                o2_file,
                0,
            )
        )

    # --- 1b. Per-target volatile store drop O0 -> O2 (hard evidence by symbol) ---
    o0_vol_by_target = extract_volatile_stores_by_target(o0_text)
    o2_vol_by_target = extract_volatile_stores_by_target(o2_text)
    for target, o0_count in sorted(o0_vol_by_target.items()):
        o2_count = o2_vol_by_target.get(target, 0)
        if o0_count > o2_count:
            findings.append(
                make_finding(
                    "OPTIMIZED_AWAY_ZEROIZE",
                    "high",
                    f"Volatile stores to %{target} dropped from {o0_count} (O0) to {o2_count} (O2) "
                    f"— symbol-specific wipe elimination detected",
                    o2_file,
                    0,
                    symbol=target,
                )
            )

    # --- 2. Non-volatile llvm.memset calls in O2 IR ---
    for lineno, line_text in find_nonvolatile_memsets(o2_text):
        findings.append(
            make_finding(
                "OPTIMIZED_AWAY_ZEROIZE",
                "high",
                f"Non-volatile @llvm.memset in O2 IR — DSE-eligible, may be removed at higher "
                f"optimization. Use zeroize crate or volatile memset. IR: {line_text[:80]}",
                o2_file,
                lineno,
            )
        )

    # --- 3. alloca with lifetime.end but no volatile store (STACK_RETENTION) ---
    o2_allocas = extract_allocas(o2_text)
    o2_lifetime_ends = extract_lifetime_ends(o2_text)
    o2_vol_targets = extract_volatile_store_targets(o2_text)

    for alloca_name, size in o2_allocas.items():
        if size not in SECRET_ALLOCA_SIZES:
            continue
        if alloca_name not in o2_lifetime_ends:
            continue
        if alloca_name in o2_vol_targets:
            continue
        findings.append(
            make_finding(
                "STACK_RETENTION",
                "high",
                f"alloca [{size} x i8] %{alloca_name} has @llvm.lifetime.end but no "
                "volatile store — stack bytes not wiped before slot is freed",
                o2_file,
                0,
                symbol=alloca_name,
            )
        )

    # --- 4. SROA/mem2reg: secret alloca present at O0 but absent at O2 ---
    o0_allocas = extract_allocas(o0_text)

    o0_vol_targets = extract_volatile_store_targets(o0_text)
    for alloca_name, size in o0_allocas.items():
        if size not in SECRET_ALLOCA_SIZES:
            continue
        if alloca_name in o2_allocas:
            continue
        # Hard evidence gate: only emit when O0 showed a wipe target on this alloca.
        if alloca_name not in o0_vol_targets:
            continue
        findings.append(
            make_finding(
                "OPTIMIZED_AWAY_ZEROIZE",
                "high",
                f"alloca [{size} x i8] %{alloca_name} present at O0 but absent at O2 — "
                "SROA/mem2reg promoted it to registers; any volatile stores targeting this "
                "alloca are now unreachable",
                o2_file,
                0,
                symbol=alloca_name,
            )
        )

    # --- 5. Secret value in argument registers at call site (REGISTER_SPILL) ---
    for lineno, varname, callee in find_arg_load_calls(o2_text):
        findings.append(
            make_finding(
                "REGISTER_SPILL",
                "medium",
                f"Secret-named SSA value '%{varname}' loaded and passed directly to "
                f"'{callee}' — value in argument register may not be cleared after call",
                o2_file,
                lineno,
                symbol=varname,
            )
        )

    # --- 6. Secret return values can persist in return registers ---
    for lineno, varname in find_secret_returns(o2_text):
        findings.append(
            make_finding(
                "REGISTER_SPILL",
                "medium",
                f"Secret-named SSA value '%{varname}' is returned directly — "
                "value may persist in return registers after function exit",
                o2_file,
                lineno,
                symbol=varname,
            )
        )

    # --- 7. Aggregate/by-value secret argument passing ---
    for lineno, snippet in find_secret_aggregate_passes(o2_text):
        findings.append(
            make_finding(
                "SECRET_COPY",
                "medium",
                "Potential by-value aggregate call argument contains secret-named data; "
                f"copy may escape zeroization tracking. Args: {snippet}",
                o2_file,
                lineno,
            )
        )

    # Collect targets already reported in section 1b (O0→O2 per-symbol comparison)
    # so that the multi-level section below does not re-emit the same target.
    reported_by_1b: set[str] = {
        target
        for target, o0_count in o0_vol_by_target.items()
        if o0_count > o2_vol_by_target.get(target, 0)
    }

    # --- 8. Optional multi-level comparison (O0->O1->O2, O2->O3) ---
    # Skip the (O0, O2) adjacent pair when O1 is absent — that comparison is already
    # done by sections 1 and 1b above, and re-emitting it here causes duplicate findings.
    level_order = ["O0", "O1", "O2", "O3"]
    present = [lvl for lvl in level_order if lvl in level_to_ir]
    for idx in range(len(present) - 1):
        from_level = present[idx]
        to_level = present[idx + 1]
        # O0→O2 without an intermediate O1 is already covered by sections 1/1b.
        if from_level == "O0" and to_level == "O2":
            continue
        _, from_ir = level_to_ir[from_level]
        to_file, to_ir = level_to_ir[to_level]
        from_targets = extract_volatile_stores_by_target(from_ir)
        to_targets = extract_volatile_stores_by_target(to_ir)
        for target, from_count in sorted(from_targets.items()):
            # Skip targets already covered by section 1b to avoid cascading duplicates.
            if target in reported_by_1b:
                continue
            to_count = to_targets.get(target, 0)
            if from_count > to_count:
                findings.append(
                    make_finding(
                        "OPTIMIZED_AWAY_ZEROIZE",
                        "high",
                        f"Volatile stores to %{target} dropped from {from_count} ({from_level}) "
                        f"to {to_count} ({to_level})",
                        to_file,
                        0,
                        symbol=target,
                    )
                )

    return findings


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def main() -> int:
    parser = argparse.ArgumentParser(
        description="LLVM IR O0 vs O2 comparison for Rust dead-store-elimination findings"
    )
    parser.add_argument("--o0", required=True, help="Path to O0 .ll file")
    parser.add_argument("--o2", required=True, help="Path to O2 .ll file")
    parser.add_argument("--o1", required=False, help="Path to O1 .ll file (optional)")
    parser.add_argument("--o3", required=False, help="Path to O3 .ll file (optional)")
    parser.add_argument("--out", required=True, help="Output findings JSON path")
    args = parser.parse_args()

    level_paths: dict[str, Path] = {
        "O0": Path(args.o0),
        "O2": Path(args.o2),
    }
    if args.o1:
        level_paths["O1"] = Path(args.o1)
    if args.o3:
        level_paths["O3"] = Path(args.o3)

    for p in level_paths.values():
        if not p.exists():
            print(f"check_llvm_patterns.py: IR file not found: {p}", file=sys.stderr)
            return 1

    level_to_ir: dict[str, tuple[str, str]] = {}
    try:
        for level, path in level_paths.items():
            level_to_ir[level] = (str(path), path.read_text(encoding="utf-8", errors="replace"))
    except OSError as e:
        print(f"check_llvm_patterns.py: failed to read IR: {e}", file=sys.stderr)
        return 1

    findings = analyze(level_to_ir)

    out_path = Path(args.out)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(findings, indent=2), encoding="utf-8")

    print(f"check_llvm_patterns.py: {len(findings)} finding(s) written to {out_path}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
