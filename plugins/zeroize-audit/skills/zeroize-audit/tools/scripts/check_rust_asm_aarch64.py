#!/usr/bin/env python3
# /// script
# requires-python = ">=3.11"
# dependencies = []
# ///
"""
check_rust_asm_aarch64.py — AArch64 Rust assembly analysis backend.

⚠  EXPERIMENTAL — AArch64 support is incomplete. Findings should be treated as
   indicative only and require manual verification before inclusion in a report.

   Known limitations:
   - x29 (frame pointer) and x30 (link register) are always saved in the prologue
     via `stp x29, x30, [sp, #-N]!`. These appear as REGISTER_SPILL findings
     because both are in AARCH64_CALLEE_SAVED. They are almost never carrying
     secret values — reviewers should verify in context.
   - `dc zva` (Data Cache Zero by Virtual Address) is not detected as a zero-store.
     This instruction is rare in Rust-generated code but may be used in
     highly-optimised zeroize implementations.
   - AArch64 has no red zone (neither Linux nor macOS AAPCS64 define one). Leaf
     functions must allocate stack space explicitly; no red-zone analysis needed.
   - Apple AArch64 (M1/M2) and Linux AArch64 both use AAPCS64 with no red zone;
     the analysis is platform-agnostic.

Called by check_rust_asm.py. Not intended for direct invocation.
"""

import re

# ---------------------------------------------------------------------------
# AArch64 register sets (AAPCS64)
# ---------------------------------------------------------------------------

AARCH64_CALLER_SAVED = {
    # Integer/pointer: argument registers and temporaries
    "x0",
    "x1",
    "x2",
    "x3",
    "x4",
    "x5",
    "x6",
    "x7",
    "x8",
    "x9",
    "x10",
    "x11",
    "x12",
    "x13",
    "x14",
    "x15",
    "x16",
    "x17",
    # SIMD/FP: v0–v7 and v16–v31 are caller-saved (argument/scratch)
    "v0",
    "v1",
    "v2",
    "v3",
    "v4",
    "v5",
    "v6",
    "v7",
    "v16",
    "v17",
    "v18",
    "v19",
    "v20",
    "v21",
    "v22",
    "v23",
    "v24",
    "v25",
    "v26",
    "v27",
    "v28",
    "v29",
    "v30",
    "v31",
}

AARCH64_CALLEE_SAVED = {
    # Integer: x19–x28 must be preserved if used
    "x19",
    "x20",
    "x21",
    "x22",
    "x23",
    "x24",
    "x25",
    "x26",
    "x27",
    "x28",
    # x29 = frame pointer (fp), x30 = link register (lr)
    # NOTE: x29 and x30 are always saved in prologues; see limitations above.
    "x29",
    "x30",
    # SIMD/FP: lower 64 bits of v8–v15 must be preserved
    "v8",
    "v9",
    "v10",
    "v11",
    "v12",
    "v13",
    "v14",
    "v15",
}

# ---------------------------------------------------------------------------
# Patterns (ARM GNU syntax, as emitted by LLVM for AArch64)
# ---------------------------------------------------------------------------

# Frame allocation
# Most common: pre-index pair store that saves fp/lr and decrements sp
RE_A64_FRAME_STP = re.compile(r"stp\s+x29,\s+x30,\s+\[sp,\s+#-(\d+)\]!")
# Alternative: explicit sub
RE_A64_FRAME_SUB = re.compile(r"sub\s+sp,\s+sp,\s+#(\d+)")

# Zero-store patterns
# str xzr/wzr, [sp, #N]       — single 64-bit (xzr) or 32-bit (wzr) zero store to stack
RE_A64_STR_XZR = re.compile(r"\bstr\s+[xw]zr,\s+\[sp(?:,\s*#-?\d+)?\]")
# stp xzr, xzr / wzr, wzr, [sp, #N]  — paired zero store (most efficient)
RE_A64_STP_XZR = re.compile(r"\bstp\s+[xw]zr,\s+[xw]zr,\s+\[sp(?:,\s*#-?\d+)?\]")
# movi vN.*, #0            — SIMD register zeroing (precedes stp qN)
RE_A64_MOVI_ZERO = re.compile(r"\bmovi\s+v\d+\.\w+,\s+#0\b")
# bl ...(memset|zeroize)   — call to zeroize/memset routine
RE_A64_MEMSET = re.compile(r"\bbl\s+.*(?:memset|volatile_set_memory|zeroize)")

# Register spill patterns
# str xN/vN/qN, [sp, #offset]        — single store to stack
RE_A64_STR_SPILL = re.compile(r"\bstr\s+(x\d+|v\d+|q\d+),\s+\[sp(?:,\s*#-?\d+)?\]")
# stp xN, xM / qN, qM, [sp, #offset]  — pair store to stack (I31: also covers SIMD q pairs)
RE_A64_STP_SPILL = re.compile(r"\bstp\s+((?:x|q)\d+),\s+((?:x|q)\d+),\s+\[sp(?:,\s*#-?\d+)?\]")

# Return instruction (no suffix on AArch64, unlike x86-64's retq)
RE_A64_RET = re.compile(r"\bret\b")


# ---------------------------------------------------------------------------
# STACK_RETENTION (AArch64)
# ---------------------------------------------------------------------------


def check_stack_retention(
    func_name: str,
    func_lines: list[tuple[int, str]],
) -> dict | None:
    """
    Detect AArch64 stack frame allocated but not zeroed before return.

    [EXPERIMENTAL] Findings require manual verification.
    """
    frame_alloc_line: tuple[int, str] | None = None
    frame_size = 0
    has_zero_store = False
    ret_line: tuple[int, str] | None = None

    for lineno, line in func_lines:
        # stp x29, x30, [sp, #-N]! — most common AArch64 prologue (pre-index)
        m = RE_A64_FRAME_STP.search(line)
        if m:
            if frame_alloc_line is None:
                frame_alloc_line = (lineno, line.strip())
            frame_size += int(m.group(1))

        # sub sp, sp, #N — additional explicit allocation (common with stp prologue)
        # Accumulate rather than taking only the first allocation so that prologues
        # using both stp+sub report the correct total frame size (I28).
        m2 = RE_A64_FRAME_SUB.search(line)
        if m2:
            if frame_alloc_line is None:
                frame_alloc_line = (lineno, line.strip())
            frame_size += int(m2.group(1))

        # Zero-store detection
        if RE_A64_STR_XZR.search(line) or RE_A64_STP_XZR.search(line):
            has_zero_store = True
        if RE_A64_MOVI_ZERO.search(line) or RE_A64_MEMSET.search(line):
            has_zero_store = True

        if RE_A64_RET.search(line):
            ret_line = (lineno, line.strip())

    if frame_alloc_line and ret_line and not has_zero_store and frame_size > 0:
        alloc_lineno, alloc_text = frame_alloc_line
        ret_lineno, _ = ret_line
        return {
            "category": "STACK_RETENTION",
            "severity": "high",
            "symbol": func_name,
            "detail": (
                f"[EXPERIMENTAL] AArch64 stack frame of {frame_size} bytes allocated "
                f"at line {alloc_lineno} ({alloc_text!r}) but no zero-store "
                f"(str xzr / stp xzr,xzr / movi+stp / zeroize call) found "
                f"before return at line {ret_lineno}"
            ),
            "evidence_detail": (
                f"{alloc_text} at line {alloc_lineno}; "
                f"no str/stp xzr or zeroize call before ret at line {ret_lineno}"
            ),
        }
    return None


# ---------------------------------------------------------------------------
# REGISTER_SPILL (AArch64)
# ---------------------------------------------------------------------------


def check_register_spill(
    func_name: str,
    func_lines: list[tuple[int, str]],
) -> list[dict]:
    """
    Detect AArch64 registers spilled to the stack.

    [EXPERIMENTAL] x29/x30 prologue saves will always appear here because both
    are in AARCH64_CALLEE_SAVED. Reviewers should check whether those registers
    actually hold sensitive values in the function under analysis.
    """
    spills: list[tuple[int, str, str]] = []  # (lineno, reg, line)

    for lineno, line in func_lines:
        # Single store: str xN/vN/qN, [sp, ...]
        m = RE_A64_STR_SPILL.search(line)
        if m:
            reg = m.group(1)
            if reg in AARCH64_CALLEE_SAVED or reg in AARCH64_CALLER_SAVED:
                spills.append((lineno, reg, line.strip()))
            elif re.match(r"^q\d+$", reg):
                # q registers are the 128-bit view of v registers; q8–q15 are
                # partially callee-saved (lower 64 bits). For simplicity,
                # classify all q-register spills as caller-saved (I31).
                spills.append((lineno, reg, line.strip()))

        # Pair store: stp xN, xM / qN, qM, [sp, ...]
        m2 = RE_A64_STP_SPILL.search(line)
        if m2:
            for reg in (m2.group(1), m2.group(2)):
                if reg == "xzr":
                    continue  # zero register — this is a zero-store, not a spill
                if (
                    reg in AARCH64_CALLEE_SAVED
                    or reg in AARCH64_CALLER_SAVED
                    or re.match(r"^q\d+$", reg)
                ):
                    spills.append((lineno, reg, line.strip()))

    findings: list[dict] = []
    seen: set[str] = set()
    for lineno, reg, line_text in spills:
        if reg not in seen:
            seen.add(reg)
            if reg in AARCH64_CALLEE_SAVED:
                reg_class, severity = "callee-saved", "high"
            elif (m := re.match(r"^q(\d+)$", reg)) and int(m.group(1)) in range(8, 16):
                # q8–q15: lower 64 bits callee-saved per AAPCS64
                reg_class, severity = "callee-saved (partial)", "high"
            else:
                reg_class, severity = "caller-saved", "medium"
            findings.append(
                {
                    "category": "REGISTER_SPILL",
                    "severity": severity,
                    "symbol": func_name,
                    "detail": (
                        f"[EXPERIMENTAL] AArch64 register {reg} ({reg_class}) spilled to "
                        f"stack at line {lineno} in function '{func_name}' "
                        f"— may expose secret value"
                    ),
                    "evidence_detail": f"{line_text} at line {lineno}",
                }
            )
    return findings


# ---------------------------------------------------------------------------
# Public entry point
# ---------------------------------------------------------------------------


def analyze_function(
    func_name: str,
    func_lines: list[tuple[int, str]],
) -> list[dict]:
    """
    Run all AArch64 checks for one sensitive function.
    Returns a (possibly empty) list of finding dicts.

    [EXPERIMENTAL] All returned findings carry [EXPERIMENTAL] in their detail
    field and require manual verification.
    """
    findings: list[dict] = []

    f = check_stack_retention(func_name, func_lines)
    if f:
        findings.append(f)

    findings.extend(check_register_spill(func_name, func_lines))

    return findings
