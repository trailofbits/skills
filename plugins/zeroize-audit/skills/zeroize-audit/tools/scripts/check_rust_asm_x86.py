#!/usr/bin/env python3
# /// script
# requires-python = ">=3.11"
# dependencies = []
# ///
"""
check_rust_asm_x86.py — x86-64 Rust assembly analysis backend.

Called by check_rust_asm.py. Not intended for direct invocation.

Detects STACK_RETENTION, REGISTER_SPILL, and red-zone STACK_RETENTION in x86-64
AT&T-syntax assembly emitted by `cargo +nightly rustc --emit=asm`.
"""

import re

# ---------------------------------------------------------------------------
# x86-64 register sets (System V ABI — identical for C/C++ and Rust)
# ---------------------------------------------------------------------------
CALLER_SAVED = {
    "rax",
    "rcx",
    "rdx",
    "rsi",
    "rdi",
    "r8",
    "r9",
    "r10",
    "r11",
    # xmm0-xmm7 are function arguments / scratch; xmm8-xmm15 are also caller-saved
    # (System V AMD64 ABI §3.2.1: XMM registers 0–15 are all caller-saved)
    "xmm0",
    "xmm1",
    "xmm2",
    "xmm3",
    "xmm4",
    "xmm5",
    "xmm6",
    "xmm7",
    "xmm8",
    "xmm9",
    "xmm10",
    "xmm11",
    "xmm12",
    "xmm13",
    "xmm14",
    "xmm15",
}
CALLEE_SAVED = {"rbx", "r12", "r13", "r14", "r15", "rbp"}

# ---------------------------------------------------------------------------
# Patterns
# ---------------------------------------------------------------------------

# Frame allocation
RE_FRAME_ALLOC = re.compile(r"subq\s+\$(\d+),\s+%rsp")
RE_PUSH = re.compile(r"push[ql]\s+%(\w+)")

# Zero-store patterns (volatile wipe) — all widths that can clear secret bytes
RE_MOVQ_ZERO = re.compile(r"movq\s+\$0,\s+-?\d+\(%r[sb]p\)")
RE_MOVL_ZERO = re.compile(r"movl\s+\$0,\s+-?\d+\(%r[sb]p\)")
RE_MOVW_ZERO = re.compile(r"movw\s+\$0,\s+-?\d+\(%r[sb]p\)")
RE_MOVB_ZERO = re.compile(r"movb\s+\$0,\s+-?\d+\(%r[sb]p\)")
RE_MEMSET_CALL = re.compile(r"call\s+.*(?:memset|volatile_set_memory|zeroize)")
# SIMD self-XOR zeroing: xorps/pxor/vpxor %regN, %regN — register is zeroed,
# typically followed by a store that constitutes the actual wipe.
RE_SIMD_ZERO = re.compile(r"(?:xorps|xorpd|pxor|vpxor)\s+%(\w+),\s+%(\w+)")

# Register spills: movq/movdqa/movups/movaps %reg, N(%rsp|%rbp)
RE_REG_SPILL = re.compile(r"mov(?:q|dqa|ups|aps)\s+%(\w+),\s+(-?\d+)\(%r[sb]p\)")

# Return instruction.  Stripping the AT&T comment character (#) before
# applying this pattern prevents false matches inside assembly comments
# (e.g. "# retq is the encoding for ...").
RE_RET = re.compile(r"\bret[ql]?\b")

# Red zone: stores to [rsp - N] (N ≤ 128) in leaf functions without subq
RE_RED_ZONE = re.compile(r"mov(?:q|l|b|w)\s+%\w+,\s+-(\d+)\(%rsp\)")


# ---------------------------------------------------------------------------
# STACK_RETENTION
# ---------------------------------------------------------------------------


def check_stack_retention(
    func_name: str,
    func_lines: list[tuple[int, str]],
) -> dict | None:
    """
    Detect stack frame allocated (subq $N, %rsp) but not zeroed before return.
    """
    frame_alloc_line: tuple[int, str] | None = None
    frame_size = 0
    has_zero_store = False
    ret_line: tuple[int, str] | None = None

    for lineno, line in func_lines:
        # Strip trailing AT&T-style comments before pattern matching to avoid
        # false positives from `# retq` or `# movq $0, ...` in comments (I25).
        code = line.split("#", 1)[0]

        m = RE_FRAME_ALLOC.search(code)
        if m and frame_alloc_line is None:
            frame_alloc_line = (lineno, line.strip())
            frame_size = int(m.group(1))

        if (
            RE_MOVQ_ZERO.search(code)
            or RE_MOVL_ZERO.search(code)
            or RE_MOVW_ZERO.search(code)
            or RE_MOVB_ZERO.search(code)
        ):
            has_zero_store = True
        if RE_MEMSET_CALL.search(code):
            has_zero_store = True
        # SIMD self-XOR (xorps/pxor %xmmN, %xmmN) zeroes a register; treat
        # as a zero-store signal to avoid false-positive STACK_RETENTION when
        # the function wipes data via SIMD before returning (I26).
        m2 = RE_SIMD_ZERO.search(code)
        if m2 and m2.group(1) == m2.group(2):
            has_zero_store = True

        if RE_RET.search(code):
            ret_line = (lineno, line.strip())

    if frame_alloc_line and ret_line and not has_zero_store and frame_size > 0:
        alloc_lineno, alloc_text = frame_alloc_line
        ret_lineno, _ = ret_line
        return {
            "category": "STACK_RETENTION",
            "severity": "high",
            "symbol": func_name,
            "detail": (
                f"Stack frame of {frame_size} bytes allocated at line {alloc_lineno} "
                f"({alloc_text!r}) but no zero-store found before return at line {ret_lineno}"
            ),
            "evidence_detail": (
                f"{alloc_text} at line {alloc_lineno}; "
                f"no volatile wipe before retq at line {ret_lineno}"
            ),
        }
    return None


# ---------------------------------------------------------------------------
# REGISTER_SPILL
# ---------------------------------------------------------------------------


def check_register_spill(
    func_name: str,
    func_lines: list[tuple[int, str]],
) -> list[dict]:
    """
    Detect registers spilled to the stack (potential secret exposure).
    """
    spills: list[tuple[int, str, str, str]] = []  # (lineno, reg, line, class)

    for lineno, line in func_lines:
        m = RE_REG_SPILL.search(line)
        if m:
            reg = m.group(1)
            if reg in CALLER_SAVED:
                spills.append((lineno, reg, line.strip(), "caller-saved"))
            elif reg in CALLEE_SAVED:
                spills.append((lineno, reg, line.strip(), "callee-saved"))

    findings = []
    seen: set[str] = set()
    for lineno, reg, line_text, reg_class in spills:
        if reg not in seen:
            seen.add(reg)
            severity = "high" if reg_class == "callee-saved" else "medium"
            findings.append(
                {
                    "category": "REGISTER_SPILL",
                    "severity": severity,
                    "symbol": func_name,
                    "detail": (
                        f"Register %{reg} ({reg_class}) spilled to stack at line {lineno} "
                        f"in function '{func_name}' — may expose secret value"
                    ),
                    "evidence_detail": f"{line_text} at line {lineno}",
                }
            )
    return findings


# ---------------------------------------------------------------------------
# RED ZONE (x86-64 specific)
# ---------------------------------------------------------------------------


def check_red_zone(
    func_name: str,
    func_lines: list[tuple[int, str]],
) -> dict | None:
    """
    Detect x86-64 leaf functions that store data in the red zone without zeroing.

    The x86-64 System V ABI reserves 128 bytes below %rsp as a "red zone" that
    leaf functions may use as scratch space without adjusting %rsp. Sensitive data
    written to this region is NOT zeroed by the callee and persists after return.
    This check only fires when no subq frame allocation is present (non-leaf
    functions are covered by check_stack_retention).
    """
    # Only applies to leaf functions (no regular frame allocation)
    if any(RE_FRAME_ALLOC.search(line) for _, line in func_lines):
        return None

    red_zone_depth = 0
    has_zero_store = False
    has_ret = False

    for _, line in func_lines:
        code = line.split("#", 1)[0]  # strip AT&T comments (I25)

        m = RE_RED_ZONE.search(code)
        if m:
            offset = int(m.group(1))
            if offset <= 128:
                red_zone_depth = max(red_zone_depth, offset)

        if (
            RE_MOVQ_ZERO.search(code)
            or RE_MOVL_ZERO.search(code)
            or RE_MOVW_ZERO.search(code)
            or RE_MOVB_ZERO.search(code)
        ):
            has_zero_store = True
        if RE_MEMSET_CALL.search(code):
            has_zero_store = True
        m2 = RE_SIMD_ZERO.search(code)
        if m2 and m2.group(1) == m2.group(2):
            has_zero_store = True
        if RE_RET.search(code):
            has_ret = True

    if red_zone_depth > 0 and has_ret and not has_zero_store:
        return {
            "category": "STACK_RETENTION",
            "severity": "high",
            "symbol": func_name,
            "detail": (
                f"Leaf function '{func_name}' stores {red_zone_depth} bytes in the "
                f"x86-64 red zone (below %rsp) without zeroing before return — "
                f"sensitive data may persist in the 128-byte region below %rsp"
            ),
            "evidence_detail": (
                f"red zone depth -{red_zone_depth}(%rsp); "
                f"no mov[qwlb] $0 or memset/zeroize call before retq"
            ),
        }
    return None


# ---------------------------------------------------------------------------
# Public entry point
# ---------------------------------------------------------------------------


def analyze_function(
    func_name: str,
    func_lines: list[tuple[int, str]],
) -> list[dict]:
    """
    Run all x86-64 checks for one sensitive function.
    Returns a (possibly empty) list of finding dicts.
    """
    findings: list[dict] = []

    f = check_stack_retention(func_name, func_lines)
    if f:
        findings.append(f)

    findings.extend(check_register_spill(func_name, func_lines))

    f = check_red_zone(func_name, func_lines)
    if f:
        findings.append(f)

    return findings
