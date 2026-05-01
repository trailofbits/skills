#!/usr/bin/env python3
# /// script
# requires-python = ">=3.11"
# dependencies = []
# ///
"""
check_mir_patterns.py — MIR text pattern analysis for Rust zeroization issues.

Reads a Rust MIR file (emitted by emit_rust_mir.sh) and a sensitive-objects JSON
file, then detects patterns indicative of missing or incorrect zeroization.

All analysis is text/regex based — no MIR parser required.

Usage:
    uv run check_mir_patterns.py \
        --mir <path.mir> --secrets <sensitive-objects.json> --out <findings.json>

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
# Sensitive name patterns (applied to local variable names in MIR)
# ---------------------------------------------------------------------------

SENSITIVE_LOCAL_RE = re.compile(
    # Match keyword not preceded/followed by a letter so that compound names
    # like 'secret_key', 'private_key', and 'auth_token' are correctly matched
    # while avoiding spurious hits on words like 'monkey' or 'tokenize'.
    r"(?i)(?<![a-zA-Z])(key|secret|password|token|nonce|seed|priv|master|credential)(?![a-zA-Z])"
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
    fid = f"F-RUST-MIR-{_finding_counter[0]:04d}"
    return {
        "id": fid,
        "language": "rust",
        "category": category,
        "severity": severity,
        "confidence": confidence,
        "detail": detail,
        "symbol": symbol,
        "location": {"file": file, "line": line},
        "evidence": [{"source": "mir_text", "detail": detail}],
    }


# ---------------------------------------------------------------------------
# MIR parsing helpers
# ---------------------------------------------------------------------------


def split_into_functions(mir_text: str) -> list[tuple[str, list[str], int]]:
    """
    Split MIR text into (fn_name, body_lines, start_lineno) tuples.
    MIR functions start with 'fn <name>' or 'mir_body' headers.
    """
    functions: list[tuple[str, list[str], int]] = []
    lines = mir_text.splitlines()
    fn_re = re.compile(r"^fn\s+(\S+)\s*\(")
    current_name = "<top>"
    current_lines: list[str] = []
    current_start = 0
    depth = 0

    for lineno, line in enumerate(lines, start=1):
        m = fn_re.match(line.strip())
        if m and depth == 0:
            if current_lines:
                functions.append((current_name, current_lines, current_start))
            current_name = m.group(1)
            current_lines = [line]
            current_start = lineno
            depth = line.count("{") - line.count("}")
        else:
            current_lines.append(line)
            depth += line.count("{") - line.count("}")
            if depth < 0:
                print(
                    f"check_mir_patterns.py: warning: negative brace depth at line {lineno} "
                    f"in {current_name!r} — MIR may be malformed",
                    file=sys.stderr,
                )
                depth = 0

    if current_lines:
        functions.append((current_name, current_lines, current_start))

    return functions


def local_names_from_debug_info(fn_lines: list[str]) -> dict[str, str]:
    """
    Extract MIR debug variable map: local slot → variable name.
    MIR debug lines look like:  debug varname => _5;
    """
    mapping: dict[str, str] = {}
    debug_re = re.compile(r"debug\s+(\w+)\s*=>\s*(_\d+)")
    for line in fn_lines:
        m = debug_re.search(line)
        if m:
            varname, slot = m.group(1), m.group(2)
            mapping[slot] = varname
    return mapping


def is_sensitive_local(
    slot: str, debug_map: dict[str, str], sensitive_re: re.Pattern[str] = SENSITIVE_LOCAL_RE
) -> bool:
    varname = debug_map.get(slot, "")
    return bool(sensitive_re.search(varname))


def is_zeroizing_type(type_name: str) -> bool:
    return bool(re.search(r"(?i)(Zeroiz|ZeroizeOnDrop|SecretBox|Zeroizing)", type_name))


# ---------------------------------------------------------------------------
# Pattern detectors
# ---------------------------------------------------------------------------


def detect_drop_before_storagedead(
    fn_name: str,
    fn_lines: list[str],
    fn_start: int,
    debug_map: dict[str, str],
    mir_file: str,
    sensitive_re: re.Pattern[str] = SENSITIVE_LOCAL_RE,
) -> list[dict]:
    """
    Pattern: drop(_X) present but StorageDead(_X) absent for any sensitive local.
    Indicates the local may persist on stack after the drop.
    """
    findings: list[dict] = []
    drop_re = re.compile(r"\bdrop\(_(\d+)\)")
    storagedead_re = re.compile(r"StorageDead\(_(\d+)\)")

    dropped: set[str] = set()
    storage_dead: set[str] = set()

    for line in fn_lines:
        for m in drop_re.finditer(line):
            dropped.add(f"_{m.group(1)}")
        for m in storagedead_re.finditer(line):
            storage_dead.add(f"_{m.group(1)}")

    has_return = any(re.search(r"\breturn\b", line) for line in fn_lines)

    for slot in dropped - storage_dead:
        if not is_sensitive_local(slot, debug_map, sensitive_re):
            continue
        if has_return:
            # Prefer the path-sensitive NOT_ON_ALL_PATHS finding over the generic
            # MISSING_SOURCE_ZEROIZE to avoid emitting duplicate findings for the
            # same slot (C7: both fired before for slots with explicit return paths).
            findings.append(
                make_finding(
                    "NOT_ON_ALL_PATHS",
                    "high",
                    f"Secret local {slot} ({debug_map.get(slot, '?')!r}) is dropped but not "
                    f"StorageDead on explicit return path(s) in '{fn_name}'",
                    mir_file,
                    fn_start,
                    symbol=debug_map.get(slot, slot),
                )
            )
        else:
            findings.append(
                make_finding(
                    "MISSING_SOURCE_ZEROIZE",
                    "medium",
                    f"Secret local {slot} ({debug_map.get(slot, '?')!r}) is dropped without "
                    f"StorageDead in '{fn_name}' — verify zeroize call in drop glue",
                    mir_file,
                    fn_start,
                    symbol=debug_map.get(slot, slot),
                )
            )

    return findings


def detect_resume_with_live_secrets(
    fn_name: str,
    fn_lines: list[str],
    fn_start: int,
    debug_map: dict[str, str],
    mir_file: str,
    sensitive_re: re.Pattern[str] = SENSITIVE_LOCAL_RE,
) -> list[dict]:
    """
    Pattern: 'resume' terminator (unwind/panic path) with sensitive locals in scope.
    """
    findings: list[dict] = []
    resume_re = re.compile(r"\bresume\b")
    has_resume = any(resume_re.search(line) for line in fn_lines)
    if not has_resume:
        return findings

    sensitive_locals = [
        slot for slot in debug_map if is_sensitive_local(slot, debug_map, sensitive_re)
    ]
    if sensitive_locals:
        names = [debug_map[s] for s in sensitive_locals[:3]]
        findings.append(
            make_finding(
                "MISSING_SOURCE_ZEROIZE",
                "medium",
                f"Panic/unwind path (resume) in '{fn_name}' with sensitive "
                f"locals {names} in scope — verify these locals are dropped "
                "(and zeroed) on the unwind path",
                mir_file,
                fn_start,
                symbol=names[0] if names else "",
            )
        )
    return findings


def detect_aggregate_move_non_zeroizing(
    fn_name: str,
    fn_lines: list[str],
    fn_start: int,
    debug_map: dict[str, str],
    mir_file: str,
    sensitive_re: re.Pattern[str] = SENSITIVE_LOCAL_RE,
) -> list[dict]:
    """
    Pattern: _Y = TypeName { field: move _X } where _X is a sensitive local
    and TypeName does not appear to be a Zeroizing wrapper.
    """
    findings: list[dict] = []
    agg_re = re.compile(r"(_\d+)\s*=\s*(\w[\w:]*)\s*\{[^}]*move\s+(_\d+)")

    for lineno, line in enumerate(fn_lines, start=fn_start):
        m = agg_re.search(line)
        if not m:
            continue
        _dest, type_name, _src = m.group(1), m.group(2), m.group(3)
        if is_sensitive_local(_src, debug_map, sensitive_re) and not is_zeroizing_type(type_name):
            src_name = debug_map.get(_src, _src)
            findings.append(
                make_finding(
                    "SECRET_COPY",
                    "medium",
                    f"Secret local '{src_name}' moved into non-Zeroizing aggregate '{type_name}' "
                    f"in '{fn_name}' — copy now untracked",
                    mir_file,
                    lineno,
                    symbol=src_name,
                )
            )
    return findings


def detect_closure_capture_secret(
    fn_name: str,
    fn_lines: list[str],
    fn_start: int,
    debug_map: dict[str, str],
    mir_file: str,
    sensitive_re: re.Pattern[str] = SENSITIVE_LOCAL_RE,
) -> list[dict]:
    """
    Pattern: closure/async state captures a sensitive local by move.
    """
    findings: list[dict] = []
    closure_re = re.compile(
        r"(_\d+)\s*=\s*.*(?:closure|async|generator|Coroutine).*move\s+(_\d+)",
        re.IGNORECASE,
    )
    for lineno, line in enumerate(fn_lines, start=fn_start):
        m = closure_re.search(line)
        if not m:
            continue
        captured_slot = m.group(2)
        if is_sensitive_local(captured_slot, debug_map, sensitive_re):
            name = debug_map.get(captured_slot, captured_slot)
            findings.append(
                make_finding(
                    "SECRET_COPY",
                    "high",
                    f"Sensitive local '{name}' is captured by move into a closure/async state "
                    f"in '{fn_name}' — copy may outlive intended wipe scope",
                    mir_file,
                    lineno,
                    symbol=name,
                )
            )
    return findings


def detect_drop_glue_without_zeroize(
    fn_name: str, fn_lines: list[str], fn_start: int, mir_file: str
) -> list[dict]:
    """
    Pattern: function is a drop glue (drop_in_place / _drop_impl) and contains
    drop(_X) but no call to zeroize::.
    """
    if not re.search(r"(drop_in_place|_drop_impl)", fn_name):
        return []

    findings: list[dict] = []
    has_drop_call = any(re.search(r"\bdrop\(_\d+\)", line) for line in fn_lines)
    has_zeroize_call = any(re.search(r"\bzeroize::", line) for line in fn_lines)

    if has_drop_call and not has_zeroize_call:
        findings.append(
            make_finding(
                "MISSING_SOURCE_ZEROIZE",
                "high",
                f"Drop glue '{fn_name}' calls drop() but no call to zeroize:: found — "
                "secret not wiped on drop",
                mir_file,
                fn_start,
                symbol=fn_name,
            )
        )
    return findings


def detect_ffi_call_with_secret(
    fn_name: str,
    fn_lines: list[str],
    fn_start: int,
    debug_map: dict[str, str],
    mir_file: str,
    sensitive_re: re.Pattern[str] = SENSITIVE_LOCAL_RE,
) -> list[dict]:
    """
    Pattern: extern "C" call with a sensitive local as an argument.
    In MIR: extern fns are called with ABI specifier; we look for
    'extern "C"' in fn declaration context and call sites with sensitive locals.
    """
    findings: list[dict] = []
    call_re = re.compile(r"\bcall\s+(\S+)\s*\(([^)]*)\)")

    # In MIR, extern fn calls appear as calls to paths containing "extern_C" or similar.
    # Heuristic: look for call sites that pass a sensitive local as an argument.
    for lineno, line in enumerate(fn_lines, start=fn_start):
        m = call_re.search(line)
        if not m:
            continue
        callee = m.group(1)
        args_text = m.group(2)
        # Check if any argument is a sensitive local
        arg_slots = re.findall(r"_(\d+)", args_text)
        for slot_num in arg_slots:
            slot = f"_{slot_num}"
            if is_sensitive_local(slot, debug_map, sensitive_re):
                # Check if the callee looks like an FFI function (not zeroize::)
                if "zeroize" in callee.lower():
                    continue
                # Look for extern "C" indication — either in callee name or nearby
                if re.search(r"(::c_|_ffi_|_sys_|extern)", callee, re.IGNORECASE):
                    src_name = debug_map.get(slot, slot)
                    findings.append(
                        make_finding(
                            "SECRET_COPY",
                            "high",
                            f"Secret local '{src_name}' passed to potential FFI call '{callee}' "
                            f"in '{fn_name}' — zeroization guarantees lost in callee",
                            mir_file,
                            lineno,
                            symbol=src_name,
                        )
                    )
    return findings


def detect_yield_with_live_secret(
    fn_name: str,
    fn_lines: list[str],
    fn_start: int,
    debug_map: dict[str, str],
    mir_file: str,
    sensitive_re: re.Pattern[str] = SENSITIVE_LOCAL_RE,
) -> list[dict]:
    """
    Pattern: Yield terminator (async/coroutine state machine) with sensitive-named
    locals that could be live at the yield point.
    """
    findings: list[dict] = []
    yield_re = re.compile(r"\byield\b")
    has_yield = any(yield_re.search(line) for line in fn_lines)
    if not has_yield:
        return findings

    sensitive_locals = [
        slot for slot in debug_map if is_sensitive_local(slot, debug_map, sensitive_re)
    ]
    if sensitive_locals:
        names = [debug_map[s] for s in sensitive_locals[:3]]
        findings.append(
            make_finding(
                "NOT_ON_ALL_PATHS",
                "high",
                f"Coroutine/async fn '{fn_name}' has Yield terminator with sensitive locals "
                f"{names} potentially live at suspension point — secrets stored in heap-allocated "
                "Future state machine; ZeroizeOnDrop covers stack variables only",
                mir_file,
                fn_start,
                symbol=names[0] if names else "",
            )
        )
    return findings


def detect_result_err_path_with_secret(
    fn_name: str,
    fn_lines: list[str],
    fn_start: int,
    debug_map: dict[str, str],
    mir_file: str,
    sensitive_re: re.Pattern[str] = SENSITIVE_LOCAL_RE,
) -> list[dict]:
    """
    Pattern: explicit error-path style return (`Err(...)`) while sensitive locals
    are still in scope.
    """
    findings: list[dict] = []
    err_re = re.compile(r"\bErr\s*\(")
    if not any(err_re.search(line) for line in fn_lines):
        return findings
    sensitive_locals = [
        slot for slot in debug_map if is_sensitive_local(slot, debug_map, sensitive_re)
    ]
    if not sensitive_locals:
        return findings
    names = [debug_map[s] for s in sensitive_locals[:3]]
    findings.append(
        make_finding(
            "NOT_ON_ALL_PATHS",
            "high",
            f"Potential Result::Err early-return path in '{fn_name}' with sensitive locals {names} "
            "still in scope — verify cleanup on all error exits",
            mir_file,
            fn_start,
            symbol=names[0] if names else "",
        )
    )
    return findings


# ---------------------------------------------------------------------------
# Main analysis
# ---------------------------------------------------------------------------


def analyze(mir_text: str, sensitive_objects: list[dict], mir_file: str) -> list[dict]:
    findings: list[dict] = []
    functions = split_into_functions(mir_text)

    extra_names = [obj.get("name", "") for obj in sensitive_objects if obj.get("name")]
    sensitive_re = SENSITIVE_LOCAL_RE
    if extra_names:
        augmented = (
            SENSITIVE_LOCAL_RE.pattern
            + "|"
            + "|".join(r"\b" + re.escape(n) + r"\b" for n in extra_names)
        )
        sensitive_re = re.compile(augmented, re.IGNORECASE)

    for fn_name, fn_lines, fn_start in functions:
        debug_map = local_names_from_debug_info(fn_lines)

        ctx = (fn_name, fn_lines, fn_start)
        findings.extend(detect_drop_before_storagedead(*ctx, debug_map, mir_file, sensitive_re))
        findings.extend(detect_resume_with_live_secrets(*ctx, debug_map, mir_file, sensitive_re))
        findings.extend(
            detect_aggregate_move_non_zeroizing(*ctx, debug_map, mir_file, sensitive_re)
        )
        findings.extend(detect_closure_capture_secret(*ctx, debug_map, mir_file, sensitive_re))
        findings.extend(detect_drop_glue_without_zeroize(*ctx, mir_file))
        findings.extend(detect_ffi_call_with_secret(*ctx, debug_map, mir_file, sensitive_re))
        findings.extend(detect_yield_with_live_secret(*ctx, debug_map, mir_file, sensitive_re))
        findings.extend(detect_result_err_path_with_secret(*ctx, debug_map, mir_file, sensitive_re))

    return findings


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def main() -> int:
    parser = argparse.ArgumentParser(
        description="MIR text pattern analysis for Rust zeroization issues"
    )
    parser.add_argument("--mir", required=True, help="Path to .mir file")
    parser.add_argument("--secrets", required=True, help="Path to sensitive-objects.json")
    parser.add_argument("--out", required=True, help="Output findings JSON path")
    args = parser.parse_args()

    mir_path = Path(args.mir)
    if not mir_path.exists():
        print(f"check_mir_patterns.py: MIR file not found: {mir_path}", file=sys.stderr)
        return 1

    secrets_path = Path(args.secrets)
    if not secrets_path.exists():
        print(f"check_mir_patterns.py: secrets file not found: {secrets_path}", file=sys.stderr)
        return 1

    try:
        mir_text = mir_path.read_text(encoding="utf-8", errors="replace")
    except OSError as e:
        print(f"check_mir_patterns.py: failed to read MIR: {e}", file=sys.stderr)
        return 1

    try:
        sensitive_objects = json.loads(secrets_path.read_text(encoding="utf-8", errors="replace"))
    except (json.JSONDecodeError, OSError) as e:
        print(f"check_mir_patterns.py: failed to parse secrets JSON: {e}", file=sys.stderr)
        return 1

    findings = analyze(mir_text, sensitive_objects, str(mir_path))

    out_path = Path(args.out)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(findings, indent=2), encoding="utf-8")

    print(f"check_mir_patterns.py: {len(findings)} finding(s) written to {out_path}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
