#!/usr/bin/env python3
# /// script
# requires-python = ">=3.11"
# dependencies = []
# ///
"""
check_rust_asm.py — Rust assembly analysis dispatcher for STACK_RETENTION and REGISTER_SPILL.

Detects the assembly architecture and delegates to the appropriate backend:
  x86-64  → check_rust_asm_x86.py      (production-ready)
  AArch64 → check_rust_asm_aarch64.py  (EXPERIMENTAL — findings require manual review)

Usage:
    uv run check_rust_asm.py --asm <hash>.O2.s \\
        --secrets sensitive-objects.json \\
        --out asm-findings.json
"""

import argparse
import importlib.util
import json
import re
import subprocess
import sys
from collections import defaultdict
from pathlib import Path

# ---------------------------------------------------------------------------
# Architecture detection
# ---------------------------------------------------------------------------


def detect_architecture(asm_text: str) -> str:
    """
    Heuristic architecture detection from assembly text.

    x86-64:  AT&T percent-prefix 64-bit register names (%rsp, %rax, …)
    AArch64: distinctive ARM GNU syntax patterns (stp x29, str xzr, movi v#.*)
    """
    # x86-64: AT&T percent-prefix 64-bit register names
    if re.search(r"%r(?:sp|bp|ax|bx|cx|dx|si|di)\b", asm_text):
        return "x86_64"
    # AArch64: distinctive prologue / zero-register / SIMD instructions (ARM GNU syntax)
    if re.search(r"stp\s+x29|str\s+xzr|stp\s+xzr|movi\s+v\d+\.\w+", asm_text):
        return "aarch64"
    # Broad AArch64 fallback: bare xN registers used as instruction operands
    if re.search(r"\b(?:x1[0-9]|x2[0-9]|x[0-9]),", asm_text):
        return "aarch64"
    return "unknown"


# ---------------------------------------------------------------------------
# Symbol demangling (shared)
# ---------------------------------------------------------------------------


def demangle_symbols(asm_text: str) -> str:
    """Demangle all Rust symbols using rustfilt if available."""
    try:
        result = subprocess.run(
            ["rustfilt"],
            input=asm_text,
            capture_output=True,
            text=True,
            timeout=30,
        )
        if result.returncode == 0:
            return result.stdout
    except (FileNotFoundError, subprocess.TimeoutExpired, OSError) as e:
        msg = f"rustfilt unavailable ({type(e).__name__})"
        print(
            f"[check_rust_asm] WARNING: {msg}, using regex demangling",
            file=sys.stderr,
        )

    # Fallback: partial demangle via regex (strips hash suffix).
    # NOTE: The pattern _ZN[A-Za-z0-9_$]+E matches any Itanium-mangled symbol
    # (C++ included); it may garble non-Rust symbols into odd-looking paths.
    # This is cosmetic — the demangled text is only used for display purposes.
    # e.g. _ZN7example9SecretKey4wipe17h1a2b3c4d5e6f7g8hE -> example::SecretKey::wipe
    def _partial(m: re.Match) -> str:
        sym = m.group(0)
        inner = re.sub(r"17h[0-9a-f]{16}E$", "", sym)
        inner = re.sub(r"^_ZN", "", inner)
        parts = []
        while inner:
            num = re.match(r"^(\d+)", inner)
            if not num:
                break
            n = int(num.group(1))
            inner = inner[len(num.group(1)) :]
            parts.append(inner[:n])
            inner = inner[n:]
        return "::".join(parts) if parts else sym

    return re.sub(r"_ZN[A-Za-z0-9_$]+E", _partial, asm_text)


# ---------------------------------------------------------------------------
# Assembly parsing (shared)
# ---------------------------------------------------------------------------

RE_FUNC_TYPE = re.compile(r"\.type\s+(\S+),\s*@function")
RE_GLOBL = re.compile(r"\.globl\s+(\S+)")
RE_LABEL = re.compile(r"^([A-Za-z_\$][A-Za-z0-9_\$@.]*):")
# Internal compiler-generated labels: Ltmp0, LBB0_1, .Ltmp0, etc.
RE_INTERNAL_LABEL = re.compile(r"^\.?L[A-Z_]")


def parse_functions(asm_lines: list[str]) -> dict[str, list[tuple[int, str]]]:
    """
    Split assembly into per-function sections.
    Returns {function_name: [(line_no, line_text), ...]}

    Supports both ELF (`.type sym,@function`) and Mach-O (`.globl sym`)
    object formats. When no `.type` directives are found (macOS), falls back
    to `.globl` symbols. Internal compiler labels (LBB0_1, Ltmp0, .Ltmp0)
    are always excluded from function-start candidates.
    """
    functions: dict[str, list[tuple[int, str]]] = {}
    current: str | None = None
    current_lines: list[tuple[int, str]] = []

    func_names: set[str] = set()
    for line in asm_lines:
        m = RE_FUNC_TYPE.search(line)
        if m:
            func_names.add(m.group(1))

    # Mach-O fallback: if no ELF .type directives found, use .globl symbols
    if not func_names:
        for line in asm_lines:
            m = RE_GLOBL.search(line)
            if m:
                func_names.add(m.group(1))

    for lineno, line in enumerate(asm_lines, 1):
        stripped = line.strip()
        m = RE_LABEL.match(stripped)
        if m:
            label = m.group(1)
            # Always skip internal compiler-generated labels regardless of func_names
            if RE_INTERNAL_LABEL.match(label):
                if current is not None:
                    current_lines.append((lineno, line))
                continue
            if not func_names or label in func_names:
                if current is not None:
                    functions[current] = current_lines
                current = label
                current_lines = [(lineno, line)]
                continue
        if current is not None:
            current_lines.append((lineno, line))

    if current is not None:
        functions[current] = current_lines

    return functions


# ---------------------------------------------------------------------------
# Sensitive object matching (shared)
# ---------------------------------------------------------------------------


def load_secrets(secrets_path: str) -> list[str] | None:
    """Return sensitive type/symbol names from sensitive-objects.json.

    Returns an empty list when the file is absent (no secrets configured is
    valid), or None when the file exists but contains corrupt JSON (signals an
    error to the caller so analysis is not silently skipped).
    """
    try:
        with open(secrets_path, encoding="utf-8") as f:
            objects = json.load(f)
        names = []
        for obj in objects:
            if obj.get("language") == "rust":
                names.append(obj.get("name", ""))
        return [n for n in names if n]
    except FileNotFoundError:
        return []
    except json.JSONDecodeError as e:
        print(
            f"[check_rust_asm] ERROR: corrupt secrets JSON at {secrets_path!r}: {e}",
            file=sys.stderr,
        )
        return None


def is_sensitive_function(func_name: str, sensitive_names: list[str]) -> bool:
    """True if the demangled function name relates to a sensitive type."""
    lower = func_name.lower()
    if "drop_in_place" in lower:
        return any(name.lower() in lower for name in sensitive_names)
    return any(name.lower() in lower for name in sensitive_names)


# ---------------------------------------------------------------------------
# Drop glue check (shared — covers both x86-64 `call` and AArch64 `bl`)
# ---------------------------------------------------------------------------

# Matches both x86-64 `call` and AArch64 `bl` to zeroize/memset routines
RE_WIPE_CALL = re.compile(r"(?:call|bl)\s+.*(?:memset|volatile_set_memory|zeroize)")


def check_drop_glue(
    func_name: str,
    func_lines: list[tuple[int, str]],
) -> dict | None:
    """
    For drop_in_place::<SensitiveType> functions, check for zeroize calls.
    If absent, emit MISSING_SOURCE_ZEROIZE (medium) as corroboration.
    Works for both x86-64 and AArch64 assembly.
    """
    if "drop_in_place" not in func_name.lower():
        return None

    has_zeroize = any(
        RE_WIPE_CALL.search(line) or "zeroize" in line.lower() for _, line in func_lines
    )
    if not has_zeroize:
        return {
            "category": "MISSING_SOURCE_ZEROIZE",
            "severity": "medium",
            "symbol": func_name,
            "detail": (
                f"drop_in_place for '{func_name}' has no zeroize/volatile-store calls "
                f"— sensitive type may not be wiped on drop"
            ),
            "evidence_detail": (
                f"No zeroize call found in {func_name} drop glue ({len(func_lines)} lines)"
            ),
        }
    return None


# ---------------------------------------------------------------------------
# Arch module loader
# ---------------------------------------------------------------------------


def _load_arch_module(name: str):
    """Load an arch backend module from the same directory as this script."""
    script_dir = Path(__file__).parent
    module_path = script_dir / f"{name}.py"
    spec = importlib.util.spec_from_file_location(name, module_path)
    if spec is None or spec.loader is None:
        raise ImportError(
            f"Cannot load arch module {name!r} from {module_path} — "
            "file not found or not a valid Python module"
        )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Analyze Rust assembly for STACK_RETENTION and REGISTER_SPILL"
    )
    parser.add_argument("--asm", required=True, help="Path to .s assembly file")
    parser.add_argument("--secrets", required=True, help="Path to sensitive-objects.json")
    parser.add_argument("--out", required=True, help="Output JSON path")
    args = parser.parse_args()

    out_path = Path(args.out)

    def _write_empty_and_return(code: int, message: str = "") -> int:
        out_path.parent.mkdir(parents=True, exist_ok=True)
        if code != 0 and message:
            error_output = [
                {
                    "id": "F-RUST-ASM-ERROR",
                    "category": "ANALYSIS_ERROR",
                    "severity": "info",
                    "detail": message,
                    "location": {"file": str(asm_path), "line": 0},
                }
            ]
            out_path.write_text(json.dumps(error_output, indent=2), encoding="utf-8")
        else:
            out_path.write_text("[]", encoding="utf-8")
        return code

    asm_path = Path(args.asm)
    if not asm_path.exists():
        print(f"[check_rust_asm] ERROR: assembly file not found: {asm_path}", file=sys.stderr)
        return _write_empty_and_return(1, f"Assembly file not found: {asm_path}")

    try:
        asm_text = asm_path.read_text(encoding="utf-8", errors="replace")
    except OSError as e:
        print(f"[check_rust_asm] ERROR: cannot read assembly file: {e}", file=sys.stderr)
        return _write_empty_and_return(1, f"Cannot read assembly file: {e}")

    arch = detect_architecture(asm_text)

    if arch == "x86_64":
        try:
            arch_module = _load_arch_module("check_rust_asm_x86")
        except ImportError as e:
            print(f"[check_rust_asm] ERROR: cannot load x86 backend: {e}", file=sys.stderr)
            return _write_empty_and_return(1, f"Cannot load x86 backend: {e}")
    elif arch == "aarch64":
        print(
            "[check_rust_asm] NOTE: AArch64 support is EXPERIMENTAL. "
            "Findings require manual verification before inclusion in a report.",
            file=sys.stderr,
        )
        try:
            arch_module = _load_arch_module("check_rust_asm_aarch64")
        except ImportError as e:
            print(f"[check_rust_asm] ERROR: cannot load AArch64 backend: {e}", file=sys.stderr)
            return _write_empty_and_return(1, f"Cannot load AArch64 backend: {e}")
    else:
        print(
            f"[check_rust_asm] WARNING: unsupported assembly architecture '{arch}'. "
            "Writing skipped finding.",
            file=sys.stderr,
        )
        output = [
            {
                "id": "F-RUST-ASM-SKIP-0001",
                "category": "ANALYSIS_SKIPPED",
                "severity": "info",
                "confidence": "confirmed",
                "detail": f"Unsupported assembly architecture '{arch}' -- no analysis performed",
                "location": {"file": str(asm_path), "line": 0},
            }
        ]
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_text(json.dumps(output, indent=2), encoding="utf-8")
        return 0

    asm_demangled = demangle_symbols(asm_text)
    asm_lines = asm_demangled.splitlines(keepends=True)

    sensitive_names = load_secrets(args.secrets)
    if sensitive_names is None:
        print("[check_rust_asm] ERROR: aborting due to corrupt secrets file", file=sys.stderr)
        return _write_empty_and_return(1, "Aborting due to corrupt secrets file")
    if not sensitive_names:
        print(
            "[check_rust_asm] WARNING: no Rust sensitive objects found in secrets file",
            file=sys.stderr,
        )

    functions = parse_functions([line.rstrip("\n") for line in asm_lines])

    # Deduplicate: collapse monomorphized instances of the same generic function.
    seen_findings: dict[tuple, dict] = {}
    instance_counts: dict[tuple, int] = defaultdict(int)
    raw_findings: list[dict] = []

    def _dedup_key(finding: dict, base_name: str) -> tuple:
        if finding["category"] == "REGISTER_SPILL":
            return (finding["category"], base_name, finding.get("evidence_detail", ""))
        return (finding["category"], base_name)

    def _record(finding: dict, base_name: str) -> None:
        key = _dedup_key(finding, base_name)
        instance_counts[key] += 1
        if key not in seen_findings:
            seen_findings[key] = finding
            # Store base_name so the output phase can reconstruct the dedup key
            # without recomputing it from finding["symbol"] (which may differ due
            # to monomorphization hash stripping vs. type-param stripping).
            finding["_base_name"] = base_name
            raw_findings.append(finding)

    for func_name, func_lines in functions.items():
        if not is_sensitive_function(func_name, sensitive_names):
            continue

        # Derive base name: strip monomorphization hash and type params
        base_name = re.sub(r"::h[0-9a-f]{16}$", "", func_name)
        base_name = re.sub(r"::<[^>]+>", "", base_name)

        # Arch-specific findings (STACK_RETENTION, REGISTER_SPILL, red zone)
        for finding in arch_module.analyze_function(func_name, func_lines):
            _record(finding, base_name)

        # Drop glue check (shared — works for both x86-64 and AArch64)
        finding = check_drop_glue(func_name, func_lines)
        if finding:
            _record(finding, base_name)

    # Assign IDs and build final output
    output = []
    for idx, finding in enumerate(raw_findings, 1):
        base_name = finding.pop("_base_name", finding["symbol"])
        key = _dedup_key(finding, base_name)
        count = instance_counts.get(key, 1)
        evidence_detail = finding.pop("evidence_detail", "")
        if count > 1:
            evidence_detail += f" (seen in {count} monomorphized instances)"
        output.append(
            {
                "id": f"F-RUST-ASM-{idx:04d}",
                "language": "rust",
                "category": finding["category"],
                "severity": finding["severity"],
                "symbol": finding["symbol"],
                "detail": finding["detail"],
                "evidence": [{"source": "asm", "detail": evidence_detail}],
                "evidence_files": [str(asm_path)],
            }
        )

    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(output, indent=2), encoding="utf-8")
    print(f"[check_rust_asm] {len(output)} finding(s) written to {args.out}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
