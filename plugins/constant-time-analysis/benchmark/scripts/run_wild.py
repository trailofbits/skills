#!/usr/bin/env python3
# /// script
# requires-python = ">=3.10"
# ///
"""
Wild-mode benchmark runner.

Walks the .o files of an actually-built production library, disassembles
each with objdump -d, and runs the analyzer with the tuned filter stack.
Aggregates findings, breaks them down by source library and function-name
hint, and prints a triage-friendly report.

This is the test of the analyzer in the wild - against full production
code, not curated snippets.

Usage:
    PYTHONPATH=. python3 benchmark/scripts/run_wild.py \
        --root benchmark/wild/libsodium --label libsodium \
        --filter ct-funcs,compiler-helpers,aggregate
"""

from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
import tempfile
from collections import Counter, defaultdict
from pathlib import Path

PLUGIN = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(PLUGIN))
sys.path.insert(0, str(PLUGIN / "benchmark" / "scripts"))

from ct_analyzer.analyzer import analyze_assembly  # noqa: E402
from ct_analyzer.filters import apply_filters  # noqa: E402


def find_object_files(root: Path) -> list[Path]:
    """All .o files under root, deduplicated by base path."""
    return sorted(set(root.rglob("*.o")))


def disassemble(obj: Path) -> str:
    """Run objdump -d on the .o, return assembly text."""
    try:
        return subprocess.check_output(
            ["objdump", "-d", "--no-show-raw-insn", str(obj)],
            text=True, errors="replace", timeout=30,
        )
    except subprocess.TimeoutExpired:
        return ""
    except subprocess.CalledProcessError:
        return ""


def analyze_object(obj: Path, filters: list[str]) -> tuple[list[dict], int, int]:
    """Disassemble + analyze one .o.  Returns (findings, n_funcs, n_instrs)."""
    asm = disassemble(obj)
    if not asm:
        return [], 0, 0
    with tempfile.NamedTemporaryFile("w", suffix=".s", delete=False) as f:
        f.write(asm)
        asm_path = f.name
    try:
        report = analyze_assembly(asm_path, "x86_64", include_warnings=True)
    except Exception:
        return [], 0, 0
    finally:
        Path(asm_path).unlink(missing_ok=True)

    # Apply filters that don't need source paths
    asm_only_filters = [f for f in filters if f not in ("memcmp-source", "non-secret")]
    kept, _ = apply_filters(report.violations, asm_only_filters)

    findings = []
    for v in kept:
        findings.append({
            "object": str(obj),
            "function": v.function,
            "mnemonic": v.mnemonic,
            "severity": v.severity.value,
            "reason": v.reason,
        })
    return findings, report.total_functions, report.total_instructions


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--root", required=True, help="Library root directory (built)")
    ap.add_argument("--label", required=True, help="Library label for output")
    ap.add_argument("--filter", default="ct-funcs,compiler-helpers,aggregate",
                    help="Filters to apply")
    ap.add_argument("--out", default=None, help="Write findings JSON to this path")
    ap.add_argument("--limit", type=int, default=0,
                    help="If >0, only analyze the first N .o files (smoke test)")
    args = ap.parse_args()

    filters = [s.strip() for s in args.filter.split(",") if s.strip()]
    root = Path(args.root).resolve()

    obj_files = find_object_files(root)
    # Filter out CMake compiler probe artifacts and obvious non-crypto dirs
    obj_files = [
        o for o in obj_files
        if "CMakeFiles/3" not in str(o) and "/test/" not in str(o)
        and "/tests/" not in str(o) and "/fuzz" not in str(o)
        and "/programs/" not in str(o) and "/bench/" not in str(o)
    ]
    if args.limit > 0:
        obj_files = obj_files[:args.limit]

    print(f"== {args.label}: {len(obj_files)} objects ==", file=sys.stderr)

    all_findings: list[dict] = []
    total_funcs = 0
    total_instrs = 0
    for i, obj in enumerate(obj_files, 1):
        if i % 50 == 0:
            print(f"  [{i}/{len(obj_files)}] processed; running findings: {len(all_findings)}", file=sys.stderr)
        findings, nfunc, ninstr = analyze_object(obj, filters)
        all_findings.extend(findings)
        total_funcs += nfunc
        total_instrs += ninstr

    by_mnemonic = Counter(f["mnemonic"] for f in all_findings)
    by_severity = Counter(f["severity"] for f in all_findings)
    by_object = Counter(Path(f["object"]).name for f in all_findings)

    out = {
        "label": args.label,
        "n_objects": len(obj_files),
        "n_functions": total_funcs,
        "n_instructions": total_instrs,
        "n_findings": len(all_findings),
        "by_mnemonic": dict(by_mnemonic.most_common()),
        "by_severity": dict(by_severity),
        "by_object": dict(by_object.most_common(20)),
        "findings": all_findings,
    }
    print(f"\n=== {args.label} ===")
    print(f"  objects        : {len(obj_files)}")
    print(f"  functions      : {total_funcs}")
    print(f"  instructions   : {total_instrs}")
    print(f"  total findings : {len(all_findings)}")
    print(f"  per 1k instrs  : {len(all_findings) * 1000 / max(1, total_instrs):.2f}")
    print(f"  by severity    : {dict(by_severity)}")
    print(f"  top mnemonics  : {dict(by_mnemonic.most_common(10))}")
    print(f"  top objects    :")
    for k, v in by_object.most_common(10):
        print(f"    {v:>4}  {k}")

    if args.out:
        Path(args.out).write_text(json.dumps(out, indent=2))
        print(f"  wrote {args.out}")


if __name__ == "__main__":
    main()
