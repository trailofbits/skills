#!/usr/bin/env python3
# /// script
# requires-python = ">=3.10"
# ///
"""Validates the Rust benchmark corpus against the constant-time analyzer.

For every CVE pattern in `vulnerable/`, the analyzer must report at least
one ERROR-level violation. For every paired fix in `safe/`, it must report
zero ERRORs. A non-zero exit means at least one expectation failed -- treat
it like a regression and investigate before shipping a release of the
analyzer.

This is the harness we use to show "the tool works on real-world vulns."
"""

from __future__ import annotations

import json
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path

PLUGIN_ROOT = Path(__file__).resolve().parents[4]
ANALYZER = PLUGIN_ROOT / "ct_analyzer" / "analyzer.py"
BENCH_DIR = Path(__file__).resolve().parent

# Patterns we expect the analyzer to detect at ERROR level. Each tuple is
# `(filename, expected_min_errors)`. We pin a minimum because compiler
# upgrades can fold or unfold a few divisions; we only enforce the floor.
VULNERABLE_EXPECTATIONS = [
    ("kyberslash.rs", 2),
    ("minerva.rs", 2),
    ("rsa_timing.rs", 2),
    # `lucky13.rs` is purely branch-based; flagged only with --warnings.
]

VULNERABLE_WARNING_EXPECTATIONS = [
    ("lucky13.rs", 4),  # multiple early-exit branches
]

# Safe fixtures must have zero ERROR-level violations. Warnings may occur
# on public-loop bounds; we don't enforce a count for those.
SAFE_FIXTURES = [
    "kyberslash.rs",
    "lucky13.rs",
    "minerva.rs",
    "rsa_timing.rs",
]


@dataclass
class Result:
    name: str
    passed: bool
    detail: str


def run_analyzer(source: Path, *extra: str) -> dict:
    cmd = [
        "uv",
        "run",
        str(ANALYZER),
        "--json",
        *extra,
        str(source),
    ]
    proc = subprocess.run(cmd, capture_output=True, text=True, cwd=PLUGIN_ROOT)
    try:
        return json.loads(proc.stdout)
    except json.JSONDecodeError as exc:
        raise RuntimeError(
            f"non-JSON output from analyzer for {source}:\n"
            f"stdout={proc.stdout!r}\nstderr={proc.stderr!r}"
        ) from exc


def check_vulnerable(name: str, min_errors: int) -> Result:
    src = BENCH_DIR / "vulnerable" / name
    report = run_analyzer(src)
    n = report.get("error_count", 0)
    ok = n >= min_errors
    detail = (
        f"{n} ERRORs (expected >= {min_errors})"
        if ok
        else f"FAILED to detect: only {n} ERROR(s), expected >= {min_errors}"
    )
    return Result(f"vulnerable/{name}", ok, detail)


def check_vulnerable_warnings(name: str, min_warnings: int) -> Result:
    src = BENCH_DIR / "vulnerable" / name
    report = run_analyzer(src, "--warnings")
    n = report.get("warning_count", 0)
    ok = n >= min_warnings
    detail = (
        f"{n} WARNs (expected >= {min_warnings})"
        if ok
        else f"FAILED to detect: only {n} WARN(s), expected >= {min_warnings}"
    )
    return Result(f"vulnerable[warn]/{name}", ok, detail)


def check_safe(name: str) -> Result:
    src = BENCH_DIR / "safe" / name
    report = run_analyzer(src)
    n = report.get("error_count", 0)
    ok = n == 0
    detail = (
        "0 ERRORs (clean)"
        if ok
        else f"FALSE POSITIVE: {n} ERROR(s) on safe code"
    )
    return Result(f"safe/{name}", ok, detail)


def main() -> int:
    if not ANALYZER.exists():
        print(f"analyzer not found at {ANALYZER}", file=sys.stderr)
        return 2

    results: list[Result] = []
    for name, n in VULNERABLE_EXPECTATIONS:
        results.append(check_vulnerable(name, n))
    for name, n in VULNERABLE_WARNING_EXPECTATIONS:
        results.append(check_vulnerable_warnings(name, n))
    for name in SAFE_FIXTURES:
        results.append(check_safe(name))

    print(f"{'=' * 70}")
    print("Rust constant-time analyzer benchmark")
    print(f"{'=' * 70}")
    width = max(len(r.name) for r in results)
    for r in results:
        status = "PASS" if r.passed else "FAIL"
        print(f"  [{status}]  {r.name:<{width}}   {r.detail}")
    print(f"{'-' * 70}")
    failed = [r for r in results if not r.passed]
    print(f"Total: {len(results)}   Passed: {len(results) - len(failed)}   Failed: {len(failed)}")
    return 0 if not failed else 1


if __name__ == "__main__":
    sys.exit(main())
