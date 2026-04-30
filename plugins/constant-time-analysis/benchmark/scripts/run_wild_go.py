#!/usr/bin/env python3
# /// script
# requires-python = ">=3.10"
# ///
"""
Wild-mode Go benchmark runner. Walks a list of Go packages, runs
``go build -gcflags=-S`` against each from a workspace with the package
in its go.mod, parses the assembly with the analyzer's Go branch, and
applies the v3 filter stack.

Usage:
    PYTHONPATH=. python3 benchmark/scripts/run_wild_go.py \
        --workspace benchmark/wild_go/workspace \
        --target stdlib:crypto/internal/fips140/mlkem \
        --target circl:github.com/cloudflare/circl/kem/mlkem/mlkem768 \
        --label go_stdlib_v3 \
        --out benchmark/results/wild_stdlib_v3.json

Build-validity preconditions (mirroring the C side):
- refuse to print headlines if any package failed to emit assembly
- refuse to print headlines if total instructions parsed < 1000

Symbol-prefix filtering: by default the disassembly only includes the
target package's symbols (gc-S emits ONE package per invocation). To
also exclude same-package generated code we accept --exclude-test
and --exclude-generated.
"""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import tempfile
from collections import Counter
from pathlib import Path

PLUGIN = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(PLUGIN))
sys.path.insert(0, str(PLUGIN / "benchmark" / "scripts"))

from ct_analyzer.analyzer import AssemblyParser  # noqa: E402
from ct_analyzer.filters import apply_filters  # noqa: E402

DEFAULT_FILTERS = [
    "compiler-helpers", "memcmp-source", "ct-funcs",
    "non-secret", "div-public", "loop-backedge",
    "go-bounds-check", "go-stack-grow", "go-public-line",
    "aggregate",
]


def run_build_S(pkg: str, workspace: Path, opt: str = "default") -> str:
    """Run `go build -gcflags=-S <pkg>` from the workspace and return stderr
    (which is where the gc compiler's -S listing goes)."""
    env = os.environ.copy()
    env["GOOS"] = env.get("GOOS", "linux")
    env["GOARCH"] = env.get("GOARCH", "amd64")
    env["CGO_ENABLED"] = "0"
    gcflag_parts = ["-S"]
    if opt == "O0":
        gcflag_parts.extend(["-N", "-l"])
    gcflags = " ".join(gcflag_parts)

    with tempfile.TemporaryDirectory() as tmpdir:
        bin_path = os.path.join(tmpdir, "discard")
        # `all=` prefix forces the flag onto every package being compiled
        # (otherwise -S only applies to the top-level package). We want
        # only the target package's symbols, so we use the unprefixed
        # form.
        cmd = ["go", "build", "-o", bin_path, "-gcflags", gcflags, pkg]
        result = subprocess.run(
            cmd, capture_output=True, text=True, env=env,
            cwd=str(workspace), timeout=300,
        )
    return result.stderr


def analyze_package(pkg: str, label_prefix: str, workspace: Path,
                    filters: list[str]) -> dict:
    """Build + analyze + filter one package. Returns a per-package report
    dict with findings, instruction count, function count, and any
    build error."""
    asm = run_build_S(pkg, workspace, opt="default")
    parser = AssemblyParser("x86_64", "go")
    funcs, viols = parser.parse(asm, include_warnings=True)
    n_instr = sum(f["instructions"] for f in funcs)
    if n_instr == 0:
        return {
            "package": pkg, "label_prefix": label_prefix,
            "n_functions": 0, "n_instructions": 0,
            "build_error": (asm[:400] + "..." if len(asm) > 400 else asm),
            "findings": [],
        }
    kept, _ = apply_filters(viols, filters)
    findings = []
    for v in kept:
        findings.append({
            "package": pkg,
            "function": v.function,
            "file": v.file,
            "line": v.line,
            "address": v.address,
            "mnemonic": v.mnemonic,
            "severity": v.severity.value,
            "reason": v.reason,
        })
    return {
        "package": pkg,
        "label_prefix": label_prefix,
        "n_functions": len(funcs),
        "n_instructions": n_instr,
        "findings": findings,
    }


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--workspace", required=True,
                    help="Go workspace dir with go.mod that imports the targets")
    ap.add_argument("--target", action="append", default=[],
                    help="Repeatable: <label>:<pkg-path>, e.g. stdlib:crypto/sha256")
    ap.add_argument("--filter",
                    default=",".join(DEFAULT_FILTERS),
                    help="Comma-separated filter set")
    ap.add_argument("--label", required=True, help="Output label")
    ap.add_argument("--out", default=None, help="Write JSON to this path")
    args = ap.parse_args()

    workspace = Path(args.workspace).resolve()
    if not (workspace / "go.mod").exists():
        print(f"FATAL: {workspace}/go.mod not found", file=sys.stderr)
        return 2
    filters = [s.strip() for s in args.filter.split(",") if s.strip()]

    targets = []
    for t in args.target:
        if ":" not in t:
            print(f"FATAL: --target expects label:pkg, got {t!r}", file=sys.stderr)
            return 2
        lp, pkg = t.split(":", 1)
        targets.append((lp, pkg))
    if not targets:
        print("FATAL: at least one --target required", file=sys.stderr)
        return 2

    print(f"== {args.label}: {len(targets)} packages ==", file=sys.stderr)
    per_pkg: list[dict] = []
    failed: list[str] = []
    for label_prefix, pkg in targets:
        print(f"  building+analyzing {pkg}...", file=sys.stderr)
        r = analyze_package(pkg, label_prefix, workspace, filters)
        per_pkg.append(r)
        if r.get("build_error") and r["n_instructions"] == 0:
            failed.append(pkg)

    total_funcs = sum(r["n_functions"] for r in per_pkg)
    total_instr = sum(r["n_instructions"] for r in per_pkg)
    all_findings = [f for r in per_pkg for f in r["findings"]]

    # Build-validity preconditions
    if failed and len(failed) == len(targets):
        print(f"FATAL: every package failed to build:", file=sys.stderr)
        for f in failed:
            print(f"  - {f}", file=sys.stderr)
        return 2
    if total_instr < 1000:
        print(f"FATAL: only {total_instr} instructions parsed across "
              f"{len(targets)} packages. Refusing to report headline.",
              file=sys.stderr)
        return 2
    if failed:
        print(f"WARNING: {len(failed)} packages failed to build "
              f"(treating as 0 findings each):", file=sys.stderr)
        for f in failed:
            print(f"  - {f}", file=sys.stderr)

    by_severity = Counter(f["severity"] for f in all_findings)
    by_mnemonic = Counter(f["mnemonic"] for f in all_findings)
    by_pkg = {r["package"]: len(r["findings"]) for r in per_pkg}

    out = {
        "label": args.label,
        "n_packages": len(targets),
        "n_packages_failed": len(failed),
        "n_functions": total_funcs,
        "n_instructions": total_instr,
        "n_findings": len(all_findings),
        "findings_per_1k_instr": (
            round(len(all_findings) * 1000 / max(1, total_instr), 2)
        ),
        "by_severity": dict(by_severity),
        "by_mnemonic": dict(by_mnemonic.most_common()),
        "by_package": by_pkg,
        "per_package": [
            {k: v for k, v in r.items() if k != "findings"} for r in per_pkg
        ],
        "findings": all_findings,
    }

    print(f"\n=== {args.label} ===")
    print(f"  packages       : {len(targets)} ({len(failed)} failed)")
    print(f"  functions      : {total_funcs}")
    print(f"  instructions   : {total_instr}")
    print(f"  total findings : {len(all_findings)}")
    print(f"  per 1k instrs  : {out['findings_per_1k_instr']}")
    print(f"  by severity    : {dict(by_severity)}")
    print(f"  top mnemonics  : {dict(by_mnemonic.most_common(10))}")
    print(f"  top packages by finding count:")
    for pkg, n in sorted(by_pkg.items(), key=lambda kv: -kv[1])[:10]:
        print(f"    {n:>5}  {pkg}")

    if args.out:
        Path(args.out).write_text(json.dumps(out, indent=2))
        print(f"  wrote {args.out}")

    return 0


if __name__ == "__main__":
    sys.exit(main())
