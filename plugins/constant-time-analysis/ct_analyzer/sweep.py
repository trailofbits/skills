#!/usr/bin/env -S uv run --script
# /// script
# requires-python = ">=3.11"
# dependencies = []
# ///
"""Run analyzer.py across architectures and optimization levels in one call.

Each configuration is a separate `analyzer.py --json` run, exactly as if it were invoked by
hand; its complete JSON payload is written to OUT/<file>.<arch>.<level>.json. The console gets
one line per configuration (PASSED / FAILED / ERROR with the reason) and a merged worklist:
every flagged instruction, grouped by function, with the configurations that emitted it.
A configuration that could not run is reported as ERROR, never as clean.

    sweep.py --warnings crypto.c                          # x86_64,arm64 x O0,O1,O2,O3,Os,Oz
    sweep.py --warnings --archs arm64 --levels O0,O2 crypto.go
    sweep.py --warnings --func 'sign|verify' --out ct-sweep crypto.c
    sweep.py --warnings --json crypto.c                   # merged worklist as JSON

Bytecode and scripting languages (Java, Kotlin, C#, PHP, JavaScript, TypeScript, Python,
Ruby) ignore --arch/--opt-level, so they run once.

Exit codes: 0 every configuration passed, 1 at least one FAILED, 2 at least one could not run
or bad arguments.
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

HERE = Path(__file__).resolve().parent
ANALYZER = HERE / "analyzer.py"
NATIVE = {".c", ".h", ".cc", ".cpp", ".cxx", ".hpp", ".hxx", ".go", ".rs", ".swift"}
DEFAULT_ARCHS = "x86_64,arm64"
DEFAULT_LEVELS = "O0,O1,O2,O3,Os,Oz"


def run_one(args: argparse.Namespace, arch: str | None, level: str | None) -> dict:
    cmd = [sys.executable, str(ANALYZER), "--json", str(args.source_file)]
    if args.warnings:
        cmd.append("--warnings")
    if arch:
        cmd += ["--arch", arch]
    if level:
        cmd += ["--opt-level", level]
    if args.compiler:
        cmd += ["--compiler", args.compiler]
    if args.func:
        cmd += ["--func", args.func]
    for flag in args.extra_flags:
        cmd += ["--extra-flags", flag]
    proc = subprocess.run(cmd, capture_output=True, text=True)
    try:
        payload = json.loads(proc.stdout)
    except json.JSONDecodeError:
        payload = {"error": (proc.stderr or proc.stdout).strip() or f"exit {proc.returncode}"}
    return {"arch": arch, "level": level, "payload": payload}


def status(payload: dict) -> str:
    if "error" in payload:
        return "ERROR"
    return "PASSED" if payload.get("passed") else "FAILED"


def config_name(r: dict) -> str:
    return f"{r['arch']}/{r['level']}" if r["arch"] else "default"


def merge(results: list[dict]) -> list[dict]:
    """One entry per (function, mnemonic, severity, line) with the configurations that hit it."""
    merged: dict[tuple, dict] = {}
    for r in results:
        for v in r["payload"].get("violations", []):
            key = (v.get("function"), v.get("mnemonic"), v.get("severity"), v.get("line"))
            entry = merged.setdefault(
                key,
                {
                    "function": v.get("function"),
                    "mnemonic": v.get("mnemonic"),
                    "severity": v.get("severity"),
                    "line": v.get("line"),
                    "reason": v.get("reason"),
                    "configs": [],
                    "count": 0,
                },
            )
            entry["count"] += 1
            name = config_name(r)
            if name not in entry["configs"]:
                entry["configs"].append(name)
    order = {"error": 0, "warning": 1}
    return sorted(
        merged.values(),
        key=lambda e: (str(e["function"]), order.get(e["severity"], 2), str(e["mnemonic"])),
    )


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("source_file", type=Path)
    ap.add_argument("--warnings", "-w", action="store_true", help="pass --warnings (do it)")
    ap.add_argument("--archs", default=DEFAULT_ARCHS, help=f"comma list (default {DEFAULT_ARCHS})")
    ap.add_argument(
        "--levels", default=DEFAULT_LEVELS, help=f"comma list (default {DEFAULT_LEVELS})"
    )
    ap.add_argument("--compiler", "-c", help="compiler override, passed to every run")
    ap.add_argument("--func", "-f", help="function regex, passed to every run")
    ap.add_argument("--extra-flags", "-X", action="append", default=[])
    ap.add_argument("--out", type=Path, default=Path("ct-sweep"), help="directory for payloads")
    ap.add_argument("--json", action="store_true", help="print the merged result as JSON")
    ap.add_argument("--jobs", type=int, default=4)
    args = ap.parse_args()

    if not args.source_file.is_file():
        print(f"error: source file not found: {args.source_file}", file=sys.stderr)
        return 2
    native = args.source_file.suffix.lower() in NATIVE
    if native:
        archs = [a for a in args.archs.split(",") if a]
        levels = [lv.lstrip("-") for lv in args.levels.split(",") if lv]
        if not archs or not levels:
            print("error: --archs and --levels need at least one value each", file=sys.stderr)
            return 2
        combos = [(a, lv) for a in archs for lv in levels]
    else:
        combos = [(None, None)]

    with ThreadPoolExecutor(max_workers=max(1, args.jobs)) as pool:
        results = list(pool.map(lambda c: run_one(args, *c), combos))

    args.out.mkdir(parents=True, exist_ok=True)
    stem = args.source_file.name
    for r in results:
        suffix = f"{r['arch']}.{r['level']}" if r["arch"] else "default"
        r["path"] = str(args.out / f"{stem}.{suffix}.json")
        Path(r["path"]).write_text(json.dumps(r["payload"], indent=1) + "\n")

    worklist = merge(results)
    summary = {
        "source_file": str(args.source_file),
        "warnings": args.warnings,
        "configurations": [
            {
                "config": config_name(r),
                "status": status(r["payload"]),
                "compiler": r["payload"].get("compiler"),
                "errors": r["payload"].get("error_count"),
                "warnings": r["payload"].get("warning_count"),
                "error": r["payload"].get("error"),
                "payload": r["path"],
            }
            for r in results
        ],
        "worklist": worklist,
    }
    (args.out / f"{stem}.sweep.json").write_text(json.dumps(summary, indent=1) + "\n")

    if args.json:
        print(json.dumps(summary, indent=1))
    else:
        if not native:
            print("bytecode/scripting language: --arch/--opt-level do not apply; one run")
        if not args.warnings:
            print(
                "note: run without --warnings; branch, comparison, lookup and encoding "
                "families are silent"
            )
        print(f"configurations ({len(results)}), full payloads in {args.out}/:")
        for c in summary["configurations"]:
            detail = (
                c["error"].strip().splitlines()[0][:160]
                if c["error"]
                else f"{c['errors']} error(s), {c['warnings']} warning(s), {c['compiler']}"
            )
            print(f"  {c['config']:<14} {c['status']:<6} {detail}")
        print(f"worklist: {len(worklist)} distinct flagged instruction(s)")
        current = None
        explained: set[str] = set()
        for e in worklist:
            if e["function"] != current:
                current = e["function"]
                print(f"\n{current}")
            where = f" line {e['line']}" if e["line"] else ""
            configs = "all" if len(e["configs"]) == len(results) else ", ".join(e["configs"])
            print(
                f"  [{e['severity'].upper()}] {e['mnemonic']}{where} x{e['count']}  in: {configs}"
            )
            if e["mnemonic"] not in explained:  # full reasons stay in the payloads
                explained.add(e["mnemonic"])
                print(f"      {e['reason']}")

    statuses = {c["status"] for c in summary["configurations"]}
    if "ERROR" in statuses:
        return 2
    return 1 if "FAILED" in statuses else 0


if __name__ == "__main__":
    raise SystemExit(main())
