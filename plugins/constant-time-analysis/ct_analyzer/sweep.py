#!/usr/bin/env -S uv run --script
# /// script
# requires-python = ">=3.10"
# dependencies = []
# ///
"""Run analyzer.py across architectures and optimization levels in one call.

Each distinct compiler configuration is an `analyzer.py --json` run; equivalent Go/Swift
level aliases share that execution and are named in the summary. Complete payloads are
written to OUT/<file>.<arch>.<level>.json. The console gets one status per configuration
(PASSED / FAILED / ERROR / INCOMPLETE with the reason) and a merged worklist:
every flagged instruction, grouped by function, with the configurations that emitted it.
A failed or empty/degraded analysis is never reported as clean. OUT must be empty.

    sweep.py --warnings crypto.c                          # x86_64,arm64 x O0,O1,O2,O3,Os,Oz
    sweep.py --warnings --archs arm64 --levels O0,O2 crypto.go
    sweep.py --warnings --func 'sign|verify' --out ct-sweep crypto.c
    sweep.py --warnings --json crypto.c                   # merged worklist as JSON

Bytecode and scripting languages (Java, Kotlin, C#, PHP, JavaScript, TypeScript, Python,
Ruby) ignore --arch/--opt-level, so they run once.

Exit codes: 0 every configuration completed without error-level findings, 1 at least one
FAILED, 2 at least one ERROR/INCOMPLETE or bad arguments. PASSED is not a security proof.
"""

from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

try:
    from .analyzer import detect_language, is_bytecode_language
except ImportError:  # direct script invocation
    from analyzer import detect_language, is_bytecode_language

HERE = Path(__file__).resolve().parent
ANALYZER = HERE / "analyzer.py"
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
        cmd.append(f"--extra-flags={flag}")
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True)
    except OSError as error:
        return {
            "arch": arch,
            "level": level,
            "payload": {"error": str(error)},
            "exit_code": None,
            "stdout": "",
            "stderr": str(error),
        }
    try:
        payload = json.loads(proc.stdout)
    except json.JSONDecodeError:
        payload = {"error": (proc.stderr or proc.stdout).strip() or f"exit {proc.returncode}"}
    if not isinstance(payload, dict):
        payload = {"error": "analyzer output is not a JSON object"}
    result = {
        "arch": arch,
        "level": level,
        "payload": payload,
        "exit_code": proc.returncode,
        "stdout": proc.stdout,
        "stderr": proc.stderr,
    }
    if "error" not in payload:
        if not valid_report(payload):
            result["error"] = "analyzer returned an incomplete or inconsistent report schema"
        elif proc.returncode != (0 if payload["passed"] else 1):
            result["error"] = f"analyzer exit {proc.returncode} contradicts its JSON report"
    return result


def valid_report(payload: dict) -> bool:
    counts = ("total_functions", "total_instructions", "error_count", "warning_count")
    if any(type(payload.get(key)) is not int or payload[key] < 0 for key in counts):
        return False
    if type(payload.get("passed")) is not bool or not isinstance(payload.get("violations"), list):
        return False
    if payload["passed"] != (payload["error_count"] == 0):
        return False
    for violation in payload["violations"]:
        if not isinstance(violation, dict):
            return False
        if violation.get("severity") not in ("error", "warning"):
            return False
        if any(
            not isinstance(violation.get(key), str)
            for key in ("function", "mnemonic", "severity", "reason")
        ):
            return False
        if violation.get("line") is not None and type(violation["line"]) is not int:
            return False
    return all(
        payload[f"{severity}_count"]
        == sum(value["severity"] == severity for value in payload["violations"])
        for severity in ("error", "warning")
    )


def status(result: dict) -> str:
    payload = result["payload"]
    if result.get("error") or "error" in payload:
        return "ERROR"
    if not payload.get("total_functions") or not payload.get("total_instructions"):
        return "INCOMPLETE"
    diagnostics = result.get("stderr", "").lower()
    if any(
        marker in diagnostics
        for marker in (
            "source analysis only",
            "no timing violations will be detected",
            "cannot be filtered out",
            "falling back to source",
            "bytecode analysis unavailable",
        )
    ):
        return "INCOMPLETE"
    return "PASSED" if payload.get("passed") else "FAILED"


def effective_level(language: str, level: str, compiler: str | None) -> str:
    """Aliases only for the adapters whose compile methods use these exact mappings."""
    if language == "go" and (not compiler or Path(compiler).name == "go"):
        return "O0" if level == "O0" else "O1"
    if language == "swift" and (not compiler or Path(compiler).name == "swiftc"):
        return {"O0": "O0", "O1": "O1", "O2": "O1", "O3": "O1", "Os": "Os", "Oz": "Os"}[level]
    return level


def config_name(r: dict) -> str:
    return f"{r['arch']}/{r['level']}" if r["arch"] else "default"


def merge(results: list[dict]) -> list[dict]:
    """One entry per (function, mnemonic, severity, line) with the configurations that hit it."""
    merged: dict[tuple, dict] = {}
    for r in results:
        for v in r["payload"].get("violations", []):
            key = (
                v.get("function"),
                v.get("mnemonic"),
                v.get("severity"),
                v.get("line"),
                v.get("reason"),
            )
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
    language = detect_language(str(args.source_file))
    if language == "unknown":
        print(f"error: unsupported source extension: {args.source_file.suffix}", file=sys.stderr)
        return 2
    if args.jobs < 1:
        ap.error("--jobs must be positive")
    if args.func:
        try:
            re.compile(args.func)
        except re.error as error:
            ap.error(f"invalid --func regex: {error}")
    native = not is_bytecode_language(language)
    aliases: dict[tuple, tuple] = {}
    if native:
        archs = [a for a in args.archs.split(",") if a]
        levels = [lv.lstrip("-") for lv in args.levels.split(",") if lv]
        if not archs or not levels:
            print("error: --archs and --levels need at least one value each", file=sys.stderr)
            return 2
        if any(not re.fullmatch(r"[A-Za-z0-9_-]+", arch) for arch in archs):
            ap.error("--archs must contain architecture identifiers, not paths")
        if any(level not in DEFAULT_LEVELS.split(",") for level in levels):
            ap.error(f"--levels must use {DEFAULT_LEVELS}")
        if language == "go" and args.extra_flags:
            ap.error(
                "the Go analyzer adapter does not support --extra-flags; use the project build"
            )
        archs = list(dict.fromkeys(archs))
        levels = list(dict.fromkeys(levels))
        combos = [(a, lv) for a in archs for lv in levels]
        canonical: dict[tuple, tuple] = {}
        for arch, level in combos:
            effective = (arch, effective_level(language, level, args.compiler))
            aliases[(arch, level)] = canonical.setdefault(effective, (arch, level))
    else:
        combos = [(None, None)]
        aliases = {(None, None): (None, None)}

    try:
        args.out.mkdir(parents=True, exist_ok=True)
        if any(args.out.iterdir()):
            print(
                f"error: output directory is not empty; choose a fresh --out: {args.out}",
                file=sys.stderr,
            )
            return 2
        # Reserve this attempt before starting work, including concurrent invocations.
        with (args.out / ".sweep-attempt").open("x") as marker:
            marker.write(str(args.source_file.resolve()) + "\n")
    except OSError as error:
        print(f"error: cannot reserve output directory: {error}", file=sys.stderr)
        return 2

    unique = list(dict.fromkeys(aliases.values()))
    with ThreadPoolExecutor(max_workers=args.jobs) as pool:
        executed = dict(zip(unique, pool.map(lambda c: run_one(args, *c), unique), strict=True))
    results = []
    for arch, level in combos:
        representative = aliases[(arch, level)]
        result = dict(executed[representative], arch=arch, level=level)
        result["executed_as"] = config_name(executed[representative])
        # Keep the requested label in the payload just as a direct invocation does.
        if result["payload"].get("optimization") is not None:
            result["payload"] = dict(result["payload"], optimization=level or "default")
        results.append(result)

    stem = args.source_file.name
    for r in results:
        suffix = f"{r['arch']}.{r['level']}" if r["arch"] else "default"
        r["path"] = str(args.out / f"{stem}.{suffix}.json")
        try:
            with Path(r["path"]).open("x") as output:
                output.write(json.dumps(r["payload"], indent=1) + "\n")
        except OSError as error:
            print(f"error: cannot write payload {r['path']}: {error}", file=sys.stderr)
            return 2

    worklist = merge([r for r in results if valid_report(r["payload"])])
    summary = {
        "source_file": str(args.source_file),
        "source_resolved": str(args.source_file.resolve()),
        "language": language,
        "executions": len(unique),
        "warnings": args.warnings,
        "configurations": [
            {
                "config": config_name(r),
                "status": status(r),
                "executed_as": r["executed_as"],
                "total_functions": r["payload"].get("total_functions"),
                "total_instructions": r["payload"].get("total_instructions"),
                "exit_code": r["exit_code"],
                "stderr": r["stderr"],
                "stdout": r["stdout"],
                "compiler": r["payload"].get("compiler"),
                "errors": r["payload"].get("error_count"),
                "warnings": r["payload"].get("warning_count"),
                "error": r.get("error") or r["payload"].get("error"),
                "payload": r["path"],
            }
            for r in results
        ],
        "worklist": worklist,
    }
    try:
        with (args.out / f"{stem}.sweep.json").open("x") as output:
            output.write(json.dumps(summary, indent=1) + "\n")
    except OSError as error:
        print(f"error: cannot write summary: {error}", file=sys.stderr)
        return 2

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
        print(
            f"configurations ({len(results)}), {len(unique)} execution(s), "
            f"full payloads and process diagnostics in {args.out}/:"
        )
        for c in summary["configurations"]:
            detail = (
                c["error"].strip()
                if c["error"]
                else f"{c['errors']} error(s), {c['warnings']} warning(s), {c['compiler']}"
            )
            print(
                f"  {c['config']:<14} {c['status']:<10} {detail}; "
                f"{c['total_functions']} function(s), {c['total_instructions']} instruction(s)"
            )
            if c["config"] != c["executed_as"]:
                print(f"    same effective compiler settings as {c['executed_as']}")
            if c["status"] == "INCOMPLETE":
                print("    analysis is empty or degraded; inspect the filter and tool diagnostics")
            if c["stderr"].strip():
                print(f"    analyzer diagnostic: {c['stderr'].strip()}")
        print(f"worklist: {len(worklist)} distinct flagged instruction(s)")
        current = None
        explained: set[tuple] = set()
        for e in worklist:
            if e["function"] != current:
                current = e["function"]
                print(f"\n{current}")
            where = f" line {e['line']}" if e["line"] else ""
            configs = "all" if len(e["configs"]) == len(results) else ", ".join(e["configs"])
            print(
                f"  [{e['severity'].upper()}] {e['mnemonic']}{where} x{e['count']}  in: {configs}"
            )
            if (e["mnemonic"], e["reason"]) not in explained:
                explained.add((e["mnemonic"], e["reason"]))
                print(f"      {e['reason']}")

    statuses = {c["status"] for c in summary["configurations"]}
    if statuses & {"ERROR", "INCOMPLETE"}:
        return 2
    return 1 if "FAILED" in statuses else 0


if __name__ == "__main__":
    raise SystemExit(main())
