#!/usr/bin/env -S uv run --script
# /// script
# requires-python = ">=3.11"
# dependencies = []
# ///
"""Run ProVerif on a model and turn its RESULT lines into a pass/fail verdict.

    verify_pv.py MODEL.pv [--timeout SECONDS] [--json]

Exit 0 only when ProVerif compiles the model and every query has the outcome its kind wants:

* reachability sanity queries (``query ... event(e)`` with no ``==>``) must be *reachable*,
  which ProVerif reports as ``RESULT not event(e) is false``; ``is true`` means the event is
  dead and every other result is vacuous;
* secrecy (``not attacker(...)``) and correspondence (``... ==> ...``) queries must be ``is true``;
* ``cannot be proved`` fails either way, and so do a missing verifier, a compile error, a timeout,
  and a model that produced no RESULT line at all.

The verifier is ``proverif`` on PATH or ``$PROVERIF_BIN``.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import subprocess
import sys
from pathlib import Path

RESULT = re.compile(r"^RESULT (?P<query>.+?) (?P<verdict>is true|is false|cannot be proved)\.?\s*$")


def classify(query: str) -> str:
    """Name the kind of query a RESULT line reports on."""
    if "==>" in query:
        return "correspondence"
    if query.startswith("not attacker(") or query.startswith("attacker("):
        return "secrecy"
    if query.startswith("not event(") or query.startswith("event("):
        return "reachability"
    return "other"


def judge(query: str, verdict: str) -> tuple[str, bool, str]:
    kind = classify(query)
    if verdict == "cannot be proved":
        return kind, False, "ProVerif could not prove it"
    if kind == "reachability":
        # `query event(e)` asks ProVerif to prove e unreachable; the sanity check passes when
        # it fails to, i.e. the event is reachable.
        ok = verdict == "is false"
        return (
            kind,
            ok,
            "event reachable" if ok else "event unreachable: dead process or impossible guard",
        )
    ok = verdict == "is true"
    return kind, ok, "holds" if ok else "violated"


def evaluate(output: str) -> dict:
    results = []
    for line in output.splitlines():
        match = RESULT.match(line.strip())
        if not match:
            continue
        kind, ok, note = judge(match["query"], match["verdict"])
        results.append(
            {
                "query": match["query"],
                "verdict": match["verdict"],
                "kind": kind,
                "ok": ok,
                "note": note,
            }
        )
    return {"results": results, "ok": bool(results) and all(r["ok"] for r in results)}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument("model", type=Path)
    parser.add_argument(
        "--timeout", type=int, default=300, help="seconds before ProVerif is stopped"
    )
    parser.add_argument("--json", action="store_true", help="print the verdict as JSON")
    args = parser.parse_args(argv)

    binary = os.environ.get("PROVERIF_BIN", "proverif")
    if shutil.which(binary) is None:
        print(f"verify_pv.py: ProVerif is required but not found: {binary}", file=sys.stderr)
        return 127
    if not args.model.is_file():
        print(f"verify_pv.py: model not found: {args.model}", file=sys.stderr)
        return 2
    try:
        proc = subprocess.run(
            [binary, str(args.model)], capture_output=True, text=True, timeout=args.timeout
        )
    except subprocess.TimeoutExpired:
        print(f"verify_pv.py: ProVerif did not finish within {args.timeout}s", file=sys.stderr)
        return 1
    output = proc.stdout + proc.stderr
    report = evaluate(output)
    report["exit_status"] = proc.returncode
    if proc.returncode != 0:
        report["ok"] = False
    if args.json:
        print(json.dumps(report, indent=2))
    else:
        for r in report["results"]:
            status = "PASS" if r["ok"] else "FAIL"
            print(f"{status} [{r['kind']}] {r['query']} {r['verdict']} ({r['note']})")
    if proc.returncode != 0:
        print(output[-2000:], file=sys.stderr)
        print("verify_pv.py: ProVerif failed to compile or run the model", file=sys.stderr)
        return 1
    if not report["results"]:
        print(
            "verify_pv.py: ProVerif produced no RESULT lines; the model has no queries",
            file=sys.stderr,
        )
        return 1
    if not report["ok"]:
        print(
            "verify_pv.py: at least one property failed; fix the model rather than the query",
            file=sys.stderr,
        )
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
