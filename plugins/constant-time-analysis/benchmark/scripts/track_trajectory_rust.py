#!/usr/bin/env python3
# /// script
# requires-python = ">=3.10"
# ///
"""Append a benchmark result to a trajectory JSONL.

Each line of the trajectory file is one row from one benchmark run:
label, timestamp, config, totals (P/R/F1/CT-AFI/error_count/warning_count).
The `pretty` subcommand renders the trajectory as an aligned table for
the V2_DESIGN writeup.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path


def cmd_append(args) -> int:
    rep = json.loads(args.result.read_text())
    row = {
        "label": rep["label"],
        "timestamp": rep["timestamp"],
        "config": rep["config"],
        "totals": rep["totals"],
    }
    args.trajectory.parent.mkdir(parents=True, exist_ok=True)
    with args.trajectory.open("a") as f:
        f.write(json.dumps(row) + "\n")
    print(f"appended {rep['label']} -> {args.trajectory}", file=sys.stderr)
    return 0


def cmd_pretty(args) -> int:
    if not args.trajectory.is_file():
        print(f"no trajectory at {args.trajectory}", file=sys.stderr)
        return 1
    rows = [json.loads(l) for l in args.trajectory.read_text().splitlines() if l.strip()]
    if not rows:
        return 0
    print(
        f"{'label':<32}  {'F1':>5}  {'F1act':>5}  {'AFI':>6}  {'AFIact':>6}  "
        f"{'TP':>3}  {'FP':>4}  {'FPact':>5}  {'FN':>3}"
    )
    print("-" * 90)
    for r in rows:
        t = r["totals"]
        f1_act = t.get("f1_actionable", t.get("f1", 0))
        afi_act = t.get("ct_afi_actionable", t.get("ct_afi", 0))
        fp_act = t.get("fp_actionable", t.get("fp", 0))
        print(
            f"{r['label'][:32]:<32}  {t['f1']:>5.3f}  {f1_act:>5.3f}  "
            f"{t['ct_afi']:>6.4f}  {afi_act:>6.4f}  "
            f"{t['tp']:>3}  {t['fp']:>4}  {fp_act:>5}  {t['fn']:>3}"
        )
    return 0


def main() -> int:
    p = argparse.ArgumentParser()
    sub = p.add_subparsers(dest="cmd", required=True)

    p_app = sub.add_parser("append")
    p_app.add_argument("result", type=Path)
    p_app.add_argument(
        "--trajectory",
        type=Path,
        default=Path(__file__).resolve().parents[1] / "results" / "rust_trajectory.jsonl",
    )
    p_app.set_defaults(func=cmd_append)

    p_pretty = sub.add_parser("pretty")
    p_pretty.add_argument(
        "--trajectory",
        type=Path,
        default=Path(__file__).resolve().parents[1] / "results" / "rust_trajectory.jsonl",
    )
    p_pretty.set_defaults(func=cmd_pretty)

    args = p.parse_args()
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
