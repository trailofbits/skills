#!/usr/bin/env python3
# /// script
# requires-python = ">=3.10"
# ///
"""Unified trajectory tracker.

Dispatches by ``--language={c,go,rust}`` into the language-specific
trajectory shape:

  * c, go -- the original CT-AFI trajectory format that lives in
             ``benchmark/results/trajectory.jsonl``.  Renders an
             ASCII plot of CT-AFI vs iteration plus an aligned table.
             Subcommands: ``append <result.json>`` or no-args (render).

  * rust  -- the per-run-config trajectory format that lives in
             ``benchmark/results/rust_trajectory.jsonl``.
             Subcommands: ``append <result.json>`` and ``pretty``.

Each path's JSONL on-disk schema is preserved byte-for-byte so the
existing trajectory files stay readable.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

PLUGIN = Path(__file__).resolve().parents[2]


# ---------------------------------------------------------------------------
# C / Go path: unchanged from the pre-unification track_trajectory.py.
# ---------------------------------------------------------------------------

_C_GO_TRAJ = PLUGIN / "benchmark" / "results" / "trajectory.jsonl"


def _c_go_load() -> list[dict]:
    if not _C_GO_TRAJ.exists():
        return []
    return [json.loads(l) for l in _C_GO_TRAJ.read_text().splitlines() if l.strip()]


def _c_go_append(entry: dict) -> None:
    _C_GO_TRAJ.parent.mkdir(parents=True, exist_ok=True)
    with _C_GO_TRAJ.open("a") as f:
        f.write(json.dumps(entry) + "\n")


def _c_go_render_plot(rows: list[dict], width: int = 60, height: int = 14) -> str:
    """ASCII plot of CT-AFI over iteration number."""
    if not rows:
        return "(empty trajectory)"
    xs = list(range(len(rows)))
    ys = [r["ct_afi"] for r in rows]
    y_min, y_max = 0.0, max(0.001, max(ys) * 1.1)
    grid = [[" "] * width for _ in range(height)]

    for i, y in enumerate(ys):
        col = int(i / max(1, len(ys) - 1) * (width - 1)) if len(ys) > 1 else 0
        row = height - 1 - int((y - y_min) / (y_max - y_min) * (height - 1))
        row = max(0, min(height - 1, row))
        grid[row][col] = "*"

    lines = []
    for r, line in enumerate(grid):
        y_label = y_max - (y_max - y_min) * r / (height - 1)
        lines.append(f"{y_label:5.3f} |" + "".join(line))
    lines.append("      +" + "-" * width)
    lines.append("       " + "0" + " " * (width - 2) + str(len(rows) - 1))
    return "\n".join(lines)


def _c_go_render_table(rows: list[dict]) -> str:
    if not rows:
        return ""
    cols = ["iter", "label", "P", "R", "F1", "n_find", "T_min", "CT_AFI", "Δ_AFI"]
    lines = ["  ".join(f"{c:>8}" for c in cols)]
    prev = None
    for i, r in enumerate(rows):
        delta = r["ct_afi"] - prev if prev is not None else 0.0
        prev = r["ct_afi"]
        lines.append("  ".join([
            f"{i:>8}",
            f"{r['label'][:8]:>8}",
            f"{r['precision']:>8.3f}",
            f"{r['recall']:>8.3f}",
            f"{r['f1']:>8.3f}",
            f"{r['n_findings']:>8}",
            f"{r['triage_minutes']:>8.1f}",
            f"{r['ct_afi']:>8.4f}",
            f"{delta:>+8.4f}",
        ]))
    return "\n".join(lines)


def main_c_go(argv: list[str]) -> int:
    """C/Go trajectory: bare-arg CLI preserved from the original script.

    Usage:
      track_trajectory.py --language c                     # render
      track_trajectory.py --language c append <result>     # append + return
    """
    if argv and argv[0] == "append":
        if len(argv) < 2:
            print("usage: track_trajectory.py --language={c,go} append <result.json>",
                  file=sys.stderr)
            return 2
        result = json.loads(Path(argv[1]).read_text())
        row = dict(result["summary"])
        row["label"] = result.get("label", "?")
        _c_go_append(row)
        return 0

    rows = _c_go_load()
    print("\n=== CT-AFI Trajectory ===\n")
    print(_c_go_render_table(rows))
    print()
    print(_c_go_render_plot(rows))
    return 0


# ---------------------------------------------------------------------------
# Rust path: unchanged from the pre-unification track_trajectory_rust.py.
# ---------------------------------------------------------------------------

_RUST_DEFAULT_TRAJ = PLUGIN / "benchmark" / "results" / "rust_trajectory.jsonl"


def _rust_cmd_append(args) -> int:
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


def _rust_cmd_pretty(args) -> int:
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


def main_rust(argv: list[str]) -> int:
    p = argparse.ArgumentParser(prog="track_trajectory.py --language=rust")
    sub = p.add_subparsers(dest="cmd", required=True)

    p_app = sub.add_parser("append")
    p_app.add_argument("result", type=Path)
    p_app.add_argument(
        "--trajectory",
        type=Path,
        default=_RUST_DEFAULT_TRAJ,
    )
    p_app.set_defaults(func=_rust_cmd_append)

    p_pretty = sub.add_parser("pretty")
    p_pretty.add_argument(
        "--trajectory",
        type=Path,
        default=_RUST_DEFAULT_TRAJ,
    )
    p_pretty.set_defaults(func=_rust_cmd_pretty)

    args = p.parse_args(argv)
    return args.func(args)


# ---------------------------------------------------------------------------
# Top-level dispatcher.
# ---------------------------------------------------------------------------

def main() -> int:
    pre = argparse.ArgumentParser(
        description="Unified benchmark trajectory tracker.",
        add_help=False,
    )
    pre.add_argument(
        "--language", required=True, choices=("c", "go", "rust"),
        help="Trajectory schema to read/write.",
    )
    args, remaining = pre.parse_known_args()
    if args.language in ("c", "go"):
        return main_c_go(remaining)
    return main_rust(remaining)


if __name__ == "__main__":
    sys.exit(main())
