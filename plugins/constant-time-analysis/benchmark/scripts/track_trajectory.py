#!/usr/bin/env python3
# /// script
# requires-python = ">=3.10"
# ///
"""
Track the CT-AFI improvement trajectory across iterations.

Each iteration writes one row to results/trajectory.jsonl. This script
renders an ASCII plot of CT-AFI vs iteration so we can see whether the
curve is asymptoting (the user's hypothesis: super-linear early, taper later).
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

PLUGIN = Path(__file__).resolve().parents[2]
TRAJ = PLUGIN / "benchmark" / "results" / "trajectory.jsonl"


def load() -> list[dict]:
    if not TRAJ.exists():
        return []
    return [json.loads(l) for l in TRAJ.read_text().splitlines() if l.strip()]


def append(entry: dict) -> None:
    TRAJ.parent.mkdir(parents=True, exist_ok=True)
    with TRAJ.open("a") as f:
        f.write(json.dumps(entry) + "\n")


def render_plot(rows: list[dict], width: int = 60, height: int = 14) -> str:
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


def render_table(rows: list[dict]) -> str:
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


def main() -> None:
    if len(sys.argv) > 1 and sys.argv[1] == "append":
        # append a result JSON file as a row
        result = json.loads(Path(sys.argv[2]).read_text())
        row = dict(result["summary"])
        row["label"] = result.get("label", "?")
        append(row)
        return

    rows = load()
    print("\n=== CT-AFI Trajectory ===\n")
    print(render_table(rows))
    print()
    print(render_plot(rows))


if __name__ == "__main__":
    main()
