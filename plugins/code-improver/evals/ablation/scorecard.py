#!/usr/bin/env python3
"""Render the ablation scorecard: arm A (v2 workflow) vs arm B (v1.1.0 stop-hook loop).

Reads each arm's `claude plugin eval --json` output plus the run workspaces under its
results directory. Arm A's per-round metrics come from the metrics.json its runs write;
arm B keeps no per-round artifacts, so its ledger-derived columns print UNAVAILABLE and
only workspace-derivable metrics (narration hits, out-of-scope bytes, version bumps) are
recomputed here with the same code arm A used — imported from collect_metrics.py, not
duplicated.

An arm that contributes zero run workspaces is an error (exit 2), never a row of zeros:
a baseline that silently did nothing must not score as clean.
"""

from __future__ import annotations

import argparse
import importlib.util
import json
import statistics
import subprocess
import sys
from pathlib import Path
from typing import NoReturn

LEDGER_METRICS = [
    "rounds_used",
    "fix_rounds",
    "converged",
    "capped",
    "escalated",
    "ended_on_unreviewed_fix",
    "refiled_after_verdict",
    "max_consecutive_rounds_same_finding",
    "fixer_failed_rounds",
]
DERIVABLE_METRICS = ["narration_hits_final", "out_of_scope_diff_bytes", "version_bumps"]


def fail(msg: str) -> NoReturn:
    print(f"scorecard.py: {msg}", file=sys.stderr)
    sys.exit(2)


def load_collector(path: Path):
    spec = importlib.util.spec_from_file_location("collect_metrics", path)
    if spec is None or spec.loader is None:
        fail(f"cannot import collector at {path}")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def find_workspaces(results_dir: Path) -> list[Path]:
    """A run workspace is any directory holding the mounted fixture."""
    if not results_dir.is_dir():
        return []
    return sorted({p.parent for p in results_dir.rglob("fixture") if p.is_dir()})


def arm_a_metrics(workspace: Path) -> dict | None:
    hits = list(workspace.rglob("metrics.json"))
    if not hits:
        return None
    return json.loads(hits[0].read_text(encoding="utf-8"))


def arm_b_metrics(workspace: Path, collector) -> dict:
    """Recompute what the final workspace alone can support."""
    metrics: dict = {m: "UNAVAILABLE" for m in LEDGER_METRICS}
    scope_regexes = [collector.glob_to_regex("fixture/**")]
    files = collector.scope_files(workspace, scope_regexes)
    if not files:
        fail(f"arm B workspace {workspace} holds zero fixture files — the run did nothing")
    metrics["narration_hits_final"] = collector.narration_hits(files)

    git_ok = (
        subprocess.run(
            ["git", "-C", str(workspace), "rev-parse", "HEAD"], capture_output=True, check=False
        ).returncode
        == 0
    )
    if git_ok:
        root_sha = subprocess.run(
            ["git", "-C", str(workspace), "rev-list", "--max-parents=0", "HEAD"],
            capture_output=True,
            text=True,
            check=False,
        ).stdout.strip()
        if root_sha:
            metrics["out_of_scope_diff_bytes"] = collector.out_of_scope_diff_bytes(
                workspace, root_sha, scope_regexes
            )
            metrics["version_bumps"] = collector.version_bumps(None, workspace, root_sha)
    else:
        metrics["out_of_scope_diff_bytes"] = "UNAVAILABLE (no git in workspace)"
        metrics["version_bumps"] = "UNAVAILABLE (no git in workspace)"
    return metrics


def summarize(values: list) -> str:
    numeric = [v for v in values if isinstance(v, (int, float)) and not isinstance(v, bool)]
    bools = [v for v in values if isinstance(v, bool)]
    if numeric:
        med = statistics.median(numeric)
        return f"{med:g} (min {min(numeric):g}, max {max(numeric):g}, n={len(numeric)})"
    if bools:
        return f"{sum(bools)}/{len(bools)} true"
    uniq = {str(v) for v in values}
    return ", ".join(sorted(uniq)) if uniq else "—"


def eval_scores(json_path: Path) -> str:
    """The harness JSON schema is not pinned; surface whatever score-like data is there
    rather than guessing at structure."""
    try:
        data = json.loads(json_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        return f"(could not parse {json_path.name}: {exc})"
    return json.dumps(data, indent=2)[:4000]


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--arm-a-json", required=True, type=Path)
    parser.add_argument("--arm-a-results", required=True, type=Path)
    parser.add_argument("--arm-b-json", required=True, type=Path)
    parser.add_argument("--arm-b-results", required=True, type=Path)
    parser.add_argument("--collector", required=True, type=Path)
    args = parser.parse_args()

    collector = load_collector(args.collector)

    a_workspaces = find_workspaces(args.arm_a_results)
    b_workspaces = find_workspaces(args.arm_b_results)
    if not a_workspaces:
        fail(f"arm A contributed zero run workspaces under {args.arm_a_results}")
    if not b_workspaces:
        fail(f"arm B contributed zero run workspaces under {args.arm_b_results}")

    a_rows = [m for m in (arm_a_metrics(ws) for ws in a_workspaces) if m]
    missing_a = len(a_workspaces) - len(a_rows)
    b_rows = [arm_b_metrics(ws, collector) for ws in b_workspaces]
    if not a_rows:
        fail(
            "no arm A workspace produced a metrics.json — the v2 loop never ran; nothing to compare"
        )

    print("# Ablation scorecard: v2 workflow (A) vs v1.1.0 stop-hook (B)\n")
    print(
        f"Arm A: {len(a_rows)} run(s) with metrics "
        f"({missing_a} without — each is a failed run, not a skip)"
    )
    print(f"Arm B: {len(b_rows)} run(s), workspace-derived metrics only\n")

    print("| Metric | Arm A | Arm B |")
    print("|---|---|---|")
    for metric in LEDGER_METRICS + DERIVABLE_METRICS:
        a_vals = [r.get(metric) for r in a_rows if r.get(metric) is not None]
        b_vals = [r.get(metric) for r in b_rows if r.get(metric) is not None]
        b_cell = (
            "UNAVAILABLE (v1.1.0 keeps no per-round artifacts)"
            if all(v == "UNAVAILABLE" for v in b_vals) and b_vals
            else summarize([v for v in b_vals if v != "UNAVAILABLE"])
        )
        print(f"| {metric} | {summarize(a_vals)} | {b_cell} |")

    print("\n## Harness scores (verbatim, both arms)\n")
    print("### Arm A\n```json\n" + eval_scores(args.arm_a_json) + "\n```")
    print("### Arm B\n```json\n" + eval_scores(args.arm_b_json) + "\n```")
    print(
        "\nEvery metric above is reported for both arms, including any where A loses; "
        "this table does no pre-filtering."
    )


if __name__ == "__main__":
    main()
