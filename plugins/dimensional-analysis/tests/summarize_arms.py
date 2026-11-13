#!/usr/bin/env python3
"""Aggregate isolated with/without eval arms and report the ablation delta.

`claude plugin eval --ablation` cannot be used here: both arms share one work
directory and the plugin arm runs first, so the baseline inherits the plugin's
annotated sources. smoke-test.sh instead runs one single-run arm per round with
pristine fixtures staged before each; this script combines those results.

The gate is the plugin arm's deterministic artifact checks. Both deltas are
reported, not gated: the baseline also finds the planted bugs, so this suite is a
regression guard rather than evidence that the plugin beats the baseline.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

ARMS = ("with", "without")


def arm_result(arm_dir: Path) -> dict:
    """Read one arm's semantic score, deterministic verdict, and cost."""
    result: dict = {"score": None, "deterministic": None, "cost": 0.0}

    verdict = arm_dir / "deterministic"
    if verdict.is_file():
        result["deterministic"] = verdict.read_text().strip()

    payload_path = arm_dir / "eval-result.json"
    if not payload_path.is_file():
        return result

    try:
        payload = json.loads(payload_path.read_text())
    except (OSError, json.JSONDecodeError):
        return result

    result["cost"] = payload.get("costUsd") or 0.0
    aggregates = payload.get("aggregates") or {}
    result["score"] = aggregates.get("overallScore")
    return result


def collect(results: Path, rounds: int) -> dict[str, list[dict]]:
    """Gather every round's result for both arms."""
    return {
        arm: [arm_result(results / f"round{r}" / arm) for r in range(1, rounds + 1)] for arm in ARMS
    }


def passes(rows: list[dict]) -> int:
    """Count rounds where the semantic grader scored a full 1.0."""
    return sum(1 for row in rows if row["score"] == 1)


def mean_score(rows: list[dict]) -> float:
    """Mean semantic score, treating an absent score as zero."""
    if not rows:
        return 0.0
    return sum((row["score"] or 0) for row in rows) / len(rows)


def det_rate(rows: list[dict]) -> float:
    """Fraction of rounds passing the deterministic artifact checks."""
    if not rows:
        return 0.0
    return sum(1 for row in rows if row["deterministic"] == "pass") / len(rows)


def report_arm(arm: str, rows: list[dict], rounds: int) -> None:
    """Print one arm's per-round detail and totals."""
    detail = ", ".join(
        f"r{i}: score={row['score']} det={row['deterministic']}"
        for i, row in enumerate(rows, start=1)
    )
    cost = sum(row["cost"] for row in rows)
    det_passes = sum(1 for row in rows if row["deterministic"] == "pass")
    print(
        f"  {arm:8} semantic {passes(rows)}/{rounds} (mean {mean_score(rows):.2f})  "
        f"deterministic {det_passes}/{rounds}  ${cost:.2f}"
    )
    print(f"           {detail}")


def main() -> int:
    """Report the delta and gate on the plugin arm's artifact checks."""
    if len(sys.argv) != 3:
        print("usage: summarize_arms.py RESULTS_DIR ROUNDS", file=sys.stderr)
        return 2

    results, rounds = Path(sys.argv[1]), int(sys.argv[2])
    if rounds < 1:
        print("error: at least one round is required", file=sys.stderr)
        return 2
    data = collect(results, rounds)

    for arm in ARMS:
        report_arm(arm, data[arm], rounds)

    semantic_delta = mean_score(data["with"]) - mean_score(data["without"])
    det_delta = det_rate(data["with"]) - det_rate(data["without"])
    print(f"\n  semantic delta      (with - without): {semantic_delta:+.2f}")
    print(f"  deterministic delta (with - without): {det_delta:+.2f}")

    # Both deltas are reported but neither gates. The eval scores recall and blocking
    # false positives only, and the baseline matches the plugin on both — the sole
    # reproducible difference was annotation coverage, which is no longer gated. So
    # this suite is a regression guard on the plugin arm, not evidence of value.
    problems = []
    if any(row["deterministic"] != "pass" for row in data["with"]):
        problems.append("plugin arm failed a deterministic check")

    if problems:
        for problem in problems:
            print(f"FAIL: {problem}", file=sys.stderr)
        return 1

    print(
        f"\nPASS: plugin arm {det_rate(data['with']):.0%} deterministic; baseline "
        f"{det_rate(data['without']):.0%}, delta {det_delta:+.2f} (reported, not gated)"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
