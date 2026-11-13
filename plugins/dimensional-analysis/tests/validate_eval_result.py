#!/usr/bin/env python3
"""Reject incomplete or below-threshold Claude plugin eval results."""

from __future__ import annotations

import json
import sys
from pathlib import Path


def main() -> int:
    if len(sys.argv) != 2:
        print("usage: validate_eval_result.py RESULT.json", file=sys.stderr)
        return 2

    path = Path(sys.argv[1])
    try:
        result = json.loads(path.read_text())
    except (OSError, json.JSONDecodeError) as error:
        print(f"error: cannot read eval result {path}: {error}", file=sys.stderr)
        return 1

    aggregates = result.get("aggregates", {})
    total = aggregates.get("casesTotal")
    passed = aggregates.get("casesPassed")
    score = aggregates.get("overallScore")
    pass_rate = aggregates.get("overallPassRate")
    if (
        result.get("partial") is not False
        or not isinstance(total, int)
        or total < 1
        or passed != total
        or score != 1
        or pass_rate != 1
    ):
        print(
            "error: semantic eval was partial or below the required 1.0 threshold "
            f"(partial={result.get('partial')!r}, passed={passed!r}/{total!r}, "
            f"score={score!r}, pass_rate={pass_rate!r})",
            file=sys.stderr,
        )
        return 1

    print(f"eval result: {passed}/{total} cases passed at score 1.0")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
