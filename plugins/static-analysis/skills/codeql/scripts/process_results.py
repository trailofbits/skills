# /// script
# requires-python = ">=3.11"
# dependencies = []
# ///
"""Filter and summarize CodeQL SARIF without placing the raw report in model context."""

from __future__ import annotations

import argparse
import json
from collections import Counter
from pathlib import Path
from typing import Any


def rules_for(run: dict[str, Any]) -> list[dict[str, Any]]:
    rules = run.get("tool", {}).get("driver", {}).get("rules", [])
    return rules if isinstance(rules, list) else []


def rule_for(result: dict[str, Any], run: dict[str, Any]) -> dict[str, Any]:
    rules = rules_for(run)
    index = result.get("ruleIndex")
    if isinstance(index, int) and not isinstance(index, bool) and 0 <= index < len(rules):
        return rules[index]
    rule_id = result.get("ruleId")
    return next((rule for rule in rules if rule.get("id") == rule_id), {})


def level_for(result: dict[str, Any], run: dict[str, Any]) -> str:
    if result.get("kind", "fail") != "fail":
        return "none"
    return str(
        result.get("level")
        or rule_for(result, run).get("defaultConfiguration", {}).get("level")
        or "warning"
    )


def is_important(result: dict[str, Any], run: dict[str, Any]) -> bool:
    properties = rule_for(result, run).get("properties", {})
    precision = properties.get("precision", "unknown")
    if precision is None or precision is False:
        precision = "unknown"
    if precision in ("high", "very-high", "unknown"):
        return True
    if precision != "medium":
        return False
    severity = properties.get("security-severity", 0)
    if severity is None or severity is False:
        severity = 0
    if isinstance(severity, bool):
        raise ValueError("security-severity must be numeric")
    return float(severity) >= 6.0


def load(path: Path) -> dict[str, Any]:
    with path.open() as handle:
        value = json.load(handle)
    if not isinstance(value, dict):
        raise ValueError("SARIF root must be an object")
    return value


def filtered(data: dict[str, Any]) -> dict[str, Any]:
    for run in data.get("runs", []):
        if isinstance(run, dict):
            results = run.get("results") or []
            run["results"] = [r for r in results if isinstance(r, dict) and is_important(r, run)]
    return data


def summary(data: dict[str, Any], top_rules: int) -> dict[str, Any]:
    levels: Counter[str] = Counter()
    rules: Counter[str] = Counter()
    total = 0
    for run in data.get("runs", []):
        if not isinstance(run, dict):
            continue
        for result in run.get("results") or []:
            if not isinstance(result, dict):
                continue
            total += 1
            levels[level_for(result, run)] += 1
            rules[str(result.get("ruleId") or "unknown")] += 1
    top = rules.most_common(None if top_rules == 0 else top_rules)
    return {"total": total, "by_level": dict(sorted(levels.items())), "top_rules": dict(top)}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    summary_parser = commands.add_parser("summary", help="print compact counts as JSON")
    summary_parser.add_argument("sarif", type=Path)
    summary_parser.add_argument("--top-rules", type=int, default=20)
    filter_parser = commands.add_parser("important-filter", help="write important-only SARIF")
    filter_parser.add_argument("raw", type=Path)
    filter_parser.add_argument("output", type=Path)
    args = parser.parse_args()

    if args.command == "summary":
        print(json.dumps(summary(load(args.sarif), args.top_rules), sort_keys=True))
        return 0
    output = args.output
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(filtered(load(args.raw)), indent=2) + "\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
