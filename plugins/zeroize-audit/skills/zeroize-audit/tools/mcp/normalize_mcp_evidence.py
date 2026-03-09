#!/usr/bin/env python3
# /// script
# requires-python = ">=3.11"
# dependencies = []
# ///
"""
Normalize Serena MCP semantic-analysis output into consistent evidence records.

Serena returns structured results with file, line, symbol, and kind fields.
This normalizer produces a consistent schema consumed by the zeroize-audit
confidence gating and evidence scoring pipeline.
"""

import argparse
import json
import sys
from collections import Counter
from pathlib import Path
from typing import Any


def _load_payload(input_path: str) -> Any:
    if input_path:
        try:
            return json.loads(Path(input_path).read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as e:
            print(f"Error reading {input_path}: {e}", file=sys.stderr)
            sys.exit(1)
    if sys.stdin.isatty():
        print("Error: no --input specified and stdin is a terminal", file=sys.stderr)
        sys.exit(2)
    try:
        return json.load(sys.stdin)
    except json.JSONDecodeError as e:
        print(f"Error: invalid JSON on stdin: {e}", file=sys.stderr)
        sys.exit(1)


def _as_results(payload: Any) -> list[dict[str, Any]]:
    if isinstance(payload, list):
        return [item for item in payload if isinstance(item, dict)]
    if isinstance(payload, dict):
        if isinstance(payload.get("results"), list):
            return [item for item in payload["results"] if isinstance(item, dict)]
        return [payload]
    return []


def _normalize_item(result: dict[str, Any], item: dict[str, Any]) -> dict[str, Any]:
    file_path = item.get("file") or item.get("uri") or result.get("target") or ""
    line = item.get("line")
    if isinstance(line, str) and line.isdigit():
        line = int(line)

    symbol = item.get("symbol") or item.get("name") or result.get("query") or ""
    kind = item.get("kind") or result.get("tool") or "mcp_result"
    detail = item.get("detail") or item.get("snippet") or ""

    confidence = item.get("confidence") if item.get("confidence") is not None else "medium"

    return {
        "file": file_path,
        "line": line,
        "symbol": symbol,
        "kind": kind,
        "detail": detail,
        "source": result.get("tool", "mcp"),
        "confidence": confidence,
        "metadata": {
            "query": result.get("query"),
            "target": result.get("target"),
            "raw_item": item,
        },
    }


def normalize(payload: Any) -> dict[str, Any]:
    results = _as_results(payload)
    normalized: list[dict[str, Any]] = []
    tools = Counter()
    kinds = Counter()

    for result in results:
        tool_name = result.get("tool", "mcp")
        tools[tool_name] += 1

        items = result.get("items")
        if not isinstance(items, list):
            items = [result]

        for raw_item in items:
            if not isinstance(raw_item, dict):
                continue
            entry = _normalize_item(result, raw_item)
            normalized.append(entry)
            kinds[entry["kind"]] += 1

    return {
        "mcp_available": len(normalized) > 0,
        "evidence_count": len(normalized),
        "evidence": normalized,
        "coverage": {
            "by_tool": dict(tools),
            "by_kind": dict(kinds),
        },
    }


def main() -> None:
    parser = argparse.ArgumentParser(description="Normalize MCP evidence JSON")
    parser.add_argument("--input", help="Input JSON file path; defaults to stdin")
    parser.add_argument("--out", required=True, help="Output JSON path")
    args = parser.parse_args()

    payload = _load_payload(args.input)
    output = normalize(payload)

    out_path = Path(args.out)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(output, indent=2) + "\n", encoding="utf-8")
    print(f"OK: wrote normalized MCP evidence to {out_path}")


if __name__ == "__main__":
    main()
