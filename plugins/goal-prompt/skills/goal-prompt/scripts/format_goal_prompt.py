#!/usr/bin/env python3
"""Format a /goal command with deterministic whitespace normalization."""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

DEFAULT_MAX_PROMPT_CHARS = 4000

# A numeric turn/time bound ("or stop after 20 turns") or a blocked clause
# ("if blocked, stop and report..."). Without one, a mis-stated condition
# keeps the goal loop running indefinitely.
STOP_CLAUSE_PATTERN = re.compile(
    r"\bafter\s+\d+\s+(?:turns?|iterations?|attempts?|rounds?|hours?|minutes?)\b"
    r"|\bblocked\b",
    re.IGNORECASE,
)


def has_stop_clause(objective: str) -> bool:
    return bool(STOP_CLAUSE_PATTERN.search(objective))


def read_text(path: str | None) -> str:
    if path in (None, "-"):
        return sys.stdin.read()
    return Path(path).read_text(encoding="utf-8")


def strip_surrounding_fence(text: str) -> str:
    stripped = text.strip()
    match = re.fullmatch(r"```[A-Za-z0-9_-]*\n(.*)\n```", stripped, flags=re.DOTALL)
    if match:
        return match.group(1)
    return text


def normalize_objective(text: str) -> str:
    text = text.replace("\r\n", "\n").replace("\r", "\n")
    text = strip_surrounding_fence(text)
    text = text.strip()
    text = re.sub(r"^/goal(?:\s+|$)", "", text, count=1)
    text = text.strip().strip('"').strip("'").strip()
    return re.sub(r"\s+", " ", text).strip()


def format_goal_command(
    text: str,
    *,
    objective_only: bool = False,
    max_chars: int = DEFAULT_MAX_PROMPT_CHARS,
) -> str:
    objective = normalize_objective(text)
    if not objective:
        raise ValueError("goal objective is empty after normalization")
    output = objective if objective_only else f"/goal {objective}"
    if max_chars > 0 and len(output) > max_chars:
        raise ValueError(f"formatted goal prompt is {len(output)} characters; limit is {max_chars}")
    return output


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Normalize text into a copy-ready /goal command.")
    parser.add_argument(
        "path",
        nargs="?",
        default="-",
        help="Draft objective file path, or '-' / omitted for stdin.",
    )
    parser.add_argument(
        "--fenced",
        action="store_true",
        help="Wrap output in a fenced text block for a final response.",
    )
    parser.add_argument(
        "--objective-only",
        action="store_true",
        help="Print only the normalized objective, without the /goal prefix.",
    )
    parser.add_argument(
        "--max-chars",
        type=int,
        default=DEFAULT_MAX_PROMPT_CHARS,
        help="Maximum formatted output length. Use 0 to disable the length check.",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        output = format_goal_command(
            read_text(args.path),
            objective_only=args.objective_only,
            max_chars=args.max_chars,
        )
    except (OSError, ValueError) as exc:
        print(f"format_goal_prompt.py: error: {exc}", file=sys.stderr)
        return 1

    if not has_stop_clause(output):
        print(
            "format_goal_prompt.py: warning: no stop bound or blocked clause found; "
            'consider adding "or stop after 20 turns" or '
            '"if blocked, stop and report the blocker"',
            file=sys.stderr,
        )

    if args.fenced:
        print("```text")
        print(output)
        print("```")
    else:
        print(output)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
