#!/usr/bin/env -S uv run --script
# /// script
# requires-python = ">=3.11"
# dependencies = ["tree-sitter", "tree-sitter-bash"]
# ///
"""
PreToolUse hook that intercepts legacy python3/pip commands.

Uses tree-sitter AST parsing to avoid false positives (e.g., `echo "pip install"`).
"""

from __future__ import annotations

import json
import shutil
import sys
from collections.abc import Iterator

import tree_sitter_bash as tsbash
from tree_sitter import Language, Node, Parser

BASH = Language(tsbash.language())

# (command, args_tuple, suggestion)
# - args_tuple: tuple of args to match as prefix
# - Empty tuple () = catch-all (matches any args)
# - First match wins, so order matters (specific before general)
LEGACY_PATTERNS: list[tuple[str, tuple[str, ...], str]] = [
    # Most specific first
    ("python", ("-m", "pip"), "`python -m pip` -> `uv add`/`uv remove`"),
    ("python3", ("-m", "pip"), "`python -m pip` -> `uv add`/`uv remove`"),
    (
        "python",
        ("-m",),
        "`python -m module` -> `uv run python -m module` (use `--with pkg` for deps)",
    ),
    (
        "python3",
        ("-m",),
        "`python -m module` -> `uv run python -m module` (use `--with pkg` for deps)",
    ),
    # Catch-all for python/python3 (covers -c, scripts, REPL, etc.)
    ("python", (), "`python` -> `uv run python` (use `--with pkg` for one-off deps)"),
    ("python3", (), "`python3` -> `uv run python` (use `--with pkg` for one-off deps)"),
    # pip commands (already specific enough)
    ("pip", ("install",), "`pip install` -> `uv add` (project) or `uv run --with pkg` (one-off)"),
    ("pip3", ("install",), "`pip install` -> `uv add` (project) or `uv run --with pkg` (one-off)"),
    ("pip", ("uninstall",), "`pip uninstall` -> `uv remove`"),
    ("pip3", ("uninstall",), "`pip uninstall` -> `uv remove`"),
    ("pip", ("freeze",), "`pip freeze` -> `uv export`"),
    ("pip3", ("freeze",), "`pip freeze` -> `uv export`"),
    ("uv", ("pip",), "`uv pip` is legacy. Use: `uv add`, `uv remove`, `uv sync`"),
]


def extract_commands(node: Node, src: bytes) -> Iterator[tuple[str, list[str]]]:
    """Yield (command_name, args) for each command, skipping string content."""
    if node.type == "command":
        parts = [
            src[c.start_byte : c.end_byte].decode().strip("'\"")
            for c in node.children
            if c.type in ("command_name", "word", "string", "raw_string")
        ]
        if parts:
            yield parts[0].rsplit("/", 1)[-1], parts[1:]

    for child in node.children:
        if child.type not in ("string", "raw_string", "comment"):
            yield from extract_commands(child, src)


def main() -> None:
    if not shutil.which("uv"):
        return

    try:
        hook_input = json.load(sys.stdin)
    except json.JSONDecodeError:
        return

    command = hook_input.get("tool_input", {}).get("command", "")
    if not command:
        return

    try:
        tree = Parser(BASH).parse(command.encode())
    except Exception:
        return

    suggestion = None
    for cmd, args in extract_commands(tree.root_node, command.encode()):
        for pattern_cmd, pattern_args, pattern_suggestion in LEGACY_PATTERNS:
            if cmd == pattern_cmd and args[: len(pattern_args)] == list(pattern_args):
                suggestion = pattern_suggestion
                break
        if suggestion:
            break

    if not suggestion:
        return

    print(
        json.dumps(
            {
                "hookSpecificOutput": {
                    "hookEventName": "PreToolUse",
                    "permissionDecision": "deny",
                    "permissionDecisionReason": f"""Use `uv` instead of legacy python/pip commands.

**Detected**: {suggestion}

**Quick reference**:
- `python` -> `uv run python`
- `python script.py` -> `uv run script.py`
- `python -m module` -> `uv run python -m module`
- `python -c "..."` with deps -> `uv run --with pkg python -c "..."`
- `pip install pkg` -> `uv add pkg` (project) or `uv run --with pkg` (one-off)
- `pip uninstall pkg` -> `uv remove pkg`

See: ${{CLAUDE_PLUGIN_ROOT}}/skills/modern-python/SKILL.md""",
                }
            }
        )
    )


if __name__ == "__main__":
    main()
