"""Keep helper functions small enough for their artifact contracts to stay reviewable."""

from __future__ import annotations

import ast
from pathlib import Path


def test_python_helpers_keep_functions_within_fifty_lines() -> None:
    functions = []
    for source in Path(__file__).parent.glob("*.py"):
        tree = ast.parse(source.read_text(encoding="utf-8"), filename=str(source))
        functions.extend(
            (source.name, node.name, (node.end_lineno or node.lineno) - node.lineno + 1)
            for node in ast.walk(tree)
            if isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef)
        )
    assert functions, "No Python functions inspected"
    assert not [(file, name, size) for file, name, size in functions if size > 50]


def test_python_helpers_accept_at_most_five_positional_parameters() -> None:
    functions = []
    for source in Path(__file__).parent.glob("*.py"):
        tree = ast.parse(source.read_text(encoding="utf-8"), filename=str(source))
        functions.extend(
            (source.name, node.name, len(node.args.posonlyargs) + len(node.args.args))
            for node in ast.walk(tree)
            if isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef)
        )
    assert functions, "No Python functions inspected"
    assert not [(file, name, size) for file, name, size in functions if size > 5]
