# /// script
# requires-python = ">=3.11"
# dependencies = []
# ///
"""Fail unless a CodeQL query suite resolves to one or more queries."""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
from pathlib import Path


class SuiteResolutionFailure(Exception):
    """A query suite that must not be analysed with."""


def resolve_queries(suite_path: Path, codeql_executable: str = "codeql") -> list[str]:
    """Resolve a query suite and return its selected query paths."""
    command = [
        codeql_executable,
        "resolve",
        "queries",
        "--format=json",
        "--",
        str(suite_path),
    ]
    try:
        result = subprocess.run(command, capture_output=True, text=True)
    except OSError as error:
        raise SuiteResolutionFailure(
            f"Could not run CodeQL while validating {suite_path}: {error}. "
            "Check that the CodeQL CLI is installed and executable."
        ) from error

    if result.returncode != 0:
        diagnostic = result.stderr.strip() or "CodeQL produced no diagnostic"
        raise SuiteResolutionFailure(
            f"CodeQL failed to resolve {suite_path}: {diagnostic}. "
            "Check the suite imports and installed query packs."
        )

    try:
        query_paths = json.loads(result.stdout)
    except json.JSONDecodeError as error:
        raise SuiteResolutionFailure(
            f"CodeQL returned invalid JSON while resolving {suite_path}: {error}. "
            "Re-run the command manually with --format=json."
        ) from error

    if not isinstance(query_paths, list) or not all(
        isinstance(query_path, str) for query_path in query_paths
    ):
        raise SuiteResolutionFailure(
            f"CodeQL returned an unexpected query list while resolving {suite_path}. "
            "Check that this CodeQL version supports --format=json."
        )
    if not query_paths:
        raise SuiteResolutionFailure(
            f"CodeQL resolved zero queries from {suite_path}. "
            "Check suite filters, imports, and installed query packs."
        )
    return query_paths


def main(argv: list[str] | None = None) -> int:
    """Validate one suite and print its resolved query count."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("suite", type=Path)
    parser.add_argument("--codeql", default="codeql", help="CodeQL executable path")
    args = parser.parse_args(argv)

    try:
        query_paths = resolve_queries(args.suite, args.codeql)
    except SuiteResolutionFailure as error:
        print(f"ERROR: {error}", file=sys.stderr)
        return 1

    print(f"Resolved {len(query_paths)} queries from {args.suite}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
