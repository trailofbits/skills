# /// script
# requires-python = ">=3.11"
# dependencies = ["yara-x>=0.10.0"]
# ///
"""YARA-X rule linter for style, metadata, compatibility, and common anti-patterns.

Compiles every rule with the yara-x Python package to catch syntax and YARA-X
compatibility errors, then applies the style checks in yara_rules.py.

Usage:
    uv run yara_lint.py rule.yar
    uv run yara_lint.py --json rules/
    uv run yara_lint.py --strict rule.yar
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

import yara_x

from yara_rules import Issue
from yara_rules import LintResult
from yara_rules import collect_rule_files
from yara_rules import coverage_error
from yara_rules import extract_rule_names
from yara_rules import lint_source
from yara_rules import rule_less_files
from yara_rules import select_exit_code


def compile_issues(content: str) -> list[Issue]:
    """Compile the source with YARA-X, reporting any failure as E000."""
    try:
        compiler = yara_x.Compiler()
        compiler.add_source(content)
        compiler.build()
    except yara_x.CompileError as e:
        return [
            Issue(
                rule="(compilation)",
                severity="error",
                code="E000",
                message=f"YARA-X compilation error: {e}",
            )
        ]
    return []


def lint_file(file_path: Path) -> LintResult:
    """Lint a YARA file: compile it, then run the style checks."""
    result = LintResult(file=str(file_path))

    try:
        content = file_path.read_text()
    except OSError as e:
        result.parse_error = f"Cannot read file: {e}"
        return result

    # Style checks still run when compilation fails -- a rule with a syntax error
    # usually has metadata and naming problems worth reporting in the same pass.
    result.issues.extend(compile_issues(content))
    result.issues.extend(lint_source(content))
    result.rules = len(extract_rule_names(content))
    return result


def format_result(result: LintResult, *, use_color: bool = True) -> str:
    """Format a lint result for terminal output."""
    if use_color:
        red, yellow, blue, reset, bold = (
            "\033[91m",
            "\033[93m",
            "\033[94m",
            "\033[0m",
            "\033[1m",
        )
    else:
        red = yellow = blue = reset = bold = ""

    if result.parse_error:
        return f"{bold}{result.file}{reset}\n  {red}ERROR{reset}: {result.parse_error}"

    if not result.issues:
        return ""

    lines = [f"{bold}{result.file}{reset}"]
    for issue in result.issues:
        color = {"error": red, "warning": yellow}.get(issue.severity, blue)
        line_info = f":{issue.line}" if issue.line else ""
        lines.append(
            f"  {color}{issue.severity.upper()}{reset} [{issue.code}] "
            f"{issue.rule}{line_info}: {issue.message}"
        )
    return "\n".join(lines)


def main() -> int:
    parser = argparse.ArgumentParser(description="YARA-X rule linter")
    parser.add_argument("path", type=Path, help="File or directory to lint")
    parser.add_argument("--json", action="store_true", help="Output JSON format")
    parser.add_argument("--strict", action="store_true", help="Treat warnings as errors")
    parser.add_argument("--no-color", action="store_true", help="Disable colored output")
    args = parser.parse_args()

    files, error = collect_rule_files(args.path)
    if error:
        print(f"Error: {error}", file=sys.stderr)
        return 1

    results = [lint_file(f) for f in files]

    if args.json:
        print(
            json.dumps(
                {
                    "results": [
                        {
                            "file": r.file,
                            "parse_error": r.parse_error,
                            "issues": [i.to_dict() for i in r.issues],
                        }
                        for r in results
                    ]
                },
                indent=2,
            )
        )
    else:
        use_color = not args.no_color and sys.stdout.isatty()
        for result in results:
            formatted = format_result(result, use_color=use_color)
            if formatted:
                print(formatted)
                print()

        for name in rule_less_files({r.file: r.rules for r in results}):
            print(f"Note: {name} holds no rules; skipped", file=sys.stderr)

    # After the report, so a file that fails to compile still shows its E000 with
    # the source location rather than only "no rules found".
    coverage = coverage_error({r.file: r.rules for r in results})
    if coverage:
        print(f"Error: {coverage}", file=sys.stderr)
        return 1

    return select_exit_code(results, strict=args.strict)


if __name__ == "__main__":
    sys.exit(main())
