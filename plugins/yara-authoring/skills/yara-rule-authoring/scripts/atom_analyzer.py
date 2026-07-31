# /// script
# requires-python = ">=3.11"
# dependencies = ["yara-x>=0.10.0"]
# ///
"""YARA-X string atom quality analyzer.

Analyzes strings for efficient atom extraction, identifying patterns that
will cause poor scanning performance. Uses yara-x for rule validation.

Usage:
    uv run atom_analyzer.py rule.yar
    uv run atom_analyzer.py --verbose rule.yar
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

import yara_x

from yara_rules import analyze_rule
from yara_rules import collect_rule_files
from yara_rules import coverage_error
from yara_rules import extract_rule_names
from yara_rules import rule_less_files


def analyze_file(file_path: Path, *, verbose: bool = False) -> tuple[int, bool]:
    """Analyze a YARA file and print results.

    Returns `(rules_analysed, failed)`. Whether analysing zero rules is an error
    is decided across the whole run in `main`, not here -- see `coverage_error`.
    """
    try:
        content = file_path.read_text()
    except OSError as e:
        print(f"Error reading {file_path}: {e}", file=sys.stderr)
        return 0, True

    compiled = True
    try:
        compiler = yara_x.Compiler()
        compiler.add_source(content)
        compiler.build()
    except yara_x.CompileError as e:
        # Keep going: the atom report is still useful, and yara_lint.py is where
        # compilation failures are meant to be reported. But a file that does not
        # compile must never be reported as clean, so `compiled` gates the ✓ below.
        print(f"\033[91mYARA-X compilation error in {file_path}:\033[0m {e}", file=sys.stderr)
        compiled = False

    has_issues = False
    rules_seen = 0

    for rule_name in extract_rule_names(content):
        rules_seen += 1
        analyses = list(analyze_rule(rule_name, content))

        if verbose or any(a.issues for a in analyses):
            print(f"\n\033[1m{rule_name}\033[0m")

        for analysis in analyses:
            if not analysis.issues and not verbose:
                continue

            has_issues = has_issues or bool(analysis.issues)

            if verbose:
                atom_info = f" [atom: {analysis.best_atom}]" if analysis.best_atom else ""
                print(f"  {analysis.string_id}: {analysis.byte_count} bytes{atom_info}")

            for issue in analysis.issues:
                color = {"error": "\033[91m", "warning": "\033[93m"}.get(issue.severity, "\033[94m")
                print(
                    f"    {color}{issue.severity.upper()}\033[0m {issue.string_id}: {issue.message}"
                )
                if issue.suggestion:
                    print(f"           Suggestion: {issue.suggestion}")

    if has_issues:
        return rules_seen, True

    if not compiled:
        print(
            f"\n{file_path}: {rules_seen} rule(s) inspected, no atom issues, but the file "
            "does not compile -- fix the compilation error before trusting this result"
        )
        return rules_seen, True

    if rules_seen:
        print(f"\n✓ All strings in {file_path} have good atom quality")
    return rules_seen, False


def main() -> int:
    parser = argparse.ArgumentParser(description="YARA-X string atom quality analyzer")
    parser.add_argument("path", type=Path, help="YARA file or directory to analyze")
    parser.add_argument(
        "--verbose", "-v", action="store_true", help="Show all strings, not just issues"
    )
    args = parser.parse_args()

    files, error = collect_rule_files(args.path)
    if error:
        print(f"Error: {error}", file=sys.stderr)
        return 1

    failed = False
    rule_counts: dict[str, int] = {}
    for yar_file in files:
        rules, file_failed = analyze_file(yar_file, verbose=args.verbose)
        rule_counts[str(yar_file)] = rules
        failed = failed or file_failed

    coverage = coverage_error(rule_counts)
    if coverage:
        print(f"Error: {coverage}", file=sys.stderr)
        return 1

    for name in rule_less_files(rule_counts):
        print(f"Note: {name} holds no rules; skipped", file=sys.stderr)

    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
