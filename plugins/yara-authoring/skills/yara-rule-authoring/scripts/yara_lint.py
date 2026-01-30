# /// script
# requires-python = ">=3.11"
# dependencies = ["plyara>=2.1"]
# ///
"""YARA rule linter for style, metadata, and common anti-patterns.

Usage:
    uv run yara_lint.py rule.yar
    uv run yara_lint.py --json rules/
    uv run yara_lint.py --strict rule.yar
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from dataclasses import dataclass
from dataclasses import field
from pathlib import Path
from typing import TYPE_CHECKING

import plyara

if TYPE_CHECKING:
    from collections.abc import Iterator


@dataclass
class Issue:
    """A linting issue."""

    rule: str
    severity: str  # error, warning, info
    code: str
    message: str
    line: int | None = None

    def to_dict(self) -> dict:
        return {
            "rule": self.rule,
            "severity": self.severity,
            "code": self.code,
            "message": self.message,
            "line": self.line,
        }


@dataclass
class LintResult:
    """Result of linting a file."""

    file: str
    issues: list[Issue] = field(default_factory=list)
    parse_error: str | None = None

    @property
    def error_count(self) -> int:
        return sum(1 for i in self.issues if i.severity == "error")

    @property
    def warning_count(self) -> int:
        return sum(1 for i in self.issues if i.severity == "warning")


# Naming convention patterns
VALID_CATEGORY_PREFIXES = frozenset(
    {
        "MAL",
        "HKTL",
        "WEBSHELL",
        "EXPL",
        "VULN",
        "SUSP",
        "PUA",
        "GEN",
        "APT",
        "CRIME",
        "RANSOM",
        "RAT",
        "MINER",
        "STEALER",
        "LOADER",
        "C2",
    }
)

VALID_PLATFORM_INDICATORS = frozenset(
    {
        "Win",
        "Lnx",
        "Mac",
        "Android",
        "iOS",
        "Multi",
        "PE",
        "ELF",
        "PS",
        "DOC",
        "PDF",
        "JAR",
    }
)

# Common FP-prone strings to warn about
FP_PRONE_STRINGS = frozenset(
    {
        "cmd.exe",
        "powershell.exe",
        "explorer.exe",
        "notepad.exe",
        "VirtualAlloc",
        "VirtualProtect",
        "CreateRemoteThread",
        "WriteProcessMemory",
        "ReadProcessMemory",
        "NtCreateThread",
        "KERNEL32.dll",
        "ntdll.dll",
        "USER32.dll",
        "ADVAPI32.dll",
        "C:\\Windows",
        "C:\\Windows\\System32",
        "%s",
        "%d",
        "%x",
        "%08x",
        "http://",
        "https://",
    }
)

# Deprecated features
DEPRECATED_PATTERNS = {
    "entrypoint": "Use pe.entry_point instead of deprecated entrypoint",
    "PEiD": "PEiD-style signatures are obsolete; use modern detection",
}


def check_naming_convention(rule_name: str) -> Iterator[Issue]:
    """Check if rule name follows the style guide convention."""
    parts = rule_name.split("_")

    if len(parts) < 3:
        yield Issue(
            rule=rule_name,
            severity="warning",
            code="W001",
            message=f"Rule name '{rule_name}' should follow CATEGORY_PLATFORM_FAMILY_DATE format",
        )
        return

    # Check category prefix
    if parts[0] not in VALID_CATEGORY_PREFIXES:
        valid = ", ".join(sorted(VALID_CATEGORY_PREFIXES))
        yield Issue(
            rule=rule_name,
            severity="info",
            code="I001",
            message=f"Unrecognized category prefix '{parts[0]}'; expected one of: {valid}",
        )


def check_metadata(rule_name: str, rule: dict) -> Iterator[Issue]:
    """Check for required and well-formed metadata."""
    metadata = {}
    if "metadata" in rule:
        for item in rule["metadata"]:
            metadata.update(item)

    # Required fields
    required = ["description", "author", "date"]
    for field_name in required:
        if field_name not in metadata:
            yield Issue(
                rule=rule_name,
                severity="error",
                code="E001",
                message=f"Missing required metadata field: {field_name}",
            )

    # Description checks
    if "description" in metadata:
        desc = metadata["description"]
        if not desc.startswith("Detects"):
            yield Issue(
                rule=rule_name,
                severity="warning",
                code="W002",
                message="Description should start with 'Detects'",
            )
        if len(desc) < 60:
            yield Issue(
                rule=rule_name,
                severity="warning",
                code="W003",
                message=f"Description too short ({len(desc)} chars); aim for 60-400 characters",
            )
        if len(desc) > 400:
            yield Issue(
                rule=rule_name,
                severity="info",
                code="I002",
                message=f"Description quite long ({len(desc)} chars); consider trimming to <400",
            )

    # Reference check
    if "reference" not in metadata:
        yield Issue(
            rule=rule_name,
            severity="warning",
            code="W004",
            message="Missing 'reference' metadata; add URL to analysis or source",
        )


def check_strings(rule_name: str, rule: dict) -> Iterator[Issue]:
    """Check strings for anti-patterns and quality issues."""
    if "strings" not in rule:
        return

    for string in rule["strings"]:
        string_id = string.get("name", "unknown")
        string_value = string.get("value", "")
        string_type = string.get("type", "text")

        # Check string length (text strings)
        if string_type == "text":
            # Handle modifiers like 'wide', 'nocase'
            clean_value = string_value.strip('"').strip("'")
            if len(clean_value) < 4:
                yield Issue(
                    rule=rule_name,
                    severity="error",
                    code="E002",
                    message=f"String {string_id} is only {len(clean_value)} bytes; "
                    "minimum 4 bytes for good atoms",
                )

            # Check for FP-prone strings
            for fp_string in FP_PRONE_STRINGS:
                if fp_string.lower() in clean_value.lower():
                    yield Issue(
                        rule=rule_name,
                        severity="warning",
                        code="W005",
                        message=f"String {string_id} contains FP-prone pattern '{fp_string}'",
                    )

        # Check hex strings
        if string_type == "byte":
            hex_value = string_value
            # Count actual bytes (excluding wildcards and spaces)
            byte_count = len(re.findall(r"[0-9A-Fa-f]{2}", hex_value))
            if byte_count < 4:
                yield Issue(
                    rule=rule_name,
                    severity="error",
                    code="E003",
                    message=f"Hex string {string_id} has only {byte_count} bytes; "
                    "minimum 4 for good atoms",
                )

            # Check for too many wildcards at start
            if re.match(r"^\{\s*\?\?", hex_value):
                yield Issue(
                    rule=rule_name,
                    severity="warning",
                    code="W006",
                    message=f"Hex string {string_id} starts with wildcard; "
                    "move fixed bytes first for better atoms",
                )


def check_condition(rule_name: str, rule: dict) -> Iterator[Issue]:
    """Check condition for performance and deprecated features."""
    if "condition_terms" not in rule:
        return

    condition_str = " ".join(str(t) for t in rule["condition_terms"])

    # Check for deprecated features
    for pattern, message in DEPRECATED_PATTERNS.items():
        if pattern.lower() in condition_str.lower():
            yield Issue(
                rule=rule_name,
                severity="warning",
                code="W007",
                message=message,
            )

    # Check for unbounded regex in strings (from raw_condition if available)
    raw_condition = rule.get("raw_condition", condition_str)
    if re.search(r"/\.\*[^?]", raw_condition) or re.search(r"/\.\+[^?]", raw_condition):
        yield Issue(
            rule=rule_name,
            severity="warning",
            code="W008",
            message="Unbounded regex (.*/.+) detected; use bounded quantifiers {1,N}",
        )


def check_string_modifiers(rule_name: str, rule: dict) -> Iterator[Issue]:
    """Check string modifiers for performance concerns."""
    if "strings" not in rule:
        return

    for string in rule["strings"]:
        string_id = string.get("name", "unknown")
        modifiers = string.get("modifiers", [])

        # nocase on long strings
        if "nocase" in modifiers:
            value = string.get("value", "")
            if len(value) > 20:
                yield Issue(
                    rule=rule_name,
                    severity="info",
                    code="I003",
                    message=f"String {string_id} uses 'nocase' on long string; performance impact",
                )

        # xor without range
        if "xor" in modifiers and not any("xor(" in str(m) for m in modifiers):
            yield Issue(
                rule=rule_name,
                severity="info",
                code="I004",
                message=f"String {string_id} uses 'xor' without range; generates 255 patterns",
            )


def lint_rule(rule: dict) -> list[Issue]:
    """Lint a single parsed rule."""
    issues = []
    rule_name = rule.get("rule_name", "unknown")

    issues.extend(check_naming_convention(rule_name))
    issues.extend(check_metadata(rule_name, rule))
    issues.extend(check_strings(rule_name, rule))
    issues.extend(check_condition(rule_name, rule))
    issues.extend(check_string_modifiers(rule_name, rule))

    return issues


def lint_file(file_path: Path) -> LintResult:
    """Lint a YARA file."""
    result = LintResult(file=str(file_path))

    try:
        content = file_path.read_text()
    except OSError as e:
        result.parse_error = f"Cannot read file: {e}"
        return result

    try:
        parser = plyara.Plyara()
        rules = parser.parse_string(content)
    except Exception as e:
        result.parse_error = f"Parse error: {e}"
        return result

    for rule in rules:
        result.issues.extend(lint_rule(rule))

    return result


def lint_directory(dir_path: Path) -> list[LintResult]:
    """Lint all YARA files in a directory."""
    results = []
    for yar_file in dir_path.rglob("*.yar"):
        results.append(lint_file(yar_file))
    for yar_file in dir_path.rglob("*.yara"):
        results.append(lint_file(yar_file))
    return results


def format_result(result: LintResult, *, use_color: bool = True) -> str:
    """Format a lint result for terminal output."""
    lines = []

    if use_color:
        red = "\033[91m"
        yellow = "\033[93m"
        blue = "\033[94m"
        reset = "\033[0m"
        bold = "\033[1m"
    else:
        red = yellow = blue = reset = bold = ""

    if result.parse_error:
        lines.append(f"{bold}{result.file}{reset}")
        lines.append(f"  {red}ERROR{reset}: {result.parse_error}")
        return "\n".join(lines)

    if not result.issues:
        return ""

    lines.append(f"{bold}{result.file}{reset}")

    for issue in result.issues:
        if issue.severity == "error":
            color = red
        elif issue.severity == "warning":
            color = yellow
        else:
            color = blue

        severity_upper = issue.severity.upper()
        line_info = f":{issue.line}" if issue.line else ""
        msg = f"  {color}{severity_upper}{reset} [{issue.code}] "
        msg += f"{issue.rule}{line_info}: {issue.message}"
        lines.append(msg)

    return "\n".join(lines)


def main() -> int:
    parser = argparse.ArgumentParser(description="YARA rule linter")
    parser.add_argument("path", type=Path, help="File or directory to lint")
    parser.add_argument("--json", action="store_true", help="Output JSON format")
    parser.add_argument("--strict", action="store_true", help="Treat warnings as errors")
    parser.add_argument("--no-color", action="store_true", help="Disable colored output")
    args = parser.parse_args()

    if args.path.is_file():
        results = [lint_file(args.path)]
    elif args.path.is_dir():
        results = lint_directory(args.path)
    else:
        print(f"Error: {args.path} does not exist", file=sys.stderr)
        return 1

    if args.json:
        output = {
            "results": [
                {
                    "file": r.file,
                    "parse_error": r.parse_error,
                    "issues": [i.to_dict() for i in r.issues],
                }
                for r in results
            ]
        }
        print(json.dumps(output, indent=2))
    else:
        use_color = not args.no_color and sys.stdout.isatty()
        for result in results:
            formatted = format_result(result, use_color=use_color)
            if formatted:
                print(formatted)
                print()

    # Calculate exit code
    total_errors = sum(r.error_count for r in results)
    total_warnings = sum(r.warning_count for r in results)
    parse_errors = sum(1 for r in results if r.parse_error)

    if parse_errors > 0 or total_errors > 0:
        return 1
    if args.strict and total_warnings > 0:
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
