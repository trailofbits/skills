"""
SARIF Parsing Helper Functions

Reusable utilities for working with SARIF files.
No external dependencies beyond standard library.
"""

import argparse
import csv
import hashlib
import json
import sys
from collections import defaultdict
from collections.abc import Iterator
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any
from urllib.parse import unquote

# What a result's severity is when neither the result nor its rule states one.
SARIF_DEFAULT_LEVEL = "warning"


@dataclass
class Finding:
    """Structured representation of a SARIF result."""

    rule_id: str
    level: str  # resolved by resolve_level(), not read from result.level
    message: str
    file_path: str | None = None
    start_line: int | None = None
    end_line: int | None = None
    start_column: int | None = None
    end_column: int | None = None
    fingerprint: str | None = None
    tool_name: str | None = None
    rule_name: str | None = None
    raw: dict = field(default_factory=dict, repr=False)


def load_sarif(path: str | Path) -> dict:
    """Load and parse a SARIF file."""
    with open(path) as f:
        return json.load(f)


def save_sarif(sarif: dict, path: str | Path, indent: int = 2) -> None:
    """Save SARIF data to file."""
    with open(path, "w") as f:
        json.dump(sarif, f, indent=indent)


def validate_version(sarif: dict) -> bool:
    """Check if SARIF version is 2.1.0."""
    return sarif.get("version") == "2.1.0"


def normalize_path(uri: str, base_path: str = "") -> str:
    """Normalize SARIF artifact URI to consistent path."""
    if not uri:
        return ""

    # Remove file:// prefix
    uri = uri.removeprefix("file://")

    # URL decode
    uri = unquote(uri)

    # Handle relative paths
    if base_path and not Path(uri).is_absolute():
        uri = str(Path(base_path) / uri)

    return str(Path(uri))


def safe_get(data: dict, *keys, default: Any = None) -> Any:
    """Safely navigate nested dict structure."""
    for key in keys:
        if isinstance(data, dict):
            data = data.get(key, {})
        elif isinstance(data, list) and isinstance(key, int):
            data = data[key] if 0 <= key < len(data) else {}
        else:
            return default
    return data if data != {} else default


def rules_for_run(run: dict) -> list[dict]:
    """Return rule definitions from either supported SARIF layout."""
    rules = (
        safe_get(run, "tool", "driver", "rules", default=[])
        or safe_get(run, "resources", "rules", default=[])
        or []
    )
    if isinstance(rules, dict):
        return [rule for rule in rules.values() if isinstance(rule, dict)]
    return [rule for rule in rules if isinstance(rule, dict)]


def find_rule(result: dict, run: dict) -> dict | None:
    """Find the rule definition a result was produced by.

    Joins on `ruleIndex` first (the cheap, unambiguous key CodeQL populates) and falls
    back to matching `ruleId`. SARIF 2.1 stores rules at
    `runs[].tool.driver.rules`; SARIF 2.0 stores them at `runs[].resources.rules`.
    """
    rules = rules_for_run(run)
    index = result.get("ruleIndex")
    if isinstance(index, int) and not isinstance(index, bool) and 0 <= index < len(rules):
        return rules[index]

    rule_id = result.get("ruleId")
    if rule_id:
        for rule in rules:
            if rule.get("id") == rule_id:
                return rule
    return None


def resolve_level(result: dict, run: dict) -> str:
    """Resolve a result's effective severity for SARIF 2.0 and 2.1.

    `result.level` is optional, and CodeQL routinely omits it: severity lives on the
    rule as `defaultConfiguration.level`, and the result inherits it. Reading
    `result.level` directly therefore scores an entire CodeQL run as clean, which is
    why a severity gate written that way exits 0 on a repo full of errors.

    Resolution order:
      1. `kind` other than "fail" (a pass/informational/notApplicable record) is "none"
      2. `result.level` when present
      3. the matched rule's default (`defaultConfiguration.level` in 2.1,
         `configuration.defaultLevel` in 2.0)
      4. "warning", the SARIF default

    `invocations[].ruleConfigurationOverrides` can outrank the rule default; no tool in
    common use emits it, so this does not read it.
    """
    if (result.get("kind") or "fail") != "fail":
        return "none"

    level = result.get("level")
    if level:
        return level

    rule = find_rule(result, run)
    if rule:
        rule_level = safe_get(rule, "defaultConfiguration", "level") or safe_get(
            rule, "configuration", "defaultLevel"
        )
        if rule_level:
            return rule_level

    return SARIF_DEFAULT_LEVEL


def extract_location(result: dict) -> tuple[str | None, int | None, int | None]:
    """Extract file path, start line, and end line from result."""
    loc = safe_get(result, "locations", 0, default={})
    phys = loc.get("physicalLocation", {})
    region = phys.get("region", {})

    # SARIF 2.0 calls this `fileLocation`; SARIF 2.1 renamed it to
    # `artifactLocation`.
    file_path = safe_get(phys, "artifactLocation", "uri") or safe_get(phys, "fileLocation", "uri")
    start_line = region.get("startLine")
    end_line = region.get("endLine")

    return file_path, start_line, end_line


def iter_results(sarif: dict) -> Iterator[tuple[dict, dict]]:
    """Iterate over all results with their run context."""
    for run in sarif.get("runs", []):
        for result in run.get("results") or []:
            yield result, run


def extract_findings(sarif: dict) -> list[Finding]:
    """Extract all findings as structured objects."""
    findings = []

    for result, run in iter_results(sarif):
        tool_name = safe_get(run, "tool", "driver", "name") or safe_get(run, "tool", "name")
        file_path, start_line, end_line = extract_location(result)

        loc = safe_get(result, "locations", 0, default={})
        phys = loc.get("physicalLocation", {})
        region = phys.get("region", {})
        rule = find_rule(result, run)

        # Get fingerprint
        fp = None
        if result.get("partialFingerprints"):
            fp = next(iter(result["partialFingerprints"].values()), None)
        elif result.get("fingerprints"):
            fp = next(iter(result["fingerprints"].values()), None)

        findings.append(
            Finding(
                rule_id=result.get("ruleId", "unknown"),
                level=resolve_level(result, run),
                message=safe_get(result, "message", "text", default=""),
                file_path=file_path,
                start_line=start_line,
                end_line=end_line,
                start_column=region.get("startColumn"),
                end_column=region.get("endColumn"),
                fingerprint=fp,
                tool_name=tool_name,
                rule_name=rule.get("name") if rule else None,
                raw=result,
            )
        )

    return findings


def filter_by_level(findings: list[Finding], *levels: str) -> list[Finding]:
    """Filter findings by severity level(s)."""
    return [f for f in findings if f.level in levels]


def filter_by_file(findings: list[Finding], pattern: str) -> list[Finding]:
    """Filter findings by file path pattern (substring match)."""
    return [f for f in findings if f.file_path and pattern in f.file_path]


def filter_by_rule(findings: list[Finding], *rule_ids: str) -> list[Finding]:
    """Filter findings by rule ID(s)."""
    return [f for f in findings if f.rule_id in rule_ids]


def sort_by_severity(findings: list[Finding], reverse: bool = False) -> list[Finding]:
    """Sort findings by severity (error > warning > note > none)."""
    severity_order = {"error": 0, "warning": 1, "note": 2, "none": 3}
    return sorted(findings, key=lambda f: severity_order.get(f.level, 99), reverse=reverse)


def group_by_file(findings: list[Finding]) -> dict[str, list[Finding]]:
    """Group findings by file path."""
    grouped = defaultdict(list)
    for f in findings:
        key = f.file_path or "unknown"
        grouped[key].append(f)
    return dict(grouped)


def group_by_rule(findings: list[Finding]) -> dict[str, list[Finding]]:
    """Group findings by rule ID."""
    grouped = defaultdict(list)
    for f in findings:
        grouped[f.rule_id].append(f)
    return dict(grouped)


def count_by_level(findings: list[Finding]) -> dict[str, int]:
    """Count findings by severity level."""
    counts = defaultdict(int)
    for f in findings:
        counts[f.level] += 1
    return dict(counts)


def count_by_rule(findings: list[Finding]) -> dict[str, int]:
    """Count findings by rule ID."""
    counts = defaultdict(int)
    for f in findings:
        counts[f.rule_id] += 1
    return dict(counts)


def compute_fingerprint(result: dict, include_message: bool = True) -> str:
    """Compute stable fingerprint from result data.

    The whole normalized path goes into the hash, directory included. Hashing the
    basename alone gave `src/auth/login.py:42` and `src/admin/login.py:42` one
    fingerprint under the same rule, so `deduplicate()` and `diff_findings()` threw
    away the second finding and called the file fixed.

    The cost is that runs reporting different absolute prefixes for the same file
    (`/github/workspace/src/a.py` vs `/builds/proj/src/a.py`) no longer match. Make the
    URIs repo-relative before fingerprinting when comparing across environments; a
    collision that hides a finding is the worse failure.
    """
    components = [result.get("ruleId", "")]

    file_path, start_line, _ = extract_location(result)
    if file_path:
        # POSIX separators so a fingerprint computed on Windows matches one from CI.
        components.append(Path(normalize_path(file_path)).as_posix())
    if start_line:
        components.append(str(start_line))
    if include_message:
        msg = safe_get(result, "message", "text", default="")
        # First 50 chars of message for stability
        components.append(msg[:50])

    return hashlib.sha256("|".join(components).encode()).hexdigest()[:16]


def deduplicate(findings: list[Finding]) -> list[Finding]:
    """Remove duplicate findings based on fingerprints."""
    seen = set()
    unique = []

    for f in findings:
        key = f.fingerprint or compute_fingerprint(f.raw)
        if key not in seen:
            seen.add(key)
            unique.append(f)

    return unique


def merge_sarif_files(*paths: str | Path) -> dict:
    """Merge multiple SARIF files into one."""
    merged = {
        "version": "2.1.0",
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "runs": [],
    }

    for path in paths:
        sarif = load_sarif(path)
        merged["runs"].extend(sarif.get("runs", []))

    return merged


def diff_findings(
    baseline: list[Finding], current: list[Finding]
) -> tuple[list[Finding], list[Finding], list[Finding]]:
    """
    Compare two sets of findings.

    Returns:
        - new: findings in current but not baseline
        - fixed: findings in baseline but not current
        - unchanged: findings in both
    """
    baseline_fps = {f.fingerprint or compute_fingerprint(f.raw) for f in baseline}
    current_fps = {f.fingerprint or compute_fingerprint(f.raw) for f in current}

    new = [f for f in current if (f.fingerprint or compute_fingerprint(f.raw)) not in baseline_fps]
    fixed = [
        f for f in baseline if (f.fingerprint or compute_fingerprint(f.raw)) not in current_fps
    ]
    unchanged = [
        f for f in current if (f.fingerprint or compute_fingerprint(f.raw)) in baseline_fps
    ]

    return new, fixed, unchanged


def get_rules(sarif: dict) -> dict[str, dict]:
    """Extract rule definitions from SARIF file."""
    rules = {}
    for run in sarif.get("runs", []):
        for rule in rules_for_run(run):
            rules[rule.get("id", "")] = rule
    return rules


def to_csv_rows(findings: list[Finding]) -> list[list[str]]:
    """Convert findings to CSV-ready rows."""
    rows = [["rule_id", "level", "file", "line", "message"]]
    for f in findings:
        rows.append(
            [
                f.rule_id,
                f.level,
                f.file_path or "",
                str(f.start_line or ""),
                f.message.replace("\n", " ")[:200],
            ]
        )
    return rows


def summary(findings: list[Finding]) -> dict:
    """Generate summary statistics for findings."""
    return {
        "total": len(findings),
        "by_level": count_by_level(findings),
        "by_rule": count_by_rule(findings),
        "files_affected": len({f.file_path for f in findings if f.file_path}),
        "rules_triggered": len({f.rule_id for f in findings}),
    }


def finding_record(finding: Finding) -> dict[str, Any]:
    """Return the compact, JSON-safe part of a finding for CLI output."""
    return {
        "rule_id": finding.rule_id,
        "level": finding.level,
        "message": finding.message,
        "file": finding.file_path,
        "line": finding.start_line,
        "end_line": finding.end_line,
        "fingerprint": finding.fingerprint or compute_fingerprint(finding.raw),
        "tool": finding.tool_name,
    }


def select_findings(
    findings: list[Finding],
    levels: list[str] | None = None,
    rules: list[str] | None = None,
    path: str | None = None,
) -> list[Finding]:
    """Apply CLI filters without bypassing resolved severity."""
    selected = findings
    if levels:
        selected = filter_by_level(selected, *levels)
    if rules:
        selected = filter_by_rule(selected, *rules)
    if path:
        selected = filter_by_file(selected, path)
    return sort_by_severity(selected)


def limited_records(findings: list[Finding], limit: int) -> list[dict[str, Any]]:
    """Bound model-facing output; zero explicitly means no limit."""
    shown = findings if limit == 0 else findings[:limit]
    return [finding_record(finding) for finding in shown]


def compact_summary(findings: list[Finding], top_rules: int) -> dict[str, Any]:
    """Return summary statistics without sending an unbounded rule map to a model."""
    stats = summary(findings)
    ranked = sorted(stats["by_rule"].items(), key=lambda item: (-item[1], item[0]))
    shown = ranked if top_rules == 0 else ranked[:top_rules]
    return {
        "total": stats["total"],
        "by_level": stats["by_level"],
        "files_affected": stats["files_affected"],
        "rules_triggered": stats["rules_triggered"],
        "top_rules": [{"rule_id": rule, "count": count} for rule, count in shown],
    }


def load_findings(path: str | Path) -> list[Finding]:
    """Load one SARIF file and warn when its version is not supported."""
    sarif = load_sarif(path)
    if sarif.get("version") not in {"2.0.0", "2.1.0"}:
        print(f"warning: {path} is not a supported SARIF 2.0/2.1 file", file=sys.stderr)
    return extract_findings(sarif)


def print_legacy_summary(findings: list[Finding]) -> None:
    """Preserve the helper's original human-readable direct-invocation output."""
    print("\nSummary:")
    stats = summary(findings)
    print(f"  Total findings: {stats['total']}")
    print(f"  Files affected: {stats['files_affected']}")
    print(f"  Rules triggered: {stats['rules_triggered']}")
    print("\nBy severity:")
    for level, count in stats["by_level"].items():
        print(f"  {level}: {count}")
    print("\nTop 5 rules:")
    for rule, count in sorted(stats["by_rule"].items(), key=lambda item: -item[1])[:5]:
        print(f"  {rule}: {count}")


def parser() -> argparse.ArgumentParser:
    cli = argparse.ArgumentParser(
        description="Summarize, filter, deduplicate, diff, or export SARIF findings."
    )
    commands = cli.add_subparsers(dest="command", required=True)

    summary_parser = commands.add_parser("summary", help="print finding counts as JSON")
    summary_parser.add_argument("sarif")
    summary_parser.add_argument(
        "--top-rules",
        type=int,
        default=20,
        help="number of rule counts to include; zero explicitly includes all",
    )

    filter_parser = commands.add_parser("filter", help="print compact matching findings as JSON")
    filter_parser.add_argument("sarif")
    filter_parser.add_argument("--level", action="append", dest="levels")
    filter_parser.add_argument("--rule", action="append", dest="rules")
    filter_parser.add_argument("--path")
    filter_parser.add_argument("--limit", type=int, default=100)

    dedupe_parser = commands.add_parser(
        "dedupe", help="remove duplicate findings across SARIF files"
    )
    dedupe_parser.add_argument("sarif", nargs="+")
    dedupe_parser.add_argument("--limit", type=int, default=100)

    diff_parser = commands.add_parser("diff", help="compare baseline and current SARIF files")
    diff_parser.add_argument("baseline")
    diff_parser.add_argument("current")
    diff_parser.add_argument("--limit", type=int, default=100)

    csv_parser = commands.add_parser("csv", help="write compact findings as CSV to stdout")
    csv_parser.add_argument("sarif")
    csv_parser.add_argument("--level", action="append", dest="levels")
    csv_parser.add_argument("--rule", action="append", dest="rules")
    csv_parser.add_argument("--path")
    return cli


def main(argv: list[str] | None = None) -> int:
    """Run the command-line interface.

    Supplying a SARIF path without a command preserves the helper's former
    human-readable direct-invocation output. Named commands return compact JSON.
    """
    argv = list(sys.argv[1:] if argv is None else argv)
    if not argv:
        print("Usage: uv run --no-project sarif_helpers.py <sarif_file>")
        return 1
    commands = {"summary", "filter", "dedupe", "diff", "csv", "-h", "--help"}
    if argv[0] not in commands or (len(argv) == 1 and Path(argv[0]).is_file()):
        sarif = load_sarif(argv[0])
        if not validate_version(sarif):
            print("Warning: SARIF version is not 2.1.0")
        print_legacy_summary(sort_by_severity(extract_findings(sarif)))
        return 0
    args = parser().parse_args(argv)

    if args.command == "summary":
        print(
            json.dumps(
                compact_summary(load_findings(args.sarif), args.top_rules),
                sort_keys=True,
            )
        )
        return 0

    if args.command == "filter":
        selected = select_findings(load_findings(args.sarif), args.levels, args.rules, args.path)
        print(
            json.dumps(
                {
                    "total": len(selected),
                    "returned": len(limited_records(selected, args.limit)),
                    "findings": limited_records(selected, args.limit),
                },
                sort_keys=True,
            )
        )
        return 0

    if args.command == "dedupe":
        findings = [finding for path in args.sarif for finding in load_findings(path)]
        unique = deduplicate(findings)
        print(
            json.dumps(
                {
                    "total": len(findings),
                    "unique": len(unique),
                    "returned": len(limited_records(unique, args.limit)),
                    "findings": limited_records(unique, args.limit),
                },
                sort_keys=True,
            )
        )
        return 0

    if args.command == "diff":
        new, fixed, unchanged = diff_findings(
            load_findings(args.baseline), load_findings(args.current)
        )
        print(
            json.dumps(
                {
                    "new": {
                        "total": len(new),
                        "findings": limited_records(new, args.limit),
                    },
                    "fixed": {
                        "total": len(fixed),
                        "findings": limited_records(fixed, args.limit),
                    },
                    "unchanged": {
                        "total": len(unchanged),
                        "findings": limited_records(unchanged, args.limit),
                    },
                },
                sort_keys=True,
            )
        )
        return 0

    if args.command == "csv":
        findings = select_findings(load_findings(args.sarif), args.levels, args.rules, args.path)
        writer = csv.writer(sys.stdout)
        writer.writerows(to_csv_rows(findings))
        return 0

    raise AssertionError(f"unhandled command: {args.command}")


if __name__ == "__main__":
    raise SystemExit(main())
