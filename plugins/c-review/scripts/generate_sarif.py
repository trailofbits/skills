#!/usr/bin/env python3
"""Generate c-review SARIF from finding frontmatter.

Usage:
    python3 generate_sarif.py /path/to/output_dir
    python3 generate_sarif.py /path/to/output_dir --output /tmp/REPORT.sarif
"""

from __future__ import annotations

import argparse
import json
import re
from pathlib import Path
from typing import Any

SEVERITY_ORDER = {"LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}
SEVERITY_LEVEL = {
    "CRITICAL": "error",
    "HIGH": "error",
    "MEDIUM": "warning",
    "LOW": "note",
}
FILTER_MIN = {"all": 1, "medium": 2, "high": 3}
SURVIVOR_VERDICTS = {"TRUE_POSITIVE", "LIKELY_TP"}

RULE_DESCRIPTIONS = {
    "access-control": "Missing or incorrect authorization check",
    "banned-functions": "Use of banned or deprecated C/C++ APIs",
    "buffer-overflow": "Out-of-bounds write to a buffer",
    "compiler-bugs": "Compiler-optimization-sensitive undefined behavior",
    "createprocess": "Windows CreateProcess or process launch misuse",
    "cross-process": "Unsafe cross-process handle or memory operation",
    "dll-planting": "DLL search-order hijacking risk",
    "dos": "Denial of service vulnerability",
    "eintr-handling": "Missing EINTR handling",
    "envvar": "Unsafe environment variable handling",
    "errno-handling": "Incorrect errno handling",
    "error-handling": "Missing or incorrect error handling",
    "exception-safety": "C++ exception safety issue",
    "exploit-mitigations": "Missing or misconfigured exploit mitigation",
    "filesystem-issues": "Filesystem race or path handling issue",
    "flexible-array": "Flexible array or struct-size misuse",
    "format-string": "Format string vulnerability",
    "half-closed-socket": "Half-closed socket handling issue",
    "inet-aton": "Legacy IPv4 parsing API misuse",
    "init-order": "C++ static initialization order issue",
    "integer-overflow": "Integer overflow or wraparound",
    "installer-race": "Windows installer filesystem race",
    "iterator-invalidation": "C++ iterator invalidation",
    "lambda-capture": "Unsafe C++ lambda capture lifetime",
    "memcpy-size": "Incorrect memcpy or memory operation size",
    "memory-leak": "Memory leak on security-relevant path",
    "move-semantics": "C++ move semantics misuse",
    "named-pipe": "Windows named pipe security issue",
    "negative-retval": "Negative return value used unsafely",
    "null-deref": "Null pointer dereference",
    "null-zero": "NULL or zero confusion",
    "oob-comparison": "Out-of-bounds comparison",
    "open-issues": "File open or creation misuse",
    "operator-precedence": "Operator precedence issue",
    "overlapping-buffers": "Overlapping memory operation buffers",
    "printf-attr": "Missing printf-format attribute",
    "privilege-drop": "Privilege drop flaw",
    "qsort": "qsort or comparator misuse",
    "race-condition": "Race condition or inconsistent synchronization",
    "regex-issues": "Regex safety issue",
    "scanf-uninit": "scanf leaves target uninitialized",
    "service-security": "Windows service security issue",
    "signal-handler": "Unsafe signal handler",
    "smart-pointer": "C++ smart pointer misuse",
    "snprintf-retval": "snprintf return value misuse",
    "socket-disconnect": "Socket disconnect handling issue",
    "spinlock-init": "Uninitialized lock primitive",
    "string-issues": "String encoding or termination issue",
    "strlen-strcpy": "strlen/strcpy size mismatch",
    "strncat-misuse": "strncat size argument misuse",
    "strncpy-termination": "strncpy missing termination",
    "thread-safety": "Thread safety issue",
    "time-issues": "Time handling issue",
    "token-privilege": "Windows token or privilege misuse",
    "type-confusion": "Type confusion or unsafe cast",
    "undefined-behavior": "Undefined behavior",
    "unsafe-stdlib": "Unsafe standard library use",
    "use-after-free": "Use-after-free or double free",
    "va-start-end": "va_list lifecycle misuse",
    "virtual-function": "C++ virtual function misuse",
    "windows-alloc": "Windows allocation API misuse",
    "windows-crypto": "Windows cryptography API misuse",
    "windows-path": "Windows path handling issue",
}


def split_frontmatter(text: str) -> tuple[dict[str, Any], str]:
    if not text.startswith("---\n"):
        return {}, text
    end = text.find("\n---", 4)
    if end == -1:
        return {}, text
    frontmatter = text[4:end]
    body = text[end + len("\n---") :].lstrip("\n")
    return parse_frontmatter(frontmatter), body


def parse_frontmatter(frontmatter: str) -> dict[str, Any]:
    result: dict[str, Any] = {}
    current_key: str | None = None
    for raw_line in frontmatter.splitlines():
        line = raw_line.rstrip()
        if not line:
            continue
        if line.startswith("  - ") and current_key:
            result.setdefault(current_key, []).append(parse_scalar(line[4:]))
            continue
        if ":" not in line or line.startswith((" ", "\t")):
            current_key = None
            continue
        key, value = line.split(":", 1)
        key = key.strip()
        value = value.strip()
        current_key = key
        if value == "":
            result[key] = []
        else:
            result[key] = parse_scalar(value)
    return result


def parse_scalar(value: str) -> Any:
    value = value.strip()
    if (value.startswith('"') and value.endswith('"')) or (
        value.startswith("'") and value.endswith("'")
    ):
        return value[1:-1]
    if value.startswith("[") and value.endswith("]"):
        inner = value[1:-1].strip()
        if not inner:
            return []
        return [parse_scalar(part.strip()) for part in inner.split(",")]
    if value.lower() == "true":
        return True
    if value.lower() == "false":
        return False
    return value


def parse_context(output_dir: Path) -> dict[str, Any]:
    path = output_dir / "context.md"
    if not path.exists():
        return {}
    frontmatter, _ = split_frontmatter(path.read_text(encoding="utf-8"))
    return frontmatter


def iter_findings(output_dir: Path) -> list[dict[str, Any]]:
    findings = []
    for path in sorted((output_dir / "findings").glob("*.md")):
        frontmatter, _ = split_frontmatter(path.read_text(encoding="utf-8"))
        frontmatter["_path"] = str(path)
        findings.append(frontmatter)
    return findings


def location_parts(location: Any) -> tuple[str, int]:
    value = str(location or "")
    if "," in value or "\n" in value:
        return value, 1
    match = re.match(r"^\[([^\]]+)\]\([^)]+\):(\d+)$", value)
    if match:
        return normalize_path(match.group(1)), int(match.group(2))
    path, sep, line = value.rpartition(":")
    if sep and line.isdecimal():
        return normalize_path(path), int(line)
    return normalize_path(value), 1


def normalize_path(path: str) -> str:
    path = path.replace("\\", "/")
    while path.startswith("./"):
        path = path[2:]
    while "//" in path:
        path = path.replace("//", "/")
    return path


def severity_allowed(severity: str, severity_filter: str) -> bool:
    return SEVERITY_ORDER.get(severity.upper(), 0) >= FILTER_MIN.get(severity_filter, 1)


def sarif_level(severity: str) -> str:
    return SEVERITY_LEVEL.get(severity.upper(), "warning")


def rule_level(findings: list[dict[str, Any]], bug_class: str) -> str:
    max_severity = "LOW"
    for finding in findings:
        if finding.get("bug_class") == bug_class:
            severity = str(finding.get("severity", "LOW")).upper()
            if SEVERITY_ORDER.get(severity, 0) > SEVERITY_ORDER.get(max_severity, 0):
                max_severity = severity
    return sarif_level(max_severity)


def build_sarif(output_dir: Path) -> dict[str, Any]:
    context = parse_context(output_dir)
    severity_filter = str(context.get("severity_filter", "all")).lower()
    threat_model = str(context.get("threat_model", "UNKNOWN"))
    findings = [
        finding
        for finding in iter_findings(output_dir)
        if "merged_into" not in finding
        and str(finding.get("fp_verdict", "")).upper() in SURVIVOR_VERDICTS
        and severity_allowed(str(finding.get("severity", "")).upper(), severity_filter)
    ]

    rules = []
    for bug_class in sorted({str(finding.get("bug_class", "unknown")) for finding in findings}):
        rules.append(
            {
                "id": bug_class,
                "shortDescription": {
                    "text": RULE_DESCRIPTIONS.get(bug_class, bug_class.replace("-", " ").title())
                },
                "defaultConfiguration": {"level": rule_level(findings, bug_class)},
            }
        )

    results = []
    for finding in findings:
        location, line = location_parts(finding.get("location"))
        severity = str(finding.get("severity", "MEDIUM")).upper()
        also_known_as = finding.get("also_known_as", [])
        if not isinstance(also_known_as, list):
            also_known_as = [str(also_known_as)]
        results.append(
            {
                "ruleId": str(finding.get("bug_class", "unknown")),
                "level": sarif_level(severity),
                "message": {
                    "text": str(finding.get("title") or finding.get("id") or "c-review finding")
                },
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {
                                "uri": location,
                                "uriBaseId": "%SRCROOT%",
                            },
                            "region": {"startLine": line},
                        }
                    }
                ],
                "properties": {
                    "finding_id": str(finding.get("id", "")),
                    "bug_class": str(finding.get("bug_class", "unknown")),
                    "severity": severity,
                    "attack_vector": str(finding.get("attack_vector", "")),
                    "exploitability": str(finding.get("exploitability", "")),
                    "fp_verdict": str(finding.get("fp_verdict", "")),
                    "also_known_as": also_known_as,
                },
            }
        )

    return {
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "c-review",
                        "informationUri": "https://github.com/trailofbits/tob-skills/tree/main/plugins/c-review",
                        "rules": rules,
                    }
                },
                "invocations": [
                    {
                        "executionSuccessful": True,
                        "properties": {
                            "threat_model": threat_model,
                            "severity_filter": severity_filter,
                        },
                    }
                ],
                "results": results,
            }
        ],
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Generate REPORT.sarif for a c-review output dir")
    parser.add_argument("output_dir", type=Path)
    parser.add_argument("--output", type=Path, default=None)
    args = parser.parse_args()

    output_dir = args.output_dir.resolve()
    output_path = args.output or output_dir / "REPORT.sarif"
    sarif = build_sarif(output_dir)
    output_path.write_text(json.dumps(sarif, indent=2) + "\n", encoding="utf-8")
    print(f"wrote {output_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
