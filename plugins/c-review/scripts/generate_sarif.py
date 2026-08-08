#!/usr/bin/env python3
# /// script
# requires-python = ">=3.11"
# dependencies = []
# ///
"""Write REPORT.sarif from a c-review workflow result document.

Usage:
    uv run generate_sarif.py --findings findings.json --output-dir /path/to/run
    uv run generate_sarif.py --findings - --output /tmp/REPORT.sarif
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

from findings_model import (
    FindingsError,
    display_title,
    is_validated,
    load,
    location,
    primaries,
    reported_findings,
    severity_filter,
)

SEVERITY_LEVEL = {"CRITICAL": "error", "HIGH": "error", "MEDIUM": "warning", "LOW": "note"}

RULE_DESCRIPTIONS = {
    "access-control": "Missing or misplaced authorization check",
    "banned-functions": "Banned or deprecated API reached by attacker-influenced data",
    "buffer-overflow": "Out-of-bounds write",
    "compiler-bugs": "Security check or scrubbing the optimizer removes",
    "createprocess": "Windows process creation misuse",
    "cross-process": "Unsafe cross-process handle or memory operation",
    "dll-planting": "DLL search-order hijacking",
    "dos": "Attacker-controlled resource consumption",
    "eintr-handling": "EINTR handling",
    "envvar": "Environment variable trust",
    "errno-handling": "errno protocol violation",
    "error-handling": "Unchecked or mis-compared return value",
    "exception-safety": "Exception path leaks or leaves partial state",
    "exploit-mitigations": "Missing or misspelled hardening flag",
    "filesystem-issues": "Symlink, temp file or path-normalization issue",
    "flexible-array": "Flexible-array or struct-hack sizing",
    "format-string": "Format-string control",
    "half-closed-socket": "Half-closed socket state",
    "inet-aton": "inet_aton/inet_addr accept trailing garbage",
    "init-order": "Static initialization order",
    "installer-race": "Installer or updater filesystem race",
    "integer-overflow": "Integer overflow, truncation or signedness",
    "iterator-invalidation": "Iterator, pointer or reference invalidated",
    "lambda-capture": "Lambda capture outliving its referent",
    "logic-flaw": "Security logic, protocol or state-machine flaw",
    "memcpy-size": "Bad size argument to a memory primitive",
    "memory-leak": "Memory or resource leak",
    "move-semantics": "Use of a moved-from object",
    "named-pipe": "Named pipe security issue",
    "negative-retval": "Negative return used as a size or index",
    "null-deref": "Null pointer dereference",
    "null-zero": "Integer 0 passed where a null pointer is required",
    "oob-comparison": "Comparison reads past the shorter buffer",
    "open-issues": "Unsafe file open or path resolution",
    "operator-precedence": "Operator precedence or associativity",
    "overlapping-buffers": "Overlapping source and destination",
    "printf-attr": "Variadic wrapper without a format attribute",
    "privilege-drop": "Incomplete or unchecked privilege drop",
    "qsort": "Non-transitive comparator drives qsort out of bounds",
    "race-condition": "TOCTOU or unsynchronized shared state",
    "regex-issues": "Regex denial of service or matching bypass",
    "scanf-uninit": "scanf family leaves targets uninitialized",
    "service-security": "Windows service configuration",
    "signal-handler": "Async-signal-unsafe handler",
    "smart-pointer": "C++ smart pointer ownership",
    "snprintf-retval": "snprintf return value misuse",
    "socket-disconnect": "connect(AF_UNSPEC) dissolves an existing association",
    "spinlock-init": "Lock primitive used before initialization",
    "string-issues": "Encoding, locale or multibyte handling",
    "strlen-strcpy": "strlen-derived allocation off by the NUL",
    "strncat-misuse": "strncat size argument means remaining space",
    "strncpy-termination": "strncpy leaves the destination unterminated",
    "thread-safety": "Non-reentrant library call in threaded code",
    "time-issues": "Clock or time-arithmetic assumption",
    "token-privilege": "Token or impersonation handling",
    "type-confusion": "Type confusion or unsafe cast",
    "undefined-behavior": "Undefined behavior the optimizer can weaponize",
    "uninitialized-data": "Use or disclosure of uninitialized memory",
    "unsafe-stdlib": "Discouraged standard library usage",
    "use-after-free": "Use after free, double free or dangling pointer",
    "va-start-end": "va_list lifecycle",
    "virtual-function": "Virtual dispatch hazard",
    "windows-alloc": "Windows allocator misuse",
    "windows-crypto": "Windows cryptography API misuse",
    "windows-path": "Windows path parsing",
}


def sarif_level(severity: Any) -> str:
    return SEVERITY_LEVEL.get(str(severity or "").upper(), "warning")


def build_sarif(doc: dict[str, Any]) -> dict[str, Any]:
    run = doc.get("run", {})
    findings = reported_findings(doc)

    classes = sorted({str(f.get("bug_class", "unknown")) for f in findings})
    rules = []
    for bug_class in classes:
        worst = "note"
        for f in findings:
            if f.get("bug_class") == bug_class:
                level = sarif_level(f.get("severity"))
                if ["note", "warning", "error"].index(level) > ["note", "warning", "error"].index(
                    worst
                ):
                    worst = level
        rules.append(
            {
                "id": bug_class,
                "shortDescription": {
                    "text": RULE_DESCRIPTIONS.get(
                        bug_class, bug_class.replace("-", " ").capitalize()
                    )
                },
                "defaultConfiguration": {"level": worst},
            }
        )

    results = []
    for f in findings:
        uri, line = location(f)
        markers = []
        if not is_validated(f):
            markers.append("severity not judge-validated")
        if not uri:
            markers.append("location missing")
        results.append(
            {
                "ruleId": str(f.get("bug_class", "unknown")),
                "level": sarif_level(f.get("severity")),
                "message": {"text": display_title(f)},
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {"uri": uri, "uriBaseId": "%SRCROOT%"},
                            "region": {"startLine": line},
                        }
                    }
                ],
                "properties": {
                    "finding_id": str(f.get("id", "")),
                    "bug_class": str(f.get("bug_class", "unknown")),
                    "function": str(f.get("function", "")),
                    "severity": str(f.get("severity", "")).upper(),
                    "attack_vector": str(f.get("attack_vector", "")),
                    "exploitability": str(f.get("exploitability", "")),
                    "fp_verdict": str(f.get("fp_verdict", "")),
                    "confidence": str(f.get("confidence", "")),
                    "found_by": str(f.get("found_by", "")),
                    "outside_assigned_classes": bool(f.get("outside_assigned_classes", False)),
                    "severity_validated": is_validated(f),
                    "also_known_as": list(f.get("also_known_as", []) or []),
                    "caveats": markers,
                },
            }
        )

    notifications = []
    for group in run.get("groups_failed", []) or []:
        notifications.append(
            {
                "level": "warning",
                "message": {
                    "text": f"Bug-class group '{group}' returned nothing; its classes are uncovered."
                },
            }
        )
    for fid in run.get("unjudged_findings", []) or []:
        notifications.append(
            {
                "level": "warning",
                "message": {
                    "text": f"Finding {fid} reached no judge; its verdict and severity are unvalidated."
                },
            }
        )

    invocation: dict[str, Any] = {
        "executionSuccessful": True,
        "properties": {
            "threat_model": str(run.get("threat_model", "UNKNOWN")),
            "severity_filter": severity_filter(doc),
            "finding_scope_root": str(run.get("finding_scope_root", ".")),
            "primaries": len(primaries(doc)),
            "reported": len(findings),
            "groups_failed": list(run.get("groups_failed", []) or []),
            "unjudged_findings": list(run.get("unjudged_findings", []) or []),
        },
    }
    if notifications:
        invocation["toolExecutionNotifications"] = notifications

    return {
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "c-review",
                        "informationUri": "https://github.com/trailofbits/skills/tree/main/plugins/c-review",
                        "rules": rules,
                    }
                },
                "originalUriBaseIds": {
                    "%SRCROOT%": {
                        "description": {
                            "text": "Root of the audited C/C++ project; finding URIs are relative to this."
                        }
                    }
                },
                "invocations": [invocation],
                "results": results,
            }
        ],
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--findings", required=True, help="path to findings.json, or - for stdin")
    parser.add_argument("--output-dir", type=Path, default=None, help="writes REPORT.sarif here")
    parser.add_argument("--output", type=Path, default=None, help="explicit output path")
    parsed = parser.parse_args(argv)

    if not parsed.output and not parsed.output_dir:
        parser.error("one of --output-dir or --output is required")

    try:
        doc = load(parsed.findings)
    except FindingsError as exc:
        print(f"generate_sarif: {exc}", file=sys.stderr)
        return 2

    out = parsed.output or (parsed.output_dir / "REPORT.sarif")
    out.parent.mkdir(parents=True, exist_ok=True)
    sarif = build_sarif(doc)
    out.write_text(json.dumps(sarif, indent=2) + "\n", encoding="utf-8")
    print(f"wrote {out} ({len(sarif['runs'][0]['results'])} result(s))")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
