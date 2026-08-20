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

from urllib.parse import quote

from findings_model import (
    FindingsError,
    as_int,
    display_title,
    is_validated,
    ledger_warnings,
    line_usable,
    load,
    location,
    primaries,
    reconciliation_warnings,
    reported_findings,
    severity_filter,
)


def _items(value: Any) -> list[str]:
    """A list-valued `run.*` field as strings. A bare string is ONE item, not its characters.

    `also_known_as: "BOF-002"` would otherwise come out as `["B","O","F","-","0","0","2"]`,
    and a list of ints raises a TypeError out of the whole generator.
    """
    if value is None:
        return []
    if isinstance(value, str):
        return [value]
    if isinstance(value, (list, tuple)):
        return [str(item) for item in value]
    return [str(value)]


SEVERITY_LEVEL = {"CRITICAL": "error", "HIGH": "error", "MEDIUM": "warning", "LOW": "note"}

# One entry per class in `assemble_findings.CLASS_PREFIXES`, which is the catalogue the
# assembler can actually emit. Held there exactly by
# `test_generate_sarif.test_rule_descriptions_cover_every_emittable_bug_class`, in both
# directions: a class with no description ships the title-cased id as its SARIF rule
# description, and a description for a class nothing can emit is dead weight that hides the
# drift.
RULE_DESCRIPTIONS = {
    "access-control": "Missing or misplaced authorization check",
    "banned-api-with-attacker-data": "Banned or deprecated API reached by attacker-influenced data",
    "buffer-overflow": "Out-of-bounds write",
    "createprocess": "Windows process creation misuse",
    "cross-process": "Unsafe cross-process handle or memory operation",
    "crypto-misuse": "Cryptographic primitive or protocol used unsafely",
    "dll-planting": "DLL search-order hijacking",
    "dos": "Attacker-controlled resource consumption",
    "envvar": "Environment variable trust",
    "error-handling": "Unchecked or mis-compared return value",
    "exception-safety": "Exception path leaks or leaves partial state",
    "exploit-mitigations": "Missing or misspelled hardening flag",
    "filesystem-issues": "Symlink, temp file or path-normalization issue",
    "flexible-array": "Flexible-array or struct-hack sizing",
    "format-string": "Format-string control",
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
    "null-deref": "Null pointer dereference",
    "oob-comparison": "Comparison reads past the shorter buffer",
    "oob-read": "Out-of-bounds read",
    "open-issues": "Unsafe file open or path resolution",
    "operator-precedence": "Operator precedence or associativity",
    "overlapping-buffers": "Overlapping source and destination",
    "privilege-drop": "Incomplete or unchecked privilege drop",
    "qsort": "Non-transitive comparator drives qsort out of bounds",
    "race-condition": "TOCTOU or unsynchronized shared state",
    "regex-issues": "Regex denial of service or matching bypass",
    "scanf-uninit": "scanf family leaves targets uninitialized",
    "service-security": "Windows service configuration",
    "signal-handler": "Async-signal-unsafe handler",
    "smart-pointer": "C++ smart pointer ownership",
    "snprintf-retval": "snprintf return value misuse",
    "socket-state": "Socket left in an unsafe or unexpected state",
    "state-field-invariant": "Invariant on a shared-state field broken by one path",
    "string-bounds-and-termination": "String bound or NUL-termination mistake",
    "string-issues": "Encoding, locale or multibyte handling",
    "thread-safety": "Non-reentrant library call in threaded code",
    "time-issues": "Clock or time-arithmetic assumption",
    "token-privilege": "Token or impersonation handling",
    "type-confusion": "Type confusion or unsafe cast",
    "undefined-behavior": "Undefined behavior the optimizer can weaponize",
    "uninitialized-data": "Use or disclosure of uninitialized memory",
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
            # `str(...)`, matching how `classes` was built. Compared raw, a `bug_class` of
            # `None` or a number matches nothing here and produces a rule whose
            # `defaultConfiguration.level` is `note` beside its own result at `error`: two
            # levels for one rule, from the same document.
            if str(f.get("bug_class", "unknown")) == bug_class:
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
        # Without this a CI gate reading only SARIF ingests a reviewer-assigned CRITICAL
        # as judge-validated, while REPORT.md says in so many words that no
        # false-positive pass ran. The two artifacts have to carry the same verdict.
        if str(f.get("severity_source", "")) == "reviewer":
            markers.append("severity is the reviewer's own; no false-positive pass ran")
        # A `line` of `"abc"` becomes startLine 1 — the top of the file — so without this
        # a SARIF consumer cannot tell an invented line from a real one.
        if not line_usable(f):
            markers.append("line number was not usable and has been replaced")
        results.append(
            {
                "ruleId": str(f.get("bug_class", "unknown")),
                "level": sarif_level(f.get("severity")),
                "message": {"text": display_title(f)},
                "locations": [
                    {
                        "physicalLocation": {
                            # Percent-encoded: a `#` in a path parses as a URI fragment,
                            # so `src/a#frag.c` pointed a code-scanning UI at `src/a`.
                            "artifactLocation": {
                                "uri": quote(uri, safe="/"),
                                "uriBaseId": "%SRCROOT%",
                            },
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
                    "severity_source": str(f.get("severity_source", "")),
                    "confidence": str(f.get("confidence", "")),
                    "found_by": str(f.get("found_by", "")),
                    "outside_assigned_classes": bool(f.get("outside_assigned_classes", False)),
                    "severity_validated": is_validated(f),
                    "also_known_as": _items(f.get("also_known_as")),
                    "caveats": markers,
                },
                # Location-derived fingerprints make every alert churn — close and reopen —
                # on an unrelated line shift above it. `finding_id` is stable per content.
                "partialFingerprints": {"cReviewFindingId/v1": str(f.get("id", ""))},
            }
        )

    notifications = []
    # No judge ran, so every `fp_verdict` and every severity below is the reviewer's own.
    # REPORT.md says this loudly; without the notification SARIF says nothing at all and the
    # two artifacts disagree about the single most important caveat in the run.
    if run.get("judge_ran") is False:
        notifications.append(
            {
                "level": "warning",
                "message": {
                    "text": "No false-positive or severity judge ran in this configuration. "
                    "Every fp_verdict and severity in this file is the reviewer's own and was "
                    "not independently reviewed."
                },
            }
        )
    for part in _items(run.get("missing_review_parts")):
        notifications.append(
            {
                "level": "error",
                "message": {
                    "text": f"The unit list generated slice '{part}' and no part file answers "
                    "it; that slice of the code was reviewed by nobody."
                },
            }
        )
    # The coverage gate's verdict, from the same `run.ledger` the Run-warnings block reads.
    # It is the strongest single signal that the review is not what it claims, so it cannot
    # reach REPORT.md alone: a CI gate reading only SARIF would see a run whose every
    # coverage claim the gate rejected as clean. `message.text` is plain text in SARIF, so
    # the markdown emphasis the Markdown renderer wants is stripped here.
    for text in ledger_warnings(run.get("ledger")) + reconciliation_warnings(doc):
        notifications.append(
            {"level": "warning", "message": {"text": text.replace("**", "").replace("`", "")}}
        )
    for group in _items(run.get("groups_failed")):
        notifications.append(
            {
                "level": "warning",
                "message": {
                    "text": f"Bug-class group '{group}' returned nothing; its classes are uncovered."
                },
            }
        )
    for failure in _items(run.get("agent_failures")):
        notifications.append(
            {
                "level": "warning",
                "message": {"text": f"Review agent failed: {failure}. Its code is unreviewed."},
            }
        )
    # The assembler's integrity checks, mirrored from the Run-warnings block in REPORT.md
    # so a SARIF consumer cannot read a run that silently dropped an agent's whole output
    # as a clean one.
    for part in _items(run.get("unrecognised_parts")):
        notifications.append(
            {
                "level": "error",
                "message": {
                    "text": f"No rule reads part file '{part}'; its findings are not in this report."
                },
            }
        )
    for part in _items(run.get("stale_part_files")):
        notifications.append(
            {
                "level": "warning",
                "message": {
                    "text": f"Part file '{part}' is an earlier draft than the agent's accepted "
                    "return; the findings read from it are degraded."
                },
            }
        )
    # `_items`, not `len(...)`. `incomplete_findings: 5` is truthy and has no length, so it
    # raises a TypeError out of this generator while `render()` — which reads the same field
    # through its own `_items` — writes REPORT.md happily: one artifact on disk without the
    # other, which is exactly what `load()` exists to turn into a clean exit 2.
    incomplete = _items(run.get("incomplete_findings"))
    if incomplete:
        notifications.append(
            {
                "level": "warning",
                "message": {
                    "text": f"{len(incomplete)} finding(s) are missing required "
                    "field(s) the agent dropped when writing its part file."
                },
            }
        )
    if run.get("expectations_checked") is False:
        notifications.append(
            {
                "level": "warning",
                "message": {
                    "text": "No part-file expectations were checked, so the agent failure list "
                    "describes the disk rather than the run and coverage may be over-reported."
                },
            }
        )
    # Free-text caveats a reviewer raised about its own coverage — units it could not
    # finish, files it could not read. They reached REPORT.md and nothing else, which is
    # the artifact asymmetry `ledger_warnings` exists to prevent.
    for note in _items(run.get("hunter_notes")):
        notifications.append({"level": "warning", "message": {"text": f"Reviewer note — {note}"}})
    for fid in _items(run.get("unjudged_findings")):
        notifications.append(
            {
                "level": "warning",
                "message": {
                    "text": f"Finding {fid} reached no judge; its verdict and severity are unvalidated."
                },
            }
        )

    ledger = run.get("ledger") if isinstance(run.get("ledger"), dict) else {}
    # `executionSuccessful` is false whenever this run measurably lost work — hardcoded true,
    # a run that lost whole reviewers, dropped an agent's entire part file, or had every
    # coverage claim rejected reads as a clean invocation to any CI gate keying off it. NOT
    # false for the unquestioned-unit blind spot, which is a property of the corpus rather
    # than of the run.
    lost_work = bool(
        _items(run.get("agent_failures"))
        or _items(run.get("groups_failed"))
        or _items(run.get("missing_review_parts"))
        or _items(run.get("unrecognised_parts"))
        # A part file that is an earlier draft than the agent's accepted return is
        # measurable loss — REPORT.md calls those findings degraded and this generator
        # already emits a warning notification for them — and a finding reported with a
        # severity no judge validated is the other half of the same story.
        or _items(run.get("stale_part_files"))
        or _items(run.get("unjudged_findings"))
        or incomplete
        or run.get("expectations_checked") is False
        or not isinstance(run.get("ledger"), dict)
        or ledger.get("error")
        # The gate's THIRD rejection condition, which `ledger_warnings` reports: a ledger of
        # `{required: 5, completed: 5, satisfied: 2}` carries no violation or missing-row
        # count, so without this `executionSuccessful` is true beside a notification saying
        # the gate rejected the run. A row the gate refused is not coverage whatever else
        # is zero.
        or as_int(ledger.get("checks_satisfied")) < as_int(ledger.get("checks_completed"))
        # A row naming a unit id that is in no unit list accounts for nothing. Same
        # asymmetry: `ledger_warnings` says so where the invocation would not.
        or ledger.get("unknown_units")
        # Both shapes `run.ledger` can hold. `ledger_warnings` reads the full
        # `check_ledger.check` report as well as the compact summary, and that shape carries
        # `violations`/`missing_rows` LISTS and no `*_count` keys at all — so on the count
        # keys alone a document with 40 violations reads as a clean invocation while the
        # notification beside it says "0 of 40 required check(s) satisfied".
        or ledger.get("violation_count")
        or ledger.get("missing_row_count")
        or ledger.get("violations")
        or ledger.get("missing_rows")
        or reconciliation_warnings(doc)
    )
    invocation: dict[str, Any] = {
        "executionSuccessful": not lost_work,
        "properties": {
            # None, not 0, when the gate left no number: a consumer computing a coverage
            # ratio has to be able to tell "no row was accepted" from "nothing was measured".
            "checks_required": ledger.get("checks_required"),
            "checks_completed": ledger.get("checks_completed"),
            "checks_satisfied": ledger.get("checks_satisfied"),
            "judge_ran": run.get("judge_ran"),
            "threat_model": str(run.get("threat_model", "UNKNOWN")),
            # What the detect phase actually saw. REPORT.md prints it under the header; a
            # SARIF consumer otherwise cannot tell an is_posix=false run from an unexamined
            # one.
            "platform_evidence": str(run.get("platform_evidence", "")),
            # The flags themselves, not just the evidence for them: in REPORT.md alone, a
            # SARIF consumer reads the justification for a platform decision without being
            # able to see the decision.
            "is_cpp": run.get("is_cpp"),
            "is_posix": run.get("is_posix"),
            "is_windows": run.get("is_windows"),
            "context_roots": str(run.get("context_roots", ".")),
            "severity_filter": severity_filter(doc),
            "finding_scope_root": str(run.get("finding_scope_root", ".")),
            "primaries": len(primaries(doc)),
            "reported": len(findings),
            "groups_failed": _items(run.get("groups_failed")),
            "agent_failures": _items(run.get("agent_failures")),
            "unjudged_findings": _items(run.get("unjudged_findings")),
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
