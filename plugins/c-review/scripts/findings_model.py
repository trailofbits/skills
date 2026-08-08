#!/usr/bin/env python3
# /// script
# requires-python = ">=3.11"
# dependencies = []
# ///
"""Shared loader and reported-set selection for the c-review artifact generators.

`REPORT.md` and `REPORT.sarif` must describe the *same* set of findings. They did
not always, because each renderer applied the survivor and severity rules itself.
Both now call `reported_findings()` here, so a change to the rule changes both.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any

SURVIVOR_VERDICTS = frozenset({"TRUE_POSITIVE", "LIKELY_TP"})
SEVERITY_ORDER = {"LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}
FILTER_MIN = {"all": 1, "medium": 2, "high": 3}
UNVALIDATED_MARKER = "UNVALIDATED SEVERITY — not judged"


class FindingsError(Exception):
    """The input document is not a c-review result. Callers exit non-zero."""


def load(source: str | Path) -> dict[str, Any]:
    """Read a workflow result document. Raises FindingsError on anything unusable.

    Deliberately strict: this input is written by an agent transcribing a JSON blob
    into a heredoc, so truncation is the realistic failure. A truncated document
    must stop the run loudly rather than produce a report that silently omits the
    tail of the findings list.
    """
    if str(source) == "-":
        raw = sys.stdin.read()
        origin = "<stdin>"
    else:
        path = Path(source)
        if not path.is_file():
            raise FindingsError(f"findings file not found: {path}")
        raw = path.read_text(encoding="utf-8")
        origin = str(path)

    if not raw.strip():
        raise FindingsError(f"{origin} is empty")
    try:
        doc = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise FindingsError(
            f"{origin} is not valid JSON ({exc}). If it was written by an agent, it was "
            f"probably truncated — re-run the persist step rather than hand-editing it."
        ) from exc

    if not isinstance(doc, dict):
        raise FindingsError(f"{origin}: expected a JSON object, got {type(doc).__name__}")
    if "findings" not in doc:
        raise FindingsError(
            f"{origin}: no 'findings' key. An empty findings list is a valid clean run; a "
            f"missing key means the document is not a c-review result."
        )
    if not isinstance(doc["findings"], list):
        raise FindingsError(f"{origin}: 'findings' must be a list")
    doc.setdefault("run", {})
    doc.setdefault("stats", {})
    doc.setdefault("coverage", [])
    return doc


def severity_filter(doc: dict[str, Any]) -> str:
    value = str(doc.get("run", {}).get("severity_filter", "all")).lower()
    return value if value in FILTER_MIN else "all"


def severity_allowed(severity: Any, filter_name: str) -> bool:
    return SEVERITY_ORDER.get(str(severity or "").upper(), 0) >= FILTER_MIN.get(filter_name, 1)


def is_validated(finding: dict[str, Any]) -> bool:
    """False when no judge confirmed this severity (judge crashed, or none ran)."""
    return finding.get("severity_validated", True) is not False


def primaries(doc: dict[str, Any]) -> list[dict[str, Any]]:
    return [f for f in doc["findings"] if not f.get("merged_into")]


def survivors(doc: dict[str, Any]) -> list[dict[str, Any]]:
    return [
        f
        for f in primaries(doc)
        if str(f.get("fp_verdict", "")).upper() in SURVIVOR_VERDICTS or not f.get("fp_verdict")
    ]


def reported_findings(doc: dict[str, Any]) -> list[dict[str, Any]]:
    """Survivors that pass the severity filter, plus every unvalidated survivor.

    An unvalidated severity is an inferred guess, so applying a `medium`/`high`
    filter to it would drop a finding on the strength of a number no judge ever
    assigned. Those are surfaced regardless of filter and labelled instead.
    """
    name = severity_filter(doc)
    out = [
        f
        for f in survivors(doc)
        if not is_validated(f) or severity_allowed(f.get("severity"), name)
    ]
    out.sort(
        key=lambda f: (
            -SEVERITY_ORDER.get(str(f.get("severity", "")).upper(), 0),
            str(f.get("id", "")),
        )
    )
    return out


def display_title(finding: dict[str, Any]) -> str:
    title = str(finding.get("title") or finding.get("id") or "c-review finding")
    if not is_validated(finding):
        return f"[{UNVALIDATED_MARKER}] {title}"
    return title


def location(finding: dict[str, Any]) -> tuple[str, int]:
    path = str(finding.get("file") or "").replace("\\", "/").strip()
    while path.startswith("./"):
        path = path[2:]
    try:
        line = int(finding.get("line", 1))
    except (TypeError, ValueError):
        line = 1
    return path, max(1, line)
