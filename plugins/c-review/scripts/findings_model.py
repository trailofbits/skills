#!/usr/bin/env python3
# /// script
# requires-python = ">=3.11"
# dependencies = []
# ///
"""Shared loader and reported-set selection for the c-review artifact generators.

`REPORT.md` and `REPORT.sarif` must describe the *same* set of findings, so both call
`reported_findings()` here rather than each applying the survivor and severity rules
itself. A change to the rule then changes both.
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
LOCATION_MISSING_MARKER = "LOCATION MISSING"
LINE_INVENTED_MARKER = "LINE NUMBER INVENTED"


class FindingsError(Exception):
    """The input document is not a c-review result. Callers exit non-zero."""


def load(source: str | Path) -> dict[str, Any]:
    """Read a workflow result document. Raises FindingsError on anything unusable.

    Deliberately strict: a truncated or hand-edited document is indistinguishable from a
    good one until it is parsed, so it must stop the run loudly rather than produce a
    report that silently omits the tail of the findings list.
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
            f"{origin} is not valid JSON ({exc}). It was probably truncated or hand-edited "
            f"— re-run assemble_findings.py rather than editing this file directly."
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
    # Element and sibling types too. `setdefault` does not overwrite a wrong-typed value, so
    # `{"findings": ["oops"]}` or `{"findings": [], "run": []}` would reach both CLIs as an
    # uncaught AttributeError, and `{"coverage": 5}` is fatal to one generator and not the
    # other — one artifact on disk without the other, instead of the documented exit 2.
    for index, finding in enumerate(doc["findings"]):
        if not isinstance(finding, dict):
            raise FindingsError(
                f"{origin}: findings[{index}] is {type(finding).__name__}, expected an object"
            )
    for key, kind in (("run", dict), ("stats", dict), ("coverage", list)):
        doc.setdefault(key, kind())
        if not isinstance(doc[key], kind):
            raise FindingsError(
                f"{origin}: '{key}' is {type(doc[key]).__name__}, expected "
                f"{'an object' if kind is dict else 'a list'}"
            )
    # `coverage`'s ELEMENTS as well as its container, the mirror image of the `findings`
    # loop above: `{"coverage": ["oops"]}` passes the container check and then raises out of
    # `render()` alone, because `build_sarif()` never reads coverage.
    for index, row in enumerate(doc["coverage"]):
        if not isinstance(row, dict):
            raise FindingsError(
                f"{origin}: coverage[{index}] is {type(row).__name__}, expected an object"
            )
    return doc


def as_int(value: Any, default: int = 0) -> int:
    """A count out of a hand-edited or foreign document. Never raises.

    A malformed count is a display defect and must not be able to delete an artifact: a
    `stats.merged` of `"three"` raising out of `render()` while SARIF is still produced
    ships a REPORT.sarif with no REPORT.md.

    `OverflowError` is in the list because `json.loads` accepts the bare `Infinity` literal
    and `int(float('inf'))` raises that rather than a ValueError — without it one `Infinity`
    in `finding.line`, `stats.merged` or `ledger.checks_required` takes out both generators
    and contradicts the "never raises" above.
    """
    if isinstance(value, bool) or value is None:
        return default
    try:
        return int(value)
    except (TypeError, ValueError, OverflowError):
        return default


def severity_filter(doc: dict[str, Any]) -> str:
    value = str(doc.get("run", {}).get("severity_filter", "all")).lower()
    return value if value in FILTER_MIN else "all"


def severity_rank(severity: Any) -> int:
    """0 for anything that is not one of the four canonical spellings."""
    return SEVERITY_ORDER.get(str(severity or "").strip().upper(), 0)


def severity_allowed(severity: Any, filter_name: str) -> bool:
    rank = severity_rank(severity)
    if rank == 0:
        # An unrecognised spelling is NOT a ranking below LOW. Compared as 0 it drops a
        # judged TRUE_POSITIVE — `severity: "INFO"`, `"HIGH "`, `["HIGH"]`, `3` — out of
        # every tier including `all`, with no counter and no warning. Under `all` it is
        # reported and rendered as Unrated; a narrower filter still drops it, because there
        # is no number to compare against the bar.
        return FILTER_MIN.get(filter_name, 1) <= 1
    return rank >= FILTER_MIN.get(filter_name, 1)


def is_validated(finding: dict[str, Any]) -> bool:
    """False when nobody deliberately assigned this severity.

    `severity_validated` is written by the assembler — True under `--no-judge` because the
    reviewer assigned it deliberately, False when a judge crashed or never saw the finding.
    A finding carrying no severity at all was assigned one by nobody, so it is unvalidated
    whatever the flag says: otherwise it scores 0 against every filter, including `all`,
    and vanishes from every tier of the report with no counter and no warning.
    """
    if not finding.get("severity"):
        return False
    return finding.get("severity_validated", True) is not False


def _survives(finding: dict[str, Any]) -> bool:
    verdict = str(finding.get("fp_verdict", "")).upper()
    return verdict in SURVIVOR_VERDICTS or not finding.get("fp_verdict")


def primaries(doc: dict[str, Any]) -> list[dict[str, Any]]:
    """Findings nothing carries into the report on their behalf.

    Not simply "no `merged_into`". A duplicate whose primary was rejected, or whose primary
    is not in this document at all, has nothing representing it: skipping it blindly drops a
    `TRUE_POSITIVE` CRITICAL out of REPORT.md because the finding it was merged into is
    later judged a false positive.

    Duplicate ids resolve to EVERY carrier, not to the last one written — a last-wins
    `{str(id): f}` lets array order decide whether a CRITICAL merged into a shared id is
    rendered or silently dropped. A duplicate counts as represented only when every finding
    carrying its target id survives.
    """
    by_id: dict[str, list[dict[str, Any]]] = {}
    for f in doc["findings"]:
        if f.get("id"):
            by_id.setdefault(str(f.get("id")), []).append(f)
    out = []
    for finding in doc["findings"]:
        target = str(finding.get("merged_into") or "")
        if not target:
            out.append(finding)
            continue
        carriers = by_id.get(target) or []
        # Guards a self-merge — `merged_into` equal to this finding's own id, which
        # otherwise resolves to the finding itself, survives, and so gets skipped: the
        # finding appears in no artifact at all.
        if (
            not carriers
            or any(c is finding for c in carriers)
            or not all(_survives(c) for c in carriers)
        ):
            out.append(finding)
    return out


def survivors(doc: dict[str, Any]) -> list[dict[str, Any]]:
    return [f for f in primaries(doc) if _survives(f)]


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
    out.sort(key=lambda f: (-severity_rank(f.get("severity")), str(f.get("id", ""))))
    return out


def reconciliation_warnings(doc: dict[str, Any]) -> list[str]:
    """Where the document and its own `stats` disagree about the merge graph.

    Lives here rather than in `render_report` because both artifacts have to carry the same
    verdict: this is the loudest integrity check in the report, and reaching REPORT.md alone
    lets a SARIF-only consumer read a document with a lost finding as clean.

    Not `primaries + merged == total`, which cries wolf on the one recovery path
    `primaries()` deliberately supports: a duplicate whose primary was judged a false
    positive is resurrected as its own finding, so it is a primary AND carries
    `merged_into`, and the arithmetic comes out one short over a document in which every
    finding is in fact rendered.
    """
    findings = [f for f in doc.get("findings") or [] if isinstance(f, dict)]
    live = primaries(doc)
    absorbed = [f for f in findings if f.get("merged_into")]
    resurrected = [f for f in absorbed if any(f is p for p in live)]
    out: list[str] = []
    if resurrected:
        out.append(
            f"{len(resurrected)} finding(s) were merged into a primary that is not in the "
            f"reported set, so they are rendered on their own rather than dropped: "
            + ", ".join(f"`{f.get('id', '?')}`" for f in resurrected[:10])
        )
    # Counted the same way `stats.merged` is — one per finding carrying `merged_into`,
    # resurrected or not. Subtracting the resurrected ones fires on exactly the recovery
    # path above: a document in which every finding is rendered gets "one of them is
    # describing a different run" one line below the warning that already explained the same
    # finding correctly, and `lost_work` flips SARIF's `executionSuccessful` false over it.
    stated = as_int(doc.get("stats", {}).get("merged"))
    actual = len(absorbed)
    if stated != actual:
        out.append(
            f"findings.json carries {actual} finding(s) with a `merged_into` but its stats "
            f"block says {stated} were merged. The two disagree, so one of them is "
            f"describing a different run."
        )
    return out


def ledger_warnings(ledger: Any) -> list[str]:
    """What the coverage gate rejected, as warning sentences. Empty only when it accepted it all.

    Lives here rather than in either renderer because both artifacts have to carry the same
    verdict: a gate that reaches REPORT.md and nothing else lets a SARIF-only consumer read
    a run whose every coverage claim was rejected as a clean one.

    Reads either shape `run.ledger` can hold — `check_ledger._summary`, or a full
    `check_ledger.check` report — and treats *absent* as unmeasured, never as clean:
    `run.ledger` is None whenever there was no `units.json` to measure against, and the
    coverage table below it claims an audit that in that case never happened.
    """
    if not isinstance(ledger, dict):
        return [
            "The coverage gate left no result, so coverage is **unmeasured**: nothing audited "
            "the rows below against the unit parse."
        ]
    if ledger.get("error"):
        return [f"The coverage gate did not run, so coverage is **unmeasured**: {ledger['error']}"]

    def _count(list_key: str, count_key: str) -> int:
        value = ledger.get(list_key)
        return len(value) if isinstance(value, list) else as_int(ledger.get(count_key))

    required = as_int(ledger.get("checks_required"))
    completed = as_int(ledger.get("checks_completed"))
    satisfied = as_int(ledger.get("checks_satisfied"))
    violations = _count("violations", "violation_count")
    missing = _count("missing_rows", "missing_row_count")

    out: list[str] = []
    # The denominator's blind spot, and it travels with the percentage whether or not the
    # gate rejected anything. A unit whose parse counted no site owes no row, so it is
    # neither covered nor missing — on a real tree that is every header, a quarter of the
    # lines, and `coverage_pct: 100.0` over the rest reads identically to full coverage.
    blind_units = _count("unquestioned_units", "unquestioned_unit_count")
    blind_lines = as_int(ledger.get("unquestioned_lines"))
    total_lines = as_int(ledger.get("lines_total"))
    if blind_units:
        share = f" ({round(100.0 * blind_lines / total_lines)}% of lines)" if total_lines else ""
        out.append(
            f"Coverage is measured over the questions asked, and {blind_units} unit(s) "
            f"holding {blind_lines} line(s){share} were asked none — the parse counted no "
            f"site in them, so they owe no ledger row and are in neither the numerator nor "
            f"the denominator. They are unreviewed as far as this gate can tell."
        )
    # Rows the gate could not audit at all, and rows it could not place. `check_ledger` files
    # every sweep and invariant row as unverifiable precisely because sweep coverage is not
    # checkable against a parse; unsaid, they sit in REPORT.md's coverage table under a blurb
    # claiming `check_ledger.py` audited them against the unit parse. An invented unit id is
    # the same silence from the other side: `unknown_units > 0` beside
    # `executionSuccessful: true` and no warning in either artifact.
    unverifiable = _count("unverifiable_rows", "unverifiable_row_count")
    if unverifiable:
        out.append(
            f"{unverifiable} ledger row(s) are outside the generated unit list — the class "
            f"sweep and the invariant audit file there by design — so nothing audited them "
            f"against the parse. They are self-reported, not verified coverage."
        )
    # `isinstance`, not `or []`: `unknown_units: 5` is truthy and not iterable, so the
    # comprehension would raise a TypeError out of BOTH renderers — the class the `_count`
    # helper above exists to close.
    raw_unknown = ledger.get("unknown_units")
    unknown = [str(u) for u in raw_unknown] if isinstance(raw_unknown, list) else []
    # NOT `_count`, which prefers the list: `check_ledger._summary` truncates this one to
    # ten ids, so the list length saturates and 25 fabricated unit ids report as 10. The
    # count key is the whole number; the list is a sample.
    unknown_count = as_int(ledger.get("unknown_unit_count")) or len(unknown)
    if unknown_count:
        out.append(
            f"{unknown_count} ledger row(s) name a unit id that is in no unit list and is not "
            f"a sweep row, so they account for nothing: "
            + ", ".join(f"`{u}`" for u in unknown[:10])
            + (" …" if unknown_count > len(unknown[:10]) else "")
        )
    # A field the gate could not read. It used to be an uncaught `TypeError` that discarded
    # every other agent's coverage; now the row is kept and audited with an empty population,
    # so it earns a real violation too — but only this says WHICH field was unreadable, and
    # without it a reader sees the violation and no reason for it.
    raw_malformed = ledger.get("malformed_rows")
    malformed_sample = [str(m) for m in raw_malformed] if isinstance(raw_malformed, list) else []
    malformed_count = as_int(ledger.get("malformed_row_count")) or len(malformed_sample)
    if malformed_count:
        out.append(
            f"{malformed_count} part field(s) were the wrong type and could not be read, so "
            f"what they held is in no artifact: "
            + ", ".join(f"`{m}`" for m in malformed_sample[:10])
            + (" …" if malformed_count > len(malformed_sample[:10]) else "")
        )
    if not (violations or missing or satisfied < completed):
        return out

    # `or []`, not the bare get: a hand-edited or older `ledger-gate.json` with
    # `violation_count > 0` and neither key leaves `kinds` as None, and the join below then
    # raises an uncaught TypeError out of BOTH renderers.
    kinds = ledger.get("violation_kinds") or []
    if not kinds and isinstance(ledger.get("violations"), list):
        kinds = sorted(
            {str(v.get("kind", "")) for v in ledger["violations"] if isinstance(v, dict)}
        )
    gaps = [str(u) for u in (ledger.get("gap_units") or [])]
    detail = [f"{satisfied} of {required} required check(s) satisfied, {completed} answered"]
    if violations:
        detail.append(f"{violations} violation(s): " + ", ".join(f"`{k}`" for k in kinds if k))
    if missing:
        detail.append(
            f"{missing} unanswered row(s)"
            + (" in " + ", ".join(f"`{u}`" for u in gaps[:10]) if gaps else "")
        )
    out.append(
        "The coverage gate rejected part of this run's ledger — "
        + "; ".join(detail)
        + ". The rejected rows are **not coverage**; see `ledger-gate.json`."
    )
    return out


def display_title(finding: dict[str, Any]) -> str:
    """The title as both artifacts print it, carrying the markers a reader must not miss.

    `[LOCATION MISSING]` is here rather than in a SARIF-only `caveats` property because a
    finding with no `file` is still emitted, at `uri: ""` and `startLine: 1` — a code
    scanning UI pins it at the repository root with nothing saying the location was
    invented, and REPORT.md renders `:10` with no caveat at all.
    """
    # Collapsed to one line. `title` is agent-authored text and reaches REPORT.md as a
    # `### ` heading: a newline in it ends the heading and renders whatever follows as real
    # Markdown, so a title could forge a `## HIGH (99)` section and a whole fake finding
    # under it.
    title = " ".join(str(finding.get("title") or finding.get("id") or "c-review finding").split())
    if not location(finding)[0]:
        title = f"[{LOCATION_MISSING_MARKER}] {title}"
    if not line_usable(finding):
        title = f"[{LINE_INVENTED_MARKER}] {title}"
    if not is_validated(finding):
        return f"[{UNVALIDATED_MARKER}] {title}"
    return title


# SARIF regions are int64 and consumers reject a non-positive `startLine`, so an unusable
# `line` has to become a number — and `1` is the top of the file with nothing saying so.
# Both artifacts read the line through `location()` and both carry the marker when it was
# invented, so REPORT.md cannot print `src/parse.c:abc` while SARIF pins line 1 uncaveated.
MAX_LINE = 2**31 - 1


def line_usable(finding: dict[str, Any]) -> bool:
    # `line_invented` is the assembler's record that it had to put a number here. It coerces
    # `line` to a usable int before anything downstream sees it — SARIF rejects anything
    # else — so without the flag an invented 1 and a real line 1 are the same value and the
    # marker could never fire on an assembled finding.
    if finding.get("line_invented") is True:
        return False
    value = finding.get("line")
    return isinstance(value, int) and not isinstance(value, bool) and 1 <= value <= MAX_LINE


def location(finding: dict[str, Any]) -> tuple[str, int]:
    path = str(finding.get("file") or "").replace("\\", "/").strip()
    while path.startswith("./"):
        path = path[2:]
    # Through `as_int`, the one place the coercion rules live: an inline
    # `except (TypeError, ValueError)` misses `OverflowError`, so a `line` of the JSON
    # `Infinity` literal — which `json.loads` accepts — raises out of BOTH renderers and
    # destroys a completed run's artifacts over a display field.
    return path, min(MAX_LINE, max(1, as_int(finding.get("line", 1), 1)))
