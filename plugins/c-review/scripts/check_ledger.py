#!/usr/bin/env python3
# /// script
# requires-python = ">=3.11"
# dependencies = []
# ///
"""Diff the review ledger against the code-generated unit list.

The distinction this script exists to enforce is the one the previous architecture
got wrong: coverage is measured against the parse, **never against the reviewer's own
account of what it reviewed**. `validate_artifacts.py` in the previous pipeline
certified 40/40 clean rows while one worker had fabricated thirteen of them, because
it validated the rows that were present rather than the rows that were owed.

Three rules, each from a measured failure (tools/c-review-bench/MEASUREMENTS.md):

1. **A finding raises the prior; it never closes the unit.** A `finding` row still
   owes an account of the rest of its population. The densest function in the corpus
   was also the one with the most misses.
2. **A `clean` verdict must account for a counted population.** `sites_accounted`
   must cover every site line `enumerate_units.py` counted for that question. A row
   claiming clean over twelve write sites while citing none is a gate failure.
3. **Every owed row must exist.** Missing rows are reported as gaps, not inferred to
   be clean.

Coverage is reported as checks completed / checks required. "Functions touched" would
have shown the 628-line function as fully covered in all four runs that found two or
three of its four bugs.

Exit codes: 0 when the ledger was checked, 2 when there was nothing to check (no
units, or no ledger rows at all) or the inputs are unreadable, and — only under
`--strict` — 1 when the ledger has gaps or violations.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

VALID_VERDICTS = frozenset({"clean", "finding", "needs-human", "not-applicable"})


class LedgerError(Exception):
    """Nothing to check, or the inputs are not a c-review run. Callers exit non-zero."""


def _load_json(path: Path) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise LedgerError(f"missing input: {path}") from exc
    except json.JSONDecodeError as exc:
        raise LedgerError(f"{path} is not valid JSON ({exc})") from exc


def load_parts(parts_dir: Path, prefixes: tuple[str, ...]) -> list[tuple[str, dict[str, Any]]]:
    """Every agent part file whose name starts with one of `prefixes`, sorted by name."""
    if not parts_dir.is_dir():
        raise LedgerError(f"no parts directory at {parts_dir}; no agent wrote its results")
    out = []
    for path in sorted(parts_dir.glob("*.json")):
        if not path.name.startswith(prefixes):
            continue
        doc = _load_json(path)
        if not isinstance(doc, dict):
            raise LedgerError(f"{path}: expected a JSON object, got {type(doc).__name__}")
        out.append((path.stem, doc))
    return out


def required_rows(units: list[dict[str, Any]]) -> dict[tuple[str, str], dict[str, Any]]:
    """(unit_id, question) -> the site lines that row must account for."""
    owed: dict[tuple[str, str], dict[str, Any]] = {}
    for unit in units:
        sites = unit.get("sites") or {}
        for question in unit.get("required_questions") or []:
            lines: set[int] = set()
            for kind, kind_lines in sites.items():
                if kind in QUESTION_SITE_KINDS.get(question, ()):
                    lines.update(int(n) for n in kind_lines)
            owed[(unit["id"], question)] = {
                "unit_id": unit["id"],
                "file": unit.get("file", ""),
                "name": unit.get("name", ""),
                "question": question,
                "sites": sorted(lines),
            }
    return owed


# Mirrors enumerate_units.QUESTIONS without importing it: this script must run with no
# dependencies, and enumerate_units needs tree-sitter at import time only for parsing,
# but keeping the two files independent means the gate can check a units.json produced
# by any version. A question present in units.json but absent here contributes an empty
# site set, so the row is still required — it just cannot be checked for completeness.
QUESTION_SITE_KINDS: dict[str, tuple[str, ...]] = {
    "bounds": ("write",),
    "integer": ("conversion",),
    "alloc-lifetime": ("alloc", "release"),
    "sizeof-arith": ("sizeof",),
    "nul-termination": ("strop",),
    "return-values": ("unchecked_call",),
    "caller-contract": ("param",),
    "banned-api": ("banned",),
    "initialisation": ("outparam",),
    "macro-contract": ("macro",),
}


def check(units_doc: dict[str, Any], parts: list[tuple[str, dict[str, Any]]]) -> dict[str, Any]:
    units = units_doc.get("units") or []
    if not units:
        raise LedgerError(
            "units.json lists no units. There is nothing to check, which is not the "
            "same as a review with no gaps."
        )
    unit_by_id = {u["id"]: u for u in units}
    owed = required_rows(units)
    if not owed:
        raise LedgerError(
            f"{len(units)} unit(s) but no required questions. Either the parse counted "
            f"no sites anywhere, or units.json predates the question set."
        )

    # Collect first, judge afterwards. Judging inline made the gate's verdict depend on
    # the alphabetical order of part filenames: a thin row from `review-01` recorded a
    # violation, the full row from `second-01` then superseded it in `seen`, and the
    # violation stayed. A second pass that genuinely finished the population could not
    # clear the gate, which is the opposite of what the second pass is for.
    candidates: dict[tuple[str, str], list[dict[str, Any]]] = {}
    unknown_units: list[str] = []
    unverifiable: list[str] = []
    findings_by_unit: dict[str, int] = {}
    rows_total = 0

    for part_id, doc in parts:
        for finding in doc.get("findings") or []:
            uid = str(finding.get("unit_id") or "")
            if uid:
                findings_by_unit[uid] = findings_by_unit.get(uid, 0) + 1
        for row in doc.get("ledger") or []:
            rows_total += 1
            uid = str(row.get("unit_id") or "")
            question = str(row.get("question") or "")
            key = (uid, question)
            if uid not in unit_by_id:
                # A sweep row is outside the generated unit list BY DESIGN: the class
                # sweep files under `(sweep)` and the invariant audit under
                # `struct.field`. Lumping those in with genuinely unmappable ids made 14
                # expected rows look like 14 errors, and hid the fact that sweep coverage
                # is simply not verifiable against a parse. Separate them and say so.
                if uid == "(sweep)" or (uid and ":" not in uid):
                    unverifiable.append(f"{part_id}: {uid}")
                else:
                    unknown_units.append(f"{part_id}: {uid or '(blank)'}")
                continue
            if key not in owed:
                # Not an error: an agent may answer a question it was not owed. It is
                # ignored so an extra row can never substitute for a missing one.
                continue
            candidates.setdefault(key, []).append(
                {
                    "unit_id": uid,
                    "question": question,
                    "verdict": str(row.get("verdict") or ""),
                    "part": part_id,
                    "accounted": sorted(
                        {int(n) for n in (row.get("sites_accounted") or []) if _is_int(n)}
                    ),
                    "evidence": str(row.get("evidence") or ""),
                }
            )

    seen: dict[tuple[str, str], dict[str, Any]] = {}
    violations: list[dict[str, Any]] = []
    for key in sorted(candidates):
        rows = candidates[key]
        # Two agents answering the same row is expected — the second pass does it by
        # design. Take the best answer, not the last one: a row that satisfies the gate
        # beats one that does not, then the one accounting for more of the population,
        # then the earlier part id so the choice is deterministic.
        scored = [(_row_violations(owed[key], r), r) for r in rows]
        scored.sort(key=lambda pair: (len(pair[0]), -len(pair[1]["accounted"]), pair[1]["part"]))
        best_violations, best = scored[0]
        seen[key] = best
        violations.extend(best_violations)

    if rows_total == 0:
        raise LedgerError(
            f"{len(parts)} part file(s) and zero ledger rows. A review that produced no "
            f"ledger has not been checked; do not report it as covered."
        )

    missing_rows = [owed[key] for key in sorted(owed) if key not in seen]
    completed = len(owed) - len(missing_rows)
    # A row that was answered but whose answer the gate rejected is NOT coverage. The
    # previous version reported 105/105 and 100% while carrying two violations, which is
    # a gate that logs and passes — the exact thing this file exists to stop being.
    violated_keys = {(v["unit_id"], v["question"]) for v in violations}
    satisfied = len([key for key in owed if key in seen and key not in violated_keys])
    verdict_counts: dict[str, int] = {}
    for entry in seen.values():
        verdict_counts[entry["verdict"]] = verdict_counts.get(entry["verdict"], 0) + 1

    units_with_findings = sorted(findings_by_unit)
    return {
        "checks_required": len(owed),
        "checks_completed": completed,
        "checks_satisfied": satisfied,
        # Headline coverage is SATISFIED over required, not answered over required.
        "coverage_pct": round(100.0 * satisfied / len(owed), 1) if owed else 0.0,
        "answered_pct": round(100.0 * completed / len(owed), 1) if owed else 0.0,
        "rows_seen": rows_total,
        "verdict_counts": verdict_counts,
        "missing_rows": missing_rows,
        "violations": violations,
        "unknown_units": sorted(set(unknown_units)),
        "unverifiable_rows": sorted(set(unverifiable)),
        "units_with_findings": [
            {
                "unit_id": uid,
                "file": unit_by_id[uid]["file"],
                "name": unit_by_id[uid]["name"],
                "start_line": unit_by_id[uid]["start_line"],
                "end_line": unit_by_id[uid]["end_line"],
                "findings": findings_by_unit[uid],
            }
            for uid in units_with_findings
            if uid in unit_by_id
        ],
        "units_total": len(units),
        "parts_read": [pid for pid, _ in parts],
    }


def _row_violations(owed_row: dict[str, Any], row: dict[str, Any]) -> list[dict[str, Any]]:
    """Everything wrong with one candidate row, as a list so rows can be compared."""
    part_id = row["part"]
    verdict = row["verdict"]
    accounted = set(row["accounted"])
    expected = set(owed_row["sites"])

    if verdict not in VALID_VERDICTS:
        return [
            _violation(
                owed_row,
                part_id,
                "invalid-verdict",
                f"verdict {verdict!r} is not one of {sorted(VALID_VERDICTS)}",
            )
        ]

    out: list[dict[str, Any]] = []
    if verdict == "not-applicable":
        if expected:
            out.append(
                _violation(
                    owed_row,
                    part_id,
                    "not-applicable-with-population",
                    f"{len(expected)} site(s) were counted here, so the question applies",
                )
            )
        return out

    if verdict in ("clean", "finding"):
        missing = sorted(expected - accounted)
        if missing:
            out.append(
                _violation(
                    owed_row,
                    part_id,
                    "population-not-accounted",
                    f"verdict {verdict} but {len(missing)} of {len(expected)} site "
                    f"line(s) are unaccounted: {missing[:12]}"
                    + (" …" if len(missing) > 12 else ""),
                )
            )
        stray = sorted(accounted - expected)
        if stray:
            out.append(
                _violation(
                    owed_row,
                    part_id,
                    "sites-outside-population",
                    f"accounted line(s) {stray[:12]} are not sites this question counts "
                    f"in this unit",
                )
            )
    if not row["evidence"].strip():
        out.append(_violation(owed_row, part_id, "no-evidence", "evidence is empty"))
    return out


def _is_int(value: Any) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)


def _violation(owed_row: dict[str, Any], part_id: str, kind: str, detail: str) -> dict[str, Any]:
    return {
        "unit_id": owed_row["unit_id"],
        "file": owed_row["file"],
        "name": owed_row["name"],
        "question": owed_row["question"],
        "part": part_id,
        "kind": kind,
        "detail": detail,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--run-dir", required=True, type=Path, help="directory holding units.json and parts/"
    )
    parser.add_argument(
        "--prefix",
        action="append",
        default=None,
        help="part-file name prefix to read (repeatable; default review- and invariant-)",
    )
    parser.add_argument(
        "--out", type=Path, default=None, help="defaults to <run-dir>/ledger-gate.json"
    )
    parser.add_argument(
        "--strict", action="store_true", help="exit 1 when gaps or violations exist"
    )
    ns = parser.parse_args(argv)

    prefixes = tuple(ns.prefix) if ns.prefix else ("review-", "invariant-", "sweep-", "second-")
    try:
        units_doc = _load_json(ns.run_dir / "units.json")
        parts = load_parts(ns.run_dir / "parts", prefixes)
        report = check(units_doc, parts)
    except LedgerError as exc:
        print(f"check_ledger: {exc}", file=sys.stderr)
        return 2

    out_path = ns.out or (ns.run_dir / "ledger-gate.json")
    out_path.write_text(json.dumps(report, indent=2), encoding="utf-8")
    print(json.dumps(_summary(report), indent=2))

    if ns.strict and (report["missing_rows"] or report["violations"]):
        print(
            f"check_ledger: {len(report['missing_rows'])} missing row(s), "
            f"{len(report['violations'])} violation(s)",
            file=sys.stderr,
        )
        return 1
    return 0


def _summary(report: dict[str, Any]) -> dict[str, Any]:
    """The compact form the workflow reads back; the full report stays on disk."""
    return {
        "checks_required": report["checks_required"],
        "checks_completed": report["checks_completed"],
        "checks_satisfied": report["checks_satisfied"],
        "coverage_pct": report["coverage_pct"],
        "answered_pct": report["answered_pct"],
        "units_total": report["units_total"],
        "verdict_counts": report["verdict_counts"],
        "missing_row_count": len(report["missing_rows"]),
        "violation_count": len(report["violations"]),
        "violation_kinds": sorted({v["kind"] for v in report["violations"]}),
        "unknown_units": report["unknown_units"][:10],
        "unverifiable_row_count": len(report["unverifiable_rows"]),
        "units_with_findings": report["units_with_findings"],
        "gap_units": sorted({row["unit_id"] for row in report["missing_rows"]})[:40],
    }


if __name__ == "__main__":
    raise SystemExit(main())
