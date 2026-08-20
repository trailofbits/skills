#!/usr/bin/env python3
# /// script
# requires-python = ">=3.11"
# # Exact pins — see enumerate_units.py's header for why; keep the four headers in step.
# dependencies = ["tree-sitter==0.26.0", "tree-sitter-c==0.24.2", "tree-sitter-cpp==0.23.4"]
# ///
"""Diff the review ledger against the code-generated unit list.

Coverage is measured against the parse, **never against the reviewer's own account of
what it reviewed**: validating the rows that are present rather than the rows that are
owed lets a fabricated or omitted row pass as clean.

Four rules, each from a measured failure recorded by the internal benchmark harness:

1. **A finding raises the prior; it never closes the unit.** A `finding` row still
   owes an account of the rest of its population.
2. **A verdict must account for a counted population.** `sites_accounted` must cover
   every site line `enumerate_units.py` counted for that question — for `needs-human`
   as much as for `clean`, or the escape hatch becomes the cheapest way to 100%. A row
   claiming clean over twelve write sites while citing none is a gate failure.
   The site lines are on disk NOWHERE while the review runs: a population the agent can
   read out of any file in the run directory is satisfiable by transcription, and a gate
   nothing in the source can falsify certifies a review that never opened a file.
   `attach_sites` recomputes them from the source at the moment this gate needs them, and
   `_bind_to_enumeration` refuses to score the run unless that recompute still agrees with
   the unit ids, question sets and site counts the enumerator recorded.
3. **Every owed row must exist.** Missing rows are reported as gaps, not inferred to
   be clean.
4. **A `finding` verdict must correspond to a filed finding.** Otherwise the verdict
   the second pass is dispatched from costs nothing to claim.

**What this gate claims, and what it does not.** It measures an HONEST reviewer: one that
skipped units, thinned its ledger, answered on evidence text alone, or hallucinated rows it
never earned is caught. A tree that moved under the review is caught only when the move
CHANGED A SITE COUNT — a count-preserving edit, a three-statement reorder, is invisible to
the binding and lands on the reviewer as violations instead. It is NOT a control
against an adversary. Every input it reads — `units.json`, the part files, the source tree
itself — is writable by the agents it scores, and there is nowhere in a run directory to
keep a secret from an agent that can read it, so a caller that edits the source and
`units.json` together into a smaller self-consistent pair passes. Scoping the producing
workers away from a shell (`agents/c-review-worker.md`, `WORKER_AGENT` in the workflow)
raises the cost of that; it does not remove it, and the assemble agent runs a command and
is trusted outright. Read a green gate as "no gap this could see", not as "not tampered
with".

Coverage is reported as checks completed / checks required, not functions touched: a
function can be touched while most of its questions go unanswered. `unquestioned_units`
is the denominator's blind spot — units whose parse counted no site owe no row at all,
so they are neither covered nor missing, and the count travels with the percentage.

Exit codes: 0 when the ledger was checked, 2 when there was nothing to check (no
units, or no ledger rows at all) or the inputs are unreadable, and — only under
`--strict` — 1 when the ledger has gaps or violations.

Run standalone this is a DIAGNOSTIC: it reads every `parts/*.json` whose name matches
`--prefix`, because it has no way to know which parts were dispatched. `assemble_findings.py`
does — the workflow passes it `--expect` — and it runs this same `check()` over that
allowlist, so the two can disagree about the same directory when a part nobody dispatched is
sitting in it. The assembler's `ledger-gate.json` is the authoritative one; `parts_read` in
this script's own summary is what makes the difference visible.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

# `attach_sites` imports enumerate_units from beside this file, and the standalone CLI is
# documented as runnable from anywhere.
sys.path.insert(0, str(Path(__file__).resolve().parent))

VALID_VERDICTS = frozenset({"clean", "finding", "needs-human", "not-applicable"})


class LedgerError(Exception):
    """Nothing to check, or the inputs are not a c-review run. Callers exit non-zero."""


def _load_json(path: Path) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise LedgerError(f"missing input: {path}") from exc
    except OSError as exc:
        # PermissionError and IsADirectoryError are OSErrors and neither is a
        # FileNotFoundError, so unhandled both escape as a traceback: the standalone gate
        # exits 1 — its own contract reserves 1 for `--strict` gaps — and the assembler
        # exits 2 with no artifacts at all.
        raise LedgerError(f"{path} cannot be read ({exc})") from exc
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        # `UnicodeDecodeError` is a ValueError, not an OSError, so one 0xFF byte in a part
        # file takes the same route out.
        raise LedgerError(f"{path} is not valid UTF-8 JSON ({exc})") from exc


def attach_sites(doc: dict[str, Any], sites: dict[str, Any] | None = None) -> dict[str, Any]:
    """Put each unit's site population back on it, in place, by REPARSING the source.

    The site lines are the answer key this gate diffs `sites_accounted` against, and nothing
    writes them to disk. Relocating them does not help — a worker with Read over the run
    directory does not care what a prompt names, so a ledger fabricated from whatever file
    holds them scores 100%. `enumerate_units` is deterministic over the source tree, so the
    populations are derived here rather than persisted, and the workers are scoped away from
    the shell that could re-derive them.

    The recompute is UNCONDITIONAL. Skipping any unit that already carries a `sites` mapping
    — nominally for hand-built fixtures — makes the answer key a per-unit opt-out written in
    the one file the agents can edit: `"sites": {"write": [<start_line>]}` buys 100% coverage
    over that unit without opening a source file. `sites` is the test injection seam instead;
    it is a Python argument, so no file in the run directory reaches it.

    Recomputing alone is not enough either, because `units.json` records no digest of the
    tree it was built from: a source rewrite between the review and this gate, with line
    counts preserved so the unit ids survive, shrinks the answer key, and a ledger accounting
    only the survivors scores 100%. `_bind_to_enumeration` narrows that to the case where
    `units.json` was edited to match — and does not close it. See its docstring, and the
    threat model at the top of this file.
    """
    units = [u for u in (doc.get("units") or []) if isinstance(u, dict)]
    if sites is None:
        try:
            import enumerate_units
        except ImportError as exc:  # pragma: no cover - depends on the interpreter's env
            raise LedgerError(
                f"the site populations are recomputed from the source and enumerate_units "
                f"could not be imported ({exc}). Coverage is unmeasured; it is not clean."
            ) from exc
        try:
            sites = enumerate_units.sites_by_id(doc)
        except enumerate_units.EnumerateError as exc:
            raise LedgerError(f"the site populations could not be recomputed: {exc}") from exc
        _bind_to_enumeration(units, sites)
    for unit in units:
        unit["sites"] = sites.get(str(unit.get("id")))
    return doc


def _bind_to_enumeration(units: list[dict[str, Any]], fresh: dict[str, Any]) -> None:
    """Fail unless the fresh parse still agrees with what `enumerate_units.py` recorded.

    `units.json` carries no digest of the tree, so a recompute on its own measures the tree
    as it is NOW, not the tree that was reviewed. It does carry three things the enumerator
    derived from the tree as it WAS — the unit id set, each unit's `required_questions`, and
    `site_counts` per question — and diffing those against the fresh parse is the binding.

    It fails the run rather than re-deriving silently, and the shapes it rejects are the
    same event from different angles:

    - **ids** — a unit deleted from `units.json` shrinks the denominator to nothing
      (`checks_required: 2` over a three-unit tree, `coverage_pct: 100.0`, exit 0) while the
      reparse in the same call computed all three.
    - **questions** — trimming `required_questions` removes rows from the denominator the
      same way, and the per-question record is trimmed with it so equality cannot see it.
    - **counts** — a source edit that thins a population without emptying it (12 write
      sites down to 3) keeps the question owed and is caught here.

    **What this does NOT catch, and why there is no fix for it in this file.** The binding
    is against numbers stored in `units.json`, which the reviewing agents can write; the
    source tree they are measured against is writable by them too. A caller that rewrites
    a function body to a stub, preserves its line span so the unit id survives, and edits
    the same unit's `required_questions`, `site_counts` and `totals.checks_required` to
    match, produces a self-consistent pair this cannot distinguish from a genuinely
    unquestioned unit. A recorded digest does not close it: `site_counts` is k and the line
    span is n, so anything published beside them strong enough to verify is strong enough to
    invert — the preimage search is C(n, k) — and any weaker scheme rests on the agent not
    owning the file. There is nowhere in a run directory to keep a secret from an agent that
    can read it, so the gate does not claim to be one. See "What the gate claims, and what
    it does not" in the plugin's `AGENTS.md`.

    A COUNT-PRESERVING source edit — a three-statement reorder — is invisible here for the
    same reason, and lands on the reviewer as `population-not-accounted` /
    `sites-outside-population` violations rather than as the source change it is. That is a
    known, accepted false charge; the alternative costs more than it buys.

    An honest source edit mid-run — a `make` step, a PoC edit, the user typing in the
    editor — lands here when it changes a count, and it should: coverage measured against a
    tree that moved is not coverage. It is reported as what it is rather than as reviewer
    violations.
    """
    doc_ids = {str(u.get("id") or "") for u in units}
    if doc_ids != set(fresh):
        missing = sorted(set(fresh) - doc_ids)[:5]
        extra = sorted(doc_ids - set(fresh))[:5]
        raise LedgerError(
            f"units.json lists {len(doc_ids)} unit(s) and re-deriving them from the source "
            f"now gives {len(fresh)}. The tree moved between the review and this gate, or "
            f"units.json was edited. "
            + (f"Not in units.json: {missing}. " if missing else "")
            + (f"Not in the source: {extra}. " if extra else "")
            + "Coverage cannot be measured against a partition that no longer exists; "
            "re-run enumerate_units.py and the review."
        )
    bad: list[str] = []
    known = set(QUESTION_SITE_KINDS)
    for unit in units:
        uid = str(unit.get("id") or "")
        populations = fresh[uid] if isinstance(fresh.get(uid), dict) else {}
        counted = {q: _site_lines(populations, QUESTION_SITE_KINDS[q]) for q in known}
        expected = {q for q, lines in counted.items() if lines}
        # `required_questions` is not necessarily a list — `_validate_units` reports that,
        # but it runs after this, and iterating a scalar here raises a TypeError out of the
        # gate. Anything that is not a list owes nothing, which mismatches and is refused.
        raw_questions = unit.get("required_questions")
        owed = (
            {q for q in raw_questions if isinstance(q, str)}
            if isinstance(raw_questions, list)
            else set()
        )
        if owed & known != expected:
            bad.append(
                f"{uid} owes {sorted(owed & known)} and the source now counts sites for "
                f"{sorted(expected)}"
            )
            continue
        counts = unit.get("site_counts")
        if expected and not isinstance(counts, dict):
            bad.append(f"{uid} carries no site_counts, so nothing pins its populations")
            continue
        for question in sorted(expected):
            if counts.get(question) != len(counted[question]):
                bad.append(
                    f"{uid}/{question}: units.json records {counts.get(question)!r} site "
                    f"line(s) and the source now holds {len(counted[question])}"
                )
    if bad:
        raise LedgerError(
            f"{len(bad)} unit/question population(s) no longer match what enumerate_units.py "
            f"recorded in units.json: "
            + "; ".join(bad[:10])
            + ("" if len(bad) <= 10 else f" … and {len(bad) - 10} more")
            + ". The source changed between the review and this gate, so the ledger was "
            "written against code that is no longer there. Re-run enumerate_units.py and "
            "the review; do not report coverage over it."
        )


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
    """(unit_id, question) -> the site lines that row must account for.

    `units` must already have been through `_validate_units`, so every entry has an `id`
    and a `sites` mapping. A question this gate does not know is still owed a row, but is
    flagged `unknown_question`: it cannot be checked for completeness, and a row that
    cannot be checked must not score as coverage (see `_row_violations`).
    """
    owed: dict[tuple[str, str], dict[str, Any]] = {}
    for unit in units:
        sites = unit["sites"]
        for question in unit.get("required_questions") or []:
            lines: set[int] = set()
            for kind, kind_lines in sites.items():
                if kind in QUESTION_SITE_KINDS.get(question, ()):
                    lines.update(kind_lines)
            owed[(unit["id"], question)] = {
                "unit_id": unit["id"],
                "file": unit.get("file", ""),
                "name": unit.get("name", ""),
                "question": question,
                "sites": sorted(lines),
                "unknown_question": question not in QUESTION_SITE_KINDS,
            }
    return owed


# Mirrors enumerate_units.QUESTIONS without importing it. NOT because this script has no
# dependencies — the PEP 723 header above declares tree-sitter and `attach_sites` imports
# enumerate_units on the main path — but so a question the enumerator adds is visibly
# unknown here rather than silently unchecked. A question present in units.json but absent
# here contributes an empty site set, so the row is still required; `_row_violations` files
# it as `unknown-question` instead of letting it pass on evidence text alone.
# `test_assemble_findings.py` holds the two tables against each other.
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


def _validate_units(units: list[Any]) -> None:
    """Every unit must be checkable. A malformed one is a broken input, not a clean row.

    `id` keys the whole gate, and a unit with no `sites` mapping has an EMPTY population
    for every question it owes — so every row over it passes on evidence text alone and
    the run scores 100%. The same one level down: a `sites` value that is not a list of ints
    either raises an uncaught `TypeError` out of `required_rows`, which destroys every
    artifact of a completed run, or once filtered silently empties the population. All of it
    is `LedgerError`, which the assembler reports rather than inferring coverage from an
    input it could not read.
    """
    bad = []
    for index, unit in enumerate(units):
        if not isinstance(unit, dict):
            bad.append(f"units[{index}] is {type(unit).__name__}, expected an object")
            continue
        if not unit.get("id"):
            bad.append(f"units[{index}] has no 'id'")
            continue
        questions = unit.get("required_questions") or []
        if not isinstance(questions, list) or not all(isinstance(q, str) for q in questions):
            # `required_rows` iterates this, and a scalar there escapes as a TypeError past
            # `run_ledger_gate`'s `except LedgerError`.
            bad.append(f"{unit['id']} has a malformed 'required_questions'")
            continue
        if len(set(questions)) != len(questions):
            # `totals.checks_required` is `sum(len(required_questions))` while `owed` is
            # keyed `(unit_id, question)`, so a duplicate collapses on one side only and
            # the denominator comparison above reads equal over a list it should not.
            bad.append(f"{unit['id']} lists a duplicate question in 'required_questions'")
            continue
        if not isinstance(unit.get("sites"), dict):
            # `attach_sites` assigns one to every unit and `_bind_to_enumeration` has
            # already refused any id the reparse did not reproduce, so reaching this means
            # `check()` was called without `attach_sites` — never from either shipped caller.
            bad.append(f"{unit['id']} has no 'sites' mapping; check() was not given a parse")
            continue
        for kind, lines in unit["sites"].items():
            if not isinstance(lines, list):
                bad.append(f"{unit['id']} sites.{kind} is {type(lines).__name__}, expected a list")
            elif not all(_is_int(n) for n in lines):
                bad.append(f"{unit['id']} sites.{kind} holds a non-integer line number")
        # A unit that owes rows but counts no site ANYWHERE is the one tamper shape the
        # guard above cannot see: it rejects a MISSING `sites` mapping, not an empty one, so
        # rewriting every unit to `{"sites": {}}` leaves `checks_required` at its real value
        # — that comes from `required_questions` — while every row passes on evidence text
        # alone. 100% coverage, zero violations, and nothing saying the population the rows
        # were diffed against was empty.
        #
        # Deliberately the union rather than per-question: a units.json from an older
        # enumerator legitimately owes a question whose own population is empty (this one
        # emits no such row), and rejecting those would refuse to check a run this is
        # documented to be able to check.
        if questions and not any(unit["sites"].values()):
            bad.append(
                f"{unit['id']} owes {len(questions)} question(s) and its sites mapping counts "
                f"no line at all, so every row over it would pass on evidence text alone"
            )
    if bad:
        raise LedgerError(
            f"{len(bad)} unit(s) in units.json cannot be checked: "
            + "; ".join(bad[:10])
            + ("" if len(bad) <= 10 else f" … and {len(bad) - 10} more")
            + ". Re-run enumerate_units.py; do not report coverage over a unit list "
            "this gate could not read."
        )


def check(units_doc: dict[str, Any], parts: list[tuple[str, dict[str, Any]]]) -> dict[str, Any]:
    units = units_doc.get("units") or []
    if not units:
        raise LedgerError(
            "units.json lists no units. There is nothing to check, which is not the "
            "same as a review with no gaps."
        )
    _validate_units(units)
    unit_by_id = {u["id"]: u for u in units}
    owed = required_rows(units)
    if not owed:
        raise LedgerError(
            f"{len(units)} unit(s) but no required questions. Either the parse counted "
            f"no sites anywhere, or units.json predates the question set."
        )
    # The denominator the ENUMERATOR recorded when it generated the partition, against the
    # one this gate derives from the same file now. Unrecorded, a `checks_required` that
    # shrinks between the review and the gate — 10 to 6 on the measured case — leaves no
    # trace in any artifact: the number is read exactly once, from this gate, and 6 of 6
    # satisfied reads identically to 10 of 10.
    recorded = (units_doc.get("totals") or {}).get("checks_required")
    if not _is_int(recorded):
        # Fail closed. `if _is_int(recorded) and …` makes the denominator check an opt-out:
        # deleting the key, or making it the STRING "18", skips the comparison entirely
        # while `ledger-gate.json` records `checks_required: len(owed)` either way, so
        # "checked and equal" and "never checked" are byte-identical to every reader.
        raise LedgerError(
            f"units.json records totals.checks_required as {recorded!r}; the gate needs the "
            f"integer the enumerator wrote there to tell a partition that was edited after "
            f"generation from one that was not. Re-run enumerate_units.py."
        )
    if recorded != len(owed):
        raise LedgerError(
            f"units.json records {recorded} required check(s) and the unit list in the same "
            f"file now owes {len(owed)}. The partition was edited after it was generated, "
            f"so the denominator this coverage would be measured against is not the one the "
            f"review was dispatched from. Re-run enumerate_units.py and the review."
        )

    # Collect first, judge afterwards, so the verdict does not depend on the order part
    # files are read and a later, fuller row can supersede an earlier thin one.
    candidates: dict[tuple[str, str], list[dict[str, Any]]] = {}
    # Every path in the unit list, and the extensions those paths use, so a row filed under
    # a bare source path is not excused as a sweep row. Derived from the unit list rather
    # than from a hard-coded extension table: this file already mirrors the enumerator's
    # question set by hand and a second copied table is a second thing to drift.
    unit_files = {str(u.get("file") or "") for u in units}
    source_suffixes = tuple(sorted({Path(f).suffix for f in unit_files if Path(f).suffix}))
    # One entry per ROW, not per distinct (part, id) pair: the report calls these numbers
    # "ledger row(s)", and deduplicating them makes one agent's whole bad ledger — 14 rows
    # naming the same invented id — read as a single row. `_summary` dedups for the SAMPLE.
    unknown_units: list[str] = []
    unverifiable: list[str] = []
    # A part field or row the gate could not read. Recorded rather than raised: `x or []`
    # accepts any non-empty non-iterable, so ONE `"sites_accounted": 7` used to escape as
    # `TypeError: 'int' object is not iterable` and take every other agent's complete
    # coverage with it — 427 satisfied checks discarded over one scalar, with the message
    # naming neither the part nor the row. This is the same trade `assemble_findings._seq`
    # makes on the same bytes. Dropping in silence would be worse than the crash, so these
    # fail the gate in `gate_failure` and under `--strict`.
    malformed: list[str] = []
    findings_by_unit: dict[str, int] = {}
    rows_total = 0

    for part_id, doc in parts:
        findings = doc.get("findings")
        if findings is not None and not isinstance(findings, list):
            malformed.append(f"{part_id}.findings is {type(findings).__name__}, not a list")
            findings = None
        for index, finding in enumerate(findings or []):
            if not isinstance(finding, dict):
                malformed.append(f"{part_id}.findings[{index}] is not an object")
                continue
            uid = str(finding.get("unit_id") or "")
            if uid:
                findings_by_unit[uid] = findings_by_unit.get(uid, 0) + 1
        ledger = doc.get("ledger")
        if ledger is not None and not isinstance(ledger, list):
            malformed.append(f"{part_id}.ledger is {type(ledger).__name__}, not a list")
            ledger = None
        for index, row in enumerate(ledger or []):
            rows_total += 1
            if not isinstance(row, dict):
                malformed.append(f"{part_id}.ledger[{index}] is not an object")
                continue
            accounted = row.get("sites_accounted")
            if accounted is not None and not isinstance(accounted, list):
                # Left to fall through with an EMPTY population rather than skipped: the
                # row still owes its sites, so it also earns a real
                # `population-not-accounted` violation instead of quietly disappearing.
                malformed.append(
                    f"{part_id}.ledger[{index}].sites_accounted is "
                    f"{type(accounted).__name__}, not a list"
                )
            uid = str(row.get("unit_id") or "")
            question = str(row.get("question") or "")
            key = (uid, question)
            if uid not in unit_by_id:
                # A sweep row is outside the generated unit list BY DESIGN: the class
                # sweep files under `(sweep)` and the invariant audit under
                # `struct.field`. Lumping those in with genuinely unmappable ids reports
                # expected rows as errors and hides that sweep coverage is not verifiable
                # against a parse at all. Separate them and say so — but only for the two
                # shapes that are actually expected, because the carve-out is what hides a
                # whole agent's rows behind a count. `unit-01` is an ASSIGNMENT id, and
                # writing one into `unit_id` is the natural mistake the naming invites; a
                # bare SOURCE PATH is the same mistake with the same shape, since `src/a.c`
                # has a dot and no colon and is the value sitting in the unit's own `file`
                # field. The invariant audit's ids are `struct.field`: no slash, no path the
                # unit list names, and no source extension.
                if uid == "(sweep)" or (
                    "." in uid
                    and ":" not in uid
                    and "/" not in uid
                    and uid not in unit_files
                    and not uid.endswith(source_suffixes)
                ):
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
                    "accounted": sorted({int(n) for n in (accounted or []) if _is_int(n)})
                    if isinstance(accounted, list)
                    else [],
                    "evidence": str(row.get("evidence") or ""),
                }
            )

    # Rule 4: a `finding` row must correspond to a filed finding in the same unit. The
    # verdict is otherwise held to exactly the same bar as `clean`, so an agent can mark
    # every row `finding` — which is what the second pass is dispatched from — while
    # filing nothing at all.
    for owed_row in owed.values():
        owed_row["unit_findings"] = findings_by_unit.get(owed_row["unit_id"], 0)

    seen: dict[tuple[str, str], dict[str, Any]] = {}
    violations: list[dict[str, Any]] = []
    for key in sorted(candidates):
        rows = candidates[key]
        # Two parts may answer the same row — a sweep agent can land on a unit a review
        # agent owns. Take the best answer, not the last one: a row that satisfies the gate
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

    # Without `sites`. `ledger-gate.json` is written into the run directory every agent can
    # read, and `missing_rows` is precisely the set a second pass is dispatched to fill —
    # publishing the owed lines there hands that pass its own answers, which is the same
    # transcription the assignment files were stripped to prevent. The count is what a
    # reader needs; the lines the second pass has to go and find, like the first one.
    missing_rows = [
        {
            **{k: v for k, v in owed[key].items() if k != "sites"},
            "site_count": len(owed[key]["sites"]),
        }
        for key in sorted(owed)
        if key not in seen
    ]
    completed = len(owed) - len(missing_rows)
    # A row that was answered but whose answer the gate rejected is NOT coverage:
    # counting it would report full coverage while carrying violations, which is a gate
    # that logs and passes.
    violated_keys = {(v["unit_id"], v["question"]) for v in violations}
    satisfied = len([key for key in owed if key in seen and key not in violated_keys])
    verdict_counts: dict[str, int] = {}
    for entry in seen.values():
        verdict_counts[entry["verdict"]] = verdict_counts.get(entry["verdict"], 0) + 1

    # A unit whose parse counted no site owes NO row, so it is absent from `owed` and
    # invisible in `coverage_pct` — 100% means 100% of the questions asked, over the
    # units that were asked anything. On real trees that is a quarter of the lines (every
    # header: struct layouts, array dimensions, constants). Reported, because a coverage
    # number whose denominator silently excludes a quarter of the code reads identically
    # to full coverage.
    unquestioned = [u for u in units if not (u.get("required_questions") or [])]
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
        "unknown_units": unknown_units,
        "unverifiable_rows": unverifiable,
        "malformed_rows": malformed,
        "units_with_findings": [
            {
                "unit_id": uid,
                # `.get`, not `[…]`: a sparse units.json would raise KeyError past the
                # assembler's `except LedgerError` and destroy a completed run's artifacts
                # over a display field.
                "file": unit_by_id[uid].get("file", ""),
                "name": unit_by_id[uid].get("name", ""),
                "start_line": unit_by_id[uid].get("start_line"),
                "end_line": unit_by_id[uid].get("end_line"),
                "findings": findings_by_unit[uid],
            }
            for uid in units_with_findings
            if uid in unit_by_id
        ],
        "units_total": len(units),
        "unquestioned_units": sorted(u["id"] for u in unquestioned),
        "unquestioned_lines": sum(_int(u.get("lines")) for u in unquestioned),
        "lines_total": sum(_int(u.get("lines")) for u in units),
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
    if owed_row.get("unknown_question"):
        # An id this gate has no site kinds for has an EMPTY owed population, so the row
        # passes on evidence text alone and scores as coverage. A rename in
        # `enumerate_units.QUESTIONS` would silently disable checking for that question
        # across the whole run. It is a violation, so it is counted and named.
        return [
            _violation(
                owed_row,
                part_id,
                "unknown-question",
                f"question {owed_row['question']!r} is not in this gate's question set, "
                f"so its site population cannot be checked",
            )
        ]

    out: list[dict[str, Any]] = []
    if verdict == "not-applicable" and expected:
        out.append(
            _violation(
                owed_row,
                part_id,
                "not-applicable-with-population",
                f"{len(expected)} site(s) were counted here, so the question applies",
            )
        )

    # `needs-human` is a legitimate answer, but it is not a cheaper one: it owes the same
    # account of the population as `clean`. Held to any weaker bar it becomes the cheapest
    # route to 100% coverage — name one site of twelve, or none, and the row still counts
    # at full weight over a population nobody looked at. The reviewer that cannot resolve
    # the question still knows which sites it could not resolve.
    if verdict in ("clean", "finding", "needs-human"):
        missing = sorted(expected - accounted)
        if missing:
            out.append(
                _violation(
                    owed_row,
                    part_id,
                    "population-not-accounted",
                    # The count, never the lines. This report lands in the run directory a
                    # second pass reads, and naming the unaccounted lines there is the
                    # answer key for exactly the rows that pass exists to redo.
                    f"verdict {verdict} but {len(missing)} of {len(expected)} site "
                    f"line(s) are unaccounted",
                )
            )
        stray = sorted(accounted - expected)
        if stray:
            out.append(
                _violation(
                    owed_row,
                    part_id,
                    "sites-outside-population",
                    # The count, never the lines — for the same reason as its sibling above,
                    # and more sharply. This one names the accounted lines that are NOT in
                    # the population, so a row claiming every line of its unit got the
                    # COMPLEMENT back verbatim in `ledger-gate.json`, which is the exact
                    # population three documents say no file the run writes holds.
                    f"verdict {verdict} but {len(stray)} of the {len(accounted)} accounted "
                    f"line(s) are not sites this question counts in this unit",
                )
            )
    if verdict == "finding" and not owed_row.get("unit_findings"):
        out.append(
            _violation(
                owed_row,
                part_id,
                "finding-verdict-with-no-finding",
                "verdict finding, but no finding was filed against this unit",
            )
        )
    if not row["evidence"].strip():
        out.append(_violation(owed_row, part_id, "no-evidence", "evidence is empty"))
    return out


def _is_int(value: Any) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)


def _site_lines(populations: Any, kinds: tuple[str, ...]) -> set[int]:
    """The line numbers one question's site kinds contribute. Never raises.

    Tolerant of a malformed `populations` because `_bind_to_enumeration` runs BEFORE
    `_validate_units`, so a `sites` value that is not a list of ints reaches here before
    anything has rejected it.
    """
    out: set[int] = set()
    if not isinstance(populations, dict):
        return out
    for kind in kinds:
        lines = populations.get(kind)
        if isinstance(lines, list):
            out.update(n for n in lines if _is_int(n))
    return out


def _int(value: Any) -> int:
    """A display integer, or 0. `int("forty")` escapes as a ValueError past
    `run_ledger_gate`'s `except LedgerError`, destroying a completed run's artifacts over a
    line-count field nothing in the verdict depends on."""
    try:
        return int(value or 0)
    except (TypeError, ValueError):
        return 0


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

    # No `second-`: no phase writes one any more. This gate has no `--expect` allowlist, so
    # a `second-*.json` left in a reused run directory would have its ledger rows counted as
    # this run's coverage.
    prefixes = tuple(ns.prefix) if ns.prefix else ("review-", "invariant-", "sweep-")
    try:
        units_doc = _load_json(ns.run_dir / "units.json")
        if not isinstance(units_doc, dict):
            raise LedgerError(
                f"{ns.run_dir / 'units.json'}: expected a JSON object, "
                f"got {type(units_doc).__name__}"
            )
        parts = load_parts(ns.run_dir / "parts", prefixes)
        report = check(attach_sites(units_doc), parts)
    except LedgerError as exc:
        print(f"check_ledger: {exc}", file=sys.stderr)
        return 2
    except Exception as exc:  # noqa: BLE001
        # Exit 1 is reserved for `--strict` gaps, so an uncaught traceback — which exits 1 —
        # tells the caller the ledger was checked and found wanting. Anything that is not a
        # LedgerError is an input this gate could not read, which is a 2.
        print(
            f"check_ledger: unexpected {type(exc).__name__}: {exc}. The ledger was NOT "
            f"checked; coverage is unmeasured, not clean.",
            file=sys.stderr,
        )
        return 2

    out_path = ns.out or (ns.run_dir / "ledger-gate.json")
    out_path.write_text(json.dumps(report, indent=2), encoding="utf-8")
    print(json.dumps(_summary(report), indent=2))

    # `unknown_units` and `malformed_rows` are in this condition for the same reason
    # `generate_sarif.lost_work` already counts them: a row naming a unit id the parse never
    # produced is a row nothing can verify. Without them a ledger of 40 rows over invented
    # ids scored 100% coverage, 0 violations and exit 0 while REPORT.sarif recorded
    # `executionSuccessful: false` on the same run.
    if ns.strict and (
        report["missing_rows"]
        or report["violations"]
        or report["unknown_units"]
        or report["malformed_rows"]
    ):
        print(
            f"check_ledger: {len(report['missing_rows'])} missing row(s), "
            f"{len(report['violations'])} violation(s), "
            f"{len(report['unknown_units'])} row(s) naming an unknown unit, "
            f"{len(report['malformed_rows'])} unreadable field(s)",
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
        # The denominator's blind spot, in the same object as the coverage number, so
        # nothing downstream can print one without the other.
        "unquestioned_unit_count": len(report["unquestioned_units"]),
        "unquestioned_lines": report["unquestioned_lines"],
        "lines_total": report["lines_total"],
        "verdict_counts": report["verdict_counts"],
        "missing_row_count": len(report["missing_rows"]),
        "violation_count": len(report["violations"]),
        "violation_kinds": sorted({v["kind"] for v in report["violations"]}),
        # The list is truncated, so the COUNT has to travel with it: without a count key
        # `findings_model` falls back to the sample length and reports 25 fabricated unit
        # ids as 10. The SAMPLE is the distinct ids; the count is rows, which is the noun
        # the report prints.
        "unknown_units": sorted(set(report["unknown_units"]))[:10],
        "unknown_unit_count": len(report["unknown_units"]),
        "unverifiable_row_count": len(report["unverifiable_rows"]),
        "malformed_rows": sorted(set(report["malformed_rows"]))[:10],
        "malformed_row_count": len(report["malformed_rows"]),
        # Which part files this gate actually read. The standalone CLI globs by PREFIX while
        # the assembler reads only the parts the workflow dispatched, so the same run
        # directory can be exit 1 "zero ledger rows" through one and 100% through the other.
        # Printing the list is what makes that visible to whoever runs the standalone gate.
        "parts_read": report["parts_read"],
        "units_with_findings": report["units_with_findings"],
        "gap_units": sorted({row["unit_id"] for row in report["missing_rows"]})[:40],
    }


if __name__ == "__main__":
    raise SystemExit(main())
