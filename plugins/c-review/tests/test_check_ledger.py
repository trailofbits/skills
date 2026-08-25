#!/usr/bin/env python3
"""Tests for the ledger gate.

The gate exists to refuse to certify a review it cannot check, so the tests that
carry the weight here are the rejections: one fixture per violation kind, and one
per zero-item guard. A suite that only proved a good ledger passes would still be
green if every checker inside `check()` were deleted.
"""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "scripts"))

from check_ledger import (  # noqa: E402
    LedgerError,
    _summary,
    attach_sites,
    check,
    load_parts,
    main,
)

PREFIXES = ("review-", "invariant-", "sweep-")
UID = "src/parse.c:1-40"
WRITES = [10, 20, 30]
CONVERSIONS = [15]
SUMMARY_KEYS = {
    "checks_required",
    "checks_completed",
    "checks_satisfied",
    "coverage_pct",
    "answered_pct",
    "unverifiable_row_count",
    "units_total",
    "verdict_counts",
    "missing_row_count",
    "violation_count",
    "violation_kinds",
    "unknown_units",
    "unknown_unit_count",
    "malformed_rows",
    "malformed_row_count",
    "parts_read",
    "units_with_findings",
    "gap_units",
    "unquestioned_unit_count",
    "unquestioned_lines",
    "lines_total",
}


def unit(**overrides):
    base = {
        "id": UID,
        "file": "src/parse.c",
        "name": "parse_header",
        "start_line": 1,
        "end_line": 40,
        # 15 is a conversion site, not a write site: it belongs to "integer"'s
        # population and is outside "bounds"'s.
        "sites": {"write": list(WRITES), "conversion": list(CONVERSIONS)},
        "required_questions": ["bounds", "integer"],
        # What `enumerate_units.assignment_unit` persists about the parse. The gate diffs
        # the fresh populations against it; a real units.json never carries `sites`.
        "site_counts": {"bounds": len(WRITES), "integer": len(CONVERSIONS)},
    }
    base.update(overrides)
    return base


def fixture_sites(units_doc):
    """The populations a real reparse would produce, keyed by id.

    `attach_sites(doc, sites=…)` is the INJECTION SEAM, and it is a Python argument on
    purpose: `units.json` sits in a run directory every worker agent can write, so a `sites`
    key in that file switching the reparse off per unit would be an answer-key opt-out the
    graded agent controls. Fixtures reach the seam; nothing on disk can.
    """
    return {
        str(u.get("id")): u.get("sites")
        for u in units_doc.get("units") or []
        if isinstance(u, dict) and isinstance(u.get("sites"), dict)
    }


@pytest.fixture(autouse=True)
def _reparse_returns_the_fixture(monkeypatch):
    """Stand in for the tree-sitter parse for the tests that go through `main`.

    `enumerate_units` imports tree-sitter lazily and this interpreter does not have it, so
    the production reparse cannot run here. Patching `sites_by_id` rather than
    `attach_sites` keeps `_bind_to_enumeration` in the path: every fixture below is checked
    against its own `site_counts` exactly as a real run is against the enumerator's.
    A real enumerate → gate round trip, and the tamper shapes it rejects, are in
    `test_enumerate_units.py`, which runs under `uv run` and can parse.
    """
    import enumerate_units

    def fake(units_doc):
        return fixture_sites(units_doc)

    monkeypatch.setattr(enumerate_units, "sites_by_id", fake)


def row(question="bounds", verdict="clean", accounted=None, evidence="bounded by n", unit_id=UID):
    if accounted is None:
        accounted = WRITES if question == "bounds" else CONVERSIONS
    return {
        "unit_id": unit_id,
        "question": question,
        "verdict": verdict,
        "sites_accounted": list(accounted),
        "evidence": evidence,
    }


def ledger(*rows, part="review-1", **extra):
    return {part: {"ledger": list(rows), **extra}}


def default_parts():
    return ledger(row(), row(question="integer"))


def owed_total(units):
    """`totals.checks_required` as the enumerator writes it. Tolerant: the malformed-unit
    fixtures below are exactly the ones that must reach their own error message."""
    total = 0
    for u in units:
        questions = u.get("required_questions") if isinstance(u, dict) else None
        if isinstance(questions, list):
            total += len(questions)
    return total


def build(run_dir, units=None, parts=None, *, units_text=None, write_units=True, parts_dir=True):
    """A run directory: units.json plus parts/<name>.json for each part given."""
    run_dir = Path(run_dir)
    run_dir.mkdir(parents=True, exist_ok=True)
    if write_units:
        if units_text is None:
            unit_list = [unit()] if units is None else units
            # `totals.checks_required` is REQUIRED by the gate — it fails closed on a
            # missing or non-integer value — so every fixture carries the number the
            # enumerator would have written for it.
            units_text = json.dumps(
                {"units": unit_list, "totals": {"checks_required": owed_total(unit_list)}}
            )
        (run_dir / "units.json").write_text(units_text, encoding="utf-8")
    if parts_dir:
        pdir = run_dir / "parts"
        pdir.mkdir(exist_ok=True)
        for name, doc in (default_parts() if parts is None else parts).items():
            (pdir / f"{name}.json").write_text(json.dumps(doc), encoding="utf-8")
    return run_dir


def report(run_dir, *, bind=True):
    """Through `attach_sites`, exactly as both callers reach `check()`.

    `attach_sites` is the whole mechanism that keeps the site populations off disk, so a
    helper reading units.json straight into `check()` would leave it with no coverage from
    this file at all.

    `bind=True` takes the `sites is None` path, so the autouse `sites_by_id` patch supplies
    the parse and `_bind_to_enumeration` runs over it: every fixture below is checked
    against its own `site_counts` exactly as a real run is. Passing `sites=` instead skips
    the binding entirely. `bind=False` is for the malformed-unit fixtures whose whole point
    is the message `_validate_units` produces, which the binding would pre-empt with a less
    specific one.
    """
    units_doc = json.loads((Path(run_dir) / "units.json").read_text(encoding="utf-8"))
    attached = (
        attach_sites(units_doc) if bind else attach_sites(units_doc, sites=fixture_sites(units_doc))
    )
    return check(attached, load_parts(Path(run_dir) / "parts", PREFIXES))


def kinds(run_dir):
    return sorted({v["kind"] for v in report(run_dir)["violations"]})


# ------------------------------------------------------------------ happy path


def test_fully_accounted_ledger_is_100_percent_with_no_violations(tmp_path):
    rep = report(build(tmp_path / "run"))
    assert rep["checks_required"] == 2
    assert rep["checks_completed"] == 2
    assert rep["coverage_pct"] == 100.0
    assert rep["violations"] == []
    assert rep["missing_rows"] == []
    assert rep["verdict_counts"] == {"clean": 2}


def test_all_three_part_prefixes_are_read(tmp_path):
    parts = {
        "review-1": {"ledger": [row()]},
        "invariant-1": {"ledger": [row(question="integer")]},
        "sweep-1": {"ledger": []},
    }
    rep = report(build(tmp_path / "run", parts=parts))
    assert rep["parts_read"] == ["invariant-1", "review-1", "sweep-1"]
    assert rep["checks_completed"] == 2


def test_a_part_from_the_removed_second_pass_grants_no_coverage(tmp_path, capsys):
    """`second-` stayed in the default prefix list after the second review pass was removed
    from the workflow, so no phase writes one any more. This gate has no `--expect`
    allowlist — unlike the assembler — so a `second-*.json` left behind in a reused run
    directory had its rows counted as THIS run's coverage, clearing (unit, question) cells
    nothing in this run ever looked at.

    Through `main` on purpose: `report()` above passes this file's own `PREFIXES`, so a test
    written against it would pin the fixture and leave the CLI default free to say anything.
    """
    parts = {
        "review-1": {"ledger": [row()]},
        "second-1": {"ledger": [row(question="integer")]},
    }
    run = build(tmp_path / "run", parts=parts)
    assert main(["--run-dir", str(run), "--strict"]) == 1
    summary = json.loads(capsys.readouterr().out)
    assert summary["parts_read"] == ["review-1"]
    assert summary["checks_completed"] == 1
    # And it is still reachable when a caller asks for it by name.
    assert main(["--run-dir", str(run), "--prefix", "review-", "--prefix", "second-"]) == 0
    assert json.loads(capsys.readouterr().out)["checks_completed"] == 2


# ------------------------------------------------------------------ violations


@pytest.mark.parametrize("verdict", ["clean", "finding"])
def test_unaccounted_population_is_a_violation(tmp_path, verdict):
    bad = build(tmp_path / "bad", parts=ledger(row(verdict=verdict, accounted=[10, 20])))
    assert "population-not-accounted" in kinds(bad)
    detail = report(bad)["violations"][0]
    assert detail["question"] == "bounds"
    assert detail["unit_id"] == UID
    assert "1 of 3 site line(s) are unaccounted" in detail["detail"]
    # And the detail does NOT name them. `ledger-gate.json` lands in the run directory a
    # second pass reads, so the unaccounted lines there would be that pass's answer key.
    assert "30" not in detail["detail"]
    assert "population-not-accounted" not in kinds(build(tmp_path / "good"))


def test_a_finding_never_closes_the_unit_rule_1(tmp_path):
    # The measured regression this gate exists to prevent: an agent files a bug on one
    # write site and stops. A finding does not close the unit — the other two counted
    # sites are still owed an account.
    bad = build(
        tmp_path / "bad",
        parts=ledger(
            row(verdict="finding", accounted=[20], evidence="overflow at 20"),
            findings=[{"unit_id": UID, "title": "overflow"}],
        ),
    )
    rep = report(bad)
    assert [v["kind"] for v in rep["violations"]] == ["population-not-accounted"]
    assert "2 of 3 site line(s) are unaccounted" in rep["violations"][0]["detail"]
    assert "10" not in rep["violations"][0]["detail"]
    # It is still recorded as answered, so the gap shows up as a violation and not
    # as a missing row.
    assert rep["checks_completed"] == 1
    assert "population-not-accounted" not in kinds(build(tmp_path / "good"))


def test_accounting_a_line_outside_the_population_is_a_violation(tmp_path):
    # 15 is a real site line in this unit, but it is a conversion, so it is not part
    # of what "bounds" counts. Citing it cannot discharge a write site.
    bad = build(tmp_path / "bad", parts=ledger(row(accounted=WRITES + [15])))
    assert kinds(bad) == ["sites-outside-population"]
    detail = report(bad)["violations"][0]["detail"]
    assert "1 of the 4 accounted line(s)" in detail
    assert "15" not in detail
    assert "sites-outside-population" not in kinds(build(tmp_path / "good"))


def test_the_gate_report_never_publishes_the_site_population_by_complement(tmp_path):
    """`ledger-gate.json` lands in the run directory every agent can read.

    `sites-outside-population` names the accounted lines that are NOT in the population, so
    a row claiming every line of its unit got the COMPLEMENT back verbatim — subtract it
    from what you claimed and you have the exact answer key, which SKILL.md, README.md and
    this module's own sibling violation each say no file the run writes holds. Both
    violations are count-only for that reason; printing `stray[:12]` would defeat it.
    """
    every_line = list(range(1, 41))
    bad = build(tmp_path / "bad", parts=ledger(row(accounted=every_line)))
    assert kinds(bad) == ["sites-outside-population"]
    detail = report(bad)["violations"][0]["detail"]
    # The only integers in the message are the two COUNTS. Recovering the population from
    # `{1..40} - stray` needs the stray lines, and they are nowhere in the report.
    numbers = {int(n) for n in re.findall(r"\d+", detail)}
    assert numbers == {len(every_line) - len(WRITES), len(every_line)}, detail
    assert "[" not in detail


def test_not_applicable_over_a_non_empty_population_is_a_violation(tmp_path):
    bad = build(tmp_path / "bad", parts=ledger(row(verdict="not-applicable", accounted=[])))
    assert kinds(bad) == ["not-applicable-with-population"]
    assert "3 site(s) were counted here" in report(bad)["violations"][0]["detail"]
    assert "not-applicable-with-population" not in kinds(build(tmp_path / "good"))


def test_not_applicable_over_an_empty_population_still_owes_evidence(tmp_path):
    """An empty owed population is the one row nothing in the source can falsify.

    `_row_violations` must not return early for `not-applicable` and skip the evidence
    check: `{"verdict": "not-applicable", "sites_accounted": [], "evidence": ""}` would be
    a free `checks_satisfied` — a verdict and nothing else.
    """
    # `bind=False`: `required_questions` only ever lists questions with a NON-EMPTY
    # population (`enumerate_units.required_questions`), so a real units.json cannot owe
    # `bounds` over zero write sites and `_bind_to_enumeration` refuses the shape outright.
    # The row rule below still has to hold for a hand-built or older unit list.
    units = [unit(sites={"write": [], "conversion": list(CONVERSIONS)})]
    free = ledger(row(verdict="not-applicable", accounted=[], evidence=""), row(question="integer"))
    free_run = build(tmp_path / "free", units=units, parts=free)
    assert sorted({v["kind"] for v in report(free_run, bind=False)["violations"]}) == [
        "no-evidence"
    ]

    answered = ledger(
        row(verdict="not-applicable", accounted=[], evidence="no write in this unit"),
        row(question="integer"),
    )
    rep = report(build(tmp_path / "run", units=units, parts=answered), bind=False)
    assert rep["violations"] == []
    assert rep["coverage_pct"] == 100.0


@pytest.mark.parametrize("evidence", ["", "   "])
def test_empty_evidence_is_a_violation(tmp_path, evidence):
    bad = build(tmp_path / "bad", parts=ledger(row(evidence=evidence)))
    assert kinds(bad) == ["no-evidence"]
    assert "no-evidence" not in kinds(build(tmp_path / "good"))


def test_unrecognised_verdict_is_a_violation(tmp_path):
    bad = build(tmp_path / "bad", parts=ledger(row(verdict="probably-fine")))
    assert kinds(bad) == ["invalid-verdict"]
    assert "'probably-fine'" in report(bad)["violations"][0]["detail"]
    assert "invalid-verdict" not in kinds(build(tmp_path / "good"))


# ------------------------------------------------------------------ accounting


def test_an_omitted_row_is_a_gap_and_is_never_counted_as_covered(tmp_path, capsys):
    run = build(tmp_path / "run", parts=ledger(row()))  # "integer" never answered
    rep = report(run)
    assert rep["checks_required"] == 2
    assert rep["checks_completed"] == 1
    assert rep["coverage_pct"] == 50.0
    assert [(r["unit_id"], r["question"]) for r in rep["missing_rows"]] == [(UID, "integer")]
    # The COUNT, never the lines: `missing_rows` is exactly the set a second pass is
    # dispatched to fill, and it is written to `ledger-gate.json` in a directory every
    # agent can read.
    assert rep["missing_rows"][0]["site_count"] == len(CONVERSIONS)
    assert "sites" not in rep["missing_rows"][0]
    assert str(CONVERSIONS[0]) not in json.dumps(rep["missing_rows"])
    # The omitted row is a gap, not a silent clean.
    assert rep["verdict_counts"] == {"clean": 1}
    assert rep["violations"] == []
    assert main(["--run-dir", str(run)]) == 0
    assert json.loads(capsys.readouterr().out)["gap_units"] == [UID]


def test_duplicate_rows_keep_the_fuller_account_and_count_once(tmp_path):
    partial = row(verdict="needs-human", accounted=[10], evidence="only site 10 reasoned about")
    full = row()
    for name, first, second in [("fuller-second", partial, full), ("fuller-first", full, partial)]:
        parts = {"review-a": {"ledger": [first]}, "review-b": {"ledger": [second]}}
        parts["review-a"]["ledger"].append(row(question="integer"))
        rep = report(build(tmp_path / name, parts=parts))
        assert rep["rows_seen"] == 3
        assert rep["checks_completed"] == 2, name
        assert rep["verdict_counts"] == {"clean": 2}, name
        assert rep["violations"] == [], name


def test_a_later_part_that_fills_the_population_clears_the_violation(tmp_path):
    # `check()` collects every candidate row and scores them before judging any, so the
    # violation a thin row appends is retracted when a fuller row supersedes it. Judging as
    # it goes makes identical ledger content give two verdicts depending on the alphabetical
    # order of part filenames — and thin-first is the ordering a sweep covering a unit a
    # reviewer only partly answered produces, so under --strict it could never clear the gate
    # it exists to clear. Both orderings below must stay clean; if one goes red,
    # judge-as-you-go is back.
    thin = row(verdict="finding", accounted=[20], evidence="overflow at 20")
    full = row(evidence="all three writes bounded")
    orderings = {
        "thin-first": {"review-1": {"ledger": [thin]}, "sweep-1": {"ledger": [full]}},
        "full-first": {"review-1": {"ledger": [full]}, "sweep-1": {"ledger": [thin]}},
    }
    seen_kinds = {}
    for name, parts in orderings.items():
        parts["review-1"]["ledger"].append(row(question="integer"))
        rep = report(build(tmp_path / name, parts=parts))
        assert rep["checks_completed"] == 2, name
        seen_kinds[name] = [v["kind"] for v in rep["violations"]]
    assert seen_kinds["thin-first"] == seen_kinds["full-first"] == []


def test_rows_for_unknown_units_do_not_count_toward_completion(tmp_path):
    parts = ledger(row(unit_id="src/ghost.c:1-9"), row(question="integer", unit_id=""))
    rep = report(build(tmp_path / "run", parts=parts))
    assert sorted(rep["unknown_units"]) == ["review-1: (blank)", "review-1: src/ghost.c:1-9"]
    assert rep["rows_seen"] == 2
    assert rep["checks_completed"] == 0
    assert rep["coverage_pct"] == 0.0
    assert len(rep["missing_rows"]) == 2


def test_unknown_and_unverifiable_counts_are_rows_not_distinct_ids(tmp_path):
    """Both numbers are printed as "N ledger row(s)" by `findings_model.ledger_warnings`.

    Deduplicating them with `sorted(set(...))` reports one agent's whole bad ledger — every
    row naming the same invented id — as ONE row. The sample stays deduplicated; the count
    is rows, which is the noun the artifacts use.
    """
    rows = [row(unit_id="unit-01"), row(question="integer", unit_id="unit-01")]
    rep = report(build(tmp_path / "unknown", parts=ledger(*rows)))
    assert len(rep["unknown_units"]) == 2
    summary = _summary(rep)
    assert summary["unknown_unit_count"] == 2
    assert summary["unknown_units"] == ["review-1: unit-01"]

    sweeps = [row(unit_id="cfg.window"), row(question="integer", unit_id="cfg.window")]
    swept = report(build(tmp_path / "sweep", parts=ledger(*sweeps)))
    assert _summary(swept)["unverifiable_row_count"] == 2


def test_a_row_filed_under_a_bare_source_path_is_unknown_not_unverifiable(tmp_path):
    """`unverifiable_rows` is "the class sweep and the invariant audit file there by design".

    A real unit id is `<file>:<start>-<end>`, so an excuse rule of `"." in uid and ":" not
    in uid` also excuses `src/parse.c` — the exact string in the unit's own `file` field,
    and the natural mistake the naming invites. The artifact then attributes a whole agent's
    ledger to a phase that did not run and tells the reader those rows were expected. The
    invariant audit's own `struct.field` ids are still excused.
    """
    bad = report(build(tmp_path / "path", parts=ledger(row(unit_id="src/parse.c"))))
    assert bad["unknown_units"] == ["review-1: src/parse.c"]
    assert bad["unverifiable_rows"] == []

    # A file with no directory component is the same mistake and is caught by the same rule.
    flat = report(build(tmp_path / "flat", parts=ledger(row(unit_id="parse.c"))))
    assert flat["unverifiable_rows"] == []

    keep = report(build(tmp_path / "keep", parts=ledger(row(unit_id="cfg.window"))))
    assert keep["unverifiable_rows"] == ["review-1: cfg.window"]
    assert keep["unknown_units"] == []


def _no_site_counts():
    u = unit()
    del u["site_counts"]
    return u


@pytest.mark.parametrize(
    ("units", "because"),
    [
        # ids — a unit deleted from `units.json`, or one the reparse cannot reproduce,
        # shrinks the denominator to nothing while the parse in the same call had it.
        ([unit(), unit(id="src/ghost.c:1-9", sites=None)], "The tree moved"),
        # questions — trimming `required_questions` removes rows from the denominator, and
        # the per-question record is trimmed with it so equality alone cannot see it.
        (
            [unit(required_questions=["bounds"], site_counts={"bounds": len(WRITES)})],
            "the source now counts sites for",
        ),
        # counts — a source edit that thins a population without emptying it.
        ([unit(site_counts={"bounds": 99, "integer": len(CONVERSIONS)})], "the source now holds"),
        # nothing pinning the populations at all.
        ([_no_site_counts()], "carries no site_counts"),
    ],
)
def test_the_binding_to_the_enumeration_refuses_a_unit_list_the_parse_no_longer_agrees_with(
    units, because, tmp_path
):
    """`_bind_to_enumeration` is what makes "recomputed from the source" mean anything.

    `units.json` carries no digest of the tree, so a recompute on its own measures the tree
    as it is NOW. The binding diffs the unit id set, each unit's `required_questions` and
    the per-question `site_counts` against the fresh parse. These fixtures are what reaches
    it from the gate's own test file: an early `return` at the top of the function leaves
    every other test here green.
    """
    run_dir = build(tmp_path / "run", units=units)
    with pytest.raises(LedgerError) as exc:
        report(run_dir)
    assert because in str(exc.value), str(exc.value)


def test_the_binding_accepts_a_unit_list_the_parse_still_agrees_with(tmp_path):
    """The other half: a checker that refuses everything is not a checker."""
    assert report(build(tmp_path / "run"))["coverage_pct"] == 100.0


def test_units_with_findings_carries_the_location_the_second_pass_needs(tmp_path):
    parts = ledger(
        row(),
        row(question="integer"),
        findings=[{"unit_id": UID}, {"unit_id": UID}, {"unit_id": "src/ghost.c:1-9"}],
    )
    rep = report(build(tmp_path / "run", parts=parts))
    assert rep["units_with_findings"] == [
        {
            "unit_id": UID,
            "file": "src/parse.c",
            "name": "parse_header",
            "start_line": 1,
            "end_line": 40,
            "findings": 2,
        }
    ]


# ------------------------------------------------------- zero-item guards (exit 2)


def assert_nothing_to_check(run_dir, capsys, message):
    assert main(["--run-dir", str(run_dir)]) == 2
    assert message in capsys.readouterr().err
    assert not (Path(run_dir) / "ledger-gate.json").exists()


def test_zero_item_guard_missing_units_json(tmp_path, capsys):
    run = build(tmp_path / "run", write_units=False)
    assert_nothing_to_check(run, capsys, "missing input:")


def test_zero_item_guard_unparseable_units_json(tmp_path, capsys):
    run = build(tmp_path / "run", units_text='{"units": [')
    assert_nothing_to_check(run, capsys, "is not valid UTF-8 JSON")


def test_zero_item_guard_empty_unit_list(tmp_path, capsys):
    run = build(tmp_path / "run", units=[])
    assert_nothing_to_check(run, capsys, "lists no units")


def test_zero_item_guard_units_without_any_required_questions(tmp_path, capsys):
    run = build(tmp_path / "run", units=[unit(required_questions=[], sites={}, site_counts={})])
    assert_nothing_to_check(run, capsys, "no required questions")


def test_zero_item_guard_no_parts_directory(tmp_path, capsys):
    run = build(tmp_path / "run", parts_dir=False)
    assert_nothing_to_check(run, capsys, "no parts directory")


def test_zero_item_guard_parts_exist_but_hold_no_ledger_rows(tmp_path, capsys):
    # "notes" does not match a read prefix, so its rows are invisible to the gate —
    # which is exactly how a run ends up with parts on disk and nothing checked.
    parts = {"review-1": {"findings": [], "ledger": []}, "notes": {"ledger": [row()]}}
    run = build(tmp_path / "run", parts=parts)
    assert_nothing_to_check(run, capsys, "zero ledger rows")


# --------------------------------------------------------------------- cli


@pytest.mark.parametrize("strict", [[], ["--strict"]])
def test_a_clean_ledger_exits_0_with_or_without_strict(tmp_path, capsys, strict):
    run = build(tmp_path / "run")
    assert main(["--run-dir", str(run), *strict]) == 0
    summary = json.loads(capsys.readouterr().out)
    assert set(summary) == SUMMARY_KEYS
    assert summary["coverage_pct"] == 100.0
    assert json.loads((run / "ledger-gate.json").read_text())["checks_completed"] == 2


@pytest.mark.parametrize(("strict", "code"), [([], 0), (["--strict"], 1)])
def test_strict_turns_gaps_and_violations_into_exit_1(tmp_path, capsys, strict, code):
    run = build(tmp_path / "run", parts=ledger(row(accounted=[10])))
    assert main(["--run-dir", str(run), *strict]) == code
    captured = capsys.readouterr()
    summary = json.loads(captured.out)
    assert set(summary) == SUMMARY_KEYS
    assert summary["missing_row_count"] == 1
    assert summary["violation_kinds"] == ["population-not-accounted"]
    # The report is written either way; --strict only changes the exit code.
    gate = json.loads((run / "ledger-gate.json").read_text())
    # One row missing and the other rejected: half answered, none satisfied. The headline
    # is the strict number, so it reads 0.0 and not the 50.0 of answered rows.
    assert gate["answered_pct"] == 50.0
    assert gate["coverage_pct"] == 0.0
    assert ("1 missing row(s), 1 violation(s)" in captured.err) is bool(strict)


def test_headline_coverage_counts_satisfied_rows_not_merely_answered_ones(tmp_path):
    """A gate that logs a violation and still reports 100% is not gating.

    The real run this comes from answered all 105 owed rows, two with verdicts the gate
    itself rejected, and reported `coverage_pct: 100.0`. Answered and satisfied are separate
    numbers and the headline is the strict one.
    """
    run = build(
        tmp_path / "r",
        units=[
            unit(
                required_questions=["bounds"],
                sites={"write": list(WRITES)},
                site_counts={"bounds": len(WRITES)},
            )
        ],
        # not-applicable over a counted population is a violation
        parts=ledger(row(verdict="not-applicable", accounted=[])),
    )
    rep = report(run)
    assert rep["checks_completed"] == 1, "the row was answered"
    assert rep["checks_satisfied"] == 0, "but its answer was rejected"
    assert rep["answered_pct"] == 100.0
    assert rep["coverage_pct"] == 0.0, "headline coverage must not count a rejected row"


def test_sweep_rows_are_unverifiable_not_unknown(tmp_path):
    """Sweep rows sit outside the generated unit list by design.

    Reporting them as `unknown_units` makes 14 expected rows read as 14 errors and hides the
    real point: whole-tree sweep coverage cannot be checked against a parse at all.
    """
    parts = ledger(row(), row(question="integer"))
    parts["sweep-classes"] = {"ledger": [row(unit_id="(sweep)", question="dos", accounted=[])]}
    parts["sweep-invariants"] = {
        "ledger": [row(unit_id="state.wnext", question="state-field-invariant", accounted=[])]
    }
    run = build(tmp_path / "r", parts=parts)
    rep = report(run)
    assert rep["unknown_units"] == [], "sweep rows are not unmappable ids"
    assert len(rep["unverifiable_rows"]) == 2
    assert rep["coverage_pct"] == 100.0, "sweep rows neither help nor hurt unit coverage"


@pytest.mark.parametrize("accounted", [[], [3]])
def test_needs_human_over_a_counted_population_is_not_free_coverage(accounted):
    """`needs-human` is a legitimate answer, not a pass.

    Without this the row is satisfied by evidence text alone, so a ledger answering
    `needs-human` on every unit with an empty `sites_accounted` scores 100% coverage over a
    population it never looked at — the zero-item hazard inside the gate built to catch it.

    A partial account is the same hazard one step quieter: naming one site of three and
    scoring the row at full weight makes `needs-human` the cheapest verdict on the board.
    """
    units = {
        "units": [
            {
                "id": "a.c:1-9",
                "file": "a.c",
                "name": "f",
                "function": "f",
                "start_line": 1,
                "end_line": 9,
                "lines": 9,
                "kind": "function",
                "sites": {"write": [3, 4, 5]},
                "site_counts": {"bounds": 3},
                "required_questions": ["bounds"],
            }
        ],
        "totals": {"checks_required": 1},
    }
    doc = {
        "ledger": [
            {
                "unit_id": "a.c:1-9",
                "question": "bounds",
                "verdict": "needs-human",
                "sites_accounted": list(accounted),
                "evidence": "could not resolve",
            }
        ],
        "findings": [],
    }
    res = check(units, [("review-01", doc)])
    assert [v["kind"] for v in res["violations"]] == ["population-not-accounted"]
    assert res["checks_satisfied"] == 0
    assert res["coverage_pct"] == 0.0


def test_needs_human_that_names_its_sites_is_accepted():
    """The escape hatch must stay usable: say which sites you could not resolve and it passes."""
    units = {
        "units": [
            {
                "id": "a.c:1-9",
                "file": "a.c",
                "name": "f",
                "function": "f",
                "start_line": 1,
                "end_line": 9,
                "lines": 9,
                "kind": "function",
                "sites": {"write": [3, 4, 5]},
                "site_counts": {"bounds": 3},
                "required_questions": ["bounds"],
            }
        ],
        "totals": {"checks_required": 1},
    }
    doc = {
        "ledger": [
            {
                "unit_id": "a.c:1-9",
                "question": "bounds",
                "verdict": "needs-human",
                "sites_accounted": [3, 4, 5],
                "evidence": "all three indexed by a caller-supplied len I cannot bound here",
            }
        ],
        "findings": [],
    }
    res = check(units, [("review-01", doc)])
    assert res["violations"] == []
    assert res["checks_satisfied"] == 1


# --------------------------------------------- the vacuous paths that would score 100%


def test_a_unit_with_no_sites_mapping_is_refused_not_scored_at_100(tmp_path):
    """`sites = unit.get("sites") or {}` degrades to an EMPTY population for every question.

    Three rows of `verdict: clean, sites_accounted: [], evidence: "."` then score
    `checks_satisfied 3/3, coverage_pct 100.0, violation_count 0` and exit 0.
    """
    run = build(
        tmp_path / "run",
        units=[{"id": "a.c:1-9", "required_questions": ["bounds", "integer", "alloc-lifetime"]}],
        parts=ledger(
            *[
                row(question=q, accounted=[], evidence=".")
                for q in ("bounds", "integer", "alloc-lifetime")
            ]
        ),
    )
    # LedgerError either way: the population is missing, so `attach_sites` tries to
    # recompute it from the source and the gate refuses to score what it could not derive.
    with pytest.raises(Exception) as excinfo:
        report(run)
    # The reparse produces no population for a unit the file describes, so the binding
    # refuses the run before anything is scored. Either message is a refusal; what this
    # test is for is that three empty rows never reach `checks_satisfied`.
    assert "a.c:1-9" in str(excinfo.value), excinfo.value
    assert main(["--run-dir", str(run)]) == 2
    assert not (run / "ledger-gate.json").exists()


def test_a_unit_with_no_id_is_refused_rather_than_crashing_the_run(tmp_path):
    run = build(tmp_path / "run", units=[{k: v for k, v in unit().items() if k != "id"}])
    with pytest.raises(Exception) as excinfo:
        # `bind=False`: an id-less unit fails the binding's id-set equality first, with a
        # message about the tree moving. `_validate_units` is what has to name the real
        # fault, and it is what the assembler's fixtures reach.
        report(run, bind=False)
    assert "has no 'id'" in str(excinfo.value)


def test_units_with_findings_survives_a_unit_missing_its_display_fields(tmp_path):
    """A KeyError here escapes the gate and the assembler's `except LedgerError`, and
    destroys every artifact of a completed run."""
    sparse = {
        "id": UID,
        "sites": {"write": list(WRITES)},
        "site_counts": {"bounds": len(WRITES)},
        "required_questions": ["bounds"],
    }
    run = build(
        tmp_path / "run",
        units=[sparse],
        parts=ledger(row(), findings=[{"unit_id": UID, "title": "t"}]),
    )
    rep = report(run)
    assert rep["units_with_findings"] == [
        {
            "unit_id": UID,
            "file": "",
            "name": "",
            "start_line": None,
            "end_line": None,
            "findings": 1,
        }
    ]


def test_a_question_this_gate_does_not_know_is_a_violation_not_a_free_pass(tmp_path):
    """`QUESTION_SITE_KINDS.get(question, ())` gives an empty owed population, so the row
    passes on evidence text alone and scores 100% — a rename in `enumerate_units.QUESTIONS`
    would silently disable checking for that question across the whole run."""
    run = build(
        tmp_path / "run",
        units=[unit(required_questions=["boundz"])],
        parts=ledger(row(question="boundz", accounted=[], evidence="looked")),
    )
    # `bind=False`: a question the gate does not know is not one the enumerator emitted,
    # so the binding refuses the unit before the row rule is reached. This is the rule that
    # has to hold if a rename ever lands in `enumerate_units.QUESTIONS`.
    rep = report(run, bind=False)
    assert [v["kind"] for v in rep["violations"]] == ["unknown-question"]
    assert rep["checks_satisfied"] == 0
    assert rep["coverage_pct"] == 0.0


def test_a_finding_verdict_with_no_filed_finding_is_a_violation(tmp_path):
    """Held to the same bar as `clean` and never cross-checked, `verdict: finding` is free.

    An agent can then mark every row `finding` with none filed: `units_with_findings` —
    which the second pass targets — comes back empty while `verdict_counts` shows findings
    everywhere.
    """
    run = build(tmp_path / "run", parts=ledger(row(verdict="finding"), row(question="integer")))
    assert "finding-verdict-with-no-finding" in kinds(run)
    ok = build(
        tmp_path / "ok",
        parts=ledger(
            row(verdict="finding"),
            row(question="integer"),
            findings=[{"unit_id": UID, "title": "t"}],
        ),
    )
    assert kinds(ok) == []


def test_an_assignment_id_in_unit_id_is_an_unknown_unit_not_an_excused_sweep_row(tmp_path):
    """Buckets are named `unit-01` while unit ids are `src/f.c:10-40`, so writing the
    assignment id into `unit_id` is the mistake the naming invites. Excusing it as a sweep
    row reclassifies every row of that agent behind a bare count."""
    run = build(tmp_path / "run", parts=ledger(row(unit_id="unit-01")))
    rep = report(run)
    assert rep["unverifiable_rows"] == []
    assert rep["unknown_units"] == ["review-1: unit-01"]
    # The two shapes that ARE expected still are.
    other = build(
        tmp_path / "other",
        parts=ledger(row(unit_id="(sweep)"), row(unit_id="z_stream.wnext")),
    )
    assert len(report(other)["unverifiable_rows"]) == 2
    assert report(other)["unknown_units"] == []


def test_units_asked_no_question_are_counted_and_named(tmp_path):
    """They owe no row, so they are in neither the numerator nor the denominator; on a real
    tree that is every header and a quarter of the lines."""
    quiet = {
        "id": "src/h.h:1-30",
        "file": "src/h.h",
        "name": "(file-scope)",
        "sites": {},
        "required_questions": [],
        "lines": 30,
    }
    rep = report(build(tmp_path / "run", units=[unit(lines=40), quiet]))
    assert rep["unquestioned_units"] == ["src/h.h:1-30"]
    assert rep["unquestioned_lines"] == 30
    assert rep["lines_total"] == 70
    assert rep["coverage_pct"] == 100.0, "the percentage itself is unchanged; the caveat is new"


# ------------------------------------------------- unit lists this cannot check


def test_a_units_json_that_carries_its_own_sites_is_reparsed_anyway(tmp_path, monkeypatch):
    """The `sites` key in the FILE is not a seam; it is a per-unit off switch for the gate.

    Every worker agent has Write and Bash over the run directory, so skipping the recompute
    for a unit that already carries a `sites` mapping lets an agent restore the answer key
    under its own control — per unit, so it buys exactly the units it will not read. Only
    the `sites=` ARGUMENT reaches the recompute, and no file can supply one.
    """
    import enumerate_units

    monkeypatch.setattr(enumerate_units, "sites_by_id", lambda doc: {UID: {"write": [99]}})
    doc = {
        "root": "/does/not/exist",
        "units": [unit(required_questions=["bounds"], site_counts={"bounds": 1})],
    }
    attached = attach_sites(doc)
    # The message fires when the assertion FAILS, so it has to describe the losing outcome:
    # what this proves is that the file's own `sites` were thrown away and the reparse won.
    assert attached["units"][0]["sites"] == {"write": [99]}, "the file's own sites won"


def test_a_unit_list_whose_sites_are_all_empty_cannot_be_checked(tmp_path):
    """The one tamper shape that scores 100% if an EMPTY sites mapping is accepted.

    `checks_required` comes from `required_questions`, so emptying every population leaves
    the denominator at its real value while every row passes on evidence text alone —
    `coverage_pct 100.0`, `violation_count 0`, and nothing saying the diff was against
    nothing. Empty has to be refused exactly like missing.
    """
    run = build(tmp_path / "run", units=[unit(sites={})])
    with pytest.raises(Exception) as exc:
        # `bind=False`: `_bind_to_enumeration` refuses this shape first now, because a unit
        # owing two questions over zero sites is a unit the enumerator never wrote. This
        # guard is the redundant one behind it, and it is what a hand-built list reaches.
        report(run, bind=False)
    assert "no line at all" in str(exc.value)
    assert main(["--run-dir", str(run)]) == 2


@pytest.mark.parametrize(
    ("overrides", "code"),
    [
        ({"required_questions": 7}, 2),
        ({"required_questions": [7]}, 2),
        ({"lines": "forty"}, 0),
    ],
    ids=["questions-scalar", "questions-not-strings", "lines-not-a-number"],
)
def test_a_malformed_display_or_question_field_is_reported_not_raised(tmp_path, overrides, code):
    """`run_ledger_gate` catches everything, so a gate that cannot run is REPORTED.

    A `TypeError` out of `required_rows` or a `ValueError` out of `int(unit["lines"])`
    escapes that catch and destroys every artifact of a completed 88-finding run over
    fields the verdict does not depend on.

    One expected code per case, not `in (0, 2)`: the three do not agree, so a widened
    assertion cannot detect either outcome flipping — and turning the `lines` case from 0
    into 2 loses the artifacts.
    """
    run = build(tmp_path / "run", units=[unit(**overrides)])
    assert main(["--run-dir", str(run)]) == code


def test_the_summary_reports_satisfied_and_completed_as_different_numbers(tmp_path):
    """`_summary` is what REPORT.md, REPORT.sarif and the workflow all print as coverage.

    Asserting the distinction against `check()`'s full report and against ledger-gate.json
    leaves the object every consumer actually reads uncovered, so `checks_satisfied`
    projected from `checks_completed` survives: a run whose rows the gate rejected then
    prints "N of N required check(s) satisfied" in both artifacts.
    """
    run = build(
        tmp_path / "run",
        parts=ledger(row(accounted=[10, 20]), row(question="integer")),
    )
    summary = _summary(report(run))
    assert summary["checks_completed"] == 2
    assert summary["checks_satisfied"] == 1
    assert summary["coverage_pct"] == 50.0
    assert summary["violation_count"] == 1


# ------------------------------------------------- inputs this cannot read


@pytest.mark.parametrize(
    "make",
    [
        lambda p: p.write_bytes(b'{"ledger": [\xff]}'),
        lambda p: (p.write_text("{}", encoding="utf-8"), p.chmod(0o000)),
        lambda p: (p.unlink(missing_ok=True), p.mkdir()),
    ],
    ids=["not-utf8", "unreadable", "a-directory"],
)
def test_a_part_file_this_cannot_read_is_exit_2_not_a_traceback(tmp_path, capsys, make):
    """`_load_json` has to catch all five, not the two obvious ones.

    `PermissionError` and `IsADirectoryError` are `OSError`s and neither is a
    `FileNotFoundError`; `UnicodeDecodeError` is a `ValueError`, not an `OSError`. Any of
    the three escaping as a traceback exits 1 — the code this script's own contract reserves
    for `--strict` gaps — and takes every artifact with it inside the assembler.
    """
    run = build(tmp_path / "run")
    part = run / "parts" / "review-1.json"
    try:
        make(part)
        assert main(["--run-dir", str(run)]) == 2
        assert "check_ledger:" in capsys.readouterr().err
        assert not (run / "ledger-gate.json").exists()
    finally:
        if part.is_file():
            part.chmod(0o644)


@pytest.mark.parametrize("recorded", [None, "2", 2.0, True, [2]])
def test_a_denominator_that_is_not_an_integer_fails_closed(tmp_path, recorded):
    """`if _is_int(recorded) and recorded != len(owed)` makes the check an OPT-OUT.

    Deleting `totals.checks_required`, or writing it as the string "2", then skips the
    comparison entirely and exits 0 at `coverage_pct: 100.0`, with `ledger-gate.json`
    reporting `checks_required: len(owed)` either way — so "checked and equal" and "never
    checked" are byte-identical to every reader of every artifact.
    """
    totals = {} if recorded is None else {"checks_required": recorded}
    run = build(
        tmp_path / "run",
        units_text=json.dumps({"units": [unit()], "totals": totals}),
    )
    with pytest.raises(Exception) as exc:
        report(run)
    assert "totals.checks_required" in str(exc.value)
    assert main(["--run-dir", str(run)]) == 2
    assert not (run / "ledger-gate.json").exists()


def test_a_denominator_that_matches_is_accepted(tmp_path):
    """The other half, so the guard above cannot be satisfied by refusing everything."""
    run = build(tmp_path / "run")
    assert report(run)["checks_required"] == 2


def test_a_duplicate_question_in_one_unit_is_refused(tmp_path):
    """`checks_required` is `sum(len(required_questions))` and `owed` is keyed
    `(unit_id, question)`, so a duplicate collapses on one side and not the other and the
    denominator comparison reads equal over a list it should have refused."""
    run = build(
        tmp_path / "run",
        units_text=json.dumps(
            {
                "units": [unit(required_questions=["bounds", "bounds", "integer"])],
                "totals": {"checks_required": 3},
            }
        ),
    )
    with pytest.raises(Exception) as exc:
        report(run, bind=False)
    assert "duplicate question" in str(exc.value)


def test_the_summary_names_the_parts_it_read_and_the_whole_unknown_unit_count(tmp_path):
    """Two numbers that need a count key beside them.

    `unknown_units` is capped at ten ids, so a `findings_model` falling back to the SAMPLE
    length reports 25 fabricated unit ids to REPORT.md and SARIF as 10. And without
    `parts_read` in the summary, the standalone gate and the assembler — which reads only
    the parts the workflow dispatched — can disagree about the same directory in silence.
    """
    rows = [row(unit_id=f"ghost-{n}") for n in range(25)]
    run = build(tmp_path / "run", parts=ledger(row(), row(question="integer"), *rows))
    summary = _summary(report(run))
    assert summary["unknown_unit_count"] == 25
    assert len(summary["unknown_units"]) == 10
    assert summary["parts_read"] == ["review-1"]


@pytest.mark.parametrize(
    ("part", "because"),
    [
        (
            {"ledger": [row(), dict(row(question="integer"), sites_accounted=7)]},
            "review-2.ledger[1].sites_accounted is int, not a list",
        ),
        ({"ledger": {"unit_id": UID}}, "review-2.ledger is dict, not a list"),
        ({"ledger": [row(), "not a row"]}, "review-2.ledger[1] is not an object"),
        ({"ledger": [row()], "findings": 3}, "review-2.findings is int, not a list"),
    ],
)
def test_one_unreadable_field_does_not_throw_away_every_other_agents_coverage(
    tmp_path, part, because
):
    """`x or []` accepts any non-empty non-iterable.

    One `"sites_accounted": 7` used to escape `check()` as `TypeError: 'int' object is not
    iterable`, so `run.ledger` came back `{"error": …}`, coverage was unmeasured and the
    OTHER agent's complete, correct rows were discarded — over one scalar, with the message
    naming neither the part file nor the row. `assemble_findings._seq` already makes this
    trade on the same bytes; this is the gate catching up to it.

    Recorded, not swallowed: a malformed field fails the gate under `--strict` and is named
    in `malformed_rows`, and a bad `sites_accounted` also leaves its row's population
    unaccounted, so it earns a real violation rather than passing on evidence text.
    """
    parts = {**ledger(row(), row(question="integer")), "review-2": part}
    run = build(tmp_path / "run", parts=parts)
    got = report(run)
    assert got["malformed_rows"] == [because]
    # The first agent's two rows are still counted. Without the fix this raised instead.
    assert got["checks_completed"] == 2
    assert main(["--run-dir", str(run), "--strict"]) == 1


def test_rows_naming_a_unit_the_parse_never_produced_fail_the_gate(tmp_path):
    """40 rows over invented ids scored `coverage_pct: 100.0`, 0 violations and exit 0.

    `generate_sarif.lost_work` already counted `unknown_units`, so the same run wrote
    `executionSuccessful: false` into REPORT.sarif while both exit codes said it passed.
    """
    ghosts = [row(unit_id=f"src/ghost{n}.c:1-40") for n in range(40)]
    run = build(tmp_path / "run", parts=ledger(row(), row(question="integer"), *ghosts))
    got = report(run)
    assert got["checks_satisfied"] == got["checks_required"], "the real rows are still clean"
    assert got["violations"] == [] and got["missing_rows"] == []
    assert len(got["unknown_units"]) == 40
    assert main(["--run-dir", str(run), "--strict"]) == 1


def test_a_clean_ledger_with_a_sweep_row_still_exits_0_under_strict(tmp_path):
    """The negative half of both tests above.

    `unverifiable_rows` — the class sweep and the invariant audit, which file outside the
    unit list BY DESIGN — must not be swept into the new `--strict` condition, or every real
    run with a sweep phase fails the gate.
    """
    sweep = row(unit_id="(sweep)")
    run = build(tmp_path / "run", parts=ledger(row(), row(question="integer"), sweep))
    got = report(run)
    assert len(got["unverifiable_rows"]) == 1
    assert got["unknown_units"] == [] and got["malformed_rows"] == []
    assert main(["--run-dir", str(run), "--strict"]) == 0


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-q"]))
