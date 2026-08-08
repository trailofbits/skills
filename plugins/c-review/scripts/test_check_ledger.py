#!/usr/bin/env python3
"""Tests for the ledger gate.

The gate exists to refuse to certify a review it cannot check, so the tests that
carry the weight here are the rejections: one fixture per violation kind, and one
per zero-item guard. A suite that only proved a good ledger passes would still be
green if every checker inside `check()` were deleted.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent))

from check_ledger import check, load_parts, main  # noqa: E402

PREFIXES = ("review-", "invariant-", "sweep-", "second-")
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
    "units_with_findings",
    "gap_units",
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
    }
    base.update(overrides)
    return base


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


def build(run_dir, units=None, parts=None, *, units_text=None, write_units=True, parts_dir=True):
    """A run directory: units.json plus parts/<name>.json for each part given."""
    run_dir = Path(run_dir)
    run_dir.mkdir(parents=True, exist_ok=True)
    if write_units:
        if units_text is None:
            units_text = json.dumps({"units": [unit()] if units is None else units})
        (run_dir / "units.json").write_text(units_text, encoding="utf-8")
    if parts_dir:
        pdir = run_dir / "parts"
        pdir.mkdir(exist_ok=True)
        for name, doc in (default_parts() if parts is None else parts).items():
            (pdir / f"{name}.json").write_text(json.dumps(doc), encoding="utf-8")
    return run_dir


def report(run_dir):
    units_doc = json.loads((Path(run_dir) / "units.json").read_text(encoding="utf-8"))
    return check(units_doc, load_parts(Path(run_dir) / "parts", PREFIXES))


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


def test_all_four_part_prefixes_are_read(tmp_path):
    parts = {
        "review-1": {"ledger": [row()]},
        "invariant-1": {"ledger": [row(question="integer")]},
        "sweep-1": {"ledger": []},
        "second-1": {"ledger": []},
    }
    rep = report(build(tmp_path / "run", parts=parts))
    assert rep["parts_read"] == ["invariant-1", "review-1", "second-1", "sweep-1"]
    assert rep["checks_completed"] == 2


# ------------------------------------------------------------------ violations


@pytest.mark.parametrize("verdict", ["clean", "finding"])
def test_unaccounted_population_is_a_violation(tmp_path, verdict):
    bad = build(tmp_path / "bad", parts=ledger(row(verdict=verdict, accounted=[10, 20])))
    assert "population-not-accounted" in kinds(bad)
    detail = report(bad)["violations"][0]
    assert detail["question"] == "bounds"
    assert detail["unit_id"] == UID
    assert "[30]" in detail["detail"]
    assert "population-not-accounted" not in kinds(build(tmp_path / "good"))


def test_a_finding_never_closes_the_unit_rule_1(tmp_path):
    # The measured regression this gate exists to prevent: an agent files a bug on
    # one write site and stops, and the old validator scored the unit as reviewed.
    # The other two counted sites are still owed an account.
    bad = build(
        tmp_path / "bad",
        parts=ledger(row(verdict="finding", accounted=[20], evidence="overflow at 20")),
    )
    rep = report(bad)
    assert [v["kind"] for v in rep["violations"]] == ["population-not-accounted"]
    assert "2 of 3 site line(s) are unaccounted: [10, 30]" in rep["violations"][0]["detail"]
    # It is still recorded as answered, so the gap shows up as a violation and not
    # as a missing row.
    assert rep["checks_completed"] == 1
    assert "population-not-accounted" not in kinds(build(tmp_path / "good"))


def test_accounting_a_line_outside_the_population_is_a_violation(tmp_path):
    # 15 is a real site line in this unit, but it is a conversion, so it is not part
    # of what "bounds" counts. Citing it cannot discharge a write site.
    bad = build(tmp_path / "bad", parts=ledger(row(accounted=WRITES + [15])))
    assert kinds(bad) == ["sites-outside-population"]
    assert "[15]" in report(bad)["violations"][0]["detail"]
    assert "sites-outside-population" not in kinds(build(tmp_path / "good"))


def test_not_applicable_over_a_non_empty_population_is_a_violation(tmp_path):
    bad = build(tmp_path / "bad", parts=ledger(row(verdict="not-applicable", accounted=[])))
    assert kinds(bad) == ["not-applicable-with-population"]
    assert "3 site(s) were counted here" in report(bad)["violations"][0]["detail"]
    assert "not-applicable-with-population" not in kinds(build(tmp_path / "good"))


def test_not_applicable_over_an_empty_population_is_allowed(tmp_path):
    units = [unit(sites={"write": [], "conversion": list(CONVERSIONS)})]
    parts = ledger(
        row(verdict="not-applicable", accounted=[], evidence=""), row(question="integer")
    )
    rep = report(build(tmp_path / "run", units=units, parts=parts))
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
    assert rep["missing_rows"][0]["sites"] == CONVERSIONS
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


def test_a_second_pass_that_fills_the_population_clears_the_violation(tmp_path):
    # KNOWN FAILURE — a real defect in check_ledger.check(), not a bad fixture.
    # Dedup replaces the thin row in `seen`, but the violation that row already
    # appended is never retracted, so the gate's verdict depends on the alphabetical
    # order of part filenames. Identical ledger content, two outcomes: thin-first is
    # flagged (checked, then superseded), full-first is clean (superseded before it
    # is ever checked). thin-first is the ordering a real second pass produces, so
    # under --strict the second pass can never clear the gate it exists to clear.
    thin = row(verdict="finding", accounted=[20], evidence="overflow at 20")
    full = row(evidence="all three writes bounded")
    orderings = {
        "thin-first": {"review-1": {"ledger": [thin]}, "second-1": {"ledger": [full]}},
        "full-first": {"review-1": {"ledger": [full]}, "second-1": {"ledger": [thin]}},
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
    assert rep["unknown_units"] == ["review-1: (blank)", "review-1: src/ghost.c:1-9"]
    assert rep["rows_seen"] == 2
    assert rep["checks_completed"] == 0
    assert rep["coverage_pct"] == 0.0
    assert len(rep["missing_rows"]) == 2


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
    assert_nothing_to_check(run, capsys, "is not valid JSON")


def test_zero_item_guard_empty_unit_list(tmp_path, capsys):
    run = build(tmp_path / "run", units=[])
    assert_nothing_to_check(run, capsys, "lists no units")


def test_zero_item_guard_units_without_any_required_questions(tmp_path, capsys):
    run = build(tmp_path / "run", units=[unit(required_questions=[])])
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
    # One row missing and the other rejected: half answered, none satisfied. The
    # headline is the strict number, so it reads 0.0 rather than the old 50.0.
    assert gate["answered_pct"] == 50.0
    assert gate["coverage_pct"] == 0.0
    assert ("1 missing row(s), 1 violation(s)" in captured.err) is bool(strict)


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-q"]))


def test_headline_coverage_counts_satisfied_rows_not_merely_answered_ones(tmp_path):
    """A gate that logs a violation and still reports 100% is not gating.

    The real run this comes from answered all 105 owed rows, two with verdicts the gate
    itself rejected, and reported `coverage_pct: 100.0`. Answered and satisfied are now
    separate numbers and the headline is the strict one.
    """
    run = build(
        tmp_path / "r",
        units=[unit(required_questions=["bounds"])],
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

    Reporting them as `unknown_units` made 14 expected rows read as 14 errors and hid the
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
