"""Invariant tests for the tri-state model.

Each of these is a checker that must fail when it inspects a broken artifact; the
worked failures (clean-without-datum, coverage that cannot reconcile, zero dependencies
reported as zero risk) all shipped in earlier drafts of this collector.
"""

from __future__ import annotations

import pytest
from model import (
    CRITERIA,
    Dependency,
    ReconciliationError,
    Signal,
    State,
    count_flags,
    coverage,
    to_json,
)

SCAN = {
    "subject": "demo",
    "path": "/tmp/demo",
    "commit": None,
    "manifests": ["package.json"],
    "scanned_at": "2026-01-01T00:00:00+00:00",
}

TRANSITIVE_NONE = {
    "examined": False,
    "reason": "no lockfile resolves the transitive tree",
    "sources": [],
    "total": 0,
    "checked": 0,
    "unverifiable": [],
    "flagged": [],
}


def clean_dep(name: str = "pkg", eco: str = "npm", dev: bool | None = False) -> Dependency:
    dep = Dependency(
        ecosystem=eco,
        name=name,
        version="1.0.0",
        version_source="lockfile",
        dev=dev,
        repo=f"github.com/acme/{name}",
        exists=True,
    )
    for criterion in CRITERIA:
        dep.signals[criterion] = Signal.clean("measured", value=0)
    return dep


def artifact(deps: list[Dependency] | None = None, transitive: dict | None = None) -> dict:
    if deps is None:
        deps = [clean_dep()]
    return to_json(deps, SCAN, ["note"], transitive or TRANSITIVE_NONE)


# ------------------------------------------------------------ signal constructors


def test_clean_signal_demands_a_datum():
    with pytest.raises(ValueError):
        Signal.clean("no advisories recorded", None)


def test_clean_signal_demands_a_detail():
    with pytest.raises(ValueError):
        Signal.clean("", value=3)


def test_clean_signal_accepts_falsy_data():
    assert Signal.clean("zero downloads", 0).value == 0
    assert Signal.clean("not archived", False).value is False


def test_flagged_and_unassessable_demand_text():
    with pytest.raises(ValueError):
        Signal.flagged("", value=True)
    with pytest.raises(ValueError):
        Signal.unassessable("")


# ------------------------------------------------------------------ reconciliation


def test_duplicate_dependencies_refused():
    with pytest.raises(ReconciliationError, match="duplicate"):
        coverage([clean_dep("a"), clean_dep("a")])


def test_missing_criterion_refused():
    dep = clean_dep()
    del dep.signals[CRITERIA[0]]
    with pytest.raises(ReconciliationError, match="wrong criteria"):
        coverage([dep])


def test_unexpected_criterion_refused():
    dep = clean_dep()
    dep.signals["novel"] = Signal.clean("measured", value=1)
    with pytest.raises(ReconciliationError, match="wrong criteria"):
        coverage([dep])


def test_zero_dependencies_refused():
    with pytest.raises(ReconciliationError, match="zero dependencies"):
        artifact(deps=[])


def test_coverage_row_that_does_not_add_up_refused():
    art = artifact()
    art["coverage"]["criteria"]["advisories"][State.CLEAN.value] += 1
    from model import validate_artifact

    with pytest.raises(ReconciliationError, match="does not account"):
        validate_artifact(art)


def test_dependency_list_shorter_than_coverage_refused():
    art = artifact(deps=[clean_dep("a"), clean_dep("b")])
    art["dependencies"].pop()
    from model import validate_artifact

    with pytest.raises(ReconciliationError, match="are listed"):
        validate_artifact(art)


def test_run_that_measured_nothing_refused():
    dep = clean_dep()
    for criterion in CRITERIA:
        dep.signals[criterion] = Signal.unassessable("every source was down")
    with pytest.raises(ReconciliationError, match="measured nothing"):
        artifact(deps=[dep])


def test_count_flags_matches_flagged_lists():
    dep = clean_dep()
    dep.signals["archived"] = Signal.flagged("repository is archived", True)
    art = artifact(deps=[dep])
    assert count_flags(art) == {"archived": 1}


# ------------------------------------------------------------- transitive accounting


def test_artifact_without_transitive_accounting_refused():
    art = artifact()
    del art["transitive"]
    from model import validate_artifact

    with pytest.raises(ReconciliationError, match="transitive"):
        validate_artifact(art)


def test_unexamined_transitive_must_say_why():
    with pytest.raises(ReconciliationError, match="say why"):
        artifact(transitive={**TRANSITIVE_NONE, "reason": None})


def test_transitive_checked_beyond_total_refused():
    bad = {
        "examined": True,
        "reason": None,
        "sources": ["package-lock.json"],
        "total": 1,
        "checked": 2,
        "lockfile_entries": 1,
        "excluded_direct": 0,
        "unverifiable": [],
        "flagged": [],
    }
    with pytest.raises(ReconciliationError, match="checked"):
        artifact(transitive=bad)


def test_transitive_flags_beyond_checked_refused():
    bad = {
        "examined": True,
        "reason": "OSV was unreachable",
        "sources": ["package-lock.json"],
        "total": 2,
        "checked": 0,
        "lockfile_entries": 2,
        "excluded_direct": 0,
        "unverifiable": [],
        "flagged": [{"ecosystem": "npm", "name": "x", "version": "1", "advisories": ["G-1"]}],
    }
    with pytest.raises(ReconciliationError, match="flags"):
        artifact(transitive=bad)


def test_transitive_flag_without_advisory_ids_refused():
    bad = {
        "examined": True,
        "reason": None,
        "sources": ["package-lock.json"],
        "total": 1,
        "checked": 1,
        "lockfile_entries": 1,
        "excluded_direct": 0,
        "unverifiable": [],
        "flagged": [{"ecosystem": "npm", "name": "x", "version": "1", "advisories": []}],
    }
    with pytest.raises(ReconciliationError, match="advisory ids"):
        artifact(transitive=bad)


def test_transitive_without_unverifiable_accounting_refused():
    bad = {
        "examined": True,
        "reason": None,
        "sources": ["package-lock.json"],
        "total": 1,
        "checked": 1,
        "lockfile_entries": 1,
        "excluded_direct": 0,
        "flagged": [],
    }
    with pytest.raises(ReconciliationError, match="unverifiable"):
        artifact(transitive=bad)


def test_transitive_ledger_detects_a_dropped_entry():
    """The lockfile count is independent of the buckets, so a triple dropped before
    bucketing breaks this equation instead of vanishing while the counts balance."""
    bad = {
        "examined": True,
        "reason": None,
        "sources": ["package-lock.json"],
        "total": 2,
        "checked": 2,
        "lockfile_entries": 4,
        "excluded_direct": 1,
        "unverifiable": [],
        "flagged": [],
    }
    with pytest.raises(ReconciliationError, match="vanished"):
        artifact(transitive=bad)


def test_transitive_checked_zero_without_reason_refused():
    bad = {
        "examined": True,
        "reason": None,
        "sources": ["package-lock.json"],
        "total": 4,
        "checked": 0,
        "lockfile_entries": 4,
        "excluded_direct": 0,
        "unverifiable": [],
        "flagged": [],
    }
    with pytest.raises(ReconciliationError, match="unaccounted"):
        artifact(transitive=bad)


def test_transitive_unverifiable_must_reconcile():
    bad = {
        "examined": True,
        "reason": None,
        "sources": ["package-lock.json"],
        "total": 5,
        "checked": 2,
        "lockfile_entries": 5,
        "excluded_direct": 0,
        "unverifiable": [{"ecosystem": "npm", "name": "x", "version": "1", "reason": "git"}],
        "flagged": [],
    }
    with pytest.raises(ReconciliationError, match="unaccounted"):
        artifact(transitive=bad)
