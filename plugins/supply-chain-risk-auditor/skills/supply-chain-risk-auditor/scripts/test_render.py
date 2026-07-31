"""Renderer tests: every flag reaches a reader, and no wording outruns the data.

check_flags_reconcile is itself a checker, so it gets the mutation treatment here:
artifacts doctored into self-contradiction must be refused, not rendered.
"""

from __future__ import annotations

import pytest
from model import CRITERIA, Dependency, ReconciliationError, Signal, to_json
from render import (
    _download_line,
    check_flags_reconcile,
    render,
    transitive_section,
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

TRANSITIVE_CLEAN = {
    "examined": True,
    "reason": None,
    "sources": ["package-lock.json"],
    "total": 5,
    "checked": 5,
    "unverifiable": [],
    "flagged": [],
}


def make_dep(
    name: str = "pkg",
    eco: str = "npm",
    dev: bool | None = False,
    version_source: str = "lockfile",
    downloads: int | None = 1000,
) -> Dependency:
    dep = Dependency(
        ecosystem=eco,
        name=name,
        version="1.0.0",
        version_source=version_source,
        dev=dev,
        repo=f"github.com/acme/{name}",
        exists=True,
    )
    for criterion in CRITERIA:
        dep.signals[criterion] = Signal.clean("measured", value=0)
    if downloads is None:
        dep.signals["downloads"] = Signal.unassessable("no download counter")
    else:
        dep.signals["downloads"] = Signal.clean(f"{downloads}/week", downloads)
    return dep


def artifact(deps: list[Dependency], transitive: dict | None = None) -> dict:
    return to_json(deps, SCAN, ["note"], transitive or TRANSITIVE_NONE)


def test_render_carries_every_section():
    text = render(artifact([make_dep()], TRANSITIVE_CLEAN))
    for heading in (
        "## Summary",
        "## Production dependencies",
        "## Findings",
        "## Transitive advisories",
        "## Informational",
        "## Coverage",
        "## Not assessable",
        "## Method and caveats",
    ):
        assert heading in text, heading


def test_flagged_production_dependency_reaches_the_findings_table():
    dep = make_dep("risky")
    dep.signals["archived"] = Signal.flagged("repository is archived", True)
    text = render(artifact([dep]))
    assert "### Reaches production" in text
    assert "`risky`" in text


def test_dev_none_never_renders_as_production():
    dep = make_dep("gomod", eco="Go", dev=None)
    dep.signals["staleness"] = Signal.flagged("no push in 3 years", "2023-01-01")
    text = render(artifact([dep]))
    assert "### Production or build-time not declared" in text
    assert "### Reaches production" not in text
    assert "can be identified as production or not" in text


def test_summary_says_latest_release_when_no_lockfile_resolves():
    text = render(artifact([make_dep(version_source="latest-release")]))
    assert "not checked at a project-resolved version" in text
    assert "versions this project resolves" not in text
    # go-mod-minimum is a floor, not a resolution; it must get the weak claim too
    go = render(artifact([make_dep(eco="Go", dev=None, version_source="go-mod-minimum")]))
    assert "versions this project resolves" not in go


def test_summary_claims_resolution_only_when_true():
    text = render(artifact([make_dep(version_source="lockfile")]))
    assert "checked at the versions this project resolves" in text


def test_unknown_criterion_in_coverage_is_refused():
    art = artifact([make_dep()])
    art["coverage"]["criteria"]["novel"] = {
        "assessed_clean": 1,
        "assessed_flagged": 0,
        "unassessable": 0,
    }
    with pytest.raises(ReconciliationError, match="knows nothing about"):
        render(art)


def test_coverage_and_dependency_flags_must_agree():
    dep = make_dep()
    dep.signals["archived"] = Signal.flagged("repository is archived", True)
    art = artifact([dep])
    art["coverage"]["criteria"]["archived"]["assessed_flagged"] = 0
    art["coverage"]["criteria"]["archived"]["assessed_clean"] = 1
    with pytest.raises(ReconciliationError, match="disagree"):
        check_flags_reconcile(art, "| Dependency |")


def test_transitive_flags_require_a_rendered_section():
    art = artifact(
        [make_dep()],
        {
            "examined": True,
            "reason": None,
            "sources": ["package-lock.json"],
            "total": 3,
            "checked": 3,
            "unverifiable": [],
            "flagged": [
                {
                    "ecosystem": "npm",
                    "name": "inner",
                    "version": "3.0.0",
                    "dev": True,
                    "advisories": ["GHSA-1"],
                }
            ],
        },
    )
    with pytest.raises(ReconciliationError, match="transitive"):
        check_flags_reconcile(art, "a report with no transitive section")
    text = render(art)
    assert "| `inner` (npm) | 3.0.0 | build-time only | GHSA-1 |" in text


def test_transitive_section_states_every_outcome():
    not_examined = transitive_section({"transitive": TRANSITIVE_NONE})
    assert any("Not examined" in line for line in not_examined)
    unchecked = transitive_section(
        {
            "transitive": {
                "examined": True,
                "reason": "OSV was unreachable",
                "sources": ["uv.lock"],
                "total": 4,
                "checked": 0,
                "flagged": [],
            }
        }
    )
    assert any("none was checked" in line for line in unchecked)
    clean = transitive_section({"transitive": TRANSITIVE_CLEAN})
    assert any("No known advisory" in line for line in clean)


def test_download_line_is_a_distribution_not_a_boolean():
    art = artifact([make_dep("a", downloads=100), make_dep("b", downloads=9000)])
    line = _download_line(art)
    assert "established for 2 of 2" in line and "`a` (100/wk)" in line
    none = artifact([make_dep("c", downloads=None)])
    assert "not determinable" in _download_line(none)


def test_render_refuses_an_artifact_it_cannot_support():
    art = artifact([make_dep()])
    art["dependencies"] = []
    art["coverage"]["total_dependencies"] = 0
    with pytest.raises(ReconciliationError):
        render(art)


def test_third_party_text_cannot_break_the_table():
    dep = make_dep("hostile")
    dep.signals["deprecated"] = Signal.flagged(
        "deprecated by its maintainers: line one\ntry `npm i other` instead | trailing",
        True,
    )
    text = render(artifact([dep]))
    row = next(line for line in text.splitlines() if "deprecated by its maintainers" in line)
    # the newline must not have split the row, and the pipe must not add a column
    assert row.startswith("| `hostile`") and "line one try" in row and "\\|" in row


def test_unverifiable_entries_are_named_never_clean():
    art = artifact(
        [make_dep()],
        {
            "examined": True,
            "reason": None,
            "sources": ["package-lock.json"],
            "total": 3,
            "checked": 2,
            "unverifiable": [
                {
                    "ecosystem": "npm",
                    "name": "internal-lib",
                    "version": "1.0.0",
                    "reason": "resolves from git+ssh://acme/internal, not the npm registry",
                }
            ],
            "flagged": [],
        },
    )
    text = render(art)
    assert "`internal-lib`" in text
    assert "could not be verified against a public registry" in text
    assert "No known advisory affects any of the 2 registry-verified" in text
