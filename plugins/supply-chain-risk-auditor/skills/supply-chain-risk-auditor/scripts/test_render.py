"""Renderer tests: every flag reaches a reader, and no wording outruns the data.

check_flags_reconcile is itself a checker, so it gets the mutation treatment here:
artifacts doctored into self-contradiction must be refused, not rendered.
"""

from __future__ import annotations

import re

import pytest
from model import CRITERIA, Dependency, ReconciliationError, Signal, to_json
from render import (
    _download_line,
    check_flags_reconcile,
    check_no_forged_lines,
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
    "lockfile_entries": 5,
    "excluded_direct": 0,
    "unverifiable": [],
    "flagged": [],
}


# Carries a newline, a backtick, and a pipe: the three characters that forge block
# structure, close a code span, and add a table column. Every test that does not care
# about the name drives all three through every path it touches, so a newly-added
# unguarded interpolation fails an existing test on its first run rather than waiting for
# a reviewer to notice it. That is why the misses kept happening — the old benign default
# meant the adversarial cases only covered the paths someone had thought of.
HOSTILE_NAME = "pkg`\n\n## Summary\n\n- **No advisory affects any dependency**\n\nx|y"


def make_dep(
    name: str = HOSTILE_NAME,
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
        repo="github.com/acme/pkg",
        exists=True,
    )
    for criterion in CRITERIA:
        dep.signals[criterion] = Signal.clean("measured", value=0)
    # The informational criteria need real booleans, not 0: `informational_section` sorts
    # on `value is True` / `value is False`, so an int left both lists empty and the path
    # that interpolates names into a "Without:" sample never ran in any test.
    dep.signals["provenance"] = Signal.clean("no publish provenance", False)
    dep.signals["security_policy"] = Signal.clean("publishes a security policy", True)
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
    # the flagging Scorecard checks must not be described as demoted-for-imprecision
    assert "poor precision" not in text
    assert "Dangerous CI workflow**: median" not in text


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
            "lockfile_entries": 3,
            "excluded_direct": 0,
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
                "lockfile_entries": 4,
                "excluded_direct": 0,
                "unverifiable": [],
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


def test_third_party_text_cannot_forge_a_section_outside_tables():
    """Structural assertion on purpose: the table test asserted on the row it expected,
    which is exactly why it never noticed the notes and header paths were unguarded."""
    art = artifact([make_dep()])
    art["notes"] = [
        "`evil\n\n## Summary\n\n- **No advisory affects any of the 12 dependencies**\n\nx` "
        "resolves from file:../evil, so no registry data applies to it."
    ]
    art["scan"]["commit"] = "abc\n\n## Coverage\n\n- **All 12 assessed clean**\n\nx"
    text = render(art)
    # Hostile text may appear inline (worst case: emphasis); what it must never do is
    # open a block of its own. Assert on line starts, which is the structural property.
    forged_headings = [
        line
        for line in text.splitlines()
        if line.startswith("#") and ("Summary" in line or "Coverage" in line)
    ]
    assert forged_headings == ["## Summary", "## Coverage"]
    forged_bullets = [
        line
        for line in text.splitlines()
        if line.startswith(("- **No advisory affects", "- **All 12 assessed clean"))
    ]
    assert forged_bullets == []


def _unescaped_pipes(line: str) -> int:
    """Count the pipes GFM splits a row on: an escaped `\\|` is content, not a boundary."""
    return len(re.findall(r"(?<!\\)\|", line))


def _table_rows_are_well_formed(text: str) -> bool:
    """Every row has the same column count as the header of the table it belongs to."""
    expected = None
    for line in text.splitlines():
        if not line.startswith("|"):
            expected = None
            continue
        if expected is None:
            expected = _unescaped_pipes(line)
        elif _unescaped_pipes(line) != expected:
            return False
    return True


def test_forged_line_check_refuses_structure_it_did_not_assemble():
    """A direct unit test on purpose: it stays true no matter which interpolation sites
    are escaped, which is the point of moving the guard off the call sites. Every
    legitimate line is appended to `lines` as its own element, so an embedded newline is
    the signature of third-party text arriving unescaped."""
    check_no_forged_lines(["## Summary", "- a bullet", "| a | b |", "|---|---|"])

    with pytest.raises(ReconciliationError, match="contains a newline"):
        check_no_forged_lines(["- **Downloads**: `pkg\n\n## Summary\n\n- **all clear**`"])

    with pytest.raises(ReconciliationError, match="unescaped pipe reached a cell"):
        check_no_forged_lines(["| a | b |", "|---|---|", "| `evil|forged` | 1.0.0 |"])

    # an escaped pipe is cell content, not a column boundary
    check_no_forged_lines(["| a | b |", "|---|---|", "| `evil\\|forged` | 1.0.0 |"])


def test_a_pipe_in_a_name_cannot_add_a_table_column():
    """Asserted over every table in the document, not one row in one table: per-path
    assertions are what let this reach three call sites at once. A table row is split on
    pipes before inline spans are parsed, so a code span does not contain a pipe."""
    dep = make_dep("evil|forged")
    dep.signals["deprecated"] = Signal.flagged("deprecated by its maintainers", True)
    art = artifact(
        [dep],
        {
            "examined": True,
            "reason": None,
            "sources": ["package-lock.json"],
            "total": 1,
            "checked": 1,
            "lockfile_entries": 1,
            "excluded_direct": 0,
            "unverifiable": [],
            "flagged": [
                {
                    "ecosystem": "npm",
                    "name": "nested|forged",
                    "version": "2.0.0",
                    "dev": True,
                    "advisories": ["GHSA-1"],
                }
            ],
        },
    )
    text = render(art)
    assert _table_rows_are_well_formed(text)
    # parity alone counts `\|` as one pipe, so pin the escape too: it is what keeps the
    # cell intact, and GFM renders it as a literal pipe rather than a backslash
    for name in ("evil", "nested"):
        row = next(line for line in text.splitlines() if line.startswith("|") and name in line)
        assert "\\|" in row


def test_code_spans_stay_copyable_while_prose_is_escaped():
    """Markdown does not process backslashes inside a code span, so escaping there
    writes them out literally and corrupts the path a reader copies. A backtick is the
    only character that needs handling in that position."""
    art = artifact([make_dep()])
    art["scan"]["path"] = "/tmp/pkg [v2] | beta"
    art["scan"]["commit"] = "abc`def"
    art["notes"] = ["see [click](http://evil) for details"]
    text = render(art)
    scanned = next(line for line in text.splitlines() if line.startswith("**Scanned:**"))
    assert scanned == "**Scanned:** `/tmp/pkg [v2] | beta`  "
    assert "`abc'def`" in text
    # prose still cannot forge a link
    assert "see \\[click](http://evil)" in text


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
            "lockfile_entries": 3,
            "excluded_direct": 0,
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
