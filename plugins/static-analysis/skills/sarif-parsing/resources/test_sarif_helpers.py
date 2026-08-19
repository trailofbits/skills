# /// script
# requires-python = ">=3.11"
# dependencies = ["pytest>=8"]
# ///
"""Tests for sarif_helpers.py, with the weight on severity resolution.

`result.level` is optional in SARIF 2.1.0, and CodeQL never emits it: severity lives on
the rule as `defaultConfiguration.level` and the result inherits it. Every helper here
used to read `result.level` directly, so `filter_by_level(findings, "error")` returned
nothing for a CodeQL run and the documented CI gate exited 0 on a repo full of errors.

fixtures/codeql-no-level.sarif is that shape, and test_naive_level_read_finds_nothing
pins it: if someone "fixes" the fixture by adding levels to its results, that test fails
rather than the suite quietly losing the only case it exists to cover.
fixtures/levels-on-results.sarif is the ordinary shape, and it is here so a resolver
cannot pass by ignoring `result.level` altogether.

The jq tests run the documented commands themselves, extracted from the markdown. A
severity gate that is correct in sarif_helpers.py and wrong in the docs is still a
severity gate that passes on a failing repo.
"""

from __future__ import annotations

import json
import re
import shutil
import subprocess
from pathlib import Path

import pytest
from sarif_helpers import (
    compute_fingerprint,
    deduplicate,
    extract_findings,
    filter_by_level,
    find_rule,
    load_sarif,
    resolve_level,
)

RESOURCES = Path(__file__).resolve().parent
SKILL = RESOURCES.parent / "SKILL.md"
JQ_QUERIES = RESOURCES / "jq-queries.md"
NO_LEVEL = RESOURCES / "fixtures/codeql-no-level.sarif"
WITH_LEVEL = RESOURCES / "fixtures/levels-on-results.sarif"

# The gate every CI pipeline built from this skill runs, in its jq form.
ERROR_GATE = '[.runs[] as $run | $run.results[] | select(level($run) == "error")] | length'
NAIVE_GATE = '[.runs[].results[] | select(.level == "error")] | length'

FENCE = re.compile(r"^```[a-z]*\n(.*?)^```", re.MULTILINE | re.DOTALL)
LEVEL_FN = re.compile(r"LEVEL_FN='\n(.*?)'\n", re.DOTALL)
# The GitHub Actions gate, which inlines its own copy of the resolver.
CI_GATE = re.compile(r"HIGH_COUNT=\$\(jq '\n(.*?)\n\s*' results\.sarif\)", re.DOTALL)


def results_of(sarif: dict) -> list[dict]:
    return [r for run in sarif["runs"] for r in run["results"]]


def jq(program: str, path: Path) -> str:
    """Run jq, failing rather than skipping when it is missing.

    A skip reads as a clean run while the only check that can catch a broken documented
    gate did not execute. jq is this skill's primary tool and CI installs it.
    """
    if not shutil.which("jq"):
        raise AssertionError(
            "jq is not installed, so the documented severity gate went unverified. "
            "Install it (brew install jq); this suite must not pass without it."
        )
    out = subprocess.run(["jq", program, str(path)], capture_output=True, text=True, check=True)
    return out.stdout.strip()


def documented_level_fn(path: Path) -> str:
    """The LEVEL_FN jq definition as the docs publish it."""
    match = LEVEL_FN.search(path.read_text())
    assert match, f"{path.name} no longer defines LEVEL_FN; the jq tests below test nothing"
    return match.group(1)


# --- the fixtures themselves, so the suite cannot go vacuous ------------------------


def test_codeql_fixture_omits_every_result_level():
    """The bug only exists on results with no level of their own."""
    results = results_of(load_sarif(NO_LEVEL))
    assert results, "fixture has no results"
    assert all("level" not in r for r in results)
    rules = load_sarif(NO_LEVEL)["runs"][0]["tool"]["driver"]["rules"]
    assert any(r.get("defaultConfiguration", {}).get("level") == "error" for r in rules)


def test_codeql_fixture_covers_both_join_directions():
    """One result joins by ruleIndex, another only by ruleId."""
    results = results_of(load_sarif(NO_LEVEL))
    assert any("ruleIndex" in r for r in results)
    assert any("ruleIndex" not in r for r in results)


def test_naive_level_read_finds_nothing_on_codeql_output():
    """The bug, stated: reading result.level scores a CodeQL run as clean."""
    results = results_of(load_sarif(NO_LEVEL))
    assert [r for r in results if r.get("level") == "error"] == []
    assert len(filter_by_level(extract_findings(load_sarif(NO_LEVEL)), "error")) == 1


# --- resolution ---------------------------------------------------------------------


def test_severity_inherited_from_rule_defaults():
    levels = {f.rule_id: f.level for f in extract_findings(load_sarif(NO_LEVEL))}
    assert levels == {
        "py/sql-injection": "error",  # defaultConfiguration.level, via ruleIndex
        "py/clear-text-logging-sensitive-data": "warning",  # via ruleId, no ruleIndex
        "py/unused-import": "warning",  # rule has no defaultConfiguration at all
    }


def test_result_level_outranks_rule_default():
    """Both fixtures hold exactly one error; a resolver that ignored result.level would
    report zero here, which is how you notice the fix was an inversion."""
    findings = extract_findings(load_sarif(WITH_LEVEL))
    assert {f.rule_id: f.level for f in findings} == {
        "python.lang.security.audit.dangerous-subprocess-use": "error",
        "python.django.security.audit.avoid-mark-safe": "warning",
    }
    rules = load_sarif(WITH_LEVEL)["runs"][0]["tool"]["driver"]["rules"]
    assert all(r["defaultConfiguration"]["level"] == "warning" for r in rules)
    assert len(filter_by_level(findings, "error")) == 1


@pytest.mark.parametrize("kind", ["pass", "notApplicable", "informational"])
def test_kind_other_than_fail_is_none(kind):
    """A passing compliance check must not inherit its rule's error level."""
    run = {"tool": {"driver": {"rules": [{"id": "r", "defaultConfiguration": {"level": "error"}}]}}}
    assert resolve_level({"ruleId": "r", "kind": kind}, run) == "none"
    assert resolve_level({"ruleId": "r", "kind": "fail"}, run) == "error"


@pytest.mark.parametrize("kind", [None, "fail"])
def test_null_or_fail_kind_resolves_from_the_rule(kind):
    """SARIF's `kind` defaults to "fail", and the jq gate coalesces null with `// "fail"`.
    `.get("kind", "fail")` would instead read an explicit null and hide the error as
    "none", so the resolver must coalesce null to "fail" to agree with the jq gate."""
    run = {"tool": {"driver": {"rules": [{"id": "r", "defaultConfiguration": {"level": "error"}}]}}}
    assert resolve_level({"ruleId": "r", "kind": kind}, run) == "error"


def test_unmatched_rule_falls_back_to_sarif_default():
    run = {"tool": {"driver": {"name": "tool-with-no-rule-metadata"}}}
    assert resolve_level({"ruleId": "r"}, run) == "warning"
    assert find_rule({"ruleId": "r"}, run) is None


@pytest.mark.parametrize("index", [9, -1])
def test_rule_index_outside_the_array_falls_back_to_rule_id(index):
    """-1 is SARIF's "no rule", and it is the dangerous one: `$rules[-1]` in jq is the
    last rule, so an unguarded index labels the result with that rule's severity."""
    run = {
        "tool": {
            "driver": {
                "rules": [
                    {"id": "r", "defaultConfiguration": {"level": "note"}},
                    {"id": "last", "defaultConfiguration": {"level": "error"}},
                ]
            }
        }
    }
    assert resolve_level({"ruleId": "r", "ruleIndex": index}, run) == "note"


# --- the documented jq gate ---------------------------------------------------------


def test_documented_jq_gate_reports_errors_from_rule_defaults():
    """Before and after, against the same bytes: the naive gate misses the error the
    documented one finds, and neither over-reports on ordinary SARIF."""
    level_fn = documented_level_fn(JQ_QUERIES)
    assert jq(NAIVE_GATE, NO_LEVEL) == "0"
    assert jq(level_fn + ERROR_GATE, NO_LEVEL) == "1"
    assert jq(NAIVE_GATE, WITH_LEVEL) == "1"
    assert jq(level_fn + ERROR_GATE, WITH_LEVEL) == "1"


def test_jq_and_python_resolution_agree():
    level_fn = documented_level_fn(JQ_QUERIES)
    program = level_fn + r'[.runs[] as $run | $run.results[] | level($run)] | join(",")'
    for fixture in (NO_LEVEL, WITH_LEVEL):
        from_jq = json.loads(jq(program, fixture)).split(",")
        assert from_jq == [f.level for f in extract_findings(load_sarif(fixture))]


def test_skill_and_reference_publish_the_same_resolution():
    assert documented_level_fn(SKILL) == documented_level_fn(JQ_QUERIES)


def test_the_github_actions_gate_runs_and_counts_the_inherited_error():
    """The gate from issue #262, run as published. It inlines its own copy of the
    resolver because a workflow step has no shell variable to paste into, so comparing
    the LEVEL_FN blocks does not cover it."""
    match = CI_GATE.search(SKILL.read_text())
    assert match, "the GitHub Actions gate is no longer where this test reads it"
    program = match.group(1)
    assert jq(program, NO_LEVEL) == "1"
    assert jq(program, WITH_LEVEL) == "1"


def test_documented_jq_does_not_read_the_last_rule_for_rule_index_minus_one(tmp_path):
    """`$rules[-1]` is the last element in jq, so the documented guard has to reject it."""
    sarif = {
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "t",
                        "rules": [
                            {"id": "r", "defaultConfiguration": {"level": "note"}},
                            {"id": "last", "defaultConfiguration": {"level": "error"}},
                        ],
                    }
                },
                "results": [{"ruleId": "r", "ruleIndex": -1, "message": {"text": "m"}}],
            }
        ],
    }
    path = tmp_path / "minus-one.sarif"
    path.write_text(json.dumps(sarif))
    program = documented_level_fn(JQ_QUERIES) + ".runs[] as $run | $run.results[] | level($run)"
    assert json.loads(jq(program, path)) == "note"
    assert jq(documented_level_fn(JQ_QUERIES) + ERROR_GATE, path) == "0"


def unresolved_severity(markdown: str) -> tuple[list[str], int]:
    """Documented jq lines that read a result's `.level` without resolving it, and the
    number of jq blocks scanned.

    Line by line, not block by block: one query reverted to `select(.level == "error")`
    hides inside a block whose other queries still resolve, which is how five of these
    survived review the first time.

    `.defaultConfiguration.level` is the rule's own field, read on purpose by the queries
    that list rule metadata, and `$r.level` is the resolver's own first branch.
    """
    offenders, blocks = [], 0
    for block in FENCE.findall(markdown):
        if "jq " not in block:
            continue
        blocks += 1
        for raw in block.splitlines():
            line = raw.strip()
            if line.startswith("#"):
                continue
            for benign in ("defaultConfiguration.level", "$r.level"):
                line = line.replace(benign, "")
            if ".level" in line and "level($run)" not in line:
                offenders.append(raw.strip())
    return offenders, blocks


def test_no_documented_jq_command_filters_on_bare_result_level():
    """No unresolved read anywhere, and the resolved queries did not vanish either.

    A doc with every severity query deleted would satisfy the first assertion, so the
    second one counts the resolutions that must still be there.
    """
    scanned, resolutions = 0, 0
    for doc in (SKILL, JQ_QUERIES):
        text = doc.read_text()
        offenders, blocks = unresolved_severity(text)
        assert offenders == [], f"{doc.name}: unresolved severity in {offenders}"
        scanned += blocks
        resolutions += text.count("level($run)")
    assert scanned >= 10, f"only {scanned} jq blocks found; block discovery is broken"
    assert resolutions >= 15, f"only {resolutions} resolved queries left in the docs"


def test_the_severity_guard_still_detects_a_regression():
    """The guard above reports nothing by design, so prove it can still report."""
    regressed = """```bash
# select(.level == "error") is what this used to say
jq '.runs[].results[] | select(.level == "error")' results.sarif
jq '.runs[].tool.driver.rules[] | {id: .id, level: .defaultConfiguration.level}' results.sarif
jq "$LEVEL_FN"'.runs[] as $run | $run.results[] | select(level($run) == "error")' out.sarif
```
"""
    offenders, blocks = unresolved_severity(regressed)
    assert blocks == 1
    assert offenders == ["""jq '.runs[].results[] | select(.level == "error")' results.sarif"""]


# --- fingerprints -------------------------------------------------------------------


def result_at(uri: str) -> dict:
    return {
        "ruleId": "py/sql-injection",
        "message": {"text": "This query depends on a user-provided value."},
        "locations": [
            {"physicalLocation": {"artifactLocation": {"uri": uri}, "region": {"startLine": 42}}}
        ],
    }


def test_fingerprint_separates_identical_findings_in_different_directories():
    """Hashing the basename alone made these one finding, so the second was discarded."""
    assert compute_fingerprint(result_at("app/auth/login.py")) != compute_fingerprint(
        result_at("app/admin/login.py")
    )


def test_deduplicate_keeps_a_finding_from_each_directory():
    sarif = {
        "version": "2.1.0",
        "runs": [
            {
                "tool": {"driver": {"name": "CodeQL"}},
                "results": [result_at("app/auth/login.py"), result_at("app/admin/login.py")],
            }
        ],
    }
    assert len(deduplicate(extract_findings(sarif))) == 2


def test_fingerprint_ignores_uri_scheme_and_percent_encoding():
    assert compute_fingerprint(result_at("file:///src/a%20b.py")) == compute_fingerprint(
        result_at("/src/a b.py")
    )


def test_fingerprint_still_matches_the_same_finding_twice():
    assert compute_fingerprint(result_at("app/auth/login.py")) == compute_fingerprint(
        result_at("app/auth/login.py")
    )
