"""Golden variant fixtures: real output from a real run of port-rule-to-languages over
`fixtures/python-command-injection.yaml`, graded by real `semgrep --test`.

This is the only check in the plugin that judges a finished port rather than the script
that produces one. The script's own behaviour is covered by workflow-failure-paths.test.mjs
and its runtime contract by test_workflow_contract.py, both run from pytest.

YAML is read with regexes rather than PyYAML because the suite runs under
`uv run --no-project --with pytest`, which supplies no third-party parser.
"""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
from pathlib import Path

import pytest

TESTS_DIR = Path(__file__).resolve().parent
FIXTURES = TESTS_DIR / "fixtures"
SOURCE_RULE = FIXTURES / "python-command-injection.yaml"

RULE_ID_RE = re.compile(r"^\s*-?\s*id:\s*(\S+)", re.MULTILINE)
LANGUAGES_RE = re.compile(r"^\s*languages:\s*\[([^\]]*)\]", re.MULTILINE)
ORIGINAL_RULE_RE = re.compile(r"^\s*original-rule:\s*(\S+)", re.MULTILINE)
PORTED_FROM_RE = re.compile(r"^\s*ported-from:\s*(\S+)", re.MULTILINE)


def golden_variants() -> list[Path]:
    """Return the checked-in variant directories produced by a real workflow run."""
    stem = SOURCE_RULE.stem
    return sorted(d for d in FIXTURES.glob(f"{stem}-*") if d.is_dir())


def rule_and_test_files(variant: Path) -> tuple[Path, Path]:
    """Return the (rule yaml, test file) pair inside a variant directory."""
    rule = variant / f"{variant.name}.yaml"
    others = [p for p in sorted(variant.iterdir()) if p != rule and p.is_file()]
    assert rule.is_file(), f"{variant.name} has no {rule.name}"
    assert len(others) == 1, f"{variant.name} should hold exactly one test file, found {others}"
    return rule, others[0]


def sole_match(pattern: re.Pattern[str], text: str, what: str, where: Path) -> str:
    """Return the single captured value for `pattern`, failing when it matched nothing."""
    found = pattern.findall(text)
    assert found, f"{where.name}: found no {what}"
    return found[0]


def test_source_rule_fixture_exists() -> None:
    assert SOURCE_RULE.is_file(), f"missing source rule fixture at {SOURCE_RULE}"
    assert sole_match(RULE_ID_RE, SOURCE_RULE.read_text(encoding="utf-8"), "rule id", SOURCE_RULE)


def test_golden_variants_are_present() -> None:
    variants = golden_variants()
    assert variants, (
        f"no golden variant directories under {FIXTURES}; fixture discovery is broken "
        "or the recorded workflow output was removed"
    )


@pytest.mark.parametrize("variant", golden_variants(), ids=lambda p: p.name)
def test_golden_rule_metadata_records_its_origin(variant: Path) -> None:
    rule, _ = rule_and_test_files(variant)
    text = rule.read_text(encoding="utf-8")
    source_id = sole_match(
        RULE_ID_RE, SOURCE_RULE.read_text(encoding="utf-8"), "rule id", SOURCE_RULE
    )

    assert sole_match(RULE_ID_RE, text, "rule id", rule) == variant.name, (
        "the rule id must match its directory, since semgrep --test keys annotations off it"
    )
    assert sole_match(ORIGINAL_RULE_RE, text, "original-rule metadata", rule) == source_id
    assert sole_match(PORTED_FROM_RE, text, "ported-from metadata", rule)

    languages = sole_match(LANGUAGES_RE, text, "languages key", rule)
    assert languages.strip(), "languages key is empty"
    assert "python" not in languages, "a port should not still declare the source language"


@pytest.mark.parametrize("variant", golden_variants(), ids=lambda p: p.name)
def test_golden_test_file_annotations_grade_the_rule(variant: Path) -> None:
    _, test_file = rule_and_test_files(variant)
    lines = test_file.read_text(encoding="utf-8").splitlines()

    vulnerable = [i for i, line in enumerate(lines) if f"ruleid: {variant.name}" in line]
    safe = [i for i, line in enumerate(lines) if f"ok: {variant.name}" in line]

    assert len(vulnerable) >= 2, (
        f"{test_file.name}: expected 2+ ruleid cases, found {len(vulnerable)}"
    )
    assert len(safe) >= 2, f"{test_file.name}: expected 2+ ok cases, found {len(safe)}"

    for index in vulnerable + safe:
        assert index + 1 < len(lines), (
            f"{test_file.name}:{index + 1} annotation has no line after it"
        )
        subject = lines[index + 1].strip()
        assert subject, f"{test_file.name}:{index + 2} is blank; the annotation grades nothing"
        assert variant.name not in subject, (
            f"{test_file.name}:{index + 2} is another annotation; annotations must sit directly "
            "above the code they grade or semgrep scores them against the wrong line"
        )


def grading_errors(report: dict, rule_file: str, rule_id: str, test_name: str) -> list[str]:
    """Return every reason semgrep's JSON does not show `test_name` graded clean.

    Read from the structured result rather than the summary line, because `All tests passed` is
    prose semgrep also prints over a run that graded nothing — a rule it skipped for want of a
    parser ends that way too, which is the failure the workflow script guards against
    everywhere else. `expected_lines` against `reported_lines` is the part that says the rule
    was applied to the annotated lines and matched them.

    The `<n>/<n>:` tally is deliberately unused: it counts rule/target pairs, not annotations,
    so it reads `1/1` for a pair that graded nothing.

    Split out from the test so the verdict itself can be exercised against the reports below
    without semgrep installed. A grader whose own judgment is untested is what this file exists
    to catch in a finished port.
    """
    if report.get("config_with_errors"):
        return [f"semgrep rejected {rule_file} itself"]

    # Both maps are keyed by path exactly as semgrep was given it — absolute when the caller
    # passed an absolute `--config` — so both are reduced to basenames before lookup.
    configs = {Path(config).name: entry for config, entry in report.get("results", {}).items()}
    checks = configs.get(rule_file, {}).get("checks", {})
    if rule_id not in checks:
        return [f"no check graded under {rule_id}, so the rule was skipped rather than run"]

    check = checks[rule_id]
    # Keyed by name, because semgrep reports each target as an absolute resolved path.
    graded = {Path(target).name: lines for target, lines in check.get("matches", {}).items()}
    if test_name not in graded:
        return [f"{test_name} is not among the graded targets ({sorted(graded)})"]

    errors = []
    expected = graded[test_name].get("expected_lines") or []
    reported = graded[test_name].get("reported_lines") or []
    if not expected:
        errors.append(f"{test_name} has no annotated lines, so a pass here measures nothing")
    if reported != expected:
        errors.append(f"{test_name}: expected matches on {expected}, semgrep reported {reported}")
    if not check.get("passed"):
        errors.append(f"{rule_id} did not pass")
    return errors


@pytest.mark.parametrize("variant", golden_variants(), ids=lambda p: p.name)
@pytest.mark.skipif(shutil.which("semgrep") is None, reason="semgrep is not installed")
def test_semgrep_grades_golden_variant_as_passing(variant: Path) -> None:
    """Run the real grader. The structural checks above still run without semgrep."""
    rule, test_file = rule_and_test_files(variant)
    completed = subprocess.run(
        ["semgrep", "--test", "--json", "--config", str(rule), str(test_file)],
        capture_output=True,
        text=True,
        check=False,
    )
    assert completed.returncode == 0, (
        f"semgrep --test failed for {variant.name}:\n{completed.stdout}{completed.stderr}"
    )

    errors = grading_errors(json.loads(completed.stdout), rule.name, variant.name, test_file.name)
    assert errors == [], f"{variant.name}:\n" + "\n".join(errors)


GREEN_REPORT = {
    "config_with_errors": [],
    "results": {
        "r.yaml": {
            "checks": {
                "r": {
                    "passed": True,
                    "matches": {"/abs/r.go": {"expected_lines": [3, 7], "reported_lines": [3, 7]}},
                }
            }
        }
    },
}


def report_with(**check: object) -> dict:
    """Return GREEN_REPORT with its single check's fields overridden."""
    merged = {**GREEN_REPORT["results"]["r.yaml"]["checks"]["r"], **check}
    return {"config_with_errors": [], "results": {"r.yaml": {"checks": {"r": merged}}}}


UNGRADED = (
    pytest.param(
        {"config_with_errors": ["r.yaml"], "results": {}},
        id="a rule semgrep could not load",
    ),
    pytest.param(
        {"config_with_errors": [], "results": {"r.yaml": {"checks": {}}}},
        # The Pro-gated-parser case: semgrep skips the rule and still ends in "All tests passed".
        id="a rule semgrep skipped rather than ran",
    ),
    pytest.param(
        report_with(matches={"/abs/r.go": {"expected_lines": [], "reported_lines": []}}),
        # The vacuous green: nothing annotated, nothing matched, reported as a pass.
        id="a pass over a test file with nothing annotated",
    ),
    pytest.param(
        report_with(
            passed=False,
            matches={"/abs/r.go": {"expected_lines": [3, 7], "reported_lines": []}},
        ),
        id="annotated lines the rule never matched",
    ),
    pytest.param(
        report_with(matches={"/abs/other.go": {"expected_lines": [3], "reported_lines": [3]}}),
        id="a green for a target that is not this variant's test file",
    ),
    pytest.param(report_with(passed=False), id="a check semgrep marked failed"),
)


@pytest.mark.parametrize("report", UNGRADED)
def test_grading_errors_rejects_a_run_that_proves_nothing(report: dict) -> None:
    """Prove the verdict fires on each way a semgrep run can look green having graded nothing."""
    assert grading_errors(report, "r.yaml", "r", "r.go"), "an ungraded run was accepted"


def test_grading_errors_accepts_a_real_green() -> None:
    """And prove it is not simply rejecting everything, which would fail the suite loudly but
    would leave the assertions above passing for the wrong reason."""
    assert grading_errors(GREEN_REPORT, "r.yaml", "r", "r.go") == []


def test_ci_has_semgrep_so_the_grader_is_never_silently_skipped() -> None:
    """Fail in CI when semgrep is missing, rather than skipping the only real grader.

    `skipif` turns an absent semgrep into a silent pass. Locally that is a convenience. In CI,
    where the workflow installs semgrep, it would mean the golden variants stopped being graded
    and every run still reported clean — the same vacuous green, one level up.
    """
    if os.environ.get("CI") != "true":
        pytest.skip("not CI: the grader may skip where semgrep is not installed")
    assert shutil.which("semgrep"), (
        "semgrep is not on PATH in CI, so the golden-variant grader skipped and the only check "
        "that judges a finished port inspected nothing"
    )
