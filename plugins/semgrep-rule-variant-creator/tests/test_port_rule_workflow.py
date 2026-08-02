"""Golden variant fixtures: real output from a real run of port-rule-to-languages over
`fixtures/python-command-injection.yaml`, graded by real `semgrep --test`.

This is the only check in the plugin that judges a finished port rather than the script
that produces one. The script's own behaviour is covered by workflow-failure-paths.test.mjs
and its runtime contract by test_workflow_contract.py, both run from pytest.

YAML is read with regexes rather than PyYAML because the suite runs under
`uv run --no-project --with pytest`, which supplies no third-party parser.
"""

from __future__ import annotations

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


@pytest.mark.parametrize("variant", golden_variants(), ids=lambda p: p.name)
@pytest.mark.skipif(shutil.which("semgrep") is None, reason="semgrep is not installed")
def test_semgrep_grades_golden_variant_as_passing(variant: Path) -> None:
    """Run the real grader. The structural checks above still run without semgrep."""
    rule, test_file = rule_and_test_files(variant)
    completed = subprocess.run(
        ["semgrep", "--test", "--config", str(rule), str(test_file)],
        capture_output=True,
        text=True,
        check=False,
    )
    output = completed.stdout + completed.stderr
    assert completed.returncode == 0, f"semgrep --test failed for {variant.name}:\n{output}"
    assert "All tests passed" in output, f"{variant.name} did not pass cleanly:\n{output}"
