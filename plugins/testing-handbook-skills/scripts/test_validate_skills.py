#!/usr/bin/env python3
"""Prove validate-skills.py still detects what it exists to detect.

A checker that has silently stopped matching passes every run and looks clean
doing it. Each test here builds a known-bad frontmatter block and asserts the
matching check rejects it, then asserts a good one is accepted — so a check
that starts matching nothing, or everything, fails this suite.

Stdlib only, like every other suite in this repo: CI runs these with
`uv run --no-project --with pytest`, an environment that has pytest and
nothing else. validate-skills.py imports pyyaml at module scope purely to
parse frontmatter, and none of the checks under test here call it, so a
stand-in satisfies the import when pyyaml is absent. It raises rather than
returning a value, so no test can quietly come to depend on a fake parser.
"""

from __future__ import annotations

import importlib.util
import re
import sys
import types
from pathlib import Path

import pytest

try:  # pragma: no cover - depends on the environment, both branches are fine
    import yaml  # noqa: F401
except ModuleNotFoundError:  # pragma: no cover
    _stub = types.ModuleType("yaml")
    _stub.YAMLError = type("YAMLError", (Exception,), {})

    def _unavailable(*_args, **_kwargs):
        raise AssertionError(
            "validate-skills.py's YAML parsing is not under test here and pyyaml "
            "is not installed — a test reaching this needs the real dependency"
        )

    _stub.safe_load = _unavailable
    sys.modules["yaml"] = _stub

_SPEC = importlib.util.spec_from_file_location(
    "validate_skills", Path(__file__).parent / "validate-skills.py"
)
assert _SPEC and _SPEC.loader
validate_skills = importlib.util.module_from_spec(_SPEC)
sys.modules["validate_skills"] = validate_skills
_SPEC.loader.exec_module(validate_skills)

# Frontmatter descriptions are single-quoted single lines by convention, so the
# shipped-description sweep below reads them without needing a YAML parser.
DESCRIPTION_LINE = re.compile(r'^description:\s*"(.*)"\s*$', re.M)

GOOD_DESCRIPTION = (
    "Sets up and runs libFuzzer, the coverage-guided fuzzer built into LLVM, on "
    "C/C++ code that compiles with Clang. Covers harness structure and campaign "
    "triage. Use when writing an LLVMFuzzerTestOneInput harness, or working out "
    "why a libFuzzer run finds nothing."
)


def check(frontmatter) -> list[str]:
    """Run frontmatter validation and return the errors it reported."""
    result = validate_skills.ValidationResult(skill_name="fixture", skill_path=Path("SKILL.md"))
    validate_skills.validate_frontmatter(frontmatter, result)
    return result.errors


def frontmatter(**overrides) -> dict:
    base = {"name": "libfuzzer", "type": "fuzzer", "description": GOOD_DESCRIPTION}
    base.update(overrides)
    return base


def test_good_frontmatter_is_accepted() -> None:
    """The positive control. If this fails, every rejection below proves nothing."""
    assert check(frontmatter()) == []


@pytest.mark.parametrize(
    "parsed",
    [pytest.param(None, id="empty-block"), pytest.param("just a string", id="bare-scalar")],
)
def test_non_mapping_frontmatter_is_rejected(parsed) -> None:
    """A block yaml accepts but that carries no fields must not validate silently.

    This is the whole-check version of the zero-guard: every field check below
    reads `frontmatter.get(...)`, so anything that is not a mapping used to skip
    all of them and report the skill clean.
    """
    assert check(parsed) != []


@pytest.mark.parametrize(
    ("parsed", "expected"),
    [
        pytest.param(None, "empty", id="empty-block"),
        pytest.param("just a string", "not a mapping", id="bare-scalar"),
    ],
)
def test_extraction_reports_non_mapping_frontmatter(monkeypatch, parsed, expected) -> None:
    """`extract_frontmatter` must pair a non-mapping result with an error.

    `validate_skill` runs the field checks only when extraction reported no
    error, so returning `(None, None)` for an empty block skipped them all.
    The parser is stubbed rather than fed YAML so this runs in CI's
    pyyaml-free environment, where it matters most.
    """
    monkeypatch.setattr(validate_skills.yaml, "safe_load", lambda _text: parsed)

    frontmatter_result, error = validate_skills.extract_frontmatter("---\n\n---\n\n# Skill\n")

    assert frontmatter_result is None
    assert error and expected in error


@pytest.mark.parametrize(
    ("description", "expected"),
    [
        pytest.param(
            "Coverage-guided fuzzer built into LLVM for C/C++ projects.",
            "trigger phrase",
            id="no-trigger-phrase",
        ),
        pytest.param(
            "Sets up {fuzzer}. Use when fuzzing {language} projects.",
            "template placeholders",
            id="template-placeholder",
        ),
        pytest.param(
            "Sets up a fuzzer for {language} projects. Use when fuzzing Rust.",
            "template placeholders",
            id="single-placeholder-among-real-text",
        ),
        pytest.param(
            "Sets up <b>libFuzzer</b>. Use when fuzzing C/C++.",
            "HTML/XML tags",
            id="html-tag",
        ),
        pytest.param(
            "Sets up libFuzzer. {{< hint >}} Use when fuzzing C/C++.",
            "Hugo shortcodes",
            id="hugo-shortcode",
        ),
        pytest.param("x" * 1025 + " Use when fuzzing.", "too long", id="over-length"),
        pytest.param("", "Missing required field", id="empty"),
    ],
)
def test_bad_description_is_rejected(description: str, expected: str) -> None:
    errors = check(frontmatter(description=description))
    assert any(expected in e for e in errors), f"expected {expected!r} in {errors}"


def test_placeholder_check_does_not_fire_on_real_descriptions() -> None:
    """Every shipped description must survive the placeholder check.

    This is the guard against the check being too greedy — a pattern that also
    matched ordinary prose would make the whole plugin unshippable.
    """
    skills_dir = Path(__file__).parent.parent / "skills"
    shipped = sorted(skills_dir.glob("*/SKILL.md"))
    assert len(shipped) >= 15, f"expected the plugin's skills, found {len(shipped)}"

    for skill in shipped:
        match = DESCRIPTION_LINE.search(skill.read_text(encoding="utf-8"))
        assert match, f"{skill.parent.name}: no single-line quoted description found"
        assert not validate_skills.PLACEHOLDER_PATTERN.search(match.group(1)), (
            f"{skill.parent.name}: description matches the placeholder pattern"
        )


@pytest.mark.parametrize(
    ("field", "value", "expected"),
    [
        pytest.param("name", "LibFuzzer", "Invalid name", id="uppercase-name"),
        pytest.param("name", "claude-fuzzer", "reserved word", id="reserved-word"),
        pytest.param("type", "wildly-invalid", "Invalid type", id="bad-type"),
    ],
)
def test_bad_field_is_rejected(field: str, value: str, expected: str) -> None:
    errors = check(frontmatter(**{field: value}))
    assert any(expected in e for e in errors), f"expected {expected!r} in {errors}"
