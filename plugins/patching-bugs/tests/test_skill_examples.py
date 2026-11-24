"""Keep skill record examples aligned with the bundled schemas."""

import json
import re
from pathlib import Path

import pytest
from records import SCHEMA_DIR, validate

SKILLS = Path(__file__).resolve().parents[1] / "skills"
SCHEMA_LINK = re.compile(
    r"\[[^\]]+\]\((?P<path>\.\./\.\./schemas/(?P<kind>[a-z-]+)\.schema\.json)\)"
)
EXAMPLE = re.compile(r"[ \t]*:?[ \t]*\n[ \t]*```json[ \t]*\n(.*?)\n[ \t]*```", re.DOTALL)
EXPECTED = {
    "reproduce-bug": {"reproduce"},
    "validate-bug": {"validate"},
    "implement-patch": {"patch"},
    "prove-patch": {"prove"},
    "patching-bugs": {"finding", "run", "regression", "report-input"},
}


def examples(skill_text: str) -> list[tuple[str, dict]]:
    links = list(SCHEMA_LINK.finditer(skill_text))
    assert links, "skill has no record schema examples"
    found = []
    for index, link in enumerate(links):
        end = links[index + 1].start() if index + 1 < len(links) else len(skill_text)
        block = EXAMPLE.match(skill_text[link.end() : end])
        assert block, f"{link.group('kind')}: schema link has no following JSON example"
        found.append((link.group("kind"), json.loads(block.group(1))))
    return found


@pytest.mark.parametrize("skill_name", sorted(EXPECTED))
def test_skill_examples_match_schemas(skill_name):
    skill = SKILLS / skill_name / "SKILL.md"
    assert skill.is_file(), f"missing skill: {skill_name}"
    found = examples(skill.read_text())
    assert {kind for kind, _ in found} == EXPECTED[skill_name]
    assert len(found) == len(EXPECTED[skill_name])
    for kind, record in found:
        schema = json.loads((SCHEMA_DIR / f"{kind}.schema.json").read_text())
        validate(record, schema)


def test_schema_link_without_example_is_rejected():
    with pytest.raises(AssertionError, match="no following JSON example"):
        examples("[run schema](../../schemas/run.schema.json)\n")


def test_zero_examples_is_rejected():
    with pytest.raises(AssertionError, match="no record schema examples"):
        examples("No schema links here")
