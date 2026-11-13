"""SKILL.md must not prescribe ignored work, and every diagram example must name a language."""

import re
from pathlib import Path

SKILL = (Path(__file__).resolve().parent.parent / "SKILL.md").read_text(encoding="utf-8")
CODE = "\n".join(re.findall(r"```(?:bash|python)\n(.*?)```", SKILL, flags=re.S))


def diagram_commands() -> list[str]:
    joined = CODE.replace("\\\n", " ")
    return [
        line for line in joined.splitlines() if re.search(r"diagram\.py|trailmark diagram", line)
    ]


def test_no_preanalysis_step():
    # The diagram command builds its own engine; pre-analysis output is never used.
    assert "preanalysis()" not in CODE


def test_every_diagram_example_names_a_language():
    commands = [c for c in diagram_commands() if "-T " in c or "--type" in c]
    assert commands, "no diagram examples found; update the pattern"
    # diagram.py defaults to --language python, so a bare example parses any repo as Python.
    assert all(re.search(r"(-l|--language) \S+", c) for c in commands), commands


def test_quick_start_focus_is_a_placeholder():
    assert "--focus main" not in SKILL
