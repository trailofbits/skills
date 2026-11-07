"""SKILL.md CLI examples must match Trailmark's real `augment` behaviour."""

import re
from pathlib import Path

SKILL = (Path(__file__).resolve().parent.parent / "SKILL.md").read_text(encoding="utf-8")
BASH = "\n".join(re.findall(r"```bash\n(.*?)```", SKILL, flags=re.S)).replace("\\\n", " ")
AUGMENT = [line for line in BASH.splitlines() if "trailmark augment" in line]


def test_every_cli_example_names_a_language():
    # `trailmark augment` defaults to --language python.
    assert AUGMENT and all(re.search(r"(--language|-l) \S+", c) for c in AUGMENT), AUGMENT


def test_json_output_goes_to_a_file():
    # --json prints the whole augmented graph.
    assert all(">" in c for c in AUGMENT if "--json" in c)


def test_absolute_target_is_required():
    # A relative root matches no finding locations on Trailmark 0.5.
    assert "absolute path" in SKILL and "unmatched" in SKILL


def test_tainted_overlap_covers_every_finding_subgraph():
    assert "every `sarif:*` and `weaudit:*` subgraph" in SKILL
