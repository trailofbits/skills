#!/usr/bin/env python3
"""Fail an eval run whose no-plugin baseline read the skill under test.

The eval harness does not sandbox the filesystem, so a baseline agent that goes
looking can find this plugin's SKILL.md (or the graders) on disk and imitate
it, deflating the ablation delta. This checker scans the ``--json`` result: any
baseline-arm response that contains the plugin's path, its script name, or a
verbatim SKILL.md phrase means the arm was not a real control.

Per house rules, the checker fails when it has nothing to inspect: a result
with no cases, no baseline arm, or no response text is an error, not a pass.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

# Paths and filenames that exist only inside this repository. A baseline citing one
# has been reading the tree; they are not expected to appear in SKILL.md prose.
PATH_MARKERS = (
    "plugins/goal-prompt",
    "format_goal_prompt.py",
)

# Phrases authored in SKILL.md that a model does not produce independently. Matching is
# case-insensitive: SKILL.md writes "**Scope to read first**", so the lowercase marker
# below never fired against the very text it names. `test_phrase_markers_in_skill`
# fails if one of these drifts out of SKILL.md again.
PHRASE_MARKERS = (
    "terminates on the wrong contract",
    "scope to read first",
    "weaken, skip, or edit",
)

MARKERS = PATH_MARKERS + PHRASE_MARKERS


def baseline_texts(result: dict) -> list[tuple[str, str]]:
    """Return (label, response text) for every baseline run in the result."""
    texts = []
    for case in result.get("cases", []):
        arms = case.get("arms") or {}
        for i, run in enumerate(arms.get("without") or []):
            chunks = [g.get("evidence") or "" for g in run.get("graders", [])]
            texts.append((f"{case.get('name')}[without run{i + 1}]", " ".join(chunks)))
    return texts


def find_contamination(result: dict) -> list[str]:
    findings = []
    for label, text in baseline_texts(result):
        haystack = text.casefold()
        hits = [m for m in MARKERS if m.casefold() in haystack]
        if hits:
            findings.append(f"{label}: {', '.join(hits)}")
    return findings


def main(argv: list[str]) -> int:
    if len(argv) != 2:
        print("usage: check_contamination.py <eval-result.json>", file=sys.stderr)
        return 2
    result = json.loads(Path(argv[1]).read_text(encoding="utf-8"))

    texts = baseline_texts(result)
    if not texts:
        print(
            "check_contamination.py: error: no baseline runs found — "
            "was the eval run with --ablation with-without and --json?",
            file=sys.stderr,
        )
        return 1
    if all(not text.strip() for _, text in texts):
        print(
            "check_contamination.py: error: baseline runs carry no response text to inspect",
            file=sys.stderr,
        )
        return 1

    findings = find_contamination(result)
    if findings:
        print("check_contamination.py: baseline arm read the plugin under test:", file=sys.stderr)
        for f in findings:
            print(f"  {f}", file=sys.stderr)
        print("the ablation delta is not trustworthy; rerun and audit traces", file=sys.stderr)
        return 1

    print(f"ok: {len(texts)} baseline run(s) clean")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
