"""Documented examples must do what the text around them says.

Two examples did not:

- The unattended-build example called `codeql-build` without `out`. The Quick Start
  has already run `mkdir -p` on the resolved `OUTPUT_DIR` by then, and
  `codeql-build.js` auto-increments when `out` is absent, so the database landed in
  `static_analysis_codeql_2` while every other artifact went to `_1`.
- `--timeout 600000` was labelled milliseconds. `codeql database analyze --help -v`
  documents `--timeout=<seconds>`, so the "ten minutes" row set almost seven days.
- Database discovery read the creation time with `awk '{print $2}'`. Claude Code
  replaces `$0`, `$1`, ... in a SKILL.md body with the words of the skill's
  arguments, so `/static-analysis:codeql run a complete scan` turned it into
  `awk '{print complete}'` and every database's creation time came back empty.

Hermetic: reads markdown only. No CodeQL, no uv, no network.
"""

from __future__ import annotations

import json
import re
from pathlib import Path

SKILL_DIR = Path(__file__).resolve().parent.parent
BUILD_CALL = re.compile(r"^/static-analysis:codeql-build (\{.*\})\s*$", re.MULTILINE)
TIMEOUT_ROW = re.compile(r"^\| `--timeout` \| `(\d+)` \| (\w+)\.", re.MULTILINE)


def test_codeql_build_examples_pass_the_resolved_output_dir() -> None:
    calls = BUILD_CALL.findall((SKILL_DIR / "SKILL.md").read_text(encoding="utf-8"))
    assert calls, "no /static-analysis:codeql-build example found in SKILL.md"
    for call in calls:
        assert "out" in json.loads(call), (
            f"{call} omits out, so codeql-build auto-increments to a second directory"
        )


def test_timeout_row_uses_codeql_units() -> None:
    text = (SKILL_DIR / "references/performance-tuning.md").read_text(encoding="utf-8")
    rows = TIMEOUT_ROW.findall(text)
    assert rows, "no --timeout row found in performance-tuning.md"
    for value, unit in rows:
        assert unit == "Seconds", f"--timeout is in seconds, not {unit}"
        assert int(value) == 600, f"ten minutes is 600 seconds, not {value}"


def test_skill_body_has_no_positional_placeholders() -> None:
    body = (SKILL_DIR / "SKILL.md").read_text(encoding="utf-8")
    found = re.findall(r"\$\d+", body)
    assert not found, f"Claude Code substitutes {found} with skill arguments"
