"""Opt-in native proof that precision contracts retain vulnerable positives."""

from __future__ import annotations

import os
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent))

from runner import run_native  # noqa: E402

PSALM = os.environ.get("TAINT_TRACE_PSALM")


def specialization_fixture(root: Path, *, specialized: bool) -> None:
    root.mkdir()
    annotation = "/** @psalm-taint-specialize */" if specialized else "/** Ordinary helper. */"
    (root / "probe.php").write_text(
        "<?php\n" + annotation + "\n"
        "function traceValue(string $value): string {\n"
        "    error_log('adapter called');\n"
        "    return $value;\n"
        "}\n"
        "echo traceValue($_GET['input']); // positive\n"
        "echo traceValue('literal'); // literal negative\n",
        encoding="utf-8",
    )
    (root / "psalm.xml").write_text(
        '<psalm xmlns="https://getpsalm.org/schema/config" findUnusedCode="false">'
        '<projectFiles><file name="probe.php"/></projectFiles></psalm>\n',
        encoding="utf-8",
    )


@pytest.mark.skipif(not PSALM, reason="Set TAINT_TRACE_PSALM for native precision proof")
def test_specialization_separates_calls_without_sanitizing_input(tmp_path: Path) -> None:
    assert PSALM is not None
    html_lines = []
    for label, specialized in (("original", False), ("specialized", True)):
        root = tmp_path / label
        specialization_fixture(root, specialized=specialized)
        run = run_native(
            backend="psalm",
            language="php",
            phase="enriched" if specialized else "baseline",
            scope="interprocedural",
            cwd=root,
            output=root / "run.json",
            argv=[PSALM, "--taint-analysis", "--debug", "--no-cache", "--output-format=json"],
        )
        assert run["status"] in {"analyzed", "limited"}, run["errors"]
        html_lines.append({f["line"] for f in run["findings"] if f["rule_id"] == "TaintedHtml"})
    assert html_lines == [{7, 8}, {7}]
