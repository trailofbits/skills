"""Opt-in native proof that precision contracts retain vulnerable positives."""

from __future__ import annotations

import os
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent))

from runner import run_native  # noqa: E402
from trace_artifacts import digest, snapshot_sources  # noqa: E402

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


def directory_fixture(root: Path) -> Path:
    source = root / "probe.php"
    source.write_text(
        "<?php\n"
        "namespace SnapshotFixture;\n"
        "class Lookup {\n"
        "/**\n"
        " * @param array $values\n"
        " * @param array $keys\n"
        " * @return mixed|null\n"
        " * @psalm-taint-specialize\n"
        " */\n"
        "public static function value($values, $keys) {\n"
        "    $keys = (array) $keys;\n"
        "    foreach ($keys as $key) {\n"
        "        if (!isset($values[$key])) { return null; }\n"
        "        $values = $values[$key];\n"
        "    }\n"
        "    return $values;\n"
        "}\n"
        "}\n"
        "echo Lookup::value(['x' => $_GET['input']], ['x']); // positive\n"
        "echo Lookup::value(['x' => 'literal'], ['x']); // literal negative\n",
        encoding="utf-8",
    )
    (root / "psalm.xml").write_text(
        '<psalm xmlns="https://getpsalm.org/schema/config" findUnusedCode="false">'
        '<projectFiles><directory name="."/></projectFiles></psalm>\n',
        encoding="utf-8",
    )
    return source


@pytest.mark.skipif(not PSALM, reason="Set TAINT_TRACE_PSALM for native precision proof")
@pytest.mark.parametrize("capture", ["model", "graph"])
def test_directory_scan_retains_positive_with_snapshots(tmp_path: Path, capture: str) -> None:
    assert PSALM is not None
    source = directory_fixture(tmp_path)
    if capture == "graph":
        snapshot_sources(
            {
                "target": str(tmp_path),
                "source_hashes": {source.name: digest(source)},
                "configuration_files": ["psalm.xml"],
            },
            tmp_path / "context.json",
        )
    run = run_native(
        backend="psalm",
        language="php",
        phase="enriched",
        scope="interprocedural",
        cwd=tmp_path,
        output=tmp_path / "run.json",
        models=[source] if capture == "model" else [],
        argv=[PSALM, "--taint-analysis", "--debug", "--no-cache", "--output-format=json"],
    )
    assert run["status"] == "analyzed", run["errors"]
    assert {(f["rule_id"], f["line"]) for f in run["findings"]} == {
        ("TaintedHtml", 19),
        ("TaintedTextWithQuotes", 19),
    }
    assert run["scanned_files"] == [str(source)]
