"""Version-aware activation, immutable configuration, and mixed Psalm reports."""

from __future__ import annotations

import json
import os
from pathlib import Path
from unittest.mock import patch

import pytest

from native import COVERAGE_UNKNOWN, normalize
from psalm_version import psalm_version
from runner import check_run, run_native

PSALM = os.environ.get("TAINT_TRACE_PSALM")


def fixture(root: Path, attributes: str = "") -> Path:
    source = root / "probe.php"
    source.write_text("<?php echo $_GET['input'];\n", encoding="utf-8")
    (root / "psalm.xml").write_text(
        '<psalm xmlns="https://getpsalm.org/schema/config" '
        f'{attributes}><projectFiles><file name="probe.php"/></projectFiles></psalm>',
        encoding="utf-8",
    )
    return source


def simulated(root: Path, version: str, *, explicit: bool = False) -> tuple[dict, list[list[str]]]:
    commands: list[list[str]] = []

    def execute(argv, cwd, timeout):
        commands.append(argv)
        if "--version" in argv:
            return 0, version, "", []
        return 0, "[]", f"Analyzing {root / 'probe.php'}\n", []

    with patch("runner.execute", side_effect=execute):
        record = run_native(
            backend="psalm",
            language="php",
            phase="baseline",
            scope="interprocedural",
            output=root / "run.json",
            cwd=root,
            argv=["psalm", *(["--taint-analysis"] if explicit else []), "--debug"],
        )
    return record, commands


@pytest.mark.parametrize(
    "banner,expected",
    [
        ("Psalm 7.1.0@abcdef\n", (7, 1, 0)),
        ("Psalm 7.0.0-dev@abc\n", (7, 0, 0)),
        ("Psalm 6.20.10\n", (6, 20, 10)),
        ("psalm test-version", None),
        ("other analyzer 7.1.0", None),
        ("Psalm 7.1.0garbage", None),
    ],
)
def test_version_requires_psalms_banner(banner, expected):
    assert psalm_version(banner) == expected


@pytest.mark.parametrize("version", ["5.26.1", "6.20.10", "7.0.0", "7.1.0", "8.0.0", "unknown"])
@pytest.mark.parametrize("setting", ["", 'runTaintAnalysis="true"', 'runTaintAnalysis="false"'])
@pytest.mark.parametrize("explicit", [False, True])
def test_activation_uses_captured_version_and_xml(tmp_path, version, setting, explicit):
    fixture(tmp_path, setting)
    run, commands = simulated(tmp_path, f"Psalm {version}\n", explicit=explicit)
    expected = explicit or version.startswith("7.") and "false" not in setting
    assert (run["status"] == "analyzed") == expected, run["errors"]
    assert len(commands) == (2 if expected else 1)
    if expected:
        assert check_run(run, tmp_path / "run.json") == []


def test_combined_activation_revalidates_historical_xml_and_version(tmp_path):
    fixture(tmp_path)
    run, _ = simulated(tmp_path, "Psalm 7.1.0\n")
    (tmp_path / "psalm.xml").write_text("<psalm runTaintAnalysis='false'/>")
    assert check_run(run, tmp_path / "run.json") == []
    run["version"]["output"] = "Psalm 7.0.0\n"
    assert any("version disagrees" in error for error in check_run(run, tmp_path / "run.json"))


def test_missing_version_snapshot_cannot_establish_combined_activation(tmp_path):
    fixture(tmp_path)
    run, _ = simulated(tmp_path, "Psalm 7.1.0\n")
    from runner_artifacts import artifact

    path = Path(run["execution"]["path"])
    saved = json.loads(path.read_text())
    del saved["effective"]["version"]
    path.write_text(json.dumps(saved))
    run["execution"].update(artifact(path))
    assert any("immutable version" in error for error in check_run(run, tmp_path / "run.json"))


def test_composer_inputs_are_captured_without_loading_php(tmp_path):
    fixture(tmp_path, 'loadLibraryPlugins="false" loadLibraryStubs="true"')
    (tmp_path / "composer.json").write_text('{"config":{"vendor-dir":"packages"}}')
    (tmp_path / "composer.lock").write_text('{"packages":[]}')
    metadata = tmp_path / "packages" / "composer"
    metadata.mkdir(parents=True)
    (metadata / "installed.json").write_text('{"packages":[]}')
    (metadata / "installed.php").write_text("<?php throw new Exception('must not execute');")
    run, _ = simulated(tmp_path, "Psalm 7.1.0\n")
    assert run["status"] == "analyzed", run["errors"]
    assert {Path(item["original_path"]).name for item in run["config_files"]} == {
        "psalm.xml",
        "composer.json",
        "composer.lock",
        "installed.json",
        "installed.php",
    }
    (tmp_path / "composer.json").write_text("{}")
    assert check_run(run, tmp_path / "run.json") == []
    snapshot = next(
        item for item in run["config_files"] if item["original_path"].endswith("composer.lock")
    )
    Path(snapshot["path"]).write_text("changed")
    assert check_run(run, tmp_path / "run.json")


def test_new_security_kinds_and_type_diagnostics_are_retained_separately(tmp_path):
    kinds = [
        "TaintedNosql",
        "TaintedLlmPrompt",
        "TaintedUrlComponent",
        "TaintedUrlPath",
        "TaintedCustom",
    ]
    issues = [
        {
            "type": kind,
            "severity": "SECURITY",
            "file_name": "probe.php",
            "line_from": 1,
            "message": kind,
            "taint_trace": [{"label": "source"}],
        }
        for kind in kinds
    ]
    issues.append({"type": "ClassMustBeFinal", "severity": "error", "message": "type diagnostic"})
    result = normalize(json.dumps(issues), "psalm", tmp_path)
    assert [finding["rule_id"] for finding in result["findings"]] == kinds
    assert all(finding["trace"] == [{"label": "source"}] for finding in result["findings"])
    assert result["limitations"] == ["Psalm ClassMustBeFinal: type diagnostic", COVERAGE_UNKNOWN]
    assert result["errors"] == []


@pytest.mark.skipif(not PSALM, reason="Set TAINT_TRACE_PSALM for native version compatibility")
@pytest.mark.parametrize(
    "setting,explicit",
    [("", False), ('runTaintAnalysis="false"', False), ('runTaintAnalysis="false"', True)],
)
def test_real_psalm_activation_and_explicit_override(tmp_path, setting, explicit):
    fixture(tmp_path, setting)
    run = run_native(
        backend="psalm",
        language="php",
        phase="baseline",
        scope="interprocedural",
        output=tmp_path / "run.json",
        cwd=tmp_path,
        argv=[
            PSALM,
            *(["--taint-analysis"] if explicit else []),
            "--debug",
            "--no-cache",
            "--output-format=json",
        ],
    )
    version = psalm_version(run["version"]["output"])
    assert version is not None, run["errors"]
    expected = explicit or version[0] == 7 and "false" not in setting
    if expected:
        assert run["status"] in {"analyzed", "limited"}, run["errors"]
        assert any(finding["rule_id"] == "TaintedHtml" for finding in run["findings"])
        assert run["scanned_files"] == [str(tmp_path / "probe.php")]
        assert check_run(run, tmp_path / "run.json") == []
    else:
        assert run["status"] == "failed"
        assert run["returncode"] is None
        assert any("--taint-analysis" in error for error in run["errors"])
