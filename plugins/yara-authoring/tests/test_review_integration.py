"""Real CLI integration: no stub can certify recursion, empty inputs, or atom color."""

from __future__ import annotations

import json
import os
import shutil
import subprocess
from pathlib import Path

import pytest

SCRIPTS = Path(__file__).resolve().parents[1] / "skills/yara-rule-authoring/scripts"
GOOD = """rule MAL_Win_Review_Test_Jan25
{
    meta:
        description = "Detects a synthetic integration-test marker"
        author = "Trail of Bits"
        reference = "https://example.com/research"
        date = "2025-01-01"
    strings:
        $marker = "FamilyUniqueBeacon_7Q3L"
    condition:
        filesize < 10KB and $marker
}
"""


def command(*args):
    return subprocess.run(args, capture_output=True, text=True, check=False, timeout=120)


@pytest.fixture(autouse=True)
def required_tools():
    for tool in ("bash", "jq", "uv", "yr"):
        assert shutil.which(tool), f"real integration requires {tool}; see plugin Requirements"


def review(path):
    process = command(shutil.which("bash"), str(SCRIPTS / "review.sh"), str(path))
    report = json.loads(process.stdout)
    assert set(report["checks"]) == {"yr_check", "yr_format", "lint", "atoms"}
    for check in report["checks"].values():
        assert type(check["status"]) is int
        assert isinstance(check["output"], str)  # public combined-stream schema
    return process, report["checks"]


def test_actual_nested_valid_and_invalid_rules(tmp_path):
    nested = tmp_path / "rules" / "nested"
    nested.mkdir(parents=True)
    source = nested / "good.yar"
    source.write_text(GOOD)
    formatted = command("yr", "fmt", str(source))
    # yr fmt may return 1 when it applied changes; check mode must now be clean.
    assert formatted.returncode in (0, 1), formatted.stderr
    assert command("yr", "fmt", "--check", str(source)).returncode == 0
    before = source.read_bytes()
    process, checks = review(nested.parent)
    assert process.returncode == 0, checks
    assert all(check["status"] == 0 for check in checks.values()), checks
    assert source.read_bytes() == before  # review does not format in place
    source.write_text("rule Broken { condition: ??? }\n")
    # Control: without recursion the CLI does not see this nested defect.
    assert command("yr", "check", str(nested.parent)).returncode == 0
    process, checks = review(nested.parent)
    assert process.returncode == 1
    assert checks["yr_check"]["status"] != 0
    assert "good.yar" in checks["yr_check"]["output"]
    assert checks["lint"]["status"] != 0
    assert checks["atoms"]["status"] != 0


@pytest.mark.parametrize("kind", ["missing", "empty-file", "empty-directory", "comments-only"])
def test_actual_missing_or_empty_inputs_are_not_clean(tmp_path, kind):
    target = tmp_path / (kind + ".yar")
    if kind == "empty-file":
        target.touch()
    elif kind == "empty-directory":
        target.mkdir()
    elif kind == "comments-only":
        target.write_text("// no rules here\n")
    process, checks = review(target)
    assert process.returncode == 1
    assert checks["lint"]["status"] != 0
    assert checks["atoms"]["status"] != 0
    assert all(check["output"] for check in checks.values()) or kind == "comments-only"


def test_actual_unreadable_input_fails_without_touching_content(tmp_path):
    target = tmp_path / "unreadable.yar"
    target.write_text(GOOD)
    target.chmod(0)
    try:
        process, checks = review(target)
        if os.geteuid() != 0:
            assert process.returncode == 1
            assert all("not readable" in check["output"] for check in checks.values())
        else:
            # Root can read mode-000 files: do not claim that exercised a permission denial.
            assert all(isinstance(check["output"], str) for check in checks.values())
    finally:
        target.chmod(0o600)
    assert target.read_text() == GOOD


def test_real_atom_output_has_no_ansi_when_redirected_or_explicitly_disabled(tmp_path):
    source = tmp_path / "weak.yar"
    source.write_text(GOOD.replace("FamilyUniqueBeacon_7Q3L", "abc"))
    for flags in [[], ["--no-color"]]:
        process = command(
            "uv", "run", "--quiet", str(SCRIPTS / "atom_analyzer.py"), *flags, str(source)
        )
        assert process.returncode == 1
        assert "ERROR" in process.stdout or "WARNING" in process.stdout
        assert "\x1b[" not in process.stdout + process.stderr
    process, checks = review(source)
    assert process.returncode == 1
    assert "\x1b[" not in checks["atoms"]["output"]


def test_linter_codes_available_for_case06_regression_fixture(tmp_path):
    # A deterministic tool check, not a paid rerun of the model-based case-06 eval.
    plugin = SCRIPTS.parents[2]
    prompt = (plugin / "evals/06-review-with-linter/prompt.md").read_text()
    assert "```yara\n" in prompt, "case 06 must retain its embedded rule fixture"
    source = prompt.split("```yara\n", 1)[1].split("```", 1)[0]
    fixture = tmp_path / "case06.yar"
    fixture.write_text(source)
    process, checks = review(fixture)
    assert process.returncode == 1
    lint = json.loads(checks["lint"]["output"])
    codes = {issue["code"] for result in lint["results"] for issue in result["issues"]}
    assert {"E002", "W009"} <= codes, codes
