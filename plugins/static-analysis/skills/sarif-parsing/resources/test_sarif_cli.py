# /// script
# requires-python = ">=3.11"
# dependencies = ["pytest>=8"]
# ///
"""End-to-end tests for the compact SARIF helper CLI."""

import json
import subprocess
import sys
from pathlib import Path

import pytest

RESOURCES = Path(__file__).resolve().parent
HELPER = RESOURCES / "sarif_helpers.py"
NO_LEVEL = RESOURCES / "fixtures/codeql-no-level.sarif"
WITH_LEVEL = RESOURCES / "fixtures/levels-on-results.sarif"


def run(*args: str) -> str:
    return subprocess.run(
        [sys.executable, str(HELPER), *args], check=True, capture_output=True, text=True
    ).stdout


def test_summary_resolves_codeql_rule_severity():
    result = json.loads(run("summary", str(NO_LEVEL)))
    assert result["total"] == 3
    assert result["by_level"] == {"error": 1, "warning": 2}
    assert result["top_rules"] == [
        {"rule_id": "py/clear-text-logging-sensitive-data", "count": 1},
        {"rule_id": "py/sql-injection", "count": 1},
        {"rule_id": "py/unused-import", "count": 1},
    ]


def test_filter_uses_resolved_severity_and_bounds_output():
    result = json.loads(run("filter", str(NO_LEVEL), "--level", "error"))
    assert result["total"] == result["returned"] == 1
    assert result["findings"][0]["rule_id"] == "py/sql-injection"


def test_dedupe_preserves_directory_distinction_and_removes_exact_repeat():
    result = json.loads(run("dedupe", str(NO_LEVEL), str(NO_LEVEL)))
    assert result["total"] == 6
    assert result["unique"] == result["returned"] == 3


def test_diff_counts_new_fixed_and_unchanged_findings():
    result = json.loads(run("diff", str(NO_LEVEL), str(WITH_LEVEL)))
    assert {name: result[name]["total"] for name in ("new", "fixed", "unchanged")} == {
        "new": 2,
        "fixed": 3,
        "unchanged": 0,
    }


def test_csv_uses_resolved_severity():
    rows = run("csv", str(WITH_LEVEL), "--level", "error").splitlines()
    assert rows[0] == "rule_id,level,file,line,message"
    assert len(rows) == 2
    assert ",error," in rows[1]


def test_path_without_a_command_preserves_the_human_summary():
    output = run(str(NO_LEVEL))
    assert "Summary:" in output
    assert "Total findings: 3" in output
    assert "By severity:" in output


def test_no_arguments_preserves_legacy_usage_and_exit_code():
    result = subprocess.run(
        [sys.executable, str(HELPER)], capture_output=True, text=True, check=False
    )
    assert result.returncode == 1
    assert result.stdout == "Usage: uv run --no-project sarif_helpers.py <sarif_file>\n"
    assert result.stderr == ""


@pytest.mark.parametrize("filename", ["summary", "filter", "dedupe", "diff", "csv"])
def test_existing_file_named_after_a_command_preserves_legacy_invocation(tmp_path, filename):
    (tmp_path / filename).write_bytes(NO_LEVEL.read_bytes())
    result = subprocess.run(
        [sys.executable, str(HELPER), filename],
        cwd=tmp_path,
        capture_output=True,
        text=True,
        check=True,
    )
    assert result.stdout == run(str(NO_LEVEL))
    assert result.stderr == ""


def test_legacy_sarif_20_resolves_resource_rule_defaults(tmp_path):
    legacy = {
        "version": "2.0.0",
        "runs": [
            {
                "tool": {"name": "LegacyTool"},
                "resources": {
                    "rules": [
                        {
                            "id": "legacy/error",
                            "configuration": {"defaultLevel": "error"},
                        }
                    ]
                },
                "results": [
                    {
                        "ruleId": "legacy/error",
                        "message": {"text": "legacy finding"},
                        "locations": [
                            {
                                "physicalLocation": {
                                    "fileLocation": {"uri": "src/legacy.py"},
                                    "region": {"startLine": 7},
                                }
                            }
                        ],
                    }
                ],
            }
        ],
    }
    path = tmp_path / "legacy.sarif"
    path.write_text(json.dumps(legacy))
    result = json.loads(run("summary", str(path)))
    assert result["by_level"] == {"error": 1}
    filtered = json.loads(run("filter", str(path), "--level", "error"))
    assert filtered["findings"][0]["file"] == "src/legacy.py"
    assert filtered["findings"][0]["line"] == 7
    assert filtered["findings"][0]["tool"] == "LegacyTool"
