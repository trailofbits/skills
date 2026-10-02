from __future__ import annotations

import copy
import json
import re
import subprocess
import sys
from pathlib import Path

import pytest
from process_results import filtered, summary


def run(rules, results):
    return {"runs": [{"tool": {"driver": {"rules": rules}}, "results": results}]}


def test_summary_resolves_rule_level_and_rule_id_fallback() -> None:
    data = run(
        [{"id": "sql", "defaultConfiguration": {"level": "error"}}],
        [{"ruleIndex": -1, "ruleId": "sql"}],
    )
    assert summary(data, 20) == {"total": 1, "by_level": {"error": 1}, "top_rules": {"sql": 1}}


def test_important_filter_keeps_high_and_high_severity_medium_only() -> None:
    data = run(
        [
            {"id": "high", "properties": {"precision": "high"}},
            {"id": "medium-keep", "properties": {"precision": "medium", "security-severity": "6"}},
            {
                "id": "medium-drop",
                "properties": {"precision": "medium", "security-severity": "5.9"},
            },
        ],
        [{"ruleIndex": 0}, {"ruleIndex": 1}, {"ruleIndex": 2}],
    )
    assert [item["ruleIndex"] for item in filtered(data)["runs"][0]["results"]] == [0, 1]


@pytest.mark.parametrize("precision", ["low", "medium", "high", "very-high", "unknown", None])
@pytest.mark.parametrize("severity", [None, "0", "5.9", "6", "9.8"])
def test_filter_matches_complete_documented_jq_output(precision, severity) -> None:
    """Use the existing workflow's jq, independently of the replacement's logic."""
    reference = Path(__file__).parents[1] / "references/sarif-processing.md"
    expression = re.search(
        r"jq '\n(.*?)\n' \"\$RAW_DIR/results.sarif\"", reference.read_text(), re.S
    )
    assert expression, "the documented jq filter must remain discoverable"
    rule = {
        "id": "query",
        "properties": {"precision": precision, "security-severity": severity},
    }
    data = run([rule], [{"ruleIndex": 0, "ruleId": "query", "message": {"text": "Full payload"}}])
    data.update(version="2.1.0", properties={"keep": [1, 2, 3]})
    data["runs"][0]["artifacts"] = [{"location": {"uri": "src/example.py"}}]
    # A second run with absent precision proves missing metadata defaults to unknown.
    data["runs"].extend(run([{"id": "unknown"}], [{"ruleIndex": 0}])["runs"])
    result = subprocess.run(
        ["jq", expression[1]], input=json.dumps(data), capture_output=True, text=True, check=True
    )
    assert filtered(copy.deepcopy(data)) == json.loads(result.stdout)


@pytest.mark.parametrize("command", ["summary", "important-filter"])
def test_cli_rejects_invalid_json_without_publishing_results(tmp_path, command) -> None:
    source = tmp_path / "malformed.sarif"
    source.write_text("{unfinished")
    output = tmp_path / "final.sarif"
    args = [
        sys.executable,
        str(Path(__file__).with_name("process_results.py")),
        command,
        str(source),
    ]
    if command == "important-filter":
        args.append(str(output))
    result = subprocess.run(args, capture_output=True, text=True, check=False)
    assert result.returncode != 0
    assert not output.exists()
    assert not result.stdout


def test_summary_empty_results() -> None:
    assert summary(run([], []), 20) == {"total": 0, "by_level": {}, "top_rules": {}}


def test_detailed_report_prioritizes_rare_error_and_retains_full_location_evidence():
    rules = [
        {"id": f"warning-{n}", "defaultConfiguration": {"level": "warning"}} for n in range(25)
    ]
    rules.append(
        {
            "id": "rare-error",
            "defaultConfiguration": {"level": "error"},
            "properties": {"security-severity": "9.8"},
        }
    )
    locations = [
        {
            "physicalLocation": {
                "artifactLocation": {"uri": "security/auth.py"},
                "region": {"startLine": 999, "startColumn": 4},
            }
        }
    ]
    results = [
        {
            "ruleId": r["id"],
            "ruleIndex": n,
            "message": {"text": "full message"},
            "locations": locations,
        }
        for n, r in enumerate(rules)
    ]
    report = summary(run(rules, results), 20, details=True)
    assert report["total"] == 26 and report["distinct_rules"] == 26
    assert report["rules_omitted"] == 6 and report["findings_omitted"] == 6
    assert report["findings"][0] == {
        "rule_id": "rare-error",
        "level": "error",
        "security_severity": "9.8",
        "locations": locations,
        "message": {"text": "full message"},
    }
    all_records = summary(run(rules, results), 0, details=True)
    assert all_records["rules_omitted"] == all_records["findings_omitted"] == 0
    assert len(all_records["findings"]) == 26


@pytest.mark.parametrize("severity", ["not-a-number", True, {}])
def test_filter_rejects_invalid_medium_severity_like_jq(tmp_path, severity) -> None:
    source = tmp_path / "invalid-severity.sarif"
    source.write_text(
        json.dumps(
            run(
                [{"properties": {"precision": "medium", "security-severity": severity}}],
                [{"ruleIndex": 0}],
            )
        )
    )
    reference = Path(__file__).parents[1] / "references/sarif-processing.md"
    expression = re.search(
        r"jq '\n(.*?)\n' \"\$RAW_DIR/results.sarif\"", reference.read_text(), re.S
    )
    assert expression
    old = subprocess.run(["jq", expression[1], str(source)], capture_output=True, check=False)
    output = tmp_path / "results.sarif"
    replacement = subprocess.run(
        [
            sys.executable,
            str(Path(__file__).with_name("process_results.py")),
            "important-filter",
            str(source),
            str(output),
        ],
        capture_output=True,
        check=False,
    )
    assert old.returncode != 0
    assert replacement.returncode != 0
    assert not output.exists()
