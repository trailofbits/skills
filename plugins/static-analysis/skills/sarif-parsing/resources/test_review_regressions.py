# /// script
# requires-python = ">=3.11"
# dependencies = ["pytest>=8"]
# ///
"""Fail-closed scan status, conservative identity, and documented jq parity."""

import copy
import csv
import io
import json
import re
import subprocess
import sys
from pathlib import Path

import pytest
from sarif_helpers import deduplicate, diff_findings, extract_findings, rules_for_run

ROOT = Path(__file__).parent
HELPER = ROOT / "sarif_helpers.py"


def finding(rule="R", path="src/a.py", line=1, level="warning"):
    return {
        "ruleId": rule,
        "level": level,
        "message": {"text": "same"},
        "partialFingerprints": {"lineHash/v1": "shared"},
        "locations": [
            {"physicalLocation": {"artifactLocation": {"uri": path}, "region": {"startLine": line}}}
        ],
    }


def document(results, tool="scanner"):
    return {"version": "2.1.0", "runs": [{"tool": {"driver": {"name": tool}}, "results": results}]}


def invoke(tmp_path, data, *args):
    path = tmp_path / "input.sarif"
    path.write_text(json.dumps(data))
    return subprocess.run(
        [sys.executable, str(HELPER), *args, str(path)], capture_output=True, text=True, check=False
    )


@pytest.mark.parametrize("change", ["rule", "path", "line", "message", "fingerprint-name", "tool"])
def test_partial_fingerprint_does_not_collapse_distinct_findings(change):
    left = document([finding()])
    right = copy.deepcopy(left)
    result = right["runs"][0]["results"][0]
    if change == "rule":
        result["ruleId"] = "OTHER"
    elif change == "path":
        result["locations"][0]["physicalLocation"]["artifactLocation"]["uri"] = "other/a.py"
    elif change == "line":
        result["locations"][0]["physicalLocation"]["region"]["startLine"] = 2
    elif change == "message":
        result["message"]["text"] = "same prefix but a distinct issue"
    elif change == "fingerprint-name":
        result["partialFingerprints"] = {"other/v1": "shared"}
    else:
        right["runs"][0]["tool"]["driver"]["name"] = "other"
    a, b = extract_findings(left), extract_findings(right)
    assert len(deduplicate(a + b + a)) == 2
    new, fixed, unchanged = diff_findings(a, b)
    assert (len(new), len(fixed), len(unchanged)) == (1, 1, 0)


def test_complete_fingerprint_tracks_moved_line_but_remains_file_scoped():
    first = finding()
    first["fingerprints"] = {"full/v1": "stable"}
    second = copy.deepcopy(first)
    second["locations"][0]["physicalLocation"]["region"]["startLine"] = 500
    a, b = extract_findings(document([first])), extract_findings(document([second]))
    assert [len(part) for part in diff_findings(a, b)] == [0, 0, 1]
    second["locations"][0]["physicalLocation"]["artifactLocation"]["uri"] = "other.py"
    assert len(deduplicate(a + extract_findings(document([second])))) == 2


@pytest.mark.parametrize(
    "shape", ["null", "missing", "failed-empty", "failed-partial", "mixed", "missing-runs"]
)
def test_incomplete_scans_are_machine_readable_errors(tmp_path, shape):
    data = document([])
    run = data["runs"][0]
    if shape == "null":
        run["results"] = None
    elif shape == "missing":
        del run["results"]
    elif shape == "missing-runs":
        del data["runs"]
    else:
        run["invocations"] = [{"executionSuccessful": False}]
        if shape == "failed-partial":
            run["results"] = [finding()]
        elif shape == "mixed":
            data["runs"].insert(0, document([finding()])["runs"][0])
    result = invoke(tmp_path, data, "summary")
    assert result.returncode == 2
    assert json.loads(result.stdout)["status"] == "error"
    assert "total" not in json.loads(result.stdout)
    with pytest.raises(ValueError):
        extract_findings(data)


def test_completed_empty_scan_is_clean(tmp_path):
    result = invoke(tmp_path, document([]), "summary")
    assert result.returncode == 0
    assert json.loads(result.stdout)["total"] == 0


@pytest.mark.parametrize(
    "command,flag", [("filter", "--limit"), ("dedupe", "--limit"), ("summary", "--top-rules")]
)
def test_negative_limits_rejected(tmp_path, command, flag):
    result = invoke(tmp_path, document([finding()]), command, flag, "-1")
    assert result.returncode == 2
    assert "nonnegative" in result.stderr


def test_previews_rank_late_errors_and_disclose_every_omission(tmp_path):
    data = document([finding(line=n) for n in range(1, 102)] + [finding(line=999, level="error")])
    result = json.loads(invoke(tmp_path, data, "dedupe").stdout)
    assert result["unique"] == 102 and result["omitted"] == 2
    assert result["by_level"] == {"warning": 101, "error": 1}
    assert result["findings"][0]["level"] == "error"
    assert (
        len(json.loads(invoke(tmp_path, data, "dedupe", "--limit", "0").stdout)["findings"]) == 102
    )
    assert len(json.loads(invoke(tmp_path, data, "dedupe", "--limit", "1").stdout)["findings"]) == 1
    baseline = tmp_path / "baseline.sarif"
    baseline.write_text(json.dumps(document([])))
    diff = json.loads(invoke(tmp_path, data, "diff", str(baseline)).stdout)
    assert diff["new"]["omitted"] == 2
    assert diff["new"]["findings"][0]["level"] == "error"


@pytest.mark.parametrize("cell", ["=1+1", "+cmd", "-cmd", "@SUM(A1)", "  =1+1", "\tcmd"])
def test_cli_csv_escapes_formulas_and_explicit_raw_mode_preserves_them(tmp_path, cell):
    data = document([finding(path=cell)])
    safe = list(csv.reader(io.StringIO(invoke(tmp_path, data, "csv").stdout)))
    raw = list(csv.reader(io.StringIO(invoke(tmp_path, data, "csv", "--raw-cells").stdout)))
    assert safe[1][2] == "'" + cell
    assert raw[1][2] == cell


def programs():
    jq_doc = (ROOT / "jq-queries.md").read_text()
    ci = (ROOT / "ci-gate.md").read_text()
    level_fn = re.search(r"LEVEL_FN='\n(.*?)'\n", jq_doc, re.S).group(1)
    gate = re.search(r"HIGH_COUNT=\$\(jq '\n(.*?)\n\s*' results\.sarif\)", ci, re.S).group(1)
    return [
        level_fn + '[.runs[] as $run | $run.results[] | select(level($run) == "error")] | length',
        gate,
    ]


@pytest.mark.parametrize("layout", ["2.0-list", "2.0-map", "2.1"])
def test_both_documented_resolvers_agree_with_python(tmp_path, layout):
    data = document(
        [
            {"ruleId": "R", "ruleIndex": -1, "message": {"text": "inherited"}},
            {"ruleId": "R", "kind": "pass", "message": {"text": "not failure"}},
            {"ruleId": "R", "level": "note", "message": {"text": "explicit"}},
        ]
    )
    run = data["runs"][0]
    rule = {"id": "R", "configuration": {"defaultLevel": "error"}}
    if layout == "2.1":
        run["tool"]["driver"]["rules"] = [{"id": "R", "defaultConfiguration": {"level": "error"}}]
    else:
        data["version"] = "2.0.0"
        run["resources"] = {
            "rules": [rule]
            if layout.endswith("list")
            else {"R": {"configuration": rule["configuration"]}}
        }
    original = copy.deepcopy(run)
    assert rules_for_run(run)[0]["id"] == "R"
    assert run == original
    assert [f.level for f in extract_findings(data)] == ["error", "none", "note"]
    path = tmp_path / "input.sarif"
    path.write_text(json.dumps(data))
    for program in programs():
        proc = subprocess.run(
            ["jq", program, str(path)], capture_output=True, text=True, check=False
        )
        assert proc.returncode == 0, proc.stderr
        assert json.loads(proc.stdout) == 1


@pytest.mark.parametrize(
    "results,invocations", [(None, []), ([], [{"executionSuccessful": False}])]
)
def test_documented_gates_fail_closed(tmp_path, results, invocations):
    data = document(results)
    data["runs"][0]["invocations"] = invocations
    path = tmp_path / "failed.sarif"
    path.write_text(json.dumps(data))
    for program in programs():
        proc = subprocess.run(
            ["jq", program, str(path)], capture_output=True, text=True, check=False
        )
        assert proc.returncode != 0
        assert proc.stdout == ""


def test_unknown_command_is_usage_error_not_traceback():
    proc = subprocess.run(
        [sys.executable, str(HELPER), "sumary"], capture_output=True, text=True, check=False
    )
    assert proc.returncode == 2
    assert "invalid choice" in proc.stderr and "Traceback" not in proc.stderr
