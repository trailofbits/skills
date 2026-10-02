"""Run the documented Semgrep checks on quality and advanced-taint examples.

These test CLI semantics and the nonempty-test contract, not model auto-selection.
Semgrep is a prerequisite, installed by the repository's Python CI job.
"""

import json
import re
import shutil
import subprocess
from pathlib import Path

import pytest
import yaml

FIXTURES = Path(__file__).parent / "fixtures"
CASES = ("code-quality", "side-effects", "propagation", "labels")


def semgrep(*args, cwd=None):
    binary = shutil.which("semgrep")
    assert binary, "Install Semgrep before running this integration suite"
    return subprocess.run(
        [binary, *map(str, args), "--metrics", "off", "--disable-version-check"],
        cwd=cwd,
        text=True,
        capture_output=True,
        timeout=60,
    )


def annotated_lines(source, kind, rule_id):
    return {
        number + 1
        for number, line in enumerate(source.splitlines(), start=1)
        if re.fullmatch(rf"\s*# {kind}: {re.escape(rule_id)}\s*", line)
    }


def graded_checks(payload):
    return [
        (rule_id, check)
        for result in payload.get("results", {}).values()
        for rule_id, check in result.get("checks", {}).items()
    ]


@pytest.mark.parametrize("case", CASES)
def test_examples_grade_positive_and_negative_cases_and_full_scan(case):
    rule = FIXTURES / f"{case}.yaml"
    target = FIXTURES / f"{case}.py"
    source = target.read_text()
    positive = annotated_lines(source, "ruleid", case)
    negative = annotated_lines(source, "ok", case)
    assert positive and negative and positive.isdisjoint(negative)

    run = semgrep("--test", "--json", "--config", rule, target)
    assert run.returncode == 0, run.stdout + run.stderr
    payload = json.loads(run.stdout)
    assert not payload["config_missing_tests"]
    assert not payload["config_with_errors"]
    checks = graded_checks(payload)
    assert len(checks) == 1 and checks[0][0] == case
    check = checks[0][1]
    assert check["passed"] and not check["errors"]
    matches = list(check["matches"].values())
    assert len(matches) == 1
    assert set(matches[0]["expected_lines"]) == positive
    assert set(matches[0]["reported_lines"]) == positive

    scan = semgrep("scan", "--oss-only", "--json", "--config", rule, target)
    assert scan.returncode == 0, scan.stdout + scan.stderr
    output = json.loads(scan.stdout)
    assert not output["errors"]
    assert {item["start"]["line"] for item in output["results"]} == positive
    assert len(output["results"]) == len(positive)
    for result in output["results"]:
        assert Path(result["path"]).resolve() == target.resolve()
        assert result["check_id"].split(".")[-1] == case
        assert "$" not in result["extra"]["message"]


@pytest.mark.parametrize("case", CASES)
def test_nonmatching_control_fails_positive_expectations(case, tmp_path):
    original = yaml.safe_load((FIXTURES / f"{case}.yaml").read_text())["rules"][0]
    rule = {key: original[key] for key in ("id", "languages", "severity", "message")}
    rule["pattern"] = "__semgrep_regression_no_match__()"
    config = tmp_path / f"{case}.yaml"
    config.write_text(yaml.safe_dump({"rules": [rule]}))
    target = tmp_path / f"{case}.py"
    target.write_text((FIXTURES / f"{case}.py").read_text())
    run = semgrep("--test", "--json", "--config", config, target, cwd=tmp_path)
    assert run.returncode != 0, run.stdout + run.stderr
    checks = graded_checks(json.loads(run.stdout))
    assert checks and all(not check["passed"] for _, check in checks)


def test_zero_graded_cases_is_not_accepted_as_success(tmp_path):
    config = tmp_path / "empty.yaml"
    config.write_text((FIXTURES / "code-quality.yaml").read_text())
    target = tmp_path / "empty.py"
    target.write_text("value = 1\n")
    run = semgrep("--test", "--json", "--config", config, target, cwd=tmp_path)
    # Some Semgrep versions return 0, others reject the empty suite. Neither is
    # allowed to satisfy the documented nonzero-positive/negative contract.
    assert not annotated_lines(target.read_text(), "ruleid", "code-quality")
    checks = graded_checks(json.loads(run.stdout))
    assert not checks or not any(
        match["expected_lines"] for _, check in checks for match in check["matches"].values()
    )
