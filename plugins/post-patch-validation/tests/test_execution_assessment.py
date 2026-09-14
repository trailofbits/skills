from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest
from test_runner import create_repo, run, scaffold


@pytest.mark.parametrize(
    ("command", "exit_code", "baseline", "finding"),
    [
        ("import app; assert app.sanitize('safe') == 'safe'", 0, False, False),
        ("import app; assert app.sanitize('<') == '<'", 1, True, True),
        ("raise AssertionError('fails on both revisions')", 10, True, False),
        ("import time; time.sleep(3)", 10, False, False),
        (
            "import app, time; "
            "time.sleep(3 if app.sanitize('<') == '<' else 0); raise AssertionError('suite')",
            10,
            True,
            False,
        ),
    ],
)
def test_suite_runs_baseline_only_after_a_completed_failure(
    tmp_path: Path, command: str, exit_code: int, baseline: bool, finding: bool
) -> None:
    repo, _, _ = create_repo(tmp_path)
    plan = tmp_path / "case" / "plan.json"
    value = scaffold(repo, plan)
    value["checks"][-1].update(argv=[sys.executable, "-c", command], timeout_seconds=1)
    plan.write_text(json.dumps(value))
    output = tmp_path / "results"
    completed = run(plan, output)
    assert completed.returncode == exit_code, completed.stderr
    result = json.loads((output / "result.json").read_text())
    suite = result["checks"][-1]
    assert ("base" in suite["runs"]) == baseline
    assert bool(result["assessment"]["findings"]) == finding
    assert bool(result["assessment"]["gaps"]) == (exit_code == 10)
    if baseline:
        # Filenames preserve the actual patched-first execution order.
        assert suite["runs"]["patched"]["stdout"] < suite["runs"]["base"]["stdout"]
        for invocation in suite["runs"].values():
            assert (output / invocation["stderr"]).is_file()


@pytest.mark.parametrize("failure", ["missing-command", "missing-cwd"])
def test_execution_gap_keeps_both_independent_patch_failures(tmp_path: Path, failure: str) -> None:
    repo, _, _ = create_repo(
        tmp_path,
        "def sanitize(value):\n"
        "    if value is None:\n        return None\n"
        "    if value == '':\n        return 'oops'\n"
        "    return value.replace('<', '&lt;', 1)\n",
    )
    plan = tmp_path / "case" / "plan.json"
    value = scaffold(repo, plan)
    suite = value["checks"][-1]
    if failure == "missing-command":
        suite["argv"] = ["/nonexistent-ppv-command"]
    else:
        suite["cwd"] = "missing-project-directory"
    plan.write_text(json.dumps(value))
    output = tmp_path / "results"
    completed = run(plan, output)
    assert completed.returncode == 10, completed.stderr
    result = json.loads((output / "result.json").read_text())
    assessment = result["assessment"]
    assert {item["kind"] for item in assessment["findings"]} == {"variant", "regression"}
    assert assessment["gaps"][0]["check_id"] == suite["id"]
    assert "execution_error" in assessment["gaps"][0]["reason"]
    assert "base" not in result["checks"][-1]["runs"]
    assert result["checks"][-1]["runs"]["patched"]["error"]
    assert (output / "artifact-manifest.json").is_file()
