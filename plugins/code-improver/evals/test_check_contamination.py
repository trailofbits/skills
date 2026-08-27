"""The contamination gate is itself a checker, so it gets the zero-items treatment:
each test proves it detects its target against a planted specimen, and that having
nothing to inspect is an error, never a pass."""

import json
import subprocess
import sys
from pathlib import Path

import pytest

SCRIPT = Path(__file__).with_name("check_contamination.py")


def run_checker(tmp_path, result):
    p = tmp_path / "result.json"
    p.write_text(json.dumps(result), encoding="utf-8")
    return subprocess.run(
        [sys.executable, str(SCRIPT), str(p)], capture_output=True, text=True, check=False
    )


def make_result(runs, arm="with"):
    return {"cases": [{"name": "structural-escalation", "arms": {arm: runs}}]}


def clean_run(tmp_path, trace_content="the agent improved the skill and escalated"):
    trace = tmp_path / "trace.jsonl"
    trace.write_text(trace_content, encoding="utf-8")
    return {
        "graders": [{"name": "g", "explanation": "the ledger shows an escalation, PASS"}],
        "tracePath": str(trace),
    }


def test_clean_result_passes(tmp_path):
    proc = run_checker(tmp_path, make_result([clean_run(tmp_path)]))
    assert proc.returncode == 0, proc.stderr
    assert "clean" in proc.stdout


def test_no_runs_is_an_error(tmp_path):
    proc = run_checker(tmp_path, {"cases": []})
    assert proc.returncode == 1
    assert "no runs" in proc.stderr


def test_nothing_to_inspect_is_an_error(tmp_path):
    run = {"graders": [{"name": "g", "explanation": ""}], "tracePath": ""}
    proc = run_checker(tmp_path, make_result([run]))
    assert proc.returncode == 1
    assert "nothing to inspect" in proc.stderr


# Both the current eval-tree path and the pre-rename one (old-version arms are built
# from the plugin's history) must stay detected.
@pytest.mark.parametrize("prefix", ["code-improver", "skill-improver"])
def test_path_marker_in_judge_text_is_flagged(tmp_path, prefix):
    run = clean_run(tmp_path)
    run["graders"][0]["explanation"] = (
        f"the response cites plugins/{prefix}/evals/structural-escalation"
    )
    proc = run_checker(tmp_path, make_result([run]))
    assert proc.returncode == 1
    assert "judge text" in proc.stderr


def test_grader_slug_in_agent_trace_is_flagged(tmp_path):
    trace = tmp_path / "trace.jsonl"
    trace.write_text("Read(escalated-within-four-rounds.md)", encoding="utf-8")
    run = {"graders": [{"name": "g", "explanation": "PASS"}], "tracePath": str(trace)}
    proc = run_checker(tmp_path, make_result([run]))
    assert proc.returncode == 1
    assert "agent trace" in proc.stderr


def test_grader_slug_in_judge_text_alone_is_not_flagged(tmp_path):
    # Judges legitimately restate their own grader; only the agent trace makes it
    # contamination.
    run = clean_run(tmp_path)
    run["graders"][0]["explanation"] = "per the escalated-within-four-rounds rubric, PASS"
    proc = run_checker(tmp_path, make_result([run]))
    assert proc.returncode == 0, proc.stderr


def test_expected_outcome_in_trace_is_flagged(tmp_path):
    run = clean_run(tmp_path, trace_content="cat case.yaml → expected_outcome: the loop stops")
    proc = run_checker(tmp_path, make_result([run]))
    assert proc.returncode == 1


def test_legacy_evidence_key_is_read(tmp_path):
    run = {
        "graders": [{"name": "g", "evidence": "cites plugins/skill-improver/evals/x"}],
        "tracePath": "",
    }
    proc = run_checker(tmp_path, make_result([run]))
    assert proc.returncode == 1


@pytest.mark.parametrize("prefix", ["code-improver", "skill-improver"])
def test_trace_directory_is_scanned(tmp_path, prefix):
    trace_dir = tmp_path / "trace"
    trace_dir.mkdir()
    (trace_dir / "agent-1.jsonl").write_text(f"ls {prefix}/evals/", encoding="utf-8")
    run = {"graders": [{"name": "g", "explanation": "PASS"}], "tracePath": str(trace_dir)}
    proc = run_checker(tmp_path, make_result([run]))
    assert proc.returncode == 1


def test_allow_listing_tolerates_the_path_but_not_content(tmp_path):
    trace = tmp_path / "trace.jsonl"
    trace.write_text("find /x/skill-improver/evals/ -type f", encoding="utf-8")
    run = {"graders": [{"name": "g", "explanation": "PASS"}], "tracePath": str(trace)}
    result = make_result([run])
    p = tmp_path / "result.json"
    p.write_text(json.dumps(result), encoding="utf-8")
    strict = subprocess.run(
        [sys.executable, str(SCRIPT), str(p)], capture_output=True, text=True, check=False
    )
    assert strict.returncode == 1  # a listing is contamination under readable names
    relaxed = subprocess.run(
        [sys.executable, str(SCRIPT), "--allow-listing", str(p)],
        capture_output=True,
        text=True,
        check=False,
    )
    assert relaxed.returncode == 0, relaxed.stderr

    trace.write_text("cat r3.md → Score PASS if ALL hold", encoding="utf-8")
    read_body = subprocess.run(
        [sys.executable, str(SCRIPT), "--allow-listing", str(p)],
        capture_output=True,
        text=True,
        check=False,
    )
    assert read_body.returncode == 1  # reading a grader body is contamination in any mode
