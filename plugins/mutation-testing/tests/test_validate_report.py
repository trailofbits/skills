"""Exercise the report grader and smoke runner without making model calls."""

import importlib.util
import os
import subprocess
import sys
from pathlib import Path

import pytest

TESTS = Path(__file__).parent
FIXTURES = TESTS / "fixtures"
SPEC = importlib.util.spec_from_file_location("validate_report", TESTS / "validate_report.py")
assert SPEC is not None and SPEC.loader is not None
validate_report = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(validate_report)


def test_accepts_reference_report():
    assert validate_report.check((FIXTURES / "good-report.md").read_text()) == []


@pytest.mark.parametrize(
    ("filename", "reason"),
    [
        ("broken-filters-both.md", "`balance >= 0` is listed as an equivalent mutant"),
        ("broken-filters-neither.md", "`balance != 0` is not listed as an equivalent mutant"),
    ],
)
def test_rejects_equivalence_errors(filename, reason):
    failures = validate_report.check((FIXTURES / filename).read_text())
    assert any(reason in failure for failure in failures)


def test_rejects_unstructured_report():
    with pytest.raises(validate_report.ReportError, match="no markdown headings"):
        validate_report.check("This is an analysis without sections.")


def test_rejects_missing_equivalence_section():
    with pytest.raises(validate_report.ReportError, match="no equivalent-mutants section"):
        validate_report.check("# Report\n## Findings\nNo classifications supplied.")


@pytest.mark.parametrize("text", ["", "# Report\nTODO"])
def test_cli_rejects_empty_or_stub_report(tmp_path, text):
    report = tmp_path / "report.md"
    report.write_text(text)
    result = subprocess.run(
        [sys.executable, str(TESTS / "validate_report.py"), str(report)],
        capture_output=True,
        text=True,
    )
    assert result.returncode == 1
    assert "a stub, not an analysis" in result.stderr


def test_cli_reports_missing_file(tmp_path):
    result = subprocess.run(
        [sys.executable, str(TESTS / "validate_report.py"), str(tmp_path / "absent.md")],
        capture_output=True,
        text=True,
    )
    assert result.returncode == 2
    assert "cannot read report" in result.stderr


def test_expected_failure_rejects_good_report():
    result = subprocess.run(
        [
            sys.executable,
            str(TESTS / "validate_report.py"),
            str(FIXTURES / "good-report.md"),
            "--expect-fail",
        ],
        capture_output=True,
        text=True,
    )
    assert result.returncode == 1
    assert "expected to fail validation but passed" in result.stderr


@pytest.fixture
def fake_claude(tmp_path):
    tool = tmp_path / "bin" / "claude"
    tool.parent.mkdir()
    tool.write_text(
        """#!/usr/bin/env python3
import json
import os
import pathlib
import shutil
import sys

args = sys.argv[1:]
assert '--no-publish' in args
assert args[args.index('--ablation') + 1] == 'none'
outcome = os.environ['MOCK_EVAL_OUTCOME']
result = {
    'partial': outcome == 'partial',
    'aggregates': {'casesTotal': 0 if outcome == 'empty' else 1,
                   'casesPassed': 1, 'overallScore': 1},
}
pathlib.Path(args[args.index('--json') + 1]).write_text(json.dumps(result))
if outcome != 'missing':
    sandbox = pathlib.Path(os.environ['TMPDIR']) / 'claude-eval-smoke'
    sandbox.mkdir()
    fixture = 'broken-filters-both.md' if outcome == 'bad' else 'good-report.md'
    shutil.copyfile(pathlib.Path(os.environ['REPORT_FIXTURES']) / fixture,
                    sandbox / 'mutation-testing-report.md')
"""
    )
    tool.chmod(0o755)
    return tool.parent


@pytest.mark.parametrize(
    ("outcome", "success", "message"),
    [
        ("good", True, "1 agent report(s) validated"),
        ("missing", False, "left no mutation-testing-report.md"),
        ("bad", False, "`balance >= 0` is listed as an equivalent mutant"),
        ("partial", False, "eval run was partial"),
        ("empty", False, "eval matched no cases"),
    ],
)
def test_smoke_checks_only_its_own_artifacts(tmp_path, fake_claude, outcome, success, message):
    # A valid unrelated report must not make a run with missing output pass.
    unrelated = tmp_path / "claude-eval-other"
    unrelated.mkdir()
    (unrelated / "mutation-testing-report.md").write_text((FIXTURES / "good-report.md").read_text())
    env = dict(
        os.environ,
        PATH=f"{fake_claude}{os.pathsep}{os.environ['PATH']}",
        TMPDIR=str(tmp_path),
        ANTHROPIC_API_KEY="mock-not-a-credential",
        DETERMINISTIC_ONLY="0",
        KEEP_ARTIFACTS="1",
        MOCK_EVAL_OUTCOME=outcome,
        REPORT_FIXTURES=str(FIXTURES),
    )
    result = subprocess.run(
        ["/bin/bash", str(TESTS / "smoke-test.sh")],
        env=env,
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert (result.returncode == 0) is success, result.stdout + result.stderr
    assert message in result.stdout + result.stderr
