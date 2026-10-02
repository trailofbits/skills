"""Exercise the pipeline, real quality gate and suite verifier with a local fake CLI."""

from __future__ import annotations

import json
import os
import re
import subprocess
import sys
import textwrap
import zipfile
from pathlib import Path

import pytest

PIPELINE = Path(__file__).with_name("codeql_pipeline.sh")

FAKE_CODEQL = r"""
import json
import os
import shutil
import sys
from pathlib import Path

args = sys.argv[1:]
with Path(os.environ["INVOCATIONS"]).open("a") as log:
    log.write(json.dumps(args) + "\n")
phase = {("resolve", "database"): "database", ("resolve", "queries"): "suite",
         ("database", "analyze"): "analysis"}.get(tuple(args[:2]))
if not phase or phase == os.environ.get("FAIL_PHASE"):
    print("controlled CLI failure", file=sys.stderr)
    raise SystemExit(9)
if phase == "database":
    print(json.dumps({"languages": ["python"]}))
elif phase == "suite":
    assert Path(args[-1]).read_text().startswith("- description:")
    print("[]" if os.environ.get("EMPTY_SUITE") else '["queries/example.ql"]')
else:
    assert Path(args[-1]).is_file() and args[-2] == "--"
    output = next(arg.split("=", 1)[1] for arg in args if arg.startswith("--output="))
    shutil.copyfile(os.environ["SOURCE_SARIF"], output)
"""

FAKE_UV = r"""
import os
import sys
args = sys.argv[1:]
assert args.pop(0) == "run"
while args[0] in ("--no-project", "--quiet"):
    args.pop(0)
os.execv(sys.executable, [sys.executable, *args])
"""


@pytest.fixture
def scan(tmp_path):
    database = tmp_path / "database with spaces"
    database.mkdir()
    (database / "codeql-database.yml").write_text(
        "finalised: true\nsourceLocationPrefix: /project\n"
    )
    (database / "baseline-info.json").write_text(
        json.dumps({"languages": {"python": {"linesOfCode": 10}}})
    )
    with zipfile.ZipFile(database / "src.zip", "w") as archive:
        archive.writestr("project/main.py", "print('source')\n")
    rules = [
        {"id": "high", "properties": {"precision": "high"}},
        {"id": "medium", "properties": {"precision": "medium", "security-severity": "7"}},
        {"id": "low", "properties": {"precision": "low", "security-severity": "9"}},
    ]
    data = {
        "version": "2.1.0",
        "properties": {"retained": {"nested": [3, 2, 1]}},
        "runs": [
            {
                "tool": {"driver": {"name": "CodeQL", "rules": rules}},
                "results": [
                    {
                        "ruleIndex": index,
                        "ruleId": rule["id"],
                        "message": {"text": "Keep full text"},
                    }
                    for index, rule in enumerate(rules)
                ],
            }
        ],
    }
    source = tmp_path / "input.sarif"
    source.write_text(json.dumps(data, indent=2) + "\n")
    bindir = tmp_path / "bin"
    bindir.mkdir()
    for name, content in (("codeql", FAKE_CODEQL), ("uv", FAKE_UV)):
        executable = bindir / name
        executable.write_text(f"#!{sys.executable}\n{content}")
        executable.chmod(0o755)
    env = {
        **os.environ,
        "PATH": f"{bindir}{os.pathsep}{os.environ['PATH']}",
        "SOURCE_SARIF": str(source),
        "INVOCATIONS": str(tmp_path / "invocations.jsonl"),
    }
    return database, tmp_path / "output with spaces", source, env


def invoke(scan, *options):
    database, output, _, env = scan
    return subprocess.run(
        [
            "/bin/bash",
            str(PIPELINE),
            "--database",
            str(database),
            "--language",
            "python",
            "--out",
            str(output),
            *options,
        ],
        cwd=database.parent,
        env=env,
        capture_output=True,
        text=True,
        check=False,
    )


def selections(report):
    return {
        section.split(":\n", 1)[0]: section.split(":\n", 1)[1].strip().splitlines()
        for section in report.split("\n## ")[1:]
    }


@pytest.mark.parametrize("mode", ["run-all", "important-only"])
@pytest.mark.parametrize("empty", [False, True])
def test_complete_outputs_and_default_selections(scan, mode, empty):
    database, output, source, _ = scan
    data = json.loads(source.read_text())
    if empty:
        data["runs"][0]["results"] = []
        source.write_text(json.dumps(data))
    result = invoke(scan, "--mode", mode)
    assert result.returncode == 0, result.stderr
    assert (output / "raw/results.sarif").read_bytes() == source.read_bytes()
    if mode == "important-only":
        data["runs"][0]["results"] = data["runs"][0]["results"][:2]
    else:
        assert (output / "results/results.sarif").read_bytes() == source.read_bytes()
    assert json.loads((output / "results/results.sarif").read_text()) == data
    report = (output / "rulesets.txt").read_text()
    assert f"# Database: {database}\n" in report
    assert f"# Scan mode: {mode}\n" in report
    assert "# Language: python\n" in report
    assert selections(report) == {
        "Query packs": ["codeql/python-queries"],
        "Model packs": ["None"],
        "Additional pack directories": ["None"],
        "Threat models": ["default (remote)"],
    }
    results = data["runs"][0]["results"]
    assert json.loads((output / "summary.json").read_text()) == {
        "total": len(results),
        "by_level": {"warning": len(results)} if results else {},
        "top_rules": {item["ruleId"]: 1 for item in results},
    }
    assert json.loads((output / "quality.json").read_text())["project_files"] == 1
    assert (output / f"raw/{mode}.qls").is_file()


def test_records_and_propagates_every_selected_option(scan):
    _, output, _, env = scan
    options = [
        "--third-party-packs",
        "vendor/python-queries community/python-queries",
        "--threat-model",
        "local",
        "--threat-model",
        "environment",
        "--model-pack",
        "acme/python-models",
        "--model-pack",
        "other/python-models",
        "--additional-pack",
        "extensions with spaces",
        "--additional-pack",
        "other models",
    ]
    result = invoke(scan, *options)
    assert result.returncode == 0, result.stderr
    assert selections((output / "rulesets.txt").read_text()) == {
        "Query packs": [
            "codeql/python-queries",
            "vendor/python-queries",
            "community/python-queries",
        ],
        "Model packs": ["acme/python-models", "other/python-models"],
        "Additional pack directories": ["extensions with spaces", "other models"],
        "Threat models": ["local", "environment"],
    }
    calls = [json.loads(line) for line in Path(env["INVOCATIONS"]).read_text().splitlines()]
    analysis = next(call for call in calls if call[:2] == ["database", "analyze"])
    assert analysis[6:-2] == [
        "--threat-model",
        "local",
        "--threat-model",
        "environment",
        "--model-packs",
        "acme/python-models",
        "--model-packs",
        "other/python-models",
        "--additional-packs",
        "extensions with spaces",
        "--additional-packs",
        "other models",
    ]
    suite = (output / "raw/run-all.qls").read_text()
    assert "from: vendor/python-queries\n" in suite
    assert "from: community/python-queries\n" in suite


@pytest.mark.parametrize("failure", ["database", "quality", "suite", "empty-suite", "analysis"])
def test_failed_gates_never_publish_final_results(scan, failure):
    database, output, _, env = scan
    if failure == "quality":
        (database / "baseline-info.json").write_text(
            '{"languages": {"python": {"linesOfCode": 0}}}'
        )
    elif failure == "empty-suite":
        env["EMPTY_SUITE"] = "1"
    else:
        env["FAIL_PHASE"] = failure
    result = invoke(scan)
    assert result.returncode != 0
    assert not (output / "results/results.sarif").exists()
    assert not (output / "summary.json").exists()


def test_invalid_mode_fails_before_creating_output(scan):
    result = invoke(scan, "--mode", "typo")
    assert result.returncode == 2
    assert not scan[1].exists()


def test_approved_partial_database_preserves_quality_status_and_reason(scan):
    database, output, _, _ = scan
    diagnostics = database / "diagnostic" / "extractors" / "python"
    diagnostics.mkdir(parents=True)
    (diagnostics / "errors.jsonl").write_text('{"severity":"error"}\n')
    result = invoke(scan)
    assert result.returncode == 3
    status = json.loads((output / "run-status.json").read_text())
    assert status["status"] == "failed" and status["exit_code"] == 3
    quality = json.loads((Path(status["attempt"]) / "quality.json").read_text())
    assert quality["status"] == "failed" and quality["exit_code"] == 3
    assert "100.0%" in quality["error"]
    assert invoke(scan, "--max-error-ratio", "100").returncode == 2
    result = invoke(
        scan,
        "--max-error-ratio",
        "100",
        "--quality-reason",
        "User approved: only generated file fails",
    )
    assert result.returncode == 0, result.stderr
    assert "only generated file fails" in (output / "rulesets.txt").read_text()
    assert json.loads((output / "quality.json").read_text())["error_ratio"] == 100
    (database / "baseline-info.json").write_text('{"languages":{"python":{"linesOfCode":0}}}')
    result = invoke(scan, "--max-error-ratio", "100", "--quality-reason", "approved")
    assert result.returncode != 0
    assert not (output / "summary.json").exists()


def test_failed_retry_archives_prior_results_and_can_recover(scan):
    _, output, source, env = scan
    assert invoke(scan).returncode == 0
    previous = (output / "summary.json").read_bytes()
    env["FAIL_PHASE"] = "analysis"
    result = invoke(scan, "--mode", "important-only")
    assert result.returncode == 9
    state = json.loads((output / "run-status.json").read_text())
    assert state["status"] == "failed" and state["exit_code"] == 9
    attempt = Path(state["attempt"])
    assert (attempt / "previous/summary.json").read_bytes() == previous
    assert (attempt / "previous/raw/results.sarif").read_bytes() == source.read_bytes()
    assert "# Scan mode: important-only" in (attempt / "rulesets.txt").read_text()
    assert not (output / "summary.json").exists()
    assert not (output / "results/results.sarif").exists()
    assert not (output / "rulesets.txt").exists()
    assert not (output / ".codeql-run.lock").exists()
    del env["FAIL_PHASE"]
    assert invoke(scan).returncode == 0
    assert json.loads((output / "run-status.json").read_text())["status"] == "complete"
    assert (output / "summary.json").read_bytes() == previous
    assert (attempt / "previous/summary.json").is_file()


def test_runtime_options_reach_codeql(scan):
    result = invoke(scan, "--threads", "2", "--timeout", "90", "--rerun")
    assert result.returncode == 0, result.stderr
    calls = [json.loads(line) for line in Path(scan[3]["INVOCATIONS"]).read_text().splitlines()]
    args = next(call for call in calls if call[:2] == ["database", "analyze"])
    assert "--threads=2" in args
    assert args[args.index("--timeout") + 1] == "90"
    assert "--rerun" in args
    reference = (PIPELINE.parent.parent / "references/performance-tuning.md").read_text()
    assert "| `--timeout` | `600` | Seconds." in reference
    assert "Milliseconds" not in reference


def test_an_existing_lock_does_not_overwrite_results(scan):
    _, output, _, _ = scan
    output.mkdir()
    (output / ".codeql-run.lock").mkdir()
    report = output / "summary.json"
    report.write_text("prior evidence")
    assert invoke(scan).returncode == 2
    assert report.read_text() == "prior evidence"


def test_documented_plan_runs_in_fresh_shell_with_all_accepted_defaults(scan):
    database, output, _, env = scan
    skill = PIPELINE.parent.parent
    block = re.search(
        r"```bash\n( +# Accepted analysis plan:.*?)\n +```", (skill / "SKILL.md").read_text(), re.S
    )
    assert block, "the executable accepted-plan example must stay testable"
    command = textwrap.dedent(block.group(1))
    command = command.replace("{baseDir}", str(skill))
    command = command.replace("/absolute/selected/database", str(database))
    command = command.replace("/absolute/output", str(output))
    command = command.replace(
        "/absolute/model-directory", str(database.parent / "model with spaces")
    )
    result = subprocess.run(
        ["bash", "-c", command],
        cwd=database.parent,
        env=env,
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 0, result.stderr
    chosen = selections((output / "rulesets.txt").read_text())
    assert chosen == {
        "Query packs": [
            "codeql/python-queries",
            "vendor/python-queries",
            "community/python-queries",
        ],
        "Model packs": ["acme/python-models"],
        "Additional pack directories": [str(database.parent / "model with spaces")],
        "Threat models": ["remote"],
    }
    calls = [json.loads(line) for line in Path(env["INVOCATIONS"]).read_text().splitlines()]
    args = next(call for call in calls if call[:2] == ["database", "analyze"])
    assert args[args.index("--model-packs") + 1] == "acme/python-models"
    assert args[args.index("--additional-packs") + 1] == chosen["Additional pack directories"][0]
    assert args[args.index("--threat-model") + 1] == "remote"
    suite = (output / "raw/run-all.qls").read_text()
    assert "vendor/python-queries" in suite and "community/python-queries" in suite


def test_documented_build_passes_same_selected_output_to_workflow(scan):
    skill = PIPELINE.parent.parent
    text = (skill / "SKILL.md").read_text()
    payload = json.loads(re.search(r"/static-analysis:codeql-build (\{.*\})", text)[1])
    assert payload["out"] == "/absolute/output"
    assert 'OUTPUT_DIR="/absolute/output"' in text
    workflow = (skill.parents[1] / "workflows/codeql-build.js").read_text()
    assert "Use the output directory given above" in workflow
    assert '"$SKILL_DIR/scripts/resolve_output_dir.sh" with no arguments once' in workflow
