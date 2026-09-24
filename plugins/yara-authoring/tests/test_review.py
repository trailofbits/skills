"""Exercise the review wrapper without requiring YARA-X or downloading packages."""

from __future__ import annotations

import json
import os
import shutil
import subprocess
from pathlib import Path

import pytest

REVIEW = Path(__file__).parents[1] / "skills/yara-rule-authoring/scripts/review.sh"


@pytest.fixture
def review_env(tmp_path):
    jq = shutil.which("jq")
    if not jq:
        pytest.skip("review.sh requires jq")
    bindir = tmp_path / "bin"
    bindir.mkdir()
    for name in ("bash", "dirname", "mktemp", "rm"):
        executable = shutil.which(name)
        assert executable, f"missing test dependency: {name}"
        (bindir / name).symlink_to(executable)
    (bindir / "jq").symlink_to(jq)
    scratch = tmp_path / "scratch"
    scratch.mkdir()
    for name in ("yr", "uv"):
        fake = bindir / name
        fake.write_text(
            "#!/bin/bash\n"
            'printf "%s\\n" "$@"\n'
            'printf "diagnostic: complete stderr\\n" >&2\n'
            'exit "${CHECK_STATUS:-0}"\n'
        )
        fake.chmod(0o755)
    return {**os.environ, "PATH": str(bindir), "TMPDIR": str(scratch)}


def review(env, *args):
    return subprocess.run(
        ["/bin/bash", str(REVIEW), *map(str, args)],
        env=env,
        capture_output=True,
        text=True,
        check=False,
    )


@pytest.mark.parametrize("status", [0, 7])
def test_preserves_complete_outputs_and_statuses(review_env, tmp_path, status):
    target = tmp_path / "rule with spaces.yar"
    target.write_text("rule Example { condition: true }")
    result = review({**review_env, "CHECK_STATUS": str(status)}, target)
    assert result.returncode == (1 if status else 0)
    checks = json.loads(result.stdout)
    scripts = REVIEW.parent
    expected_args = {
        "yr_check": ["check", "--", str(target)],
        "yr_format": ["fmt", "--check", "--", str(target)],
        "lint": ["run", "--quiet", str(scripts / "yara_lint.py"), "--json", "--", str(target)],
        "atoms": ["run", "--quiet", str(scripts / "atom_analyzer.py"), "--", str(target)],
    }
    assert checks == {
        "target": str(target),
        "checks": {
            name: {
                "status": status,
                "output": "\n".join(args) + "\ndiagnostic: complete stderr\n",
            }
            for name, args in expected_args.items()
        },
    }
    assert not list(Path(review_env["TMPDIR"]).iterdir())


def test_directory_check_reaches_nested_rules(review_env, tmp_path):
    nested = tmp_path / "rules" / "nested"
    nested.mkdir(parents=True)
    result = review(review_env, nested.parent)
    assert result.returncode == 0
    checks = json.loads(result.stdout)["checks"]
    assert checks["yr_check"]["output"].startswith("check\n--recursive\n--\n")
    assert checks["yr_format"]["output"].startswith("fmt\n--check\n--recursive\n--\n")


def test_missing_command_fails_but_keeps_other_results(review_env, tmp_path):
    (Path(review_env["PATH"]) / "yr").unlink()
    result = review(review_env, tmp_path / "rule.yar")
    assert result.returncode == 1
    checks = json.loads(result.stdout)["checks"]
    assert checks["yr_check"]["status"] == 127
    assert checks["yr_format"]["status"] == 127
    assert checks["lint"]["status"] == checks["atoms"]["status"] == 0
    assert "command not found" in checks["yr_check"]["output"]
    assert not list(Path(review_env["TMPDIR"]).iterdir())


def test_missing_json_tool_is_not_a_success(review_env, tmp_path):
    (Path(review_env["PATH"]) / "jq").unlink()
    result = review(review_env, tmp_path / "rule.yar")
    assert result.returncode == 2
    assert "jq is required" in result.stderr
    assert not result.stdout


def test_missing_python_runner_keeps_cli_results(review_env, tmp_path):
    (Path(review_env["PATH"]) / "uv").unlink()
    result = review(review_env, tmp_path / "rule.yar")
    assert result.returncode == 1
    checks = json.loads(result.stdout)["checks"]
    assert checks["yr_check"]["status"] == checks["yr_format"]["status"] == 0
    assert checks["lint"]["status"] == checks["atoms"]["status"] == 127
    assert "command not found" in checks["lint"]["output"]
    assert not list(Path(review_env["TMPDIR"]).iterdir())


def test_usage_rejects_missing_target(review_env):
    result = review(review_env)
    assert result.returncode == 2
    assert "usage:" in result.stderr


def test_usage_rejects_extra_target(review_env):
    result = review(review_env, "one.yar", "two.yar")
    assert result.returncode == 2
    assert "usage:" in result.stderr
    assert not result.stdout
