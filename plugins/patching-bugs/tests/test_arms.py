import json
import shutil
import subprocess
import sys
from pathlib import Path

import pytest
from arms import ArmSpec, run_arms
from records import verify_manifest

FIXTURE = Path(__file__).parent / "fixtures/planted-bug"


def git(repo, *args):
    return subprocess.check_output(["git", "-C", str(repo), *args], text=True).strip()


@pytest.fixture
def bug_repo(tmp_path):
    repo = tmp_path / "repo"
    shutil.copytree(FIXTURE, repo)
    git(repo, "init", "-q")
    git(repo, "config", "user.email", "test@example.org")
    git(repo, "config", "user.name", "Test")
    git(repo, "add", ".")
    git(repo, "commit", "-qm", "baseline")
    baseline = git(repo, "rev-parse", "HEAD")
    source = repo / "app.py"
    source.write_text(
        source.read_text().replace(
            'target = Path("uploads") / name', 'target = Path("uploads") / Path(name).name'
        )
    )
    git(repo, "add", "app.py")
    git(repo, "commit", "-qm", "fix")
    return repo, baseline, git(repo, "rev-parse", "HEAD")


def spec(poc="poc.py"):
    return ArmSpec([sys.executable, "build.py"], [sys.executable, poc], "dist/app.py", 30)


def test_fixed_patch_reverts_and_artifact_changes(bug_repo, tmp_path):
    repo, baseline, patch = bug_repo
    head_before = git(repo, "rev-parse", "HEAD")
    worktrees_before = git(repo, "worktree", "list", "--porcelain")
    out = tmp_path / "proof"
    result = run_arms(repo, baseline, patch, spec(), out)
    assert result["reverted"] == "pass"
    assert result["build_identity"] == "pass"
    assert git(repo, "rev-parse", "HEAD") == head_before
    assert git(repo, "worktree", "list", "--porcelain") == worktrees_before
    verify_manifest(out)
    assert json.loads((out / "manifest.json").read_text())["files"]


def test_build_failure_cannot_reuse_old_artifact(bug_repo, tmp_path):
    repo, baseline, _ = bug_repo
    (repo / "build.py").write_text('raise SystemExit("build broken")\n')
    git(repo, "add", "build.py")
    git(repo, "commit", "-qm", "break build")
    result = run_arms(repo, baseline, git(repo, "rev-parse", "HEAD"), spec(), tmp_path / "proof")
    assert result["build_identity"] == "fail"


def test_crash_before_reach_is_inconclusive(bug_repo, tmp_path):
    repo, baseline, patch = bug_repo
    (repo / "crash.py").write_text('raise RuntimeError("setup failed")\n')
    git(repo, "add", "crash.py")
    git(repo, "commit", "-qm", "crash fixture")
    result = run_arms(repo, baseline, patch, spec("crash.py"), tmp_path / "proof")
    assert result["reverted"] == "inconclusive"


def test_unfixed_patch_fails_reverted_arm(bug_repo, tmp_path):
    repo, baseline, _ = bug_repo
    (repo / "app.py").write_text(FIXTURE.joinpath("app.py").read_text())
    git(repo, "add", "app.py")
    git(repo, "commit", "-qm", "reintroduce bug")
    result = run_arms(repo, baseline, git(repo, "rev-parse", "HEAD"), spec(), tmp_path / "proof")
    assert result["reverted"] == "fail"


def test_binary_poc_output_is_saved(bug_repo, tmp_path):
    repo, baseline, patch = bug_repo
    poc = tmp_path / "binary_poc.py"
    poc.write_text('import sys\nsys.stdout.buffer.write(b"PATCH_REACHED\\n\\xff\\n")\n')
    run_arms(repo, baseline, patch, spec(str(poc)), tmp_path / "proof")
    assert b"\xff" in (tmp_path / "proof/receipts/baseline/poc/stdout.txt").read_bytes()


def test_reverted_arm_needs_no_git_identity(bug_repo, tmp_path, monkeypatch):
    repo, baseline, patch = bug_repo
    git(repo, "config", "--unset", "user.name")
    git(repo, "config", "--unset", "user.email")
    git(repo, "config", "user.useConfigOnly", "true")
    monkeypatch.setenv("GIT_CONFIG_GLOBAL", "/dev/null")
    monkeypatch.setenv("GIT_CONFIG_NOSYSTEM", "1")
    monkeypatch.setenv("HOME", str(tmp_path))
    for key in (
        "GIT_AUTHOR_NAME",
        "GIT_AUTHOR_EMAIL",
        "GIT_COMMITTER_NAME",
        "GIT_COMMITTER_EMAIL",
        "EMAIL",
    ):
        monkeypatch.delenv(key, raising=False)
    result = run_arms(repo, baseline, patch, spec(), tmp_path / "proof")
    assert result["reverted"] == "pass"
