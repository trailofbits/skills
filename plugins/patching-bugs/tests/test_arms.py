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


def test_cargo_target_dir_is_private_to_each_source_arm(bug_repo, tmp_path, monkeypatch):
    repo, baseline, patch = bug_repo
    shared_target = tmp_path / "shared-cargo-target"
    monkeypatch.setenv("CARGO_TARGET_DIR", str(shared_target))
    build = tmp_path / "build_from_source.py"
    build.write_text(
        """import os
from pathlib import Path

target = Path(os.environ["CARGO_TARGET_DIR"])
target.mkdir(parents=True, exist_ok=True)
artifact = target / "app.py"
if not artifact.exists():
    artifact.write_bytes(Path("app.py").read_bytes())
print(target.resolve())
"""
    )
    poc = tmp_path / "run_built_source.py"
    poc.write_text(
        """import hashlib
import json
import os
from pathlib import Path

artifact = Path(os.environ["CARGO_TARGET_DIR"]) / "app.py"
data = artifact.read_bytes()
print("PATCH_LOADED " + json.dumps({
    "path": str(artifact.resolve()), "sha256": hashlib.sha256(data).hexdigest()
}))
print("PATCH_REACHED")
raise SystemExit(0 if b"Path(name).name" in data else 1)
"""
    )
    out = tmp_path / "proof"
    result = run_arms(
        repo,
        baseline,
        patch,
        ArmSpec([sys.executable, str(build)], [sys.executable, str(poc)], "target/app.py", 30),
        out,
    )
    assert result["reverted"] == "pass"
    assert result["build_identity"] == "pass"
    assert result["hashes"]["baseline"] == result["hashes"]["reverted"]
    assert result["hashes"]["baseline"] != result["hashes"]["patched"]
    targets = {
        name: Path((out / "receipts" / name / "build/stdout.txt").read_text().strip())
        for name in ("baseline", "patched", "reverted")
    }
    assert len(set(targets.values())) == 3
    assert all(path.name == "target" and path.parent.name == name for name, path in targets.items())
    assert not shared_target.exists()
    for name in targets:
        assert json.loads((out / "receipts" / name / "arm.json").read_text())["loaded_identity"]


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
