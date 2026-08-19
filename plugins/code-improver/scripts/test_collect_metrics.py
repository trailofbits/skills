"""CLI-level tests for collect_metrics.py.

The collector's contract is that inspecting zero items fails: every test that plants
nothing asserts exit 2, and every counting metric is proven against a specimen that
contains the thing being counted, so a collector that stopped matching anything cannot
stay green.
"""

import json
import subprocess
import sys
from pathlib import Path

SCRIPT = Path(__file__).with_name("collect_metrics.py")


def run(*argv, cwd=None):
    return subprocess.run(
        [sys.executable, str(SCRIPT), *argv], capture_output=True, text=True, cwd=cwd, check=False
    )


def make_ledger(tmp_path, **overrides):
    ledger = {
        "version": 1,
        "skill": "/repo/plugins/demo/skills/demo",
        "scope": ["plugins/demo/**"],
        "rounds": [
            {
                "round": 1,
                "type": "review",
                "open": {"critical": 1, "major": 0, "minor": 1, "info": 0},
            },
            {
                "round": 1,
                "type": "fix",
                "verdicts": {"fixed": 1, "rejected": 1, "deferred": 0},
                "failed": False,
            },
            {
                "round": 2,
                "type": "review",
                "open": {"critical": 0, "major": 0, "minor": 1, "info": 0},
            },
        ],
        "findings": {
            "a.md:3:dangling-reference": {
                "status": "fixed",
                "severity": "critical",
                "rounds_seen": [1],
                "refiled_after_verdict": 0,
            },
            "a.md:1:non-gerund-name": {
                "status": "rejected",
                "severity": "major",
                "rounds_seen": [1],
                "refiled_after_verdict": 2,
            },
            "a.md:40:verbose-line": {
                "status": "open",
                "severity": "minor",
                "rounds_seen": [1, 2, 3, 7],
                "refiled_after_verdict": 0,
            },
        },
        "result": {"converged": True, "capped": False, "escalation": None, "halted": ""},
    }
    ledger.update(overrides)
    path = tmp_path / "ledger.json"
    path.write_text(json.dumps(ledger), encoding="utf-8")
    return path


def read_metrics(tmp_path):
    return json.loads((tmp_path / "metrics.json").read_text(encoding="utf-8"))


def git(repo, *argv):
    subprocess.run(["git", "-C", str(repo), *argv], capture_output=True, check=True)


def make_repo(tmp_path):
    repo = tmp_path / "repo"
    (repo / "plugins/demo/skills/demo").mkdir(parents=True)
    (repo / "plugins/demo/skills/demo/SKILL.md").write_text("clean content\n", encoding="utf-8")
    (repo / "outside.md").write_text("out of scope\n", encoding="utf-8")
    git(repo.parent, "init", "-q", str(repo))
    git(repo, "add", "-A")
    git(
        repo,
        "-c",
        "user.name=t",
        "-c",
        "user.email=t@t",
        "commit",
        "-qm",
        "baseline",
    )
    sha = subprocess.run(
        ["git", "-C", str(repo), "rev-parse", "HEAD"], capture_output=True, text=True, check=True
    ).stdout.strip()
    return repo, sha


# ---------------------------------------------------------------- zero-items guards


def test_missing_ledger_fails(tmp_path):
    proc = run("--ledger", str(tmp_path / "absent.json"), "--out", str(tmp_path / "m.json"))
    assert proc.returncode == 2
    assert "ledger not found" in proc.stderr
    assert not (tmp_path / "m.json").exists()


def test_unparseable_ledger_fails(tmp_path):
    bad = tmp_path / "ledger.json"
    bad.write_text("{nope", encoding="utf-8")
    proc = run("--ledger", str(bad), "--out", str(tmp_path / "m.json"))
    assert proc.returncode == 2
    assert "not valid JSON" in proc.stderr


def test_zero_rounds_fails(tmp_path):
    ledger = make_ledger(tmp_path, rounds=[])
    proc = run("--ledger", str(ledger), "--out", str(tmp_path / "m.json"))
    assert proc.returncode == 2
    assert "zero rounds" in proc.stderr


def test_missing_result_block_fails(tmp_path):
    ledger = make_ledger(tmp_path, result=None)
    proc = run("--ledger", str(ledger), "--out", str(tmp_path / "m.json"))
    assert proc.returncode == 2
    assert "no result block" in proc.stderr


def test_scope_matching_zero_files_fails(tmp_path):
    ledger = make_ledger(tmp_path)
    repo, _sha = make_repo(tmp_path)
    proc = run(
        "--ledger",
        str(ledger),
        "--out",
        str(tmp_path / "m.json"),
        "--repo",
        str(repo),
        "--scope",
        "does-not-exist/**",
    )
    assert proc.returncode == 2
    assert "matched zero files" in proc.stderr


def test_scope_without_repo_fails(tmp_path):
    ledger = make_ledger(tmp_path)
    proc = run("--ledger", str(ledger), "--out", str(tmp_path / "m.json"), "--scope", "plugins/**")
    assert proc.returncode == 2
    assert "--scope needs --repo" in proc.stderr


# ---------------------------------------------------------------- ledger metrics


def test_ledger_metrics(tmp_path):
    ledger = make_ledger(tmp_path)
    proc = run("--ledger", str(ledger), "--out", str(tmp_path / "metrics.json"), "--tokens", "4321")
    assert proc.returncode == 0, proc.stderr
    metrics = read_metrics(tmp_path)
    assert metrics["rounds_used"] == 2
    assert metrics["fix_rounds"] == 1
    assert metrics["converged"] is True
    assert metrics["ended_on_unreviewed_fix"] is False
    assert metrics["refiled_after_verdict"] == 2
    # rounds_seen [1, 2, 3, 7]: the longest consecutive run is 1..3.
    assert metrics["max_consecutive_rounds_same_finding"] == 3
    assert metrics["open_blocking"] == 0
    assert metrics["open_minor"] == 1
    assert metrics["subagent_tokens"] == 4321


def test_ended_on_unreviewed_fix(tmp_path):
    ledger = make_ledger(
        tmp_path,
        rounds=[
            {"round": 1, "type": "review", "open": {}},
            {"round": 1, "type": "fix", "verdicts": {}, "failed": False},
        ],
        result={"converged": False, "capped": True, "escalation": None, "halted": ""},
    )
    proc = run("--ledger", str(ledger), "--out", str(tmp_path / "metrics.json"))
    assert proc.returncode == 0, proc.stderr
    assert read_metrics(tmp_path)["ended_on_unreviewed_fix"] is True


# ---------------------------------------------------------------- narration


def test_narration_counted_and_clean_tree_is_zero(tmp_path):
    ledger = make_ledger(tmp_path)
    repo, _sha = make_repo(tmp_path)
    proc = run(
        "--ledger",
        str(ledger),
        "--out",
        str(tmp_path / "metrics.json"),
        "--repo",
        str(repo),
        "--scope",
        "plugins/demo/**",
    )
    assert proc.returncode == 0, proc.stderr
    assert read_metrics(tmp_path)["narration_hits_final"] == 0

    # The counter is proven against a specimen: planted narration must be found.
    planted = repo / "plugins/demo/skills/demo/SKILL.md"
    planted.write_text(
        "round 3 moved this here\npreviously fixed in iteration 2\n"
        "this was moved here per the review\n",
        encoding="utf-8",
    )
    proc = run(
        "--ledger",
        str(ledger),
        "--out",
        str(tmp_path / "metrics.json"),
        "--repo",
        str(repo),
        "--scope",
        "plugins/demo/**",
    )
    assert proc.returncode == 0, proc.stderr
    assert read_metrics(tmp_path)["narration_hits_final"] >= 3


def test_scope_star_does_not_cross_directories(tmp_path):
    ledger = make_ledger(tmp_path)
    repo, _sha = make_repo(tmp_path)
    (repo / "plugins/demo/top.md").write_text("round 1 narration\n", encoding="utf-8")
    nested = repo / "plugins/demo/skills/demo/SKILL.md"
    nested.write_text("round 2 narration\n", encoding="utf-8")

    proc = run(
        "--ledger",
        str(ledger),
        "--out",
        str(tmp_path / "metrics.json"),
        "--repo",
        str(repo),
        "--scope",
        "plugins/demo/*",
    )
    assert proc.returncode == 0, proc.stderr
    assert read_metrics(tmp_path)["narration_hits_final"] == 1  # top.md only

    proc = run(
        "--ledger",
        str(ledger),
        "--out",
        str(tmp_path / "metrics.json"),
        "--repo",
        str(repo),
        "--scope",
        "plugins/demo/**",
    )
    assert proc.returncode == 0, proc.stderr
    assert read_metrics(tmp_path)["narration_hits_final"] == 2


# ---------------------------------------------------------------- git-derived


def test_out_of_scope_diff_bytes(tmp_path):
    ledger = make_ledger(tmp_path)
    repo, sha = make_repo(tmp_path)
    (repo / "plugins/demo/skills/demo/SKILL.md").write_text("in-scope change\n", encoding="utf-8")
    proc = run(
        "--ledger",
        str(ledger),
        "--out",
        str(tmp_path / "metrics.json"),
        "--repo",
        str(repo),
        "--baseline-sha",
        sha,
        "--scope",
        "plugins/demo/**",
    )
    assert proc.returncode == 0, proc.stderr
    assert read_metrics(tmp_path)["out_of_scope_diff_bytes"] == 0

    (repo / "outside.md").write_text("tampered\n", encoding="utf-8")
    proc = run(
        "--ledger",
        str(ledger),
        "--out",
        str(tmp_path / "metrics.json"),
        "--repo",
        str(repo),
        "--baseline-sha",
        sha,
        "--scope",
        "plugins/demo/**",
    )
    assert proc.returncode == 0, proc.stderr
    assert read_metrics(tmp_path)["out_of_scope_diff_bytes"] > 0


def test_version_bumps_from_round_diffs(tmp_path):
    ledger = make_ledger(tmp_path)
    diff_dir = tmp_path / "artifacts"
    diff_dir.mkdir()
    (diff_dir / "fixes-round-1.diff").write_text(
        '--- a/plugin.json\n+++ b/plugin.json\n-  "version": "1.0.0"\n+  "version": "1.0.1"\n',
        encoding="utf-8",
    )
    (diff_dir / "fixes-round-2.diff").write_text(
        '--- a/plugin.json\n+++ b/plugin.json\n-  "version": "1.0.0"\n+  "version": "1.0.2"\n',
        encoding="utf-8",
    )
    proc = run(
        "--ledger",
        str(ledger),
        "--out",
        str(tmp_path / "metrics.json"),
        "--diff-dir",
        str(diff_dir),
    )
    assert proc.returncode == 0, proc.stderr
    # baseline -> 1.0.1 -> 1.0.2: the version value changed twice.
    assert read_metrics(tmp_path)["version_bumps"] == 2


def test_version_bump_reverted_counts_as_churn(tmp_path):
    ledger = make_ledger(tmp_path)
    diff_dir = tmp_path / "artifacts"
    diff_dir.mkdir()
    (diff_dir / "fixes-round-1.diff").write_text('+  "version": "1.0.1"\n', encoding="utf-8")
    (diff_dir / "fixes-round-2.diff").write_text("--- nothing about versions\n", encoding="utf-8")
    proc = run(
        "--ledger",
        str(ledger),
        "--out",
        str(tmp_path / "metrics.json"),
        "--diff-dir",
        str(diff_dir),
    )
    assert proc.returncode == 0, proc.stderr
    # baseline -> 1.0.1 -> baseline: applied and reverted is two changes.
    assert read_metrics(tmp_path)["version_bumps"] == 2


def test_version_bumps_null_without_inputs(tmp_path):
    ledger = make_ledger(tmp_path)
    proc = run("--ledger", str(ledger), "--out", str(tmp_path / "metrics.json"))
    assert proc.returncode == 0, proc.stderr
    metrics = read_metrics(tmp_path)
    assert metrics["version_bumps"] is None
    assert metrics["narration_hits_final"] is None
    assert metrics["out_of_scope_diff_bytes"] is None
