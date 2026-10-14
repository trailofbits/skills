"""The documented commands must work, and the two severity tables must agree."""

import re
import subprocess
from pathlib import Path

SKILL_DIR = Path(__file__).resolve().parent.parent
SKILL = (SKILL_DIR / "SKILL.md").read_text(encoding="utf-8")
REPORT = (SKILL_DIR / "references" / "report-format.md").read_text(encoding="utf-8")


def git(*args, cwd):
    return subprocess.run(["git", *args], cwd=cwd, capture_output=True, text=True)


def test_worktree_commands_compare_the_checked_out_branch(tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()
    git("init", "-q", "-b", "main", cwd=repo)
    (repo / "a.py").write_text("def f():\n    return 1\n")
    git("add", "-A", cwd=repo)
    git("-c", "user.email=t@t", "-c", "user.name=t", "commit", "-qm", "one", cwd=repo)
    commands = re.findall(r"^git worktree add .*$", SKILL, flags=re.M)
    assert len(commands) == 2
    for i, line in enumerate(commands):
        dest = tmp_path / f"wt{i}"
        line = line.replace('"$BEFORE_DIR"', str(dest)).replace('"$AFTER_DIR"', str(dest))
        line = line.replace("{before_ref}", "main").replace("{after_ref}", "main")
        proc = subprocess.run(line, shell=True, cwd=repo, capture_output=True, text=True)
        # Comparing the current branch must work; without --detach git refuses it.
        assert proc.returncode == 0, proc.stderr


def severity_row(text: str, level: str) -> str:
    return next(line for line in text.splitlines() if re.match(rf"\|\s*\**{level}\**\s*\|", line))


def test_severity_tables_agree_on_complexity_thresholds():
    for level, number in (("HIGH", "> 10"), ("MEDIUM", "> 3")):
        assert number in severity_row(SKILL, level) and number in severity_row(REPORT, level)
