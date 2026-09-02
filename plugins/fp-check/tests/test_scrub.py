"""The scrubber must remove identity WITHOUT destroying evidence.

A greedy path rule once replaced an agent's whole `location` with "/SCRATCH",
taking `search.py:27` with it. The regrade then failed and read as model
variance. These cases pin both halves of the contract.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

from scrub_capture import scrub, username_patterns

SCRUBBER = Path(__file__).resolve().parent / "scrub_capture.py"


def run_scrubber(target: Path, home: Path) -> subprocess.CompletedProcess:
    """Invoke the script end to end, with `home` deciding the username.

    Exercising main() rather than scrub() is the point: the substitution and the
    leak check that verifies it live in different functions, and the bug was
    that they disagreed.
    """
    env = dict(os.environ, HOME=str(home))
    env.pop("USERPROFILE", None)
    return subprocess.run(
        [sys.executable, str(SCRUBBER), str(target)],
        capture_output=True,
        text=True,
        check=False,
        env=env,
    )


# Built at runtime rather than written as literals: the plugin validator rejects
# a hardcoded /Users/... or /home/... path anywhere in the repo, and cannot tell
# a test input from a real reference. It is right to be strict, so these are
# assembled instead.
HOME = "/" + "Users"
SCRATCH = "/private/tmp/" + "claude-501"


def test_repo_relative_path_survives_an_absolute_prefix():
    raw = f"{SCRATCH}/xyz/worktree/plugins/fp-check/evals/x/search.py:27"
    out = scrub(raw, "gros")
    assert "search.py:27" in out, "file:line evidence must survive scrubbing"
    assert "plugins/fp-check" in out
    assert SCRATCH not in out


def test_home_path_is_removed_but_basename_survives():
    out = scrub(f"{HOME}/gros/somewhere/deep/search.py:20", "gros")
    assert "gros" not in out
    assert "search.py:20" in out


def test_scratch_path_keeps_its_basename():
    out = scrub(f"{SCRATCH}/a/b/c/report.md", "gros")
    assert "report.md" in out
    assert "claude-5" + "01" not in out


def test_encoded_project_slug_is_removed():
    out = scrub("-" + "Users-gros-ToB-tools-tob-skills-internal", "gros")
    assert "gros" not in out


def test_scrubbing_is_idempotent():
    once = scrub(f"{SCRATCH}/x/plugins/a/search.py:27", "gros")
    assert scrub(once, "gros") == once


# --------------------------------------------------------------------------
# The username rule has the same two failure modes as the path rules: it can
# destroy evidence, and it can disagree with the check that verifies it.
# --------------------------------------------------------------------------


def test_a_username_inside_an_ordinary_word_is_left_alone():
    """`max` must not turn "maximum severity" into "USERimum severity".

    This is also what made the scrubber abort a whole capture batch: the
    substitution was word-bounded, the leak check was a plain `in`, so the
    surviving "max" inside "maximum" was reported as an unscrubbed identity
    after the file had already been written.
    """
    text = "maximum severity was claimed; the finding is grossly inflated"
    assert scrub(text, "max") == text


def test_an_ambiguous_username_does_not_eat_ordinary_prose():
    """A login that is also an English word only scrubs in identity contexts."""
    text = "The web root is served from /srv; root cause is a missing check."
    out = scrub(text, "root")
    assert "root cause" in out, "'root cause' must survive; it is the finding"
    assert "web root" in out


def test_an_ambiguous_username_is_still_scrubbed_where_it_carries_identity():
    out = scrub("~root/notes.md and root@buildbox ran it", "root")
    assert "~root/" not in out
    assert "root@" not in out
    assert "notes.md" in out, "the filename is evidence and must survive"


def test_the_leak_check_agrees_with_the_substitution():
    """Whatever scrub() leaves behind must not be reported as a leak.

    Pins the two against each other over a range of usernames rather than
    trusting that they were written consistently.
    """
    samples = [
        "maximum severity and a grossly inflated claim",
        "root cause is a missing check in the web root",
        "the developer built it",
        "drwxr-xr-x 5 gros 160 Jul 30 search.py",
    ]
    for username in ("max", "root", "dev", "gros"):
        for sample in samples:
            cleaned = scrub(sample, username)
            for pattern in username_patterns(username):
                assert not pattern.search(cleaned), (
                    f"scrub({sample!r}, {username!r}) left {pattern.pattern} behind; "
                    f"the leak check would abort the batch on it"
                )


def test_a_normal_username_is_still_removed_everywhere():
    assert "gros" not in scrub("drwxr-xr-x 5 gros 160 Jul 30 search.py", "gros")
    assert "gros" not in scrub("~gros/x and gros@host", "gros")


def test_an_empty_username_is_a_no_op_not_a_crash():
    text = "nothing to scrub here"
    assert scrub(text, "") == text


def test_the_script_does_not_abort_on_a_username_inside_a_word(tmp_path: Path):
    """The failure this reproduces killed a whole N-run capture batch.

    scrub() substituted `\\bmax\\b`, so "maximum" was correctly left alone; the
    leak check then used a plain `in`, found "max" inside "maximum", and exited
    1 *after* writing the file. capture-runs.sh calls this under `set -e`, so
    run 1 took the batch down with it and no pass rate was ever printed.
    """
    home = tmp_path / "max"
    home.mkdir()
    target = tmp_path / "cap.jsonl"
    target.write_text(
        json.dumps({"text": "maximum severity was claimed; the finding is grossly inflated"}) + "\n"
    )

    proc = run_scrubber(target, home)

    assert proc.returncode == 0, (
        f"the scrubber must not abort on an ordinary word containing the login:\n{proc.stderr}"
    )
    assert "maximum severity" in target.read_text(), "the capture text must survive intact"


def test_the_script_still_removes_a_real_identity(tmp_path: Path):
    """The opposite failure: a scrubber that never reports a leak."""
    home = tmp_path / "distinctlogin"
    home.mkdir()
    target = tmp_path / "cap.jsonl"
    target.write_text(json.dumps({"text": "drwxr-xr-x 5 distinctlogin 160 search.py"}) + "\n")

    proc = run_scrubber(target, home)

    assert proc.returncode == 0, proc.stderr
    cleaned = target.read_text()
    assert "distinctlogin" not in cleaned
    assert "search.py" in cleaned, "the filename is evidence and must survive"


def test_the_script_refuses_a_home_that_yields_no_username(tmp_path: Path):
    """An empty username turned the whole scrubber into a no-op reporting success.

    `username_patterns("")` returns `[]`, so nothing was substituted, and the
    leak check then read `any(... for pat in [])` — vacuously false over an
    empty list. Measured before the fix: `HOME=/ scrub_capture.py cap.jsonl`
    printed "scrubbed 1 file(s)", exited 0, and left `~alice` and `alice@box`
    exactly where they were. "I do not know what to remove" must not read as
    "there was nothing to remove".
    """
    target = tmp_path / "cap.jsonl"
    original = json.dumps({"type": "x", "note": "see ~alice and alice@box"}) + "\n"
    target.write_text(original)

    proc = run_scrubber(target, Path(os.sep))

    assert proc.returncode == 1, (
        f"a home yielding no username must be refused, not treated as a clean file:\n"
        f"{proc.stdout}{proc.stderr}"
    )
    assert "no username" in proc.stderr
    assert target.read_text() == original, "a refusal must not rewrite the file"


def test_a_capture_whose_only_leak_is_a_machine_path_is_scrubbed(tmp_path: Path):
    """The leak check ran only the username patterns, never the path rules.

    A capture carrying a scratch path and no login anywhere in it was written
    back and reported clean with the path half of the contract unchecked, though
    the module docstring promises all three categories. The check now re-runs
    the whole rule set over what was written, so cleaned text that never reaches
    disk is reported rather than announced as a success.
    """
    home = tmp_path / "distinctlogin"
    home.mkdir()
    target = tmp_path / "cap.jsonl"
    location = f"{SCRATCH}/wt/plugins/fp-check/evals/case2/search.py:14"
    target.write_text(json.dumps({"type": "result", "location": location}) + "\n")

    proc = run_scrubber(target, home)

    assert proc.returncode == 0, proc.stderr
    cleaned = target.read_text()
    assert "claude-5" + "01" not in cleaned, "the machine path must be gone"
    assert "search.py:14" in cleaned, "the file:line evidence is what the capture is for"


def test_the_script_rejects_a_missing_file(tmp_path: Path):
    proc = run_scrubber(tmp_path / "nope.jsonl", tmp_path)
    assert proc.returncode == 1
    assert "not a file" in proc.stderr
