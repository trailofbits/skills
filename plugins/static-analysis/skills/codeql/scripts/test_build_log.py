"""Run build_log.sh, rather than reading it.

`make shell` checks this file's syntax and test_shell_blocks.py checks the markdown that
calls it. Neither executes it — so the claim the whole build-method ladder rests on, that
`run_logged` returns the command's exit status and not tee's, was never demonstrated.
"""

from __future__ import annotations

import subprocess
from pathlib import Path

BUILD_LOG = Path(__file__).resolve().parent / "build_log.sh"


def _bash(script: str, cwd: Path) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["bash", "-c", f'. "{BUILD_LOG}"\n{script}'],
        cwd=cwd,
        capture_output=True,
        text=True,
    )


# --- the exit-status claim ---------------------------------------------------------


def test_run_logged_reports_the_commands_failure(tmp_path: Path) -> None:
    """The bug this file was written to fix, in its simplest form.

    Without pipefail `false | tee` exits 0, so the ladder recorded a failed build as a
    success and never tried the next method.
    """
    result = _bash('run_logged false\necho "status=$?"', tmp_path)
    assert "status=1" in result.stdout


def test_run_logged_reports_success(tmp_path: Path) -> None:
    """The other direction: a working build must not look like a failure."""
    result = _bash('run_logged true\necho "status=$?"', tmp_path)
    assert "status=0" in result.stdout


def test_sourcing_sets_pipefail_for_the_caller(tmp_path: Path) -> None:
    """Blocks that pipe directly, rather than through the wrapper, inherit the setting."""
    result = _bash('false | true\necho "status=$?"', tmp_path)
    assert "status=1" in result.stdout


def test_run_logged_keeps_arguments_apart(tmp_path: Path) -> None:
    """argv, not a string: a path with a space must survive as one argument."""
    result = _bash('run_logged printf "[%s]" "two words"', tmp_path)
    assert "[two words]" in result.stdout


# --- where the log goes ------------------------------------------------------------


def test_output_is_written_to_the_log(tmp_path: Path) -> None:
    _bash("run_logged echo hello-from-the-build", tmp_path)
    assert "hello-from-the-build" in (tmp_path / "build.log").read_text()


def test_log_file_defaults_under_output_dir(tmp_path: Path) -> None:
    scans = tmp_path / "scans"
    scans.mkdir()
    result = subprocess.run(
        ["bash", "-c", f'OUTPUT_DIR="{scans}"\n. "{BUILD_LOG}"\nrun_logged echo hi'],
        cwd=tmp_path,
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0
    assert "hi" in (scans / "build.log").read_text()


def test_an_unwritable_log_fails_at_source_time(tmp_path: Path) -> None:
    """Not four rungs later, as a CodeQL problem.

    tee's failure is the pipeline's failure under pipefail, so every method would report
    failure and the run would end at --build-mode=none blaming the build.
    """
    missing = tmp_path / "no-such-dir" / "build.log"
    result = subprocess.run(
        ["bash", "-c", f'LOG_FILE="{missing}"\n. "{BUILD_LOG}"\nrun_logged true'],
        cwd=tmp_path,
        capture_output=True,
        text=True,
    )
    assert result.returncode != 0
    assert "cannot write build log" in result.stderr
