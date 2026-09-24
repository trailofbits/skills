"""Execution tests for the deterministic output-directory resolver."""

from __future__ import annotations

import subprocess
from pathlib import Path

SCRIPT = Path(__file__).with_name("resolve_output_dir.sh")


def run(tmp_path: Path, *args: str) -> Path:
    result = subprocess.run(
        [str(SCRIPT), *args], cwd=tmp_path, text=True, capture_output=True, check=True
    )
    return Path(result.stdout.strip())


def test_uses_first_available_default(tmp_path: Path) -> None:
    assert run(tmp_path) == tmp_path / "static_analysis_codeql_1"


def test_increments_existing_default(tmp_path: Path) -> None:
    (tmp_path / "static_analysis_codeql_1").mkdir()
    assert run(tmp_path) == tmp_path / "static_analysis_codeql_2"


def test_honours_requested_directory_and_creates_it(tmp_path: Path) -> None:
    requested = tmp_path / "results with spaces"
    assert run(tmp_path, str(requested)) == requested
    assert requested.is_dir()


def test_help_does_not_create_a_directory(tmp_path: Path) -> None:
    result = subprocess.run(
        [str(SCRIPT), "--help"], cwd=tmp_path, text=True, capture_output=True, check=True
    )
    assert result.stdout.startswith("usage:")
    assert not (tmp_path / "--help").exists()
