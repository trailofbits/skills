"""The bundled example rules must pass the checks the skill's checklist requires of every rule."""

from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

import pytest

SKILL = Path(__file__).resolve().parents[1] / "skills" / "yara-rule-authoring"
EXAMPLES = sorted((SKILL / "examples").glob("*.yar"))


def yr() -> str:
    path = shutil.which("yr")
    if path is None:
        pytest.fail("yr (YARA-X CLI) is not on PATH; CI installs it before these tests")
    return path


@pytest.mark.parametrize("rule", EXAMPLES, ids=lambda p: p.name)
def test_example_compiles_without_warnings(rule):
    proc = subprocess.run([yr(), "check", str(rule)], capture_output=True, text=True, check=False)
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert "warning" not in (proc.stdout + proc.stderr).lower()


@pytest.mark.parametrize("rule", EXAMPLES, ids=lambda p: p.name)
def test_example_is_formatted(rule):
    proc = subprocess.run(
        [yr(), "fmt", "--check", str(rule)], capture_output=True, text=True, check=False
    )
    assert proc.returncode == 0, proc.stdout + proc.stderr


def test_atom_analyzer_prints_no_colour_codes_when_piped():
    uv = shutil.which("uv")
    if uv is None:
        pytest.fail("uv is not on PATH; atom_analyzer.py runs under `uv run`")
    proc = subprocess.run(
        [uv, "run", "--quiet", "--no-project", str(SKILL / "scripts" / "atom_analyzer.py")]
        + [str(EXAMPLES[0])],
        capture_output=True,
        text=True,
        check=False,
    )
    # Exit 1 means atom issues were found; the check here is only the output encoding.
    assert proc.returncode in (0, 1) and proc.stdout.strip(), proc.stderr
    assert "\033[" not in proc.stdout + proc.stderr
