from __future__ import annotations

import hashlib
import subprocess
import sys
from pathlib import Path

import pytest
from conftest import SCRIPT


@pytest.mark.parametrize(
    "argv",
    [[], ["unknown-command"], ["print-schema", "--typo"], ["run"], ["validate-plan"]],
)
def test_usage_errors_return_64(argv: list[str]) -> None:
    result = subprocess.run([sys.executable, str(SCRIPT), *argv], capture_output=True)
    assert result.returncode == 64
    assert b"usage:" in result.stderr
    assert b"error:" in result.stderr
    assert b"Traceback" not in result.stderr


@pytest.mark.parametrize("argv", [["--help"], ["run", "--help"]])
def test_help_returns_zero(argv: list[str]) -> None:
    result = subprocess.run([sys.executable, str(SCRIPT), *argv], capture_output=True)
    assert result.returncode == 0
    assert b"usage:" in result.stdout
    assert result.stderr == b""


def test_invalid_utf8_plan_returns_64(tmp_path: Path) -> None:
    plan = tmp_path / "plan.json"
    plan.write_bytes(b'{"summary": "\xff"}')
    result = subprocess.run(
        [sys.executable, str(SCRIPT), "validate-plan", "--plan", str(plan)],
        capture_output=True,
    )
    assert result.returncode == 64
    assert b"cannot read JSON" in result.stderr
    assert b"plan.json" in result.stderr
    assert b"Traceback" not in result.stderr


def test_manifest_includes_nested_manifest_files(tmp_path: Path, ppv) -> None:
    (tmp_path / "artifact-manifest.json").write_bytes(b"runner manifest")
    nested = tmp_path / "scratch" / "check" / "artifact-manifest.json"
    nested.parent.mkdir(parents=True)
    content = b"check artifact\n"
    nested.write_bytes(content)

    manifest = ppv.artifact_manifest(tmp_path)
    assert manifest["files"] == [
        {
            "path": "scratch/check/artifact-manifest.json",
            "sha256": hashlib.sha256(content).hexdigest(),
            "bytes": len(content),
        }
    ]


@pytest.mark.parametrize("own_manifest_exists", [False, True])
def test_manifest_rejects_zero_evidence_files(
    tmp_path: Path, ppv, own_manifest_exists: bool
) -> None:
    if own_manifest_exists:
        (tmp_path / "artifact-manifest.json").write_bytes(b"runner manifest")
    with pytest.raises(ppv.PlanError, match="zero files"):
        ppv.artifact_manifest(tmp_path)
