"""Evidence integrity checks, independent of model behavior."""

import json
from pathlib import Path

import pytest
from evidence import IntegrityError, seal, verify


def save(root: Path, name: str, value: dict) -> None:
    """Write a fixture record without going through production writers."""
    path = root / name
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value))


def test_transitive_evidence_and_resume(tmp_path):
    source = tmp_path / "source.txt"
    source.write_text("before")
    save(
        tmp_path,
        "prepare.json",
        {"stage": "prepare", "agent": "a", "inputs": [], "artifacts": ["source.txt"]},
    )
    seal(tmp_path, "prepare.json")
    save(
        tmp_path,
        "hunt.json",
        {"stage": "hunt", "agent": "b", "inputs": ["prepare.json"], "artifacts": []},
    )
    seal(tmp_path, "hunt.json")
    before = {p.name: p.read_bytes() for p in tmp_path.iterdir()}
    seal(tmp_path, "hunt.json")
    verify(tmp_path, "hunt.json")
    assert before == {p.name: p.read_bytes() for p in tmp_path.iterdir()}
    source.write_text("after")
    with pytest.raises(ValueError, match="changed evidence"):
        verify(tmp_path, "hunt.json")


@pytest.mark.parametrize("mutation", ["new", "missing", "symlink"])
def test_package_changes_are_detected(tmp_path, mutation):
    package = tmp_path / "package"
    package.mkdir()
    log = package / "log"
    log.write_text("observations")
    save(
        tmp_path,
        "stage.json",
        {"stage": "replay", "agent": "c", "inputs": [], "artifacts": ["package"]},
    )
    seal(tmp_path, "stage.json")
    if mutation == "new":
        (package / "added").write_text("extra")
    else:
        log.unlink()
        if mutation == "symlink":
            log.symlink_to(tmp_path / "stage.json")
    with pytest.raises(ValueError):
        verify(tmp_path, "stage.json")


@pytest.mark.parametrize("path", ["../outside", "/tmp/outside", "missing"])
def test_invalid_evidence_cannot_be_sealed(tmp_path, path):
    save(tmp_path, "stage.json", {"stage": "hunt", "agent": "a", "inputs": [], "artifacts": [path]})
    with pytest.raises(ValueError):
        seal(tmp_path, "stage.json")
    assert not (tmp_path / "stage.json.seal.json").exists()


def test_changed_evidence_raises_integrity_error(tmp_path):
    (tmp_path / "source.txt").write_text("before")
    save(
        tmp_path,
        "prepare.json",
        {"stage": "prepare", "agent": "a", "inputs": [], "artifacts": ["source.txt"]},
    )
    seal(tmp_path, "prepare.json")
    (tmp_path / "source.txt").write_text("after")
    with pytest.raises(IntegrityError, match="Stale or changed evidence"):
        verify(tmp_path, "prepare.json")


def test_missing_sealed_evidence_raises_integrity_error(tmp_path):
    (tmp_path / "source.txt").write_text("before")
    save(
        tmp_path,
        "prepare.json",
        {"stage": "prepare", "agent": "a", "inputs": [], "artifacts": ["source.txt"]},
    )
    seal(tmp_path, "prepare.json")
    (tmp_path / "source.txt").unlink()
    with pytest.raises(IntegrityError, match=r"Missing evidence: source.txt"):
        verify(tmp_path, "prepare.json")
