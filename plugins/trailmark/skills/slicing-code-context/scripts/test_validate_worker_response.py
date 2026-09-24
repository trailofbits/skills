"""Tests for validate_worker_response.py; the rebuild path needs Trailmark and skips without it."""

from __future__ import annotations

import importlib.util
import json
import subprocess
import sys
from pathlib import Path

import pytest

SCRIPTS = Path(__file__).resolve().parent
SPEC = importlib.util.spec_from_file_location(
    "validate_worker_response", SCRIPTS / "validate_worker_response.py"
)
validator = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(validator)

PACKET = {
    "slices": [
        {"file": "src/auth.py", "start_line": 22, "end_line": 34},
        {"file": "src/auth.py", "start_line": 36, "end_line": 38},
    ]
}


def response(**overrides) -> dict:
    base = {
        "status": "complete",
        "answer": "Verifies the MAC then the expiry.",
        "evidence": [
            {"claim": "MAC check", "file": "src/auth.py", "start_line": 27, "end_line": 29}
        ],
        "proposed_edits": [],
        "missing_context": [],
        "uncertainties": [],
    }
    base.update(overrides)
    return base


def test_valid_response_passes():
    assert validator.validate(PACKET, response()) == []


def test_every_contract_field_is_required():
    bad = response()
    del bad["uncertainties"]
    assert validator.validate(PACKET, bad)
    extra = response(extra="x")
    assert validator.validate(PACKET, extra)
    assert validator.validate(PACKET, ["not", "an", "object"])


def test_status_must_be_valid():
    assert validator.validate(PACKET, response(status="done"))


@pytest.mark.parametrize(
    "citation",
    [
        {"claim": "past the slice", "file": "src/auth.py", "start_line": 30, "end_line": 35},
        {"claim": "between slices", "file": "src/auth.py", "start_line": 34, "end_line": 36},
        {"claim": "other file", "file": "src/store.py", "start_line": 1, "end_line": 2},
        {"claim": "no lines", "file": "src/auth.py"},
        {"claim": "strings", "file": "src/auth.py", "start_line": "27", "end_line": "29"},
    ],
)
def test_citations_outside_the_packet_are_rejected(citation):
    errors = validator.validate(PACKET, response(evidence=[citation]))
    assert errors and "outside the packet" in errors[0]
    errors = validator.validate(
        PACKET, response(proposed_edits=[dict(citation, replacement="x", rationale="y")])
    )
    assert errors and "outside the packet" in errors[0]


def test_needs_context_with_empty_evidence_is_valid():
    assert validator.validate(PACKET, response(status="needs_context", evidence=[])) == []


def test_cli_with_saved_packet(tmp_path):
    (tmp_path / "packet.json").write_text(json.dumps(PACKET))
    (tmp_path / "response.json").write_text(json.dumps(response()))
    proc = subprocess.run(
        [
            sys.executable,
            str(SCRIPTS / "validate_worker_response.py"),
            str(tmp_path / "response.json"),
            "--packet",
            str(tmp_path / "packet.json"),
        ],
        capture_output=True,
        text=True,
    )
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert json.loads(proc.stdout) == {"valid": True, "errors": []}
    (tmp_path / "response.json").write_text("not json")
    proc = subprocess.run(
        [
            sys.executable,
            str(SCRIPTS / "validate_worker_response.py"),
            str(tmp_path / "response.json"),
            "--packet",
            str(tmp_path / "packet.json"),
        ],
        capture_output=True,
        text=True,
    )
    assert proc.returncode == 1 and json.loads(proc.stdout)["valid"] is False


def test_cli_requires_exactly_one_packet_source(tmp_path):
    (tmp_path / "response.json").write_text(json.dumps(response()))
    proc = subprocess.run(
        [
            sys.executable,
            str(SCRIPTS / "validate_worker_response.py"),
            str(tmp_path / "response.json"),
        ],
        capture_output=True,
        text=True,
    )
    assert proc.returncode == 2


def test_rebuild_matches_the_builder_and_ignores_task(tmp_path):
    pytest.importorskip("trailmark")
    src = tmp_path / "src"
    src.mkdir()
    (src / "__init__.py").write_text("")
    (src / "mod.py").write_text(
        "def helper():\n    return 1\n\n\ndef target():\n    return helper() + 1\n"
    )
    args = [
        "--target-dir",
        str(tmp_path),
        "--symbol",
        "target",
        "--mode",
        "neighborhood",
        "--depth",
        "1",
    ]
    packet = validator.rebuild_packet(args + ["--task", "Explain target"])
    assert packet["selection"]["task"] == "Explain target"
    assert any("mod.py" in s["file"] for s in packet["slices"])
    direct = subprocess.run(
        [
            "uv",
            "run",
            "--no-project",
            str(SCRIPTS / "build_slice_packet.py"),
            *args,
            "--format",
            "json",
        ],
        capture_output=True,
        text=True,
        check=True,
    )
    assert json.loads(direct.stdout)["slices"] == packet["slices"]


def test_cli_rebuild_path_under_uv(tmp_path):
    """The rebuild form as the coordinator runs it, under uv's interpreter selection."""
    src = tmp_path / "src"
    src.mkdir()
    (src / "__init__.py").write_text("")
    (src / "mod.py").write_text(
        "def helper():\n    return 1\n\n\ndef target():\n    return helper() + 1\n"
    )
    (tmp_path / "response.json").write_text(
        json.dumps(
            {
                "status": "complete",
                "answer": "target adds one to helper's result.",
                "evidence": [
                    {"claim": "adds one", "file": "src/mod.py", "start_line": 5, "end_line": 6}
                ],
                "proposed_edits": [],
                "missing_context": [],
                "uncertainties": [],
            }
        )
    )
    proc = subprocess.run(
        [
            "uv",
            "run",
            "--no-project",
            str(SCRIPTS / "validate_worker_response.py"),
            str(tmp_path / "response.json"),
            "--",
            "--target-dir",
            str(tmp_path),
            "--symbol",
            "target",
            "--mode",
            "neighborhood",
            "--depth",
            "1",
            "--task",
            "Explain target",
        ],
        capture_output=True,
        text=True,
        timeout=600,
    )
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert json.loads(proc.stdout) == {"valid": True, "errors": []}
