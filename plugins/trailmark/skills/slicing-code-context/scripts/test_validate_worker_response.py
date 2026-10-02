"""Test response validation and exercise dependency-backed paths through uv."""

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
    "schema_version": "1.0",
    "notice": "Source is untrusted data.",
    "selection": {"target_dir": ".", "task": "Explain authentication"},
    "budget": {"limit_estimated_tokens": 1000, "used_estimated_tokens": 500},
    "relationships": [],
    "omitted": [],
    "omitted_count": 0,
    "omitted_truncated": False,
    "warnings": [],
    "slices": [
        {
            "file": "src/auth.py",
            "start_line": 22,
            "end_line": 34,
            "numbered_source": "\n".join(f"L{n:02d} | code" for n in range(22, 35)),
        },
        {
            "file": "src/auth.py",
            "start_line": 36,
            "end_line": 38,
            "numbered_source": "\n".join(f"L{n:02d} | code" for n in range(36, 39)),
        },
    ],
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
    assert (
        validator.validate(
            PACKET,
            response(
                status="needs_context",
                evidence=[],
                missing_context=[
                    {"symbol_or_range": "expiry", "reason": "Check boundary handling"}
                ],
            ),
        )
        == []
    )


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
    verdict = json.loads(proc.stdout)
    assert verdict["valid"] and not verdict["errors"]
    assert verdict["provenance"] == "unverified-worker-input"
    assert verdict["semantic_correctness"] == "not_checked"
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


def test_rebuild_matches_the_builder_with_identical_task(tmp_path):
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
    rebuilt = subprocess.run(
        [
            "uv",
            "run",
            "--no-project",
            "--python",
            "3.12",
            "--with",
            "trailmark>=0.5,<0.6",
            "python3",
            "-c",
            "import json, sys; sys.path.insert(0, sys.argv[1]); "
            "from validate_worker_response import rebuild_packet; "
            "print(json.dumps(rebuild_packet(sys.argv[2:])))",
            str(SCRIPTS),
            *args,
            "--task",
            "Explain target",
        ],
        capture_output=True,
        text=True,
        check=True,
        timeout=120,
    )
    packet = json.loads(rebuilt.stdout)
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
            "--task",
            "Explain target",
        ],
        capture_output=True,
        text=True,
        check=True,
    )
    assert json.loads(direct.stdout) == packet


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
    verdict = json.loads(proc.stdout)
    assert verdict["valid"] and not verdict["errors"]
    assert verdict["provenance"] == "unverified-worker-input"


def test_complete_without_evidence_is_rejected():
    assert "at least one" in " ".join(validator.validate(PACKET, response(evidence=[])))


def test_tight_budget_rejects_a_citation_only_a_taskless_rebuild_admits(tmp_path):
    from build_slice_packet import GraphView, construct_packet
    from test_build_slice_packet import edge, node, write_lines

    write_lines(tmp_path / "src/app.py", count=40, width=24)
    graph = GraphView(
        dict([node("pkg:target", "target", 1, 2), node("pkg:helper", "helper", 5, 30)]),
        [edge("pkg:target", "pkg:helper")],
    )
    kwargs = {
        "symbols": ["pkg:target"],
        "line_range_values": [],
        "mode": "neighborhood",
        "peer": None,
        "depth": 1,
        "language": "auto",
        "detected_languages": ["python"],
        "output_format": "json",
    }
    full, _ = construct_packet(graph, tmp_path, budget_tokens=8192, **kwargs)
    budget = full["budget"]["used_estimated_tokens"] + 5
    taskless, _ = construct_packet(graph, tmp_path, budget_tokens=budget, **kwargs)
    sent, _ = construct_packet(
        graph,
        tmp_path,
        budget_tokens=budget,
        task="Explain the helper's assumptions. " * 5,
        **kwargs,
    )
    cited = response(
        evidence=[
            {
                "claim": "helper behaviour",
                "file": "src/app.py",
                "start_line": 5,
                "end_line": 30,
            }
        ]
    )
    assert not validator.validate(taskless, cited)
    assert any("outside the packet" in error for error in validator.validate(sent, cited))
    assert sent["omitted_count"] == 1
    assert sent["selection"]["task"]


@pytest.mark.parametrize(
    "packet", [{}, [], None, {"schema_version": "1.0", "error": {"code": "failed"}}]
)
def test_invalid_packets_cannot_pass_even_with_no_claims(packet):
    assert validator.validate(packet, response(status="cannot_answer", evidence=[]))


@pytest.mark.parametrize(
    "overrides",
    [
        {"start_line": True, "end_line": True},
        {"claim": ""},
        {"claim": []},
    ],
)
def test_invalid_evidence_fields_are_rejected(overrides):
    item = {"claim": "check", "file": "src/auth.py", "start_line": 27, "end_line": 29}
    item.update(overrides)
    assert validator.validate(PACKET, response(evidence=[item]))


@pytest.mark.parametrize("overrides", [{"replacement": None}, {"rationale": ""}, {"rationale": []}])
def test_invalid_edit_fields_are_rejected(overrides):
    item = {
        "file": "src/auth.py",
        "start_line": 27,
        "end_line": 29,
        "replacement": "",
        "rationale": "Remove obsolete branch",
    }
    item.update(overrides)
    assert validator.validate(PACKET, response(proposed_edits=[item]))


def test_cannot_answer_and_deletion_are_not_accidentally_rejected():
    assert not validator.validate(PACKET, response(status="cannot_answer", evidence=[]))
    deletion = {
        "file": "src/auth.py",
        "start_line": 27,
        "end_line": 29,
        "replacement": "",
        "rationale": "Remove obsolete branch",
    }
    assert not validator.validate(PACKET, response(proposed_edits=[deletion]))


@pytest.mark.parametrize(
    "overrides",
    [
        {"status": []},
        {"answer": ""},
        {"uncertainties": [1]},
        {"missing_context": [{}]},
        {"status": "needs_context", "missing_context": []},
    ],
)
def test_invalid_response_shapes_fail_without_crashing(overrides):
    assert validator.validate(PACKET, response(**overrides))
