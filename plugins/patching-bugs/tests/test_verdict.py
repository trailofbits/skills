import json
import shutil
from pathlib import Path

import pytest
from records import RecordError, write_manifest
from verdict import verdict

FIXTURE = Path(__file__).parent / "fixtures/run-ready"


def case(tmp_path):
    run = tmp_path / "run"
    shutil.copytree(FIXTURE, run)
    return run


def change(run, rel, **fields):
    path = run / rel
    record = json.loads(path.read_text())
    record.update(fields)
    path.write_text(json.dumps(record))
    if path.parent != run:
        write_manifest(path.parent)


def test_ready(tmp_path):
    assert verdict(case(tmp_path))[0] == "READY"


@pytest.mark.parametrize(
    ("record", "field", "value", "expected"),
    [
        ("reproduce/reproduce.json", "outcome", "not_reproduced", "NOT_REPRODUCED"),
        ("validate/validate.json", "outcome", "inconclusive", "NOT_REPRODUCED"),
        ("prove/attempt-1/prove.json", "reverted", "fail", "NOT_READY"),
        ("prove/attempt-1/prove.json", "build_identity", "fail", "NOT_READY"),
        ("regression/regression.json", "coverage", "INCOMPLETE", "READY_WITH_CONCERNS"),
    ],
)
def test_rule(tmp_path, record, field, value, expected):
    run = case(tmp_path)
    change(run, record, **{field: value})
    assert verdict(run)[0] == expected


@pytest.mark.parametrize(
    ("outcome", "expected"),
    [
        ("REPRODUCED_REGRESSION", "NOT_READY"),
        ("INCOMPLETE_FIX", "NOT_READY"),
        ("UNRESOLVED", "READY_WITH_CONCERNS"),
    ],
)
def test_regression_outcome(tmp_path, outcome, expected):
    run = case(tmp_path)
    change(
        run,
        "regression/regression.json",
        outcomes=[{"candidate_id": "c1", "outcome": outcome, "decision_receipt": "decision.txt"}],
    )
    assert verdict(run)[0] == expected


def test_unfixed_variant(tmp_path):
    run = case(tmp_path)
    change(
        run,
        "patch/attempt-1/patch.json",
        variants=[
            {"location": "other.py", "status": "not_fixed", "reason": "Needs separate change"}
        ],
    )
    assert verdict(run)[0] == "READY_WITH_CONCERNS"


def test_missing_record(tmp_path):
    run = case(tmp_path)
    (run / "validate/validate.json").unlink()
    with pytest.raises(RecordError, match="validate"):
        verdict(run)


def test_failed_proof_needs_no_regression_record(tmp_path):
    run = case(tmp_path)
    change(run, "prove/attempt-1/prove.json", reverted="fail")
    (run / "regression/regression.json").unlink()
    assert verdict(run)[0] == "NOT_READY"


def test_missing_latest_proof_is_not_ready(tmp_path):
    run = case(tmp_path)
    (run / "prove/attempt-1/prove.json").unlink()
    assert verdict(run)[0] == "NOT_READY"


def test_missing_patch_commit_is_not_ready(tmp_path):
    run = case(tmp_path)
    change(run, "patch/attempt-1/patch.json", patch_commit=None)
    assert verdict(run)[0] == "NOT_READY"


def test_missing_patch_record_is_not_ready(tmp_path):
    run = case(tmp_path)
    (run / "patch/attempt-1/patch.json").unlink()
    assert verdict(run)[0] == "NOT_READY"


@pytest.mark.parametrize(
    ("record", "agent"),
    [
        ("validate/validate.json", "reproducer"),
        ("prove/attempt-1/prove.json", "patcher"),
    ],
)
def test_same_agent_in_independent_steps_is_not_ready(tmp_path, record, agent):
    run = case(tmp_path)
    change(run, record, agent=agent)
    status, reasons = verdict(run)
    assert status == "NOT_READY"
    assert any("agent" in reason for reason in reasons)


def test_native_evidence_gap_blocks_readiness(tmp_path):
    run = case(tmp_path)
    proof = run / "prove/attempt-1"
    (proof / "receipts/interior-patched.stdout").write_text("missing observation\n")
    write_manifest(proof)
    status, reasons = verdict(run)
    assert status == "NOT_READY"
    assert any("interior" in reason for reason in reasons)
