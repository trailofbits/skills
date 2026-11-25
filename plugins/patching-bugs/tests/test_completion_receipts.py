"""A readiness claim needs retained child sessions and an executed campaign."""

import json
import shutil
from pathlib import Path

import pytest
from completion import campaign_receipts
from records import RecordError, check, write_manifest
from verdict import verdict

FIXTURE = Path(__file__).parent / "fixtures/run-ready"


def run_case(tmp_path: Path) -> Path:
    run = tmp_path / "run"
    shutil.copytree(FIXTURE, run)
    return run


def replace_json(path: Path, **fields: object) -> None:
    value = json.loads(path.read_text())
    value.update(fields)
    path.write_text(json.dumps(value))


def test_ready_status_rejects_missing_campaign(tmp_path: Path) -> None:
    run = run_case(tmp_path)
    regression = json.loads((run / "regression/regression.json").read_text())
    regression["campaign_dir"] = str(tmp_path / "empty-campaign")
    (tmp_path / "empty-campaign").mkdir()
    (run / "regression/regression.json").write_text(json.dumps(regression))
    write_manifest(run / "regression")
    assert verdict(run)[0] == "NOT_READY"
    with pytest.raises(RecordError, match="campaign"):
        check(run)


def test_ready_status_rejects_missing_patch_session(tmp_path: Path) -> None:
    run = run_case(tmp_path)
    (run / "patch/attempt-1/receipts/session-launch.json").unlink()
    write_manifest(run / "patch/attempt-1")
    assert verdict(run)[0] == "NOT_READY"
    with pytest.raises(RecordError, match=r"patch.*session"):
        check(run)


@pytest.mark.parametrize("role", ["patch", "prove"])
def test_ready_status_rejects_forged_raw_launch(tmp_path: Path, role: str) -> None:
    run = run_case(tmp_path)
    step = run / role / "attempt-1"
    raw = step / "receipts/session-launch.raw.json"
    value = json.loads(raw.read_text())
    value["state"]["metadata"]["sessionID"] = "forged"
    raw.write_text(json.dumps(value))
    write_manifest(step)
    assert verdict(run)[0] == "NOT_READY"
    with pytest.raises(RecordError, match="session"):
        check(run)


def test_ready_status_rejects_reused_child_session(tmp_path: Path) -> None:
    run = run_case(tmp_path)
    step = run / "prove/attempt-1"
    launch = step / "receipts/session-launch.json"
    raw = step / "receipts/session-launch.raw.json"
    value = json.loads(launch.read_text())
    value["call"]["sessionID"] = "existing-child"
    launch.write_text(json.dumps(value))
    source = json.loads(raw.read_text())
    source["state"]["input"] = value["call"]
    raw.write_text(json.dumps(source))
    write_manifest(step)
    status, reasons = verdict(run)
    assert status == "NOT_READY"
    assert any("reused" in reason for reason in reasons)


@pytest.mark.parametrize("outcome", ["running", "failed"])
def test_ready_status_rejects_unsuccessful_child_session(tmp_path: Path, outcome: str) -> None:
    run = run_case(tmp_path)
    step = run / "prove/attempt-1"
    terminal = step / "receipts/session-terminal.json"
    raw = step / "receipts/session-terminal.raw.json"
    replace_json(raw, outcome=outcome)
    value = json.loads(terminal.read_text())
    value["response"]["outcome"] = outcome
    terminal.write_text(json.dumps(value))
    write_manifest(step)
    status, reasons = verdict(run)
    assert status == "NOT_READY"
    assert any("did not succeed" in reason for reason in reasons)


def test_ready_status_rejects_missing_campaign_snapshot(tmp_path: Path) -> None:
    run = run_case(tmp_path)
    (run / "regression/receipts/campaign-report.json").unlink()
    write_manifest(run / "regression")
    assert verdict(run)[0] == "NOT_READY"
    with pytest.raises(RecordError, match="campaign"):
        check(run)


def test_ready_with_concerns_requires_same_completion_evidence(tmp_path: Path) -> None:
    run = run_case(tmp_path)
    patch = run / "patch/attempt-1/patch.json"
    replace_json(
        patch,
        variants=[{"location": "other.py", "status": "not_fixed", "reason": "Deferred"}],
    )
    write_manifest(patch.parent)
    replace_json(run / "run.json", status="ready_with_concerns")
    assert verdict(run)[0] == "READY_WITH_CONCERNS"
    check(run)
    (run / "regression/receipts/campaign-report.json").unlink()
    write_manifest(run / "regression")
    assert verdict(run)[0] == "NOT_READY"
    with pytest.raises(RecordError, match="campaign"):
        check(run)


def test_unrelated_campaign_cannot_support_ready_status(tmp_path: Path) -> None:
    run = run_case(tmp_path)
    patch = json.loads((run / "patch/attempt-1/patch.json").read_text())
    regression = json.loads((run / "regression/regression.json").read_text())
    patch["patch_commit"] = "c" * 40
    with pytest.raises(RecordError, match="campaign source differs"):
        campaign_receipts(run, patch, regression)


def test_codex_child_sessions_are_accepted(tmp_path: Path) -> None:
    run = run_case(tmp_path)
    for role, child in (("patch", "patcher"), ("prove", "prover")):
        step = run / role / "attempt-1"
        receipts = step / "receipts"
        call = {"task_name": child, "fork_turns": "none"}
        response = {"task_name": child}
        launch = {
            "tool": "codex.spawn_agent",
            "parent_session": "coordinator",
            "observed_at": "2026-09-30T12:00:00+00:00",
            "call": call,
            "response": response,
        }
        terminal_response = {"agents": [{"agent_name": child, "agent_status": {"completed": None}}]}
        terminal = {
            "tool": "codex.list_agents",
            "observed_at": "2026-09-30T12:01:00+00:00",
            "response": terminal_response,
        }
        for name, value in (
            ("session-launch.json", launch),
            (
                "session-launch.raw.json",
                {"tool": "codex.spawn_agent", "call": call, "response": response},
            ),
            ("session-terminal.json", terminal),
            (
                "session-terminal.raw.json",
                {"tool": "codex.list_agents", "response": terminal_response},
            ),
        ):
            (receipts / name).write_text(json.dumps(value))
        write_manifest(step)
    assert verdict(run) == ("READY", [])
