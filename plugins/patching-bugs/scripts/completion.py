"""Check retained child sessions and Regression Hunt work before patch readiness."""

import json
import os
import subprocess
import sys
from datetime import datetime
from pathlib import Path, PurePosixPath

from records import RecordError, retained_file, verify_manifest

REPORT_SCRIPT = Path(__file__).resolve().parents[2] / "regression-hunt/scripts/report.py"


def require(condition: object, message: str) -> None:
    if not condition:
        raise RecordError(message)


def _json(path: Path) -> dict:
    try:
        value = json.loads(path.read_text())
    except (OSError, json.JSONDecodeError) as error:
        raise RecordError(f"{path}: unreadable session or campaign receipt: {error}") from error
    require(isinstance(value, dict), f"{path}: expected JSON object")
    return value


def _session_files(step: Path, stem: str) -> tuple[dict, dict]:
    receipt = step / "receipts" / f"session-{stem}.json"
    raw = step / "receipts" / f"session-{stem}.raw.json"
    require(receipt.is_file() and raw.is_file(), f"{step}: missing {stem} session receipt")
    return _json(receipt), _json(raw)


def _observed(value: dict, step: Path) -> datetime:
    try:
        observed = datetime.fromisoformat(value["observed_at"])
    except (KeyError, TypeError, ValueError) as error:
        raise RecordError(f"{step}: invalid session observed_at") from error
    require(observed.tzinfo is not None, f"{step}: session observed_at needs timezone")
    return observed


def _opencode_launch(step: Path, launch: dict, raw: dict) -> str:
    call, response = launch.get("call"), launch.get("response")
    if not isinstance(call, dict) or not isinstance(response, dict):
        raise RecordError(f"{step}: missing launch API")
    require("sessionID" not in call, f"{step}: reused OpenCode child session")
    require(
        all(
            isinstance(call.get(key), str) and call[key].strip()
            for key in ("agent", "prompt", "description")
        ),
        f"{step}: incomplete OpenCode subagent call",
    )
    child = response.get("sessionID")
    if not isinstance(child, str) or not child.strip():
        raise RecordError(f"{step}: missing child session ID")
    require(child != launch.get("parent_session"), f"{step}: child is parent session")
    require(response.get("status") == "running", f"{step}: subagent did not launch")
    output = response.get("output")
    require(isinstance(output, str) and output.strip(), f"{step}: missing subagent output")
    state = raw.get("state")
    require(raw.get("type") == "tool" and raw.get("name") == "subagent", f"{step}: wrong raw tool")
    if not isinstance(state, dict):
        raise RecordError(f"{step}: unfinished raw launch")
    require(state.get("status") == "completed", f"{step}: unfinished raw launch")
    require(state.get("input") == call, f"{step}: raw launch call differs")
    metadata = state.get("metadata")
    require(
        isinstance(metadata, dict)
        and metadata.get("sessionID") == child
        and metadata.get("status") == "running",
        f"{step}: raw launch response differs",
    )
    require(
        isinstance(state.get("content"), list)
        and any(
            part.get("text") == response.get("output")
            for part in state["content"]
            if isinstance(part, dict)
        ),
        f"{step}: raw launch output differs",
    )
    return child


def _codex_launch(step: Path, launch: dict, raw: dict) -> str:
    call, response = launch.get("call"), launch.get("response")
    if not isinstance(call, dict) or not isinstance(response, dict):
        raise RecordError(f"{step}: missing launch API")
    require(call.get("fork_turns") == "none", f"{step}: Codex child inherited context")
    child = response.get("task_name")
    if not isinstance(child, str) or not child.strip():
        raise RecordError(f"{step}: missing child agent handle")
    require(
        raw == {"tool": "codex.spawn_agent", "call": call, "response": response},
        f"{step}: raw launch differs",
    )
    return child


def _terminal(step: Path, launch: dict, terminal: dict, raw: dict, child: str) -> None:
    response = terminal.get("response")
    if not isinstance(response, dict):
        raise RecordError(f"{step}: missing terminal API response")
    if launch["tool"] == "subagent":
        require(terminal.get("tool") == "opencode.sessions.get", f"{step}: wrong terminal tool")
        require(terminal.get("call") == {"sessionID": child}, f"{step}: wrong session get call")
        require(raw == response, f"{step}: raw session differs")
        require(response.get("id") == child, f"{step}: wrong terminal child")
        require(
            response.get("parentID") == launch["parent_session"], f"{step}: wrong parent session"
        )
        require(response.get("agent") == launch["call"]["agent"], f"{step}: wrong child agent")
        require("fork" not in response, f"{step}: child session inherited fork")
        require(response.get("outcome") == "succeeded", f"{step}: child did not succeed")
        return
    require(terminal.get("tool") == "codex.list_agents", f"{step}: wrong terminal tool")
    require(
        raw == {"tool": "codex.list_agents", "response": response}, f"{step}: raw terminal differs"
    )
    agents = response.get("agents")
    require(isinstance(agents, list), f"{step}: missing agent list")
    matches = [
        entry for entry in agents if isinstance(entry, dict) and entry.get("agent_name") == child
    ]
    require(len(matches) == 1, f"{step}: child not listed exactly once")
    status = matches[0].get("agent_status")
    require(
        isinstance(status, dict) and len(status) == 1 and next(iter(status)) == "completed",
        f"{step}: child did not complete successfully",
    )


def child_session(step: Path, agent: str) -> tuple[str, str]:
    """Return the coordinator parent and fresh child handle for one stage."""
    verify_manifest(step)
    launch, raw_launch = _session_files(step, "launch")
    terminal, raw_terminal = _session_files(step, "terminal")
    tool = launch.get("tool")
    require(tool in ("subagent", "codex.spawn_agent"), f"{step}: unsupported session tool")
    parent = launch.get("parent_session")
    if not isinstance(parent, str) or not parent.strip():
        raise RecordError(f"{step}: missing parent session")
    child = (
        _opencode_launch(step, launch, raw_launch)
        if tool == "subagent"
        else _codex_launch(step, launch, raw_launch)
    )
    require(child == agent, f"{step}: record agent differs from child session")
    require(
        _observed(terminal, step) >= _observed(launch, step), f"{step}: terminal predates launch"
    )
    _terminal(step, launch, terminal, raw_terminal, child)
    return parent, child


def _report_script() -> Path:
    configured = os.environ.get("REGRESSION_HUNT_REPORT_SCRIPT")
    script = Path(configured) if configured else REPORT_SCRIPT
    require(script.is_file(), f"regression-hunt report script missing: {script}")
    return script


def _campaign_report(campaign: Path) -> dict:
    try:
        result = subprocess.run(
            [sys.executable, str(_report_script()), str(campaign), "--verify-discovery"],
            capture_output=True,
            text=True,
            check=False,
            timeout=120,
        )
    except (OSError, subprocess.TimeoutExpired) as error:
        raise RecordError(f"regression campaign verification failed: {error}") from error
    require(result.returncode == 0, f"regression campaign invalid: {result.stderr.strip()}")
    try:
        report = json.loads(result.stdout)
    except json.JSONDecodeError as error:
        raise RecordError("regression campaign verifier returned invalid JSON") from error
    require(isinstance(report, dict), "regression campaign verifier returned non-object")
    return report


def _campaign_source(campaign: Path, name: str) -> Path:
    relative = PurePosixPath(name)
    require(not relative.is_absolute() and ".." not in relative.parts, "unsafe campaign receipt")
    source = (campaign / relative).resolve()
    require(
        source.is_relative_to(campaign.resolve()) and source.is_file(), "missing campaign receipt"
    )
    return source


def campaign_receipts(run_dir: Path, patch: dict, regression: dict) -> None:
    """Reconcile one pinned hunt with the copied result and decision receipts."""
    verify_manifest(run_dir / "regression")
    campaign = Path(regression["campaign_dir"])
    if not campaign.is_absolute():
        campaign = run_dir / campaign
    require(campaign.is_dir(), f"regression campaign missing: {campaign}")
    report = _campaign_report(campaign)
    index = _json(campaign / "campaign.json")
    changes = index.get("changes")
    if not isinstance(changes, list) or len(changes) != 1:
        raise RecordError("campaign needs one patch change")
    if not isinstance(changes[0], dict):
        raise RecordError("campaign change is not an object")
    source = changes[0].get("input")
    require(isinstance(source, dict), "campaign needs pinned source commits")
    require(
        source.get("s0") == patch["baseline_commit"] and source.get("s1") == patch["patch_commit"],
        "campaign source differs from patch attempt",
    )
    coverage = (
        "COMPLETE"
        if all(row["status"] == "COMPLETE" for row in report["changes"])
        else "INCOMPLETE"
    )
    require(regression["coverage"] == coverage, "regression coverage differs from campaign")
    snapshot = retained_file(run_dir, "regression/receipts/campaign-report.json", "regression")
    require(
        snapshot is not None and _json(snapshot) == report,
        "missing or stale campaign report receipt",
    )
    outcomes = {row["candidate_id"]: row for row in regression["outcomes"]}
    findings = {row["id"]: row for row in report["findings"]}
    require(len(outcomes) == len(regression["outcomes"]), "duplicate regression candidate")
    require(outcomes.keys() == findings.keys(), "regression candidates differ from campaign")
    candidates = {row["id"]: row for row in changes[0]["candidates"]}
    for candidate_id, outcome in outcomes.items():
        require(
            outcome["outcome"] == findings[candidate_id]["outcome"],
            "regression outcome differs from campaign",
        )
        name = outcome["decision_receipt"]
        copied = retained_file(run_dir, f"regression/receipts/{name}", "regression")
        if copied is None:
            raise RecordError(f"{candidate_id}: decision receipt missing from manifest")
        source_name = (
            candidates[candidate_id].get("decision") or candidates[candidate_id]["candidate"]
        )
        require(
            copied.read_bytes() == _campaign_source(campaign, source_name).read_bytes(),
            f"{candidate_id}: decision receipt differs from campaign",
        )


def completion_gaps(
    run_dir: Path, attempt: int, patch: dict, proof: dict, regression: dict
) -> list[str]:
    """Return concrete evidence gaps without asserting that agents followed instructions."""
    gaps = []
    try:
        patch_session = child_session(run_dir / f"patch/attempt-{attempt}", patch["agent"])
        prove_session = child_session(run_dir / f"prove/attempt-{attempt}", proof["agent"])
        require(patch_session[0] == prove_session[0], "patch and prove have different coordinators")
        require(patch_session[1] != prove_session[1], "patch and prove reused a child session")
    except (RecordError, OSError, ValueError, KeyError, TypeError) as error:
        gaps.append(f"patch/prove session: {error}")
    try:
        campaign_receipts(run_dir, patch, regression)
    except (RecordError, OSError, ValueError, KeyError, TypeError) as error:
        gaps.append(f"regression campaign: {error}")
    return gaps
