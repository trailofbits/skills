"""Validate coordinator-captured host observations, never substitute for host controls."""

from datetime import datetime
from pathlib import Path

from evidence import IntegrityError, files, local, read

AGENT_LAUNCH_TOOLS = ("codex.spawn_agent", "subagent")
AGENT_STATUS_TOOLS = ("codex.list_agents", "opencode.sessions.get")
FINISHED_STATUSES = ("completed", "errored")


def require(condition: object, message: str) -> None:
    if not condition:
        raise ValueError(message)


def timestamp(name: str, value: dict) -> datetime:
    observed = value.get("observed_at")
    require(isinstance(observed, str) and observed.strip(), f"{name}: missing observed_at")
    parsed = datetime.fromisoformat(value["observed_at"])
    require(parsed.tzinfo is not None, f"{name}: observed_at needs a timezone")
    return parsed


def retained(root: Path, name: str, value: dict, missing: str) -> dict:
    """Confine raw evidence to coordinator-owned runtime/ and hash it with its record."""
    evidence = value.get("evidence")
    if not isinstance(evidence, list) or not evidence:
        raise ValueError(f"{name}: {missing}")
    require(all(isinstance(p, str) for p in evidence), f"{name}: evidence must contain paths")
    for path in [name, *evidence]:
        require(
            local(root, path).is_relative_to(local(root, "runtime")),
            f"{name}: host observations and evidence belong in coordinator-owned runtime/",
        )
    hashes = files(root, [name, *evidence])
    for path in hashes:
        require(local(root, path).stat().st_size, f"{path}: empty runtime evidence")
    require(any(path != name for path in hashes), f"{name}: retain separate raw evidence")
    return {"record": name, "hashes": hashes, "value": value}


def observation(root: Path, name: str, attempt: dict, event: str) -> dict:
    """Keep host observations outside worker outputs and bind their raw evidence."""
    value = read(root, name)
    require(value.get("event") == event, f"{name}: expected {event} host observation")
    require(value.get("attempt") == attempt["id"], f"{name}: wrong host attempt")
    for field in ("host", "session", "agent", "context"):
        require(
            isinstance(value.get(field), str) and value[field].strip(),
            f"{name}: missing host {field}",
        )
    timestamp(name, value)
    return retained(root, name, value, "retain raw host evidence")


def agent_observation(root: Path, name: str, attempt: dict, event: str) -> dict:
    value = read(root, name)
    require(value.get("event") == event, f"{name}: expected {event} agent record")
    require(value.get("attempt") == attempt["id"], f"{name}: wrong agent attempt")
    timestamp(name, value)
    return retained(root, name, value, "retain the raw agent tool response")


def _codex_agent_launch(name: str, call: dict, response: dict) -> None:
    require(
        call.get("fork_turns") == "none",
        f"{name}: agent inherited conversation (fork_turns={call.get('fork_turns')!r})",
    )
    handle = response.get("task_name")
    require(isinstance(handle, str) and handle.strip(), f"{name}: response lacks the agent handle")


def _opencode_agent_launch(root: Path, name: str, receipt: dict, attempts: dict) -> None:
    value = receipt["value"]
    call, response = value["call"], value["response"]
    parent = value.get("parent_session")
    require(isinstance(parent, str) and parent.strip(), f"{name}: missing parent session")
    require("sessionID" not in call, f"{name}: pass no sessionID to start a new child")
    for field in ("agent", "description", "prompt"):
        require(
            isinstance(call.get(field), str) and call[field].strip(), f"{name}: missing {field}"
        )
    child = response.get("sessionID")
    require(isinstance(child, str) and child.strip(), f"{name}: response lacks child sessionID")
    require(child != parent, f"{name}: child session is the parent session")
    require(response.get("status") == "running", f"{name}: subagent response is not running")
    require(
        isinstance(response.get("output"), str) and response["output"].strip(),
        f"{name}: response lacks subagent output",
    )
    for other in attempts.values():
        if other["id"] == value["attempt"]:
            continue
        require(child != other.get("agent"), f"{name}: reused child session from {other['id']}")
    raw = read(root, value["evidence"][0])
    state = raw.get("state")
    require(raw.get("type") == "tool" and raw.get("name") == "subagent", f"{name}: wrong raw tool")
    if not isinstance(state, dict):
        raise ValueError(f"{name}: raw tool unfinished")
    require(state.get("status") == "completed", f"{name}: raw tool unfinished")
    require(state.get("input") == call, f"{name}: raw subagent call differs from record")
    metadata = state.get("metadata")
    require(
        isinstance(metadata, dict)
        and metadata.get("sessionID") == child
        and metadata.get("status") == "running",
        f"{name}: raw subagent response differs from record",
    )
    content = state.get("content")
    require(
        isinstance(content, list)
        and any(
            isinstance(part, dict) and part.get("text") == response["output"] for part in content
        ),
        f"{name}: raw subagent output differs from record",
    )


def agent_launch(root: Path, name: str, attempt: dict, attempts: dict) -> dict:
    """Accept a spawn record only when the new agent started without inherited conversation."""
    receipt = agent_observation(root, name, attempt, "launch")
    value = receipt["value"]
    tool = value.get("tool")
    require(
        tool in AGENT_LAUNCH_TOOLS,
        f"{name}: unsupported agent tool {tool!r}; add a recognizer before binding",
    )
    call, response = value.get("call"), value.get("response")
    require(
        isinstance(call, dict) and isinstance(response, dict),
        f"{name}: record the tool call and its response",
    )
    if tool == "subagent":
        _opencode_agent_launch(root, name, receipt, attempts)
    else:
        _codex_agent_launch(name, call, response)
    return receipt


def agent_handle(receipt: dict) -> str:
    response = receipt["value"]["response"]
    if receipt["value"]["tool"] == "subagent":
        return response["sessionID"]
    return response["task_name"]


def _opencode_agent_terminal(root: Path, name: str, receipt: dict, attempt: dict) -> None:
    value = receipt["value"]
    call, response = value.get("call"), value.get("response")
    require(
        isinstance(call, dict) and isinstance(response, dict),
        f"{name}: record the session get call and response",
    )
    launched = attempt["launch"]["value"]
    child = launched["response"]["sessionID"]
    require(call.get("sessionID") == child, f"{name}: wrong child session get call")
    require(response.get("id") == child, f"{name}: wrong child session")
    require(
        response.get("parentID") == launched["parent_session"],
        f"{name}: wrong parent session",
    )
    require(response.get("agent") == launched["call"]["agent"], f"{name}: wrong child agent")
    require("fork" not in response, f"{name}: child session inherited a fork")
    require(
        response.get("outcome") in ("succeeded", "failed"),
        f"{name}: child session has not finished",
    )
    require(
        read(root, value["evidence"][0]) == response, f"{name}: raw session differs from record"
    )


def agent_terminal(root: Path, name: str, attempt: dict) -> dict:
    """Accept a terminal observation for the same bound agent and tool family."""
    receipt = agent_observation(root, name, attempt, "terminal")
    value = receipt["value"]
    tool = value.get("tool")
    require(tool in AGENT_STATUS_TOOLS, f"{name}: unsupported agent status tool {tool!r}")
    launched_tool = attempt["launch"]["value"]["tool"]
    if launched_tool == "subagent":
        require(tool == "opencode.sessions.get", f"{name}: expected OpenCode session get")
        _opencode_agent_terminal(root, name, receipt, attempt)
        require(
            timestamp(name, value)
            >= timestamp(attempt["launch"]["record"], attempt["launch"]["value"]),
            f"{name}: terminal record predates launch",
        )
        return receipt
    require(tool == "codex.list_agents", f"{name}: expected Codex agent list")
    response = value.get("response")
    agents = response.get("agents") if isinstance(response, dict) else None
    if not isinstance(agents, list):
        raise ValueError(f"{name}: response lacks the agent list")
    statuses = [
        entry.get("agent_status")
        for entry in agents
        if isinstance(entry, dict) and entry.get("agent_name") == attempt["agent"]
    ]
    require(len(statuses) == 1, f"{name}: agent {attempt['agent']} is not listed exactly once")
    status = statuses[0]
    require(
        isinstance(status, dict) and len(status) == 1 and next(iter(status)) in FINISHED_STATUSES,
        f"{name}: agent has not finished (status {status!r})",
    )
    launched = attempt["launch"]
    require(
        timestamp(name, value) >= timestamp(launched["record"], launched["value"]),
        f"{name}: terminal record predates launch",
    )
    return receipt


def launch(root: Path, name: str, attempt: dict, attempts: dict) -> dict:
    receipt = observation(root, name, attempt, "launch")
    value = receipt["value"]
    require(value.get("fresh_context") is True, f"{name}: fresh context is not verified")
    require(value.get("isolated") is True, f"{name}: environment isolation is not verified")
    require(value.get("directory") == attempt["directory"], f"{name}: wrong attempt directory")
    require(
        isinstance(value.get("environment"), str) and value["environment"].strip(),
        f"{name}: missing host environment identity",
    )
    for other in attempts.values():
        if other["id"] == attempt["id"] or other.get("verification") != "isolated":
            continue
        prior = other["launch"]["value"]
        for field in ("agent", "context", "environment"):
            require(
                (value["host"], value["session"], value[field])
                != (prior["host"], prior["session"], prior[field]),
                f"{name}: reused host {field} from {other['id']}",
            )
    return receipt


def terminal(root: Path, name: str, attempt: dict) -> dict:
    receipt = observation(root, name, attempt, "terminal")
    value, started = receipt["value"], attempt["launch"]["value"]
    for field in ("host", "session", "agent", "context"):
        require(value[field] == started[field], f"{name}: wrong terminal {field}")
    require(
        value.get("state") in ("completed", "stopped", "failed"),
        f"{name}: host has not confirmed termination",
    )
    require(value.get("active_commands") == [], f"{name}: commands may still be running")
    require(
        value.get("resources_released") is True,
        f"{name}: release or isolate owned runtime resources before retry",
    )
    require(
        datetime.fromisoformat(value["observed_at"])
        >= datetime.fromisoformat(started["observed_at"]),
        f"{name}: terminal observation predates launch",
    )
    return receipt


def verify_receipt(root: Path, receipt: dict) -> None:
    """Reject runtime evidence that changed or disappeared after binding."""
    try:
        current = files(root, list(receipt["hashes"]))
    except ValueError as error:
        raise IntegrityError(f"{receipt['record']}: runtime evidence missing: {error}") from error
    if current != receipt["hashes"]:
        raise IntegrityError(f"{receipt['record']}: runtime evidence changed")
    if read(root, receipt["record"]) != receipt["value"]:
        raise IntegrityError(
            f"{receipt['record']}: stored launch data differs from the runtime record"
        )
