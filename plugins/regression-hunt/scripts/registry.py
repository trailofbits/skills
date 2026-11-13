"""Reserve campaign identities and validate assignments; never launch or judge agents."""

import argparse
import fcntl
import json
import os
import tempfile
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path

from evidence import IntegrityError, digest, files, local, read, verify
from runtime import agent_handle, agent_launch, agent_terminal, launch, terminal, verify_receipt

VERSION = 3
LEVELS = {"isolated": 2, "shared-host": 1}

STAGES = ("prepare", "hunt", "reproduce", "replay", "adjudicate", "report")
CANDIDATE_STAGES = ("reproduce", "replay", "adjudicate")
BUILD_STAGES = ("reproduce", "replay")


def require(condition: object, message: str) -> None:
    if not condition:
        raise ValueError(message)


def load(root: Path) -> dict:
    path = local(root, "registry.json")
    if not path.exists():
        require(
            not local(root, "attempts").exists(),
            "Missing registry: restore it before reserving IDs",
        )
        return {"version": VERSION, "scope": None, "attempts": {}, "prefixes": {}, "candidates": {}}
    data = read(root, "registry.json")
    if data.get("version") != VERSION:
        raise ValueError(
            f"Unsupported registry version {data.get('version')}: this helper requires version "
            f"{VERSION} and does not migrate; do not reset the registry"
        )
    for field in ("attempts", "prefixes", "candidates"):
        require(
            isinstance(data.get(field), dict), f"Invalid registry {field}; restore the registry"
        )
    scope = data.get("scope")
    if not isinstance(scope, dict):
        raise ValueError("Missing frozen scope; restore the registry")
    if digest(local(root, scope["file"])) != scope["hash"]:
        raise IntegrityError("Frozen scope changed; restore it")
    return data


def changes_by_id(changes: list[dict] | None) -> dict:
    if not isinstance(changes, list) or not changes:
        raise ValueError("Scope needs a nonempty change list")
    result = {}
    for change in changes:
        if not isinstance(change, dict):
            raise ValueError("Scope changes must be ID/input objects")
        cid = change.get("id")
        require(isinstance(cid, str) and cid.strip(), "Scope needs nonempty change IDs")
        require(cid != "campaign" and cid not in result, f"Invalid or duplicate scope ID: {cid}")
        require(change.get("input"), f"{cid}: missing original input")
        result[cid] = change["input"]
    return result


def initialize(root: Path) -> dict:
    """Freeze the original request before any assignment or mutable progress exists."""
    with transaction(root) as data:
        require(
            not data["attempts"], "Initialize scope before dispatch; never replace campaign scope"
        )
        changes = changes_by_id(read(root, "scope.json").get("changes"))
        scope = {
            "file": "scope.json",
            "hash": digest(local(root, "scope.json")),
            "changes": changes,
        }
        require(data.get("scope") in (None, scope), "Campaign scope is already frozen")
        data["scope"] = scope
        return scope


def check_scope(root: Path, campaign: dict) -> None:
    require(local(root, "registry.json").is_file(), "Missing registry: initialize campaign scope")
    with transaction(root, write=False) as data:
        require(data.get("scope"), "Initialize scope before reporting")
        require(
            changes_by_id(campaign.get("changes")) == data["scope"]["changes"],
            "Campaign differs from frozen scope: restore missing, added or changed inputs",
        )


def save(root: Path, data: dict) -> None:
    """Publish a complete registry, leaving the old file intact if writing fails."""
    target = local(root, "registry.json")
    fd, name = tempfile.mkstemp(prefix=".registry-", dir=root)
    temporary = Path(name)
    try:
        with os.fdopen(fd, "w") as stream:
            json.dump(data, stream, indent=2, sort_keys=True)
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, target)
        directory_fd = os.open(root, os.O_RDONLY)
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
    finally:
        temporary.unlink(missing_ok=True)


@contextmanager
def transaction(root: Path, *, write: bool = True) -> Iterator[dict]:
    """Serialize reservations and publish each operation atomically."""
    with local(root, ".registry.lock").open("a+b") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        data = load(root)
        yield data
        if write:
            save(root, data)


def inputs_snapshot(root: Path, inputs: list[str]) -> dict[str, str]:
    require(isinstance(inputs, list), "inputs must be a list of campaign-relative paths")
    require(all(isinstance(p, str) and p for p in inputs), "inputs must contain nonempty paths")
    require(len(inputs) == len(set(inputs)), "Duplicate assignment inputs")
    names = list(inputs)
    for name in inputs:
        if local(root, name + ".seal.json").exists():
            verify(root, name)
            names.append(name + ".seal.json")
    return files(root, names)


def assigned(data: dict, attempt_id: str) -> dict:
    require(attempt_id in data["attempts"], f"Unknown attempt: {attempt_id}")
    return data["attempts"][attempt_id]


def candidate_input(data: dict, assignment: dict) -> None:
    cid = assignment.get("candidate")
    if assignment["stage"] not in CANDIDATE_STAGES:
        require(cid is None, "Only reproduction, replay and adjudication take a candidate")
        return
    require(cid in data["candidates"], f"Unknown candidate: {cid}")
    entry = data["candidates"][cid]
    require(entry["change"] == assignment["change"], f"{cid}: wrong assigned change")
    require(
        entry.get("file") in assignment["inputs"], f"{cid}: include the accepted candidate file"
    )


def prerequisite_changes(root: Path, change: str, inputs: list[str]) -> None:
    if change == "campaign":
        return
    for name in inputs:
        if local(root, name + ".seal.json").exists():
            require(
                read(root, name).get("change") == change,
                f"{name}: prerequisite belongs to another change",
            )


def new_attempt(root: Path, data: dict, assignment: dict, *, prefix: str | None = None) -> dict:
    stage = assignment.get("stage")
    require(stage in STAGES, f"Unknown stage: {stage}")
    change = assignment.get("change")
    if not isinstance(change, str) or not change.strip():
        raise ValueError("Assignment needs a change ID")
    require(data.get("scope"), "Initialize scope before reserving attempts")
    require(
        change == "campaign" if stage == "report" else change in data["scope"]["changes"],
        f"{change}: assignment is outside frozen scope",
    )
    inputs = assignment.get("inputs", [])
    hashes = inputs_snapshot(root, inputs)
    prerequisite_changes(root, change, inputs)
    candidate_input(data, {**assignment, "inputs": inputs})
    if stage == "hunt" and prefix is None:
        prefix = f"h{len(data['prefixes']) + 1:03}-"
        require(prefix not in data["prefixes"], f"Prefix collision: {prefix}")
        data["prefixes"][prefix] = change
    if prefix is not None:
        require(
            not any(
                a["prefix"] == prefix and a["state"] in ("reserved", "running")
                for a in data["attempts"].values()
            ),
            f"{prefix}: discovery attempt is still active",
        )
    aid = f"a{len(data['attempts']) + 1:03}"
    directory = f"attempts/{aid}"
    require(aid not in data["attempts"], f"Attempt ID collision: {aid}")
    require(not local(root, directory).exists(), f"Attempt directory already exists: {directory}")
    attempt = {
        "id": aid,
        "stage": stage,
        "change": change,
        "candidate": assignment.get("candidate"),
        "prefix": prefix,
        "inputs": inputs,
        "input_hashes": hashes,
        "directory": directory,
        "agent": None,
        "state": "reserved",
        "record": None,
        "seal": None,
        "launch": None,
        "terminal": None,
        "verification": None,
    }
    data["attempts"][aid] = attempt
    return attempt


def reserve(root: Path, assignment: dict) -> dict:
    with transaction(root) as data:
        return new_attempt(root, data, assignment)


def distinct_candidate_agent(data: dict, attempt: dict, agent: str) -> None:
    """One agent handle may reproduce, replay or adjudicate a candidate, never two of these."""
    if attempt["stage"] not in CANDIDATE_STAGES:
        return
    for other in data["attempts"].values():
        require(
            other["id"] == attempt["id"]
            or other["stage"] not in CANDIDATE_STAGES
            or other["candidate"] != attempt["candidate"]
            or other["agent"] != agent,
            f"{attempt['id']}: agent {agent} already worked on candidate "
            f"{attempt['candidate']} in {other['id']}",
        )


def host_binding(root: Path, data: dict, attempt: dict, agent: str, record: str) -> dict:
    receipt = launch(root, record, attempt, data["attempts"])
    require(receipt["value"]["agent"] == agent, f"{attempt['id']}: wrong host agent")
    return receipt


def agent_binding(root: Path, data: dict, attempt: dict, agent: str, record: str) -> dict:
    receipt = agent_launch(root, record, attempt)
    require(agent_handle(receipt) == agent, f"{attempt['id']}: wrong agent handle")
    return receipt


def bind(
    root: Path,
    attempt_id: str,
    agent: str,
    host_record: str | None = None,
    *,
    agent_record: str | None = None,
) -> dict:
    require(isinstance(agent, str) and agent.strip(), "Record the actual agent handle")
    require(
        (host_record is None) != (agent_record is None),
        "Bind with exactly one of --host-record or --agent-record",
    )
    with transaction(root) as data:
        attempt = assigned(data, attempt_id)
        require(attempt["state"] in ("reserved", "running"), f"{attempt_id}: {attempt['state']}")
        require(
            attempt["agent"] in (None, agent),
            f"{attempt_id}: agent already assigned; retry instead",
        )
        if host_record is not None:
            receipt, level = host_binding(root, data, attempt, agent, host_record), "isolated"
        elif agent_record is not None:
            receipt, level = agent_binding(root, data, attempt, agent, agent_record), "shared-host"
        require(attempt["launch"] in (None, receipt), f"{attempt_id}: launch evidence changed")
        distinct_candidate_agent(data, attempt, agent)
        attempt.update(agent=agent, launch=receipt, state="running", verification=level)
        return attempt


def candidate(root: Path, attempt_id: str, key: str, agent: str) -> str:
    """Reserve once per stable discovery key, including across interrupted attempts."""
    require(isinstance(key, str) and key.strip(), "Candidate key must describe the hypothesis")
    with transaction(root) as data:
        attempt = assigned(data, attempt_id)
        require(attempt["state"] == "running", f"{attempt_id}: {attempt['state']}")
        require(attempt["stage"] == "hunt", "Only hunt attempts allocate candidates")
        require(attempt["agent"] == agent, f"{attempt_id}: wrong agent")
        prefix = attempt["prefix"]
        existing = {cid: c for cid, c in data["candidates"].items() if c["prefix"] == prefix}
        for cid, entry in existing.items():
            if entry["key"] == key:
                return cid
        cid = f"{prefix}{len(existing) + 1:03}"
        require(cid not in data["candidates"], f"Candidate ID collision: {cid}")
        data["candidates"][cid] = {
            "prefix": prefix,
            "key": key,
            "change": attempt["change"],
            "file": None,
        }
        return cid


def stopped(root: Path, attempt: dict, host_record: str | None, agent_record: str | None) -> dict:
    """Require termination evidence of the same kind as the launch evidence."""
    level = attempt.get("verification")
    if level == "isolated" and host_record is not None and agent_record is None:
        return terminal(root, host_record, attempt)
    if level == "shared-host" and agent_record is not None and host_record is None:
        return agent_terminal(root, agent_record, attempt)
    raise ValueError(
        f"{attempt['id']}: retry {level} attempts with the matching record type "
        "(--host-record for isolated, --agent-record for shared-host)"
    )


def retry(
    root: Path,
    attempt_id: str,
    inputs: list[str] | None = None,
    *,
    host_record: str | None = None,
    agent_record: str | None = None,
) -> dict:
    """Retire an assignment only after the coordinator records confirmed termination."""
    with transaction(root) as data:
        old = assigned(data, attempt_id)
        require(old["state"] != "superseded", f"{attempt_id}: already superseded")
        require(old["launch"], f"{attempt_id}: recover and bind the launch before retry")
        verify_receipt(root, old["launch"])
        old["terminal"] = stopped(root, old, host_record, agent_record)
        old["state"] = "superseded"
        assignment = {k: old[k] for k in ("stage", "change", "candidate", "inputs")}
        if inputs is not None:
            assignment["inputs"] = inputs
        return new_attempt(root, data, assignment, prefix=old["prefix"])


def inside(root: Path, name: str, directory: str) -> None:
    require(
        local(root, name).is_relative_to(local(root, directory)),
        f"{name}: outside assigned directory {directory}",
    )


def hunt_candidates(root: Path, data: dict, attempt: dict, value: dict, name: str) -> dict:
    expected = {cid for cid, c in data["candidates"].items() if c["prefix"] == attempt["prefix"]}
    listed = value.get("candidates")
    if not isinstance(listed, list) or not all(isinstance(c, str) for c in listed):
        raise ValueError(f"{name}: candidates must be an ID list")
    require(
        len(listed) == len(set(listed)) and set(listed) == expected,
        f"{name}: duplicate, missing or unassigned candidate IDs",
    )
    paths = value.get("candidate_files")
    if not isinstance(paths, dict) or set(paths) != expected:
        raise ValueError(f"{name}: candidate_files must map every assigned candidate ID")
    sealed = read(root, name + ".seal.json")["artifacts"]
    for cid, path in paths.items():
        inside(root, path, attempt["directory"])
        require(path in sealed, f"{cid}: candidate file is not sealed")
        entry = read(root, path)
        require(entry.get("id") == cid, f"{path}: wrong candidate ID")
        require(entry.get("key") == data["candidates"][cid]["key"], f"{cid}: candidate key changed")
    return paths


def build_directories(root: Path, attempt: dict, value: dict, name: str) -> None:
    """A completed reproduction or replay may build only inside its own fresh attempt directory."""
    if attempt["stage"] not in BUILD_STAGES or value.get("status") != "complete":
        return
    dirs = value.get("build_dirs")
    if not isinstance(dirs, list) or not dirs or not all(isinstance(d, str) and d for d in dirs):
        raise ValueError(f"{name}: list every build directory in build_dirs")
    own = local(root, attempt["directory"]).resolve()
    for directory in dirs:
        outside = (
            f"{attempt['id']}: build dir {directory} is outside attempt directory "
            f"{attempt['directory']}"
        )
        try:
            path = local(root, directory).resolve()
        except ValueError as error:
            raise ValueError(f"{outside} ({error})") from error
        require(path.is_relative_to(own), outside)


def checked(root: Path, data: dict, attempt_id: str, name: str) -> dict:
    attempt = assigned(data, attempt_id)
    require(attempt["state"] in ("running", "accepted"), f"{attempt_id}: {attempt['state']}")
    verify_receipt(root, attempt["launch"])
    inside(root, name, attempt["directory"])
    value = verify(root, name)
    for field, expected in (
        ("attempt", attempt_id),
        ("stage", attempt["stage"]),
        ("agent", attempt["agent"]),
        ("candidate", attempt["candidate"]),
        ("change", attempt["change"]),
    ):
        require(value.get(field) == expected, f"{name}: wrong assigned {field}")
    require(value.get("status") in ("complete", "blocked"), f"{name}: invalid completion status")
    require(sorted(value["inputs"]) == sorted(attempt["inputs"]), f"{name}: wrong assigned inputs")
    if inputs_snapshot(root, attempt["inputs"]) != attempt["input_hashes"]:
        raise IntegrityError(
            f"{attempt_id}: inputs changed since assignment; retry with new inputs"
        )
    for path in value["artifacts"]:
        inside(root, path, attempt["directory"])
    build_directories(root, attempt, value, name)
    if attempt["state"] == "accepted" and (
        attempt["record"] != name or attempt["seal"] != digest(local(root, name + ".seal.json"))
    ):
        raise IntegrityError(f"{attempt_id}: accepted record changed")
    if attempt["stage"] == "hunt":
        hunt_candidates(root, data, attempt, value, name)
    return value


def check_change(value: dict, change: str, name: str) -> None:
    """Records must belong to the indexed change, including early exclusions."""
    require(value.get("change") == change, f"{name}: wrong indexed change")


def check(root: Path, attempt_id: str, name: str) -> dict:
    with transaction(root, write=False) as data:
        return checked(root, data, attempt_id, name)


def unaccepted_reason(root: Path, data: dict, name: str) -> str:
    """Explain why a record has no accepted owner; the record itself is untrusted here."""
    try:
        value = read(root, name)
    except (OSError, ValueError) as error:
        return f"{name}: unreadable unaccepted record: {error}"
    aid = value.get("attempt")
    if not isinstance(aid, str) or not aid:
        return f"{name}: missing registered attempt ID"
    if aid not in data["attempts"]:
        return f"Unknown attempt: {aid}"
    return f"{aid}: result is not accepted ({data['attempts'][aid]['state']})"


def accepted(root: Path, name: str) -> dict:
    """Require registry acceptance; any later change to an accepted record is an integrity error."""
    with transaction(root, write=False) as data:
        owner = next(
            (
                a
                for a in data["attempts"].values()
                if a.get("record") == name and a["state"] == "accepted"
            ),
            None,
        )
        if owner is None:
            raise ValueError(unaccepted_reason(root, data, name))
        try:
            value = read(root, name)
            if value.get("attempt") != owner["id"]:
                raise IntegrityError(
                    f"{name}: accepted record names attempt {value.get('attempt')!r}, "
                    f"not {owner['id']}"
                )
            return checked(root, data, owner["id"], name)
        except IntegrityError:
            raise
        except (OSError, ValueError, KeyError, TypeError) as error:
            raise IntegrityError(f"{name}: accepted record no longer validates: {error}") from error


def receipt_level(attempt: dict) -> str | None:
    value = (attempt.get("launch") or {}).get("value") or {}
    if "tool" in value:
        return "shared-host"
    if value.get("isolated") is True:
        return "isolated"
    return None


def verification(root: Path, names: list[str]) -> str | None:
    """Return the weakest verification level among the records' attempts, or None."""
    with transaction(root, write=False) as data:
        owners = [assigned(data, read(root, name).get("attempt", "")) for name in names]
        levels = [
            a.get("verification") if a.get("verification") == receipt_level(a) else None
            for a in owners
        ]
    known = [level for level in levels if isinstance(level, str) and level in LEVELS]
    if len(known) != len(levels):
        return None
    return min(known, key=lambda level: LEVELS[level])


def accept(root: Path, attempt_id: str, name: str) -> dict:
    with transaction(root) as data:
        value = checked(root, data, attempt_id, name)
        attempt = assigned(data, attempt_id)
        if attempt["stage"] == "hunt":
            for cid, path in value["candidate_files"].items():
                data["candidates"][cid]["file"] = path
        attempt.update(state="accepted", record=name, seal=digest(local(root, name + ".seal.json")))
        return attempt


def show(root: Path) -> dict:
    with transaction(root, write=False) as data:
        return data


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(description=__doc__)
    commands = result.add_subparsers(dest="command", required=True)
    for command in ("init", "reserve", "bind", "candidate", "retry", "check", "accept", "show"):
        sub = commands.add_parser(command)
        sub.add_argument("campaign", type=Path)
        command_arguments(sub, command)
    return result


def command_arguments(sub: argparse.ArgumentParser, command: str) -> None:
    if command not in ("init", "reserve", "show"):
        sub.add_argument("attempt")
    if command == "reserve":
        sub.add_argument("--stage", choices=STAGES, required=True)
        sub.add_argument("--change", required=True)
        sub.add_argument("--candidate")
        sub.add_argument("--input", action="append", default=[])
    if command in ("bind", "candidate"):
        sub.add_argument("--agent", required=True)
    if command in ("bind", "retry"):
        records = sub.add_mutually_exclusive_group(required=True)
        records.add_argument("--host-record")
        records.add_argument("--agent-record")
    if command == "candidate":
        sub.add_argument("--key", required=True)
    if command == "retry":
        sub.add_argument("--inputs", nargs="*")
    if command in ("accept", "check"):
        sub.add_argument("record")


def execute(args: argparse.Namespace) -> object:
    root = args.campaign.resolve(strict=True)
    if args.command == "reserve":
        return reserve(
            root,
            {
                "stage": args.stage,
                "change": args.change,
                "candidate": args.candidate,
                "inputs": args.input,
            },
        )
    operations = {
        "init": lambda: initialize(root),
        "bind": lambda: bind(
            root, args.attempt, args.agent, args.host_record, agent_record=args.agent_record
        ),
        "candidate": lambda: {"candidate": candidate(root, args.attempt, args.key, args.agent)},
        "retry": lambda: retry(
            root,
            args.attempt,
            args.inputs,
            host_record=args.host_record,
            agent_record=args.agent_record,
        ),
        "check": lambda: check(root, args.attempt, args.record),
        "accept": lambda: accept(root, args.attempt, args.record),
        "show": lambda: show(root),
    }
    return operations[args.command]()


def main() -> None:
    command = parser()
    args = command.parse_args()
    try:
        value = execute(args)
    except (OSError, ValueError, KeyError, TypeError) as error:
        command.exit(1, f"Registry {args.command} error: {error}\n")
    print(json.dumps(value, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
