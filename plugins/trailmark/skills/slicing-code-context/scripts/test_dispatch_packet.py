"""Exercise request transport, exact-packet provenance, errors, and source drift."""

import json
import os
import subprocess
import uuid
from pathlib import Path

import pytest

import build_slice_packet as builder
import dispatch_packet as dispatch
import validate_worker_response as validator


@pytest.fixture
def slice_request(tmp_path, monkeypatch):
    monkeypatch.setattr(dispatch.tempfile, "gettempdir", lambda: str(tmp_path))
    source = tmp_path / "source with spaces"
    source.mkdir()
    (source / "app.py").write_text("def target():\n    return 1\n")
    node = {
        "name": "target",
        "kind": "function",
        "location": {
            "file_path": "app.py",
            "start_line": 1,
            "end_line": 2,
        },
    }
    graph = builder.GraphView({"app:target": node}, [])
    monkeypatch.setattr(builder, "load_trailmark_graph", lambda *_a, **_kw: (graph, ["python"]))
    path = tmp_path / "request.json"
    args = [
        "--target-dir",
        str(source),
        "--symbol",
        "target",
        "--format",
        "json",
        "--task",
        "Explain the caller's assumptions",
    ]
    path.write_text(json.dumps({"builder_args": args}))
    return path, args, str(uuid.uuid4())


def worker_response():
    return {
        "status": "complete",
        "answer": "Returns one.",
        "evidence": [
            {"claim": "constant return", "file": "app.py", "start_line": 1, "end_line": 2}
        ],
        "proposed_edits": [],
        "missing_context": [],
        "uncertainties": [],
    }


def test_saves_exact_worker_bytes_and_never_rebuilds(slice_request):
    path, _args, session = slice_request
    paths = dispatch.prepare(path, session)
    raw = dispatch.consume(session)
    assert Path(paths["packet"]).read_bytes() == raw
    packet = json.loads(raw)
    assert not validator.validate(packet, worker_response())
    assert not validator.verify_receipt(raw, Path(paths["receipt"]), packet)
    assert Path(paths["response"]).parent == Path(paths["packet"]).parent
    with pytest.raises(FileNotFoundError):
        dispatch.consume(session)


@pytest.mark.parametrize(
    "task",
    [
        "caller's assumptions",
        "$(touch INJECTED)",
        "`touch INJECTED`",
        "'; touch INJECTED; #",
        'quote";\n日本語 $HOME',
    ],
)
def test_task_metacharacters_are_data(slice_request, task, monkeypatch, tmp_path):
    path, args, session = slice_request
    args[-1] = task
    path.write_text(json.dumps({"builder_args": args}))
    monkeypatch.chdir(tmp_path)
    dispatch.prepare(path, session)
    packet = json.loads(dispatch.consume(session))
    assert packet["selection"]["task"] == task
    assert not (tmp_path / "INJECTED").exists()


def test_pending_request_is_not_overwritten(slice_request):
    path, _args, session = slice_request
    first = dispatch.prepare(path, session)
    with pytest.raises(FileExistsError):
        dispatch.prepare(path, session)
    pending = json.loads((dispatch.session_directory(session) / "pending.json").read_text())
    assert pending["attempt"] == Path(first["packet"]).parent.name
    assert json.loads(dispatch.consume(session))["selection"]["task"].endswith("assumptions")


def test_known_failure_preserves_all_candidate_ids(slice_request, monkeypatch):
    path, _args, session = slice_request
    paths = dispatch.prepare(path, session)
    details = [{"id": "a:target"}, {"id": "b:target"}]

    def fail(*_args, **_kwargs):
        raise builder.SlicePacketError("ambiguous_symbol", "Choose an exact ID", details)

    monkeypatch.setattr(builder, "construct_packet", fail)
    raw = dispatch.consume(session)
    error = json.loads(raw)
    assert error["error"]["details"] == details
    receipt = json.loads(Path(paths["receipt"]).read_text())
    assert receipt["builder_exit_status"] == 2
    assert validator.validate(error, worker_response())


def test_unexpected_exception_is_not_swallowed(slice_request, monkeypatch):
    path, _args, session = slice_request
    dispatch.prepare(path, session)

    def bug(*_args, **_kwargs):
        raise RuntimeError("unexpected implementation failure")

    monkeypatch.setattr(builder, "construct_packet", bug)
    with pytest.raises(RuntimeError, match="unexpected implementation"):
        dispatch.consume(session)


def test_bare_mode_refuses_before_disclosing_or_claiming_source(slice_request, monkeypatch):
    path, _args, session = slice_request
    paths = dispatch.prepare(path, session)
    monkeypatch.setenv("CLAUDE_CODE_SIMPLE", "1")
    with pytest.raises(ValueError, match="Bare mode"):
        dispatch.consume(session)
    assert not Path(paths["packet"]).exists()
    assert (dispatch.session_directory(session) / "pending.json").is_file()


def test_error_cli_preserves_every_candidate(slice_request, monkeypatch, capsys):
    path, _args, session = slice_request
    paths = dispatch.prepare(path, session)
    details = [{"id": "a:target", "file": "a.py"}, {"id": "b:target", "file": "b.py"}]

    def fail(*_args, **_kwargs):
        raise builder.SlicePacketError("ambiguous_symbol", "Choose an exact ID", details)

    monkeypatch.setattr(builder, "construct_packet", fail)
    packet = json.loads(dispatch.consume(session))
    Path(paths["response"]).write_text(
        json.dumps(worker_response() | {"status": "cannot_answer", "evidence": []})
    )
    assert (
        validator.main(
            [paths["response"], "--packet", paths["packet"], "--receipt", paths["receipt"]]
        )
        == 1
    )
    verdict = json.loads(capsys.readouterr().out)
    assert verdict["builder_error"] == packet["error"]
    assert verdict["builder_error"]["details"] == details


def test_concurrent_consumers_cannot_replay_a_request(slice_request, tmp_path):
    path, _args, session = slice_request
    paths = dispatch.prepare(path, session)
    command = [
        "uv",
        "run",
        "--no-project",
        str(Path(dispatch.__file__)),
        "consume",
        "--session",
        session,
    ]
    env = {**os.environ, "TMPDIR": str(tmp_path)}
    children = [
        subprocess.Popen(command, env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        for _ in range(2)
    ]
    outputs = [child.communicate(timeout=120) for child in children]
    assert sorted(child.returncode for child in children) == [0, 2]
    winner = next(i for i, child in enumerate(children) if child.returncode == 0)
    assert outputs[winner][0] == Path(paths["packet"]).read_bytes()
    assert json.loads(outputs[winner][0])["slices"]


@pytest.mark.parametrize("change", ["packet", "request", "source"])
def test_receipt_rejects_tampering_or_changed_source(slice_request, change):
    path, args, session = slice_request
    paths = dispatch.prepare(path, session)
    raw = dispatch.consume(session)
    if change == "packet":
        raw += b" "
    elif change == "request":
        Path(paths["request"]).write_text("{}")
    else:
        (Path(args[1]) / "app.py").write_text("def target():\n    return 2\n")
    assert validator.verify_receipt(raw, Path(paths["receipt"]), json.loads(raw))


@pytest.mark.parametrize(
    "extra", [["--format", "markdown"], ["--help", "x"], ["--task", "duplicate"]]
)
def test_dispatch_rejects_non_json_and_duplicate_or_unknown_options(slice_request, extra):
    path, args, session = slice_request
    path.write_text(json.dumps({"builder_args": args + extra}))
    with pytest.raises(ValueError):
        dispatch.prepare(path, session)


def test_symlinked_private_root_is_rejected(slice_request, tmp_path):
    path, _args, session = slice_request
    other = tmp_path / "other"
    other.mkdir()
    (tmp_path / f"trailmark-slices-{os.getuid()}").symlink_to(other, target_is_directory=True)
    with pytest.raises(ValueError, match="private"):
        dispatch.prepare(path, session)


def test_real_dynamic_command_uses_only_host_session_and_static_script(slice_request, tmp_path):
    path, args, session = slice_request
    marker = tmp_path / "INJECTED"
    args[-1] = f"caller's task; $(touch '{marker}') `touch '{marker}'` 日本語"
    path.write_text(json.dumps({"builder_args": args}))
    paths = dispatch.prepare(path, session)
    skill = Path(__file__).parents[2] / "code-slice-dispatch" / "SKILL.md"
    command = next(line[2:-1] for line in skill.read_text().splitlines() if line.startswith("!`"))
    assert "$ARGUMENTS" not in command
    env = {
        **os.environ,
        "CLAUDE_SESSION_ID": session,
        "CLAUDE_SKILL_DIR": str(skill.parent),
        "TMPDIR": str(tmp_path),
        "ARGUMENTS": "'; touch INJECTED; #",
    }
    run = subprocess.run(
        ["bash", "-c", command], cwd=tmp_path, env=env, text=True, capture_output=True, timeout=120
    )
    assert run.returncode == 0, run.stdout + run.stderr
    assert json.loads(run.stdout)["selection"]["task"] == args[-1]
    assert Path(paths["packet"]).read_text() == run.stdout
    assert not marker.exists()
