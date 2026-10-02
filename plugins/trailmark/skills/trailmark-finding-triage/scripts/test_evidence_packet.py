"""Tests for evidence_packet.py: one graph build, exact binding, evidence fields per finding."""

from __future__ import annotations

import argparse
import importlib.util
import json
import shutil
import subprocess
import sys
import types
from pathlib import Path

import pytest

SCRIPT = Path(__file__).resolve().parent / "evidence_packet.py"

pytestmark = pytest.mark.skipif(shutil.which("uv") is None, reason="uv is required")

APP = """from flask import Flask, request

from .store import load, parse

app = Flask(__name__)


@app.route("/upload", methods=["POST"])
def upload():
    return parse(request.get_data())


@app.route("/item/<key>")
def item(key):
    return load(key)
"""
STORE = """import pickle


def parse(blob):
    return pickle.loads(blob)


def load(key):
    def inner(k):
        return open("/data/" + k).read()

    return inner(key)


def unused(expr):
    return eval(expr)
"""


@pytest.fixture(scope="module")
def project(tmp_path_factory) -> Path:
    root = tmp_path_factory.mktemp("proj with space")
    pkg = root / "svc"
    pkg.mkdir()
    (pkg / "__init__.py").write_text("")
    (pkg / "app.py").write_text(APP)
    (pkg / "store.py").write_text(STORE)
    (root / "NOTES.txt").write_text("not code\n")
    return root


def run(project: Path, *findings: str, extra: tuple[str, ...] = ()) -> subprocess.CompletedProcess:
    args = [a for f in findings for a in ("--finding", f)]
    return subprocess.run(
        [
            "uv",
            "run",
            "--quiet",
            "--no-project",
            str(SCRIPT),
            "--target",
            str(project),
            "--language",
            "python",
            *args,
            *extra,
        ],
        capture_output=True,
        text=True,
    )


@pytest.fixture(scope="module")
def packet(project) -> dict:
    proc = run(project, "svc/store.py:5", "svc/store.py:5-9", "svc/store.py:16", "NOTES.txt:1")
    assert proc.returncode == 0, proc.stderr
    return json.loads(proc.stdout)


def test_reachable_sink_has_paths_and_taint(packet):
    f = packet["findings"][0]
    assert f["bound_node"] == "svc.store:parse" and f["binding"] == "exact"
    assert [p["path"] for p in f["entrypoint_paths"]] == [["svc.app:upload", "svc.store:parse"]]
    assert f["entrypoint_paths"][0]["trust_level"] == "untrusted_external"
    assert f["tainted"] is True and f["entrypoint_reachable"] is True
    assert f["callers"] == ["svc.app:upload"]
    assert packet["trailmark_version"].startswith("0.5")


def test_range_spanning_two_functions_lists_both_and_picks_narrowest(packet):
    f = packet["findings"][1]
    ids = [m["id"] for m in f["matches"]]
    assert set(ids) == {"svc.store:parse", "svc.store:load"}
    assert f["bound_node"] == "svc.store:parse" and f["binding"].startswith("ambiguous")


def test_dead_code_has_no_paths(packet):
    f = packet["findings"][2]
    assert f["bound_node"] == "svc.store:unused"
    assert f["entrypoint_paths"] == [] and f["callers"] == [] and f["entrypoint_reachable"] is False


def test_non_source_anchor_is_unbound(packet):
    f = packet["findings"][3]
    assert f["bound_node"] is None and "not in the graph" in f["binding"]


def test_absolute_paths_and_out_file(project, tmp_path):
    out = tmp_path / "ev.json"
    proc = run(project, f"{project}/svc/store.py:5", extra=("--out", str(out)))
    assert proc.returncode == 0, proc.stderr
    assert json.loads(out.read_text())["findings"][0]["bound_node"] == "svc.store:parse"


def test_bad_arguments(project, tmp_path):
    assert run(project, "svc/store.py").returncode == 2
    proc = subprocess.run(
        [
            "uv",
            "run",
            "--quiet",
            str(SCRIPT),
            "--target",
            str(tmp_path / "nope"),
            "--finding",
            "a.py:1",
        ],
        capture_output=True,
        text=True,
    )
    assert proc.returncode == 2 and "not a directory" in proc.stderr


def test_module_declaration_binds_and_diagnostics_are_explicit(project):
    proc = run(project, "svc/store.py:1")
    assert proc.returncode == 0, proc.stderr
    packet = json.loads(proc.stdout)
    assert packet["findings"][0]["binding_kind"] == "module"
    assert packet["graph"]["parser_diagnostics_available"] is False
    assert packet["graph"]["limitations"]


def test_subdirectory_target_and_ambiguous_paths(project, monkeypatch, tmp_path):
    monkeypatch.chdir(project)
    proc = run(project / "svc", "svc/store.py:5")
    assert proc.returncode == 0, proc.stderr
    assert json.loads(proc.stdout)["findings"][0]["bound_node"] == "store:parse"
    (tmp_path / "store.py").write_text("def other():\n    pass\n")
    monkeypatch.chdir(tmp_path)
    proc = run(project / "svc", "store.py:5")
    assert proc.returncode == 2 and "ambiguous path" in proc.stderr
    proc = run(project / "svc", "store.py:5", extra=("--path-base", "target"))
    assert proc.returncode == 0, proc.stderr
    assert json.loads(proc.stdout)["findings"][0]["bound_node"] == "store:parse"


@pytest.mark.parametrize("anchor", ["svc/store.py:0", "svc/store.py:9-4", "svc/store.py:5:2"])
def test_invalid_ranges_and_columns_fail_before_graph(project, anchor, monkeypatch):
    spec = importlib.util.spec_from_file_location("packet_test", SCRIPT)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    api = types.ModuleType("trailmark.query.api")
    api.QueryEngine = types.SimpleNamespace(
        from_directory=lambda *_a, **_kw: pytest.fail("graph built for invalid argument")
    )
    monkeypatch.setitem(sys.modules, "trailmark", types.ModuleType("trailmark"))
    monkeypatch.setitem(sys.modules, "trailmark.query", types.ModuleType("trailmark.query"))
    monkeypatch.setitem(sys.modules, "trailmark.query.api", api)
    with pytest.raises(ValueError):
        module.build(argparse.Namespace(target=str(project), language="python", finding=[anchor]))


def test_container_and_procedure_binding_ignores_null_locations(tmp_path):
    spec = importlib.util.spec_from_file_location("packet_binding", SCRIPT)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    for kind in module.CALLABLE | module.CONTAINERS:
        nodes = {
            "item": {
                "id": "item",
                "kind": kind,
                "location": {"file_path": "a.sol", "start_line": 1, "end_line": 5},
            },
            "proxy": {"id": "proxy", "kind": "proxy", "location": None},
        }
        assert module.bind(nodes, "a.sol", 1, 1, tmp_path)[0]["kind"] == kind


def test_empty_graph_and_output_failure_are_clear(project, tmp_path):
    proc = run(project, "svc/store.py:5", extra=("--language", "solidity"))
    assert proc.returncode == 2 and "no nodes" in proc.stderr and not proc.stdout
    proc = run(project, "svc/store.py:5", extra=("--out", str(tmp_path)))
    assert proc.returncode == 2 and "cannot write" in proc.stderr
    assert "Traceback" not in proc.stderr


def test_output_summary_preserves_complete_packet(project, tmp_path):
    full = json.loads(run(project, "svc/store.py:5").stdout)
    out = tmp_path / "complete.json"
    proc = run(project, "svc/store.py:5", extra=("--out", str(out)))
    assert proc.returncode == 0, proc.stderr
    assert json.loads(out.read_text()) == full
    assert json.loads(proc.stdout)["complete_evidence_on_disk"] is True


def test_real_class_and_solidity_contract_declarations(tmp_path):
    (tmp_path / "a.py").write_text(
        "class Settings:\n    secret = 'example'\n    def read(self):\n        return self.secret\n"
    )
    proc = run(tmp_path, "a.py:1")
    assert proc.returncode == 0, proc.stderr
    assert json.loads(proc.stdout)["findings"][0]["binding_kind"] == "class"
    (tmp_path / "Vault.sol").write_text(
        "pragma solidity ^0.8.0;\ncontract Vault {\n uint public balance;\n"
        " function get() public view returns(uint) { return balance; }\n}\n"
    )
    proc = run(tmp_path, "Vault.sol:2", extra=("--language", "solidity"))
    assert proc.returncode == 0, proc.stderr
    finding = json.loads(proc.stdout)["findings"][0]
    assert finding["bound_node"] is not None and finding["binding_kind"] in ("contract", "class")
