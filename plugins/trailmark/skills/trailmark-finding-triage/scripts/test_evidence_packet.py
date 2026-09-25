"""Tests for evidence_packet.py: one graph build, exact binding, evidence fields per finding."""

from __future__ import annotations

import json
import shutil
import subprocess
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
