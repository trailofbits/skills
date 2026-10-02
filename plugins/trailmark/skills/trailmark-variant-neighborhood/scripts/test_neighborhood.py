"""Tests for neighborhood.py on a generated project: dimensions, caps, exclusions, binding."""

from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path

import pytest

SCRIPT = Path(__file__).resolve().parent / "neighborhood.py"

pytestmark = pytest.mark.skipif(shutil.which("uv") is None, reason="uv is required")

SINK = "import os\n\n\ndef run(cmd):\n    return os.system(cmd)\n"
SEED = "from .sink import run\n\n\ndef seed(p):\n    return run('x ' + p)\n"
API = """from flask import Flask, request

from .sink import run
from .seedmod import seed
from .kinds import A, B

app = Flask(__name__)


@app.route("/s", methods=["POST"])
def handler():
    helper()
    return seed(request.form["p"])


def helper():
    return 1


@app.route("/k", methods=["POST"])
def kind():
    return (A() if request.form["k"] == "a" else B()).go(request.form["p"])
"""
KINDS = """from .sink import run


class Base:
    def go(self, p):
        raise NotImplementedError


class A(Base):
    def go(self, p):
        return run('a ' + p)


class B(Base):
    def go(self, p):
        return 0
"""


@pytest.fixture(scope="module")
def project(tmp_path_factory) -> Path:
    root = tmp_path_factory.mktemp("proj with space")
    pkg = root / "app"
    pkg.mkdir()
    (pkg / "__init__.py").write_text("")
    (pkg / "sink.py").write_text(SINK)
    (pkg / "seedmod.py").write_text(SEED)
    (pkg / "api.py").write_text(API)
    (pkg / "kinds.py").write_text(KINDS)
    ops = "from .sink import run\n\n" + "".join(
        f"\ndef op{i}():\n    return run('fixed {i}')\n\n" for i in range(12)
    )
    (pkg / "ops.py").write_text(ops)
    tests = root / "tests"
    tests.mkdir()
    (tests / "test_sink.py").write_text(
        "from app.sink import run\n\n\ndef test_run():\n    run('true')\n"
    )
    return root


def nbhd(project: Path, *extra: str) -> subprocess.CompletedProcess:
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
            *extra,
        ],
        capture_output=True,
        text=True,
    )


@pytest.fixture(scope="module")
def result(project) -> dict:
    proc = nbhd(project, "--seed", "app/seedmod.py:5", "--cap", "5")
    assert proc.returncode == 0, proc.stderr
    return json.loads(proc.stdout)


def test_seed_binding_and_paths(result):
    seed = result["seed"]
    assert seed["node"] == "app.seedmod:seed"
    assert seed["entrypoint_paths"] == [["app.api:handler", "app.seedmod:seed"]]
    assert seed["callers"] == ["app.api:handler"]


def test_same_sink_is_capped_and_drops_are_listed(result):
    d = result["dimensions"]["same_sink"]
    assert len(d["shown"]) == 5 and d["total"] == len(d["shown"]) + len(d["dropped"])
    assert d["total"] >= 13  # 12 fixed ops + A.go, the test caller excluded
    assert set(result["candidates_over_cap"]) <= set(d["dropped"])


def test_same_caller_and_interface_siblings(result):
    assert result["dimensions"]["same_caller"]["shown"] == ["app.api:helper"]
    interface = set(result["dimensions"]["same_interface"]["shown"])
    assert {"app.kinds:A.go", "app.kinds:B.go"} <= interface


def test_test_callers_are_excluded_with_a_reason(result):
    assert result["exclusions"] == [
        {"node": "tests.test_sink:test_run", "file": "tests/test_sink.py", "reason": "test"}
    ]
    assert all(c["status"] == "candidate" for c in result["candidates"])


def test_include_tests_and_node_id_seed(project):
    proc = nbhd(project, "--seed", "app.seedmod:seed", "--include-tests")
    data = json.loads(proc.stdout)
    assert proc.returncode == 0 and data["exclusions"] == []
    sink = data["dimensions"]["same_sink"]
    assert "tests.test_sink:test_run" in sink["shown"] + sink["dropped"]


def test_unbound_seed_and_bad_args(project):
    proc = nbhd(project, "--seed", "app/sink.py:1")
    assert proc.returncode == 2 and "does not bind" in proc.stderr
    assert nbhd(project, "--seed", "nonsense").returncode == 2
    assert nbhd(project, "--seed", "app.seedmod:seed", "--cap", "0").returncode == 2
