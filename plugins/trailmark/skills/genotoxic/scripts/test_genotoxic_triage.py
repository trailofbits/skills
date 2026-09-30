"""Tests for genotoxic_triage.py: binding, graph buckets, input formats, necessist merge."""

from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path

import pytest

SCRIPT = Path(__file__).resolve().parent / "genotoxic_triage.py"

pytestmark = pytest.mark.skipif(shutil.which("uv") is None, reason="uv is required")

BRANCHY = (
    "def parse(d):\n"
    + "".join(f"    if d == {i}:\n        return {i}\n" for i in range(12))
    + "    return -1\n"
)
LIB = """import sys


def small(x):
    return x + 1


def only_tested(x):
    return x * 2


def noisy(x):
    sys.stderr.write("value %d\\n" % x)
    return x


def dead(x):
    return x - 1
"""
APP = """from flask import Flask, request

from .core import parse
from .lib import noisy, small

app = Flask(__name__)


@app.route("/p", methods=["POST"])
def route():
    return str(noisy(small(parse(len(request.get_data())))))
"""
TEST = """from app.lib import only_tested, small


def test_small():
    small(1)
    assert only_tested(2) == 4
"""


@pytest.fixture(scope="module")
def project(tmp_path_factory) -> Path:
    root = tmp_path_factory.mktemp("proj with space")
    (root / "app").mkdir()
    (root / "app" / "__init__.py").write_text("")
    (root / "app" / "core.py").write_text(BRANCHY)
    (root / "app" / "lib.py").write_text(LIB)
    (root / "app" / "web.py").write_text(APP)
    (root / "tests").mkdir()
    (root / "tests" / "test_lib.py").write_text(TEST)
    return root


def triage(project: Path, *extra: str) -> subprocess.CompletedProcess:
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


def write(path: Path, data) -> Path:
    path.write_text(json.dumps(data))
    return path


MUTANTS = [
    {"id": "a", "file_path": "app/core.py", "line": 3, "status": "survived"},
    {"id": "b", "file_path": "app/lib.py", "line": 5, "status": "survived"},
    {"id": "c", "file_path": "app/lib.py", "line": 9, "status": "survived"},
    {"id": "d", "file_path": "app/lib.py", "line": 13, "status": "survived"},
    {"id": "e", "file_path": "app/lib.py", "line": 18, "status": "survived"},
    {"id": "f", "file_path": "README.md", "line": 1, "status": "survived"},
    {"id": "g", "file_path": "app/lib.py", "line": 5, "status": "killed"},
]


@pytest.fixture(scope="module")
def result(project, tmp_path_factory) -> dict:
    tmp = tmp_path_factory.mktemp("in")
    removals = write(
        tmp / "r.json",
        [
            {"test_file_path": "tests/test_lib.py", "line": 5, "removed_statement": "small(1)"},
            {"test_file_path": "tests/test_lib.py", "line": 6, "removed_statement": "print('x')"},
        ],
    )
    proc = triage(
        project, "--mutants", str(write(tmp / "m.json", MUTANTS)), "--necessist", str(removals)
    )
    assert proc.returncode == 0, proc.stderr
    return json.loads(proc.stdout)


def by_id(result: dict) -> dict:
    return {m["id"]: m for m in result["mutants"]}


def test_graph_buckets(result):
    m = by_id(result)
    assert "g" not in m  # killed mutants are dropped
    assert m["a"]["node_id"] == "app.core:parse" and m["a"]["graph_bucket"] == "fuzzing_targets"
    assert m["a"]["cyclomatic_complexity"] > 10 and m["a"]["entrypoint_paths"]
    assert m["b"]["graph_bucket"] == "missing_tests"
    assert m["c"]["graph_bucket"] == "false_positives" and m["c"]["reason"] == "only test callers"
    assert m["e"]["reason"] == "no callers (dead code)"
    assert m["f"]["reason"] == "no containing function in graph"


def test_logging_is_a_hint_not_a_bucket(result):
    m = by_id(result)["d"]
    assert m["logging_hint"] is True and m["graph_bucket"] == "missing_tests"


def test_necessist_mapping_and_corroboration(result):
    mapped, unmapped = result["necessist"]
    assert mapped["node_id"] == "app.lib:small" and mapped["graph_bucket"] == "missing_tests"
    assert unmapped["reason"] == "unmappable to production code"
    assert result["corroborated_nodes"] == ["app.lib:small"]


def test_mewt_results_are_converted(project, tmp_path):
    mewt = {
        "results": [
            {
                "mutant": {
                    "id": 7,
                    "line_offset": 4,
                    "mutation_slug": "AOS",
                    "old_text": "+",
                    "new_text": "-",
                },
                "target": {"path": "app/lib.py"},
                "outcome": {"status": "Uncaught"},
            }
        ]
    }
    proc = triage(project, "--mutants", str(write(tmp_path / "mewt.json", mewt)))
    m = json.loads(proc.stdout)["mutants"][0]
    assert m["line"] == 5 and m["node_id"] == "app.lib:small"


def test_bad_input(project, tmp_path):
    bad = tmp_path / "bad.json"
    bad.write_text("{}")
    assert triage(project, "--mutants", str(bad)).returncode == 2
    assert triage(project, "--mutants", str(tmp_path / "missing.json")).returncode == 2
    good = write(tmp_path / "ok.json", MUTANTS[:1])
    nobad = write(tmp_path / "n.json", [{"line": 1}])
    assert triage(project, "--mutants", str(good), "--necessist", str(nobad)).returncode == 2
