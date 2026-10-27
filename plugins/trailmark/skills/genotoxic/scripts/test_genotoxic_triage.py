"""Tests for genotoxic_triage.py: binding, graph buckets, input formats, necessist merge."""

from __future__ import annotations

import importlib.util
import json
import re
import shutil
import subprocess
from pathlib import Path

import pytest

SCRIPT = Path(__file__).resolve().parent / "genotoxic_triage.py"
GRAPH_ANALYSIS = SCRIPT.parent.parent / "references" / "graph-analysis.md"

spec = importlib.util.spec_from_file_location("genotoxic_triage", SCRIPT)
gt = importlib.util.module_from_spec(spec)
spec.loader.exec_module(gt)


def uv() -> str:
    # Fail rather than skip: a skipped run leaves the script unexercised while CI is green.
    path = shutil.which("uv")
    if path is None:
        pytest.fail("uv is not on PATH; genotoxic_triage.py runs under `uv run`")
    return path


BRANCHY = (
    "def parse(d):\n"
    + "".join(f"    if d == {i}:\n        return {i}\n" for i in range(12))
    + "    return -1\n"
)
LIB = """import math
import sys


def small(x):
    return x + 1


def only_tested(x):
    return x * 2


def noisy(x):
    sys.stderr.write("value %d\\n" % x)
    return x


def dead(x):
    return x - 1


def fact(n):
    return 1 if n <= 1 else n * fact(n - 1)


def lg(x):
    return math.log(x)
"""
APP = """from flask import Flask, request

from .core import parse
from .lib import noisy, small

app = Flask(__name__)


@app.route("/p", methods=["POST"])
def route():
    return str(noisy(small(parse(len(request.get_data())))))
"""
DUP_A = "def deposit(x):\n    return x\n"
DUP_B = "def deposit(x):\n    return -x\n"
TEST = """from app.lib import fact, lg, only_tested, small


def test_small():
    small(1)
    assert only_tested(2) == 4
    assert fact(3) == 6
    assert lg(1) == 0
"""


@pytest.fixture(scope="module")
def project(tmp_path_factory) -> Path:
    root = tmp_path_factory.mktemp("proj with space")
    (root / "app").mkdir()
    (root / "app" / "__init__.py").write_text("")
    (root / "app" / "core.py").write_text(BRANCHY)
    (root / "app" / "lib.py").write_text(LIB)
    (root / "app" / "web.py").write_text(APP)
    (root / "app" / "acct_a.py").write_text(DUP_A)
    (root / "app" / "acct_b.py").write_text(DUP_B)
    (root / "tests").mkdir()
    (root / "tests" / "test_lib.py").write_text(TEST)
    return root


def triage(project: Path, *extra: str, cwd: Path | None = None) -> subprocess.CompletedProcess:
    return subprocess.run(
        [uv(), "run", "--quiet", str(SCRIPT), "--target", str(project), "--language", "python"]
        + list(extra),
        capture_output=True,
        text=True,
        cwd=cwd,
    )


def write(path: Path, data) -> Path:
    path.write_text(json.dumps(data))
    return path


MUTANTS = [
    {"id": "a", "file_path": "app/core.py", "line": 3, "status": "survived"},
    {"id": "b", "file_path": "app/lib.py", "line": 6, "status": "survived"},
    {"id": "c", "file_path": "app/lib.py", "line": 10, "status": "survived"},
    {"id": "d", "file_path": "app/lib.py", "line": 14, "status": "survived"},
    {"id": "e", "file_path": "app/lib.py", "line": 19, "status": "survived"},
    {"id": "f", "file_path": "README.md", "line": 1, "status": "survived"},
    {"id": "g", "file_path": "app/lib.py", "line": 6, "status": "killed"},
    {"id": "h", "file_path": "app/web.py", "line": 10, "status": "survived"},
    {"id": "i", "file_path": "app/lib.py", "line": 23, "status": "survived"},
    {"id": "j", "file_path": "app/lib.py", "line": 27, "status": "survived"},
    {"id": "k", "file_path": "app/lib.py", "line": 6, "status": "timeout"},
]
REMOVALS = [
    {"test_file_path": "tests/test_lib.py", "line": 5, "removed_statement": "small(1)"},
    {"test_file_path": "tests/test_lib.py", "line": 6, "removed_statement": "print('x')"},
    {
        "test_file_path": "tests/test_lib.py",
        "line": 7,
        "removed_statement": "self.assertEqual(only_tested(3), 6)",
    },
    {"test_file_path": "tests/test_acct.py", "line": 3, "removed_statement": "deposit(1)"},
    {"test_file_path": "test/Vault.t.sol", "line": 9, "removed_statement": "vm.prank(alice);"},
    {"test_file_path": "test/Vault.t.sol", "line": 8, "removed_statement": 'vm.label(a, "a");'},
]


@pytest.fixture(scope="module")
def result(project, tmp_path_factory) -> dict:
    tmp = tmp_path_factory.mktemp("in")
    proc = triage(
        project,
        "--mutants",
        str(write(tmp / "m.json", MUTANTS)),
        "--necessist",
        str(write(tmp / "r.json", REMOVALS)),
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
    assert m["e"]["reason"].startswith("no callers (dead code)")
    assert "dynamic dispatch" in m["e"]["reason"]


def test_unbound_records_are_not_false_positives(result):
    f = by_id(result)["f"]
    assert f["graph_bucket"] == "unbound" and "not in the graph" in f["reason"]


def test_entrypoint_without_callers_is_not_dead_code(result):
    h = by_id(result)["h"]
    assert h["node_id"] == "app.web:route" and h["is_entrypoint"] is True
    assert h["graph_bucket"] != "false_positives"


def test_self_recursion_is_not_a_production_caller(result):
    i = by_id(result)["i"]
    assert i["node_id"] == "app.lib:fact" and i["production_callers"] == []
    assert i["reason"] == "only test callers"


def test_logging_is_a_hint_not_a_bucket(result):
    m = by_id(result)
    assert m["d"]["logging_hint"] is True and m["d"]["graph_bucket"] == "missing_tests"
    assert m["j"]["logging_hint"] is False  # math.log is arithmetic, not logging


def test_dropped_statuses_are_counted(result):
    assert result["dropped_statuses"] == {"killed": 1, "timeout": 1}


def test_necessist_mapping_and_corroboration(result):
    small, printed, wrapped, dup, prank, label = result["necessist"]
    assert small["node_id"] == "app.lib:small" and small["graph_bucket"] == "missing_tests"
    assert printed["reason"] == "unmappable to production code"
    assert wrapped["node_id"] == "app.lib:only_tested"  # inner call, not assertEqual
    assert dup["graph_bucket"] == "needs_review"
    assert dup["ambiguous_candidates"] == ["app.acct_a:deposit", "app.acct_b:deposit"]
    assert prank["graph_bucket"] == "missing_tests" and "vm.prank" in prank["reason"]
    assert label["graph_bucket"] == "false_positives"
    assert result["corroborated_nodes"] == ["app.lib:small"]


def test_blast_radius_needs_cc_above_5():
    ev = {
        "cyclomatic_complexity": 1,
        "production_callers": ["x"],
        "test_callers": [],
        "is_entrypoint": False,
        "entrypoint_paths": [],
        "tainted": False,
        "privilege_boundary": False,
        "high_blast_radius": True,
        "entrypoint_reachable": False,
    }
    assert gt.classify(ev)[0] == "missing_tests"
    assert gt.classify(dict(ev, cyclomatic_complexity=6))[0] == "fuzzing_targets"


@pytest.mark.parametrize(
    "path,expected",
    [
        ("src/Button.test.ts", True),
        ("src/Button.spec.tsx", True),
        ("spec/models/user_spec.rb", True),
        ("conftest.py", True),
        ("Tests/AppTests/Login.swift", True),
        ("test/Vault.t.sol", True),
        ("app/spec/models/user.rb", False),
        ("src/latest.py", False),
    ],
)
def test_test_path_patterns(path, expected):
    assert gt.is_test(path) is expected


def test_mewt_results_are_converted_and_null_outcomes_dropped(project, tmp_path):
    def result_for(i, status):
        return {
            "mutant": {
                "id": i,
                "line_offset": 5,
                "mutation_slug": "AOS",
                "old_text": "+",
                "new_text": "-",
            },
            "target": {"path": "app/lib.py"},
            "outcome": {"status": status} if status else None,
        }

    mewt = {"results": [result_for(7, "Uncaught"), result_for(8, None), result_for(9, "Timeout")]}
    proc = triage(project, "--mutants", str(write(tmp_path / "mewt.json", mewt)))
    out = json.loads(proc.stdout)
    assert [m["id"] for m in out["mutants"]] == [7]
    assert out["mutants"][0]["line"] == 6 and out["mutants"][0]["node_id"] == "app.lib:small"
    assert out["dropped_statuses"] == {"no_outcome": 1, "timeout": 1}


def test_working_directory_relative_paths_bind(project, tmp_path):
    mutants = write(tmp_path / "m.json", [{"id": 1, "file_path": "lib.py", "line": 6}])
    proc = triage(project, "--mutants", str(mutants), cwd=project / "app")
    assert proc.returncode == 0, proc.stderr
    assert json.loads(proc.stdout)["mutants"][0]["node_id"] == "app.lib:small"


def test_nothing_binds_exits_nonzero(project, tmp_path):
    mutants = write(tmp_path / "m.json", [{"id": 1, "file_path": "elsewhere/x.py", "line": 2}])
    proc = triage(project, "--mutants", str(mutants))
    assert proc.returncode == 2 and "none of 1 survived mutants bind" in proc.stderr
    assert json.loads(proc.stdout)["mutants"][0]["graph_bucket"] == "unbound"


def test_all_killed_succeeds_with_a_note(project, tmp_path):
    mutants = write(
        tmp_path / "m.json", [{"file_path": "app/lib.py", "line": 6, "status": "killed"}]
    )
    proc = triage(project, "--mutants", str(mutants))
    assert proc.returncode == 0 and "no survived mutants to triage" in proc.stderr


def test_out_writes_full_json_and_prints_a_summary(project, tmp_path):
    out = tmp_path / "triage.json"
    proc = triage(
        project, "--mutants", str(write(tmp_path / "m.json", MUTANTS[:2])), "--out", str(out)
    )
    assert proc.returncode == 0, proc.stderr
    summary = json.loads(proc.stdout)
    assert summary["out"] == str(out) and "graph_bucket_counts" in summary
    assert len(json.loads(out.read_text())["mutants"]) == 2 and summary["mutants"] == 2


def test_bad_input(project, tmp_path):
    bad = tmp_path / "bad.json"
    bad.write_text("{}")
    assert triage(project, "--mutants", str(bad)).returncode == 2
    assert triage(project, "--mutants", str(write(tmp_path / "e.json", []))).returncode == 2
    assert triage(project, "--mutants", str(tmp_path / "missing.json")).returncode == 2
    good = write(tmp_path / "ok.json", MUTANTS[:1])
    nobad = write(tmp_path / "n.json", [{"line": 1}])
    assert triage(project, "--mutants", str(good), "--necessist", str(nobad)).returncode == 2


def test_graph_analysis_recipes_bind_and_classify(project):
    """The manual route in references/graph-analysis.md must work on a real graph too."""
    blocks = re.findall(r"```python\n(.*?)```", GRAPH_ANALYSIS.read_text(), flags=re.S)
    defs = "\n\n".join(b for b in blocks if b.lstrip().startswith(("def ", "import")))
    code = (
        defs
        + "\nimport json\nfrom trailmark.query.api import QueryEngine\n"
        + 'engine = QueryEngine.from_directory(".", language="python")\n'
        + "engine.preanalysis()\n"
        + "mutants = "
        + json.dumps(
            [
                {"id": "route", "file_path": "app/web.py", "line": 10},
                {"id": "small", "file_path": "app/lib.py", "line": 6},
                {"id": "dead", "file_path": "app/lib.py", "line": 19},
            ]
        )
        + "\nres = batch_triage(engine, mutants)\n"
        + "print(json.dumps({k: sorted(m['id'] for m in v) for k, v in res.items()}))\n"
    )
    proc = subprocess.run(
        [
            uv(),
            "run",
            "--quiet",
            "--no-project",
            "--with",
            "trailmark>=0.5,<0.6",
            "python",
            "-c",
            code,
        ],
        capture_output=True,
        text=True,
        cwd=project,
    )
    assert proc.returncode == 0, proc.stderr
    buckets = json.loads(proc.stdout.splitlines()[-1])
    assert buckets["false_positives"] == ["dead"]
    assert sorted(buckets["missing_tests"]) == ["route", "small"]


def test_undecided_outcomes_are_an_incomplete_campaign_not_success(project, tmp_path):
    mewt = {
        "results": [
            {
                "mutant": {"id": 1, "line_offset": 5},
                "target": {"path": "app/lib.py"},
                "outcome": None,
            }
        ]
    }
    proc = triage(project, "--mutants", str(write(tmp_path / "mewt.json", mewt)))
    assert proc.returncode == 2 and "incomplete" in proc.stderr
    odd = [{"file_path": "app/lib.py", "line": 6, "status": "pending"}]
    assert triage(project, "--mutants", str(write(tmp_path / "odd.json", odd))).returncode == 2


def test_one_record_jsonl_files_are_accepted(project, tmp_path):
    one = tmp_path / "one.jsonl"
    one.write_text(json.dumps({"id": 1, "file_path": "app/lib.py", "line": 6}) + "\n")
    removal = tmp_path / "r.jsonl"
    removal.write_text(
        json.dumps(
            {"test_file_path": "tests/test_lib.py", "line": 5, "removed_statement": "small(1)"}
        )
        + "\n"
    )
    proc = triage(project, "--mutants", str(one), "--necessist", str(removal))
    assert proc.returncode == 0, proc.stderr
    out = json.loads(proc.stdout)
    assert (
        out["mutants"][0]["node_id"] == "app.lib:small"
        and out["necessist"][0]["node_id"] == "app.lib:small"
    )
