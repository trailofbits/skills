"""Tests for evolve.py. Unit tests need no Trailmark; the end-to-end test skips without it."""

from __future__ import annotations

import importlib.util
import json
import subprocess
from pathlib import Path

import pytest

SCRIPTS = Path(__file__).resolve().parent
SPEC = importlib.util.spec_from_file_location("evolve", SCRIPTS / "evolve.py")
evolve = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(evolve)


def graph(nodes: dict, edges: list, subgraphs: dict, **summary) -> dict:
    base = {
        "total_nodes": len(nodes),
        "functions": 0,
        "classes": 0,
        "call_edges": len(edges),
        "entrypoints": 0,
    }
    base.update(summary)
    return {
        "language": "python",
        "root_path": "/src",
        "summary": base,
        "nodes": nodes,
        "edges": edges,
        "subgraphs": subgraphs,
    }


def node(kind="function", cc=1, file="src/service.py"):
    return {"kind": kind, "cyclomatic_complexity": cc, "location": {"file_path": file}}


BEFORE = graph(
    {"m": node("module", None), "m:run": node(cc=2), "m:auth": node(), "m:query": node()},
    [{"source": "m:run", "target": "m:auth", "kind": "calls"}],
    {"tainted": ["m:run"], "privilege_boundary": ["m:auth"]},
    functions=3,
    entrypoints=1,
)
AFTER = graph(
    {
        "m": node("module", None),
        "m:run": node(cc=7),
        "m:query": node(),
        "m:export": node(file="src/api.rs"),
    },
    [
        {"source": "m:run", "target": "m:query", "kind": "calls"},
        {"source": "m:export", "target": "m:query", "kind": "calls"},
    ],
    {"tainted": ["m:run", "m:query", "m:export"], "high_blast_radius": ["m:query"]},
    functions=3,
    entrypoints=2,
)
NATIVE = {
    "summary_delta": {},
    "nodes": {
        "added": [
            {
                "id": "m:export",
                "name": "export",
                "kind": "function",
                "file": "src/api.rs",
                "cyclomatic_complexity": 1,
            }
        ],
        "removed": [
            {
                "id": "m:auth",
                "name": "auth",
                "kind": "function",
                "file": "src/service.py",
                "cyclomatic_complexity": 1,
            }
        ],
        "modified": [
            {"id": "m:run", "changes": {"cyclomatic_complexity": {"before": 2, "after": 7}}},
            {"id": "m", "changes": {"line_span": {"before": 3, "after": 4}}},
        ],
    },
    "edges": {
        "added": [
            {"source": "m:run", "target": "m:query", "kind": "calls"},
            {"source": "m:export", "target": "m:query", "kind": "calls"},
        ],
        "removed": [{"source": "m:run", "target": "m:auth", "kind": "calls"}],
    },
    "entrypoints": {
        "added": [
            {
                "id": "m:export",
                "kind": "api",
                "trust_level": "untrusted_external",
                "asset_value": "high",
                "description": None,
            }
        ],
        "removed": [],
        "modified": [
            {
                "id": "m:run",
                "before": {"kind": "api", "trust_level": "trusted_internal"},
                "after": {"kind": "api", "trust_level": "untrusted_external"},
            }
        ],
    },
}


def render(found=None):
    subgraph = evolve.compute_subgraph_diff(BEFORE, AFTER)
    found = evolve.candidates(NATIVE, subgraph, BEFORE, AFTER) if found is None else found
    return (
        evolve.render_report(
            name="t",
            project="p",
            before_label="v1",
            after_label="v2",
            language="auto",
            before=BEFORE,
            after=AFTER,
            native=NATIVE,
            subgraph=subgraph,
            found=found,
            evidence_dir="evidence",
            tool_version="0.5.0",
        ),
        subgraph,
        found,
    )


def test_candidates_cover_every_signal_class_with_proposed_severities():
    _, _, found = render()
    kinds = {f["kind"]: f["severity"] for f in found}
    assert kinds["new_entrypoint"] == "HIGH"  # untrusted_external
    assert kinds["entrypoint_trust_changed"] == "MEDIUM"
    assert kinds["tainted_sensitive_node"] == "HIGH"  # m:query matches the sensitive-name pattern
    assert kinds["new_high_blast_radius"] == "MEDIUM"
    assert kinds["privilege_boundary_removed"] == "MEDIUM"
    assert kinds["complexity_increase"] == "HIGH"  # +5 on a tainted node
    assert all(f["what"] and f["evidence"] and f["nodes"] for f in found)


def test_report_has_every_section_and_every_row():
    report, subgraph, found = render()
    for section in (
        "## Summary",
        "## Critical Structural Changes",
        "## Attack Surface Evolution",
        "### New Entrypoints",
        "### Removed Entrypoints",
        "### Modified Entrypoints",
        "## Complexity Evolution",
        "### Increased Complexity (CC delta > 0)",
        "### Decreased Complexity (CC delta < 0)",
        "## Taint Propagation Changes",
        "### Newly Tainted Nodes",
        "### De-Tainted Nodes",
        "## Blast Radius Shifts",
        "### Nodes Entering high_blast_radius",
        "### Nodes Leaving high_blast_radius",
        "## Privilege Boundary Changes",
        "### New Boundary Crossings",
        "### Removed Boundary Crossings",
        "## Subgraph Membership Changes",
        "## New Code (Added Nodes)",
        "## Removed Code (Deleted Nodes)",
        "## New Call Relationships (Added Edges)",
        "## Removed Call Relationships (Deleted Edges)",
        "## Methodology",
    ):
        assert section in report, section
    assert "| Total nodes | 4 | 4 | 0 |" in report
    assert "| Entrypoints | 1 | 2 | +1 |" in report
    assert "| m:run | 2 | 7 | +5 | src/service.py |" in report
    assert "| m:run | trusted_internal | untrusted_external | api |" in report
    assert "| m:export | m:query | calls |" in report and "| m:run | m:auth | calls |" in report
    assert "| m | line_span |" in report  # every modified node is listed
    for name, change in subgraph["subgraphs"].items():
        assert name in report
        for member in [*change["added"], *change["removed"]]:
            assert member in report
    assert "Python, Rust" in report
    assert "pre-analysis" in report.lower() and "limitation" in report.lower()


def test_todo_markers_only_where_the_reviewer_must_write():
    report, _, found = render()
    assert report.count("**Security impact:** TODO") == len(found)
    assert report.count("**Recommendation:** TODO") == len(found)
    assert (
        report.count(evolve.TODO) == 2 * len(found) + 1
    )  # plus the Methodology limitations marker
    empty, _, _ = render(found=[])
    assert "No pre-classified candidates" in empty and empty.count(evolve.TODO) == 1


def test_empty_sections_say_so():
    report, _, _ = render()
    section = report.split("### Removed Entrypoints")[1].split("###")[0]
    assert "No changes." in section


def test_health_check_rejects_empty_graphs():
    with pytest.raises(SystemExit, match="no functions or classes"):
        evolve.check_health(graph({}, [], {}, functions=0, classes=0), "before")


def test_mode_selection_is_exclusive(tmp_path):
    with pytest.raises(SystemExit, match="choose one mode"):
        evolve.main(["--language", "auto", "--output-dir", str(tmp_path)])
    with pytest.raises(SystemExit, match="choose one mode"):
        evolve.main(
            [
                "--before-dir",
                "a",
                "--before-graph",
                "b.json",
                "--language",
                "auto",
                "--output-dir",
                str(tmp_path),
            ]
        )
    with pytest.raises(SystemExit, match="all required for pre-exported mode"):
        evolve.main(
            ["--before-graph", "b.json", "--language", "auto", "--output-dir", str(tmp_path)]
        )


def test_pre_exported_mode_writes_complete_artifacts(tmp_path):
    for name, payload in (("b.json", BEFORE), ("a.json", AFTER), ("d.json", NATIVE)):
        (tmp_path / name).write_text(json.dumps(payload))
    out = tmp_path / "out"
    assert (
        evolve.main(
            [
                "--before-graph",
                str(tmp_path / "b.json"),
                "--after-graph",
                str(tmp_path / "a.json"),
                "--native-diff",
                str(tmp_path / "d.json"),
                "--language",
                "auto",
                "--output-dir",
                str(out),
                "--name",
                "unit",
            ]
        )
        == 0
    )
    assert json.loads((out / "evidence/before_graph.json").read_text()) == BEFORE
    assert json.loads((out / "evidence/after_graph.json").read_text()) == AFTER
    assert json.loads((out / "evidence/trailmark_diff.json").read_text()) == NATIVE
    assert json.loads(
        (out / "evidence/subgraph_diff.json").read_text()
    ) == evolve.compute_subgraph_diff(BEFORE, AFTER)
    packet = json.loads((out / "summary.json").read_text())
    assert (
        packet["report"] == "GRAPH_EVOLUTION_unit.md"
        and packet["candidates"]
        and packet["languages_detected"] == ["Python", "Rust"]
    )
    assert (out / "GRAPH_EVOLUTION_unit.md").read_text().startswith("# Graph Evolution Report")


def test_worktree_cleanup_removes_the_first_when_the_second_fails(tmp_path, monkeypatch):
    calls = []

    def fake_run(args, **_):
        calls.append(args)
        if "add" in args and args[-1] == "bad":
            return subprocess.CompletedProcess(args, 1, "", "bad ref")
        return subprocess.CompletedProcess(args, 0, "", "")

    monkeypatch.setattr(evolve.subprocess, "run", fake_run)
    with pytest.raises(SystemExit, match="bad ref"):
        evolve.checkout_worktrees(tmp_path, ("good", "bad"), tmp_path / "wt")
    removed = [a for a in calls if "remove" in a]
    assert len(removed) == 1 and removed[0][-1].endswith("before")
    assert any("prune" in a for a in calls)


def test_end_to_end_directories_match_the_trailmark_api(tmp_path):
    pytest.importorskip("trailmark")
    from trailmark.query.api import QueryEngine

    before, after = tmp_path / "before", tmp_path / "after"
    before.mkdir()
    after.mkdir()
    (before / "app.py").write_text("def run(x):\n    return x\n")
    (after / "app.py").write_text(
        "def run(x):\n    if x:\n        return helper(x)\n    return x\n\n\n"
        "def helper(x):\n    return x * 2\n"
    )
    out = tmp_path / "out"
    assert (
        evolve.main(
            [
                "--before-dir",
                str(before),
                "--after-dir",
                str(after),
                "--language",
                "python",
                "--output-dir",
                str(out),
                "--name",
                "e2e",
            ]
        )
        == 0
    )
    b = QueryEngine.from_directory(str(before), language="python")
    a = QueryEngine.from_directory(str(after), language="python")
    expected_native = a.diff_against(b)
    a.preanalysis()
    assert json.loads((out / "evidence/trailmark_diff.json").read_text()) == json.loads(
        json.dumps(expected_native, default=str)
    )
    assert json.loads((out / "evidence/after_graph.json").read_text()) == json.loads(a.to_json())
    report = (out / "GRAPH_EVOLUTION_e2e.md").read_text()
    assert "| app:helper |" in report and "## Methodology" in report


def test_assemble_copies_reviewed_findings_and_refuses_todos(tmp_path):
    for name, payload in (("b.json", BEFORE), ("a.json", AFTER), ("d.json", NATIVE)):
        (tmp_path / name).write_text(json.dumps(payload))
    out = tmp_path / "out"
    base_args = [
        "--before-graph",
        str(tmp_path / "b.json"),
        "--after-graph",
        str(tmp_path / "a.json"),
    ]
    base_args += ["--native-diff", str(tmp_path / "d.json"), "--language", "auto"]
    assert evolve.main([*base_args, "--output-dir", str(out), "--name", "asm"]) == 0
    findings = out / "findings.md"
    assert findings.read_text().count(evolve.TODO) >= 2
    report_path = out / "GRAPH_EVOLUTION_asm.md"
    assert evolve.FINDINGS_BEGIN in report_path.read_text()
    # Unreviewed findings still carry TODOs: assembling must refuse.
    with pytest.raises(SystemExit, match="marker"):
        evolve.main(["--assemble", "--output-dir", str(out)])
    reviewed = "### [HIGH] Reviewed finding\n\n**What changed:** x\n**Evidence:** y\n"
    reviewed += "**Security impact:** z\n**Recommendation:** w\n"
    findings.write_text(reviewed)
    # The Methodology marker is the reviewer's too; simulate completing it.
    report_path.write_text(
        report_path.read_text().replace(f"{evolve.TODO}: add limitations", "none")
    )
    assert evolve.main(["--assemble", "--output-dir", str(out)]) == 0
    report = report_path.read_text()
    assert "### [HIGH] Reviewed finding" in report and evolve.TODO not in report
    assert report.count(evolve.FINDINGS_BEGIN) == 1 and report.count(evolve.FINDINGS_END) == 1
    # Assembling twice is idempotent.
    assert evolve.main(["--assemble", "--output-dir", str(out)]) == 0
    assert report_path.read_text() == report


def test_assemble_requires_a_single_report_and_findings(tmp_path):
    with pytest.raises(SystemExit, match="exactly one"):
        evolve.main(["--assemble", "--output-dir", str(tmp_path)])
    (tmp_path / "GRAPH_EVOLUTION_x.md").write_text(
        "# r\n" + evolve.FINDINGS_BEGIN + "\n" + evolve.FINDINGS_END + "\n"
    )
    with pytest.raises(SystemExit, match="findings.md"):
        evolve.main(["--assemble", "--output-dir", str(tmp_path)])


def test_build_modes_still_require_language(tmp_path):
    with pytest.raises(SystemExit, match="--language is required"):
        evolve.main(["--before-dir", "a", "--after-dir", "b", "--output-dir", str(tmp_path)])
