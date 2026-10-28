"""Structural evidence and artifact gates; native engine contracts live in test_runner."""

from __future__ import annotations

import json
import os
import subprocess
import sys
from collections import Counter
from pathlib import Path
from unittest.mock import patch

import pytest

sys.path.insert(0, str(Path(__file__).parent))

import taint_trace as tt  # noqa: E402
from manifest_validation import validate_model_fields  # noqa: E402
from runner import run_native  # noqa: E402
from trace_artifacts import JsonObject  # noqa: E402


def edge(source, target, kind="calls", **attributes):
    return {
        "source": source,
        "target": target,
        "kind": kind,
        "confidence": "heuristic",
        "attributes": attributes,
    }


def test_reference_edges_and_deferred_calls_remain_distinct():
    graph = {
        "nodes": {key: {"name": key} for key in ("entry", "sink", "callback")},
        "edges": [edge("entry", "sink", deferred=True), edge("entry", "callback", "references")],
    }
    packets = tt.neighborhoods(graph, [{"node_id": "entry"}], ["entry", "sink", "callback"])
    assert packets[0]["slices"][0]["entrypoint_paths"] == [["entry"]]
    assert packets[1]["slices"][0]["entrypoint_paths"] == [["entry", "sink"]]
    assert packets[1]["slices"][0]["edges"][0]["attributes"]["deferred"] is True
    assert packets[2]["slices"][0]["entrypoint_paths"] == []


def test_focus_binding_ambiguity_unresolved_and_bounded_slices():
    graph = {
        "nodes": {str(i): {"name": "overload"} for i in range(150)},
        "edges": [edge(str(i), str(i + 1)) for i in range(149)],
    }
    packets = tt.neighborhoods(graph, [], ["overload", "missing"], limit=4)
    assert packets[0]["binding"] == "ambiguous"
    assert len(packets[0]["matches"]) == 150
    assert len(packets[0]["slices"]) == 4
    assert all(len(p["nodes"]) <= 4 for p in packets[0]["slices"])
    assert packets[1]["binding"] == "unresolved"


def context(root: Path) -> JsonObject:
    source = root / "app.py"
    return {
        "schema_version": 1,
        "target": str(root),
        "trailmark_version": "test",
        "capabilities": list(tt.REQUIRED_APIS),
        "summary": {"source_file_counts": {"python": 1}},
        "source_policy": {"roots": [str(root)], "files": [{"path": str(source)}]},
        "source_hashes": {"app.py": tt.digest(source)},
        "configuration_files": [],
        "parse_diagnostics": [],
        "graph": {
            "nodes": {
                "request": {
                    "name": "request",
                    "location": {"file_path": str(source), "start_line": 1, "end_line": 3},
                }
            },
            "edges": [],
        },
    }


@pytest.fixture
def artifacts(tmp_path):
    root = tmp_path
    (root / "app.py").write_text("def request():\n    sink(value)\n    return value\n")
    snapshot = context(root)
    tt.snapshot_sources(snapshot, root / "context.json")
    tt.write_json(root / "context.json", snapshot)
    manifest = {
        "schema_version": 1,
        "target": str(root),
        "context": "context.json",
        "models": [],
        "components": [],
        "limitations": [],
    }
    tt.write_json(root / "manifest.json", manifest)
    return root, manifest


def fake_run(root: Path, phase: str, *, model: Path | None = None, line: int = 2) -> JsonObject:
    """Mock native execution; real engine contracts live in test_runner."""
    output = {
        "tool": "joern",
        "findings": [
            {
                "rule_id": "fixture-rule",
                "file": "app.py",
                "line": line,
                "message": "artifact fixture",
            }
        ],
        "scanned_files": ["app.py"],
        "errors": [],
    }

    def execute(argv, cwd, timeout):
        return 0, "joern fixture 1.0" if "--version" in argv else json.dumps(output), "", []

    with patch("runner.execute", execute):
        return run_native(
            backend="joern",
            language="python",
            phase=phase,
            scope="interprocedural",
            output=root / f"{phase}.json",
            cwd=root,
            argv=["joern", "--script", "trace.sc"],
            version_argv=["joern", "--version"],
            models=[model] if model else [],
        )


def active_component(root, monkeypatch, manifest):
    # Capability assertions themselves are tested against real tools in test_runner.
    monkeypatch.setattr("runner.check_probe", lambda proof, path: [])
    tt.write_json(
        root / "probe.json",
        {
            "backend": "joern",
            "language": "python",
            "expect": {"cross_function": [{"file": "app.py", "line": 2}]},
        },
    )
    fake_run(root, "baseline")
    manifest["components"] = [
        {
            "id": "app",
            "language": "python",
            "backend": "joern",
            "scope": "interprocedural",
            "status": "analyzed",
            "reason": "",
            "gaps": [],
            "probe": "probe.json",
            "baseline": "baseline.json",
            "enriched": "enriched.json",
        }
    ]


def test_fully_skipped_report_records_failure(artifacts):
    root, manifest = artifacts
    manifest["components"] = [
        {
            "id": "legacy",
            "language": "cairo",
            "status": "skipped",
            "reason": "Positive native fixture did not report the flow.",
        }
    ]
    tt.write_json(root / "manifest.json", manifest)
    result = tt.render_report(root / "manifest.json", root / "report.md")
    assert not result["valid"] and result["skipped_components"] == 1
    assert result["status"] == "failed"
    assert "skipped" in (root / "report.md").read_text()


def test_baseline_gate_rejects_preexisting_edits(artifacts, monkeypatch):
    root, manifest = artifacts
    active_component(root, monkeypatch, manifest)
    tt.write_json(root / "manifest.json", manifest)
    assert tt.validate_manifest(root / "manifest.json", "baseline")["valid"]
    (root / "app.py").write_text("# premature annotation\n")
    result = tt.validate_manifest(root / "manifest.json", "baseline")
    assert not result["valid"]
    assert any("Source differs" in e for e in result["errors"])


@pytest.mark.parametrize("backend", ["codeql", "semgrep-pro"])
def test_manifest_relies_on_native_evidence_without_access_requirement(
    artifacts, monkeypatch, backend
):
    root, manifest = artifacts
    active_component(root, monkeypatch, manifest)
    # This unit exercises manifest policy; native command validation has separate contracts.
    monkeypatch.setattr("runner.check_run", lambda record, path: [])
    manifest["components"][0]["backend"] = backend
    proof = tt.read_json(root / "probe.json")
    proof["backend"] = backend
    tt.write_json(root / "probe.json", proof)
    run = tt.read_json(root / "baseline.json")
    run["backend"] = backend
    tt.write_json(root / "baseline.json", run)
    tt.write_json(root / "manifest.json", manifest)
    result = tt.validate_manifest(root / "manifest.json", "baseline")
    assert result["valid"], result
    assert "access" not in manifest["components"][0]


def test_probe_limitations_survive_in_validated_report(artifacts, monkeypatch):
    root, manifest = artifacts
    active_component(root, monkeypatch, manifest)
    fake_run(root, "enriched")
    proof = tt.read_json(root / "probe.json")
    proof["limitations"] = ["optional sanitizer capability was not demonstrated"]
    tt.write_json(root / "probe.json", proof)
    tt.write_json(root / "manifest.json", manifest)
    result = tt.render_report(root / "manifest.json", root / "report.md")
    assert result["valid"] and result["status"] == "limited"
    assert "optional sanitizer capability was not demonstrated" in (root / "report.md").read_text()


@pytest.mark.parametrize(
    "content", ["{broken", "[]", '{"components": null}', '{"components": [null], "models": [null]}']
)
def test_malformed_manifest_still_writes_failed_report(artifacts, content):
    root, _ = artifacts
    (root / "manifest.json").write_text(content)
    result = tt.render_report(root / "manifest.json", root / "report.md")
    assert not result["valid"]
    assert "Status: **failed**" in (root / "report.md").read_text()
    assert "Validation errors" in (root / "report.md").read_text()


def test_failed_native_artifacts_are_not_reported_as_findings(artifacts, monkeypatch):
    root, manifest = artifacts
    active_component(root, monkeypatch, manifest)
    fake_run(root, "enriched")
    run = tt.read_json(root / "enriched.json")
    run["findings"][0]["message"] = "forged finding text"
    tt.write_json(root / "enriched.json", run)
    tt.write_json(root / "manifest.json", manifest)
    result = tt.render_report(root / "manifest.json", root / "report.md")
    report = (root / "report.md").read_text()
    assert not result["valid"]
    assert "forged finding text" not in report
    assert "Finding changes:" not in report
    assert "enriched.json" in report and "failed validation" in report


def test_historical_finding_snippets_are_bound_to_original_sources(artifacts, monkeypatch):
    root, manifest = artifacts
    active_component(root, monkeypatch, manifest)
    run = tt.read_json(root / "baseline.json")
    run["findings"][0]["source_line"] = "forged identity to hide a finding delta"
    tt.write_json(root / "baseline.json", run)
    tt.write_json(root / "manifest.json", manifest)
    result = tt.validate_manifest(root / "manifest.json", "baseline")
    assert any("source snippet" in error for error in result["errors"])


def model() -> JsonObject:
    return {
        "id": "request-input",
        "language": "python",
        "backend": "joern",
        "role": "source",
        "anchor": {"file": "app.py", "start_line": 1, "end_line": 3, "node_id": "request"},
        "value": "return",
        "contexts": ["shell"],
        "evidence": ["Source inspection: adapter returns external request bytes."],
        "assumptions": [],
        "artifact": "model.txt",
    }


def test_modeling_gap_is_optional_and_preserves_analyst_evidence():
    item = model()
    errors = []
    validate_model_fields(item, errors)
    assert errors == []  # Existing manifests remain readable.
    gap = {
        "description": "The adapter return has no source binding.",
        "baseline_evidence": ["baseline.json: no trace across adapter return"],
        "expected_effect": "Native positive gains a trace; literal remains negative.",
    }
    item["modeling_gap"] = gap.copy()
    validate_model_fields(item, errors)
    assert errors == []
    assert item["modeling_gap"] == gap
    assert "benefit" not in item  # Structure validation cannot establish utility.


@pytest.mark.parametrize(
    "gap, field",
    [
        (None, "object"),
        ([], "object"),
        ({}, "description"),
        (
            {"description": " ", "expected_effect": "effect", "baseline_evidence": ["trace"]},
            "description",
        ),
        (
            {"description": "gap", "expected_effect": 1, "baseline_evidence": ["trace"]},
            "expected_effect",
        ),
        (
            {"description": "gap", "expected_effect": "effect", "baseline_evidence": []},
            "baseline_evidence",
        ),
        (
            {"description": "gap", "expected_effect": "effect", "baseline_evidence": [""]},
            "baseline_evidence",
        ),
    ],
)
def test_malformed_modeling_gap_is_rejected(gap, field):
    item = model()
    item["modeling_gap"] = gap
    errors = []
    validate_model_fields(item, errors)
    assert any(f"modeling_gap{'.' + field if field != 'object' else ''}" in e for e in errors)


def test_complete_provenance_and_immutable_baseline(artifacts, monkeypatch):
    root, manifest = artifacts
    active_component(root, monkeypatch, manifest)
    native_model = root / "model.txt"
    native_model.write_text("native model fixture\n")
    manifest["models"] = [model()]
    manifest["components"][0]["status"] = "limited"
    fake_run(root, "enriched", model=native_model)
    rebound = context(root)
    tt.snapshot_sources(rebound, root / "rebound.json")
    tt.write_json(root / "rebound.json", rebound)
    manifest["rebound_context"] = "rebound.json"
    tt.write_json(root / "manifest.json", manifest)
    result = tt.validate_manifest(root / "manifest.json")
    assert result["valid"], result
    report = tt.render_report(root / "manifest.json", root / "report.md")
    assert report["valid"]
    assert "0 newly reported; 0 no longer reported" in (root / "report.md").read_text()
    native_model.write_text("unexpected change\n")
    result = tt.validate_manifest(root / "manifest.json")
    assert any("snapshot the model" in e for e in result["errors"])


@pytest.mark.parametrize("artifact", ["app.py", "./app.py"])
def test_inline_edits_compare_original_and_rebound_source_snapshots(
    artifacts, monkeypatch, artifact
):
    root, manifest = artifacts
    active_component(root, monkeypatch, manifest)
    source = root / "app.py"
    source.write_text("# native annotation fixture\n" + source.read_text())
    native_model = model()
    native_model["artifact"] = artifact
    manifest["models"] = [native_model]
    manifest["components"][0]["status"] = "limited"
    fake_run(root, "enriched", model=source, line=3)
    rebound = context(root)
    rebound["graph"]["nodes"]["request"]["location"].update(start_line=2, end_line=4)
    tt.snapshot_sources(rebound, root / "rebound.json")
    tt.write_json(root / "rebound.json", rebound)
    manifest["rebound_context"] = "rebound.json"
    tt.write_json(root / "manifest.json", manifest)
    result = tt.render_report(root / "manifest.json", root / "report.md")
    assert result["valid"], result
    assert "0 newly reported; 0 no longer reported" in (root / "report.md").read_text()


@pytest.mark.parametrize(
    "mutate, expected",
    [
        (lambda m: m.update(contexts=["*"]), "sanitizer"),
        (lambda m: m.update(evidence=[]), "evidence"),
        (lambda m: m["anchor"].update(node_id="missing"), "absent"),
        (lambda m: m["anchor"].update(start_line=99), "outside"),
    ],
)
def test_invalid_models_fail_with_useful_errors(artifacts, mutate, expected):
    root, _ = artifacts
    (root / "model.txt").write_text("native fixture\n")
    item = model()
    item["role"] = "sanitizer"
    mutate(item)
    errors = []
    try:
        tt._validate_models([item], context(root), root, {}, "baseline", errors=errors)
    except ValueError as exc:
        errors.append(str(exc))
    assert any(expected in e for e in errors)


def test_duplicate_bindings_and_unsupported_sanitizers(artifacts):
    root, _ = artifacts
    (root / "model.txt").write_text("native fixture\n")
    first, second = model(), model()
    second["id"] = "duplicate"
    errors = []
    tt._validate_models([first, second], context(root), root, {}, "baseline", errors=errors)
    assert any("duplicate" in e for e in errors)
    first.update(role="sanitizer", backend="clang")
    errors = []
    tt._validate_models([first], context(root), root, {}, "baseline", errors=errors)
    assert any("independent vulnerability" in e for e in errors)


def test_incompatible_capabilities_and_empty_scan(artifacts):
    root, _ = artifacts
    value = context(root)
    value["capabilities"].remove("entrypoint_evidence")
    value["summary"]["source_file_counts"] = {}
    errors = tt.context_errors(value, root)
    assert any("capabilities" in e for e in errors)
    assert any("zero files" in e for e in errors)


def test_rebound_anchor_moves_and_ambiguous_matches_are_retained(artifacts):
    root, _ = artifacts
    original, rebound = context(root), context(root)
    rebound["graph"]["nodes"]["request"]["location"].update(start_line=8, end_line=10)
    result = tt.rebind_anchor(model(), original, rebound, root)
    assert result["binding"] == "resolved" and result["matches"][0]["start_line"] == 8
    rebound["graph"]["nodes"]["duplicate"] = rebound["graph"]["nodes"]["request"]
    assert tt.rebind_anchor(model(), original, rebound, root)["binding"] == "ambiguous"


def test_native_scan_must_overlap_graphed_target_sources(artifacts, monkeypatch):
    root, manifest = artifacts
    active_component(root, monkeypatch, manifest)
    snapshot = context(root)
    snapshot["source_hashes"] = {"other.py": tt.digest(root / "app.py")}
    (root / "other.py").write_text((root / "app.py").read_text())
    tt.write_json(root / "context.json", snapshot)
    tt.write_json(root / "manifest.json", manifest)
    result = tt.validate_manifest(root / "manifest.json", "baseline")
    assert any("zero overlap" in e for e in result["errors"])


def test_other_components_graph_cannot_authorize_an_ungraphed_component(artifacts, monkeypatch):
    root, manifest = artifacts
    active_component(root, monkeypatch, manifest)
    empty_component = root / "ungraphed"
    empty_component.mkdir()
    manifest["components"][0]["root"] = str(empty_component)
    tt.write_json(root / "manifest.json", manifest)
    result = tt.validate_manifest(root / "manifest.json", "baseline")
    assert any("component has zero graphed source files" in error for error in result["errors"])


def test_model_cannot_use_another_components_enriched_run(artifacts):
    root, _ = artifacts
    native_model = root / "model.txt"
    native_model.write_text("native model fixture\n")
    other = root / "other-component"
    other.mkdir()
    run = fake_run(root, "enriched", model=native_model)
    run["component_root"] = str(other)
    errors = []
    tt._validate_models(
        [model()], context(root), root, {("python", "joern"): [run]}, "complete", errors=errors
    )
    assert any("did not snapshot the model" in error for error in errors)


def test_original_source_and_configuration_snapshots_survive_edits(artifacts):
    root, _ = artifacts
    (root / "psalm.xml").write_text("<psalm/>\n")
    snapshot = context(root)
    snapshot["configuration_files"] = ["psalm.xml"]
    tt.snapshot_sources(snapshot, root / "original.json")
    assert len(snapshot["source_snapshots"]) == 2
    (root / "app.py").write_text("# annotation added\nchanged\n")
    assert tt.context_errors(snapshot, root) == []
    assert any("Source differs" in e for e in tt.context_errors(snapshot, root, current=True))
    Path(snapshot["source_snapshots"][0]["path"]).write_text("tampered\n")
    assert any("snapshot changed" in e for e in tt.context_errors(snapshot, root))


def test_launcher_preserves_arguments_without_generator_bootstrap(tmp_path):
    commands = tmp_path / "bin"
    commands.mkdir()
    path = commands / "uv"
    path.write_text('#!/bin/sh\nprintf "%s\\n" "$@"\n')
    path.chmod(0o755)
    launcher = Path(__file__).with_name("taint_trace.sh")
    env = {**os.environ, "PATH": f"{commands}:/usr/bin:/bin"}
    argument = "path with spaces/$(touch should-not-exist)"
    result = subprocess.run(
        ["bash", str(launcher), "context", "--target", argument],
        cwd=tmp_path,
        env=env,
        text=True,
        capture_output=True,
    )
    assert result.returncode == 0
    assert result.stdout.splitlines()[-3:] == ["context", "--target", argument]
    assert not (tmp_path / "should-not-exist").exists()
    path.unlink()
    result = subprocess.run(
        ["bash", str(launcher), "catalog"], env=env, text=True, capture_output=True
    )
    assert result.returncode == 127
    assert "requires uv on PATH" in result.stderr


def test_finding_delta_ignores_line_shifts_but_keeps_duplicate_counts():
    first = {"rule_id": "r", "file": "/target/app.py", "line": 2, "source_line": "sink(x)"}
    shifted = {**first, "line": 12}
    assert tt.finding_key(first, Path("/target")) == tt.finding_key(shifted, Path("/target"))
    assert (
        sum(
            (
                Counter([tt.finding_key(first, Path("/target"))] * 2)
                - Counter([tt.finding_key(shifted, Path("/target"))])
            ).values()
        )
        == 1
    )
