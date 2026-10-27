"""Exercise evidence APIs against the published Trailmark dependency."""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path

import pytest

pytest.importorskip("trailmark", reason="Run with trailmark>=0.7.1,<0.8 for graph contracts")
sys.path.insert(0, str(Path(__file__).parent))

from taint_trace import build_context, context_errors, main
from trace_artifacts import JsonObject

SEMGREP = os.environ.get("TAINT_TRACE_SEMGREP")
if SEMGREP == "1":
    SEMGREP = "semgrep"


def test_php_templates_includes_configuration_callbacks_and_proxies(tmp_path):
    (tmp_path / "index.php").write_text(
        "<?php\ninclude __DIR__ . '/view.phtml';\n"
        "function direct($request) { return unknown_proxy($request); }\n"
        "register_callback('direct');\n"
    )
    (tmp_path / "view.phtml").write_text("<b><?= $_GET['value'] ?></b>\n")
    (tmp_path / "a.php").write_text("<?php namespace App; class Handler {}\n")
    (tmp_path / "b.php").write_text("<?php namespace App; class Handler {}\n")
    (tmp_path / "config.json").write_text(
        json.dumps({"handler": "App\\Handler", "missing": "Elsewhere.Handler"})
    )
    snapshot = build_context(tmp_path, "php", ["direct", "Handler"])
    assert context_errors(snapshot, tmp_path, current=True) == []
    assert snapshot["source_hashes"].keys() >= {"index.php", "view.phtml", "a.php", "b.php"}
    assert snapshot["entrypoint_evidence"]
    candidates = snapshot["entrypoint_candidates"]
    assert any(f["binding"] == "ambiguous" for f in candidates)
    assert any(f["binding"] == "unresolved" and f["node_id"] is None for f in candidates)
    assert any(f["basis"] == "reference" for f in candidates)
    assert snapshot["unresolved_calls"]
    assert any(n.get("origin") == "proxy" for n in snapshot["graph"]["nodes"].values())
    assert "findings" not in snapshot
    assert all("confidence" in e for e in snapshot["graph"]["edges"])


def test_empty_source_tree_fails(tmp_path):
    with pytest.raises(ValueError):
        build_context(tmp_path)


def test_missing_capability_fails(tmp_path, monkeypatch):
    from trailmark.query.api import QueryEngine

    monkeypatch.setattr(QueryEngine, "entrypoint_evidence", None)
    with pytest.raises(ValueError, match="required evidence APIs"):
        build_context(tmp_path)


def capture(root: Path, output: Path, *, focus: bool = False) -> JsonObject:
    argv = ["context", "--target", str(root), "--languages", "python", "--output", str(output)]
    assert main([*argv, "--focus", "handler"] if focus else argv) == 0
    return json.loads(output.read_text())


def native_rules() -> JsonObject:
    return {
        "rules": [
            {
                "id": "fixture.request-shell",
                "languages": ["python"],
                "message": "request to shell",
                "severity": "ERROR",
                "mode": "taint",
                "pattern-sources": [{"pattern": "input()"}],
                "pattern-sinks": [{"pattern": "sink_output(...)"}],
            }
        ]
    }


def pipeline_manifest(root: Path) -> JsonObject:
    return {
        "schema_version": 1,
        "target": str(root),
        "context": "context.json",
        "models": [],
        "limitations": [],
        "components": [
            {
                "id": "app",
                "language": "python",
                "backend": "semgrep",
                "scope": "intraprocedural",
                "status": "limited",
                "reason": "CE scope",
                "probe": "probe.json",
                "baseline": "baseline.json",
                "enriched": "enriched.json",
                "gaps": ["transport.recv is a fixture contract; its dependency is not graphed"],
            }
        ],
    }


def scan(root: Path, records: Path, phase: str, config: Path) -> int:
    argv = [
        "run",
        "--backend",
        "semgrep",
        "--language",
        "python",
        "--phase",
        phase,
        "--scope",
        "intraprocedural",
        "--cwd",
        str(root),
        "--output",
        str(records / f"{phase}.json"),
    ]
    if phase == "enriched":
        argv += ["--model", str(config)]
    native = [
        SEMGREP or "semgrep",
        "scan",
        "--oss-only",
        "--metrics=off",
        "--disable-version-check",
        "--json",
        "--config",
        str(config),
        str(root / "app.py"),
    ]
    return main([*argv, "--", *native])


def input_model(snapshot: JsonObject, root: Path, config: Path) -> JsonObject:
    node_id, node = next(
        (key, node)
        for key, node in snapshot["graph"]["nodes"].items()
        if node.get("name") == "request_input"
    )
    return {
        "id": "request-return",
        "language": "python",
        "backend": "semgrep",
        "role": "source",
        "anchor": {
            "file": "app.py",
            "start_line": node["location"]["start_line"],
            "end_line": node["location"]["end_line"],
            "node_id": node_id,
        },
        "value": "return",
        "contexts": ["shell"],
        "evidence": ["Accessor returns transport.recv()"],
        "assumptions": ["The fixture transport contract returns attacker-controlled bytes"],
        "artifact": config.relative_to(root).as_posix(),
    }


@pytest.fixture
def pipeline(tmp_path):
    source = tmp_path / "app.py"
    source.write_text(
        "from transport import recv\n"
        "def request_input():\n    return recv()\n"
        "def handler():\n    sink_output(request_input())\n"
    )
    records = tmp_path / ".trailmark/taint-trace"
    records.mkdir(parents=True)
    snapshot = capture(tmp_path, records / "context.json", focus=True)
    assert (
        main(
            [
                "probe",
                "--executable",
                SEMGREP or "semgrep",
                "--backend",
                "semgrep",
                "--language",
                "python",
                "--output",
                str(records / "probe.json"),
            ]
        )
        == 0
    )
    return tmp_path, records, snapshot


@pytest.mark.skipif(not SEMGREP, reason="Set TAINT_TRACE_SEMGREP to run native Semgrep tests")
def test_real_cli_pipeline_preserves_source_and_baseline_configuration(pipeline, capsys):
    root, records, snapshot = pipeline
    source = root / "app.py"
    original_text = source.read_text()
    rule = native_rules()
    baseline_config, enriched_config = (
        records / name for name in ("baseline-rules.json", "rules.json")
    )
    baseline_config.write_text(json.dumps(rule))
    manifest, manifest_file = pipeline_manifest(root), records / "manifest.json"
    manifest_file.write_text(json.dumps(manifest))
    assert scan(root, records, "baseline", baseline_config) == 0
    assert main(["validate", "--manifest", str(manifest_file), "--stage", "baseline"]) == 0
    rule["rules"][0]["pattern-sources"] = [{"pattern": "request_input()"}]
    enriched_config.write_text(json.dumps(rule))
    manifest["models"] = [input_model(snapshot, root, enriched_config)]
    assert scan(root, records, "enriched", enriched_config) == 0
    capture(root, records / "rebound.json")
    manifest["rebound_context"] = "rebound.json"
    manifest_file.write_text(json.dumps(manifest))
    report = records / "report.md"
    assert main(["report", "--manifest", str(manifest_file), "--output", str(report)]) == 0
    assert "1 newly reported" in report.read_text()
    assert baseline_config.read_text() != enriched_config.read_text()
    assert source.read_text() == original_text
    assert main(["context", "--target", str(root), "--output", str(records / "context.json")]) == 2
    assert json.loads((records / "context.json").read_text()) == snapshot
    capsys.readouterr()
