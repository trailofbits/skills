"""Reports treat target source, analyzer diagnostics, and provenance as literal text."""

from __future__ import annotations

import json
import re
from pathlib import Path
from urllib.parse import unquote

import pytest

import trace_report as reports
from manifest_validation import ValidationResult
from native import normalize
from trace_artifacts import JsonObject, digest, write_json

PAYLOAD = '<img src="https://attacker.invalid/pixel">\n![beacon](https://attacker.invalid/image)'


@pytest.fixture
def validation_result() -> ValidationResult:
    return {
        "valid": True,
        "stage": "complete",
        "active_components": 1,
        "failed_components": 0,
        "limited_components": 0,
        "skipped_components": 0,
        "status": "analyzed",
        "errors": [],
        "limitations": [],
    }


def assert_literal_payload(text: str, count: int = 1) -> None:
    assert text.count('&lt;img src="https://attacker\\.invalid/pixel"&gt;') == count
    assert text.count(r"\!\[beacon\]\(https://attacker\.invalid/image\)") == count
    assert "<img" not in text
    assert "\n![beacon]" not in text


def test_plain_text_cannot_create_markdown_blocks_or_table_cells() -> None:
    text = reports.report_text(PAYLOAD + "\n# forged\n| injected |\n`code` **bold** ~~strike~~")
    assert_literal_payload(text)
    assert "\n" not in text
    assert r"\# forged \| injected \| \`code\` \*\*bold\*\* \~\~strike\~\~" in text


@pytest.mark.parametrize("value", ["` " + PAYLOAD, "`` " + PAYLOAD, "``` " + PAYLOAD + " ````"])
def test_code_values_cannot_close_their_delimiters(value: str) -> None:
    text = reports.report_code(value)
    delimiter = re.match(r"`+", text)
    assert delimiter is not None
    assert text.endswith(delimiter[0])
    content = text[len(delimiter[0]) : -len(delimiter[0])]
    assert content == " " + " ".join(value.split()) + " "
    assert delimiter[0] not in content


def test_artifact_links_escape_labels_and_encode_destinations(tmp_path: Path) -> None:
    path = tmp_path / 'report)![beacon](image) [label] #hash%20\n<img src="x">.json'
    link = reports.report_link(path)
    label, destination = link.rsplit("](", 1)
    assert r"report\)\!\[beacon\]\(image\) \[label\] \#hash%20" in label
    assert "&lt;img" in label
    assert not any(character in destination[:-1] for character in '\n()[]<>" #')
    assert unquote(destination[:-1]) == path.as_posix()


def checker_diagnostic(root: Path) -> str:
    source = root / "Boundary![file](beacon).java"
    line = "    sink(input); // " + PAYLOAD.replace("\n", " ")
    source.write_text("class Boundary {\n" + line + "\n}\n", encoding="utf-8")
    return (
        f"{source}:2: error: [argument] incompatible argument for parameter value of sink.\n"
        f"{line}\n         ^\n"
        "  found   : @Tainted String\n"
        "  required: @Untainted String\n1 error\n"
    )


def test_checker_framework_echoed_source_is_inert_in_public_report(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, validation_result: ValidationResult
) -> None:
    diagnostic = checker_diagnostic(tmp_path)
    normalized = normalize(diagnostic, "checker-framework", tmp_path)
    assert len(normalized["findings"]) == 1
    run: JsonObject = {
        **normalized,
        "scope": "interprocedural",
        "version": {"output": PAYLOAD},
        "native_output": {"path": "native![artifact](beacon).txt"},
    }
    write_json(tmp_path / "run.json", run)
    write_json(tmp_path / "context.json", {"graph": {"nodes": {}}})
    manifest = {
        "target": str(tmp_path),
        "context": "context.json",
        "models": [],
        "components": [{"id": "app", "status": "analyzed", "enriched": "run.json"}],
    }
    write_json(tmp_path / "manifest.json", manifest)
    monkeypatch.setattr(reports, "validate_manifest", lambda path: validation_result)
    reports.render_report(tmp_path / "manifest.json", tmp_path / "report.md")
    report = (tmp_path / "report.md").read_text(encoding="utf-8")
    assert_literal_payload(report, count=2)
    assert r"Boundary\!\[file\]\(beacon\)\.java:2:" in report
    assert "found : @Tainted String required: @Untainted String" in report
    assert r"native\!\[artifact\]\(beacon\)\.txt" in report
    assert "native%21%5Bartifact%5D%28beacon%29.txt" in report
    preserved = json.loads((tmp_path / "run.json").read_text(encoding="utf-8"))
    assert preserved["findings"][0]["message"] == diagnostic.strip()


def test_components_and_native_metadata_are_literal(tmp_path: Path) -> None:
    component: JsonObject = dict.fromkeys(
        ("id", "language", "backend", "status", "scope", "reason"), PAYLOAD
    )
    table = reports.component_table([component])
    assert_literal_payload("\n".join(table), count=5)
    assert len(re.split(r"(?<!\\)\|", table[-1])) == 6
    recorded = reports.recorded_components({"components": [component]}, tmp_path)
    assert_literal_payload("\n".join(recorded), count=3)
    component.update({"status": "failed", "gaps": [PAYLOAD]})
    assert_literal_payload("\n".join(reports.component_report(component, tmp_path, tmp_path)), 3)
    run = {"scope": PAYLOAD, "version": {"output": PAYLOAD}, "findings": []}
    assert_literal_payload(
        "\n".join(reports.native_run_lines(run, tmp_path, "baseline", tmp_path)), 2
    )


def test_execution_provenance_links_preserve_captured_commands_and_escape_metadata(
    tmp_path: Path,
) -> None:
    path = tmp_path / 'run)![beacon](image) [label] #hash%20\n<img src="x">.execution.json'
    captured = {
        "requested": {
            "argv": ["analyzer", "--config", "target-config.json"],
            "config_files": [{"file": "target-config.json", "sha256": "requested-digest"}],
        },
        "effective": {
            "argv": ["analyzer", "--config", "isolated-config.json"],
            "config_files": [{"file": "isolated-config.json", "sha256": "effective-digest"}],
        },
        "policy": PAYLOAD,
        "assumptions": ["Explicit callbacks remain caller managed.", PAYLOAD],
    }
    write_json(path, captured)
    before = digest(path)
    run = {
        "scope": "interprocedural",
        "findings": [],
        "execution": {
            "path": path.name,
            "sha256": before,
            "policy": captured["policy"],
            "assumptions": captured["assumptions"],
        },
    }
    lines = reports.native_run_lines(run, tmp_path / "run.json", "baseline", tmp_path)
    link = next(line for line in lines if line.startswith("- Native execution:"))
    label, destination = link.rsplit("](", 1)
    assert r"run\)\!\[beacon\]\(image\) \[label\] \#hash%20" in label
    assert "&lt;img" in label
    assert not any(character in destination[:-1] for character in '\n()[]<>" #')
    assert unquote(destination[:-1]) == path.as_posix()
    text = "\n".join(lines)
    assert_literal_payload(text, count=2)
    assert "Execution policy:" in text
    assert "Execution assumption: Explicit callbacks remain caller managed" in text
    assert "target-config" not in text
    assert "isolated-config" not in text
    assert json.loads(path.read_text(encoding="utf-8")) == captured
    assert digest(path) == before


def test_model_provenance_and_rebound_values_are_literal(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    model = {
        "id": PAYLOAD,
        "role": PAYLOAD,
        "value": "` " + PAYLOAD,
        "artifact": "`` " + PAYLOAD,
        "contexts": [PAYLOAD],
        "evidence": [PAYLOAD],
        "assumptions": [PAYLOAD],
        "anchor": {"node_id": "entry"},
    }
    binding = {"binding": PAYLOAD, "matches": [PAYLOAD]}
    monkeypatch.setattr(reports, "rebind_anchor", lambda *args: binding)
    lines = reports.model_report(
        model, {"graph": {"nodes": {"entry": {}}}}, {"graph": {}}, tmp_path
    )
    # The two native code spans retain literal HTML behind uncloseable delimiters.
    assert_literal_payload("\n".join(lines[1:3]), count=2)
    assert reports.report_code(model["value"]) in lines[0]
    assert reports.report_code(model["artifact"]) in lines[0]
    assert reports.report_text(PAYLOAD) in lines[-1]
    assert reports.report_text(json.dumps(binding["matches"])) in lines[-1]


def test_failed_report_and_coverage_do_not_trust_validation_messages(
    tmp_path: Path, validation_result: ValidationResult
) -> None:
    validation_result.update({"valid": False, "errors": [PAYLOAD], "limitations": [PAYLOAD]})
    manifest = {"components": [{"id": PAYLOAD, "status": "failed", "reason": PAYLOAD}]}
    failed = reports.failed_report(tmp_path / "manifest.json", manifest, validation_result)
    assert_literal_payload("\n".join(failed), count=3)
    coverage = reports.coverage_report({"context": "` " + PAYLOAD}, validation_result)
    assert_literal_payload("\n".join(coverage[-3:]))
    assert reports.report_code("` " + PAYLOAD) in "\n".join(coverage)


def test_missing_artifact_exception_cannot_add_markup(tmp_path: Path) -> None:
    component = {"status": "analyzed", "baseline": PAYLOAD}
    lines = reports.component_report(component, tmp_path, tmp_path)
    assert "Cannot read baseline artifact:" in "\n".join(lines)
    assert "<img" not in "\n".join(lines)
    assert "![beacon]" not in "\n".join(lines)


def boundary_warning(root: Path, line: int, source_line: str) -> JsonObject:
    return {
        "rule_id": "TaintedSql",
        "file": str(root / "boundary.py"),
        "line": line,
        "source_line": source_line,
        "message": "Untrusted query reaches execution",
        "trace": [
            {"label": "request.query", "file": str(root / "handler.py"), "line": 4},
            {"label": "Boundary.execute", "file": str(root / "boundary.py"), "line": 8},
        ],
    }


def test_second_warning_location_keeps_native_counts_without_claiming_another_flow(
    tmp_path: Path,
) -> None:
    inner = boundary_warning(tmp_path, 10, "return driver.execute(query)")
    wrapper = boundary_warning(tmp_path, 8, "def execute(query):")
    # The same native trace is reported at both the wrapper and its implementation.
    assert inner["trace"] == wrapper["trace"]
    records = {
        "baseline": {"findings": [inner]},
        "enriched": {"findings": [inner, wrapper]},
    }
    text = "\n".join(reports.finding_changes(records, tmp_path))
    assert "1 newly reported; 0 no longer reported" in text
    assert "native warning records, not unique flows" in text
    assert "duplicate a baseline warning" in text
    assert "do not establish recovered flows" in text
    # Reporting neither deduplicates nor rewrites the analyzer's retained records.
    assert len(records["enriched"]["findings"]) == 2
    assert records["enriched"]["findings"][0]["trace"] == inner["trace"]


def test_source_line_survives_annotation_line_shifts_without_a_warning_delta(
    tmp_path: Path,
) -> None:
    before = boundary_warning(tmp_path, 10, "return driver.execute(query)")
    after = {**before, "line": 15}
    records = {"baseline": {"findings": [before]}, "enriched": {"findings": [after]}}
    text = "\n".join(reports.finding_changes(records, tmp_path))
    assert "0 newly reported; 0 no longer reported" in text
    assert "unchanged counts do not establish redundancy" in text
    assert "Compare native traces and source evidence" in text


@pytest.mark.parametrize("coverage", [None, []])
def test_file_inventory_does_not_substitute_for_flow_coverage(
    tmp_path: Path, coverage: list[str] | None, validation_result: ValidationResult
) -> None:
    run = {
        "scope": "interprocedural",
        "scanned_files": coverage,
        "findings": [],
        "version": {"output": "Analyzer 1.0"},
    }
    text = "\n".join(reports.native_run_lines(run, tmp_path / "run.json", "baseline", tmp_path))
    assert "0 native warning records" in text
    assert ("unknown (limited)" if coverage is None else "0 files") in text
    context = "\n".join(reports.coverage_report({}, validation_result))
    assert "processed files, not path or flow coverage" in context
    assert "unmeasured benefit remains unknown" in context


def test_old_model_without_gap_metadata_retains_unknown_benefit(tmp_path: Path) -> None:
    model = {"id": "boundary", "role": "sink", "value": "query", "artifact": "boundary.py"}
    lines = reports.model_report(model, {}, {}, tmp_path)
    text = "\n".join(lines)
    assert "Benefit: unmeasured" in text
    assert "reviewer approval do not establish" in text
    assert "Modeling-gap hypothesis" not in text


def test_gap_metadata_is_a_hypothesis_even_when_it_predicts_more_warnings(tmp_path: Path) -> None:
    model = {
        "id": "boundary",
        "role": "sink",
        "value": "query",
        "artifact": "boundary.py",
        "evidence": ["The query argument reaches driver.execute unchanged."],
        "modeling_gap": {
            "description": "The dependency method is unresolved in baseline diagnostics.",
            "baseline_evidence": ["baseline.json: UndefinedMethod at boundary.py:10"],
            "expected_effect": "The native analyzer may report the request-to-query path.",
        },
    }
    text = "\n".join(reports.model_report(model, {}, {}, tmp_path))
    assert "Evidence: The query argument" in text
    assert "Modeling-gap hypothesis (analyst supplied)" in text
    assert "Baseline evidence: baseline\\.json" in text
    assert "Expected effect (hypothesis)" in text
    assert "Benefit: unmeasured" in text
    assert "warning counts alone cannot confirm the expected effect" in text


def test_gap_hypotheses_and_their_evidence_cannot_add_markup(tmp_path: Path) -> None:
    model = {
        "modeling_gap": {
            "description": PAYLOAD,
            "baseline_evidence": [PAYLOAD],
            "expected_effect": PAYLOAD,
        }
    }
    text = "\n".join(reports.model_report(model, {}, {}, tmp_path))
    assert_literal_payload(text, count=3)
