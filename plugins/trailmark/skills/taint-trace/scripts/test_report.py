"""Reports treat target source, analyzer diagnostics, and provenance as literal text."""

from __future__ import annotations

import json
import re
from pathlib import Path
from urllib.parse import unquote

import pytest
from trailmark.query.api import QueryEngine

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


def comparison_context(
    root: Path, name: str, source: str, declarations: list[tuple[str, int, int]]
) -> JsonObject:
    snapshot = root / f"{name}.snapshot"
    snapshot.write_text(source, encoding="utf-8")
    return {
        "source_snapshots": [{"file": "boundary.py", "path": str(snapshot)}],
        "graph": {
            "nodes": {
                ident: {
                    "location": {
                        "file_path": str(root / "boundary.py"),
                        "start_line": start,
                        "end_line": end,
                    }
                }
                for ident, start, end in declarations
            },
        },
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
    source = "def execute(query):\n    return driver.execute(query)\n"
    original = comparison_context(tmp_path, "original", source, [("execute", 1, 2)])
    rebound = comparison_context(
        tmp_path, "rebound", "# annotation\n" + source, [("execute", 2, 3)]
    )
    # Historical matching must not depend on the current worktree.
    (tmp_path / "boundary.py").write_text("different source\n")
    before = boundary_warning(tmp_path, 2, "return driver.execute(query)")
    after = {**before, "line": 3}
    records = {"baseline": {"findings": [before]}, "enriched": {"findings": [after]}}
    text = "\n".join(reports.finding_changes(records, tmp_path, contexts=(original, rebound)))
    assert "0 newly reported; 0 no longer reported" in text
    assert "unchanged counts do not establish redundancy" in text
    assert "Compare native traces and source evidence" in text


def php_comparison_context(root: Path, name: str, source: str) -> JsonObject:
    (root / "boundary.php").write_text(source, encoding="utf-8")
    snapshot = root / f"{name}.snapshot"
    snapshot.write_text(source, encoding="utf-8")
    engine = QueryEngine.from_directory(str(root), language="php", detect_entrypoints_=False)
    return {
        "source_snapshots": [{"file": "boundary.php", "path": str(snapshot)}],
        "graph": json.loads(engine.to_json()),
    }


@pytest.mark.parametrize("declared_sink", [False, True])
def test_real_php_lambda_ids_can_shift_without_a_warning_delta(tmp_path, declared_sink) -> None:
    sink = "function sink($value): void { echo $value; }\n" if declared_sink else ""
    source = (
        "<?php\n" + sink + "function execute($input) {\n"
        "    $sink = fn($value) => sink($value);\n    $sink($input);\n}\n"
    )
    annotation = "/** @psalm-taint-source input */\n"
    original = php_comparison_context(tmp_path, "original", source)
    rebound = php_comparison_context(
        tmp_path, "rebound", source.replace("function execute", annotation + "function execute")
    )
    old, new = (
        {ident: node for ident, node in context["graph"]["nodes"].items() if "$lambda@" in ident}
        for context in (original, rebound)
    )
    assert len(old) == len(new) == 1
    assert old.keys().isdisjoint(new)
    line = 4 if declared_sink else 3
    assert next(iter(old.values()))["location"]["start_line"] == line
    assert next(iter(new.values()))["location"]["start_line"] == line + 1
    before = {
        **boundary_warning(tmp_path, line, source.splitlines()[line - 1]),
        "file": "boundary.php",
    }
    records = {
        "baseline": {"findings": [before]},
        "enriched": {"findings": [{**before, "line": line + 1}]},
    }
    text = "\n".join(reports.finding_changes(records, tmp_path, contexts=(original, rebound)))
    assert "0 newly reported; 0 no longer reported" in text


@pytest.mark.parametrize("trailing_newline", [False, True])
@pytest.mark.parametrize("annotated", [False, True])
def test_real_php_script_end_boundaries_preserve_matched_warnings(
    tmp_path, trailing_newline, annotated
) -> None:
    source = "<?php\necho $input;" + ("\n" if trailing_newline else "")
    edited = source.replace("echo", "/** model */\necho") if annotated else source
    original = php_comparison_context(tmp_path, "original", source)
    rebound = php_comparison_context(tmp_path, "rebound", edited)
    scripts = [node for node in original["graph"]["nodes"].values() if node["name"] == "<script>"]
    assert len(scripts) == 1
    assert scripts[0]["location"]["end_line"] == len(source.splitlines()) + trailing_newline
    warning = {**boundary_warning(tmp_path, 2, "echo $input;"), "file": "boundary.php"}
    records = {
        "baseline": {"findings": [warning]},
        "enriched": {"findings": [{**warning, "line": 2 + annotated}]},
    }
    text = "\n".join(reports.finding_changes(records, tmp_path, contexts=(original, rebound)))
    assert "0 newly reported; 0 no longer reported" in text


def test_real_php_identical_lambdas_keep_distinct_locations_after_annotations(tmp_path):
    statement = "    $sink = fn($value) => sink($value);\n"
    source = (
        "<?php\nfunction sink($value): void { echo $value; }\n"
        "function execute($input) {\n" + statement * 2 + "}\n"
    )
    original = php_comparison_context(tmp_path, "original", source)
    rebound = php_comparison_context(
        tmp_path, "rebound", source.replace("function execute", "/** model */\nfunction execute")
    )
    before = {**boundary_warning(tmp_path, 4, statement.strip()), "file": "boundary.php"}
    records = {
        "baseline": {"findings": [before]},
        "enriched": {"findings": [{**before, "line": 6}]},
    }
    text = "\n".join(reports.finding_changes(records, tmp_path, contexts=(original, rebound)))
    assert "1 newly reported; 1 no longer reported" in text
    records["enriched"]["findings"] = [{**before, "line": 5}] * 2
    text = "\n".join(reports.finding_changes(records, tmp_path, contexts=(original, rebound)))
    assert "1 newly reported; 0 no longer reported" in text


@pytest.mark.parametrize("same_line", [False, True])
def test_real_php_added_or_same_line_lambda_owners_remain_ambiguous(tmp_path, same_line):
    statement = "$sink = fn($value) => sink($value);"
    first_line = f"    {statement} {statement}" if same_line else f"    {statement}"
    source = (
        "<?php\nfunction sink($value): void { echo $value; }\n"
        f"function execute($input) {{\n{first_line}\n}}\n"
    )
    after = source if same_line else source.replace("\n}\n", f"\n    {statement}\n}}\n")
    original = php_comparison_context(tmp_path, "original", source)
    rebound = php_comparison_context(tmp_path, "rebound", after)
    warning = {**boundary_warning(tmp_path, 4, first_line), "file": "boundary.php"}
    records = {"baseline": {"findings": [warning]}, "enriched": {"findings": [warning]}}
    text = "\n".join(reports.finding_changes(records, tmp_path, contexts=(original, rebound)))
    assert "1 newly reported; 1 no longer reported" in text


def test_enclosing_declaration_changes_do_not_rebind_an_unchanged_inner_sink(tmp_path):
    source = "class First:\n    def execute(self):\n        sink(input)\n"
    original = comparison_context(tmp_path, "original", source, [("owner", 1, 3), ("method", 2, 3)])
    rebound = comparison_context(
        tmp_path, "rebound", source.replace("First", "Second"), [("owner", 1, 3), ("method", 2, 3)]
    )
    for context in (original, rebound):
        context["graph"]["edges"] = [{"source": "owner", "target": "method", "kind": "contains"}]
    warning = boundary_warning(tmp_path, 3, "sink(input)")
    records = {"baseline": {"findings": [warning]}, "enriched": {"findings": [warning]}}
    text = "\n".join(reports.finding_changes(records, tmp_path, contexts=(original, rebound)))
    assert "1 newly reported; 1 no longer reported" in text


@pytest.mark.parametrize("with_contexts", [False, True])
def test_identical_sink_text_in_distinct_functions_keeps_location_changes(tmp_path, with_contexts):
    source = "def first():\n    sink(input)\n\ndef second():\n    sink(input)\n"
    context = comparison_context(tmp_path, "source", source, [("first", 1, 2), ("second", 4, 5)])
    before = boundary_warning(tmp_path, 2, "sink(input)")
    after = {**before, "line": 5}
    records = {"baseline": {"findings": [before]}, "enriched": {"findings": [after]}}
    contexts = (context, context) if with_contexts else None
    text = "\n".join(reports.finding_changes(records, tmp_path, contexts=contexts))
    assert "1 newly reported; 1 no longer reported" in text


def test_identical_sinks_in_one_function_keep_distinct_locations_after_annotations(tmp_path):
    source = "def execute():\n    sink(input)\n    sink(input)\n"
    original = comparison_context(tmp_path, "original", source, [("execute", 1, 3)])
    rebound = comparison_context(
        tmp_path, "rebound", "# annotation\n" + source, [("execute", 2, 4)]
    )
    before = boundary_warning(tmp_path, 2, "sink(input)")
    records = {
        "baseline": {"findings": [before]},
        "enriched": {"findings": [{**before, "line": 4}]},
    }
    text = "\n".join(reports.finding_changes(records, tmp_path, contexts=(original, rebound)))
    assert "1 newly reported; 1 no longer reported" in text
    records["enriched"]["findings"] = [{**before, "line": 3}] * 2
    text = "\n".join(reports.finding_changes(records, tmp_path, contexts=(original, rebound)))
    assert "1 newly reported; 0 no longer reported" in text


def test_new_identical_sink_does_not_acquire_an_existing_location_identity(tmp_path):
    source = "def execute():\n    sink(input)\n"
    original = comparison_context(tmp_path, "original", source, [("execute", 1, 2)])
    rebound = comparison_context(
        tmp_path, "rebound", source + "    sink(input)\n", [("execute", 1, 3)]
    )
    before = boundary_warning(tmp_path, 2, "sink(input)")
    records = {"baseline": {"findings": [before]}, "enriched": {"findings": [before]}}
    text = "\n".join(reports.finding_changes(records, tmp_path, contexts=(original, rebound)))
    assert "1 newly reported; 1 no longer reported" in text
    assert "unmatched or ambiguous locations" in text


def test_identical_statement_in_a_different_declaration_does_not_match(tmp_path):
    source = "def first():\n    sink(input)\n"
    original = comparison_context(tmp_path, "original", source, [("first", 1, 2)])
    rebound = comparison_context(
        tmp_path, "rebound", source.replace("first", "second"), [("second", 1, 2)]
    )
    warning = boundary_warning(tmp_path, 2, "sink(input)")
    records = {"baseline": {"findings": [warning]}, "enriched": {"findings": [warning]}}
    text = "\n".join(reports.finding_changes(records, tmp_path, contexts=(original, rebound)))
    assert "1 newly reported; 1 no longer reported" in text


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
