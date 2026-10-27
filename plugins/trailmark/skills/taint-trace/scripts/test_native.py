"""Native adapter fixtures preserve real output shapes without running analyzers."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from native import COVERAGE_UNKNOWN, JsonObject, normalize


def sarif_text(results: list[JsonObject], **run_fields: object) -> str:
    rules = [
        {"id": "js/sql-injection", "properties": {"kind": "path-problem"}},
        {"id": "js/unused-variable", "properties": {"kind": "problem"}},
    ]
    run = {"tool": {"driver": {"name": "CodeQL", "rules": rules}}, "results": results, **run_fields}
    return json.dumps({"version": "2.1.0", "runs": [run]})


def sarif_result(*, flow: bool = True, **location: object) -> JsonObject:
    physical = {
        "artifactLocation": location or {"uri": "app.js", "uriBaseId": "%SRCROOT%"},
        "region": {"startLine": 2},
    }
    result: JsonObject = {
        "ruleId": "js/sql-injection",
        "message": {"text": "Untrusted input reaches SQL"},
        "locations": [{"physicalLocation": physical}],
    }
    if flow:
        result["codeFlows"] = [
            {
                "threadFlows": [
                    {
                        "locations": [
                            {
                                "location": {
                                    "physicalLocation": physical,
                                }
                            }
                        ]
                    }
                ]
            }
        ]
    return result


def test_codeql_undefined_srcroot_resolves_real_shape_against_cwd(tmp_path: Path) -> None:
    (tmp_path / "app.js").write_text("const user = request();\nquery(user);\n", encoding="utf-8")
    result = normalize(sarif_text([sarif_result()]), "codeql", tmp_path)
    assert result["errors"] == []
    assert result["findings"][0]["file"] == str(tmp_path / "app.js")
    assert result["findings"][0]["source_line"] == "query(user);"
    assert result["scanned_files"] is None
    assert result["limitations"] == [COVERAGE_UNKNOWN]


def test_sarif_defined_base_chain_resolves_file_uris(tmp_path: Path) -> None:
    bases = {"%SRCROOT%": {"uri": "src/", "uriBaseId": "ROOT"}, "ROOT": {"uri": tmp_path.as_uri()}}
    result = normalize(sarif_text([sarif_result()], originalUriBaseIds=bases), "codeql", tmp_path)
    assert result["findings"][0]["file"] == str(tmp_path / "src" / "app.js")


@pytest.mark.parametrize(
    "bases",
    [
        {"%SRCROOT%": {"uriBaseId": "%SRCROOT%"}},
        {"%SRCROOT%": {"uriBaseId": "OTHER"}, "OTHER": {"uriBaseId": "%SRCROOT%"}},
    ],
)
def test_sarif_defined_base_cycles_still_fail(tmp_path: Path, bases: JsonObject) -> None:
    with pytest.raises(ValueError, match="cyclic"):
        normalize(sarif_text([sarif_result()], originalUriBaseIds=bases), "codeql", tmp_path)


def test_sarif_indexed_artifact_can_have_undefined_srcroot(tmp_path: Path) -> None:
    artifacts = [{"location": {"uri": "app.js", "uriBaseId": "%SRCROOT%"}}]
    text = sarif_text([sarif_result(index=0)], artifacts=artifacts)
    result = normalize(text, "codeql", tmp_path)
    assert result["findings"][0]["file"] == str(tmp_path / "app.js")


@pytest.mark.parametrize("index", [-1, 1, True])
def test_sarif_invalid_artifact_index_fails(tmp_path: Path, index: object) -> None:
    text = sarif_text([sarif_result(index=index)], artifacts=[{"location": {"uri": "app.js"}}])
    with pytest.raises(ValueError, match="artifact index"):
        normalize(text, "codeql", tmp_path)


def test_codeql_mixed_alerts_filter_rule_kind_instead_of_code_flows(tmp_path: Path) -> None:
    ordinary = sarif_result()
    ordinary["ruleId"] = "js/unused-variable"
    empty = sarif_result(flow=False)
    empty["codeFlows"] = []
    no_location: JsonObject = {"ruleId": "js/unused-variable"}
    text = sarif_text([ordinary, empty, no_location, sarif_result(flow=False)])
    result = normalize(text, "codeql", tmp_path)
    assert [item["rule_id"] for item in result["findings"]] == ["js/sql-injection"] * 2
    assert [item["trace"] for item in result["findings"]] == [[], None]


@pytest.mark.parametrize(
    "reference",
    [
        {"ruleIndex": 0},
        {"rule": {"index": 0}},
        {"rule": {"id": "js/command-line-injection"}},
        {"rule": {"index": 0, "toolComponent": {"index": 0}}},
        {"ruleId": "js/command-line-injection"},
    ],
)
@pytest.mark.parametrize("flow", [False, True])
def test_codeql_path_problem_survives_with_or_without_code_flows(
    tmp_path: Path, reference: JsonObject, flow: bool
) -> None:
    rule = {"id": "js/command-line-injection", "properties": {"kind": "path-problem"}}
    driver: JsonObject = {"name": "CodeQL", "rules": [rule]}
    tool: JsonObject = {"driver": driver}
    reference_rule = reference.get("rule", {})
    assert isinstance(reference_rule, dict)
    if "toolComponent" in reference_rule:
        tool["extensions"] = [{"name": "codeql/javascript-queries", "rules": [rule]}]
        driver["rules"] = [{"id": "ordinary", "properties": {"kind": "problem"}}]
    alert = sarif_result(flow=flow)
    alert.pop("ruleId")
    alert.update(reference)
    result = normalize(sarif_text([alert], tool=tool), "codeql", tmp_path)
    assert [item["rule_id"] for item in result["findings"]] == ["js/command-line-injection"]
    assert bool(result["findings"][0]["trace"]) is flow


@pytest.mark.parametrize("index", [-1, 5, True])
@pytest.mark.parametrize("extension", [False, True])
def test_codeql_invalid_rule_references_fail(
    tmp_path: Path, index: object, extension: bool
) -> None:
    alert = sarif_result()
    alert["rule"] = (
        {"index": 0, "toolComponent": {"index": index}} if extension else {"index": index}
    )
    with pytest.raises(ValueError, match="index"):
        normalize(sarif_text([alert]), "codeql", tmp_path)


@pytest.mark.parametrize("backend", ["semgrep", "joern", "pysa"])
def test_other_sarif_backends_keep_results_without_code_flows(tmp_path: Path, backend: str) -> None:
    result = normalize(sarif_text([sarif_result(flow=False)]), backend, tmp_path)
    assert len(result["findings"]) == 1
    assert result["findings"][0]["trace"] is None


def test_sarif_preserves_invocation_errors_and_notifications(tmp_path: Path) -> None:
    invocation = {
        "executionSuccessful": False,
        "toolExecutionNotifications": [
            {"level": "error", "message": {"text": "query failed"}},
            *[
                {"level": "none", "descriptor": {"id": ident}, "message": {"text": ""}}
                for ident in (
                    "cli/platform",
                    "cli/sip-enablement",
                    "cli/file-coverage-baseline",
                    "js/baseline/expected-extracted-files",
                )
            ],
        ],
        "toolConfigurationNotifications": [
            {"level": "warning", "message": {"text": "partial"}},
            {"level": "warning", "descriptor": {"id": "missing-model"}, "message": {"text": ""}},
            {"level": "warning", "message": {"text": "  "}},
        ],
    }
    result = normalize(sarif_text([], invocations=[invocation]), "codeql", tmp_path)
    assert result["findings"] == []
    assert result["errors"] == ["Native SARIF invocation failed", "query failed"]
    assert result["limitations"] == ["partial", "missing-model", COVERAGE_UNKNOWN]


def test_sarif_zero_runs_fails(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="zero analyzer runs"):
        normalize('{"runs": []}', "codeql", tmp_path)


def pysa_stdout_issue() -> JsonObject:
    return {
        "line": 9,
        "column": 22,
        "path": "source.py",
        "code": 5001,
        "name": "Possible shell injection",
        "description": "Data from UserControlled may reach RemoteCodeExecution",
        "long_description": "Data from UserControlled may reach RemoteCodeExecution",
        "concise_description": "Data from UserControlled may reach RemoteCodeExecution",
        "define": "source.convert",
    }


def pysa_saved_issue() -> JsonObject:
    return {
        "kind": "issue",
        "data": {
            "callable": "source.convert",
            "callable_line": 7,
            "code": 5001,
            "line": 9,
            "start": 22,
            "end": 30,
            "filename": "source.py",
            "message": "Data from UserControlled may reach RemoteCodeExecution",
            "traces": [{"name": "forward", "roots": []}, {"name": "backward", "roots": []}],
            "features": [],
            "sink_handle": {"kind": "Call"},
            "master_handle": "fixture-handle",
        },
    }


def test_pysa_stdout_issue_array_matches_documented_output(tmp_path: Path) -> None:
    result = normalize(json.dumps([pysa_stdout_issue()]), "pysa", tmp_path)
    assert result["errors"] == []
    issue = result["findings"][0]
    assert (issue["rule_id"], issue["file"], issue["line"]) == (
        "5001",
        str(tmp_path / "source.py"),
        9,
    )
    assert "RemoteCodeExecution" in issue["message"]
    assert issue["trace"] is None
    assert result["limitations"] == [COVERAGE_UNKNOWN]


def test_pysa_saved_jsonl_header_model_and_issue_preserve_trace(tmp_path: Path) -> None:
    records = [
        {"file_version": 3, "config": {"repo": str(tmp_path)}},
        {"kind": "model", "data": {"callable": "source.convert", "sources": [], "sinks": []}},
        pysa_saved_issue(),
    ]
    text = "\n".join(json.dumps(record) for record in records) + "\n"
    result = normalize(text, "pysa", tmp_path)
    assert result["errors"] == []
    assert len(result["findings"]) == 1
    issue = result["findings"][0]
    assert issue["file"] == str(tmp_path / "source.py")
    assert issue["end_line"] == 9  # Saved "end" is a column, not an end line.
    assert issue["trace"] == [{"name": "forward", "roots": []}, {"name": "backward", "roots": []}]


def test_pysa_saved_single_issue_record_is_valid_jsonl(tmp_path: Path) -> None:
    result = normalize(json.dumps(pysa_saved_issue()) + "\n", "pysa", tmp_path)
    assert len(result["findings"]) == 1


@pytest.mark.parametrize("text", ["[]", '{"file_version":3}', '{"kind":"model","data":{}}'])
def test_pysa_zero_findings_do_not_establish_scanned_coverage(tmp_path: Path, text: str) -> None:
    result = normalize(text, "pysa", tmp_path)
    assert result["findings"] == [] and result["errors"] == []
    assert result["scanned_files"] is None and result["limitations"] == [COVERAGE_UNKNOWN]


def test_pysa_structured_configuration_errors_are_not_findings(tmp_path: Path) -> None:
    text = json.dumps({"errors": [{"code": 1, "description": "Model is not in the environment"}]})
    result = normalize(text, "pysa", tmp_path)
    assert result["findings"] == []
    assert result["errors"] == ["Model is not in the environment"]


@pytest.mark.parametrize(
    "text",
    [
        "",
        "not JSON",
        "{}",
        "[5]",
        '{"errors":[]}',
        '{"kind":"unexpected","data":{}}',
        '{"kind":"issue","data":{}}',
        '[{"filename":"source.py","line":9,"code":5001}]',
        '{"file_version":3}\n{"kind":"issue",broken}',
    ],
)
def test_pysa_unknown_or_malformed_outputs_fail(tmp_path: Path, text: str) -> None:
    with pytest.raises(ValueError):
        normalize(text, "pysa", tmp_path)


@pytest.mark.parametrize("field,value", [("line", 0), ("line", True), ("code", None)])
def test_pysa_stdout_bad_location_or_code_fails(tmp_path: Path, field: str, value: object) -> None:
    issue = pysa_stdout_issue()
    issue[field] = value
    with pytest.raises(ValueError):
        normalize(json.dumps([issue]), "pysa", tmp_path)


@pytest.mark.parametrize("backend", ["semgrep", "joern"])
def test_explicit_zero_scan_inventory_remains_an_error(tmp_path: Path, backend: str) -> None:
    data = (
        {"results": [], "errors": [], "paths": {"scanned": []}}
        if backend == "semgrep"
        else {"tool": "joern", "findings": [], "errors": [], "scanned_files": []}
    )
    result = normalize(json.dumps(data), backend, tmp_path)
    assert result["errors"] == ["Analyzer scanned zero source files"]
    assert result["scanned_files"] == []
