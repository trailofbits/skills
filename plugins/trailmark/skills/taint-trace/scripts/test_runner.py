"""Artifact integrity checks and contracts exercised against installed engines."""

from __future__ import annotations

import json
import os
import plistlib
import shutil
import subprocess
import sys
from pathlib import Path
from unittest.mock import patch

import pytest

sys.path.insert(0, str(Path(__file__).parent))

from contracts import psalm_core_expectations, semgrep_fixture
from native import normalize
from runner import (
    argument_binds,
    check_probe,
    check_probe_baseline,
    check_run,
    expected_sites,
    probe,
    psalm_coverage,
    psalm_scan_errors,
    run_native,
    version_command,
)
from runner_config import snapshot_files

NATIVE_COMMANDS = {
    "joern": ["joern", "--script", "trace.sc"],
    "psalm": ["psalm", "--taint-analysis", "--debug", "--output-format=json"],
    "clang": [
        "clang",
        "--analyze",
        "-Xclang",
        "-analyzer-checker=optin.taint.GenericTaint",
        "probe.c",
    ],
    "checker-framework": ["javac", "-processor", "TaintingChecker", "probe.java"],
    "pysa": ["pyre", "analyze"],
    "infer": ["infer", "analyze", "--pulse-only"],
    "codeql": ["codeql", "database", "analyze", "db", "taint.qls"],
    "semgrep": ["semgrep", "scan", "--oss-only", "--config", "rule.json", "."],
    "semgrep-pro": ["semgrep", "scan", "--pro-languages", "--config", "rule.json", "."],
    "opengrep": ["opengrep", "scan", "--config", "rule.json", "."],
}


def native_run(tmp_path, data, *, backend="joern", language="java", returncode=0, **kwargs):
    source = tmp_path / "probe.java"
    source.write_text("first\nsink(value);\nlast\n", encoding="utf-8")
    if backend == "psalm" and not (tmp_path / "psalm.xml").exists():
        (tmp_path / "psalm.xml").write_text(
            '<psalm xmlns="https://getpsalm.org/schema/config">'
            '<projectFiles><file name="probe.java"/></projectFiles></psalm>\n',
            encoding="utf-8",
        )
    argv = kwargs.pop("argv", NATIVE_COMMANDS[backend])
    scope = kwargs.pop("scope", "intraprocedural")
    version_argv = kwargs.pop("version_argv", version_command(backend, argv))
    native_stderr = kwargs.pop("native_stderr", None)

    def execute(command, cwd, timeout):
        if command == version_argv or backend == "psalm" and "--version" in command:
            return 0, f"{backend} test-version", "", []
        if backend == "psalm":
            assert "--taint-analysis" in command
            assert any(item.startswith("--root=") for item in command)
        else:
            assert command == argv
        stderr = f"Analyzing {source}\n" if backend == "psalm" else ""
        if native_stderr is not None:
            stderr = native_stderr
        return returncode, data if isinstance(data, str) else json.dumps(data), stderr, []

    with patch("runner.execute", side_effect=execute):
        return run_native(
            backend=backend,
            language=language,
            phase="baseline",
            scope=scope,
            output=tmp_path / "run.json",
            argv=argv,
            cwd=tmp_path,
            version_argv=version_argv,
            **kwargs,
        )


def joern_data(**changes):
    return {
        "tool": "joern",
        "findings": [
            {"rule_id": "test", "file": "probe.java", "line": 2, "message": "native test fixture"}
        ],
        "scanned_files": ["probe.java"],
        "errors": [],
        **changes,
    }


@pytest.mark.parametrize(
    "backend,language,argv,error",
    [
        ("psalm", "php", ["psalm", "--output-format=json"], "--taint-analysis"),
        ("pysa", "python", ["pyre", "check"], "pyre analyze"),
        ("clang", "c", ["clang", "--analyze", "probe.c"], "GenericTaint"),
        (
            "clang",
            "c",
            ["clang", "-analyzer-checker=optin.taint.GenericTaint", "probe.c"],
            "analyzer mode",
        ),
        ("checker-framework", "java", ["javac", "probe.java"], "TaintingChecker"),
        (
            "checker-framework",
            "java",
            ["javac", "-processor", "TaintingChecker", "-proc:none", "probe.java"],
            "disables",
        ),
        ("infer", "c", ["infer", "analyze", "--no-pulse"], "enable Pulse"),
        ("infer", "c", ["infer", "capture", "--pulse-only"], "do not execute"),
        ("joern", "java", ["joern", "--param", "outFile=joern.json"], "--script"),
        ("codeql", "java", ["codeql", "database", "create", "db"], "database analyze"),
        ("psalm", "php", [sys.executable, "emit.py", "--taint-analysis"], "does not match"),
    ],
)
def test_inactive_native_analysis_is_rejected_before_target_execution(
    tmp_path, backend, language, argv, error
):
    record = native_run(tmp_path, [], backend=backend, language=language, argv=argv)
    assert record["status"] == "failed"
    assert record["returncode"] is None
    assert any(error in item for item in record["errors"])


def test_saved_run_cannot_drop_native_activation_or_change_engine(tmp_path):
    record = native_run(tmp_path, [], backend="psalm", language="php")
    assert check_run(record, tmp_path / "run.json") == []
    record["argv"].remove("--taint-analysis")
    assert any("--taint-analysis" in error for error in check_run(record, tmp_path / "run.json"))
    record["argv"].append("--taint-analysis")
    record["engine"] = "semgrep-ce"
    assert any("Recorded engine" in error for error in check_run(record, tmp_path / "run.json"))


@pytest.mark.parametrize(
    "backend,flag,scope,error",
    [
        ("semgrep", "--pro", "intraprocedural", "analysis-mode flags"),
        ("semgrep", "--pro-languages", "intraprocedural", "analysis-mode flags"),
        ("semgrep", "--pro-intrafile", "intraprocedural", "analysis-mode flags"),
        ("semgrep", "--oss-only", "intrafile", "only intraprocedural"),
        ("semgrep-pro", "--oss-only", "intraprocedural", "requires explicit activation"),
        ("semgrep-pro", "--pro-languages", "intrafile", "exceeds"),
        ("semgrep-pro", "--pro-intrafile", "interprocedural", "exceeds"),
        ("opengrep", "--pro", "intraprocedural", "analysis-mode flags"),
        ("opengrep", "--json", "interprocedural", "within a file"),
        ("opengrep", "--json", "intrafile", "--taint-intrafile"),
    ],
)
def test_semgrep_engine_and_scope_must_match_activation(tmp_path, backend, flag, scope, error):
    semgrep_fixture(tmp_path, "python")
    record = native_run(
        tmp_path,
        {"results": [], "errors": [], "paths": {"scanned": ["probe.py"]}},
        backend=backend,
        language="python",
        scope=scope,
        argv=[
            "opengrep" if backend == "opengrep" else "semgrep",
            "scan",
            flag,
            "--config",
            "rule.json",
            ".",
        ],
    )
    assert record["returncode"] is None
    assert any(error in item for item in record["errors"])


@pytest.mark.parametrize("backend,reported", [("semgrep", "PRO"), ("semgrep-pro", "OSS")])
def test_reported_native_engine_cannot_disagree_with_backend(tmp_path, backend, reported):
    semgrep_fixture(tmp_path, "python")
    record = native_run(
        tmp_path,
        {
            "engine_requested": reported,
            "results": [],
            "errors": [],
            "paths": {"scanned": ["probe.py"]},
        },
        backend=backend,
        language="python",
    )
    assert record["status"] == "failed"
    assert any("Native reported engine" in item for item in record["errors"])


def test_semgrep_engine_record_preserves_activated_edition(tmp_path):
    semgrep_fixture(tmp_path, "python")
    record = native_run(
        tmp_path,
        {
            "engine_requested": "PRO",
            "results": [],
            "errors": [],
            "paths": {"scanned": ["probe.py"]},
        },
        backend="semgrep-pro",
        language="python",
        scope="intrafile",
        argv=["semgrep", "scan", "--pro-intrafile", "--config", "rule.json", "."],
    )
    assert record["status"] == "analyzed"
    assert record["engine"] == "semgrep-pro-intrafile"
    assert check_run(record, tmp_path / "run.json") == []
    record["scope"] = "interprocedural"
    assert any("exceeds" in error for error in check_run(record, tmp_path / "run.json"))


@pytest.mark.parametrize(
    "backend,language,argv,data",
    [
        (
            "psalm",
            "php",
            ["php", "-d", "memory_limit=-1", "vendor/bin/psalm", "--taint-analysis"],
            [],
        ),
        (
            "pysa",
            "python",
            ["uv", "run", "--no-project", "--with", "pyre-check", "pyre", "analyze"],
            [{"file_version": 3}],
        ),
        (
            "checker-framework",
            "java",
            ["javac", "-processor", "OtherChecker,TaintingChecker", "probe.java"],
            "",
        ),
        (
            "codeql",
            "java",
            ["codeql", "database", "analyze", "db", "taint.qls", "--format=sarif-latest"],
            {"runs": [{"tool": {"driver": {"name": "CodeQL"}}, "results": []}]},
        ),
    ],
)
def test_supported_native_wrappers_and_processor_lists(tmp_path, backend, language, argv, data):
    record = native_run(tmp_path, data, backend=backend, language=language, argv=argv)
    assert record["status"] == ("analyzed" if backend == "psalm" else "limited"), record["errors"]
    assert check_run(record, tmp_path / "run.json") == []
    assert record["version"]["argv"] == version_command(backend, record["argv"])


def test_version_capture_must_use_the_same_native_environment(tmp_path):
    record = native_run(
        tmp_path,
        [{"file_version": 3}],
        backend="pysa",
        language="python",
        argv=["uv", "run", "--project", "analysis", "pyre", "analyze"],
        version_argv=["pyre", "--version"],
    )
    assert record["returncode"] is None
    assert any("same native executable and environment" in item for item in record["errors"])


def test_native_artifacts_and_baseline_source_snapshot(tmp_path):
    record = native_run(tmp_path, joern_data(), models=[tmp_path / "probe.java"])
    assert record["status"] == "limited"
    assert record["findings"][0]["source_line"] == "sink(value);"
    (tmp_path / "probe.java").write_text("// annotation added\nchanged\n", encoding="utf-8")
    assert record["model_files"][0]["original_path"] == str(tmp_path / "probe.java")
    assert record["model_files"][0]["path"] != str(tmp_path / "probe.java")
    assert check_run(record, tmp_path / "run.json") == []
    assert record["findings"][0]["source_line"] == "sink(value);"
    Path(record["native_output"]["path"]).write_text("{}", encoding="utf-8")
    assert any("hash mismatch" in error for error in check_run(record, tmp_path / "run.json"))


@pytest.mark.parametrize("suffix", [".php", ".py", ".java", ".go", ".yaml", ".json"])
def test_input_snapshots_do_not_expand_extension_based_discovery(tmp_path, suffix):
    source = tmp_path / ("input" + suffix)
    source.write_bytes(b"original input\n")
    records = [
        item
        for kind in ("model", "config")
        for item in snapshot_files(tmp_path / "run.json", [source], kind)
    ]
    assert list(tmp_path.rglob("*" + suffix)) == [source]
    for record in records:
        assert record["original_path"] == str(source)
        assert Path(record["path"]).read_bytes() == source.read_bytes()


def test_immutable_run_refuses_overwrite(tmp_path):
    native_run(tmp_path, joern_data())
    with pytest.raises(FileExistsError):
        native_run(tmp_path, joern_data())


@pytest.mark.parametrize("changes", [{"scanned_files": []}, {"errors": ["native parse failed"]}])
def test_structured_failure_even_when_command_exits_zero(tmp_path, changes):
    record = native_run(tmp_path, joern_data(**changes))
    assert record["status"] == "failed"
    assert check_run(record, tmp_path / "run.json")


def test_missing_coverage_is_limited_not_successful_inventory(tmp_path):
    record = native_run(
        tmp_path,
        [{"type": "TaintedHtml", "file_path": str(tmp_path / "probe.java"), "line_from": 2}],
        backend="psalm",
        language="php",
        native_stderr="",
    )
    assert record["status"] == "limited"
    assert record["scanned_files"] is None
    assert check_run(record, tmp_path / "run.json") == []
    record["status"] = "analyzed"
    assert any("coverage" in error for error in check_run(record, tmp_path / "run.json"))


def test_psalm_debug_coverage_is_measured_and_revalidated(tmp_path):
    record = native_run(tmp_path, [], backend="psalm", language="php")
    assert record["status"] == "analyzed", record["errors"]
    assert record["scanned_files"] == [str(tmp_path / "probe.java")]
    assert not record["limitations"]
    assert check_run(record, tmp_path / "run.json") == []
    record["scanned_files"].append(str(tmp_path / "unscanned.php"))
    assert any("coverage disagrees" in error for error in check_run(record, tmp_path / "run.json"))


def test_psalm_baseline_captures_configuration_without_models(tmp_path):
    record = native_run(tmp_path, [], backend="psalm", language="php")
    assert not record["model_files"]
    assert len(record["config_files"]) == 1
    snapshot = Path(record["config_files"][0]["path"])
    original = snapshot.read_bytes()
    (tmp_path / "psalm.xml").write_text("<changed-later/>")
    assert snapshot.read_bytes() == original
    assert check_run(record, tmp_path / "run.json") == []
    record["config_files"] = []
    assert any("captured native XML" in error for error in check_run(record, tmp_path / "run.json"))


def test_psalm_coverage_uses_only_target_analysis_not_dependency_scanning(tmp_path):
    source = tmp_path / "probe.php"
    source.write_text("<?php echo 'safe';\n")
    unknown = normalize("[]", "psalm", tmp_path)
    for stderr in (f"Scanning {source}\n", "Analyzing files...\n", f"Analyzing {__file__}\n"):
        assert psalm_coverage(unknown.copy(), stderr, tmp_path) == unknown
    measured = psalm_coverage(unknown.copy(), f"Analyzing {source}\nAnalyzing {source}\n", tmp_path)
    assert measured["scanned_files"] == [str(source)]
    assert not measured["limitations"]


def test_psalm_empty_json_does_not_establish_nonempty_analysis(tmp_path):
    source = tmp_path / "source.php"
    source.write_text("<?php echo 'constant';\n")
    for stderr in ("", "Analyzing files...\n", f"Scanning {source}\n"):
        assert psalm_scan_errors(stderr, [], tmp_path)
    assert psalm_scan_errors(f"Analyzing {source}\n", [], tmp_path) == []


def test_nonzero_native_failure_with_plausible_json(tmp_path):
    record = native_run(tmp_path, joern_data(), returncode=2)
    assert record["status"] == "failed"


def test_missing_native_output_and_stale_native_output(tmp_path):
    stale = tmp_path / "report.json"
    stale.write_text(json.dumps(joern_data()), encoding="utf-8")
    record = native_run(tmp_path, joern_data(), native_output=stale)
    assert any("not refreshed" in error for error in record["errors"])
    (tmp_path / "run.json").unlink()
    record = native_run(tmp_path, joern_data(), native_output=tmp_path / "absent.json")
    assert any("missing" in error for error in record["errors"])


def test_checker_success_silence_and_taint_diagnostic(tmp_path):
    empty = normalize("", "checker-framework", tmp_path)
    assert not empty["findings"] and empty["scanned_files"] is None
    with pytest.raises(ValueError, match="recognizable"):
        normalize("TAINT_TRACE_CHECKER_SUCCESS", "checker-framework", tmp_path)
    result = normalize(
        "Probe.java:5: error: [argument] incompatible argument\n"
        "  found: @Tainted String\n  required: @Untainted String\n1 error\n",
        "checker-framework",
        tmp_path,
    )
    assert result["findings"][0]["line"] == 5
    result = normalize(
        "Probe.java:5: error: cannot find symbol\n1 error\n", "checker-framework", tmp_path
    )
    assert result["errors"]


def test_clang_keeps_taint_findings_separate_from_other_checkers(tmp_path):
    native = plistlib.dumps(
        {
            "files": ["probe.c"],
            "diagnostics": [
                {"check_name": "core.NullDereference", "location": {"file": 0, "line": 1}},
                {
                    "check_name": "optin.taint.GenericTaint",
                    "location": {"file": 0, "line": 2},
                    "description": "native taint warning",
                },
            ],
        }
    ).decode()
    results = normalize(native, "clang", tmp_path)
    assert [item["line"] for item in results["findings"]] == [2]


def test_semgrep_rejects_search_rules_and_unloaded_models(tmp_path):
    semgrep_fixture(tmp_path, "python")
    rules = json.loads((tmp_path / "rule.json").read_text())
    rules["rules"][0].pop("mode")
    (tmp_path / "search.json").write_text(json.dumps(rules), encoding="utf-8")
    output = run_native(
        backend="semgrep",
        language="python",
        phase="baseline",
        scope="intraprocedural",
        output=tmp_path / "run.json",
        argv=["semgrep", "scan", "--oss-only", "--config", "search.json"],
        cwd=tmp_path,
    )
    assert output["status"] == "failed"
    assert any("Zero applicable" in error for error in output["errors"])
    (tmp_path / "run.json").unlink()
    output = run_native(
        backend="semgrep",
        language="python",
        phase="baseline",
        scope="intraprocedural",
        output=tmp_path / "run.json",
        argv=["semgrep", "scan", "--oss-only", "--config", "rule.json"],
        cwd=tmp_path,
        models=[tmp_path / "search.json"],
    )
    assert any("not in the loaded" in error for error in output["errors"])


@pytest.mark.parametrize("kind", ["source", "stub", "stub_ignored_as_source", "missing", "ignored"])
def test_psalm_model_files_must_be_in_xml_source_or_stub_inputs(tmp_path, kind):
    model = tmp_path / "model.php"
    model.write_text(
        "<?php /** @psalm-taint-source input */ function input(): string {}\n", encoding="utf-8"
    )
    section = (
        '<projectFiles><file name="model.php"/></projectFiles>'
        if kind == "source"
        else '<projectFiles><directory name="src"/></projectFiles>'
    )
    if kind in {"stub", "stub_ignored_as_source"}:
        section += '<stubs><file name="model.php"/></stubs>'
    if kind == "stub_ignored_as_source":
        section = (
            '<projectFiles><directory name="."/><ignoreFiles><file name="model.php"/>'
            '</ignoreFiles></projectFiles><stubs><file name="model.php"/></stubs>'
        )
    if kind == "ignored":
        section = (
            '<projectFiles><directory name="."/><ignoreFiles>'
            '<file name="model.php"/></ignoreFiles></projectFiles>'
        )
    (tmp_path / "psalm.xml").write_text(
        '<psalm xmlns="https://getpsalm.org/schema/config">' + section + "</psalm>",
        encoding="utf-8",
    )
    record = native_run(tmp_path, [], backend="psalm", language="php", models=[model])
    assert record["status"] == ("failed" if kind in {"missing", "ignored"} else "analyzed")
    if kind in {"source", "stub", "stub_ignored_as_source"}:
        # Baseline retains the old config even as enrichment changes the current config/source.
        (tmp_path / "psalm.xml").write_text("<changed/>", encoding="utf-8")
        model.write_text("<?php // edited\n", encoding="utf-8")
        assert check_run(record, tmp_path / "run.json") == []
    else:
        assert any("absent from" in error for error in record["errors"])


def test_clang_and_infer_models_bind_to_configuration_options(tmp_path):
    model = tmp_path / "model.yaml"
    assert argument_binds(
        model,
        ["clang", "-Xclang", f"optin.taint.TaintPropagation:Config={model}"],
        tmp_path,
        "clang",
    )
    assert not argument_binds(model, ["clang", "--analyze", str(model)], tmp_path, "clang")
    assert argument_binds(model, ["infer", "--pulse-taint-config", "model.yaml"], tmp_path, "infer")
    assert not argument_binds(model, ["infer", "--unrelated", "model.yaml"], tmp_path, "infer")


def test_excluded_taint_rule_and_native_skipped_rules_fail(tmp_path):
    semgrep_fixture(tmp_path, "python")
    result = run_native(
        backend="semgrep",
        language="python",
        phase="baseline",
        scope="intraprocedural",
        output=tmp_path / "excluded.json",
        cwd=tmp_path,
        argv=[
            "semgrep",
            "scan",
            "--oss-only",
            "--config",
            "rule.json",
            "--exclude-rule=taint-trace-capability",
        ],
    )
    assert result["status"] == "failed"
    assert any("Zero applicable" in error for error in result["errors"])
    result = normalize(
        json.dumps(
            {
                "results": [],
                "errors": [],
                "paths": {"scanned": ["probe.py"]},
                "skipped_rules": [{"rule_id": "requires-newer-engine"}],
            }
        ),
        "semgrep",
        tmp_path,
    )
    assert result["errors"]


def test_mixed_semgrep_results_only_count_taint_rules(tmp_path):
    semgrep_fixture(tmp_path, "python")
    data = {
        "results": [
            {
                "check_id": rule,
                "path": "probe.py",
                "start": {"line": line},
                "extra": {"message": "fixture"},
            }
            for rule, line in [("prefix.taint-trace-capability", 4), ("ordinary-search", 5)]
        ],
        "errors": [],
        "paths": {"scanned": ["probe.py"]},
    }
    record = native_run(tmp_path, data, backend="semgrep", language="python")
    assert record["status"] == "analyzed"
    assert len(record["findings"]) == 1
    assert check_run(record, tmp_path / "run.json") == []


def test_proof_rejects_negative_outside_scan_and_unproved_scope(tmp_path):
    (tmp_path / "positive.java").write_text("sink(tainted);\n", encoding="utf-8")
    (tmp_path / "negative.java").write_text('sink("literal");\n', encoding="utf-8")
    proof = {
        "fixture_root": str(tmp_path),
        "scope": "interprocedural",
        "expect": {
            "positive": [{"file": "positive.java", "line": 1}],
            "negative": [{"file": "negative.java", "line": 1}],
        },
    }
    run = {
        "findings": [{"file": str(tmp_path / "positive.java"), "line": 1}],
        "scanned_files": None,
    }
    errors = expected_sites(proof, run)
    assert any("not observably scanned" in error for error in errors)
    assert any("cross-function" in error for error in errors)
    proof["expect"]["positive"] = []
    assert any("nonempty positive" in error for error in expected_sites(proof, run))


def test_missing_tools_fail_gracefully(tmp_path):
    proof = probe(
        backend="semgrep",
        language="python",
        output=tmp_path / "missing.json",
        executable="/nonexistent-taint-trace-tool",
    )
    assert proof["status"] == "failed"
    assert check_probe(proof, tmp_path / "missing.json")
    proof = probe(
        backend="joern",
        language="java",
        output=tmp_path / "joern.json",
        executable="/nonexistent-taint-trace-joern",
    )
    assert proof["status"] == "failed"
    assert any("preparation command failed" in error for error in proof["errors"])
    assert proof["fixture_files"]


def test_capability_requires_the_expected_vulnerability_context(tmp_path):
    source = tmp_path / "probe.php"
    source.write_text("sql_sink(html_escape(request_value()));\necho 'literal';\n")
    proof = {
        "fixture_root": str(tmp_path),
        "scope": "intraprocedural",
        "expect": {
            "positive": [{"file": source.name, "line": 1, "rule_id": "TaintedSql"}],
            "negative": [{"file": source.name, "line": 2}],
        },
    }
    finding = {"file": str(source), "line": 1, "rule_id": "TaintedHtml"}
    run = {"findings": [finding], "scanned_files": [str(source)]}
    assert any("finding missing" in error for error in expected_sites(proof, run))
    finding["rule_id"] = "TaintedSql"
    assert expected_sites(proof, run) == []


@pytest.mark.parametrize("change", ["missing", "phase", "backend", "version", "findings"])
def test_psalm_capability_baseline_cannot_be_omitted_or_changed(tmp_path, change):
    baseline = native_run(tmp_path, [], backend="psalm", language="php")
    proof = {
        "profile": "psalm-taint-contracts-v2",
        "backend": "psalm",
        "baseline_run": str(tmp_path / "run.json"),
    }
    enriched = dict(baseline)
    assert check_probe_baseline(proof, enriched) == []
    if change == "missing":
        proof.pop("baseline_run")
    elif change == "findings":
        baseline["findings"] = [{"rule_id": "TaintedSql"}]
    elif change == "version":
        baseline["version"] = {**baseline["version"], "output": "different engine"}
    else:
        baseline[change] = "different"
    (tmp_path / "run.json").write_text(json.dumps(baseline), encoding="utf-8")
    assert check_probe_baseline(proof, enriched)


def test_custom_contract_preparation_failure_is_preserved(tmp_path):
    source = tmp_path / "fixtures"
    source.mkdir()
    (source / "probe.c").write_text("one\ntwo\n", encoding="utf-8")
    contract = tmp_path / "contract.json"
    contract.write_text(
        json.dumps(
            {
                "backend": "clang",
                "language": "c",
                "scope": "intraprocedural",
                "fixture_root": "fixtures",
                "commands": [[sys.executable, "-c", "raise SystemExit(2)"], ["clang"]],
                "expect": {
                    "positive": [{"file": "probe.c", "line": 1}],
                    "negative": [{"file": "probe.c", "line": 2}],
                },
            }
        ),
        encoding="utf-8",
    )
    proof = probe(backend="clang", language="c", output=tmp_path / "proof.json", contract=contract)
    assert proof["status"] == "failed"
    assert proof["preparation"][0]["returncode"] == 2
    assert Path(proof["preparation"][0]["stderr"]["path"]).is_file()


def integration_executable(name: str, default: str) -> str | None:
    value = os.environ.get(f"TAINT_TRACE_{name}")
    return default if value == "1" else value or None


SEMGREP = integration_executable("SEMGREP", "semgrep")
OPENGREP = integration_executable("OPENGREP", "opengrep")
PSALM = integration_executable("PSALM", "psalm")

SEMGREP_LANGUAGES = [
    "python",
    "javascript",
    "typescript",
    "php",
    "java",
    "kotlin",
    "c_sharp",
    "go",
    "ruby",
    "swift",
    "rust",
    "dart",
    "c",
    "cpp",
    "objc",
    "bash",
    "lua",
    "r",
    "julia",
    "solidity",
    "circom",
    "move_on_aptos",
    "move_on_sui",
]


@pytest.mark.skipif(not SEMGREP, reason="Set TAINT_TRACE_SEMGREP to enable native integration")
@pytest.mark.parametrize("language", SEMGREP_LANGUAGES)
def test_real_semgrep_positive_literal_and_sanitized_negative(tmp_path, language):
    output = tmp_path / "proof.json"
    proof = probe(backend="semgrep", language=language, output=output, executable=SEMGREP)
    assert proof["status"] == "passed", proof["errors"]
    assert check_probe(proof, output) == []
    if language == "python":
        original = Path(proof["run"]).read_text()
        run = json.loads(original)
        run["findings"] = []
        Path(proof["run"]).write_text(json.dumps(run), encoding="utf-8")
        assert any("disagree" in error for error in check_probe(proof, output))
        Path(proof["run"]).write_text(original, encoding="utf-8")
        fixture = Path(proof["fixture_root"]) / "probe.py"
        fixture.write_text(fixture.read_text() + "# later edit\n", encoding="utf-8")
        assert any("fixture artifact hash" in error for error in check_probe(proof, output))


@pytest.mark.skipif(not OPENGREP, reason="Set TAINT_TRACE_OPENGREP to enable native integration")
def test_real_opengrep_vbnet_gate(tmp_path):
    proof = probe(
        backend="opengrep", language="vb", output=tmp_path / "proof.json", executable=OPENGREP
    )
    assert proof["status"] == "passed", proof["errors"]
    assert proof["scope"] == "intraprocedural"


@pytest.mark.skipif(not OPENGREP, reason="Set TAINT_TRACE_OPENGREP to enable native integration")
def test_real_opengrep_intrafile_propagation_and_literal_negative(tmp_path):
    fixtures = tmp_path / "fixtures"
    fixtures.mkdir()
    semgrep_fixture(fixtures, "python")
    (fixtures / "probe.py").write_text(
        "def consume(value):\n    sink_output(value)\n"
        "def vulnerable():\n    consume(source_input())\n"
        "def consume_literal(value):\n    sink_output(value)\n"
        "def literal():\n    consume_literal('constant')\n"
    )
    contract = {
        "backend": "opengrep",
        "language": "python",
        "scope": "intrafile",
        "fixture_root": "fixtures",
        "commands": [
            [
                OPENGREP,
                "scan",
                "--taint-intrafile",
                "--json",
                "--no-git-ignore",
                "--config",
                "rule.json",
                "probe.py",
            ]
        ],
        "expect": {
            "positive": [{"file": "probe.py", "line": 2}],
            "negative": [{"file": "probe.py", "line": 6}],
            "cross_function": [{"file": "probe.py", "line": 2}],
        },
    }
    path = tmp_path / "contract.json"
    path.write_text(json.dumps(contract))
    proof = probe(
        backend="opengrep", language="python", output=tmp_path / "proof.json", contract=path
    )
    assert proof["status"] == "passed", proof["errors"]
    # The same callee sink is not reachable to the default single-function scan.
    contract["scope"] = "intraprocedural"
    contract["commands"][0].remove("--taint-intrafile")
    contract["expect"].pop("cross_function")
    path.write_text(json.dumps(contract))
    unenabled = probe(
        backend="opengrep", language="python", output=tmp_path / "unenabled.json", contract=path
    )
    assert unenabled["status"] == "failed"
    assert any("finding missing for positive" in error for error in unenabled["errors"])


@pytest.mark.skipif(
    not PSALM, reason="Psalm is not installed; set TAINT_TRACE_PSALM to its executable"
)
def test_real_psalm_annotation_acceptance_and_context_sanitization(tmp_path):
    proof = probe(backend="psalm", language="php", output=tmp_path / "proof.json", executable=PSALM)
    assert proof["status"] == "passed", proof["errors"]
    baseline = json.loads(Path(proof["baseline_run"]).read_text())
    assert baseline["status"] in {"analyzed", "limited"}, baseline["errors"]
    assert baseline["findings"] == []
    run = json.loads(Path(proof["run"]).read_text())
    assert {item["rule_id"] for item in run["findings"]} >= {
        "TaintedHtml",
        "TaintedSql",
        "TaintedShell",
    }
    assert check_probe(proof, tmp_path / "proof.json") == []
    sql = next(item for item in run["findings"] if item["rule_id"] == "TaintedSql")
    assert any(
        "sql_sink(escape_html(request_value()))" in point.get("snippet", "")
        for point in sql["trace"]
    )


@pytest.mark.skipif(not PSALM, reason="Psalm is not installed")
def test_real_psalm_does_not_bootstrap_target_composer_autoloader(tmp_path):
    assert PSALM is not None
    vendor = tmp_path / "vendor"
    vendor.mkdir()
    marker = tmp_path / "bootstrap-executed"
    (vendor / "autoload.php").write_text(
        "<?php file_put_contents(__DIR__ . '/../bootstrap-executed', 'executed');\n"
    )
    (tmp_path / "composer.json").write_text('{"name":"fixture/application","autoload":{}}')
    (tmp_path / "probe.php").write_text("<?php echo $_GET['input'];\n")
    (tmp_path / "psalm.xml").write_text(
        '<psalm xmlns="https://getpsalm.org/schema/config" findUnusedCode="false">'
        '<projectFiles><file name="probe.php"/></projectFiles></psalm>\n'
    )
    record = run_native(
        backend="psalm",
        language="php",
        phase="baseline",
        scope="interprocedural",
        cwd=tmp_path,
        output=tmp_path / "run.json",
        argv=[PSALM, "--taint-analysis", "--debug", "--no-cache", "--output-format=json"],
    )
    assert record["status"] in {"analyzed", "limited"}, record["errors"]
    assert any(f["rule_id"] == "TaintedHtml" for f in record["findings"])
    assert record["scanned_files"] == [str(tmp_path / "probe.php")]
    assert not marker.exists()
    assert check_run(record, tmp_path / "run.json") == []


@pytest.mark.skipif(not PSALM, reason="Psalm is not installed")
@pytest.mark.parametrize("selection", ["empty", "ignored", "clean"])
def test_real_psalm_empty_scan_is_not_a_clean_result(tmp_path, selection):
    assert PSALM is not None
    source_root = tmp_path / "src"
    source_root.mkdir()
    if selection != "empty":
        (source_root / "source.php").write_text("<?php echo 'constant';\n")
    exclusions = (
        '<ignoreFiles><directory name="src"/></ignoreFiles>' if selection == "ignored" else ""
    )
    (tmp_path / "psalm.xml").write_text(
        '<psalm xmlns="https://getpsalm.org/schema/config" findUnusedCode="false">'
        '<projectFiles><directory name="src"/>' + exclusions + "</projectFiles></psalm>\n"
    )
    record = run_native(
        backend="psalm",
        language="php",
        phase="baseline",
        scope="interprocedural",
        output=tmp_path / "empty.json",
        cwd=tmp_path,
        argv=[PSALM, "--taint-analysis", "--debug", "--no-cache", "--output-format=json"],
    )
    assert record["returncode"] == 0 and record["findings"] == []
    if selection == "clean":
        assert record["status"] == "analyzed", record["errors"]
        assert record["scanned_files"] == [str((source_root / "source.php").resolve())]
        assert check_run(record, tmp_path / "empty.json") == []
    else:
        assert record["status"] == "failed"
        assert any("nonempty target scan" in error for error in record["errors"])


def clang_fixture(tmp_path, name):
    fixture = tmp_path / "fixtures"
    fixture.mkdir()
    (fixture / name).write_text(
        "extern char *source_input(void);\n"
        "extern void sink_output(const char *);\n"
        "static char *wrapper(char *value) { return value; }\n"
        "void test(void) {\n"
        " char *value = source_input();\n"
        " sink_output(value);\n"
        ' sink_output("safe");\n'
        " sink_output(wrapper(source_input()));\n"
        "}\n",
        encoding="utf-8",
    )
    (fixture / "taint.yaml").write_text(
        "Propagations:\n  - Name: source_input\n    DstArgs: [-1]\n"
        "Sinks:\n  - Name: sink_output\n    Args: [0]\n",
        encoding="utf-8",
    )


def clang_contract(tmp_path, clang, language, name):
    contract = tmp_path / "contract.json"
    contract.write_text(
        json.dumps(
            {
                "backend": "clang",
                "language": language,
                "scope": "translation-unit",
                "fixture_root": "fixtures",
                "commands": [
                    [
                        clang,
                        "--analyze",
                        "-Xclang",
                        "-analyzer-checker=optin.taint.GenericTaint",
                        "-Xclang",
                        "-analyzer-config",
                        "-Xclang",
                        "optin.taint.TaintPropagation:Config={workdir}/taint.yaml",
                        "-Xclang",
                        "-analyzer-output=plist",
                        "-o",
                        "probe.plist",
                        name,
                    ]
                ],
                "native_output": "{workdir}/probe.plist",
                "version_command": [clang, "--version"],
                "expect": {
                    "positive": [{"file": name, "line": 6}, {"file": name, "line": 8}],
                    "negative": [{"file": name, "line": 7}],
                    "cross_function": [{"file": name, "line": 8}],
                },
            }
        ),
        encoding="utf-8",
    )
    return contract


@pytest.mark.skipif(not shutil.which("clang"), reason="Clang is not installed")
@pytest.mark.parametrize("language,extension", [("c", "c"), ("cpp", "cpp")])
def test_real_clang_contract_and_cross_function_flow(tmp_path, language, extension):
    clang = shutil.which("clang")
    assert clang is not None
    help_result = subprocess.run(
        [clang, "-cc1", "-analyzer-checker-help"], capture_output=True, text=True, check=True
    )
    if "optin.taint.GenericTaint" not in help_result.stdout:
        pytest.skip("Installed Clang has no optin.taint.GenericTaint checker")
    name = f"probe.{extension}"
    clang_fixture(tmp_path, name)
    contract = clang_contract(tmp_path, clang, language, name)
    output = tmp_path / "proof.json"
    proof = probe(backend="clang", language=language, output=output, contract=contract)
    assert proof["status"] == "passed", proof["errors"]
    assert check_probe(proof, output) == []
    record = json.loads(Path(proof["run"]).read_text())
    assert record["status"] == "limited" and record["scanned_files"] is None


def core_psalm_output(argv, cwd, timeout, *, omit_sql=False):
    if "--version" in argv:
        return 0, "Psalm stock-test-version", "", []
    baseline = any("psalm-baseline.xml" in item for item in argv)
    source = cwd / ("unmodeled/probe.php" if baseline else "probe.php")
    findings = (
        []
        if baseline
        else [
            {
                "type": site.get("rule_id", "TaintedHtml"),
                "file_path": str(source),
                "line_from": site["line"],
                "message": "native core finding",
            }
            for site in psalm_core_expectations()["positive"]
            if not omit_sql or site.get("rule_id") != "TaintedSql"
        ]
    )
    return 2 if findings else 0, json.dumps(findings), f"Analyzing {source}\n", []


def test_stock_psalm_core_passes_with_optional_limitations(tmp_path):
    output = tmp_path / "proof.json"
    with patch("runner.execute", side_effect=core_psalm_output):
        proof = probe(backend="psalm", language="php", output=output)
    assert proof["status"] == "passed", proof["errors"]
    assert proof["limitations"]
    assert all(item["status"] == "limited" for item in proof["optional_capabilities"].values())
    run = json.loads(Path(proof["run"]).read_text())
    assert run["status"] == "limited"
    assert set(proof["limitations"]) <= set(run["limitations"])
    assert check_probe(proof, output) == []
    proof["limitations"] = []
    assert any("omits" in error for error in check_probe(proof, output))


def test_psalm_core_requires_native_sql_after_html_escape(tmp_path):
    def execute(argv, cwd, timeout):
        return core_psalm_output(argv, cwd, timeout, omit_sql=True)

    with patch("runner.execute", side_effect=execute):
        proof = probe(backend="psalm", language="php", output=tmp_path / "proof.json")
    assert proof["status"] == "failed"
    assert any("TaintedSql" in error for error in proof["errors"])


def test_builtin_psalm_expectations_and_fixture_capture_are_bound(tmp_path):
    output = tmp_path / "proof.json"
    with patch("runner.execute", side_effect=core_psalm_output):
        proof = probe(backend="psalm", language="php", output=output)
    proof["expect"]["positive"] = proof["expect"]["positive"][:1]
    assert any("required expectations" in error for error in check_probe(proof, output))
    proof["expect"] = psalm_core_expectations()
    proof["fixture_files"] = []
    assert any("immutable fixture" in error for error in check_probe(proof, output))


def test_rule_snapshots_retain_history_and_bind_command_and_models(tmp_path):
    semgrep_fixture(tmp_path, "python")
    record = native_run(
        tmp_path,
        {"results": [], "errors": [], "paths": {"scanned": ["probe.py"]}},
        backend="semgrep",
        language="python",
        models=[tmp_path / "rule.json"],
    )
    (tmp_path / "rule.json").unlink()
    assert check_run(record, tmp_path / "run.json") == []
    record["argv"][record["argv"].index("rule.json")] = "unrelated.json"
    assert any("not bound" in error for error in check_run(record, tmp_path / "run.json"))
    record["argv"][record["argv"].index("unrelated.json")] = "rule.json"
    record["model_files"][0]["original_path"] = str(tmp_path / "unloaded.json")
    assert any("not in the loaded" in error for error in check_run(record, tmp_path / "run.json"))


@pytest.mark.parametrize(
    "value,expected", [(None, None), ("1", "semgrep"), ("/bin/semgrep", "/bin/semgrep")]
)
def test_native_integration_requires_explicit_environment_opt_in(monkeypatch, value, expected):
    monkeypatch.delenv("TAINT_TRACE_SEMGREP", raising=False)
    if value is not None:
        monkeypatch.setenv("TAINT_TRACE_SEMGREP", value)
    with patch("shutil.which", return_value="/installed/semgrep"):
        assert integration_executable("SEMGREP", "semgrep") == expected


FAKE_STARTUP_PSALM = r"""
import json
import os
import runpy
import sys
from pathlib import Path
import xml.etree.ElementTree as ET

args = sys.argv[1:]
root = Path(next((arg.split("=", 1)[1] for arg in args if arg.startswith("--root=")), os.getcwd()))
for bootstrap in (root / "vendor" / "autoload.php", root.parent.parent / "autoload.php"):
    if bootstrap.is_file():
        runpy.run_path(str(bootstrap))
log = Path(__file__).with_suffix(".jsonl")
with log.open("a") as stream:
    stream.write(json.dumps({"argv": args, "cwd": os.getcwd()}) + "\n")
if "--version" in args:
    print("Psalm startup-test-version")
else:
    config = Path(next(arg.split("=", 1)[1] for arg in args if arg.startswith("--config=")))
    assert config.is_absolute()
    tree = ET.parse(config).getroot()
    mode = tree.attrib.get("resolveFromConfigFile", "true")
    base = config.parent if mode in {"true", "1"} else root
    for item in tree.iter():
        if item.tag.rsplit("}", 1)[-1] == "file":
            source = (base / item.attrib["name"]).resolve()
            print("Analyzing " + str(source), file=sys.stderr)
    print("[]")
"""


def startup_fixture(tmp_path):
    target, tools = tmp_path / "target", tmp_path / "tools"
    target.mkdir()
    tools.mkdir()
    (target / "vendor").mkdir()
    source = target / "source.php"
    source.write_text("<?php echo 'literal';\n")
    config = target / "psalm.xml"
    config.write_text(
        '<psalm xmlns="https://getpsalm.org/schema/config">'
        '<projectFiles><file name="source.php"/></projectFiles></psalm>'
    )
    marker = target / "bootstrap-executed"
    (target / "vendor" / "autoload.php").write_text(
        f"from pathlib import Path\nPath({str(marker)!r}).write_text('bootstrapped')\n"
    )
    executable = tools / "psalm"
    executable.write_text(f"#!{sys.executable}\n" + FAKE_STARTUP_PSALM)
    executable.chmod(0o700)
    argv = [str(executable), "--taint-analysis", "--debug", "--output-format=json"]
    return target, tools, marker, argv


def startup_run(target, argv, **kwargs):
    return run_native(
        backend="psalm",
        language="php",
        phase="baseline",
        scope="interprocedural",
        output=target / "run.json",
        cwd=target,
        argv=argv,
        **kwargs,
    )


def test_startup_fixture_exercises_composer_bootstrap_before_version(tmp_path):
    target, _, marker, argv = startup_fixture(tmp_path)
    result = subprocess.run(
        [argv[0], f"--root={target}", "--version"],
        cwd=target,
        capture_output=True,
        text=True,
        check=True,
    )
    assert "Psalm startup-test-version" in result.stdout
    assert marker.read_text() == "bootstrapped"


def test_psalm_isolates_native_and_version_composer_discovery_and_snapshots_commands(tmp_path):
    target, tools, marker, argv = startup_fixture(tmp_path)
    requested = list(argv)
    record = startup_run(target, argv)
    assert record["status"] == "analyzed", record["errors"]
    assert not marker.exists()
    calls = [json.loads(line) for line in (tools / "psalm.jsonl").read_text().splitlines()]
    assert len(calls) == 2 and "--version" in calls[0]["argv"]
    roots = [next(arg for arg in call["argv"] if arg.startswith("--root=")) for call in calls]
    assert roots[0] == roots[1]
    root = Path(roots[0].split("=", 1)[1])
    assert not root.is_relative_to(target) and not root.parent.parent.is_relative_to(target)
    assert not root.exists(), "The private startup directory is ephemeral"
    execution = json.loads(Path(record["execution"]["path"]).read_text())
    assert execution["requested"]["argv"] == requested == argv
    assert execution["requested"]["version_argv"] is None
    assert execution["effective"]["argv"] == record["argv"]
    assert execution["effective"]["version_argv"] == record["version"]["argv"]
    assert execution["effective"]["config_files"] == record["config_files"]
    assert record["execution"]["policy"] == "psalm-private-composer-root"
    assert f"--config={target / 'psalm.xml'}" in record["argv"]
    argv.append("--different-later")
    (target / "psalm.xml").write_text("<changed-later/>")
    assert check_run(record, target / "run.json") == []


def test_psalm_preserves_explicit_root_and_binds_relative_config_before_version(tmp_path):
    target, tools, marker, argv = startup_fixture(tmp_path)
    argv += ["--root", "../tools", "--config", "psalm.xml"]
    record = startup_run(target, argv, version_argv=[argv[0], "--version"])
    assert record["status"] == "analyzed", record["errors"]
    assert not marker.exists()
    assert f"--root={tools}" in record["argv"]
    assert f"--root={tools}" in record["version"]["argv"]
    assert f"--config={target / 'psalm.xml'}" in record["argv"]
    assert record["execution"]["policy"] == "caller-managed"
    assert check_run(record, target / "run.json") == []


def test_psalm_explicit_root_retains_native_configuration_discovery(tmp_path):
    target, tools, marker, argv = startup_fixture(tmp_path)
    config = tools / "psalm.xml"
    config.write_text(
        '<psalm xmlns="https://getpsalm.org/schema/config"><projectFiles>'
        f'<file name="{target / "source.php"}"/></projectFiles></psalm>'
    )
    record = startup_run(target, argv + [f"--root={tools}"])
    assert record["status"] == "analyzed", record["errors"]
    assert not marker.exists()
    assert record["config_files"][0]["original_path"] == str(config)
    assert check_run(record, target / "run.json") == []


@pytest.mark.parametrize("mode", ["false", "0"])
def test_psalm_explicit_root_preserves_root_relative_model_bindings(tmp_path, mode):
    target, tools, marker, argv = startup_fixture(tmp_path)
    root = tools / "environment"
    root.mkdir()
    (target / "psalm.xml").write_text(
        f'<psalm xmlns="https://getpsalm.org/schema/config" resolveFromConfigFile="{mode}">'
        '<projectFiles><file name="../../target/source.php"/></projectFiles></psalm>'
    )
    record = startup_run(
        target, argv + [f"--root={root}", "--config=psalm.xml"], models=[target / "source.php"]
    )
    assert record["status"] == "analyzed", record["errors"]
    assert not marker.exists()
    assert check_run(record, target / "run.json") == []


@pytest.mark.parametrize(
    "form", [["--root", "tool-root"], ["--root=tool-root"], ["-r", "tool-root"], ["-rtool-root"]]
)
def test_psalm_automatic_version_keeps_all_supported_root_option_forms(form):
    argv = ["php", "-d", "memory_limit=-1", "psalm.phar", *form, "--taint-analysis"]
    assert version_command("psalm", argv) == [
        "php",
        "-d",
        "memory_limit=-1",
        "psalm.phar",
        "--root=tool-root",
        "--version",
    ]


def test_psalm_mismatched_version_root_prevents_every_process(tmp_path):
    target, tools, marker, argv = startup_fixture(tmp_path)
    record = startup_run(
        target,
        argv + [f"--root={tools}"],
        version_argv=[argv[0], f"--root={target}", "--version"],
    )
    assert record["status"] == "failed" and record["returncode"] is None
    assert any("same startup --root" in item for item in record["errors"])
    assert not marker.exists() and not (tools / "psalm.jsonl").exists()


@pytest.mark.parametrize(
    "kind", ["activation", "xml", "root-relative", "root-relative-zero", "duplicate-root"]
)
def test_psalm_preflight_errors_prevent_even_version_startup(tmp_path, kind):
    target, tools, marker, argv = startup_fixture(tmp_path)
    if kind == "activation":
        argv.remove("--taint-analysis")
    elif kind == "xml":
        (target / "psalm.xml").write_text("<invalid")
    elif kind.startswith("root-relative"):
        config = target / "psalm.xml"
        mode = "0" if kind.endswith("zero") else "false"
        config.write_text(
            config.read_text().replace("<psalm ", f'<psalm resolveFromConfigFile="{mode}" ')
        )
    else:
        argv += [f"--root={tools}", f"--root={target}"]
    record = startup_run(target, argv)
    assert record["status"] == "failed" and record["returncode"] is None
    assert not marker.exists() and not (tools / "psalm.jsonl").exists()


def test_execution_identity_snapshot_rejects_saved_command_and_version_rebinding(tmp_path):
    target, _, _, argv = startup_fixture(tmp_path)
    record = startup_run(target, argv)
    record["version"]["argv"].append("--different-environment")
    errors = check_run(record, target / "run.json")
    assert any("immutable execution snapshot" in item for item in errors)
