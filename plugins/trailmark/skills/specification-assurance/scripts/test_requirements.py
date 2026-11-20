"""Accounting regressions using the structure emitted by Duvet's --json report."""

import copy
import hashlib
import importlib.util
import json
import subprocess
import sys
from pathlib import Path

import pytest

SCRIPT = Path(__file__).with_name("requirements.py")
spec = importlib.util.spec_from_file_location("assurance_requirements", SCRIPT)
requirements = importlib.util.module_from_spec(spec)
spec.loader.exec_module(requirements)


def write_json(path, value):
    path.write_text(json.dumps(value))
    return path


@pytest.fixture
def artifacts(tmp_path):
    # Includes an entirely unannotated requirement, as a real Duvet report does.
    report = {
        "specifications": {
            "spec.md": {
                "requirements": [0, 1],
                "sections": [
                    {
                        "lines": [
                            [[[0, 2], 240, "A packet MUST contain at most 16 bytes."]],
                            [[[1], 224, "A rejected packet MUST leave the counter unchanged."]],
                        ]
                    }
                ],
            }
        },
        "annotations": [
            {
                "type": "SPEC",
                "target_path": "spec.md",
                "target_section": "length",
                "level": "MUST",
                "comment": "A packet MUST contain at most 16 bytes.\n",
            },
            {
                "type": "SPEC",
                "target_path": "spec.md",
                "target_section": "rejection",
                "level": "MUST",
                "comment": "A rejected packet MUST leave the counter unchanged.\n",
            },
            {"source": "packet.py", "target_path": "spec.md", "line": 1},
        ],
        "statuses": {
            "0": {"spec": 39, "citation": 39, "related": [2]},
            "1": {"spec": 51, "incomplete": 51},
        },
    }
    before = write_json(tmp_path / "before.json", report)
    after = write_json(tmp_path / "after.json", report)
    inventory = requirements.inventory(before)
    (tmp_path / "packet.py").write_text("def accepted(packet):\n    return len(packet) <= 16\n")
    (tmp_path / "test_packet.py").write_text(
        "def test_size():\n    assert not accepted(b'x' * 17)\n"
    )
    (tmp_path / "native.log").write_text("test_size PASSED; 1 passed\n")
    check = {
        "kind": "test",
        "scope": "implementation",
        "property": "test_size rejects a 17-byte packet",
        "location": {"file": "test_packet.py", "line": 2},
        "command": "pytest -q test_packet.py",
        "result": "pass",
        "exit_code": 0,
        "log": "native.log",
    }
    ledger = {
        "requirements": [
            {
                "id": inventory[0]["id"],
                "verdict": "supported",
                "rationale": "The bound and the rejection assertion agree.",
                "implementation": [{"file": "packet.py", "line": 2, "role": "production"}],
                "checks": [check],
                "assumptions": [],
            },
            {
                "id": inventory[1]["id"],
                "verdict": "unknown",
                "rationale": "No stateful receiver was available to assess state preservation.",
                "implementation": [],
                "checks": [],
                "assumptions": [],
            },
        ],
        "limitations": [],
    }
    ledger_path = write_json(tmp_path / "ledger.json", ledger)
    return tmp_path, report, before, after, ledger, ledger_path


def gate(artifacts):
    root, _, before, after, ledger, ledger_path = artifacts
    write_json(ledger_path, ledger)
    return requirements.check_ledger(before, after, ledger_path, root)


def test_inventory_retains_uncited_obligations_with_stable_ids(artifacts):
    _, report, before, after, _, _ = artifacts
    first = requirements.inventory(before)
    assert len(first) == 2
    assert first[0]["id"] == "106a9a86e59d9600eb8f"
    assert first[1]["citation_characters"] == 0
    report["annotations"][0]["comment"] = "A packet MUST contain\n at most 16 bytes."
    report["specifications"]["spec.md"]["requirements"].reverse()
    write_json(after, report)
    assert {r["id"] for r in requirements.inventory(after)} == {r["id"] for r in first}


@pytest.mark.parametrize("value", [{}, {"version": "2", "annotations": {}, "sources": {}}])
def test_unrecognized_report_formats_are_not_empty_successes(tmp_path, value):
    with pytest.raises(ValueError, match="legacy JSON"):
        requirements.inventory(write_json(tmp_path / "report.json", value))


def test_zero_and_duplicate_requirements_fail(artifacts):
    _, report, _, after, _, _ = artifacts
    report["specifications"]["spec.md"]["requirements"] = []
    with pytest.raises(ValueError, match="zero requirements"):
        requirements.inventory(write_json(after, report))
    report["specifications"]["spec.md"]["requirements"] = [0, 0]
    with pytest.raises(ValueError, match="Duplicate requirement"):
        requirements.inventory(write_json(after, report))


def test_inventory_rejects_unreferenced_requirement_annotations(artifacts):
    _, report, _, after, _, _ = artifacts
    report["specifications"]["spec.md"]["requirements"] = [0]
    with pytest.raises(ValueError, match="omitted SPEC annotations"):
        requirements.inventory(write_json(after, report))


def test_mixed_empty_and_nonempty_specifications_cannot_pass_both_snapshots(artifacts):
    _, report, before, after, _, _ = artifacts
    report["specifications"]["empty.md"] = {"requirements": []}
    write_json(before, report)
    write_json(after, report)
    with pytest.raises(ValueError, match="zero requirements from empty.md"):
        gate(artifacts)


def test_requested_documents_must_be_present_even_when_other_documents_extract(artifacts):
    root, _, before, _, _, _ = artifacts
    assert len(requirements.inventory(before, ["./spec.md"], root)) == 2
    with pytest.raises(ValueError, match="absent from Duvet report.*missing.md"):
        requirements.inventory(before, ["spec.md", "missing.md"], root)


@pytest.mark.parametrize("count", ["39", -1, True, [], None])
def test_malformed_status_cannot_become_truthy_citation_evidence(artifacts, count):
    _, report, _, after, _, _ = artifacts
    report["statuses"]["0"]["citation"] = count
    with pytest.raises(ValueError, match="nonnegative integers"):
        requirements.inventory(write_json(after, report))


@pytest.mark.parametrize("related", ["2", [True], [-1], [100]])
def test_inventory_rejects_invalid_related_annotations(artifacts, related):
    _, report, _, after, _, _ = artifacts
    report["statuses"]["0"]["related"] = related
    with pytest.raises(ValueError, match="related Duvet annotation indices"):
        requirements.inventory(write_json(after, report))


def test_partial_assessment_has_valid_accounting_and_retains_gaps(artifacts):
    result = gate(artifacts)
    assert result == {
        "valid": True,
        "status": "gaps",
        "total": 2,
        "verdicts": {"supported": 1, "unknown": 1},
        "limitations": [],
        "errors": [],
    }


def test_supported_scope_can_have_an_explicit_inapplicable_requirement(artifacts):
    artifacts[4]["requirements"][1].update(
        verdict="not_applicable",
        rationale="This stateless profile has no counter; SPEC section 1 excludes it.",
    )
    assert gate(artifacts)["status"] == "supported"
    artifacts[4]["limitations"].append("An external implementation dependency was not inspected.")
    assert gate(artifacts)["status"] == "gaps"


@pytest.mark.parametrize("mutation", ["omitted", "duplicate", "invented", "all_inapplicable"])
def test_ledger_cannot_hide_the_denominator(artifacts, mutation):
    records = artifacts[4]["requirements"]
    if mutation == "omitted":
        records.pop()
    elif mutation == "duplicate":
        records.append(copy.deepcopy(records[0]))
    elif mutation == "invented":
        records[1]["id"] = "not-in-the-specification"
    else:
        for record in records:
            record["verdict"] = "not_applicable"
    assert not gate(artifacts)["valid"]


def test_final_report_cannot_drop_a_requirement(artifacts):
    _, report, _, after, ledger, _ = artifacts
    report["specifications"]["spec.md"]["requirements"] = [0]
    report["annotations"].pop(1)
    report["statuses"]["0"]["related"] = [1]
    report["specifications"]["spec.md"]["sections"] = [
        {"lines": [[[[0, 1], 240, report["annotations"][0]["comment"].strip()]]]}
    ]
    report["statuses"].pop("1")
    ledger["requirements"].pop()
    write_json(after, report)
    result = gate(artifacts)
    assert not result["valid"]
    assert any("inventory changed" in error for error in result["errors"])


@pytest.mark.parametrize(
    "mutation",
    [
        "no_checks",
        "failed_exit",
        "false_property",
        "empty_log",
        "missing_log",
        "missing_source",
        "bad_line",
        "outside_root",
        "no_citation",
    ],
)
def test_annotations_alone_cannot_support_a_requirement(artifacts, mutation):
    root, report, _, after, ledger, _ = artifacts
    record = ledger["requirements"][0]
    check = record["checks"][0]
    if mutation == "no_checks":
        record["checks"] = []
    elif mutation == "failed_exit":
        check["exit_code"] = 1
    elif mutation == "false_property":
        check["result"] = "fail"  # A native per-query failure can have process exit 0.
    elif mutation == "empty_log":
        (root / "native.log").write_text("")
    elif mutation == "missing_log":
        check["log"] = "does-not-exist.log"
    elif mutation == "missing_source":
        record["implementation"][0]["file"] = "does-not-exist.py"
    elif mutation == "bad_line":
        check["location"]["line"] = 100
    elif mutation == "outside_root":
        check["log"] = "../outside.log"
        (root.parent / "outside.log").write_text("unrelated evidence")
    else:
        report["statuses"]["0"].pop("citation")
        report["specifications"]["spec.md"]["sections"][0]["lines"][0][0][0] = [0]
        write_json(after, report)
    assert not gate(artifacts)["valid"]


@pytest.mark.parametrize(
    "coverage,valid",
    [
        ("partial", False),
        ("overlapping", False),
        ("complementary", True),
        ("full", True),
    ],
)
def test_complete_traceability_uses_union_of_spans_not_sum_of_counts(artifacts, coverage, valid):
    _, report, before, after, _, _ = artifacts
    first, second = "A packet MUST be bounded to sixteen bytes; ", "rejection MUST preserve état."
    report["annotations"][0]["comment"] = first + second
    report["annotations"].append({"type": "IMPLICATION", "target_path": "spec.md"})
    left = [0, 2, 3] if coverage == "overlapping" else [0, 2]
    right = [0, 3] if coverage == "complementary" else [0, 2] if coverage == "full" else [0]
    report["specifications"]["spec.md"]["sections"][0]["lines"][0] = [
        [left, 240, first],
        [right, 224, second],
    ]
    report["statuses"]["0"] = {
        "spec": len((first + second).encode()),
        "citation": len(first.encode()) + (len(second.encode()) if coverage == "full" else 0),
        "implication": len(first.encode())
        if coverage == "overlapping"
        else len(second.encode())
        if coverage == "complementary"
        else 0,
    }
    if coverage == "overlapping":
        status = report["statuses"]["0"]
        assert status["citation"] + status["implication"] >= status["spec"]
    write_json(before, report)
    write_json(after, report)
    artifacts[4]["requirements"][0]["id"] = requirements.inventory(before)[0]["id"]
    assert gate(artifacts)["valid"] is valid


@pytest.mark.parametrize("kind", ["TEST", "EXCEPTION", "TODO"])
def test_nonimplementation_annotations_cannot_cover_a_supported_requirement(artifacts, kind):
    _, report, _, after, _, _ = artifacts
    report["annotations"][2]["type"] = kind
    write_json(after, report)
    assert not gate(artifacts)["valid"]


@pytest.mark.parametrize("verdict", ["partial", "violated", "missing"])
@pytest.mark.parametrize(
    "severity,consequence", [(None, None), ("high", ""), ("urgent", "State can diverge.")]
)
def test_divergences_require_severity_and_consequence(artifacts, verdict, severity, consequence):
    record = artifacts[4]["requirements"][0]
    record.update(verdict=verdict, severity=severity, consequence=consequence)
    assert not gate(artifacts)["valid"]


@pytest.mark.parametrize("severity", sorted(requirements.SEVERITIES))
def test_every_severity_is_retained(artifacts, severity):
    record = artifacts[4]["requirements"][0]
    record.update(
        verdict="violated",
        severity=severity,
        consequence="Oversized packets can change receiver state.",
    )
    assert gate(artifacts)["status"] == "gaps"


def test_model_proof_requires_an_implementation_binding(artifacts):
    check = artifacts[4]["requirements"][0]["checks"][0]
    check["kind"] = "formal"
    assert not gate(artifacts)["valid"]
    check["scope"] = "model"
    assert not gate(artifacts)["valid"]
    check.update(
        scope="implementation",
        binding="The verified accepted definition is the production definition.",
    )
    assert gate(artifacts)["valid"]


def test_model_only_enforcement_is_not_production(artifacts):
    artifacts[4]["requirements"][0]["implementation"][0]["role"] = "model"
    assert not gate(artifacts)["valid"]


def test_cli_preserves_gap_and_invalid_results(artifacts):
    root, _, before, after, _, ledger_path = artifacts
    output = root / "gate.json"
    argv = [
        sys.executable,
        str(SCRIPT),
        "check",
        "--specification=spec.md",
        "--baseline",
        str(before),
        "--report",
        str(after),
        "--ledger",
        str(ledger_path),
        "--root",
        str(root),
        "--output",
        str(output),
    ]
    completed = subprocess.run(argv, capture_output=True, text=True, check=False)
    assert completed.returncode == 1
    assert json.loads(output.read_text())["status"] == "gaps"
    ledger_path.unlink()
    completed = subprocess.run(argv, capture_output=True, text=True, check=False)
    assert completed.returncode == 2
    assert json.loads(output.read_text())["status"] == "invalid"


@pytest.fixture
def finalizer(artifacts):
    root, _, before, after, ledger, _ = artifacts
    run = root / "run with 'quotes'"
    run.mkdir()
    (run / "requirements").mkdir()
    (run / "report.md").write_text("Assessment: one supported obligation, one unknown.\n")
    (run / "duvet-before.json").write_bytes(before.read_bytes())
    write_json(run / "inventory.json", {"requirements": requirements.inventory(before)})
    policy = {
        "schema_version": 1,
        "roots": [{"path": str(root), "name": "root", "category": "authored"}],
        "files": [
            {"path": str(root / name), "status": "inspected", "unit": "file", "root": "root"}
            for name in ("packet.py", "test_packet.py")
        ],
    }
    graph = {
        "schema_version": 1,
        "trailmark_version": "0.8.0",
        "root_path": str(root),
        "summary": {"source_files": 2, "parse_diagnostics": []},
        "source_policy": policy,
        "nodes": {
            name: {"kind": "module", "location": {"file_path": str(root / name), "start_line": 1}}
            for name in ("packet.py", "test_packet.py")
        },
        "edges": [],
    }
    write_json(run / "graph.json", graph)
    write_json(run / "source-policy.json", policy)
    write_json(run / "diagnostics.json", [])
    write_json(run / "graph-scope.json", {"production_files": ["packet.py"]})
    write_json(run / "ledger.json", ledger)
    for record in ledger["requirements"]:
        write_json(run / "requirements" / f"{record['id']}.json", record)
    # A deterministic native-tool fixture lets these tests observe real process
    # exits, missing writes, and stale artifacts without downloading Duvet in CI.
    duvet = root / "duvet fixture"
    duvet.write_text(
        f"#!{sys.executable}\n"
        "import pathlib, sys\n"
        f"source = pathlib.Path({str(after)!r})\n"
        "args = sys.argv\n"
        "pathlib.Path(args[args.index('--json')+1]).write_bytes(source.read_bytes())\n"
        "pathlib.Path(args[args.index('--html')+1]).write_text('<html>Native fixture</html>')\n"
        "print('native fixture report generated')\n"
    )
    duvet.chmod(0o755)
    argv = [
        sys.executable,
        str(SCRIPT),
        "finalize",
        "--root",
        str(root),
        "--run",
        str(run),
        "--duvet",
        str(duvet),
        "--specification=spec.md",
        "--production-source-files=1",
        "--output",
        str(run / "gate.json"),
    ]
    argv.extend(f"--requirement={record['id']}" for record in ledger["requirements"])
    argv.extend(assessment_flag(run, record) for record in ledger["requirements"])
    return root, run, duvet, argv, ledger


def assessment_flag(run, record):
    path = run / "requirements" / f"{record['id']}.json"
    return f"--assessment-sha256={record['id']}:{hashlib.sha256(path.read_bytes()).hexdigest()}"


def save_fixture_assessment(finalizer, record):
    """Set an assessment and its coordinator binding before exercising reporting."""
    _, run, _, argv, _ = finalizer
    write_json(run / "requirements" / f"{record['id']}.json", record)
    prefix = f"--assessment-sha256={record['id']}:"
    argv[:] = [value for value in argv if not value.startswith(prefix)]
    argv.append(assessment_flag(run, record))


def run_finalizer(finalizer, extra=()):
    _, run, _, argv, _ = finalizer
    completed = subprocess.run([*argv, *extra], capture_output=True, text=True, check=False)
    result = json.loads((run / "gate.json").read_text())
    assert json.loads(completed.stdout) == result
    return completed.returncode, result


def test_finalizer_executes_native_process_and_checks_actual_files(finalizer):
    _, run, _, _, _ = finalizer
    code, result = run_finalizer(finalizer)
    assert code == 1 and result["valid"] and result["status"] == "gaps"
    assert result["duvet_exit_code"] == 0
    assert Path(result["duvet_report"]).is_file()
    assert Path(result["duvet_html"]).read_text() == "<html>Native fixture</html>"
    assert Path(result["duvet_log"]).read_text() == "native fixture report generated\n"
    assert len(list(run.glob("gate-native-*/execution.json"))) == 1
    assert result["graph_source_files"] == 2
    assert result["production_source_files"] == 1


def test_finalizer_can_issue_supported_only_after_native_artifacts_pass(finalizer):
    _, run, _, _, ledger = finalizer
    ledger["requirements"][1].update(
        verdict="not_applicable", rationale="The selected profile has no mutable counter."
    )
    record = ledger["requirements"][1]
    save_fixture_assessment(finalizer, record)
    write_json(run / "ledger.json", ledger)
    code, result = run_finalizer(finalizer)
    assert code == 0 and result["status"] == "supported" and result["valid"]


@pytest.mark.parametrize(
    "artifact",
    [
        "report.md",
        "ledger.json",
        "inventory.json",
        "duvet-before.json",
        "worker",
        "graph.json",
        "source-policy.json",
        "diagnostics.json",
        "graph-scope.json",
    ],
)
def test_finalizer_rejects_missing_artifacts_despite_a_plausible_old_gate(finalizer, artifact):
    _, run, _, _, ledger = finalizer
    write_json(run / "gate.json", {"valid": True, "status": "supported", "total": 2})
    path = (
        run / "requirements" / f"{ledger['requirements'][0]['id']}.json"
        if artifact == "worker"
        else run / artifact
    )
    path.unlink()
    code, result = run_finalizer(finalizer)
    assert code == 2 and result["status"] == "invalid"


@pytest.mark.parametrize("exit_code", [0, 1])
def test_finalizer_cannot_reuse_stale_duvet_output_after_failure_or_noop(finalizer, exit_code):
    _, run, duvet, _, _ = finalizer
    write_json(run / "duvet-after.json", {"old": "report"})
    duvet.write_text(f"#!{sys.executable}\nraise SystemExit({exit_code})\n")
    code, result = run_finalizer(finalizer)
    assert code == 2 and result["status"] == "invalid"
    assert len(list(run.glob("gate-native-*/execution.json"))) == 1


@pytest.mark.parametrize("correct_id", [False, True])
def test_failed_worker_must_be_not_checked_under_its_own_id(finalizer, correct_id):
    _, run, _, argv, ledger = finalizer
    records = ledger["requirements"]
    failed = records[0]["id"]
    # The failed worker wrote nothing. A different not_checked record cannot
    # compensate for falsely calling the failed requirement supported.
    (run / "requirements" / f"{failed}.json").unlink()
    argv[:] = [value for value in argv if not value.startswith(f"--assessment-sha256={failed}:")]
    records[0 if correct_id else 1]["verdict"] = "not_checked"
    write_json(run / "ledger.json", ledger)
    code, result = run_finalizer(finalizer, [f"--failed-requirement={failed}"])
    assert code == (1 if correct_id else 2)
    if not correct_id:
        assert any(f"Failed worker {failed}" in error for error in result["errors"])


def test_finalizer_preserves_exact_ids_requested_documents_and_setup_limitations(finalizer):
    for flags, expected in [
        (["--requirement=invented"], "Workflow requirement IDs"),
        (["--specification=missing.md"], "Requested specifications absent"),
        (["--limitation=Unsupported formal source"], "Setup limitations were lost"),
    ]:
        code, result = run_finalizer(finalizer, flags)
        assert code == 2
        assert any(expected in error for error in result["errors"])


@pytest.mark.parametrize(
    "mutation", ["verdict", "failed_check", "assumptions", "severity", "consequence", "rationale"]
)
def test_report_cannot_rewrite_a_retained_failed_assessment(finalizer, mutation):
    root, run, _, _, ledger = finalizer
    record = ledger["requirements"][0]
    record.update(verdict="violated", severity="high", consequence="Oversized input mutates state.")
    record["checks"][0].update(result="fail", exit_code=1, log="failed.log")
    (root / "failed.log").write_text("state preservation assertion FAILED\n")
    save_fixture_assessment(finalizer, record)
    other = ledger["requirements"][1]
    other.update(
        verdict="not_applicable",
        rationale="The selected profile has no separate counter obligation.",
    )
    save_fixture_assessment(finalizer, other)
    if mutation == "verdict":
        record["verdict"] = "supported"
        record["checks"][0].update(result="pass", exit_code=0, log="native.log")
    elif mutation == "failed_check":
        record["checks"].pop()
    elif mutation == "assumptions":
        record["assumptions"] = ["Assume all callers reject oversized input."]
    else:
        record[mutation] = {
            "severity": "info",
            "consequence": "None observed.",
            "rationale": "Tests passed.",
        }[mutation]
    write_json(run / "ledger.json", ledger)
    code, result = run_finalizer(finalizer)
    assert code == 2 and result["status"] == "invalid"
    assert any("Ledger changed retained worker assessment" in error for error in result["errors"])


def test_retained_native_failures_remain_a_valid_gap(finalizer):
    root, run, _, _, ledger = finalizer
    record = ledger["requirements"][0]
    record.update(verdict="violated", severity="high", consequence="Oversized input mutates state.")
    record["checks"][0].update(result="fail", exit_code=1, log="failed.log")
    (root / "failed.log").write_text("state preservation assertion FAILED\n")
    save_fixture_assessment(finalizer, record)
    write_json(run / "ledger.json", ledger)
    code, result = run_finalizer(finalizer)
    assert code == 1 and result["verdicts"]["violated"] == 1


def test_reporting_cannot_rewrite_both_worker_record_and_ledger(finalizer):
    _, run, _, _, ledger = finalizer
    record = ledger["requirements"][0]
    record.update(verdict="unknown", rationale="Rewritten after assessment.")
    write_json(run / "requirements" / f"{record['id']}.json", record)
    write_json(run / "ledger.json", ledger)
    code, result = run_finalizer(finalizer)
    assert code == 2
    assert any("Retained worker assessment changed" in error for error in result["errors"])


def test_completed_workers_need_exact_sha256_bindings(finalizer):
    _, _, _, argv, _ = finalizer
    argv[:] = [value for value in argv if not value.startswith("--assessment-sha256=")]
    code, result = run_finalizer(finalizer)
    assert code == 2
    assert any("cover exactly the completed workers" in error for error in result["errors"])


@pytest.mark.parametrize("original_line", [2, None, 1, True])
def test_only_explicit_line_relocations_can_differ_from_worker_records(finalizer, original_line):
    root, run, _, _, ledger = finalizer
    for name in ("packet.py", "test_packet.py"):
        path = root / name
        path.write_text("# annotation\n# quotation\n" + path.read_text())
    record = ledger["requirements"][0]
    for anchor in [record["implementation"][0], record["checks"][0]["location"]]:
        anchor["line"] = 4
        if original_line is not None:
            anchor["original_line"] = original_line
    write_json(run / "ledger.json", ledger)
    code, _ = run_finalizer(finalizer)
    assert code == (1 if type(original_line) is int and original_line == 2 else 2)


@pytest.mark.parametrize(
    "mutation",
    [
        "empty",
        "zero",
        "wrong_total",
        "no_inspection",
        "no_production_node",
        "proxy_only",
        "wrong_scope",
        "claimed_count",
        "policy_mismatch",
        "diagnostics_mismatch",
    ],
)
def test_native_graph_evidence_cannot_be_replaced_by_setup_claims(finalizer, mutation):
    _, run, _, argv, _ = finalizer
    graph = requirements.read_json(run / "graph.json")
    if mutation == "empty":
        graph = {}
    elif mutation in {"zero", "wrong_total"}:
        graph["summary"]["source_files"] = 0 if mutation == "zero" else 3
    elif mutation == "no_inspection":
        graph["source_policy"]["files"] = []
        write_json(run / "source-policy.json", graph["source_policy"])
    elif mutation == "no_production_node":
        graph["nodes"].pop("packet.py")
    elif mutation == "proxy_only":
        graph["nodes"]["packet.py"]["origin"] = "proxy"
    elif mutation == "wrong_scope":
        write_json(run / "graph-scope.json", {"production_files": ["native.log"]})
    elif mutation == "claimed_count":
        argv[argv.index("--production-source-files=1")] = "--production-source-files=2"
    elif mutation == "policy_mismatch":
        write_json(run / "source-policy.json", {"files": []})
    else:
        write_json(run / "diagnostics.json", [{"message": "parse failed"}])
    write_json(run / "graph.json", graph)
    code, result = run_finalizer(finalizer)
    assert code == 2 and result["status"] == "invalid"


def test_graph_evidence_accepts_native_merged_source_policy(finalizer):
    _, run, _, _, _ = finalizer
    graph = requirements.read_json(run / "graph.json")
    files = graph["source_policy"]["files"]
    graph["source_policy"] = {
        "schema_version": 1,
        "components": [{"files": [item]} for item in files],
    }
    write_json(run / "graph.json", graph)
    write_json(run / "source-policy.json", graph["source_policy"])
    assert run_finalizer(finalizer)[0] == 1


def test_supported_enforcement_must_belong_to_the_inspected_production_graph(finalizer):
    _, run, _, _, ledger = finalizer
    record = ledger["requirements"][0]
    record["implementation"][0]["file"] = "test_packet.py"
    save_fixture_assessment(finalizer, record)
    write_json(run / "ledger.json", ledger)
    code, result = run_finalizer(finalizer)
    assert code == 2
    assert any(
        "outside the inspected production graph scope" in error for error in result["errors"]
    )


def test_inventory_and_check_resolve_specifications_against_target_root(artifacts):
    root, report, before, after, ledger, ledger_path = artifacts
    target = str(root / "spec.md")
    report["specifications"][target] = report["specifications"].pop("spec.md")
    for annotation in report["annotations"]:
        annotation["target_path"] = target
    write_json(before, report)
    write_json(after, report)
    for record, item in zip(ledger["requirements"], requirements.inventory(before), strict=True):
        record["id"] = item["id"]
    write_json(ledger_path, ledger)
    for command, flags, expected in [
        ("inventory", ["--report", str(before)], 0),
        (
            "check",
            ["--baseline", str(before), "--report", str(after), "--ledger", str(ledger_path)],
            1,
        ),
    ]:
        output = root / f"{command}-root.json"
        completed = subprocess.run(
            [
                sys.executable,
                str(SCRIPT),
                command,
                "--root",
                str(root),
                "--specification=spec.md",
                "--output",
                str(output),
                *flags,
            ],
            cwd=root.parent,
            capture_output=True,
            text=True,
            check=False,
        )
        assert completed.returncode == expected, completed.stdout + completed.stderr
