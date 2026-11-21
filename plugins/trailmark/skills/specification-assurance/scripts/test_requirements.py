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


def bind_record(root, record):
    record["files"] = {
        name: requirements.file_state(root / name) for name in requirements.evidence_files(record)
    }


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
    (tmp_path / "spec.md").write_text("A packet MUST contain at most 16 bytes.\n")
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
    for record in ledger["requirements"]:
        bind_record(tmp_path, record)
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


def test_remote_specifications_require_a_local_snapshot(artifacts):
    root, report, before, after, _, _ = artifacts
    with pytest.raises(ValueError, match="Pin remote specifications"):
        requirements.inventory(before, ["https://example.com/spec.md"], root)
    report["specifications"]["https://example.com/spec.md"] = report["specifications"].pop(
        "spec.md"
    )
    with pytest.raises(ValueError, match="Pin remote specifications"):
        requirements.inventory(write_json(after, report))


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


def test_cli_preserves_gap_and_invalid_results(finalizer):
    _, run, _, _, _ = finalizer
    code, result = run_finalizer(finalizer)
    assert code == 1 and result["status"] == "gaps"
    (run / "ledger.json").unlink()
    code, result = run_finalizer(finalizer)
    assert code == 2 and result["status"] == "invalid"


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
    (root / ".duvet").mkdir()
    (root / ".duvet/config.toml").write_text(
        "'$schema' = \"https://awslabs.github.io/duvet/config/v0.4.0.json\"\n"
        '[[specification]]\nsource = "spec.md"\n'
        '[report.snapshot]\nenabled = true\npath = ".duvet/snapshot.txt"\n'
    )
    (root / ".duvet/snapshot.txt").write_text("accepted snapshot\n")
    write_json(run / "ledger.json", ledger)
    for record in ledger["requirements"]:
        write_json(run / "requirements" / f"{record['id']}.json", record)
    # A deterministic native-tool fixture lets these tests observe real process
    # exits, missing writes, and stale artifacts without downloading Duvet in CI.
    after = after.rename(run / "final-source.json")
    duvet = root.parent / f"duvet fixture-{root.name}"
    duvet.write_text(
        f"#!{sys.executable}\n"
        "import pathlib, sys, tomllib\n"
        f"source = pathlib.Path({str(after)!r})\n"
        "args = sys.argv\n"
        "pathlib.Path(args[args.index('--json')+1]).write_bytes(source.read_bytes())\n"
        "pathlib.Path(args[args.index('--html')+1]).write_text('<html>Native fixture</html>')\n"
        "config = tomllib.loads(pathlib.Path(args[args.index('--config-path')+1]).read_text())\n"
        "pathlib.Path(config['report']['snapshot']['path']).write_text('candidate snapshot\\n')\n"
        "print('native fixture report generated')\n"
    )
    duvet.chmod(0o755)
    argv = [
        sys.executable,
        str(SCRIPT),
        "finalize",
        "--request",
        str(run / "validation-request.json"),
        "--duvet",
        str(duvet),
        "--output",
        str(run / "gate.json"),
    ]
    write_json(
        run / "validation-request.json",
        {
            "schema_version": 1,
            "root": str(root),
            "run": str(run),
            "specifications": ["spec.md"],
            "production_source_files": 1,
            "requirements": [record["id"] for record in ledger["requirements"]],
            "failed_requirements": [],
            "limitations": [],
            "assessments": {},
        },
    )
    fixture = root, run, duvet, argv, ledger
    requirements.begin_snapshot(root, run)
    requirements.freeze_snapshot(root, run)
    for record in ledger["requirements"]:
        save_fixture_assessment(fixture, record)
    write_json(run / "ledger.json", ledger)
    return fixture


def save_fixture_assessment(finalizer, record):
    """Set an assessment and its coordinator binding before exercising reporting."""
    root, run, _, _, _ = finalizer
    path = write_json(run / "requirements" / f"{record['id']}.json", record)
    sealed = requirements.seal_record(root, run, path)
    record.update(requirements.read_json(path))
    request = requirements.read_json(run / "validation-request.json")
    request["assessments"][record["id"]] = sealed["record_sha256"]
    write_json(run / "validation-request.json", request)


def run_finalizer(finalizer, extra=()):
    _, run, _, argv, _ = finalizer
    completed = subprocess.run([*argv, *extra], capture_output=True, text=True, check=False)
    result = json.loads((run / "gate.json").read_text())
    assert json.loads(completed.stdout) == result
    return completed.returncode, result


def refresh_fixture_snapshot(finalizer):
    root, run, _, _, ledger = finalizer
    (run / "source-snapshot.json").unlink()
    (run / "source-inputs.json").unlink()
    requirements.begin_snapshot(root, run)
    requirements.freeze_snapshot(root, run)
    for record in ledger["requirements"]:
        save_fixture_assessment(finalizer, record)
    write_json(run / "ledger.json", ledger)


@pytest.mark.parametrize("name", ["alternate.py", "ignored/alternate.py", "build.toml"])
def test_added_production_or_build_inputs_invalidate_sealed_scope(finalizer, name):
    root, run, _, _, _ = finalizer
    (root / ".gitignore").write_text("ignored/\n")
    refresh_fixture_snapshot(finalizer)
    path = root / name
    path.parent.mkdir(exist_ok=True)
    path.write_text("# new alternate entry point or build input\n")
    code, result = run_finalizer(finalizer)
    assert code == 2
    assert any("Target snapshot changed" in error for error in result["errors"])
    assert not list(run.glob("gate-native-*"))


def test_workers_share_one_snapshot_without_duplicating_project_hashes(finalizer):
    root, run, _, _, ledger = finalizer
    snapshot = requirements.read_json(run / "source-snapshot.json")
    assert ".duvet/config.toml" in snapshot
    digests = {record["snapshot_sha256"] for record in ledger["requirements"]}
    assert len(digests) == 1
    assert all(".duvet/config.toml" not in record["files"] for record in ledger["requirements"])
    with pytest.raises(FileExistsError):
        requirements.freeze_snapshot(root, run)


def test_pinned_specifications_inside_run_still_bind_full_text(finalizer):
    root, run, _, _, _ = finalizer
    pinned = run / "pinned-spec.md"
    pinned.write_text(
        "Definition: packets include the header.\nA packet MUST contain at most 16 bytes.\n"
    )
    config = root / ".duvet/config.toml"
    config.write_text(
        config.read_text()
        + "\n[[specification]]\nsource = "
        + json.dumps(str(pinned.relative_to(root)))
        + "\n"
    )
    frozen = requirements.snapshot_files(root, run)
    assert str(pinned.relative_to(root)) in frozen
    pinned.write_text(pinned.read_text().replace("include", "exclude"))
    assert requirements.snapshot_files(root, run) != frozen


@pytest.mark.parametrize("change", ["add_entrypoint", "edit_source", "chmod"])
def test_freeze_rejects_changes_between_begin_and_native_analysis(finalizer, change):
    root, run, _, _, _ = finalizer
    (run / "source-inputs.json").unlink()
    (run / "source-snapshot.json").unlink()
    requirements.begin_snapshot(root, run)
    if change == "add_entrypoint":
        (root / "alternate.py").write_text("def alternate(packet): return True\n")
    elif change == "edit_source":
        (root / "packet.py").write_text("def accepted(packet): return True\n")
    else:
        path = root / "packet.py"
        path.chmod(path.stat().st_mode ^ 0o100)
    # The retained graph still describes the earlier inputs.
    with pytest.raises(ValueError, match="Inputs changed during baseline/graph analysis"):
        requirements.freeze_snapshot(root, run)
    assert not (run / "source-snapshot.json").exists()


def test_freeze_requires_the_preanalysis_capture(finalizer):
    _, run, _, _, _ = finalizer
    (run / "source-inputs.json").unlink()
    with pytest.raises(FileNotFoundError):
        requirements.freeze_snapshot(finalizer[0], run)


def test_changed_executable_permissions_invalidate_the_gate(finalizer):
    root, run, _, _, _ = finalizer
    path = root / "packet.py"
    path.chmod(path.stat().st_mode ^ 0o100)
    code, result = run_finalizer(finalizer)
    assert code == 2
    assert any("changed since assessment" in error for error in result["errors"])
    assert not list(run.glob("gate-native-*"))


@pytest.mark.parametrize("relative", [False, True])
def test_retargeting_identical_launcher_symlinks_invalidates_the_gate(finalizer, relative):
    root, run, _, _, ledger = finalizer
    for name in ("first", "second"):
        directory = root / name
        directory.mkdir()
        (directory / "launcher.py").write_text(
            "from pathlib import Path\n"
            "print(Path(__file__).resolve().with_name('config').read_text())\n"
        )
        (directory / "config").write_text(name)
    link = root / "launcher.py"
    link.symlink_to(Path("first/launcher.py") if relative else root / "first/launcher.py")
    ledger["requirements"][1]["verdict"] = "not_applicable"
    refresh_fixture_snapshot(finalizer)
    assert run_finalizer(finalizer)[0] == 0
    assert subprocess.check_output([sys.executable, str(link)], text=True).strip() == "first"
    before = requirements.file_state(link)
    link.unlink()
    link.symlink_to(Path("second/launcher.py") if relative else root / "second/launcher.py")
    after = requirements.file_state(link)
    assert before["sha256"] == after["sha256"] and before["mode"] == after["mode"]
    assert subprocess.check_output([sys.executable, str(link)], text=True).strip() == "second"
    code, result = run_finalizer(finalizer)
    assert code == 2
    assert any("Target snapshot changed" in error for error in result["errors"])
    assert len(list(run.glob("gate-native-*"))) == 1


@pytest.mark.parametrize("directory_alias", [False, True])
def test_run_evidence_preserves_distinct_symlink_bindings(finalizer, directory_alias):
    root, run, _, _, ledger = finalizer
    alternate = root / "other"
    alternate.mkdir()
    (alternate / "test_packet.py").write_bytes((root / "test_packet.py").read_bytes())
    first, second = run / "first.py", run / "second.py"
    first.symlink_to(root / "test_packet.py")
    if directory_alias:
        alias = run / "alias"
        alias.symlink_to(root, target_is_directory=True)
        second = alias / "test_packet.py"
    else:
        second.symlink_to(Path("..") / "test_packet.py")
    check = ledger["requirements"][0]["checks"][0]
    check["location"]["file"] = str(first.relative_to(root))
    other = copy.deepcopy(check)
    other["location"]["file"] = str(second.relative_to(root))
    ledger["requirements"][0]["checks"].append(other)
    refresh_fixture_snapshot(finalizer)
    assert run_finalizer(finalizer)[0] == 1
    if directory_alias:
        alias.unlink()
        alias.symlink_to(alternate, target_is_directory=True)
    else:
        second.unlink()
        second.symlink_to(alternate / "test_packet.py")
    code, result = run_finalizer(finalizer)
    assert code == 2
    assert any("Evidence file changed" in error for error in result["errors"])


def test_absolute_specification_aliases_still_resolve_inside_the_target(finalizer):
    root, _, _, _, _ = finalizer
    alias = root.parent / f"{root.name}-alias"
    alias.symlink_to(root, target_is_directory=True)
    config = root / ".duvet/config.toml"
    config.write_text(
        config.read_text().replace(
            'source = "spec.md"', f"source = {json.dumps(str(alias / 'spec.md'))}"
        )
    )
    refresh_fixture_snapshot(finalizer)
    code, result = run_finalizer(finalizer)
    assert code == 1 and result["valid"]


@pytest.mark.parametrize("name", [".", ".duvet", "deploy"])
def test_directory_traversal_permission_changes_invalidate_the_gate(finalizer, name):
    root, run, _, _, ledger = finalizer
    directory = root / name
    directory.mkdir(exist_ok=True)
    directory.chmod(0o755)
    ledger["requirements"][1]["verdict"] = "not_applicable"
    refresh_fixture_snapshot(finalizer)
    assert run_finalizer(finalizer)[0] == 0
    directory.chmod(0o754)  # The assessor retains access; another account loses traversal.
    code, result = run_finalizer(finalizer)
    assert code == 2
    assert any("Target snapshot changed" in error for error in result["errors"])
    assert len(list(run.glob("gate-native-*"))) == 1


@pytest.mark.parametrize("name", [".", "packet.py"])
@pytest.mark.parametrize("field", ["uid", "gid"])
def test_ownership_changes_invalidate_the_gate(finalizer, monkeypatch, name, field):
    root, run, _, argv, ledger = finalizer
    ledger["requirements"][1]["verdict"] = "not_applicable"
    refresh_fixture_snapshot(finalizer)
    assert run_finalizer(finalizer)[0] == 0
    original_stat = Path.stat

    def changed_owner(path, *, follow_symlinks=True):
        state = original_stat(path, follow_symlinks=follow_symlinks)
        if path == root / name:
            values = list(state)
            values[4 if field == "uid" else 5] += 1
            return requirements.os.stat_result(values)
        return state

    # Simulate chown without requiring a privileged test runner.
    monkeypatch.setattr(Path, "stat", changed_owner)
    monkeypatch.setattr(sys, "argv", argv[1:])
    assert requirements.main() == 2
    result = json.loads((run / "gate.json").read_text())
    assert not result["valid"]
    assert any("changed" in error for error in result["errors"])
    assert len(list(run.glob("gate-native-*"))) == 1


@pytest.mark.parametrize("during_duvet", [False, True])
def test_symlink_loops_replace_a_previous_successful_gate(finalizer, during_duvet):
    root, run, duvet, _, ledger = finalizer
    link = root / "launcher.py"
    link.symlink_to("packet.py")
    ledger["requirements"][1]["verdict"] = "not_applicable"
    refresh_fixture_snapshot(finalizer)
    assert run_finalizer(finalizer)[0] == 0
    if during_duvet:
        duvet.write_text(
            duvet.read_text()
            + f"link = pathlib.Path({str(link)!r})\nlink.unlink()\nlink.symlink_to(link.name)\n"
        )
    else:
        link.unlink()
        link.symlink_to(link.name)
    code, result = run_finalizer(finalizer)
    assert code == 2 and not result["valid"]
    assert any("launcher.py" in error for error in result["errors"])
    assert len(list(run.glob("gate-native-*"))) == (2 if during_duvet else 1)
    if during_duvet:
        assert result["duvet_exit_code"] == 0


def test_sealing_does_not_read_the_whole_shared_manifest(finalizer, monkeypatch):
    root, run, _, _, ledger = finalizer
    read_json = requirements.read_json

    def reject_manifest(path):
        assert path != run / "source-snapshot.json"
        return read_json(path)

    monkeypatch.setattr(requirements, "read_json", reject_manifest)
    path = run / "requirements" / f"{ledger['requirements'][0]['id']}.json"
    sealed = requirements.seal_record(root, run, path)
    assert sealed["record_sha256"] == requirements.file_sha256(path)


def test_added_directory_symlink_cannot_bypass_file_list_seal(finalizer):
    root, run, _, _, _ = finalizer
    (root / "alternate").symlink_to(root, target_is_directory=True)
    code, result = run_finalizer(finalizer)
    assert code == 2
    assert any("Directory symlinks cannot be frozen" in error for error in result["errors"])
    assert not list(run.glob("gate-native-*"))


def test_source_walk_errors_cannot_silently_omit_a_subtree(finalizer, monkeypatch):
    def failed_walk(root, *, followlinks, onerror):
        onerror(PermissionError("unreadable production directory"))
        return []

    monkeypatch.setattr(requirements.os, "walk", failed_walk)
    with pytest.raises(PermissionError, match="unreadable production"):
        requirements.snapshot_files(finalizer[0], finalizer[1])


@pytest.mark.parametrize("exit_code", [0, 7])
def test_baseline_never_changes_accepted_snapshot_even_on_failure(finalizer, exit_code):
    root, run, duvet, _, _ = finalizer
    duvet.write_text(duvet.read_text() + f"raise SystemExit({exit_code})\n")
    output = run / "baseline.json"
    completed = subprocess.run(
        [
            sys.executable,
            str(SCRIPT),
            "baseline",
            "--root",
            str(root),
            "--run",
            str(run),
            "--duvet",
            str(duvet),
            "--output",
            str(output),
        ],
        capture_output=True,
        text=True,
        check=False,
    )
    result = requirements.read_json(output)
    assert completed.returncode == (0 if exit_code == 0 else 2)
    assert result["duvet_exit_code"] == exit_code
    assert Path(result["duvet_snapshot"]).is_relative_to(run)
    assert (root / ".duvet/snapshot.txt").read_text() == "accepted snapshot\n"


@pytest.mark.parametrize("launch_failure", [False, True])
def test_native_failures_retain_exit_status_and_artifact_paths(finalizer, launch_failure):
    _, run, duvet, argv, _ = finalizer
    if launch_failure:
        argv[argv.index("--duvet") + 1] = str(duvet) + "-absent"
    else:
        duvet.write_text(duvet.read_text() + "raise SystemExit(7)\n")
    code, result = run_finalizer(finalizer)
    assert code == 2
    assert result["duvet_exit_code"] == (None if launch_failure else 7)
    execution = requirements.read_json(Path(result["duvet_execution"]))
    assert execution["exit_code"] == result["duvet_exit_code"]
    assert execution["error"]
    assert Path(result["duvet_log"]).stat().st_size
    for field in ("duvet_report", "duvet_html", "duvet_snapshot"):
        assert Path(result[field]).is_relative_to(run)
        assert Path(result[field]).is_file() == (not launch_failure)


@pytest.mark.parametrize("no_nodes", [False, True])
def test_diagnosed_production_parse_failures_remain_completed_gaps(finalizer, no_nodes):
    root, run, _, _, _ = finalizer
    graph = requirements.read_json(run / "graph.json")
    diagnostics = [
        {
            "location": {"file_path": str(root / "packet.py")},
            "kind": "parse_error",
            "message": "unsupported production syntax",
        }
    ]
    graph["nodes"] = {} if no_nodes else {"tests": graph["nodes"]["test_packet.py"]}
    graph["summary"]["parse_diagnostics"] = diagnostics
    write_json(run / "graph.json", graph)
    write_json(run / "diagnostics.json", diagnostics)
    refresh_fixture_snapshot(finalizer)
    code, result = run_finalizer(finalizer)
    assert code == 1 and result["valid"] and result["status"] == "gaps"
    assert any("parse diagnostics" in item for item in result["limitations"])


def test_finalizer_executes_native_process_and_checks_actual_files(finalizer):
    root, run, _, _, _ = finalizer
    code, result = run_finalizer(finalizer)
    assert code == 1 and result["valid"] and result["status"] == "gaps"
    assert result["duvet_exit_code"] == 0
    assert Path(result["duvet_report"]).is_file()
    assert Path(result["duvet_html"]).read_text() == "<html>Native fixture</html>"
    assert Path(result["duvet_log"]).read_text() == "native fixture report generated\n"
    assert len(list(run.glob("gate-native-*/execution.json"))) == 1
    assert result["graph_source_files"] == 2
    assert result["production_source_files"] == 1
    assert Path(result["duvet_snapshot"]).read_text() == "candidate snapshot\n"
    assert (root / ".duvet/snapshot.txt").read_text() == "accepted snapshot\n"


@pytest.mark.parametrize("name", ["native.log", "packet.py", "test_packet.py", "spec.md"])
def test_changed_evidence_is_rejected_before_native_reporting(finalizer, name):
    root, run, _, _, _ = finalizer
    path = root / name
    path.write_text(path.read_text().replace("<= 16", "<= 160") + "\nFAILED\n")
    code, result = run_finalizer(finalizer)
    assert code == 2
    assert any("changed since assessment" in error for error in result["errors"])
    assert not list(run.glob("gate-native-*"))


def test_worker_cannot_omit_evidence_content_bindings(finalizer):
    _, run, _, _, ledger = finalizer
    record = ledger["requirements"][0]
    record["files"].pop("native.log")
    path = write_json(run / "requirements" / f"{record['id']}.json", record)
    request = requirements.read_json(run / "validation-request.json")
    request["assessments"][record["id"]] = hashlib.sha256(path.read_bytes()).hexdigest()
    write_json(run / "validation-request.json", request)
    write_json(run / "ledger.json", ledger)
    code, result = run_finalizer(finalizer)
    assert code == 2
    assert any("Missing SHA-256 bindings" in error for error in result["errors"])
    assert not list(run.glob("gate-native-*"))


@pytest.mark.parametrize("mutation", ["malformed_json", "rewritten_verdict"])
def test_invalid_ledger_cannot_run_duvet_or_write_a_snapshot(finalizer, mutation):
    root, run, _, _, ledger = finalizer
    if mutation == "malformed_json":
        (run / "ledger.json").write_text("{")
    else:
        ledger["requirements"][0]["verdict"] = "not_applicable"
        write_json(run / "ledger.json", ledger)
    code, result = run_finalizer(finalizer)
    assert code == 2 and not result["valid"]
    assert not list(run.glob("gate-native-*"))
    assert (root / ".duvet/snapshot.txt").read_text() == "accepted snapshot\n"


def test_final_traceability_rejection_keeps_candidate_snapshot_inside_run(finalizer):
    root, run, _, _, _ = finalizer
    report = requirements.read_json(run / "final-source.json")
    report["specifications"]["spec.md"]["sections"][0]["lines"][0][0][0] = [0]
    report["statuses"]["0"] = {"spec": 39, "incomplete": 39}
    write_json(run / "final-source.json", report)
    code, result = run_finalizer(finalizer)
    assert code == 2
    assert any("complete Duvet implementation traceability" in error for error in result["errors"])
    assert Path(result["duvet_snapshot"]).is_relative_to(run)
    assert Path(result["duvet_snapshot"]).read_text() == "candidate snapshot\n"
    assert (root / ".duvet/snapshot.txt").read_text() == "accepted snapshot\n"


def test_native_process_cannot_change_evidence_after_preflight(finalizer):
    root, _, duvet, _, _ = finalizer
    duvet.write_text(
        duvet.read_text() + f"pathlib.Path({str(root / 'native.log')!r}).write_text('FAILED\\n')\n"
    )
    code, result = run_finalizer(finalizer)
    assert code == 2
    assert any("changed since assessment" in error for error in result["errors"])


def test_retained_parse_diagnostics_force_a_gap(finalizer):
    _, run, _, _, ledger = finalizer
    graph = requirements.read_json(run / "graph.json")
    diagnostics = [{"kind": "parse_error", "message": "alternate production path did not parse"}]
    graph["summary"]["parse_diagnostics"] = diagnostics
    write_json(run / "graph.json", graph)
    write_json(run / "diagnostics.json", diagnostics)
    (run / "source-snapshot.json").unlink()
    (run / "source-inputs.json").unlink()
    requirements.begin_snapshot(finalizer[0], run)
    requirements.freeze_snapshot(finalizer[0], run)
    ledger["requirements"][1]["verdict"] = "not_applicable"
    for record in ledger["requirements"]:
        save_fixture_assessment(finalizer, record)
    write_json(run / "ledger.json", ledger)
    code, result = run_finalizer(finalizer)
    assert code == 1 and result["valid"] and result["status"] == "gaps"
    assert any("1 parse diagnostics" in item for item in result["limitations"])


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
        "source-snapshot.json",
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
    _, run, _, _, ledger = finalizer
    records = ledger["requirements"]
    failed = records[0]["id"]
    # The failed worker wrote nothing. A different not_checked record cannot
    # compensate for falsely calling the failed requirement supported.
    (run / "requirements" / f"{failed}.json").unlink()
    request = requirements.read_json(run / "validation-request.json")
    request["assessments"].pop(failed)
    request["failed_requirements"] = [failed]
    write_json(run / "validation-request.json", request)
    records[0 if correct_id else 1]["verdict"] = "not_checked"
    write_json(run / "ledger.json", ledger)
    code, result = run_finalizer(finalizer)
    assert code == (1 if correct_id else 2)
    if not correct_id:
        assert any(f"Failed worker {failed}" in error for error in result["errors"])


def test_finalizer_preserves_exact_ids_requested_documents_and_setup_limitations(finalizer):
    _, run, _, _, _ = finalizer
    original = requirements.read_json(run / "validation-request.json")
    for field, value, expected in [
        ("requirements", ["invented"], "Workflow requirement IDs"),
        ("specifications", ["missing.md"], "Requested specifications absent"),
        ("limitations", ["Unsupported formal source"], "Setup limitations were lost"),
    ]:
        write_json(run / "validation-request.json", {**original, field: value})
        code, result = run_finalizer(finalizer)
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
    record["checks"][0]["log"] = str((run / "failed.log").relative_to(root))
    (run / "failed.log").write_text("state preservation assertion FAILED\n")
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
    record["checks"][0]["log"] = str((run / "failed.log").relative_to(root))
    (run / "failed.log").write_text("state preservation assertion FAILED\n")
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
    _, run, _, _, _ = finalizer
    request = requirements.read_json(run / "validation-request.json")
    request["assessments"] = {}
    write_json(run / "validation-request.json", request)
    code, result = run_finalizer(finalizer)
    assert code == 2
    assert any("cover exactly the completed workers" in error for error in result["errors"])


@pytest.mark.parametrize("original_line", [2, None, 1, True])
def test_annotations_cannot_rebind_changed_source_as_original_evidence(finalizer, original_line):
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
    assert code == 2


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
    _, run, _, _, _ = finalizer
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
        request = requirements.read_json(run / "validation-request.json")
        request["production_source_files"] = 2
        write_json(run / "validation-request.json", request)
    elif mutation == "policy_mismatch":
        write_json(run / "source-policy.json", {"files": []})
    else:
        write_json(run / "diagnostics.json", [{"message": "parse failed"}])
    write_json(run / "graph.json", graph)
    code, result = run_finalizer(finalizer)
    assert code == 2 and result["status"] == "invalid"


@pytest.mark.parametrize("directory", [".trailmark", ".duvet/reports", "run"])
@pytest.mark.parametrize("stage", ["freeze", "finalize"])
def test_inspected_graph_files_need_snapshot_bindings(finalizer, directory, stage):
    root, run, _, _, ledger = finalizer
    path = (run if directory == "run" else root / directory) / "generated.py"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("def generated(): return True\n")
    graph = requirements.read_json(run / "graph.json")
    graph["summary"]["source_files"] += 1
    graph["source_policy"]["files"].append(
        {"path": str(path), "status": "inspected", "unit": "file", "root": "root"}
    )
    graph["nodes"]["generated"] = {
        "kind": "module",
        "location": {"file_path": str(path), "start_line": 1},
    }
    write_json(run / "graph.json", graph)
    write_json(run / "source-policy.json", graph["source_policy"])
    write_json(run / "graph-scope.json", {"production_files": ["packet.py", str(path)]})
    request = requirements.read_json(run / "validation-request.json")
    request["production_source_files"] = 2
    write_json(run / "validation-request.json", request)
    ledger["requirements"][1]["verdict"] = "not_applicable"
    (run / "source-inputs.json").unlink()
    (run / "source-snapshot.json").unlink()
    requirements.begin_snapshot(root, run)
    if stage == "freeze":
        with pytest.raises(ValueError, match="Inspected graph files lack source snapshot bindings"):
            requirements.freeze_snapshot(root, run)
    else:
        # Reproduce a run sealed by an earlier helper that omitted graph inputs.
        snapshot = write_json(run / "source-snapshot.json", requirements.snapshot_files(root, run))
        (run / "source-snapshot.sha256").write_text(requirements.file_sha256(snapshot))
        for record in ledger["requirements"]:
            save_fixture_assessment(finalizer, record)
        write_json(run / "ledger.json", ledger)
        path.write_text("def generated(): return False\n")
        code, result = run_finalizer(finalizer)
        assert code == 2 and not result["valid"]
        assert any(
            "Inspected graph files lack source snapshot bindings" in error
            for error in result["errors"]
        )
        assert not list(run.glob("gate-native-*"))


def test_graph_evidence_accepts_native_merged_source_policy(finalizer):
    _, run, _, _, ledger = finalizer
    graph = requirements.read_json(run / "graph.json")
    files = graph["source_policy"]["files"]
    graph["source_policy"] = {
        "schema_version": 1,
        "components": [{"files": [item]} for item in files],
    }
    write_json(run / "graph.json", graph)
    write_json(run / "source-policy.json", graph["source_policy"])
    (run / "source-snapshot.json").unlink()
    (run / "source-inputs.json").unlink()
    requirements.begin_snapshot(finalizer[0], run)
    requirements.freeze_snapshot(finalizer[0], run)
    for record in ledger["requirements"]:
        save_fixture_assessment(finalizer, record)
    write_json(run / "ledger.json", ledger)
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
    assert (
        requirements.check_ledger(before, after, ledger_path, root, ["spec.md"])["status"] == "gaps"
    )
    output = root / "inventory-root.json"
    completed = subprocess.run(
        [
            sys.executable,
            str(SCRIPT),
            "inventory",
            "--root",
            str(root),
            "--specification=spec.md",
            "--report",
            str(before),
            "--output",
            str(output),
        ],
        cwd=root.parent,
        capture_output=True,
        text=True,
        check=False,
    )
    assert completed.returncode == 0, completed.stdout + completed.stderr
