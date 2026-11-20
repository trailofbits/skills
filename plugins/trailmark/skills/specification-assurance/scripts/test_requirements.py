"""Accounting regressions using the structure emitted by Duvet's --json report."""

import copy
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
        "specifications": {"spec.md": {"requirements": [0, 1]}},
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
        "statuses": {"0": {"citation": 39, "related": [2]}, "1": {"incomplete": 51}},
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
        write_json(after, report)
    assert not gate(artifacts)["valid"]


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
