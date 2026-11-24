"""Native proof checks require scoped observations and project receipts."""

import json
from pathlib import Path

import pytest
from native_proof import assess_proof
from records import check, write_manifest
from render import render
from test_render import case, change
from test_repair_scope import coverage_plan
from verdict import verdict


def native_run(tmp_path: Path) -> Path:
    run = case(tmp_path)
    plan = coverage_plan()
    change(run, "finding.json", repair_scope=plan)
    proof_dir = run / "prove/attempt-1"
    patch = json.loads((run / "patch/attempt-1/patch.json").read_text())
    cases = []
    for item in plan["cases"]:
        runs = {}
        for side in ("baseline", "patched"):
            actual = item["expected"]
            if item["role"] == "representative" and side == "baseline":
                actual = "wrong"
            output = (
                "PATCH_CASE "
                + json.dumps({"input": item["input"], "actual": actual})
                + "\nPATCH_REACHED\n"
            )
            receipt = f"receipts/{item['check_id']}-{side}.stdout"
            path = proof_dir / receipt
            path.parent.mkdir(exist_ok=True)
            path.write_text(output)
            stderr = f"receipts/{item['check_id']}-{side}.stderr"
            (proof_dir / stderr).write_text("")
            runs[side] = {
                "exit_code": 1 if actual == "wrong" else 0,
                "elapsed_ms": 1,
                "stdout": receipt,
                "stderr": stderr,
            }
        cases.append(
            {
                "check_id": item["check_id"],
                "argv": [
                    "python",
                    "receipts/proof-case.py",
                    json.dumps(item["input"]),
                    json.dumps(item["expected"]),
                ],
                "source": "receipts/proof-case.py",
                "runs": runs,
            }
        )
    (proof_dir / "receipts/proof-case.py").write_text(
        "import json\n"
        "import sys\n"
        "\n"
        "inputs = json.loads(sys.argv[1])\n"
        "expected = json.loads(sys.argv[2])\n"
        'actual = __import__("labels").remove_prefix(*inputs)\n'
        'print("PATCH_CASE " + json.dumps({"input": inputs, "actual": actual}))\n'
        'print("PATCH_REACHED", flush=True)\n'
        "assert actual == expected\n"
    )
    (proof_dir / "receipts/source.json").write_text(
        json.dumps(
            {
                "baseline_commit": patch["baseline_commit"],
                "patch_commit": patch["patch_commit"],
                "trees": {"baseline": "1" * 40, "patched": "2" * 40, "reverted": "1" * 40},
            }
        )
    )
    (proof_dir / "receipts/project-patched.stdout").write_text("10 passed\n")
    (proof_dir / "receipts/project-patched.stderr").write_text("")
    proof = json.loads((proof_dir / "prove.json").read_text())
    proof.update(
        schema_version=2,
        failure_type="runtime",
        baseline_commit=patch["baseline_commit"],
        patch_commit=patch["patch_commit"],
        cases=cases,
        project_checks=[
            {
                "check_id": "project-suite",
                "kind": "suite",
                "argv": ["pytest"],
                "baseline": None,
                "patched": {
                    "exit_code": 0,
                    "elapsed_ms": 1,
                    "stdout": "receipts/project-patched.stdout",
                    "stderr": "receipts/project-patched.stderr",
                },
            }
        ],
        unproven=["Behavior outside the declared boundary was not assessed."],
    )
    (proof_dir / "prove.json").write_text(json.dumps(proof))
    write_manifest(proof_dir)
    return run


def test_native_cases_and_project_check_establish_scoped_proof(tmp_path):
    result = assess_proof(native_run(tmp_path), 1)
    assert result.findings == ()
    assert result.gaps == ()
    assert {path.name for path in result.case_paths} >= {
        "proof-case.py",
        "interior-baseline.stdout",
        "interior-patched.stdout",
        "ordinary-patched.stdout",
    }


@pytest.mark.parametrize("kind", ["patch", "prove"])
def test_attempt_beyond_run_count_is_a_reportable_evidence_gap(tmp_path, kind):
    run = native_run(tmp_path)
    directory = run / kind / "attempt-2"
    directory.mkdir()
    record = json.loads((run / kind / "attempt-1" / f"{kind}.json").read_text())
    record["attempt"] = 2
    (directory / f"{kind}.json").write_text(json.dumps(record))
    write_manifest(directory)
    check(run)
    assert verdict(run)[0] == "NOT_READY"
    output = render(run).read_text()
    assert "INCONCLUSIVE" in output
    assert "run.attempts" in output
    assert f"{kind}/attempt-2" in output
    assert "REPAIR SUCCEEDED" not in output


@pytest.mark.parametrize("field", ["cases", "project_checks", "unproven"])
def test_empty_proof_arrays_remain_reportable_evidence_gaps(tmp_path, field):
    run = native_run(tmp_path)
    change(run, "prove/attempt-1/prove.json", **{field: []})
    check(run)
    assert verdict(run)[0] == "NOT_READY"
    output = render(run).read_text()
    assert "REPAIR SUCCEEDED" not in output
    assert "INCONCLUSIVE" in output


def test_missing_assertion_marker_is_an_evidence_gap(tmp_path):
    run = native_run(tmp_path)
    path = run / "prove/attempt-1/receipts/interior-baseline.stdout"
    path.write_text(path.read_text().replace("PATCH_REACHED\n", ""))
    write_manifest(run / "prove/attempt-1")
    result = assess_proof(run, 1)
    assert any("interior" in gap and "reached" in gap for gap in result.gaps)


def test_marker_before_observation_is_an_evidence_gap(tmp_path):
    run = native_run(tmp_path)
    path = run / "prove/attempt-1/receipts/interior-baseline.stdout"
    lines = path.read_text().splitlines()
    path.write_text("\n".join(reversed(lines)) + "\n")
    write_manifest(path.parents[1])
    result = assess_proof(run, 1)
    assert any("assertion marker" in gap for gap in result.case_gaps)


def test_trustworthy_patched_failure_is_a_finding(tmp_path):
    run = native_run(tmp_path)
    path = run / "prove/attempt-1/receipts/interior-patched.stdout"
    path.write_text(path.read_text().replace('"actual": "a:id:b"', '"actual": "wrong"'))
    proof_path = run / "prove/attempt-1/prove.json"
    proof = json.loads(proof_path.read_text())
    proof["cases"][0]["runs"]["patched"]["exit_code"] = 1
    proof_path.write_text(json.dumps(proof))
    write_manifest(proof_path.parent)
    result = assess_proof(run, 1)
    assert any("interior" in finding for finding in result.findings)
    assert result.gaps == ()


def test_missing_project_receipt_is_an_evidence_gap(tmp_path):
    run = native_run(tmp_path)
    (run / "prove/attempt-1/receipts/project-patched.stdout").unlink()
    write_manifest(run / "prove/attempt-1")
    result = assess_proof(run, 1)
    assert any("project-suite" in gap for gap in result.gaps)


def test_unattributed_project_failure_is_an_evidence_gap(tmp_path):
    run = native_run(tmp_path)
    path = run / "prove/attempt-1/prove.json"
    proof = json.loads(path.read_text())
    proof["project_checks"][0]["patched"]["exit_code"] = 1
    path.write_text(json.dumps(proof))
    write_manifest(path.parent)
    result = assess_proof(run, 1)
    assert any("baseline attribution" in gap for gap in result.project_gaps)


def test_attributed_project_failure_is_a_finding(tmp_path):
    run = native_run(tmp_path)
    directory = run / "prove/attempt-1"
    (directory / "receipts/project-baseline.stdout").write_text("10 passed\n")
    (directory / "receipts/project-baseline.stderr").write_text("")
    path = directory / "prove.json"
    proof = json.loads(path.read_text())
    proof["project_checks"][0]["baseline"] = {
        "exit_code": 0,
        "elapsed_ms": 1,
        "stdout": "receipts/project-baseline.stdout",
        "stderr": "receipts/project-baseline.stderr",
    }
    proof["project_checks"][0]["patched"]["exit_code"] = 1
    path.write_text(json.dumps(proof))
    write_manifest(directory)
    result = assess_proof(run, 1)
    assert any("project-suite" in finding for finding in result.project_findings)


def test_proof_commit_mismatch_is_an_evidence_gap(tmp_path):
    run = native_run(tmp_path)
    path = run / "prove/attempt-1/prove.json"
    proof = json.loads(path.read_text())
    proof["patch_commit"] = "c" * 40
    path.write_text(json.dumps(proof))
    write_manifest(path.parent)
    result = assess_proof(run, 1)
    assert "proof commits differ from the recorded patch" in result.case_gaps


def test_missing_explicit_limits_are_an_evidence_gap(tmp_path):
    run = native_run(tmp_path)
    path = run / "prove/attempt-1/prove.json"
    proof = json.loads(path.read_text())
    proof["unproven"] = []
    path.write_text(json.dumps(proof))
    write_manifest(path.parent)
    result = assess_proof(run, 1)
    assert "unproven limits were not recorded" in result.project_gaps
    output = render(run).read_text()
    assert "REPAIR SUCCEEDED" not in output
    assert "No explicit limits were recorded" in output


def test_missing_source_tree_receipt_is_an_arm_gap(tmp_path):
    run = native_run(tmp_path)
    directory = run / "prove/attempt-1"
    (directory / "receipts/source.json").unlink()
    write_manifest(directory)
    result = assess_proof(run, 1)
    assert any("source tree" in gap for gap in result.arm_gaps)
    output = render(run).read_text()
    assert "REPAIR SUCCEEDED" not in output


def test_reverted_tree_must_match_original_baseline(tmp_path):
    run = native_run(tmp_path)
    directory = run / "prove/attempt-1"
    path = directory / "receipts/source.json"
    source = json.loads(path.read_text())
    source["trees"]["reverted"] = "3" * 40
    path.write_text(json.dumps(source))
    write_manifest(directory)
    result = assess_proof(run, 1)
    assert any("reverted tree" in gap for gap in result.arm_gaps)


def test_native_proof_is_the_readiness_gate(tmp_path):
    run = native_run(tmp_path)
    assert verdict(run)[0] == "READY"
    path = run / "prove/attempt-1/receipts/interior-patched.stdout"
    path.write_text(path.read_text().replace('"actual": "a:id:b"', '"actual": "wrong"'))
    proof_path = run / "prove/attempt-1/prove.json"
    proof = json.loads(proof_path.read_text())
    proof["cases"][0]["runs"]["patched"]["exit_code"] = 1
    proof_path.write_text(json.dumps(proof))
    write_manifest(proof_path.parent)
    assert verdict(run)[0] == "NOT_READY"


def test_report_uses_native_proof_without_post_patch_result(tmp_path):
    output = render(native_run(tmp_path)).read_text()
    assert "REPAIR SUCCEEDED" in output
    assert "Bounded class repaired" in output
    assert "Scoped case proof" in output
    assert "Project checks" in output
    assert "Post-patch validation" not in output


def test_report_hides_case_harness_when_poc_disclosure_is_disabled(tmp_path):
    run = native_run(tmp_path)
    source = run / "prove/attempt-1/receipts/proof-case.py"
    source.write_text("SECRET_CASE_HARNESS\n")
    proof = run / "prove/attempt-1/prove.json"
    record = json.loads(proof.read_text())
    record["cases"][0]["argv"].append("SECRET_CASE_ARGUMENT")
    proof.write_text(json.dumps(record))
    write_manifest(proof.parent)
    output = render(run).read_text()
    assert "SECRET_CASE_HARNESS" not in output
    assert "SECRET_CASE_ARGUMENT" not in output
    assert "Case harness source omitted by disclosure choice" in output


def test_report_includes_case_harness_when_disclosure_is_enabled(tmp_path):
    run = native_run(tmp_path)
    source = run / "prove/attempt-1/receipts/proof-case.py"
    source.write_text("VISIBLE_CASE_HARNESS\n")
    write_manifest(source.parents[1])
    change(run, "report-input.json", include_poc=True)
    assert "VISIBLE_CASE_HARNESS" in render(run).read_text()
