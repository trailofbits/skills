"""A repair claim cannot exceed the declared cases and retained observations."""

import json

import pytest
from records import write_manifest
from render import render
from repair_scope import assess_scope
from test_render import case, change


def coverage_plan():
    return {
        "mode": "bounded_class",
        "boundary": "Remove one leading id: while preserving later occurrences.",
        "cases": [
            {
                "check_id": "interior",
                "role": "representative",
                "input": ["id:a:id:b", "id:"],
                "expected": "a:id:b",
                "why": "Reported interior occurrence",
            },
            {
                "check_id": "repeated",
                "role": "representative",
                "input": ["id:id:a", "id:"],
                "expected": "id:a",
                "why": "Consecutive leading occurrences",
            },
            {
                "check_id": "ordinary",
                "role": "control",
                "input": ["id:a", "id:"],
                "expected": "a",
                "why": "Ordinary leading prefix remains supported",
            },
        ],
        "exclusions": ["Unrelated title_label capitalization defect"],
    }


def with_coverage(tmp_path, plan=None):
    run = case(tmp_path)
    if plan is not None:
        change(run, "finding.json", repair_scope=plan)
    return run


def test_bounded_claim_names_cases_controls_and_exclusions(tmp_path):
    run = with_coverage(tmp_path)
    output = render(run).read_text()
    assert "Bounded class repaired" in output
    assert "Consecutive leading occurrences" in output
    assert "Ordinary leading prefix remains supported" in output
    assert "Unrelated title_label capitalization defect" in output
    assert "PATCH_CASE" in output
    assert "prove/attempt-1/receipts/repeated-patched.stdout" in output


@pytest.mark.parametrize("invalid", ["missing", "duplicate", "wrong_input", "still_failing"])
def test_unusable_case_evidence_withholds_bounded_claim(tmp_path, invalid):
    run = with_coverage(tmp_path)
    proof_dir = run / "prove/attempt-1"
    path = proof_dir / "prove.json"
    proof = json.loads(path.read_text())
    if invalid == "missing":
        proof["cases"].pop(1)
    elif invalid == "duplicate":
        proof["cases"][1]["check_id"] = "interior"
    else:
        stdout = proof_dir / "receipts/repeated-patched.stdout"
        observed = {"input": ["unexpected"], "actual": "id:a"}
        if invalid == "still_failing":
            observed = {"input": coverage_plan()["cases"][1]["input"], "actual": "wrong"}
            proof["cases"][1]["runs"]["patched"]["exit_code"] = 1
        stdout.write_text("PATCH_CASE " + json.dumps(observed) + "\nPATCH_REACHED\n")
    path.write_text(json.dumps(proof))
    write_manifest(proof_dir)
    output = render(run).read_text()
    assert "Bounded class repaired" not in output
    assert "REPAIR SUCCEEDED" not in output


@pytest.mark.parametrize("invalid", ["one_example", "no_control", "same_input"])
def test_bounded_plan_requires_distinct_representatives_and_control(tmp_path, invalid):
    plan = coverage_plan()
    if invalid == "one_example":
        plan["cases"].pop(1)
    elif invalid == "no_control":
        plan["cases"].pop()
    else:
        plan["cases"][1]["input"] = plan["cases"][0]["input"]
    scope = assess_scope(with_coverage(tmp_path, plan), 1, True)
    assert scope.label == "Exact example repaired"
    assert "coverage incomplete" in scope.detail


def test_exact_example_plan_cannot_claim_bounded_class(tmp_path):
    plan = coverage_plan()
    plan["mode"] = "exact_example"
    scope = assess_scope(with_coverage(tmp_path, plan), 1, True)
    assert scope.label == "Exact example repaired"


def test_incomplete_revert_cannot_claim_repair(tmp_path):
    run = with_coverage(tmp_path)
    change(run, "prove/attempt-1/prove.json", reverted="fail")
    output = render(run).read_text()
    assert "Repair not established" in output
    assert "REPAIR SUCCEEDED" not in output
