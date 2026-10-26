"""JSON booleans must not satisfy numeric native-proof observations (or vice versa).

Like native_run, these tests assess authored records, not real harness executions.
"""

import json

import pytest
from native_proof import assess_proof
from records import check, write_manifest
from render import render
from test_native_proof import native_run
from verdict import verdict

JSON_TYPE_MISMATCHES = [
    pytest.param(True, 1, id="true-vs-one"),
    pytest.param(False, 0, id="false-vs-zero"),
    pytest.param(1, True, id="one-vs-true"),
    pytest.param(0, False, id="zero-vs-false"),
    pytest.param(True, 1.0, id="true-vs-float"),
    pytest.param([True], [1], id="array"),
    pytest.param({"strict": False}, {"strict": 0}, id="object"),
    pytest.param(
        {"items": [{"strict": True}]},
        {"items": [{"strict": 1}]},
        id="nested-object-array",
    ),
]


def typed_run(tmp_path, check_id, planned_input, expected, overrides=None):
    """Keep unrelated evidence valid while varying one planned case's receipts."""
    run = native_run(tmp_path)
    finding_path = run / "finding.json"
    finding = json.loads(finding_path.read_text())
    case = next(c for c in finding["repair_scope"]["cases"] if c["check_id"] == check_id)
    case.update(input=planned_input, expected=expected)
    finding_path.write_text(json.dumps(finding))

    directory = run / "prove/attempt-1"
    proof_path = directory / "prove.json"
    proof = json.loads(proof_path.read_text())
    retained = next(c for c in proof["cases"] if c["check_id"] == check_id)
    retained["argv"][-2:] = [json.dumps(planned_input), json.dumps(expected)]
    for side in ("baseline", "patched"):
        failing_baseline = side == "baseline" and case["role"] == "representative"
        observation = {
            "input": planned_input,
            "actual": "wrong" if failing_baseline else expected,
        }
        fields = dict((overrides or {}).get(side, {}))
        retained["runs"][side]["exit_code"] = fields.pop("exit_code", 1 if failing_baseline else 0)
        observation.update(fields)
        stdout = directory / retained["runs"][side]["stdout"]
        stdout.write_text("PATCH_CASE " + json.dumps(observation) + "\nPATCH_REACHED\n")
    proof_path.write_text(json.dumps(proof))
    write_manifest(directory)
    check(run)
    return run


@pytest.mark.parametrize("planned,observed", JSON_TYPE_MISMATCHES)
@pytest.mark.parametrize("side", ["baseline", "patched"])
def test_json_typed_input_mismatch_is_an_evidence_gap(tmp_path, planned, observed, side):
    run = typed_run(tmp_path, "interior", planned, "a:id:b", {side: {"input": observed}})
    result = assess_proof(run, 1)
    assert result.case_gaps == (f"interior {side}: observed input differs from the repair plan",)
    assert result.findings == ()
    assert verdict(run)[0] == "NOT_READY"
    assert "REPAIR SUCCEEDED" not in render(run).read_text()


@pytest.mark.parametrize("expected,actual", JSON_TYPE_MISMATCHES)
@pytest.mark.parametrize("check_id", ["interior", "ordinary"])
@pytest.mark.parametrize("exit_code", [0, 1])
def test_json_typed_patched_output_mismatch_cannot_pass(
    tmp_path, expected, actual, check_id, exit_code
):
    run = typed_run(
        tmp_path,
        check_id,
        ["typed-case"],
        expected,
        {"patched": {"actual": actual, "exit_code": exit_code}},
    )
    result = assess_proof(run, 1)
    if exit_code == 0:
        message = (
            "patched exit and observation disagree"
            if check_id == "interior"
            else "patched control exit and observation disagree"
        )
        assert result.case_gaps == (f"{check_id}: {message}",)
        assert result.findings == ()
    else:
        message = (
            "scoped failure remains after the patch"
            if check_id == "interior"
            else "valid control fails after the patch"
        )
        assert result.case_findings == (f"{check_id}: {message}",)
        assert result.gaps == ()
    assert verdict(run)[0] == "NOT_READY"
    assert "REPAIR SUCCEEDED" not in render(run).read_text()


@pytest.mark.parametrize("expected,actual", JSON_TYPE_MISMATCHES)
def test_json_typed_baseline_control_mismatch_is_a_gap(tmp_path, expected, actual):
    run = typed_run(
        tmp_path, "ordinary", ["typed-case"], expected, {"baseline": {"actual": actual}}
    )
    result = assess_proof(run, 1)
    assert result.case_gaps == ("ordinary: baseline control did not pass",)
    assert result.findings == ()
    assert verdict(run)[0] == "NOT_READY"


@pytest.mark.parametrize("expected,actual", JSON_TYPE_MISMATCHES)
def test_json_typed_baseline_failure_is_not_mistaken_for_expected_output(
    tmp_path, expected, actual
):
    run = typed_run(
        tmp_path, "interior", ["typed-case"], expected, {"baseline": {"actual": actual}}
    )
    result = assess_proof(run, 1)
    assert result.gaps == ()
    assert result.findings == ()
    assert verdict(run)[0] == "READY"


@pytest.mark.parametrize("check_id", ["interior", "ordinary"])
@pytest.mark.parametrize(
    "value",
    [
        pytest.param(True, id="true"),
        pytest.param(False, id="false"),
        pytest.param(1, id="one"),
        pytest.param(0, id="zero"),
        pytest.param(1.5, id="fraction"),
        pytest.param(None, id="null"),
        pytest.param([True, False, 1, 0], id="array"),
        pytest.param({"items": [{"strict": True, "count": 1}]}, id="nested-object"),
    ],
)
def test_json_typed_matching_inputs_and_outputs_still_pass(tmp_path, check_id, value):
    run = typed_run(tmp_path, check_id, value, value)
    result = assess_proof(run, 1)
    assert result.gaps == ()
    assert result.findings == ()
    assert verdict(run)[0] == "READY"
    assert "REPAIR SUCCEEDED" in render(run).read_text()


@pytest.mark.parametrize("check_id", ["interior", "ordinary"])
def test_json_number_equivalence_is_preserved(tmp_path, check_id):
    # This regression separates booleans from numbers, not int from float.
    run = typed_run(
        tmp_path,
        check_id,
        {"count": 1},
        [1],
        {
            "baseline": {"input": {"count": 1.0}},
            "patched": {"input": {"count": 1.0}, "actual": [1.0]},
        },
    )
    result = assess_proof(run, 1)
    assert result.gaps == ()
    assert result.findings == ()
    assert verdict(run)[0] == "READY"
