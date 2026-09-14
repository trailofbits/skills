from __future__ import annotations

import pytest


def observation(kind: str, *, base: bool = True, patched: bool = True) -> dict:
    runs = {"patched": {"status": "completed", "matched": patched, "marker": True}}
    if kind != "suite" or not patched:
        runs["base"] = {"status": "completed", "matched": base, "marker": True}
    check = {"id": f"check-{kind}", "kind": kind, "runs": runs}
    if kind == "behavior":
        check["comparison"] = {"matched": True}
    return check


def evidence(ppv, **failures: bool) -> list[dict]:
    return [observation(kind, patched=not failures.get(kind, False)) for kind in ppv.KINDS]


@pytest.mark.parametrize(
    "failures",
    [
        (),
        ("variant",),
        ("behavior",),
        ("security",),
        ("suite",),
        ("exploit", "variant", "behavior", "regression", "security", "suite"),
    ],
)
def test_every_supported_failure_is_retained(ppv, failures: tuple[str, ...]) -> None:
    assessment = ppv.assess_checks(evidence(ppv, **dict.fromkeys(failures, True)))
    assert assessment["status"] == "complete"
    assert assessment["gaps"] == []
    assert {item["kind"] for item in assessment["findings"]} == set(failures)
    assert all(item["check_id"] == f"check-{item['kind']}" for item in assessment["findings"])
    assert assessment["human_review_required"] is True
    assert ppv.assessment_exit_code(assessment) == bool(failures)


@pytest.mark.parametrize("status", ["timeout", "execution_error"])
def test_unrelated_execution_gap_does_not_hide_failures(ppv, status: str) -> None:
    checks = evidence(ppv, variant=True, regression=True)
    checks[-1]["runs"]["patched"]["status"] = status
    assessment = ppv.assess_checks(checks)
    assert assessment["status"] == "incomplete"
    assert {item["kind"] for item in assessment["findings"]} == {"variant", "regression"}
    assert len(assessment["gaps"]) == 1
    assert assessment["gaps"][0]["check_id"] == "check-suite"
    assert status in assessment["gaps"][0]["reason"]
    assert ppv.assessment_exit_code(assessment) == 10


@pytest.mark.parametrize("kind", ["exploit", "variant", "regression", "security", "suite"])
def test_bad_baseline_leaves_a_gap_instead_of_a_finding(ppv, kind: str) -> None:
    checks = [observation(k, base=k != kind, patched=k != kind) for k in ppv.KINDS]
    assessment = ppv.assess_checks(checks)
    assert assessment["status"] == "incomplete"
    assert assessment["findings"] == []
    assert assessment["gaps"][0]["check_id"] == f"check-{kind}"


@pytest.mark.parametrize("side", ["base", "patched"])
@pytest.mark.parametrize("kind", ["exploit", "variant"])
def test_missing_marker_does_not_support_a_finding(ppv, side: str, kind: str) -> None:
    checks = evidence(ppv, **{kind: True})
    check = next(c for c in checks if c["kind"] == kind)
    check["runs"][side]["marker"] = False
    assessment = ppv.assess_checks(checks)
    assert assessment["findings"] == []
    assert f"{side}: marker_missing" in assessment["gaps"][0]["reason"]


@pytest.mark.parametrize("side", ["base", "patched"])
def test_failed_global_control_withholds_findings_but_keeps_observations(ppv, side: str) -> None:
    checks = evidence(ppv, variant=True, security=True)
    checks[0]["runs"][side]["matched"] = False
    assessment = ppv.assess_checks(checks)
    assert assessment["findings"] == []
    assert {gap["check_id"] for gap in assessment["gaps"]} == {
        "check-control",
        "check-variant",
        "check-security",
    }
    assert checks[2]["runs"]["patched"]["matched"] is False


def test_missing_checks_cannot_pass(ppv) -> None:
    for checks in ([], evidence(ppv)[1:], evidence(ppv)[:-1]):
        assessment = ppv.assess_checks(checks)
        assert assessment["status"] == "incomplete"
        assert assessment["gaps"][0]["check_id"] is None
        assert ppv.assessment_exit_code(assessment) == 10


def test_missing_required_run_and_comparison_leave_gaps(ppv) -> None:
    checks = evidence(ppv)
    del checks[2]["runs"]["base"]
    del checks[3]["comparison"]
    assessment = ppv.assess_checks(checks)
    assert assessment["findings"] == []
    assert {gap["check_id"] for gap in assessment["gaps"]} == {"check-variant", "check-behavior"}


def test_behavior_output_difference_is_a_finding_even_when_both_commands_pass(ppv) -> None:
    checks = evidence(ppv)
    checks[3]["comparison"]["matched"] = False
    assessment = ppv.assess_checks(checks)
    assert [item["kind"] for item in assessment["findings"]] == ["behavior"]
    assert assessment["gaps"] == []


def test_cleanup_failure_preserves_supported_findings(ppv) -> None:
    assessment = ppv.assess_checks(evidence(ppv, variant=True), ["could not prune worktrees"])
    assert [item["kind"] for item in assessment["findings"]] == ["variant"]
    assert assessment["gaps"] == [
        {"check_id": None, "reason": "Cleanup failed: could not prune worktrees"}
    ]
    assert ppv.assessment_exit_code(assessment) == 10


@pytest.mark.parametrize("level", ["source", "build", "runtime"])
@pytest.mark.parametrize("outcome", ["pass", "failure", "gap", "mixed"])
def test_reports_show_findings_gaps_and_evidence_scope(ppv, level: str, outcome: str) -> None:
    checks = evidence(ppv, variant=outcome in {"failure", "mixed"})
    if outcome in {"gap", "mixed"}:
        checks[-1]["runs"]["patched"]["status"] = "timeout"
    result = {
        "finding": {"id": "TEST", "summary": "Unsafe markup"},
        "inputs": {
            "base_commit": "0" * 40,
            "patch_sha256": "0" * 64,
            "evidence_level": level,
            "submodules": {},
            "forwarded_env": {},
        },
        "checks": checks,
        "assessment": ppv.assess_checks(checks),
    }
    report = ppv.markdown_report(result)
    assert f"Declared evidence level: {level} ({ppv.EVIDENCE_LEVEL_SUMMARIES[level]})" in report
    assert ("All supplied checks passed." in report) == (outcome == "pass")
    assert ("variant safety assertion still fails" in report) == (outcome in {"failure", "mixed"})
    assert ("patched: timeout" in report) == (outcome in {"gap", "mixed"})
    if outcome in {"gap", "mixed"}:
        assert "| suite | not run | incomplete |" in report
