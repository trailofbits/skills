from __future__ import annotations

import json
import re
import subprocess
from pathlib import Path

import yaml
from test_runner import run, scaffold

EVALS = Path(__file__).resolve().parents[1] / "evals"
EXPECTED = {"complete-fix", "missed-variant", "behavior-regression", "mixed-failures"}


def artifact(case: str) -> tuple[dict, str]:
    kinds = {
        "complete-fix": [],
        "missed-variant": ["variant"],
        "behavior-regression": ["behavior"],
        "mixed-failures": ["variant", "behavior"],
    }[case]
    findings = [
        {"check_id": f"check-{kind}", "kind": kind, "message": "The assertion failed."}
        for kind in kinds
    ]
    result = {
        "schema_version": "2.0",
        "assessment": {
            "status": "complete",
            "findings": findings,
            "gaps": [],
            "human_review_required": True,
        },
        # Declared checks alone cannot satisfy a finding grader.
        "checks": [{"id": "check-variant", "kind": "variant", "runs": {}}],
    }
    variant = "did not match" if "variant" in kinds else "matched"
    behavior = "changed" if "behavior" in kinds else "same"
    report = (
        f"| `check-variant` | variant | matched | {variant} | not compared |\n"
        f"| `check-behavior` | behavior | matched | matched | {behavior} |\n"
    )
    return result, report


def cases() -> list[dict]:
    paths = sorted(EVALS.glob("*/case.yaml"))
    assert {path.parent.name for path in paths} == EXPECTED
    return [yaml.safe_load(path.read_text()) for path in paths]


def test_four_evals_grade_saved_artifacts_without_model_judges() -> None:
    for case in cases():
        assert case["runs"] == 3
        assert case["execution"]["timeout_seconds"] == 1800
        assert any(g["type"] == "file_exists" for g in case["graders"])
        regexes = [g for g in case["graders"] if g["type"] == "regex"]
        assert len(regexes) == 2
        assert all(g["target"]["source"] == "file" for g in regexes)
        assert all(g["type"] != "llm" for g in case["graders"])


def test_graders_require_actual_assessment_fields_and_observations() -> None:
    asserted = 0
    for case in cases():
        result, report = artifact(case["name"])
        opposite = "missed-variant" if case["name"] == "complete-fix" else "complete-fix"
        bad_result, bad_report = artifact(opposite)
        for grader in case["graders"]:
            if grader["type"] != "regex":
                continue
            pattern = re.compile(grader["pattern"])
            is_json = grader["target"]["path"].endswith("result.json")
            golden = json.dumps(result, sort_keys=True, indent=2) if is_json else report
            defective = json.dumps(bad_result, sort_keys=True) if is_json else bad_report
            assert pattern.search(golden), grader["name"]
            assert not pattern.search(defective), grader["name"]
            assert not pattern.search(
                "All checks passed. Found a variant and a behavior regression."
            )
            if is_json:
                assert not pattern.search(json.dumps({"checks": result["checks"]}))
            asserted += 1
    assert asserted == 8


def test_mixed_failure_eval_rejects_either_dropped_finding() -> None:
    case = next(c for c in cases() if c["name"] == "mixed-failures")
    for kind in ("variant", "behavior"):
        result, _ = artifact(case["name"])
        result["assessment"]["findings"] = [
            item for item in result["assessment"]["findings"] if item["kind"] != kind
        ]
        # A copied raw check or a reviewer concern cannot replace a runner finding.
        result["checks"].append({"check_id": "decoy", "kind": kind, "message": "failed"})
        grader = next(g for g in case["graders"] if g["name"] == f"{kind}-finding-retained")
        assert not re.search(grader["pattern"], json.dumps(result, sort_keys=True))


def test_complete_eval_rejects_empty_or_incomplete_evidence() -> None:
    case = next(c for c in cases() if c["name"] == "complete-fix")
    grader = next(g for g in case["graders"] if g["name"] == "complete-without-findings-or-gaps")
    for assessment in (
        {},
        {"status": "incomplete", "findings": [], "gaps": [], "human_review_required": True},
        {
            "status": "complete",
            "findings": [],
            "gaps": [{"check_id": None, "reason": "missing"}],
            "human_review_required": True,
        },
    ):
        assert not re.search(
            grader["pattern"], json.dumps({"assessment": assessment}, sort_keys=True)
        )


def test_variant_observation_cannot_match_a_later_failure() -> None:
    case = next(c for c in cases() if c["name"] == "missed-variant")
    grader = next(g for g in case["graders"] if g["name"] == "variant-observation")
    report = (
        "| `variant` | variant | matched | matched | not compared |\n"
        "| `regression` | regression | matched | did not match | not compared |\n"
    )
    assert not re.search(grader["pattern"], report)


def test_eval_scaffolds_create_clean_two_commit_repositories(tmp_path: Path) -> None:
    ran = 0
    for directory in sorted(path.parent for path in EVALS.glob("*/case.yaml")):
        workdir = tmp_path / directory.name
        workdir.mkdir()
        subprocess.run(["bash", str(directory / "scaffold.sh")], cwd=workdir, check=True)
        base = subprocess.run(
            ["git", "rev-parse", "vulnerable"],
            cwd=workdir,
            text=True,
            stdout=subprocess.PIPE,
            check=True,
        ).stdout.strip()
        head = subprocess.run(
            ["git", "rev-parse", "HEAD"],
            cwd=workdir,
            text=True,
            stdout=subprocess.PIPE,
            check=True,
        ).stdout.strip()
        status = subprocess.run(
            ["git", "status", "--short"],
            cwd=workdir,
            text=True,
            stdout=subprocess.PIPE,
            check=True,
        ).stdout
        assert base != head
        assert status == ""
        plan = workdir / "post-patch-validation" / "plan.json"
        value = scaffold(workdir, plan)
        for check in value["checks"]:
            check["argv"] = [
                arg.replace("import app", "import renderer as app")
                .replace("app.sanitize", "app.render")
                .replace("app.py", "renderer.py")
                for arg in check["argv"]
            ]
            if check["kind"] == "behavior":
                check["argv"][-1] = check["argv"][-1].replace("'safe'", "' safe '")
            if check["kind"] == "security":
                # Already-escaped text must not be corrupted by the markup repair.
                check["argv"][-1] = "import renderer; assert renderer.render('&lt;') == '&lt;'"
        plan.write_text(json.dumps(value))
        output = workdir / "post-patch-validation" / "results"
        completed = run(plan, output)
        expected_exit = 0 if directory.name == "complete-fix" else 1
        assert completed.returncode == expected_exit, completed.stderr
        case = yaml.safe_load((directory / "case.yaml").read_text())
        for grader in case["graders"]:
            if grader["type"] == "file_exists":
                assert (workdir / grader["path"]).is_file()
            else:
                text = (workdir / grader["target"]["path"]).read_text()
                assert re.search(grader["pattern"], text), grader["name"]
        ran += 1
    assert ran == 4
