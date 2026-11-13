import hashlib
import json
import shutil
import subprocess
import sys

import pytest
from records import check, write_manifest
from render import render
from test_proof_types import compile_run
from test_render import FIXTURE, case, change


def stop_before_patch(run):
    change(run, "run.json", attempts=0, status="not_reproduced")
    for kind in ("patch", "prove", "regression"):
        directory = run / kind
        for path in sorted(directory.rglob("*"), reverse=True):
            if path.is_file():
                path.unlink()
            else:
                path.rmdir()
        directory.rmdir()


def healthy_baseline(tmp_path):
    run = case(tmp_path)
    stop_before_patch(run)
    change(
        run,
        "finding.json",
        title="Baseline value",
        claim="value() returns a wrong result",
        invariant="value() returns 7",
        affected_code=[],
        repair_scope={
            "mode": "exact_example",
            "boundary": "The requested call value() returns 7.",
            "cases": [
                {
                    "check_id": "value",
                    "role": "representative",
                    "input": [],
                    "expected": 7,
                    "why": "The expressly requested input.",
                }
            ],
            "exclusions": ["Other behavior was not assessed."],
        },
    )
    package = run / "reproduce/poc"
    target = package / "value.py"
    target.write_text("def value():\n    return 7\n")
    poc = package / "poc.py"
    poc.write_text(
        "import hashlib, json, pathlib\n"
        "import value\n"
        "loaded = pathlib.Path(value.__file__).resolve()\n"
        "print('PATCH_LOADED ' + json.dumps({'path': str(loaded), "
        "'sha256': hashlib.sha256(loaded.read_bytes()).hexdigest()}))\n"
        "actual = value.value()\n"
        "print('PATCH_CASE ' + json.dumps({'input': [], 'actual': actual}))\n"
        "print('PATCH_REACHED')\n"
        "assert actual == 7\n"
    )
    build_argv = [sys.executable, "-m", "py_compile", str(target.relative_to(run))]
    poc_argv = [sys.executable, str(poc.relative_to(run))]
    for step in ("reproduce", "validate"):
        receipts = run / step / "receipts"
        for name, argv in (("build", build_argv), ("target", poc_argv)):
            result = subprocess.run(argv, cwd=run, capture_output=True, check=False)
            assert result.returncode == 0
            (receipts / f"{name}.stdout").write_bytes(result.stdout)
            (receipts / f"{name}.stderr").write_bytes(result.stderr)
            (receipts / f"{name}.exit.json").write_text(
                json.dumps({"exit_code": result.returncode})
            )
        write_manifest(run / step)
    change(
        run,
        "reproduce/reproduce.json",
        outcome="not_reproduced",
        failure_type="runtime",
        target_artifact=str(target.relative_to(run)),
        build_argv=build_argv,
        poc_argv=poc_argv,
        observed="The requested value() call returns 7 and its assertion passes.",
    )
    change(
        run, "validate/validate.json", outcome="not_confirmed", reason="The same call returns 7."
    )
    change(
        run,
        "report-input.json",
        bug="The requested baseline value was checked.",
        fix_why="No change was made; the baseline returned the expected value.",
        open_risks=["Other behavior was not assessed."],
        baseline_checks=[
            {
                "check_id": "value",
                "reproduce": {
                    "stdout": "reproduce/receipts/target.stdout",
                    "exit": "reproduce/receipts/target.exit.json",
                },
                "validate": {
                    "stdout": "validate/receipts/target.stdout",
                    "exit": "validate/receipts/target.exit.json",
                },
            }
        ],
    )
    return run


def test_compiler_report_does_not_describe_an_impossible_runtime_assertion(tmp_path):
    run = compile_run(tmp_path)
    output = render(run).read_text()
    assert "baseline reached the safety assertion" not in output
    assert "Bounded class repaired" in output
    assert "Automated patch verdict:</strong> READY" in output


def test_observed_healthy_baseline_reports_no_patch_required(tmp_path):
    run = healthy_baseline(tmp_path)
    check(run)
    output = render(run).read_text()
    assert "No patch required" in output
    assert "Automated patch verdict" in output
    assert "not applicable" in output


def test_contradictory_runtime_loader_keeps_baseline_inconclusive(tmp_path):
    run = healthy_baseline(tmp_path)
    change(
        run,
        "reproduce/reproduce.json",
        failure_type="runtime",
        target_artifact="dist/app.py",
    )
    check(run)
    output = render(run).read_text()
    assert "INCONCLUSIVE" in output
    assert "No patch required" not in output


@pytest.mark.parametrize("kind", ["patch", "prove"])
def test_retained_attempt_contradicts_zero_attempt_baseline(tmp_path, kind):
    run = healthy_baseline(tmp_path)
    shutil.copytree(FIXTURE / kind, run / kind)
    check(run)
    output = render(run).read_text()
    assert "INCONCLUSIVE" in output
    assert "No patch required" not in output
    assert "no patch exists to assess" not in output.lower()
    assert "No patch commit was recorded" not in output


@pytest.mark.parametrize(
    "problem",
    [
        "missing",
        "wrong_input",
        "wrong_result",
        "no_observation",
        "failed_exit",
        "same_agent",
        "out_of_step",
        "no_plan",
    ],
)
def test_missing_or_invalid_healthy_observations_remain_inconclusive(tmp_path, problem):
    run = healthy_baseline(tmp_path)
    stdout = run / "validate/receipts/target.stdout"
    if problem == "missing":
        stdout.unlink()
    elif problem == "wrong_input":
        stdout.write_text(stdout.read_text().replace('"input": []', '"input": [1]'))
    elif problem == "wrong_result":
        stdout.write_text(stdout.read_text().replace('"actual": 7', '"actual": 8'))
    elif problem == "no_observation":
        stdout.write_text("PATCH_REACHED\n")
    elif problem == "failed_exit":
        (run / "validate/receipts/target.exit.json").write_text('{"exit_code": 1}')
    elif problem == "same_agent":
        change(run, "validate/validate.json", agent="reproducer")
    elif problem == "out_of_step":
        prose = json.loads((run / "report-input.json").read_text())
        prose["baseline_checks"][0]["validate"] = prose["baseline_checks"][0]["reproduce"]
        change(run, "report-input.json", baseline_checks=prose["baseline_checks"])
    else:
        finding = json.loads((run / "finding.json").read_text())
        del finding["repair_scope"]
        (run / "finding.json").write_text(json.dumps(finding))
    write_manifest(run / "validate")
    output = render(run).read_text()
    assert "INCONCLUSIVE" in output
    assert "<strong>No patch required" not in output
    assert "Target outcome: No patch required" not in output


def test_healthy_baseline_without_receipt_mapping_is_conservative(tmp_path):
    run = healthy_baseline(tmp_path)
    prose = json.loads((run / "report-input.json").read_text())
    del prose["baseline_checks"]
    (run / "report-input.json").write_text(json.dumps(prose))
    assert "Inconclusive" in render(run).read_text()


def test_unavailable_compiler_reports_inconclusive(tmp_path):
    run = compile_run(tmp_path)
    stop_before_patch(run)
    change(
        run,
        "reproduce/reproduce.json",
        outcome="blocked",
        blocker="Compiler unavailable.",
        observed="No compiler diagnostic could be observed.",
    )
    for path in sorted((run / "validate").rglob("*"), reverse=True):
        if path.is_file():
            path.unlink()
        else:
            path.rmdir()
    (run / "validate").rmdir()
    (run / "reproduce/receipts/missing-compiler.stderr").write_text(
        "Compiler executable not found\n"
    )
    write_manifest(run / "reproduce")
    output = render(run).read_text()
    assert "INCONCLUSIVE" in output
    assert "No patch required" not in output


def test_stop_before_reproduction_still_produces_a_report(tmp_path):
    run = case(tmp_path)
    stop_before_patch(run)
    for step in ("reproduce", "validate"):
        for path in sorted((run / step).rglob("*"), reverse=True):
            if path.is_file():
                path.unlink()
            else:
                path.rmdir()
        (run / step).rmdir()
    output = render(run).read_text()
    assert "INCONCLUSIVE" in output
    assert "required reproduce record missing" in output
    assert "No patch required" not in output


def test_missing_validation_and_native_gap_cannot_affirm_target_repair(tmp_path):
    run = case(tmp_path)
    (run / "validate/validate.json").unlink()
    write_manifest(run / "validate")
    path = run / "prove/attempt-1/receipts/interior-patched.stdout"
    path.write_text("missing observation\n")
    write_manifest(path.parents[1])
    output = render(run).read_text()
    assert "Inconclusive" in output
    assert "target bug no longer reproduces" not in output


def test_external_receipt_reference_is_not_presented_as_retained_evidence(tmp_path):
    run = case(tmp_path)
    missing = "/temporary-proof-to-be-deleted/stdout.txt"
    proof_path = run / "prove/attempt-1/prove.json"
    proof = json.loads(proof_path.read_text())
    proof["cases"][0]["runs"]["patched"]["stdout"] = missing
    proof_path.write_text(json.dumps(proof))
    write_manifest(proof_path.parent)
    raw = (run / "prove/attempt-1/prove.json").read_bytes()
    output = render(run).read_text()
    assert "INCONCLUSIVE" in output
    assert "unsafe proof receipt" in output
    assert missing in output
    assert hashlib.sha256(raw).hexdigest() in output


def test_retained_receipt_survives_source_cleanup(tmp_path):
    run = case(tmp_path)
    temporary = tmp_path / "disposable-output.txt"
    temporary.write_text("external source\n")
    retained = run / "prove/attempt-1/receipts/interior-patched.stdout"
    digest = hashlib.sha256(retained.read_bytes()).hexdigest()
    temporary.unlink()
    output = render(run).read_text()
    assert str(retained.relative_to(run)) in output
    assert digest in output
    assert "Content-Security-Policy" in output
