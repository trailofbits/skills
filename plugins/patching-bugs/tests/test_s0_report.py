"""A retained no-patch control must be presented as a control, with case receipts."""

import json
import re
import shutil
import subprocess
import sys
from pathlib import Path

from records import write_manifest
from render import render
from report_sections import Evidence
from test_render import case, change
from test_repair_scope import with_coverage
from test_terminal_reports import stop_before_patch

SCRIPT = Path(__file__).resolve().parents[1] / "scripts/render.py"
CASES = [
    ("empty-payload", "representative", {"raw": ""}, False),
    ("trailing-separator", "representative", {"raw": "item::"}, False),
    ("valid-payload", "control", {"raw": "item"}, True),
]


def s0_case(tmp_path: Path, *, with_refs: bool = False, with_metadata: bool = False) -> Path:
    run = case(tmp_path)
    stop_before_patch(run)
    planned = [
        {
            "check_id": name,
            "role": role,
            "input": value,
            "expected": expected,
            "why": "Required scoped check.",
        }
        for name, role, value, expected in CASES
    ]
    change(
        run,
        "finding.json",
        title="JavaScript parser control",
        claim="Malformed values may be accepted.",
        invariant="Malformed values are rejected and valid values remain accepted.",
        poc="HIDDEN_POC_MARKER",
        repair_scope={
            "mode": "bounded_class",
            "boundary": "The parser's documented input forms.",
            "cases": planned,
            "exclusions": ["Unrelated parsers are outside this control."],
        },
        status="not_reproduced",
    )
    target = run / "reproduce/poc/control.js"
    shutil.rmtree(target.parent)
    target.parent.mkdir()
    target.write_text("// HIDDEN_POC_SOURCE\n")
    change(
        run,
        "reproduce/reproduce.json",
        outcome="not_reproduced",
        failure_type="runtime",
        target_artifact="reproduce/poc/control.js",
        build_argv=["node", "--check", "reproduce/poc/control.js"],
        poc_argv=["node", "reproduce/poc/control.js"],
        observed="All required malformed checks were rejected; the valid control passed.",
    )
    change(
        run,
        "validate/validate.json",
        outcome="not_confirmed",
        reason="An independent check observed the same results on the unchanged snapshot.",
    )
    for step in ("reproduce", "validate"):
        receipts = run / step / "receipts"
        shutil.rmtree(receipts)
        receipts.mkdir()
        for name, _, value, expected in CASES:
            (receipts / f"{name}.stdout").write_text(
                "PATCH_LOADED "
                + json.dumps({"path": str(target.resolve())})
                + "\n"
                + "PATCH_CASE "
                + json.dumps({"input": value, "actual": expected})
                + "\n"
                + "PATCH_REACHED\n"
            )
            (receipts / f"{name}.exit.json").write_text('{"exit_code": 0}\n')
        write_manifest(run / step)
    mapping = [
        {
            "check_id": name,
            "reproduce": {
                "stdout": f"reproduce/receipts/{name}.stdout",
                "exit": f"reproduce/receipts/{name}.exit.json",
            },
            "validate": {
                "stdout": f"validate/receipts/{name}.stdout",
                "exit": f"validate/receipts/{name}.exit.json",
            },
        }
        for name, _, _, _ in CASES
    ]
    metadata = {
        "run_type": "s0 control",
        "date": "2026-10-06",
        "model": "GPT-6 Astra",
        "reasoning_effort": "maximum",
        "elapsed_seconds": 92,
        "recorded_tokens": 5120,
    }
    change(
        run,
        "report-input.json",
        bug="The scoped parser behavior was checked on the unchanged control snapshot.",
        fix_why="No patch was made or required.",
        open_risks=["Behavior outside the declared boundary remains untested."],
        **({"run_metadata": metadata} if with_metadata else {}),
        **({"baseline_checks": mapping} if with_refs else {}),
    )
    return run


def test_report_input_assembles_retained_s0_case_receipts(tmp_path):
    run = s0_case(tmp_path)
    result = subprocess.run(
        [sys.executable, str(SCRIPT), "--prepare-input", str(run)],
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 0, result.stderr
    report_input = json.loads((run / "report-input.json").read_text())
    assert {entry["check_id"] for entry in report_input["baseline_checks"]} == {
        name for name, _, _, _ in CASES
    }
    output = (run / "report.html").read_text()
    assert "CONTROL PASSED" in output
    assert "The scoped bug was absent; valid controls passed; no patch was required." in output
    for entry in report_input["baseline_checks"]:
        for step in ("reproduce", "validate"):
            for path in entry[step].values():
                assert (run / path).is_file()
                assert f'href="#{Evidence(path, "", 0, "").anchor}"' in output


def test_missing_one_planned_reference_is_inconclusive_and_named(tmp_path):
    run = s0_case(tmp_path, with_refs=True)
    report_input = json.loads((run / "report-input.json").read_text())
    report_input["baseline_checks"] = report_input["baseline_checks"][:-1]
    (run / "report-input.json").write_text(json.dumps(report_input))
    output = render(run).read_text()
    assert "INCONCLUSIVE" in output
    assert "valid-payload" in output
    assert "CONTROL PASSED" not in output
    assert "valid-payload</th><td>Missing retained receipt" in output
    report_anchor = Evidence("report-input.json", "", 0, "").anchor
    assert f'href="#{report_anchor}">Report input</a>' in output


def test_raw_not_reproduced_without_receipt_mapping_cannot_pass(tmp_path):
    output = render(s0_case(tmp_path)).read_text()
    assert "INCONCLUSIVE" in output
    assert "CONTROL PASSED" not in output
    assert "empty-payload" in output


def test_control_pass_requires_a_planned_valid_control(tmp_path):
    run = s0_case(tmp_path, with_refs=True)
    finding = json.loads((run / "finding.json").read_text())
    finding["repair_scope"]["cases"] = finding["repair_scope"]["cases"][:-1]
    (run / "finding.json").write_text(json.dumps(finding))
    report_input = json.loads((run / "report-input.json").read_text())
    report_input["baseline_checks"] = report_input["baseline_checks"][:-1]
    (run / "report-input.json").write_text(json.dumps(report_input))
    output = render(run).read_text()
    assert "INCONCLUSIVE" in output
    assert "valid control" in output
    assert "CONTROL PASSED" not in output


def test_duplicate_representative_inputs_cannot_establish_a_class(tmp_path):
    run = s0_case(tmp_path, with_refs=True)
    finding = json.loads((run / "finding.json").read_text())
    finding["repair_scope"]["cases"][1]["input"] = {"raw": ""}
    (run / "finding.json").write_text(json.dumps(finding))
    for step in ("reproduce", "validate"):
        path = run / step / "receipts/trailing-separator.stdout"
        path.write_text(path.read_text().replace('"item::"', '""'))
        write_manifest(run / step)
    output = render(run).read_text()
    assert "INCONCLUSIVE" in output
    assert "distinct representative" in output
    assert "CONTROL PASSED" not in output


def test_first_screen_identity_case_brief_metadata_and_stage_links(tmp_path):
    output = render(s0_case(tmp_path, with_refs=True, with_metadata=True)).read_text()
    order = [
        "What happened",
        "What changed",
        "Verification",
        "Scope and limits",
        "Supporting evidence",
        "Earlier attempts",
    ]
    starts = [output.index(f">{title}</h2>") for title in order]
    assert starts == sorted(starts)
    first_screen = output[: output.index(">Supporting evidence</h2>")]
    for text in (
        "JavaScript parser control",
        "CONTROL PASSED",
        "Auditor review needed",
        "Unrelated parsers are outside this control.",
        "Recorded finding",
        "Receipts",
    ):
        assert text in first_screen
    assert re.search(r'<a href="#evidence-[a-f0-9]+">', first_screen)


def test_disclosure_and_static_report_contract(tmp_path):
    output = render(s0_case(tmp_path, with_refs=True)).read_text()
    assert "HIDDEN_POC_MARKER" not in output
    assert "HIDDEN_POC_SOURCE" not in output
    assert "<script" not in output.lower()
    assert not re.search(r"https?://|@import|url\(", output, re.I)
    assert (
        '<meta http-equiv="Content-Security-Policy" '
        "content=\"default-src 'none'; style-src 'unsafe-inline'\">"
    ) in output


def test_absent_run_metadata_is_omitted(tmp_path):
    run = s0_case(tmp_path, with_refs=True, with_metadata=True)
    report_input = json.loads((run / "report-input.json").read_text())
    del report_input["run_metadata"]
    (run / "report-input.json").write_text(json.dumps(report_input))
    output = render(run).read_text()
    assert "Model</" not in output
    assert "Reasoning effort</" not in output
    assert "Recorded tokens</" not in output
    assert output.count("Unavailable") == 0


def test_missing_retained_case_receipt_names_the_case_and_stage(tmp_path):
    run = s0_case(tmp_path, with_refs=True)
    (run / "validate/receipts/valid-payload.stdout").unlink()
    write_manifest(run / "validate")
    output = render(run).read_text()
    assert "INCONCLUSIVE" in output
    assert "validate valid-payload" in output
    assert "CONTROL PASSED" not in output


def test_ambiguous_receipts_are_not_wired_as_proof(tmp_path):
    run = s0_case(tmp_path)
    for step in ("reproduce", "validate"):
        receipts = run / step / "receipts"
        for suffix in ("stdout", "exit.json"):
            shutil.copyfile(
                receipts / f"empty-payload.{suffix}",
                receipts / f"duplicate-empty-payload.{suffix}",
            )
        write_manifest(run / step)
    result = subprocess.run(
        [sys.executable, str(SCRIPT), "--prepare-input", str(run)],
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 0, result.stderr
    report_input = json.loads((run / "report-input.json").read_text())
    assert "empty-payload" not in {row["check_id"] for row in report_input["baseline_checks"]}
    output = (run / "report.html").read_text()
    assert "INCONCLUSIVE" in output
    assert "missing baseline check references for empty-payload" in output


def test_poc_path_cannot_be_a_baseline_receipt_reference(tmp_path):
    run = s0_case(tmp_path, with_refs=True)
    report_input = json.loads((run / "report-input.json").read_text())
    report_input["baseline_checks"][0]["reproduce"]["stdout"] = "reproduce/poc/control.js"
    (run / "report-input.json").write_text(json.dumps(report_input))
    output = render(run).read_text()
    assert "INCONCLUSIVE" in output
    assert "check reference is not a receipt" in output
    assert "HIDDEN_POC_SOURCE" not in output


def test_no_patch_control_requires_final_assertion_marker(tmp_path):
    run = s0_case(tmp_path, with_refs=True)
    path = run / "reproduce/receipts/valid-payload.stdout"
    path.write_text("PATCH_REACHED\n" + path.read_text().replace("PATCH_REACHED\n", ""))
    write_manifest(run / "reproduce")
    output = render(run).read_text()
    assert "INCONCLUSIVE" in output
    assert "No patch required" not in output


def test_missing_native_case_observation_is_inconclusive(tmp_path):
    run = case(tmp_path)
    path = run / "prove/attempt-1/receipts/interior-patched.stdout"
    path.write_text("missing observation\n")
    write_manifest(path.parents[1])
    output = render(run).read_text()
    assert "INCONCLUSIVE" in output
    assert "REPAIR SUCCEEDED" not in output
    assert "assertion was not reached" in output


def test_retained_native_proof_allows_success(tmp_path):
    run = with_coverage(tmp_path)
    output = render(run).read_text()
    assert "REPAIR SUCCEEDED" in output
    assert "INCONCLUSIVE" not in output
    assert "Coverage unproven" not in output
    assert f'href="#{Evidence("prove/attempt-1/prove.json", "", 0, "").anchor}"' in output


def test_untrustworthy_native_case_evidence_is_inconclusive(tmp_path):
    for issue in ("missing_marker", "wrong_input", "missing_observation"):
        run = with_coverage(tmp_path / issue)
        result = run / "prove/attempt-1/receipts/interior-patched.stdout"
        content = result.read_text()
        if issue == "missing_marker":
            content = content.replace("PATCH_REACHED\n", "")
        elif issue == "wrong_input":
            content = content.replace("id:a:id:b", "other")
        else:
            content = "PATCH_REACHED\n"
        result.write_text(content)
        write_manifest(run / "prove/attempt-1")
        output = render(run).read_text()
        assert "INCONCLUSIVE" in output
        assert "REPAIR SUCCEEDED" not in output
        assert "Scoped case proof" in output


def test_malformed_case_observation_is_inconclusive(tmp_path):
    run = with_coverage(tmp_path)
    result = run / "prove/attempt-1/receipts/interior-patched.stdout"
    result.write_text("PATCH_CASE {malformed\nPATCH_REACHED\n")
    write_manifest(run / "prove/attempt-1")
    output = render(run).read_text()
    assert "INCONCLUSIVE" in output
    assert "interior patched" in output
    assert "REPAIR SUCCEEDED" not in output


def test_failed_focused_suite_prevents_repair_success(tmp_path):
    run = with_coverage(tmp_path)
    patch = json.loads((run / "patch/attempt-1/patch.json").read_text())
    patch["suite_after"]["failed"] = 1
    (run / "patch/attempt-1/patch.json").write_text(json.dumps(patch))
    write_manifest(run / "patch/attempt-1")
    output = render(run).read_text()
    assert "FAILED REPAIR" in output
    assert "Focused suite" in output
    assert "REPAIR SUCCEEDED" not in output


def test_inconclusive_revert_proof_does_not_become_failed_repair(tmp_path):
    run = with_coverage(tmp_path)
    change(run, "prove/attempt-1/prove.json", reverted="inconclusive")
    output = render(run).read_text()
    assert "INCONCLUSIVE" in output
    assert "FAILED REPAIR" not in output
    assert "Reverted arm: inconclusive" in output


def test_decisive_native_case_finding_fails_repair(tmp_path):
    run = with_coverage(tmp_path)
    proof_dir = run / "prove/attempt-1"
    result = proof_dir / "receipts/interior-patched.stdout"
    result.write_text(
        'PATCH_CASE {"input": ["id:a:id:b", "id:"], "actual": "wrong"}\nPATCH_REACHED\n'
    )
    path = proof_dir / "prove.json"
    data = json.loads(path.read_text())
    data["cases"][0]["runs"]["patched"]["exit_code"] = 1
    path.write_text(json.dumps(data))
    write_manifest(run / "prove/attempt-1")
    output = render(run).read_text()
    assert "FAILED REPAIR" in output
    assert "Scoped case proof" in output
    row = re.search(r'<tr id="check-cases".*?</tr>', output, re.S)
    assert row is not None and 'href="#evidence-' in row.group()
