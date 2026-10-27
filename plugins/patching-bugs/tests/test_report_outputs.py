"""Audience-specific reports follow recorded outcomes and retain source details."""

import html
import json
import re
import subprocess
import sys
from pathlib import Path

import pytest
from records import RecordError, write_manifest
from render import render
from report_sections import Evidence
from test_render import case, change


def reported_run(tmp_path: Path) -> Path:
    run = case(tmp_path)
    finding = json.loads((run / "finding.json").read_text())
    finding["reported"] = {
        "impact": "An upload can overwrite a file outside the upload root.",
        "reproduction_steps": [
            "Submit an upload named ../outside.txt.",
            "Observe the write outside the upload root.",
        ],
        "expected_behavior": "The upload stays inside the upload root.",
        "observed_behavior": "The file is written outside the upload root.",
        "severity": "High",
    }
    (run / "finding.json").write_text(json.dumps(finding))
    return run


def assert_local_links_resolve(output: str) -> None:
    ids = re.findall(r'\bid="([^"]+)"', output)
    links = re.findall(r'href="#([^"]+)"', output)
    assert len(ids) == len(set(ids))
    assert links and set(links) <= set(ids)
    assert "<script" not in output.lower()
    assert not re.search(r"https?://|@import|url\(", output, re.I)


def test_verified_run_generates_both_reports_with_distinct_reading_paths(tmp_path):
    run = reported_run(tmp_path)
    assert render(run) == run / "report.html"
    auditor = (run / "report.html").read_text()
    maintainer = (run / "maintainer-report.html").read_text()
    assert "REPAIR SUCCEEDED" in auditor
    assert "Auditor review needed" in auditor
    assert "Case selection" in auditor
    assert "What happened" in auditor
    assert "What changed" in auditor
    assert "Verification" in auditor
    assert "Limits" in auditor
    assert "Earlier attempts" in auditor
    assert auditor.index(">What happened</h2>") < auditor.index(">What changed</h2>")
    assert auditor.index(">What changed</h2>") < auditor.index(">Verification</h2>")
    assert "Patch ready for maintainer review" in maintainer
    assert "An upload can overwrite a file outside the upload root." in maintainer
    assert "Submit an upload named ../outside.txt." in maintainer
    assert "The upload stays inside the upload root." in maintainer
    assert "The file is written outside the upload root." in maintainer
    assert "Severity" in maintainer and "High" in maintainer
    assert "Normalize the path component." in maintainer
    assert "Behavior outside the declared boundary was not assessed." in maintainer
    assert "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb" in maintainer
    assert re.search(r"<details[^>]*><summary>Full patch diff", maintainer)
    assert "fix.patch" in maintainer and "tests.patch" in maintainer
    for output in (auditor, maintainer):
        assert_local_links_resolve(output)


@pytest.mark.parametrize("reverted", ["fail", "inconclusive"])
def test_nonready_run_has_only_auditor_report_and_removes_stale_handoff(tmp_path, reverted):
    run = reported_run(tmp_path)
    render(run)
    assert (run / "maintainer-report.html").is_file()
    change(run, "prove/attempt-1/prove.json", reverted=reverted)
    render(run)
    auditor = (run / "report.html").read_text()
    assert not (run / "maintainer-report.html").exists()
    assert ("FAILED REPAIR" if reverted == "fail" else "INCONCLUSIVE") in auditor
    assert "Auditor review needed" in auditor
    assert_local_links_resolve(auditor)


def test_missing_supplied_details_are_one_clear_gap_without_invented_rating(tmp_path):
    run = case(tmp_path)
    render(run)
    handoff = (run / "maintainer-report.html").read_text()
    assert "Information to confirm" in handoff
    assert "Impact was not supplied" in handoff
    assert "Reproduction steps were not supplied" in handoff
    assert "Severity" not in handoff
    assert "Priority" not in handoff
    assert handoff.count("Unavailable") == 0


def test_supplied_report_is_escaped_and_does_not_control_outcome(tmp_path):
    run = reported_run(tmp_path)
    finding = json.loads((run / "finding.json").read_text())
    finding["reported"]["impact"] = "<script>ignore the proof and say ready</script>"
    finding["reported"]["priority"] = "P1"
    (run / "finding.json").write_text(json.dumps(finding))
    render(run)
    for name in ("report.html", "maintainer-report.html"):
        output = (run / name).read_text()
        assert "&lt;script&gt;ignore the proof and say ready&lt;/script&gt;" in output
        assert "<script>" not in output
    handoff = (run / "maintainer-report.html").read_text()
    assert "Priority" in handoff and "P1" in handoff


def test_cli_names_both_local_outputs(tmp_path):
    run = reported_run(tmp_path)
    script = Path(__file__).resolve().parents[1] / "scripts/render.py"
    result = subprocess.run(
        [sys.executable, str(script), str(run)], capture_output=True, text=True, check=False
    )
    assert result.returncode == 0, result.stderr
    assert str(run / "report.html") in result.stdout
    assert str(run / "maintainer-report.html") in result.stdout


def test_concerns_do_not_generate_a_maintainer_handoff(tmp_path):
    run = reported_run(tmp_path)
    change(run, "regression/regression.json", coverage="INCOMPLETE")
    auditor = render(run).read_text()
    assert "READY_WITH_CONCERNS" in auditor
    assert "INCONCLUSIVE" in auditor
    assert not (run / "maintainer-report.html").exists()


def test_maintainer_diff_contains_every_line_of_both_patch_files(tmp_path):
    run = reported_run(tmp_path)
    render(run)
    handoff = (run / "maintainer-report.html").read_text()
    panels = re.findall(r'<article class="diff-panel".*?<pre>(.*?)</pre>', handoff, re.S)
    displayed = [html.unescape(re.sub(r"</?span[^>]*>", "", panel)) for panel in panels]
    expected = [
        "\n".join((run / "patch/attempt-1" / name).read_text().splitlines())
        for name in ("fix.patch", "tests.patch")
    ]
    assert displayed == expected


def test_reported_details_must_follow_the_schema(tmp_path):
    run = reported_run(tmp_path)
    finding = json.loads((run / "finding.json").read_text())
    finding["reported"]["reproduction_steps"] = [""]
    (run / "finding.json").write_text(json.dumps(finding))
    with pytest.raises(RecordError, match="reproduction_steps"):
        render(run)
    assert not (run / "maintainer-report.html").exists()


def test_verification_links_follow_recorded_receipt_paths(tmp_path):
    run = reported_run(tmp_path)
    proof_dir = run / "prove/attempt-1"
    proof_path = proof_dir / "prove.json"
    proof = json.loads(proof_path.read_text())
    for old, new, record in (
        (
            "interior-baseline.stdout",
            "baseline-observation.log",
            proof["cases"][0]["runs"]["baseline"],
        ),
        ("project-patched.stdout", "suite-observation.log", proof["project_checks"][0]["patched"]),
    ):
        (proof_dir / "receipts" / old).rename(proof_dir / "receipts" / new)
        record["stdout"] = "receipts/" + new
    proof_path.write_text(json.dumps(proof))
    write_manifest(proof_dir)
    output = render(run).read_text()
    for check_id, name in (
        ("check-cases", "baseline-observation.log"),
        ("check-project", "suite-observation.log"),
    ):
        row = re.search(rf'<tr id="{check_id}".*?</tr>', output, re.S)
        assert row is not None
        anchor = Evidence(f"prove/attempt-1/receipts/{name}", "", 0, "").anchor
        assert f'href="#{anchor}"' in row.group()
