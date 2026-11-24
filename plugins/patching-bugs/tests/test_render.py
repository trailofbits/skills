import html
import json
import re
import shutil
import subprocess
import sys
from pathlib import Path

import pytest
from records import RecordError, check, write_manifest
from render import _evidence, render
from report_sections import Evidence, evidence_html, evidence_label

FIXTURE = Path(__file__).parent / "fixtures/run-ready"


def case(tmp_path):
    run = tmp_path / "run"
    shutil.copytree(FIXTURE, run)
    return run


def change(run, rel, **fields):
    path = run / rel
    record = json.loads(path.read_text())
    record.update(fields)
    path.write_text(json.dumps(record))
    if path.parent != run:
        write_manifest(path.parent)


def test_render_is_deterministic_and_hides_poc(tmp_path):
    run = case(tmp_path)
    first = render(run).read_bytes()
    second = render(run).read_bytes()
    assert first == second
    assert b">REPAIR SUCCEEDED</p>" in first
    assert b"Automated patch verdict:</strong> READY" in first
    assert b"print(&quot;PATCH_REACHED&quot;)" not in first
    assert b"<script>" not in first


def test_untrusted_text_is_escaped(tmp_path):
    run = case(tmp_path)
    change(run, "report-input.json", bug="<script>alert(1)</script> \u202e")
    (run / "reproduce/receipts/poc.txt").write_text("<script>alert(1)</script>\n")
    write_manifest(run / "reproduce")
    output = render(run).read_text()
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in output
    assert "\\u202e" in output
    assert "<script>" not in output


def test_long_prose_refused(tmp_path):
    run = case(tmp_path)
    change(run, "report-input.json", bug="One. Two. Three. Four.")
    with pytest.raises(RecordError, match="sentence"):
        render(run)


def test_tampered_receipt_refused(tmp_path):
    run = case(tmp_path)
    (run / "reproduce/receipts/poc.txt").write_text("changed")
    with pytest.raises(RecordError, match=r"poc\.txt"):
        render(run)


def test_not_ready_without_regression_renders(tmp_path):
    run = case(tmp_path)
    change(run, "prove/attempt-1/prove.json", reverted="fail")
    shutil.rmtree(run / "regression")
    assert "Automated patch verdict:</strong> NOT_READY" in render(run).read_text()


def test_not_reproduced_without_patch_or_proof_renders(tmp_path):
    run = case(tmp_path)
    change(run, "run.json", attempts=0, status="not_reproduced")
    change(run, "reproduce/reproduce.json", outcome="not_reproduced")
    shutil.rmtree(run / "patch")
    shutil.rmtree(run / "prove")
    output = render(run).read_text()
    assert "Automated patch verdict:</strong> NOT_REPRODUCED" in output
    assert "INCONCLUSIVE" in output


def test_proof_rows_and_checklist_show_results(tmp_path):
    run = case(tmp_path)
    output = render(run).read_text()
    for label in (
        "Reproduction",
        "Independent validation",
        "Three-arm proof",
        "Scoped case proof",
        "Project checks",
        "Build identity",
        "Variants",
        "Focused suite",
        "Regression outcomes",
    ):
        assert label in output
    assert "Patched behavior did not reproduce the bug" in output
    assert "Reverted behavior reproduced the bug" in output
    assert "Required checks produced usable evidence" in output
    assert "No variants recorded" in output
    assert "Before: 9 passed, 1 failed; after: 10 passed, 0 failed" in output
    assert "0 reproduced; 0 incomplete fix; 0 unresolved; 0 reviewed" in output
    assert 'href="#evidence-' in output


def test_poc_is_omitted_from_all_evidence_when_disabled(tmp_path):
    run = case(tmp_path)
    finding = run / "finding.json"
    record = json.loads(finding.read_text())
    record["poc"] = "SECRET_POC_TEXT"
    finding.write_text(json.dumps(record))
    (run / "reproduce/poc/poc.py").write_text("SECRET_POC_SOURCE")
    write_manifest(run / "reproduce")
    output = render(run).read_text()
    assert "SECRET_POC_TEXT" not in output
    assert "SECRET_POC_SOURCE" not in output


def test_nested_manifest_cannot_read_outside_file(tmp_path):
    run = case(tmp_path)
    (tmp_path / "outside.txt").write_text("OUTSIDE_SECRET")
    poc_receipts = run / "reproduce/poc/receipts"
    poc_receipts.mkdir()
    (run / "reproduce/poc/manifest.json").write_text(
        json.dumps({"files": {"receipts/../../../../outside.txt": "fake"}})
    )
    write_manifest(run / "reproduce")
    output = render(run).read_text()
    assert "OUTSIDE_SECRET" not in output


def test_step_manifest_traversal_is_rejected_by_evidence_reader(tmp_path):
    run = case(tmp_path)
    manifest = run / "reproduce/manifest.json"
    data = json.loads(manifest.read_text())
    data["files"]["receipts/../../../../outside.txt"] = "fake"
    manifest.write_text(json.dumps(data))
    with pytest.raises(RecordError, match="unsafe"):
        _evidence(run)


def test_poc_named_manifest_does_not_crash_cli(tmp_path):
    run = case(tmp_path)
    (run / "reproduce/poc/manifest.json").write_text("PoC source, not JSON")
    write_manifest(run / "reproduce")
    script = Path(__file__).resolve().parents[1] / "scripts/render.py"
    result = subprocess.run(
        [sys.executable, str(script), str(run)], capture_output=True, text=True, check=False
    )
    assert result.returncode == 0, result.stderr
    assert "Traceback" not in result.stderr


def test_failed_build_null_hash_renders_not_ready(tmp_path):
    run = case(tmp_path)
    change(
        run,
        "prove/attempt-1/prove.json",
        hashes={
            "baseline": "1" * 64,
            "patched": None,
            "reverted": "1" * 64,
        },
        build_identity="fail",
    )
    shutil.rmtree(run / "regression")
    check(run)
    output = render(run).read_text()
    assert "FAILED REPAIR" in output
    assert "Build identity" in output


@pytest.mark.parametrize(
    "char",
    ["\u200b", "\u200c", "\u200d", "\u200e", "\u200f", "\u061c", "\ufeff", "\u2028", "\u2029"],
)
def test_invisible_characters_are_visible(tmp_path, char):
    run = case(tmp_path)
    change(run, "report-input.json", bug=f"Before{char}after")
    assert f"\\u{ord(char):04x}" in render(run).read_text()


def test_binary_patch_renders_with_replacement_character(tmp_path):
    run = case(tmp_path)
    (run / "patch/attempt-1/fix.patch").write_bytes(b"@@ -1 +1 @@\n+\xff\n")
    write_manifest(run / "patch/attempt-1")
    assert "\ufffd" in render(run).read_text()


def test_each_changed_file_links_to_its_own_diff(tmp_path):
    run = case(tmp_path)
    (run / "patch/attempt-1/fix.patch").write_text(
        "diff --git a/one.py b/one.py\n--- a/one.py\n+++ b/one.py\n"
        "@@ -1 +1 @@\n-old\n+new\n"
        "diff --git a/two.py b/two.py\n--- a/two.py\n+++ b/two.py\n"
        "@@ -2 +2 @@\n-before\n+after\n"
    )
    write_manifest(run / "patch/attempt-1")
    output = render(run).read_text()
    assert '<a href="#diff-file-0">one.py</a>' in output
    assert '<a href="#diff-file-1">two.py</a>' in output
    assert 'id="diff-file-0"><h3>one.py</h3>' in output
    assert 'id="diff-file-1"><h3>two.py</h3>' in output


def test_diff_lines_are_preserved_in_order(tmp_path):
    run = case(tmp_path)
    output = render(run).read_text()
    panels = re.findall(r'<article class="diff-panel".*?<pre>(.*?)</pre>', output, re.S)
    displayed = [html.unescape(re.sub(r"</?span[^>]*>", "", panel)) for panel in panels]
    expected = [
        "\n".join((run / "patch/attempt-1" / name).read_text().splitlines())
        for name in ("fix.patch", "tests.patch")
    ]
    assert displayed == expected


def test_incomplete_fix_is_visible_in_regression_check(tmp_path):
    run = case(tmp_path)
    change(
        run,
        "regression/regression.json",
        outcomes=[
            {
                "candidate_id": "c1",
                "outcome": "INCOMPLETE_FIX",
                "decision_receipt": "decision.txt",
            }
        ],
    )
    output = render(run).read_text()
    check_block = re.search(r'<tr id="check-regression-outcomes".*?</tr>', output, re.S)
    assert check_block is not None
    assert "1 incomplete fix" in check_block.group()
    assert "state-fail" in check_block.group()


def test_failed_patch_without_commit_or_diff_renders_not_ready(tmp_path):
    run = case(tmp_path)
    change(run, "patch/attempt-1/patch.json", patch_commit=None)
    (run / "patch/attempt-1/fix.patch").unlink()
    (run / "patch/attempt-1/tests.patch").unlink()
    write_manifest(run / "patch/attempt-1")
    shutil.rmtree(run / "prove")
    shutil.rmtree(run / "regression")
    output = render(run).read_text()
    assert "FAILED REPAIR" in output
    assert "No patch commit recorded" in output


def test_report_contains_native_records_and_receipts(tmp_path):
    output = render(case(tmp_path)).read_text()
    assert "prove/attempt-1/prove.json" in output
    assert "prove/attempt-1/receipts/interior-baseline.stdout" in output
    assert "prove/attempt-1/receipts/project-patched.stdout" in output
    assert "Behavior outside the declared boundary was not assessed" in output


def test_report_navigation_and_local_resources(tmp_path):
    output = render(case(tmp_path)).read_text()
    ids = re.findall(r'\bid="([^"]+)"', output)
    links = re.findall(r'href="#([^"]+)"', output)
    assert len(ids) == len(set(ids))
    assert links and set(links) <= set(ids)
    assert [
        target
        for target in links
        if target in {"outcome", "change", "verification", "limits", "evidence", "attempts"}
    ][:6] == ["outcome", "change", "verification", "limits", "evidence", "attempts"]
    assert '<table class="checks">' in output
    assert "<th>Recorded finding</th>" in output
    assert "<script" not in output.lower()
    assert not re.search(r"https?://|@import|url\(", output, re.I)
    assert (
        '<meta http-equiv="Content-Security-Policy" '
        "content=\"default-src 'none'; style-src 'unsafe-inline'\">"
    ) in output


def test_conclusion_has_established_and_unestablished_evidence(tmp_path):
    run = case(tmp_path)
    path = run / "prove/attempt-1/receipts/interior-patched.stdout"
    path.write_text("observation missing\n")
    write_manifest(path.parents[1])
    output = render(run).read_text()
    summary = output.split('class="summary', 1)[1].split("</div>", 1)[0]
    assert "INCONCLUSIVE" in summary
    assert "Auditor review needed" in summary
    assert "What remains unproven" in output
    check_row = re.search(r'<tr id="check-cases".*?</tr>', output, re.S)
    assert check_row is not None
    assert "assertion was not reached" in check_row.group()
    assert "Behavior outside the declared boundary" in output
    assert not (run / "maintainer-report.html").exists()


def test_conclusion_names_both_findings_and_gaps(tmp_path):
    run = case(tmp_path)
    proof_dir = run / "prove/attempt-1"
    path = proof_dir / "receipts/interior-patched.stdout"
    path.write_text(
        'PATCH_CASE {"input": ["id:a:id:b", "id:"], "actual": "wrong"}\nPATCH_REACHED\n'
    )
    proof_path = proof_dir / "prove.json"
    proof = json.loads(proof_path.read_text())
    proof["cases"][0]["runs"]["patched"]["exit_code"] = 1
    proof_path.write_text(json.dumps(proof))
    (proof_dir / "receipts/repeated-patched.stdout").write_text("observation missing\n")
    write_manifest(proof_dir)
    output = render(run).read_text()
    assert "FAILED REPAIR" in output
    assert "scoped failure remains" in output
    assert "repeated patched" in output
    assert not (run / "maintainer-report.html").exists()


def test_verification_rows_show_status_and_receipts(tmp_path):
    output = render(case(tmp_path)).read_text()
    rows = re.findall(r'<tr id="check-[^"]+".*?</tr>', output, re.S)
    assert len(rows) >= 8
    assert all(
        re.search(r"(?:✓ Pass|! Caution|✗ Fail|! Inconclusive|\u2013 Not applicable)", row)
        for row in rows
    )
    assert all('href="#evidence-' in row for row in rows)
    assert "Scoped case proof" in output
    assert "Project checks" in output


@pytest.mark.parametrize(
    ("statuses", "expected"),
    [(["fixed"], "✓ Pass"), (["fixed", "not_fixed"], "! Caution")],
)
def test_nonempty_variant_statuses(tmp_path, statuses, expected):
    run = case(tmp_path)
    variants = [
        {"location": f"variant-{index}.py", "status": status, "reason": "Recorded result"}
        for index, status in enumerate(statuses)
    ]
    change(run, "patch/attempt-1/patch.json", variants=variants)
    output = render(run).read_text()
    fixed = statuses.count("fixed")
    assert f"Variants: {fixed}/{len(statuses)} fixed." in output
    if "not_fixed" in statuses:
        assert "variant-1.py: Recorded result." in output
    assert expected in output


@pytest.mark.parametrize(
    ("path", "expected"),
    [
        ("reproduce/receipts/poc.stdout", "Standard output of poc"),
        ("validate/receipts/build.stderr", "Standard error of build"),
        ("patch/attempt-1/receipts/focused-after.exit", "Exit status of focused-after"),
        ("validate/receipts/build.status.json", "Exit status of build"),
        ("validate/validate.json", "Validation record"),
        ("patch/attempt-1/patch.json", "Patch record"),
        ("reproduce/poc/poc.py", "Proof-of-concept source"),
        ("patch/attempt-1/receipts/helper.py", "Helper script used by this step"),
        ("regression/receipts/decision.json", "Regression decision record"),
        ("prove/attempt-1/receipts/case.stdout", "Standard output of case"),
        ("reproduce/receipts/unknown.dat", "Receipt file"),
    ],
)
def test_evidence_label_from_path(path, expected):
    assert evidence_label(path) == expected


def test_evidence_label_is_shown_under_path():
    item = Evidence("reproduce/receipts/poc.stdout", "output", 6, "a" * 64, True)
    _, detail = evidence_html([item], {})
    assert re.search(
        r"<h4>reproduce/receipts/poc.stdout</h4>"
        r'<p class="evidence-label">Standard output of poc</p>',
        detail,
    )


def test_verification_links_to_specific_retained_receipts(tmp_path):
    output = render(case(tmp_path)).read_text()
    assert output.index('id="check-reproduction"') < output.index('id="check-validation"')
    assert output.index('id="check-validation"') < output.index('id="check-arms"')
    assert "prove/attempt-1/receipts/interior-baseline.stdout" in output
    assert "prove/attempt-1/receipts/project-patched.stdout" in output
    for anchor in ("check-cases", "check-project", "check-arms"):
        row = re.search(rf'<tr id="{anchor}".*?</tr>', output, re.S)
        assert row is not None
        assert 'href="#evidence-' in row.group()
    assert "Step manifest SHA-256" not in output


def test_diff_and_full_receipts_are_collapsed(tmp_path):
    output = render(case(tmp_path)).read_text()
    css = output.split("<style>", 1)[1].split("</style>", 1)[0]
    assert ".diff-panel pre" in css
    assert ".add{" in css
    assert "<summary>Full patch diff</summary>" in output
    assert "Full retained content" in output
    assert "SHA-256" in output


def test_cli_rejects_bad_record_without_traceback(tmp_path):
    run = case(tmp_path)
    (run / "report-input.json").write_text("{bad json")
    script = Path(__file__).resolve().parents[1] / "scripts/render.py"
    result = subprocess.run(
        [sys.executable, str(script), str(run)], capture_output=True, text=True, check=False
    )
    assert result.returncode == 1
    assert len(result.stderr.splitlines()) == 1
    assert "Traceback" not in result.stderr
