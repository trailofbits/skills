#!/usr/bin/env python3
"""Tests for the REPORT.md renderer."""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent))

from findings_model import UNVALIDATED_MARKER, reported_findings  # noqa: E402
from generate_sarif import build_sarif  # noqa: E402
from render_report import main, render  # noqa: E402


def finding(**overrides):
    base = {
        "id": "BOF-001",
        "bug_class": "buffer-overflow",
        "title": "Missing bounds check",
        "file": "src/parse.c",
        "line": 142,
        "function": "parse_header",
        "confidence": "High",
        "description": "len comes from the network header and is never bounded.",
        "code": "memcpy(buf, src, len);",
        "data_flow": "source: recv_request; sink: memcpy; validation: none",
        "reachability": "recv_request -> dispatch -> parse_header",
        "impact": "Heap overflow with attacker-controlled length.",
        "mitigations_checked": "FORTIFY not applied at this site",
        "recommendation": "Bound len against sizeof(buf).",
        "fp_verdict": "TRUE_POSITIVE",
        "fp_rationale": "src/parse.c:142 has no bound",
        "severity": "HIGH",
        "attack_vector": "Remote",
        "exploitability": "Reliable",
        "severity_rationale": "reliable remote heap write",
        "severity_validated": True,
    }
    base.update(overrides)
    return base


def doc(findings, coverage=None, **run):
    run_block = {
        "threat_model": "REMOTE",
        "severity_filter": "all",
        "finding_scope_root": "src",
        "context_roots": ".",
        "is_cpp": False,
        "is_posix": True,
        "is_windows": False,
    }
    run_block.update(run)
    return {
        "run": run_block,
        "stats": {"merged": 0},
        "findings": findings,
        "coverage": coverage or [],
    }


def test_platform_flags_render_as_json_booleans():
    out = render(doc([finding()]))
    assert "is_cpp=false, is_posix=true, is_windows=false" in out


def test_frontmatter_and_counts():
    out = render(doc([finding()]))
    assert out.startswith("---\nstage: final-report\n")
    assert "threat_model: REMOTE" in out
    assert "total_primaries: 1" in out
    assert "reported_findings: 1" in out


def test_high_severity_body_is_embedded():
    out = render(doc([finding()]))
    assert "## HIGH (1)" in out
    assert "### BOF-001 — Missing bounds check" in out
    assert "memcpy(buf, src, len);" in out
    assert "**Data flow**" in out
    assert "**Impact**" in out


def test_low_severity_body_is_summarised_not_embedded():
    out = render(doc([finding(severity="LOW")]))
    assert "## LOW (1)" in out
    assert "**Recommendation**" in out
    assert "**Data flow**" not in out


def test_rejected_primaries_land_in_a_not_reported_table():
    findings = [finding(), finding(id="BOF-002", fp_verdict="FALSE_POSITIVE", severity=None)]
    out = render(doc(findings))
    assert "## Not reported" in out
    assert "BOF-002" in out.split("## Not reported")[1]


def test_merged_duplicate_is_not_listed_twice():
    findings = [finding(also_known_as=["BOF-002"]), finding(id="BOF-002", merged_into="BOF-001")]
    out = render(doc(findings))
    assert "**Also reported as:** BOF-002" in out
    assert "## Not reported" not in out


def test_zero_findings_still_renders_a_report():
    out = render(doc([]))
    assert "No findings passed" in out
    assert "reported_findings: 0" in out


def test_failed_group_is_surfaced_as_a_warning():
    out = render(doc([finding()], groups_failed=["concurrency"]))
    assert "## Run warnings" in out
    assert "uncovered" in out
    assert "`concurrency`" in out


def test_unjudged_finding_is_labelled():
    out = render(doc([finding(severity_validated=False)], unjudged_findings=["BOF-001"]))
    assert UNVALIDATED_MARKER in out
    assert "unvalidated severity" in out


def test_hunter_notes_reach_the_report():
    out = render(doc([finding()], hunter_notes=["arithmetic: could not read generated headers"]))
    assert "could not read generated headers" in out


def test_coverage_table_is_labelled_self_reported():
    coverage = [
        {
            "group": "memory-bounds",
            "bug_class": "buffer-overflow",
            "outcome": "reported",
            "population": "31 memcpy sites",
            "evidence": "src/parse.c:142",
        }
    ]
    out = render(doc([finding()], coverage=coverage))
    assert "## Coverage (self-reported, unverified)" in out
    assert "Nothing downstream validates them" in out
    assert "src/parse.c:142" in out


def test_pipe_in_text_does_not_break_the_table():
    coverage = [
        {
            "group": "g",
            "bug_class": "c",
            "outcome": "reported",
            "population": "a|b",
            "evidence": "x|y",
        }
    ]
    out = render(doc([finding()], coverage=coverage))
    row = next(line for line in out.splitlines() if "a\\|b" in line)
    # 5 cells => 6 unescaped delimiters. The pipes inside the text must be escaped
    # so they do not create phantom columns.
    unescaped = len(re.findall(r"(?<!\\)\|", row))
    assert unescaped == 6


def test_outside_class_findings_are_flagged():
    out = render(doc([finding(outside_assigned_classes=True)]))
    assert "outside the finder's assigned bug classes" in out


def test_report_and_sarif_describe_the_same_set():
    # The two renderers previously applied the survivor/filter rules separately,
    # which is how they drifted apart. Both now go through reported_findings().
    findings = [
        finding(id="A", severity="HIGH"),
        finding(id="B", severity="LOW"),
        finding(id="C", fp_verdict="LIKELY_FP", severity=None),
        finding(id="D", merged_into="A"),
    ]
    d = doc(findings, severity_filter="medium")
    expected = {f["id"] for f in reported_findings(d)}
    sarif_ids = {r["properties"]["finding_id"] for r in build_sarif(d)["runs"][0]["results"]}
    md = render(d)
    assert expected == {"A"}
    assert sarif_ids == expected
    for fid in expected:
        assert f"### {fid} —" in md
    assert "### B —" not in md


def test_main_writes_report(tmp_path):
    src = tmp_path / "findings.json"
    src.write_text(json.dumps(doc([finding()])), encoding="utf-8")
    assert main(["--findings", str(src), "--output-dir", str(tmp_path)]) == 0
    assert "# C/C++ Security Review" in (tmp_path / "REPORT.md").read_text()


def test_main_exits_non_zero_on_bad_input(tmp_path, capsys):
    src = tmp_path / "findings.json"
    src.write_text("{nope", encoding="utf-8")
    assert main(["--findings", str(src), "--output-dir", str(tmp_path)]) == 2
    assert "render_report:" in capsys.readouterr().err
    assert not (tmp_path / "REPORT.md").exists()


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-q"]))
