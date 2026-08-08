#!/usr/bin/env python3
"""Tests for findings_model loading/selection and the SARIF generator."""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent))

import findings_model  # noqa: E402
from findings_model import FindingsError, load, reported_findings  # noqa: E402
from generate_sarif import build_sarif, main  # noqa: E402


def finding(**overrides):
    base = {
        "id": "BOF-001",
        "bug_class": "buffer-overflow",
        "title": "Missing bounds check",
        "file": "src/parse.c",
        "line": 142,
        "function": "parse_header",
        "confidence": "High",
        "description": "d",
        "code": "memcpy(buf, src, len);",
        "impact": "i",
        "recommendation": "r",
        "fp_verdict": "TRUE_POSITIVE",
        "fp_rationale": "src/parse.c:142 has no bound",
        "severity": "HIGH",
        "attack_vector": "Remote",
        "exploitability": "Reliable",
        "severity_validated": True,
    }
    base.update(overrides)
    return base


def doc(findings, **run):
    run_block = {"threat_model": "REMOTE", "severity_filter": "all", "finding_scope_root": "src"}
    run_block.update(run)
    return {"run": run_block, "stats": {}, "findings": findings, "coverage": []}


def write(tmp_path: Path, payload) -> Path:
    path = tmp_path / "findings.json"
    path.write_text(
        json.dumps(payload) if not isinstance(payload, str) else payload, encoding="utf-8"
    )
    return path


# ------------------------------------------------------------------ loader


def test_load_rejects_missing_file(tmp_path):
    with pytest.raises(FindingsError, match="not found"):
        load(tmp_path / "nope.json")


def test_load_rejects_empty_file(tmp_path):
    with pytest.raises(FindingsError, match="empty"):
        load(write(tmp_path, ""))


def test_load_rejects_truncated_json(tmp_path):
    # The realistic failure: an agent transcribed the document into a heredoc and
    # it was cut short. Reporting a clean empty report here would hide the loss.
    with pytest.raises(FindingsError, match="truncated"):
        load(write(tmp_path, '{"findings": [{"id": "BOF-0'))


def test_load_rejects_non_object(tmp_path):
    with pytest.raises(FindingsError, match="expected a JSON object"):
        load(write(tmp_path, [1, 2, 3]))


def test_load_rejects_missing_findings_key(tmp_path):
    with pytest.raises(FindingsError, match="no 'findings' key"):
        load(write(tmp_path, {"run": {}}))


def test_load_rejects_non_list_findings(tmp_path):
    with pytest.raises(FindingsError, match="must be a list"):
        load(write(tmp_path, {"findings": {}}))


def test_load_accepts_empty_findings_list(tmp_path):
    loaded = load(write(tmp_path, doc([])))
    assert loaded["findings"] == []


def test_load_from_stdin(tmp_path, monkeypatch):
    monkeypatch.setattr("sys.stdin", __import__("io").StringIO(json.dumps(doc([finding()]))))
    assert len(load("-")["findings"]) == 1


# -------------------------------------------------------- reported selection


def test_merged_findings_are_not_reported():
    d = doc([finding(), finding(id="BOF-002", merged_into="BOF-001")])
    assert [f["id"] for f in reported_findings(d)] == ["BOF-001"]


@pytest.mark.parametrize("verdict", ["LIKELY_FP", "FALSE_POSITIVE", "OUT_OF_SCOPE"])
def test_rejected_verdicts_are_not_reported(verdict):
    d = doc([finding(fp_verdict=verdict, severity=None)])
    assert reported_findings(d) == []


@pytest.mark.parametrize("verdict", ["TRUE_POSITIVE", "LIKELY_TP"])
def test_survivor_verdicts_are_reported(verdict):
    assert len(reported_findings(doc([finding(fp_verdict=verdict)]))) == 1


def test_severity_filter_drops_lower_tiers():
    findings = [finding(id="A", severity="LOW"), finding(id="B", severity="HIGH")]
    assert [f["id"] for f in reported_findings(doc(findings, severity_filter="high"))] == ["B"]
    assert len(reported_findings(doc(findings, severity_filter="all"))) == 2


def test_unvalidated_severity_survives_a_strict_filter():
    # Its severity is a placeholder no judge assigned, so filtering on it would
    # drop a finding on the strength of a guess.
    f = finding(id="U", severity="LOW", severity_validated=False)
    assert [x["id"] for x in reported_findings(doc([f], severity_filter="high"))] == ["U"]


def test_reported_sorted_by_severity_then_id():
    findings = [
        finding(id="B", severity="LOW"),
        finding(id="A", severity="CRITICAL"),
        finding(id="C", severity="CRITICAL"),
    ]
    assert [f["id"] for f in reported_findings(doc(findings))] == ["A", "C", "B"]


# --------------------------------------------------------------- sarif shape


def test_sarif_basic_shape():
    sarif = build_sarif(doc([finding()]))
    assert sarif["version"] == "2.1.0"
    run = sarif["runs"][0]
    assert run["tool"]["driver"]["name"] == "c-review"
    assert "%SRCROOT%" in run["originalUriBaseIds"]
    assert len(run["results"]) == 1
    result = run["results"][0]
    assert result["ruleId"] == "buffer-overflow"
    assert result["level"] == "error"
    loc = result["locations"][0]["physicalLocation"]
    assert loc["artifactLocation"]["uri"] == "src/parse.c"
    assert loc["region"]["startLine"] == 142
    assert result["properties"]["finding_id"] == "BOF-001"


@pytest.mark.parametrize(
    ("severity", "level"),
    [("CRITICAL", "error"), ("HIGH", "error"), ("MEDIUM", "warning"), ("LOW", "note")],
)
def test_severity_maps_to_sarif_level(severity, level):
    sarif = build_sarif(doc([finding(severity=severity)]))
    assert sarif["runs"][0]["results"][0]["level"] == level


def test_start_line_is_clamped_to_one():
    # SARIF region.startLine has a schema minimum of 1; a 0 would make the whole
    # file fail strict validation and GitHub code-scanning ingestion.
    sarif = build_sarif(doc([finding(line=0)]))
    assert (
        sarif["runs"][0]["results"][0]["locations"][0]["physicalLocation"]["region"]["startLine"]
        == 1
    )


def test_leading_dot_slash_stripped_from_uri():
    sarif = build_sarif(doc([finding(file="./src/parse.c")]))
    assert (
        sarif["runs"][0]["results"][0]["locations"][0]["physicalLocation"]["artifactLocation"][
            "uri"
        ]
        == "src/parse.c"
    )


def test_zero_findings_produces_valid_empty_sarif():
    sarif = build_sarif(doc([]))
    assert sarif["runs"][0]["results"] == []
    assert sarif["runs"][0]["tool"]["driver"]["rules"] == []


def test_rule_level_is_the_worst_severity_in_the_class():
    findings = [finding(id="A", severity="LOW"), finding(id="B", severity="CRITICAL")]
    rules = build_sarif(doc(findings))["runs"][0]["tool"]["driver"]["rules"]
    assert rules[0]["defaultConfiguration"]["level"] == "error"


def test_failed_group_becomes_a_notification():
    sarif = build_sarif(doc([finding()], groups_failed=["concurrency"]))
    invocation = sarif["runs"][0]["invocations"][0]
    assert invocation["properties"]["groups_failed"] == ["concurrency"]
    assert any(
        "concurrency" in n["message"]["text"] for n in invocation["toolExecutionNotifications"]
    )


def test_unjudged_finding_is_marked_and_notified():
    f = finding(id="U", severity_validated=False)
    sarif = build_sarif(doc([f], unjudged_findings=["U"]))
    result = sarif["runs"][0]["results"][0]
    assert result["properties"]["severity_validated"] is False
    assert findings_model.UNVALIDATED_MARKER in result["message"]["text"]
    assert sarif["runs"][0]["invocations"][0]["toolExecutionNotifications"]


def test_unknown_bug_class_still_gets_a_rule():
    rules = build_sarif(doc([finding(bug_class="brand-new-class")]))["runs"][0]["tool"]["driver"][
        "rules"
    ]
    assert rules[0]["id"] == "brand-new-class"
    assert rules[0]["shortDescription"]["text"]


# ------------------------------------------------------------------- cli


def test_main_writes_sarif(tmp_path):
    src = write(tmp_path, doc([finding()]))
    assert main(["--findings", str(src), "--output-dir", str(tmp_path)]) == 0
    written = json.loads((tmp_path / "REPORT.sarif").read_text())
    assert len(written["runs"][0]["results"]) == 1


def test_main_exits_non_zero_on_bad_input(tmp_path, capsys):
    src = write(tmp_path, "{not json")
    assert main(["--findings", str(src), "--output-dir", str(tmp_path)]) == 2
    assert "generate_sarif:" in capsys.readouterr().err
    assert not (tmp_path / "REPORT.sarif").exists()


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-q"]))
