"""Regression tests for generate_sarif.py rule metadata."""

from __future__ import annotations

from pathlib import Path

import pytest

from generate_sarif import RULE_DESCRIPTIONS, build_sarif


def _write_finding(
    findings_dir: Path,
    *,
    fid: str,
    bug_class: str,
    title: str,
    location: str,
    severity: str = "HIGH",
    fp_verdict: str | None = "TRUE_POSITIVE",
) -> None:
    findings_dir.mkdir(parents=True, exist_ok=True)
    fp_line = f"fp_verdict: {fp_verdict}\n" if fp_verdict is not None else ""
    content = f"""---
id: {fid}
bug_class: {bug_class}
title: {title}
location: {location}
severity: {severity}
{fp_line}\
confidence: High
attack_vector: Remote
exploitability: Reliable
---

Body.
"""
    (findings_dir / f"{fid}.md").write_text(content, encoding="utf-8")


def _rule_by_id(sarif: dict, rule_id: str) -> dict:
    rules = sarif["runs"][0]["tool"]["driver"]["rules"]
    for rule in rules:
        if rule["id"] == rule_id:
            return rule
    raise KeyError(rule_id)


@pytest.fixture
def output_dir(tmp_path: Path) -> Path:
    (tmp_path / "context.md").write_text(
        "---\nthreat_model: REMOTE\nseverity_filter: all\n---\n",
        encoding="utf-8",
    )
    findings = tmp_path / "findings"
    _write_finding(
        findings,
        fid="BOF-001",
        bug_class="buffer-overflow",
        title="Missing bounds check in parse_header",
        location="src/net/parse.c:142",
    )
    _write_finding(
        findings,
        fid="TYPE-001",
        bug_class="type-confusion",
        title="Unsafe cast between incompatible struct pointers",
        location="src/proto/decode.c:10",
    )
    return tmp_path


def test_build_sarif_uses_c_rule_descriptions(output_dir: Path) -> None:
    sarif = build_sarif(output_dir)
    rules = sarif["runs"][0]["tool"]["driver"]["rules"]
    rule_ids = {r["id"] for r in rules}
    assert rule_ids == {"buffer-overflow", "type-confusion"}

    bof = _rule_by_id(sarif, "buffer-overflow")
    assert bof["shortDescription"]["text"] == RULE_DESCRIPTIONS["buffer-overflow"]
    assert bof["shortDescription"]["text"] != "Buffer Overflow"

    typ = _rule_by_id(sarif, "type-confusion")
    assert typ["shortDescription"]["text"] == RULE_DESCRIPTIONS["type-confusion"]
    assert typ["shortDescription"]["text"] != "Type Confusion"


def test_build_sarif_result_rule_id_matches_bug_class(output_dir: Path) -> None:
    sarif = build_sarif(output_dir)
    results = sarif["runs"][0]["results"]
    assert len(results) == 2
    by_rule = {r["ruleId"]: r for r in results}
    assert by_rule["buffer-overflow"]["message"]["text"] == ("Missing bounds check in parse_header")
    assert by_rule["type-confusion"]["properties"]["bug_class"] == "type-confusion"


def test_build_sarif_uses_canonical_findings_index(tmp_path: Path) -> None:
    (tmp_path / "context.md").write_text(
        "---\nthreat_model: REMOTE\nseverity_filter: all\n---\n",
        encoding="utf-8",
    )
    findings = tmp_path / "findings"
    _write_finding(
        findings,
        fid="BOF-001",
        bug_class="buffer-overflow",
        title="Indexed judged finding",
        location="src/net/parse.c:142",
    )
    _write_finding(
        findings,
        fid="UAF-001",
        bug_class="use-after-free",
        title="Orphaned unjudged finding",
        location="src/net/parse.c:199",
        fp_verdict=None,
    )
    (tmp_path / "findings-index.txt").write_text(
        f"{findings / 'BOF-001.md'}\n\n",
        encoding="utf-8",
    )

    sarif = build_sarif(tmp_path)

    results = sarif["runs"][0]["results"]
    assert [r["properties"]["finding_id"] for r in results] == ["BOF-001"]
    assert results[0]["properties"]["unjudged"] is False


def test_build_sarif_empty_findings(tmp_path: Path) -> None:
    (tmp_path / "context.md").write_text(
        "---\nthreat_model: REMOTE\nseverity_filter: all\n---\n",
        encoding="utf-8",
    )
    (tmp_path / "findings").mkdir()
    sarif = build_sarif(tmp_path)
    run = sarif["runs"][0]
    assert run["tool"]["driver"]["name"] == "c-review"
    assert run["tool"]["driver"]["rules"] == []
    assert run["results"] == []


def test_rule_descriptions_cover_manifest_bug_classes() -> None:
    """Every manifest bug_class should have an explicit SARIF description."""
    import json

    manifest_path = Path(__file__).resolve().parents[1] / "prompts/clusters/manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    bug_classes = [p["bug_class"] for cluster in manifest["clusters"] for p in cluster["passes"]]
    missing = [bc for bc in bug_classes if bc not in RULE_DESCRIPTIONS]
    assert missing == [], f"missing RULE_DESCRIPTIONS for: {missing}"


def test_unjudged_finding_survives_strict_filter_with_marker(tmp_path: Path) -> None:
    """A partial-run finding with no fp_verdict must NOT be silently dropped by a
    strict severity_filter; it is surfaced and clearly marked as unvalidated."""
    (tmp_path / "context.md").write_text(
        "---\nthreat_model: REMOTE\nseverity_filter: high\n---\n",
        encoding="utf-8",
    )
    findings = tmp_path / "findings"
    findings.mkdir()
    # No fp_verdict and no severity — exactly what a worker writes before the
    # fp-judge runs. Confidence High infers only MEDIUM severity, so a naive
    # severity filter (high) would otherwise drop it.
    (findings / "UAF-001.md").write_text(
        "---\nid: UAF-001\nbug_class: use-after-free\n"
        "title: Dangling pointer after free\nlocation: src/lib.c:5\n"
        "confidence: High\n---\n\nBody.\n",
        encoding="utf-8",
    )

    results = build_sarif(tmp_path)["runs"][0]["results"]

    assert len(results) == 1
    result = results[0]
    assert result["properties"]["finding_id"] == "UAF-001"
    assert result["properties"]["unjudged"] is True
    assert result["properties"]["severity_validated"] is False
    assert result["message"]["text"].startswith("[UNVALIDATED SEVERITY")


def test_judged_finding_below_filter_is_still_dropped(tmp_path: Path) -> None:
    """The unjudged exemption must not leak into judged findings: a judged LOW
    survivor is still filtered out under severity_filter=high."""
    (tmp_path / "context.md").write_text(
        "---\nthreat_model: REMOTE\nseverity_filter: high\n---\n",
        encoding="utf-8",
    )
    findings = tmp_path / "findings"
    _write_finding(
        findings,
        fid="UAF-001",
        bug_class="use-after-free",
        title="Low-sev judged finding",
        location="src/lib.c:5",
        severity="LOW",
        fp_verdict="TRUE_POSITIVE",
    )

    assert build_sarif(tmp_path)["runs"][0]["results"] == []
