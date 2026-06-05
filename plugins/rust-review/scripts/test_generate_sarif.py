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
        bug_class="buffer-overflow-unsafe",
        title="Unchecked get_unchecked on attacker index",
        location="src/lib.rs:42",
    )
    _write_finding(
        findings,
        fid="PTRCAST-001",
        bug_class="pointer-cast",
        title="usize to *mut T via as without provenance",
        location="src/ffi.rs:10",
    )
    return tmp_path


def test_build_sarif_uses_rust_rule_descriptions(output_dir: Path) -> None:
    sarif = build_sarif(output_dir)
    rules = sarif["runs"][0]["tool"]["driver"]["rules"]
    rule_ids = {r["id"] for r in rules}
    assert rule_ids == {"buffer-overflow-unsafe", "pointer-cast"}

    bof = _rule_by_id(sarif, "buffer-overflow-unsafe")
    assert bof["shortDescription"]["text"] == RULE_DESCRIPTIONS["buffer-overflow-unsafe"]
    assert bof["shortDescription"]["text"] != "Buffer Overflow Unsafe"

    ptr = _rule_by_id(sarif, "pointer-cast")
    assert ptr["shortDescription"]["text"] == RULE_DESCRIPTIONS["pointer-cast"]
    assert ptr["shortDescription"]["text"] != "Pointer Cast"


def test_build_sarif_result_rule_id_matches_bug_class(output_dir: Path) -> None:
    sarif = build_sarif(output_dir)
    results = sarif["runs"][0]["results"]
    assert len(results) == 2
    by_rule = {r["ruleId"]: r for r in results}
    assert by_rule["buffer-overflow-unsafe"]["message"]["text"] == (
        "Unchecked get_unchecked on attacker index"
    )
    assert by_rule["pointer-cast"]["properties"]["bug_class"] == "pointer-cast"


def test_build_sarif_uses_canonical_findings_index(tmp_path: Path) -> None:
    (tmp_path / "context.md").write_text(
        "---\nthreat_model: REMOTE\nseverity_filter: all\n---\n",
        encoding="utf-8",
    )
    findings = tmp_path / "findings"
    _write_finding(
        findings,
        fid="BOF-001",
        bug_class="buffer-overflow-unsafe",
        title="Indexed judged finding",
        location="src/lib.rs:42",
    )
    _write_finding(
        findings,
        fid="UAF-001",
        bug_class="use-after-free",
        title="Orphaned unjudged finding",
        location="src/lib.rs:99",
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
    assert run["tool"]["driver"]["name"] == "rust-review"
    assert run["tool"]["driver"]["rules"] == []
    assert run["results"] == []


def test_rule_descriptions_cover_manifest_bug_classes() -> None:
    """Every manifest bug_class should have an explicit SARIF description."""
    import json

    manifest_path = Path(__file__).resolve().parents[1] / "prompts/clusters/manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    bug_classes = [
        p["bug_class"]
        for cluster in manifest["clusters"]
        for p in cluster["passes"]
    ]
    missing = [bc for bc in bug_classes if bc not in RULE_DESCRIPTIONS]
    assert missing == [], f"missing RULE_DESCRIPTIONS for: {missing}"
