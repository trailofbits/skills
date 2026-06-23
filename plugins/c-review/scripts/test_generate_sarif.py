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
    merged_into: str | None = None,
) -> None:
    findings_dir.mkdir(parents=True, exist_ok=True)
    fp_line = f"fp_verdict: {fp_verdict}\n" if fp_verdict is not None else ""
    merged_line = f"merged_into: {merged_into}\n" if merged_into else ""
    content = f"""---
id: {fid}
bug_class: {bug_class}
title: {title}
location: {location}
severity: {severity}
{fp_line}{merged_line}\
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


def test_missing_index_entry_is_skipped_not_crash(tmp_path: Path) -> None:
    """A stale findings-index.txt entry pointing at a file that no longer exists must
    be skipped with a warning, not raise FileNotFoundError — Phase-8b's safety net
    must still produce REPORT.sarif from the survivors that do exist."""
    (tmp_path / "context.md").write_text(
        "---\nthreat_model: REMOTE\nseverity_filter: all\n---\n", encoding="utf-8"
    )
    findings = tmp_path / "findings"
    _write_finding(
        findings,
        fid="BOF-001",
        bug_class="buffer-overflow",
        title="real",
        location="src/a.c:1",
    )
    (tmp_path / "findings-index.txt").write_text(
        f"{findings / 'BOF-001.md'}\n{findings / 'GHOST-404.md'}\n",
        encoding="utf-8",
    )

    results = build_sarif(tmp_path)["runs"][0]["results"]
    assert [r["properties"]["finding_id"] for r in results] == ["BOF-001"]


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


def test_judged_fp_findings_are_dropped(tmp_path: Path) -> None:
    """fp-judge-rejected findings (FALSE_POSITIVE / LIKELY_FP) must never reach
    SARIF; a TRUE_POSITIVE in the same dir still surfaces. This guards the core
    fp-judge stage — a regression here would ship false positives to users."""
    (tmp_path / "context.md").write_text(
        "---\nthreat_model: REMOTE\nseverity_filter: all\n---\n", encoding="utf-8"
    )
    findings = tmp_path / "findings"
    _write_finding(
        findings,
        fid="UAF-001",
        bug_class="use-after-free",
        title="real",
        location="src/a.c:1",
        fp_verdict="TRUE_POSITIVE",
    )
    _write_finding(
        findings,
        fid="INT-001",
        bug_class="integer-overflow",
        title="false positive",
        location="src/b.c:1",
        fp_verdict="FALSE_POSITIVE",
    )
    _write_finding(
        findings,
        fid="NULL-001",
        bug_class="null-deref",
        title="likely false positive",
        location="src/c.c:1",
        fp_verdict="LIKELY_FP",
    )

    results = build_sarif(tmp_path)["runs"][0]["results"]
    assert [r["properties"]["finding_id"] for r in results] == ["UAF-001"]


def test_zero_line_is_clamped_to_one(tmp_path: Path) -> None:
    """A location ending in :0 must not emit region.startLine 0 — the SARIF schema
    minimum is 1, and a 0 makes the whole REPORT.sarif fail strict validation /
    GitHub code-scanning ingestion."""
    (tmp_path / "context.md").write_text(
        "---\nthreat_model: REMOTE\nseverity_filter: all\n---\n", encoding="utf-8"
    )
    findings = tmp_path / "findings"
    _write_finding(
        findings,
        fid="UAF-001",
        bug_class="use-after-free",
        title="zero line",
        location="src/lib.c:0",
    )

    results = build_sarif(tmp_path)["runs"][0]["results"]
    region = results[0]["locations"][0]["physicalLocation"]["region"]
    assert region["startLine"] == 1


def test_judged_survivor_missing_severity_is_surfaced_not_dropped(tmp_path: Path) -> None:
    """A judged survivor whose severity the fp-judge failed to write must be
    surfaced (marked unvalidated) even under a strict filter — the safety net must
    not silently delete a confirmed true positive."""
    (tmp_path / "context.md").write_text(
        "---\nthreat_model: REMOTE\nseverity_filter: high\n---\n", encoding="utf-8"
    )
    findings = tmp_path / "findings"
    findings.mkdir()
    (findings / "UAF-001.md").write_text(
        "---\nid: UAF-001\nbug_class: use-after-free\n"
        "title: Confirmed but severity not written\nlocation: src/lib.c:5\n"
        "fp_verdict: TRUE_POSITIVE\nconfidence: High\n---\n\nBody.\n",
        encoding="utf-8",
    )

    results = build_sarif(tmp_path)["runs"][0]["results"]
    assert len(results) == 1
    result = results[0]
    assert result["properties"]["finding_id"] == "UAF-001"
    assert result["properties"]["severity_validated"] is False
    assert result["message"]["text"].startswith("[UNVALIDATED SEVERITY")


def test_frontmatterless_finding_is_skipped_not_phantom(tmp_path: Path) -> None:
    """A finding file with no parseable frontmatter must be skipped, not emitted as
    a phantom result with ruleId 'unknown' and an empty id/uri."""
    (tmp_path / "context.md").write_text(
        "---\nthreat_model: REMOTE\nseverity_filter: all\n---\n", encoding="utf-8"
    )
    findings = tmp_path / "findings"
    _write_finding(
        findings,
        fid="UAF-001",
        bug_class="use-after-free",
        title="real",
        location="src/a.c:1",
    )
    (findings / "broken.md").write_text("no frontmatter here\n", encoding="utf-8")

    results = build_sarif(tmp_path)["runs"][0]["results"]
    assert [r["properties"]["finding_id"] for r in results] == ["UAF-001"]
    assert all(r["ruleId"] != "unknown" for r in results)


def test_clean_run_reports_zero_skips(output_dir: Path) -> None:
    """A healthy run records skipped_findings: 0 and adds no skip notifications."""
    invocation = build_sarif(output_dir)["runs"][0]["invocations"][0]
    assert invocation["executionSuccessful"] is True
    assert invocation["properties"]["skipped_findings"] == 0
    assert "skipped_paths" not in invocation["properties"]
    assert "toolExecutionNotifications" not in invocation


def test_skipped_findings_surfaced_in_invocation(tmp_path: Path) -> None:
    """Dropped finding files (missing index entry + frontmatterless file) must be
    surfaced in the artifact — a count, the paths, and one warning notification
    each — while executionSuccessful stays True and good findings still emit."""
    (tmp_path / "context.md").write_text(
        "---\nthreat_model: REMOTE\nseverity_filter: all\n---\n", encoding="utf-8"
    )
    findings = tmp_path / "findings"
    _write_finding(
        findings,
        fid="UAF-001",
        bug_class="use-after-free",
        title="real",
        location="src/a.c:1",
    )
    (findings / "broken.md").write_text("no frontmatter here\n", encoding="utf-8")
    # Index lists the good file, a frontmatterless file, and a ghost (unreadable).
    (tmp_path / "findings-index.txt").write_text(
        f"{findings / 'UAF-001.md'}\n{findings / 'broken.md'}\n{findings / 'GHOST-404.md'}\n",
        encoding="utf-8",
    )

    run = build_sarif(tmp_path)["runs"][0]
    invocation = run["invocations"][0]
    assert [r["properties"]["finding_id"] for r in run["results"]] == ["UAF-001"]
    assert invocation["executionSuccessful"] is True
    assert invocation["properties"]["skipped_findings"] == 2
    assert len(invocation["properties"]["skipped_paths"]) == 2
    notifications = invocation["toolExecutionNotifications"]
    assert len(notifications) == 2
    assert all(n["level"] == "warning" for n in notifications)
    assert any("GHOST-404" in n["message"]["text"] for n in notifications)
    assert any("broken.md" in n["message"]["text"] for n in notifications)


def test_location_parts_branch_coverage() -> None:
    """Cover location_parts shapes: plain, markdown-link, trailing-colon, multi,
    bare path, and the :0 clamp."""
    from generate_sarif import location_parts

    assert location_parts("src/lib.c:42") == ("src/lib.c", 42)
    assert location_parts("[src/lib.c](/abs/src/lib.c):42") == ("src/lib.c", 42)
    assert location_parts("src/lib.c:") == ("src/lib.c", 1)
    assert location_parts("src/lib.c") == ("src/lib.c", 1)
    assert location_parts("a.c:1, b.c:2") == ("a.c:1, b.c:2", 1)
    assert location_parts("src/lib.c:0") == ("src/lib.c", 1)
    assert location_parts(None) == ("", 1)


def test_malformed_frontmatter_finding_is_skipped_not_crash(tmp_path: Path) -> None:
    """Regression for malformed frontmatter: a scalar key then an indented list
    item used to raise AttributeError and abort the whole run, so no REPORT.sarif
    was emitted. The bad file must be skipped (and surfaced) so survivors emit."""
    (tmp_path / "context.md").write_text(
        "---\nthreat_model: REMOTE\nseverity_filter: all\n---\n", encoding="utf-8"
    )
    findings = tmp_path / "findings"
    _write_finding(
        findings,
        fid="BOF-001",
        bug_class="buffer-overflow",
        title="real",
        location="src/a.c:1",
    )
    # Scalar then list item on one key: parse_frontmatter appends to the scalar.
    (findings / "MALFORMED.md").write_text(
        "---\nid: MALFORMED\nbug_class: use-after-free\n"
        "title: bad frontmatter\nlocation: src/a.c:42\n"
        "  - src/b.c:88\nseverity: HIGH\n---\n\nBody.\n",
        encoding="utf-8",
    )

    run = build_sarif(tmp_path)["runs"][0]
    assert [r["properties"]["finding_id"] for r in run["results"]] == ["BOF-001"]
    # The malformed file is surfaced in the invocation, not only on stderr.
    invocation = run["invocations"][0]
    assert invocation["properties"]["skipped_findings"] == 1
    assert any("MALFORMED" in p for p in invocation["properties"]["skipped_paths"])


def test_merged_finding_whose_target_was_fp_rejected_is_emitted(tmp_path: Path) -> None:
    """A finding merged into an FP-rejected primary must not inherit the rejection;
    its own TRUE_POSITIVE verdict must still surface."""
    (tmp_path / "context.md").write_text(
        "---\nthreat_model: REMOTE\nseverity_filter: all\n---\n", encoding="utf-8"
    )
    findings = tmp_path / "findings"
    _write_finding(
        findings,
        fid="DUP-A",
        bug_class="buffer-overflow",
        title="real bug, folded into DUP-B",
        location="src/a.c:10",
        fp_verdict="TRUE_POSITIVE",
        merged_into="DUP-B",
    )
    _write_finding(
        findings,
        fid="DUP-B",
        bug_class="buffer-overflow",
        title="the duplicate, later judged FP",
        location="src/a.c:10",
        fp_verdict="FALSE_POSITIVE",
    )

    result_ids = [
        r["properties"]["finding_id"] for r in build_sarif(tmp_path)["runs"][0]["results"]
    ]
    assert result_ids == ["DUP-A"]


def test_merged_finding_with_surviving_target_is_skipped(tmp_path: Path) -> None:
    """When the merge target survives, the merged finding is still skipped — no
    false duplicate."""
    (tmp_path / "context.md").write_text(
        "---\nthreat_model: REMOTE\nseverity_filter: all\n---\n", encoding="utf-8"
    )
    findings = tmp_path / "findings"
    _write_finding(
        findings,
        fid="DUP-A",
        bug_class="buffer-overflow",
        title="folded duplicate",
        location="src/a.c:10",
        fp_verdict="TRUE_POSITIVE",
        merged_into="DUP-B",
    )
    _write_finding(
        findings,
        fid="DUP-B",
        bug_class="buffer-overflow",
        title="surviving primary",
        location="src/a.c:10",
        fp_verdict="TRUE_POSITIVE",
    )

    result_ids = [
        r["properties"]["finding_id"] for r in build_sarif(tmp_path)["runs"][0]["results"]
    ]
    assert result_ids == ["DUP-B"]


def test_merged_finding_whose_target_is_missing_is_emitted(tmp_path: Path) -> None:
    """A finding merged into a missing target id (aborted dedup / stale field)
    must survive."""
    (tmp_path / "context.md").write_text(
        "---\nthreat_model: REMOTE\nseverity_filter: all\n---\n", encoding="utf-8"
    )
    findings = tmp_path / "findings"
    _write_finding(
        findings,
        fid="DUP-A",
        bug_class="buffer-overflow",
        title="orphaned by missing target",
        location="src/a.c:10",
        fp_verdict="TRUE_POSITIVE",
        merged_into="DUP-GHOST",
    )

    result_ids = [
        r["properties"]["finding_id"] for r in build_sarif(tmp_path)["runs"][0]["results"]
    ]
    assert result_ids == ["DUP-A"]


def test_finding_with_no_location_is_marked(tmp_path: Path) -> None:
    """A survivor with no `location` must be emitted (not dropped) but flagged:
    empty URI, `location_missing: True`, and a `LOCATION MISSING` title marker so
    the phantom `:1` location is never read as a real one."""
    (tmp_path / "context.md").write_text(
        "---\nthreat_model: REMOTE\nseverity_filter: all\n---\n", encoding="utf-8"
    )
    findings = tmp_path / "findings"
    findings.mkdir()
    (findings / "BOF-001.md").write_text(
        "---\nid: BOF-001\nbug_class: buffer-overflow\n"
        "title: no location recorded\nseverity: HIGH\n"
        "fp_verdict: TRUE_POSITIVE\nconfidence: High\n---\n\nBody.\n",
        encoding="utf-8",
    )

    result = build_sarif(tmp_path)["runs"][0]["results"][0]
    assert result["properties"]["location_missing"] is True
    assert "LOCATION MISSING" in result["message"]["text"]
    loc = result["locations"][0]["physicalLocation"]
    assert loc["artifactLocation"]["uri"] == ""
    assert loc["region"]["startLine"] == 1


if __name__ == "__main__":
    import sys

    raise SystemExit(pytest.main([__file__, *sys.argv[1:]]))
