#!/usr/bin/env python3
"""Tests for the deterministic findings assembler."""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent))

import assemble_findings as assemble_findings_mod  # noqa: E402
from assemble_findings import (  # noqa: E402
    CLASS_PREFIXES,
    REVIEWER_RATIONALE,
    UNJUDGED_RATIONALE,
    main,
)

WORKFLOW_JS = Path(__file__).resolve().parent.parent / "workflows" / "c-review.js"


# ------------------------------------------------------------------ fixtures


def raw_finding(**overrides):
    base = {
        "bug_class": "buffer-overflow",
        "title": "Missing bounds check",
        "file": "src/parse.c",
        "line": 142,
        "function": "parse_header",
        "unit_id": "src/parse.c:parse_header",
        "confidence": "High",
        "description": "len comes from the network header and is never bounded.",
        "code": "memcpy(buf, src, len);",
        "data_flow": "source: recv_request; sink: memcpy; validation: none",
        "reachability": "recv_request -> dispatch -> parse_header",
        "impact": "Heap overflow with attacker-controlled length.",
        "mitigations_checked": "FORTIFY not applied at this site",
        "recommendation": "Bound len against sizeof(buf).",
        "outside_assigned_classes": False,
    }
    base.update(overrides)
    return base


def producing_part(part_id, findings=None, ledger=None, **overrides):
    part = {
        "part_id": part_id,
        "findings": findings or [],
        "ledger": ledger or [],
        "external_sources_consulted": False,
        "external_sources_detail": "none",
        "notes": "",
    }
    part.update(overrides)
    return part


def write_run(tmp_path, parts, detect=None, units=None, ledger_gate=None):
    """Lay out a run directory: parts/<stem>.json plus the optional phase outputs."""
    run_dir = tmp_path / "run"
    (run_dir / "parts").mkdir(parents=True, exist_ok=True)
    for stem, doc in parts.items():
        payload = doc if isinstance(doc, str) else json.dumps(doc, indent=2)
        (run_dir / "parts" / f"{stem}.json").write_text(payload, encoding="utf-8")
    if detect is not None:
        (run_dir / "detect.json").write_text(json.dumps(detect), encoding="utf-8")
    if units is not None:
        (run_dir / "units.json").write_text(json.dumps(units), encoding="utf-8")
    if ledger_gate is not None:
        (run_dir / "ledger-gate.json").write_text(json.dumps(ledger_gate), encoding="utf-8")
    return run_dir


def assemble(run_dir, *extra):
    return main(
        [
            "--run-dir",
            str(run_dir),
            "--threat-model",
            "REMOTE",
            "--severity-filter",
            "all",
            *extra,
        ]
    )


def load_doc(run_dir):
    return json.loads((run_dir / "findings.json").read_text(encoding="utf-8"))


def by_id(doc):
    return {f["id"]: f for f in doc["findings"]}


def by_key(doc):
    return {f["key"]: f for f in doc["findings"]}


def verdict(key, **overrides):
    entry = {
        "key": key,
        "fp_verdict": "TRUE_POSITIVE",
        "fp_rationale": "no bound between source and sink",
        "severity": "HIGH",
        "attack_vector": "Remote",
        "exploitability": "Reliable",
        "severity_rationale": "reliable remote heap write",
    }
    entry.update(overrides)
    return entry


def big_run(tmp_path, per_part=22, parts=4):
    """A run at the volume that destroyed the old persist agent: 88 distinct findings."""
    classes = ["buffer-overflow", "integer-overflow", "use-after-free", "logic-flaw"]
    layout = {}
    total = 0
    for p in range(parts):
        findings = []
        for i in range(per_part):
            findings.append(
                raw_finding(
                    bug_class=classes[(p + i) % len(classes)],
                    title=f"finding {p}-{i}",
                    file=f"src/mod{p}.c",
                    line=100 + i,
                    function=f"fn_{p}_{i}",
                    description=f"description {p}-{i}",
                    code=f"code_{p}_{i}();",
                    impact=f"impact {p}-{i}",
                    recommendation=f"recommendation {p}-{i}",
                )
            )
            total += 1
        layout[f"review-unit-{p:02d}"] = producing_part(f"review-unit-{p:02d}", findings)
    return write_run(tmp_path, layout), total


# ------------------------------------------------------- P1: the defect being fixed


def test_p1_large_run_keeps_every_finding_and_every_evidence_field(tmp_path):
    """tools/c-review-bench/MEASUREMENTS.md §5: 86 candidates in, 23 out, evidence stripped from 23 of 23.

    The old persist agent was faithful at 15 and 25 findings and destroyed the document at
    75 and 86. This is the same volume, assembled by code.
    """
    run_dir, total = big_run(tmp_path)
    assert total == 88
    assert assemble(run_dir) == 0
    doc = load_doc(run_dir)

    assert len(doc["findings"]) == 88
    assert doc["stats"]["raw_findings"] == 88
    assert doc["stats"]["primaries"] == 88
    for finding in doc["findings"]:
        for field in ("description", "code", "impact", "recommendation", "function", "found_by"):
            assert finding[field], f"{finding['id']} lost {field}"

    spot = next(f for f in doc["findings"] if f["title"] == "finding 3-7")
    assert spot["description"] == "description 3-7"
    assert spot["code"] == "code_3_7();"
    assert spot["impact"] == "impact 3-7"
    assert spot["recommendation"] == "recommendation 3-7"
    assert spot["function"] == "fn_3_7"
    assert spot["found_by"] == "review-unit-03"

    # And the report carries them too, not just findings.json.
    report = (run_dir / "REPORT.md").read_text(encoding="utf-8")
    assert "description 3-7" in report
    sarif = json.loads((run_dir / "REPORT.sarif").read_text(encoding="utf-8"))
    assert len(sarif["runs"][0]["results"]) == 88


def test_summary_reports_counts_only_and_never_a_finding_payload(tmp_path, capsys):
    run_dir, _ = big_run(tmp_path)
    assert assemble(run_dir) == 0
    summary = json.loads(capsys.readouterr().out)
    assert summary["ok"] is True
    assert summary["stats"]["raw_findings"] == 88
    assert summary["unjudged"] == 88
    assert set(summary) == {
        "ok",
        "findings_json",
        "report_md",
        "report_sarif",
        "stats",
        "unjudged",
        "ignored_merges",
        "ignored_verdicts",
        "unrecognised_parts",
        # lifted out of run.ledger so the workflow can read coverage back without
        # re-parsing findings.json; counts only, never a finding payload
        "checks_required",
        "checks_completed",
        "checks_satisfied",
    }
    blob = json.dumps(summary)
    assert "memcpy" not in blob
    assert "description 3-7" not in blob


def test_assembly_is_byte_for_byte_deterministic(tmp_path):
    run_dir, _ = big_run(tmp_path)
    assert assemble(run_dir) == 0
    first = (run_dir / "findings.json").read_bytes()
    assert assemble(run_dir) == 0
    assert (run_dir / "findings.json").read_bytes() == first


# ------------------------------------------------------------------ normalisation


def test_key_comes_from_the_filename_not_the_part_id_field(tmp_path):
    run_dir = write_run(
        tmp_path,
        {"review-unit-01": producing_part("TYPO-NOT-THE-STEM", [raw_finding()])},
    )
    assert assemble(run_dir) == 0
    doc = load_doc(run_dir)
    assert doc["findings"][0]["key"] == "review-unit-01#0"
    assert doc["findings"][0]["found_by"] == "review-unit-01"


def test_unknown_bug_class_falls_back_to_logic_flaw(tmp_path):
    run_dir = write_run(
        tmp_path,
        {"review-unit-01": producing_part("review-unit-01", [raw_finding(bug_class="wat")])},
    )
    assert assemble(run_dir) == 0
    finding = load_doc(run_dir)["findings"][0]
    assert finding["bug_class"] == "logic-flaw"
    assert finding["reported_bug_class"] == "wat"
    assert finding["id"].startswith("LOGIC-")


def test_path_is_normalised(tmp_path):
    cases = {
        "review-unit-01": producing_part(
            "review-unit-01",
            [
                raw_finding(file="[src/a.c](src/a.c)", line=1, title="link"),
                raw_finding(file="./src/b.c", line=2, title="dot"),
                raw_finding(file="src//c.c", line=3, title="slash"),
                raw_finding(file="src\\d.c", line=4, title="backslash"),
            ],
        )
    }
    run_dir = write_run(tmp_path, cases)
    assert assemble(run_dir) == 0
    files = sorted(f["file"] for f in load_doc(run_dir)["findings"])
    assert files == ["src/a.c", "src/b.c", "src/c.c", "src/d.c"]


def test_absent_or_nonpositive_line_becomes_one(tmp_path):
    run_dir = write_run(
        tmp_path,
        {
            "review-unit-01": producing_part(
                "review-unit-01",
                [
                    raw_finding(line=0, title="zero", file="src/z.c"),
                    raw_finding(line=-4, title="negative", file="src/n.c"),
                    raw_finding(line=None, title="absent", file="src/a.c"),
                ],
            )
        },
    )
    assert assemble(run_dir) == 0
    assert {f["line"] for f in load_doc(run_dir)["findings"]} == {1}


# ------------------------------------------------------------------ merging


def test_tier1_merges_identical_file_line_and_class(tmp_path):
    run_dir = write_run(
        tmp_path,
        {
            "review-unit-01": producing_part("review-unit-01", [raw_finding(confidence="Low")]),
            "second-01": producing_part("second-01", [raw_finding(confidence="High")]),
        },
    )
    assert assemble(run_dir) == 0
    doc = load_doc(run_dir)
    keyed = by_key(doc)
    primary = keyed["second-01#0"]
    duplicate = keyed["review-unit-01#0"]
    assert doc["stats"]["merged"] == 1
    assert doc["stats"]["primaries"] == 1
    assert duplicate["merged_into"] == primary["id"]
    assert primary["also_known_as"] == [duplicate["id"]]
    assert "merged_into" not in primary


def test_tier1_tie_breaks_on_the_smallest_key(tmp_path):
    run_dir = write_run(
        tmp_path,
        {
            "review-unit-01": producing_part("review-unit-01", [raw_finding(confidence="Medium")]),
            "sweep-01": producing_part("sweep-01", [raw_finding(confidence="Medium")]),
        },
    )
    assert assemble(run_dir) == 0
    keyed = by_key(load_doc(run_dir))
    assert "merged_into" not in keyed["review-unit-01#0"]
    assert keyed["sweep-01#0"]["merged_into"] == keyed["review-unit-01#0"]["id"]


def test_a_different_class_at_the_same_site_is_not_a_tier1_duplicate(tmp_path):
    """Tier 1 keys on bug_class, so it leaves this pair alone.

    Tier 1.5 does merge a same-function pair across classes, which is the point of it, so
    this fixture keeps the two out of one function to isolate the tier-1 rule.
    """
    run_dir = write_run(
        tmp_path,
        {
            "review-unit-01": producing_part(
                "review-unit-01",
                [
                    raw_finding(),
                    raw_finding(
                        bug_class="integer-overflow", title="width", function="(file-level)"
                    ),
                ],
            )
        },
    )
    assert assemble(run_dir) == 0
    assert load_doc(run_dir)["stats"]["merged"] == 0


# ------------------------------------------------------------------ tier 1.5


def near_pair(tmp_path, first=None, second=None):
    """Two findings two lines apart in one function, filed under different bug classes."""
    later = {"line": 144, "bug_class": "integer-overflow", "title": "width", "confidence": "Low"}
    later.update(second or {})
    return write_run(
        tmp_path,
        {
            "review-unit-01": producing_part(
                "review-unit-01",
                [raw_finding(confidence="High", **(first or {})), raw_finding(**later)],
            )
        },
    )


def test_tier1_5_merges_across_bug_classes_on_the_same_line(tmp_path):
    """One unchecked length filed twice on line 142: as the overflow and as the truncation.

    Tier 1 cannot see this — the classes differ — and it is the commonest pair the dedup
    agent used to be spawned for. Cross-class merging is capped at
    `CROSS_CLASS_NEARBY_LINES` (0), so this pair merges and the one two lines apart below
    does not; see that test for the measurement behind the cap.
    """
    run_dir = near_pair(tmp_path, second={"line": 142})
    assert assemble(run_dir) == 0
    doc = load_doc(run_dir)
    keyed = by_key(doc)
    assert doc["stats"]["merged"] == 1
    assert doc["stats"]["merged_auto"] == 1
    assert doc["stats"]["merged_agent"] == 0
    assert keyed["review-unit-01#1"]["merged_into"] == keyed["review-unit-01#0"]["id"]
    assert keyed["review-unit-01#0"]["also_known_as"] == [keyed["review-unit-01#1"]["id"]]


def test_tier1_5_does_not_merge_different_classes_two_lines_apart(tmp_path):
    """The measured regression. Two lines apart and two classes apart is not one bug.

    On the 2026-08-07 host cell this rule cost two ground-truth bugs outright: an
    off-by-one at line 34 was folded into a missing-bound-check at line 35, and a memory
    leak at line 85 into an unchecked-return at line 88. Both were found, both were
    correct, and neither reached the report. Replaying all three scored cells with the
    cap in place recovered both (13/17 -> 15/17) and changed nothing on the other two,
    including their decoy false-positive counts.

    Such a pair is not refused, only left unmerged for the dedup agent, which reads both
    write-ups instead of guessing from a line distance.
    """
    run_dir = near_pair(tmp_path)  # 142 vs 144, buffer-overflow vs integer-overflow
    assert assemble(run_dir) == 0
    doc = load_doc(run_dir)
    assert doc["stats"]["merged"] == 0
    assert all(f.get("merged_into") is None for f in doc["findings"])


def test_tier1_5_still_merges_the_same_class_within_the_full_window(tmp_path):
    """The cap is cross-class only. Same class inside NEARBY_LINES is the original case
    this tier exists for, and no measured same-class merge was wrong."""
    run_dir = near_pair(tmp_path, second={"line": 145, "bug_class": "buffer-overflow"})
    assert assemble(run_dir) == 0
    assert load_doc(run_dir)["stats"]["merged_auto"] == 1


def test_tier1_5_normalises_the_function_name_the_way_the_js_does(tmp_path):
    run_dir = near_pair(
        tmp_path, {"function": "Parse_Header"}, {"function": "parse header", "line": 142}
    )
    assert assemble(run_dir) == 0
    assert load_doc(run_dir)["stats"]["merged_auto"] == 1


def test_tier1_5_does_not_merge_four_lines_apart(tmp_path):
    run_dir = near_pair(tmp_path, second={"line": 146})
    assert assemble(run_dir) == 0
    assert load_doc(run_dir)["stats"]["merged"] == 0


def test_tier1_5_does_not_merge_across_functions(tmp_path):
    run_dir = near_pair(tmp_path, second={"function": "parse_body"})
    assert assemble(run_dir) == 0
    assert load_doc(run_dir)["stats"]["merged"] == 0


def test_tier1_5_does_not_merge_across_files(tmp_path):
    run_dir = near_pair(tmp_path, second={"file": "src/other.c"})
    assert assemble(run_dir) == 0
    assert load_doc(run_dir)["stats"]["merged"] == 0


@pytest.mark.parametrize(
    ("first", "second"),
    [
        ({}, {"function": "(file-level)"}),
        ({"function": "(file-level)"}, {}),
        ({"function": "(file-level)"}, {"function": "file_level"}),
        ({"function": "n/a"}, {"function": "-"}),
    ],
)
def test_tier1_5_never_merges_a_file_level_finding(tmp_path, first, second):
    """Two file-level findings sharing a file says nothing about them being one bug."""
    run_dir = near_pair(tmp_path, first, second)
    assert assemble(run_dir) == 0
    assert load_doc(run_dir)["stats"]["merged"] == 0


def test_tier1_5_chains_transitively_without_chaining_merged_into(tmp_path):
    """100-102-104 is one group even though the ends are four apart.

    Merging pairwise would want 100 into 102 and 102 into 104, and a `merged_into` pointing
    at something itself merged is not resolvable by any consumer.
    """
    run_dir = write_run(
        tmp_path,
        {
            "review-unit-01": producing_part(
                "review-unit-01",
                [
                    raw_finding(line=100, title="a", confidence="Medium"),
                    raw_finding(line=102, title="b", confidence="Medium"),
                    raw_finding(line=104, title="c", confidence="Medium"),
                ],
            )
        },
    )
    assert assemble(run_dir) == 0
    doc = load_doc(run_dir)
    keyed = by_key(doc)
    primary = keyed["review-unit-01#0"]["id"]
    assert doc["stats"]["merged_auto"] == 2
    assert doc["stats"]["primaries"] == 1
    assert keyed["review-unit-01#1"]["merged_into"] == primary
    assert keyed["review-unit-01#2"]["merged_into"] == primary
    live = {f["id"] for f in doc["findings"] if not f.get("merged_into")}
    assert all(f["merged_into"] in live for f in doc["findings"] if f.get("merged_into"))


def test_a_tier1_primary_demoted_by_tier1_5_takes_its_duplicates_with_it(tmp_path):
    """Tier 1 folds b into a; tier 1.5 then folds a into c. b must end up on c, not on a.

    a is live when tier 1.5 runs, so it is a candidate to lose — and if b were left pointing
    at it, `merged_into` would name a finding that is not in the reported set.
    """
    run_dir = write_run(
        tmp_path,
        {
            "review-unit-01": producing_part(
                "review-unit-01",
                [
                    raw_finding(title="a", confidence="Medium"),
                    raw_finding(title="b", confidence="Low"),
                    raw_finding(
                        line=142, title="c", confidence="High", bug_class="integer-overflow"
                    ),
                ],
            )
        },
    )
    assert assemble(run_dir) == 0
    doc = load_doc(run_dir)
    keyed = by_key(doc)
    winner = keyed["review-unit-01#2"]
    assert doc["stats"]["primaries"] == 1
    assert doc["stats"]["merged_auto"] == 2
    assert keyed["review-unit-01#0"]["merged_into"] == winner["id"]
    assert keyed["review-unit-01#1"]["merged_into"] == winner["id"]
    assert "merged_into" not in winner
    assert winner["also_known_as"] == sorted(
        [keyed["review-unit-01#0"]["id"], keyed["review-unit-01#1"]["id"]]
    )


def test_merged_auto_and_merged_agent_are_counted_separately(tmp_path):
    """The split is the evidence for whether the dedup agent is still worth spawning."""
    run_dir = write_run(
        tmp_path,
        {
            "review-unit-01": producing_part(
                "review-unit-01",
                [
                    raw_finding(line=142),
                    raw_finding(line=143, title="width"),
                    raw_finding(line=900, function="emit_frame", title="far away"),
                ],
            ),
            "dedup-01": {
                "part_id": "dedup-01",
                "merges": [
                    {
                        "primary": "review-unit-01#0",
                        "duplicates": ["review-unit-01#2"],
                        "rationale": "same cause site, different consequence",
                    }
                ],
            },
        },
    )
    assert assemble(run_dir) == 0
    stats = load_doc(run_dir)["stats"]
    assert stats["merged_auto"] == 1
    assert stats["merged_agent"] == 1
    assert stats["merged"] == 2
    assert stats["primaries"] == 1


def test_agent_merge_is_applied(tmp_path):
    run_dir = write_run(
        tmp_path,
        {
            "review-unit-01": producing_part(
                "review-unit-01",
                [raw_finding(), raw_finding(line=150, title="second site")],
            ),
            "dedup-01": {
                "part_id": "dedup-01",
                "merges": [
                    {
                        "primary": "review-unit-01#0",
                        "duplicates": ["review-unit-01#1"],
                        "rationale": "same cause site",
                    }
                ],
            },
        },
    )
    assert assemble(run_dir) == 0
    doc = load_doc(run_dir)
    keyed = by_key(doc)
    assert doc["stats"]["merged"] == 1
    assert keyed["review-unit-01#1"]["merged_into"] == keyed["review-unit-01#0"]["id"]


def test_merge_with_an_unknown_key_is_ignored_and_counted(tmp_path, capsys):
    run_dir = write_run(
        tmp_path,
        {
            "review-unit-01": producing_part("review-unit-01", [raw_finding()]),
            "dedup-01": {
                "part_id": "dedup-01",
                "merges": [
                    {"primary": "review-unit-01#0", "duplicates": ["review-unit-99#7"]},
                    {"primary": "nope#0", "duplicates": ["review-unit-01#0"]},
                ],
            },
        },
    )
    assert assemble(run_dir) == 0
    summary = json.loads(capsys.readouterr().out)
    assert summary["ignored_merges"] == 2
    assert load_doc(run_dir)["stats"]["merged"] == 0


def test_merge_of_an_already_merged_key_is_ignored_and_counted(tmp_path, capsys):
    """No chaining: merged_into must always name a finding that is itself a primary."""
    run_dir = write_run(
        tmp_path,
        {
            # a and b are a tier-1 pair, so b is already merged into a.
            "review-unit-01": producing_part(
                "review-unit-01",
                [raw_finding(confidence="High"), raw_finding(confidence="Low")],
            ),
            "review-unit-02": producing_part(
                "review-unit-02", [raw_finding(line=300, title="third")]
            ),
            "dedup-01": {
                "part_id": "dedup-01",
                "merges": [
                    {"primary": "review-unit-02#0", "duplicates": ["review-unit-01#1"]},
                    {"primary": "review-unit-01#1", "duplicates": ["review-unit-02#0"]},
                ],
            },
        },
    )
    assert assemble(run_dir) == 0
    summary = json.loads(capsys.readouterr().out)
    assert summary["ignored_merges"] == 2
    doc = load_doc(run_dir)
    keyed = by_key(doc)
    assert doc["stats"]["merged"] == 1
    assert keyed["review-unit-01#1"]["merged_into"] == keyed["review-unit-01#0"]["id"]
    ids = {f["id"] for f in doc["findings"] if not f.get("merged_into")}
    assert all(f["merged_into"] in ids for f in doc["findings"] if f.get("merged_into"))


# ------------------------------------------------------------------ verdicts


def test_verdict_is_applied_to_its_finding(tmp_path):
    run_dir = write_run(
        tmp_path,
        {
            "review-unit-01": producing_part("review-unit-01", [raw_finding()]),
            "verdict-01": {"part_id": "verdict-01", "verdicts": [verdict("review-unit-01#0")]},
        },
    )
    assert assemble(run_dir) == 0
    doc = load_doc(run_dir)
    finding = doc["findings"][0]
    assert finding["fp_verdict"] == "TRUE_POSITIVE"
    assert finding["severity"] == "HIGH"
    assert finding["attack_vector"] == "Remote"
    assert finding["exploitability"] == "Reliable"
    assert finding["severity_validated"] is True
    assert doc["run"]["unjudged_findings"] == []
    assert doc["stats"]["verdict_counts"] == {"TRUE_POSITIVE": 1}
    assert doc["stats"]["severity_counts"] == {"HIGH": 1}


def test_unjudged_primary_gets_the_exact_fallback(tmp_path, capsys):
    """Without --no-judge a primary with no verdict is still a judge failure.

    This is the only way to reproduce the judged configuration for comparison, so the
    rationale string is asserted literally rather than through the constant alone.
    """
    run_dir = write_run(
        tmp_path,
        {
            "review-unit-01": producing_part(
                "review-unit-01", [raw_finding(severity="LOW", attack_vector="Local")]
            )
        },
    )
    assert assemble(run_dir) == 0
    summary = json.loads(capsys.readouterr().out)
    doc = load_doc(run_dir)
    finding = doc["findings"][0]
    assert finding["fp_verdict"] == "LIKELY_TP"
    assert finding["fp_rationale"] == UNJUDGED_RATIONALE
    assert finding["fp_rationale"] == "JUDGE DID NOT RUN — verdict and severity are unvalidated"
    # The reviewer said LOW; without --no-judge that is not authoritative and the fallback
    # overwrites it, exactly as before reviewer severity existed.
    assert finding["severity"] == "MEDIUM"
    assert finding["severity_validated"] is False
    assert "severity_source" not in finding
    assert doc["run"]["judge_ran"] is True
    assert doc["run"]["unjudged_findings"] == [finding["id"]]
    assert doc["run"]["unjudged_keys"] == ["review-unit-01#0"]
    assert summary["unjudged"] == 1
    assert "unvalidated severity" in (run_dir / "REPORT.md").read_text(encoding="utf-8")


# ------------------------------------------------------------------ --no-judge


def test_no_judge_makes_the_reviewer_severity_authoritative(tmp_path, capsys):
    run_dir = write_run(
        tmp_path,
        {
            "review-unit-01": producing_part(
                "review-unit-01",
                [
                    raw_finding(
                        severity="CRITICAL", attack_vector="Remote", exploitability="Reliable"
                    )
                ],
            )
        },
    )
    assert assemble(run_dir, "--no-judge") == 0
    summary = json.loads(capsys.readouterr().out)
    doc = load_doc(run_dir)
    finding = doc["findings"][0]
    assert finding["severity"] == "CRITICAL"
    assert finding["attack_vector"] == "Remote"
    assert finding["exploitability"] == "Reliable"
    assert finding["severity_source"] == "reviewer"
    assert finding["fp_verdict"] == "LIKELY_TP"
    assert finding["fp_rationale"] == REVIEWER_RATIONALE
    # True on purpose: reported_findings() exempts unvalidated findings from the severity
    # filter, so False here would silently disable --severity-filter for the whole run.
    assert finding["severity_validated"] is True
    assert doc["run"]["judge_ran"] is False
    # `judge_mode: batched` beside `judge_ran: false` would read as a judge that ran and
    # rejected nothing, which is the opposite of what happened.
    assert doc["run"]["judge_mode"] is None
    assert doc["run"]["judge_batch_size"] is None
    assert doc["run"]["unjudged_findings"] == []
    assert doc["run"]["unjudged_keys"] == []
    assert summary["unjudged"] == 0
    assert doc["stats"]["severity_counts"] == {"CRITICAL": 1}


def test_no_judge_severity_filter_still_filters(tmp_path):
    """The regression `severity_validated=True` exists to prevent.

    With it False, `reported_findings()` exempts every finding from the filter and
    `--severity-filter high` reports the LOW one too.
    """
    run_dir = write_run(
        tmp_path,
        {
            "review-unit-01": producing_part(
                "review-unit-01",
                [
                    raw_finding(title="low one", severity="LOW"),
                    raw_finding(line=300, title="high one", severity="HIGH"),
                ],
            )
        },
    )
    assert assemble(run_dir, "--no-judge", "--severity-filter", "high") == 0
    doc = load_doc(run_dir)
    assert doc["stats"]["survivors"] == 2
    assert doc["stats"]["reported"] == 1
    report = (run_dir / "REPORT.md").read_text(encoding="utf-8")
    assert "high one" in report
    assert "low one" not in report.split("## Not reported")[0]
    sarif = json.loads((run_dir / "REPORT.sarif").read_text(encoding="utf-8"))
    assert [r["message"]["text"] for r in sarif["runs"][0]["results"]] == ["high one"]


@pytest.mark.parametrize("severity", [None, "", "Critical!!", 7])
def test_no_judge_defaults_an_unusable_reviewer_severity_to_medium(tmp_path, severity):
    """A severity findings_model cannot score would be dropped by a `high` filter.

    MEDIUM is wrong but visible; silently unfiltered is not.
    """
    run_dir = write_run(
        tmp_path,
        {"review-unit-01": producing_part("review-unit-01", [raw_finding(severity=severity)])},
    )
    assert assemble(run_dir, "--no-judge") == 0
    finding = load_doc(run_dir)["findings"][0]
    assert finding["severity"] == "MEDIUM"
    assert finding["severity_validated"] is True


def test_no_judge_upper_cases_a_lowercase_reviewer_severity(tmp_path):
    run_dir = write_run(
        tmp_path,
        {"review-unit-01": producing_part("review-unit-01", [raw_finding(severity="high")])},
    )
    assert assemble(run_dir, "--no-judge") == 0
    doc = load_doc(run_dir)
    assert doc["findings"][0]["severity"] == "HIGH"
    assert doc["stats"]["severity_counts"] == {"HIGH": 1}


def test_a_verdict_still_overrides_the_reviewer_under_no_judge(tmp_path):
    """The judged and unjudged configurations must be comparable on one run directory."""
    run_dir = write_run(
        tmp_path,
        {
            "review-unit-01": producing_part(
                "review-unit-01", [raw_finding(severity="CRITICAL", attack_vector="Remote")]
            ),
            "verdict-01": {
                "part_id": "verdict-01",
                "verdicts": [verdict("review-unit-01#0", severity="LOW", attack_vector="Local")],
            },
        },
    )
    assert assemble(run_dir, "--no-judge") == 0
    doc = load_doc(run_dir)
    finding = doc["findings"][0]
    assert finding["severity"] == "LOW"
    assert finding["attack_vector"] == "Local"
    assert finding["fp_verdict"] == "TRUE_POSITIVE"
    assert finding["fp_rationale"] == "no bound between source and sink"
    assert "severity_source" not in finding
    assert doc["run"]["unjudged_findings"] == []


def test_a_rejecting_verdict_drops_the_reviewer_severity(tmp_path):
    """A FALSE_POSITIVE must not be listed as the reviewer's CRITICAL in "Not reported"."""
    run_dir = write_run(
        tmp_path,
        {
            "review-unit-01": producing_part(
                "review-unit-01",
                [raw_finding(severity="CRITICAL", attack_vector="Remote", exploitability="Easy")],
            ),
            "verdict-01": {
                "part_id": "verdict-01",
                "verdicts": [verdict("review-unit-01#0", fp_verdict="FALSE_POSITIVE", severity="")],
            },
        },
    )
    assert assemble(run_dir, "--no-judge") == 0
    finding = load_doc(run_dir)["findings"][0]
    assert "severity" not in finding
    assert "attack_vector" not in finding
    assert "exploitability" not in finding


def test_no_judge_report_says_the_severity_is_reviewer_assigned(tmp_path):
    run_dir = write_run(
        tmp_path,
        {"review-unit-01": producing_part("review-unit-01", [raw_finding(severity="HIGH")])},
    )
    assert assemble(run_dir, "--no-judge") == 0
    report = (run_dir / "REPORT.md").read_text(encoding="utf-8")
    assert "reviewer-assigned and unreviewed" in report
    assert "No false-positive pass ran in this configuration" in report
    # The unjudged-fallback warning is a different thing and must not appear here.
    assert "unvalidated severity" not in report


def test_verdict_for_an_unknown_key_is_ignored_and_counted(tmp_path, capsys):
    run_dir = write_run(
        tmp_path,
        {
            "review-unit-01": producing_part("review-unit-01", [raw_finding()]),
            "verdict-01": {
                "part_id": "verdict-01",
                "verdicts": [verdict("review-unit-01#9"), verdict("other#0")],
            },
        },
    )
    assert assemble(run_dir) == 0
    summary = json.loads(capsys.readouterr().out)
    assert summary["ignored_verdicts"] == 2
    assert summary["unjudged"] == 1
    assert load_doc(run_dir)["findings"][0]["fp_verdict"] == "LIKELY_TP"


def test_first_verdict_for_a_key_wins(tmp_path, capsys):
    run_dir = write_run(
        tmp_path,
        {
            "review-unit-01": producing_part("review-unit-01", [raw_finding()]),
            "verdict-01": {
                "part_id": "verdict-01",
                "verdicts": [verdict("review-unit-01#0", severity="HIGH")],
            },
            "verdict-02": {
                "part_id": "verdict-02",
                "verdicts": [verdict("review-unit-01#0", severity="LOW")],
            },
        },
    )
    assert assemble(run_dir) == 0
    assert json.loads(capsys.readouterr().out)["ignored_verdicts"] == 1
    assert load_doc(run_dir)["findings"][0]["severity"] == "HIGH"


def test_non_survivor_carries_no_severity(tmp_path):
    run_dir = write_run(
        tmp_path,
        {
            "review-unit-01": producing_part("review-unit-01", [raw_finding()]),
            "verdict-01": {
                "part_id": "verdict-01",
                "verdicts": [
                    verdict(
                        "review-unit-01#0",
                        fp_verdict="FALSE_POSITIVE",
                        fp_rationale="the caller bounds len at src/dispatch.c:88",
                    )
                ],
            },
        },
    )
    assert assemble(run_dir) == 0
    doc = load_doc(run_dir)
    finding = doc["findings"][0]
    assert finding["fp_verdict"] == "FALSE_POSITIVE"
    assert "severity" not in finding
    assert "attack_vector" not in finding
    assert finding["severity_validated"] is True
    assert doc["stats"]["survivors"] == 0
    assert doc["stats"]["reported"] == 0


def test_survivor_without_a_severity_is_medium_and_unvalidated(tmp_path):
    run_dir = write_run(
        tmp_path,
        {
            "review-unit-01": producing_part("review-unit-01", [raw_finding()]),
            "verdict-01": {
                "part_id": "verdict-01",
                "verdicts": [verdict("review-unit-01#0", severity="")],
            },
        },
    )
    assert assemble(run_dir) == 0
    finding = load_doc(run_dir)["findings"][0]
    assert finding["severity"] == "MEDIUM"
    assert finding["severity_validated"] is False


def test_a_merged_duplicate_is_never_judged_or_left_unjudged(tmp_path, capsys):
    run_dir = write_run(
        tmp_path,
        {
            "review-unit-01": producing_part("review-unit-01", [raw_finding(confidence="High")]),
            "second-01": producing_part("second-01", [raw_finding(confidence="Low")]),
            "verdict-01": {
                "part_id": "verdict-01",
                "verdicts": [verdict("review-unit-01#0"), verdict("second-01#0")],
            },
        },
    )
    assert assemble(run_dir) == 0
    summary = json.loads(capsys.readouterr().out)
    assert summary["unjudged"] == 0
    assert summary["ignored_verdicts"] == 1
    duplicate = by_key(load_doc(run_dir))["second-01#0"]
    assert "fp_verdict" not in duplicate
    assert "severity" not in duplicate


def test_severity_filter_reaches_the_reported_count(tmp_path):
    run_dir = write_run(
        tmp_path,
        {
            "review-unit-01": producing_part(
                "review-unit-01",
                [raw_finding(title="low one"), raw_finding(line=200, title="high one")],
            ),
            "verdict-01": {
                "part_id": "verdict-01",
                "verdicts": [
                    verdict("review-unit-01#0", severity="LOW"),
                    verdict("review-unit-01#1", severity="HIGH"),
                ],
            },
        },
    )
    assert assemble(run_dir, "--severity-filter", "high") == 0
    doc = load_doc(run_dir)
    assert doc["run"]["severity_filter"] == "high"
    assert doc["stats"]["survivors"] == 2
    assert doc["stats"]["reported"] == 1


# ------------------------------------------------------------------ public ids


def test_public_ids_are_location_sorted_and_per_prefix_sequential(tmp_path):
    run_dir = write_run(
        tmp_path,
        {
            "review-unit-01": producing_part(
                "review-unit-01",
                [
                    raw_finding(file="src/z.c", line=10, title="z"),
                    raw_finding(file="src/a.c", line=90, title="a90"),
                    raw_finding(file="src/a.c", line=9, title="a9"),
                    raw_finding(
                        file="src/a.c", line=5, title="int here", bug_class="integer-overflow"
                    ),
                ],
            )
        },
    )
    assert assemble(run_dir) == 0
    doc = load_doc(run_dir)
    ordered = [(f["file"], f["line"], f["id"]) for f in doc["findings"]]
    assert ordered == [
        ("src/a.c", 5, "INT-001"),
        ("src/a.c", 9, "BOF-001"),
        ("src/a.c", 90, "BOF-002"),
        ("src/z.c", 10, "BOF-003"),
    ]


def test_ids_are_stable_when_an_unrelated_part_grows(tmp_path):
    """An id must depend on the finding's own location, not on how many others there are."""
    first = write_run(
        tmp_path / "one",
        {
            "review-unit-01": producing_part(
                "review-unit-01", [raw_finding(file="src/z.c", line=10, title="anchor")]
            )
        },
    )
    assert assemble(first) == 0
    anchor = load_doc(first)["findings"][0]["id"]

    second = write_run(
        tmp_path / "two",
        {
            "review-unit-01": producing_part(
                "review-unit-01", [raw_finding(file="src/z.c", line=10, title="anchor")]
            ),
            "review-unit-02": producing_part(
                "review-unit-02",
                [raw_finding(file="src/z.c", line=20, title="later", bug_class="memory-leak")],
            ),
        },
    )
    assert assemble(second) == 0
    kept = next(f for f in load_doc(second)["findings"] if f["title"] == "anchor")
    assert kept["id"] == anchor == "BOF-001"


# ------------------------------------------------------------------ run block


def test_run_block_carries_detect_units_ledger_and_flags(tmp_path):
    run_dir = write_run(
        tmp_path,
        {
            "review-unit-01": producing_part(
                "review-unit-01",
                [raw_finding()],
                external_sources_consulted=True,
                external_sources_detail="read zlib upstream",
                notes="could not read generated headers",
            )
        },
        detect={
            "is_cpp": False,
            "is_posix": True,
            "is_windows": False,
            "platform_evidence": "src/net.c:12 calls recv()",
            "purpose": "decompression library",
            "entry_points": ["src/net.c:12 network read"],
            "trust_boundaries": ["network"],
            "existing_hardening": ["ASAN in CI"],
        },
        units={"totals": {"units": 41, "checks_required": 180}, "units": []},
    )
    assert (
        assemble(
            run_dir,
            "--scope",
            "src",
            "--context-roots",
            "include",
            "--worker-model",
            "sonnet",
            "--judge-mode",
            "single",
            "--judge-batch-size",
            "7",
            "--groups-attempted",
            "memory-bounds, integer-safety",
            "--groups-failed",
            "concurrency",
            "--agent-failure",
            "sweep-02 timed out",
        )
        == 0
    )
    run = load_doc(run_dir)["run"]
    assert run["is_posix"] is True
    assert run["purpose"] == "decompression library"
    assert run["entry_points"] == ["src/net.c:12 network read"]
    assert run["finding_scope_root"] == "src"
    assert run["context_roots"] == "include"
    assert run["worker_model"] == "sonnet"
    assert run["judge_mode"] == "single"
    assert run["judge_batch_size"] == 7
    assert run["groups_attempted"] == ["memory-bounds", "integer-safety"]
    assert run["groups_failed"] == ["concurrency"]
    assert run["agent_failures"] == ["sweep-02 timed out"]
    assert run["units"] == {"units": 41, "checks_required": 180}
    assert run["judge_ran"] is True
    # units.json carries totals but no unit list, so the gate has nothing to check and says
    # so. See the ledger section for the case where it runs.
    assert "lists no units" in run["ledger"]["error"]
    assert run["hunter_notes"] == ["review-unit-01: could not read generated headers"]
    assert run["hunter_external_sources"] == [
        {"group": "review-unit-01", "consulted": True, "detail": "read zlib upstream"}
    ]


def test_absent_optional_inputs_leave_null_not_a_crash(tmp_path):
    run_dir = write_run(
        tmp_path, {"review-unit-01": producing_part("review-unit-01", [raw_finding()])}
    )
    assert assemble(run_dir) == 0
    run = load_doc(run_dir)["run"]
    assert run["ledger"] is None
    assert run["units"] is None
    assert run["is_cpp"] is None


# ------------------------------------------------------------------ ledger gate


LEDGER_UNIT = {
    "id": "src/parse.c:parse_header",
    "file": "src/parse.c",
    "name": "parse_header",
    "start_line": 100,
    "end_line": 200,
    "sites": {"write": [142, 150]},
    "required_questions": ["bounds"],
}
LEDGER_ROW = {
    "unit_id": "src/parse.c:parse_header",
    "question": "bounds",
    "verdict": "finding",
    "sites_accounted": [142, 150],
    "evidence": "142 is the reported overflow; 150 is bounded by sizeof(buf)",
}


def test_the_ledger_gate_runs_in_process_and_lands_in_the_run_block(tmp_path, capsys):
    """No separate gate agent: check_ledger is imported and called, like the generators."""
    run_dir = write_run(
        tmp_path,
        {"review-unit-01": producing_part("review-unit-01", [raw_finding()], ledger=[LEDGER_ROW])},
        units={"units": [LEDGER_UNIT], "totals": {"units": 1, "checks_required": 1}},
    )
    assert assemble(run_dir) == 0
    capsys.readouterr()
    ledger = load_doc(run_dir)["run"]["ledger"]
    assert ledger["checks_required"] == 1
    assert ledger["checks_completed"] == 1
    assert ledger["coverage_pct"] == 100.0
    assert ledger["violation_count"] == 0
    # The full report is on disk; run.ledger is the compact projection of it.
    on_disk = json.loads((run_dir / "ledger-gate.json").read_text(encoding="utf-8"))
    assert on_disk["checks_required"] == 1
    assert on_disk["units_with_findings"][0]["unit_id"] == "src/parse.c:parse_header"


def test_the_gate_reports_an_incomplete_ledger_without_failing_the_assembly(tmp_path):
    """A gap is the gate's answer, not an error: the findings still ship, flagged."""
    run_dir = write_run(
        tmp_path,
        {"review-unit-01": producing_part("review-unit-01", [raw_finding()], ledger=[])},
        units={"units": [LEDGER_UNIT, dict(LEDGER_UNIT, id="src/parse.c:emit")]},
    )
    # One row present for two owed, so the gate has something to check and reports the gap.
    part = run_dir / "parts" / "review-unit-01.json"
    doc = json.loads(part.read_text(encoding="utf-8"))
    doc["ledger"] = [LEDGER_ROW]
    part.write_text(json.dumps(doc), encoding="utf-8")

    assert assemble(run_dir) == 0
    ledger = load_doc(run_dir)["run"]["ledger"]
    assert ledger["checks_required"] == 2
    assert ledger["checks_completed"] == 1
    assert ledger["missing_row_count"] == 1


def test_a_ledger_error_is_recorded_and_never_aborts_the_assembly(tmp_path, capsys):
    """Nothing to check is a broken gate, not a broken review.

    A gate failure that took the report with it would trade a visible warning for a lost
    run; a gate failure recorded nowhere would read exactly like a gate that passed.
    """
    run_dir = write_run(
        tmp_path,
        {"review-unit-01": producing_part("review-unit-01", [raw_finding()])},
        units={"units": [LEDGER_UNIT]},
    )
    assert assemble(run_dir) == 0
    captured = capsys.readouterr()
    assert "ledger gate did not run" in captured.err
    assert json.loads(captured.out)["ok"] is True
    doc = load_doc(run_dir)
    assert "zero ledger rows" in doc["run"]["ledger"]["error"]
    assert len(doc["findings"]) == 1
    assert (run_dir / "findings.json").is_file()
    assert (run_dir / "REPORT.md").is_file()
    assert (run_dir / "REPORT.sarif").is_file()
    assert not (run_dir / "ledger-gate.json").exists()


def test_no_unit_list_means_no_gate_and_no_failure(tmp_path):
    """Running without a parse is a configuration, not a gap to report."""
    run_dir = write_run(
        tmp_path,
        {"review-unit-01": producing_part("review-unit-01", [raw_finding()], ledger=[LEDGER_ROW])},
    )
    assert assemble(run_dir) == 0
    assert load_doc(run_dir)["run"]["ledger"] is None
    assert not (run_dir / "ledger-gate.json").exists()


def test_an_existing_gate_file_is_honoured_when_there_is_no_unit_list(tmp_path):
    run_dir = write_run(
        tmp_path,
        {"review-unit-01": producing_part("review-unit-01", [raw_finding()])},
        ledger_gate={"checks_required": 180, "checks_completed": 179},
    )
    assert assemble(run_dir) == 0
    assert load_doc(run_dir)["run"]["ledger"] == {"checks_required": 180, "checks_completed": 179}


def test_coverage_rows_come_from_the_part_ledgers(tmp_path):
    run_dir = write_run(
        tmp_path,
        {
            "review-unit-01": producing_part(
                "review-unit-01",
                [raw_finding()],
                ledger=[
                    {
                        "unit_id": "src/parse.c:parse_header",
                        "question": "bounds",
                        "verdict": "finding",
                        "sites_accounted": [142, 150],
                        "evidence": "both writes bounded by len",
                    }
                ],
            )
        },
    )
    assert assemble(run_dir) == 0
    coverage = load_doc(run_dir)["coverage"]
    assert coverage == [
        {
            "group": "review-unit-01",
            "bug_class": "bounds",
            "outcome": "finding",
            "population": "2 site(s): 142, 150",
            "evidence": "both writes bounded by len",
            "unit_id": "src/parse.c:parse_header",
        }
    ]
    assert "both writes bounded by len" in (run_dir / "REPORT.md").read_text(encoding="utf-8")


# ------------------------------------------------------------------ failure modes


def test_missing_run_dir_exits_2(tmp_path, capsys):
    missing = tmp_path / "nope"
    assert assemble(missing) == 2
    assert "run directory does not exist" in capsys.readouterr().err
    assert not missing.exists()


def test_missing_parts_dir_exits_2(tmp_path, capsys):
    run_dir = tmp_path / "run"
    run_dir.mkdir()
    assert assemble(run_dir) == 2
    assert "no parts directory" in capsys.readouterr().err
    assert list(run_dir.iterdir()) == []


def test_zero_part_files_exits_2(tmp_path, capsys):
    """A checker that inspects zero items must fail. An empty parts/ is every agent lost."""
    run_dir = write_run(tmp_path, {})
    assert assemble(run_dir) == 2
    assert "holds no part files" in capsys.readouterr().err
    assert not (run_dir / "findings.json").exists()
    assert not (run_dir / "REPORT.md").exists()
    assert not (run_dir / "REPORT.sarif").exists()


def test_parts_present_but_none_producing_exits_2(tmp_path, capsys):
    """The same rule one level down: files present, but nothing that reviewed any code.

    Counting part *files* passes when every review and sweep agent died and only `detect`
    wrote one. That assembled to `producing_parts: 0`, zero findings, zero coverage, exit 0
    and a clean REPORT.md reading as "no findings" — indistinguishable from a clean
    codebase, and collected by the bench as zero recall for the tool rather than a failed
    run.
    """
    run_dir = write_run(tmp_path, {"detect-01": '{"purpose": "x", "is_cpp": false}'})
    assert assemble(run_dir) == 2
    err = capsys.readouterr().err
    assert "none of them is a producing part" in err
    assert "detect-01" in err
    assert not (run_dir / "findings.json").exists()
    assert not (run_dir / "REPORT.md").exists()
    assert not (run_dir / "REPORT.sarif").exists()


def test_one_producing_part_among_non_producing_ones_is_enough(tmp_path):
    """The guard must not fire on a real run, which carries non-producing parts too."""
    run_dir = write_run(
        tmp_path,
        {
            "detect-01": '{"purpose": "x", "is_cpp": false}',
            "review-unit-01": producing_part("review-unit-01", [raw_finding()]),
        },
    )
    assert assemble(run_dir) == 0
    doc = json.loads((run_dir / "findings.json").read_text())
    assert doc["stats"]["producing_parts"] == 1


def test_a_part_that_is_not_valid_json_exits_2(tmp_path, capsys):
    run_dir = write_run(
        tmp_path,
        {
            "review-unit-01": producing_part("review-unit-01", [raw_finding()]),
            "review-unit-02": '{"findings": [{"title": "trunc',
        },
    )
    assert assemble(run_dir) == 2
    assert "is not valid JSON" in capsys.readouterr().err
    assert not (run_dir / "findings.json").exists()
    assert not (run_dir / "REPORT.md").exists()


def test_a_part_that_is_not_an_object_exits_2(tmp_path, capsys):
    run_dir = write_run(
        tmp_path,
        {
            "review-unit-01": producing_part("review-unit-01", [raw_finding()]),
            "review-unit-02": "[1, 2, 3]",
        },
    )
    assert assemble(run_dir) == 2
    assert "expected a JSON object" in capsys.readouterr().err
    assert not (run_dir / "findings.json").exists()


def test_expect_catches_a_missing_part(tmp_path, capsys):
    run_dir = write_run(
        tmp_path, {"review-unit-01": producing_part("review-unit-01", [raw_finding()])}
    )
    assert assemble(run_dir, "--expect", "review-unit-01", "--expect", "invariant-01") == 2
    err = capsys.readouterr().err
    assert "invariant-01" in err
    assert "review-unit-01" not in err.split("absent from")[1]
    assert not (run_dir / "findings.json").exists()


def test_expect_passes_when_every_named_part_is_present(tmp_path):
    run_dir = write_run(
        tmp_path,
        {
            "review-unit-01": producing_part("review-unit-01", [raw_finding()]),
            "invariant-01": producing_part("invariant-01", []),
        },
    )
    assert assemble(run_dir, "--expect", "review-unit-01", "--expect", "invariant-01.json") == 0


def test_a_corrupt_optional_input_exits_2(tmp_path, capsys):
    """Absent is allowed; unparseable is not — "no ledger" must not mean "ledger broke"."""
    run_dir = write_run(
        tmp_path, {"review-unit-01": producing_part("review-unit-01", [raw_finding()])}
    )
    (run_dir / "ledger-gate.json").write_text("{oops", encoding="utf-8")
    assert assemble(run_dir) == 2
    assert "ledger gate" in capsys.readouterr().err
    assert not (run_dir / "findings.json").exists()


def test_an_unrecognised_part_is_counted_and_warned_about(tmp_path, capsys):
    run_dir = write_run(
        tmp_path,
        {
            "review-unit-01": producing_part("review-unit-01", [raw_finding()]),
            "reviewunit02": producing_part("reviewunit02", [raw_finding(line=999)]),
        },
    )
    assert assemble(run_dir) == 0
    captured = capsys.readouterr()
    assert "no rule reads part file(s) reviewunit02" in captured.err
    assert json.loads(captured.out)["unrecognised_parts"] == 1
    assert load_doc(run_dir)["stats"]["raw_findings"] == 1


# ------------------------------------------------------------------ clean run


def test_a_zero_findings_run_succeeds_and_writes_all_three_artifacts(tmp_path, capsys):
    run_dir = write_run(
        tmp_path,
        {
            "review-unit-01": producing_part(
                "review-unit-01",
                [],
                ledger=[
                    {
                        "unit_id": "src/parse.c:parse_header",
                        "question": "bounds",
                        "verdict": "clean",
                        "sites_accounted": [10],
                        "evidence": "the single write is bounded by sizeof(buf)",
                    }
                ],
            )
        },
    )
    assert assemble(run_dir) == 0
    summary = json.loads(capsys.readouterr().out)
    assert summary["stats"]["raw_findings"] == 0
    assert summary["stats"]["reported"] == 0
    assert (run_dir / "findings.json").is_file()
    assert (run_dir / "REPORT.md").is_file()
    assert (run_dir / "REPORT.sarif").is_file()
    assert "No findings passed" in (run_dir / "REPORT.md").read_text(encoding="utf-8")
    assert json.loads((run_dir / "REPORT.sarif").read_text())["runs"][0]["results"] == []


# ------------------------------------------------------------------ catalogue drift


def _js_class_keys() -> list[str]:
    """Top-level keys of the JS workflow's CLASSES object, extracted tolerantly."""
    if not WORKFLOW_JS.is_file():
        return []
    text = WORKFLOW_JS.read_text(encoding="utf-8")
    start = text.find("const CLASSES")
    if start < 0:
        return []
    body = text[start:]
    end = body.find("\n}\n")
    if end > 0:
        body = body[:end]
    return re.findall(r"^ {2}['\"]?([a-z][a-z0-9-]*)['\"]?\s*:\s*\{", body, re.MULTILINE)


def test_class_prefixes_match_the_js_catalogue():
    """CLASS_PREFIXES is a copy of the JS CLASSES key set; this is what keeps it a copy.

    A class the JS spawns a hunter for but this file does not know silently becomes
    `logic-flaw` here, so its findings land under the wrong id prefix and the wrong SARIF
    rule — a drift no other check would notice.
    """
    keys = _js_class_keys()
    if len(keys) < 40:
        pytest.fail(
            f"catalogue extraction matched {len(keys)} classes — the regex is broken, "
            f"not the catalogue"
        )
    assert len(set(keys)) == len(keys), "the JS catalogue has a duplicate key"
    js = set(keys)
    mine = set(CLASS_PREFIXES)
    assert js == mine, (
        f"catalogue drift: only in c-review.js {sorted(js - mine)}; "
        f"only in CLASS_PREFIXES {sorted(mine - js)}"
    )


def test_every_class_has_a_distinct_prefix():
    prefixes = list(CLASS_PREFIXES.values())
    assert len(set(prefixes)) == len(prefixes)
    assert len(CLASS_PREFIXES) == 56


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-q"]))


def _pointer_run(tmp_path, owner_findings, pointers):
    run = tmp_path / "ptr"
    (run / "parts").mkdir(parents=True)
    (run / "parts" / "review-unit-01.json").write_text(
        json.dumps({"findings": owner_findings, "ledger": []}), encoding="utf-8"
    )
    (run / "parts" / "review-unit-02.json").write_text(
        json.dumps({"findings": [], "ledger": [], "pointers": pointers}), encoding="utf-8"
    )
    return run


def _f(line, **kw):
    base = {
        "bug_class": "buffer-overflow",
        "title": "owner finding",
        "file": "src/a.c",
        "line": line,
        "function": "owner_fn",
        "confidence": "High",
        "description": "d",
        "code": "c",
        "impact": "i",
        "recommendation": "r",
        "severity": "HIGH",
    }
    base.update(kw)
    return base


def test_a_pointer_nobody_owned_is_promoted_to_a_finding(tmp_path):
    """The safety net for the out-of-slice rule.

    Reviewers are told not to write up bugs outside their own units, because those lines
    have an owner. That is only safe if a pointer the owner then missed still reaches the
    report — otherwise the instruction silently loses bugs.
    """
    run = _pointer_run(
        tmp_path,
        [_f(10)],
        [{"file": "src/b.c", "line": 400, "note": "len is never bounded before the copy"}],
    )
    assert (
        main(
            [
                "--run-dir",
                str(run),
                "--threat-model",
                "REMOTE",
                "--severity-filter",
                "all",
                "--no-judge",
            ]
        )
        == 0
    )
    doc = json.loads((run / "findings.json").read_text())
    promoted = [f for f in doc["findings"] if f.get("from_pointer")]
    assert len(promoted) == 1, "an unclaimed pointer must become a finding"
    assert promoted[0]["file"] == "src/b.c" and promoted[0]["line"] == 400
    assert "never bounded" in promoted[0]["description"]
    assert doc["run"]["pointers_promoted"] == 1


def test_a_pointer_the_owner_already_filed_is_dropped(tmp_path):
    """The cost saving. The owner's write-up is the better one; the pointer is redundant."""
    run = _pointer_run(
        tmp_path,
        [_f(100)],
        [{"file": "src/a.c", "line": 104, "note": "same bug, seen from another slice"}],
    )
    assert (
        main(
            [
                "--run-dir",
                str(run),
                "--threat-model",
                "REMOTE",
                "--severity-filter",
                "all",
                "--no-judge",
            ]
        )
        == 0
    )
    doc = json.loads((run / "findings.json").read_text())
    assert [f for f in doc["findings"] if f.get("from_pointer")] == []
    assert doc["run"]["pointers_seen"] == 1
    assert doc["run"]["pointers_promoted"] == 0


def test_two_pointers_at_one_place_promote_once(tmp_path):
    run = _pointer_run(
        tmp_path,
        [_f(10)],
        [
            {"file": "src/b.c", "line": 400, "note": "unbounded copy"},
            {"file": "src/b.c", "line": 402, "note": "also looks unbounded"},
        ],
    )
    assert (
        main(
            [
                "--run-dir",
                str(run),
                "--threat-model",
                "REMOTE",
                "--severity-filter",
                "all",
                "--no-judge",
            ]
        )
        == 0
    )
    doc = json.loads((run / "findings.json").read_text())
    assert len([f for f in doc["findings"] if f.get("from_pointer")]) == 1


def _js_const(name: str) -> int | None:
    """Read `const <name> = <int>` out of the workflow, or None if absent."""
    if not WORKFLOW_JS.is_file():
        return None
    m = re.search(rf"^const {name} = (\d+)\s*$", WORKFLOW_JS.read_text(encoding="utf-8"), re.M)
    return int(m.group(1)) if m else None


@pytest.mark.parametrize("name", ["NEARBY_LINES", "CROSS_CLASS_NEARBY_LINES"])
def test_the_merge_windows_match_between_the_js_and_this_module(name):
    """Both files implement the same near-duplicate rule; nothing but this keeps them equal.

    The JS side uses these to drop pairs from the dedup agent's prompt on the grounds that
    the assembler already merged them. If the two disagree, a pair the JS considers handled
    and the assembler declines to merge is never merged by anyone — it falls between the two
    rules and is reported twice, or worse, the reverse: merged by the JS accounting and
    dropped from the agent's prompt while the assembler leaves both live.
    """
    js = _js_const(name)
    if js is None:
        pytest.skip(f"{name} not found in the workflow")
    assert js == getattr(assemble_findings_mod, name), (
        f"{name} is {js} in c-review.js and "
        f"{getattr(assemble_findings_mod, name)} in assemble_findings.py"
    )


# ------------------------------------------------- hand assembly loses the bookkeeping


def test_no_expect_warns_and_records_that_coverage_was_never_checked(tmp_path, capsys):
    """A checker handed zero items must not report success.

    The workflow always passes one `--expect` per dispatched agent, so an empty list means
    a hand assembly — the documented recovery path when the assemble agent dies. On the
    2026-08-07 slice cell one review agent never wrote its part file; the workflow logged
    the gap, and the hand-assembled document then carried `agent_failures: []` with a full
    `parts_read`, which reads as a complete 13-slice run rather than the 12-slice run it
    was. Nothing can recover the expectation after the fact, so the document has to say it
    was never checked instead of letting an empty failure list mean "no failures".
    """
    run_dir = write_run(
        tmp_path, {"review-unit-01": producing_part("review-unit-01", [raw_finding()])}
    )
    assert assemble(run_dir) == 0
    assert "no --expect given" in capsys.readouterr().err
    assert load_doc(run_dir)["run"]["expectations_checked"] is False


def test_expect_marks_the_document_as_checked(tmp_path):
    run_dir = write_run(
        tmp_path, {"review-unit-01": producing_part("review-unit-01", [raw_finding()])}
    )
    assert assemble(run_dir, "--expect", "review-unit-01=1") == 0
    assert load_doc(run_dir)["run"]["expectations_checked"] is True


def test_a_missing_part_is_still_fatal_when_it_was_expected(tmp_path, capsys):
    """The guard the slice cell needed: name the dispatched part and the loss is caught."""
    run_dir = write_run(
        tmp_path, {"review-unit-01": producing_part("review-unit-01", [raw_finding()])}
    )
    assert assemble(run_dir, "--expect", "review-unit-01=1", "--expect", "review-unit-11=4") == 2
    assert "review-unit-11" in capsys.readouterr().err


def _thin(**over):
    """A finding written to disk with `description` dropped — the measured stale-file shape."""
    f = raw_finding(**over)
    f["description"] = ""
    return f


def test_a_certified_part_with_a_thin_file_is_reported_stale(tmp_path, capsys):
    """The measured fault, in the exact shape the 2026-08-07 container cell produced.

    The sweep agent made two StructuredOutput calls: the first with 7 findings and no
    `description`, rejected by the schema; the second with all 7 complete, accepted. It had
    already written its part file from the rejected draft and never rewrote it. Only the
    workflow's copy of the accepted return can tell that apart from an agent that simply had
    nothing to say, which is what `--expect-complete` carries.
    """
    run_dir = write_run(
        tmp_path, {"sweep-classes": producing_part("sweep-classes", [_thin(), _thin(line=200)])}
    )
    assert assemble(run_dir, "--expect-complete", "sweep-classes") == 0
    err = capsys.readouterr().err
    assert "STALE part file(s) sweep-classes" in err
    assert load_doc(run_dir)["run"]["stale_part_files"] == ["sweep-classes"]


def test_a_thin_file_that_was_never_certified_is_not_called_stale(tmp_path):
    """Without the certification the two faults are indistinguishable, so do not guess:
    the finding is still reported incomplete, but nothing claims the file is out of date."""
    run_dir = write_run(tmp_path, {"sweep-classes": producing_part("sweep-classes", [_thin()])})
    assert assemble(run_dir) == 0
    doc = load_doc(run_dir)
    assert doc["run"]["stale_part_files"] == []
    assert doc["run"]["incomplete_findings"]


def test_a_certified_part_whose_file_is_complete_is_not_stale(tmp_path):
    """The flag must be inert on a good part, or 'stale' stops meaning anything."""
    run_dir = write_run(
        tmp_path, {"sweep-classes": producing_part("sweep-classes", [raw_finding()])}
    )
    assert assemble(run_dir, "--expect-complete", "sweep-classes") == 0
    doc = load_doc(run_dir)
    assert doc["run"]["stale_part_files"] == []
    assert doc["run"]["incomplete_findings"] == []


def test_required_part_fields_match_between_the_js_and_this_module():
    """The JS uses its copy to decide which parts to certify as complete. If it drifts, a
    part could be certified on a weaker field set than the assembler checks, and every
    finding missing the extra field would be reported stale when it is merely thin."""
    if not WORKFLOW_JS.is_file():
        pytest.skip("workflow not present")
    m = re.search(r"^const REQUIRED_PART_FIELDS = \[([^\]]*)\]", WORKFLOW_JS.read_text(), re.M)
    assert m, "REQUIRED_PART_FIELDS not found in the workflow"
    js = tuple(re.findall(r"'([a-z_]+)'", m.group(1)))
    assert js == assemble_findings_mod.REQUIRED_FINDING_FIELDS
