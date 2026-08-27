#!/usr/bin/env python3
"""Tests for the deterministic findings assembler."""

from __future__ import annotations

import json
import re
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "scripts"))

import assemble_findings as assemble_findings_mod  # noqa: E402
import check_ledger  # noqa: E402
import findings_model  # noqa: E402
from assemble_findings import (  # noqa: E402
    CLASS_PREFIXES,
    REVIEWER_RATIONALE,
    UNJUDGED_RATIONALE,
    main,
)

WORKFLOW_JS = Path(__file__).resolve().parent.parent / "workflows" / "c-review.js"

# Not `skipif`. The cross-implementation drift tests below are the only thing holding the
# Python assembler and workflows/c-review.js to one rule, and a silent skip makes the suite
# pass having checked nothing. Set C_REVIEW_ALLOW_NO_NODE=1 to opt out deliberately.
if shutil.which("node") is None:  # pragma: no cover - environment guard
    import os

    if os.environ.get("C_REVIEW_ALLOW_NO_NODE") != "1":
        pytest.fail(
            "node is not installed, so the JS/Python drift tests would skip and this suite "
            "would pass having compared nothing. Install node, or set "
            "C_REVIEW_ALLOW_NO_NODE=1 to accept the gap deliberately.",
            pytrace=False,
        )


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
        if isinstance(units, dict) and "totals" not in units:
            # The gate fails closed on a missing `totals.checks_required`, so a fixture
            # without one never reaches the rule it was written for. Supplied here as the
            # enumerator would have written it; a fixture that is ABOUT the denominator
            # passes its own `totals` and keeps it.
            units = dict(
                units,
                totals={
                    "checks_required": sum(
                        len(u["required_questions"])
                        for u in (units.get("units") or [])
                        if isinstance(u, dict) and isinstance(u.get("required_questions"), list)
                    )
                },
            )
        (run_dir / "units.json").write_text(json.dumps(units), encoding="utf-8")
    if ledger_gate is not None:
        (run_dir / "ledger-gate.json").write_text(json.dumps(ledger_gate), encoding="utf-8")
    return run_dir


# No units.json means no coverage gate ran, which is exit 1 — "the artifacts were written
# but nothing verified them against a parse" — not exit 0. Almost every fixture here is a
# hand assembly over part files alone, so almost every one lands on it; the few that supply
# a unit list assert the code their gate actually produces.
UNVERIFIED = 1


@pytest.fixture(autouse=True)
def _reparse_returns_the_fixture(monkeypatch):
    """Stand in for the tree-sitter parse the gate runs at assemble time.

    `check_ledger.attach_sites` always reparses — a `sites` key in `units.json` must not
    switch the answer key off per unit, in the one file every worker agent can write — and
    this interpreter has no tree-sitter. Patching `sites_by_id` rather than `attach_sites`
    keeps the enumerate-time binding in the path, so a fixture whose `site_counts` disagree
    with its own `sites` is refused here exactly as a tampered run is in production. The
    real round trip lives in `test_enumerate_units.py`, which runs under `uv run`.
    """
    import enumerate_units

    monkeypatch.setattr(
        enumerate_units,
        "sites_by_id",
        lambda doc: {
            str(u.get("id")): u.get("sites")
            for u in doc.get("units") or []
            if isinstance(u, dict) and isinstance(u.get("sites"), dict)
        },
    )


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
    """A run at the volume that destroyed the persist agent this replaces: 88 findings."""
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
    """A measured harness failure: 86 candidates in, 23 out, evidence stripped from 23 of 23.

    An LLM persist agent is faithful at 15 and 25 findings and destroys the document at 75
    and 86, which is why assembly is code. This is that volume.
    """
    run_dir, total = big_run(tmp_path)
    assert total == 88
    assert assemble(run_dir) == UNVERIFIED
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
    assert assemble(run_dir) == UNVERIFIED
    summary = json.loads(capsys.readouterr().out)
    assert summary["ok"] is False
    assert summary["stats"]["raw_findings"] == 88
    assert summary["unjudged"] == 88
    assert set(summary) == {
        "ok",
        "artifacts_written",
        "gate_error",
        "findings_json",
        "report_md",
        "report_sarif",
        "stats",
        "unjudged",
        "ignored_merges",
        "ignored_verdicts",
        "unrecognised_parts",
        "ignored_fields",
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
    assert assemble(run_dir) == UNVERIFIED
    first = (run_dir / "findings.json").read_bytes()
    assert assemble(run_dir) == UNVERIFIED
    assert (run_dir / "findings.json").read_bytes() == first


# ------------------------------------------------------------------ normalisation


def test_key_comes_from_the_filename_not_the_part_id_field(tmp_path):
    run_dir = write_run(
        tmp_path,
        {"review-unit-01": producing_part("TYPO-NOT-THE-STEM", [raw_finding()])},
    )
    assert assemble(run_dir) == UNVERIFIED
    doc = load_doc(run_dir)
    assert doc["findings"][0]["key"] == "review-unit-01#0"
    assert doc["findings"][0]["found_by"] == "review-unit-01"


def test_unknown_bug_class_falls_back_to_logic_flaw(tmp_path):
    run_dir = write_run(
        tmp_path,
        {"review-unit-01": producing_part("review-unit-01", [raw_finding(bug_class="wat")])},
    )
    assert assemble(run_dir) == UNVERIFIED
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
    assert assemble(run_dir) == UNVERIFIED
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
    assert assemble(run_dir) == UNVERIFIED
    assert {f["line"] for f in load_doc(run_dir)["findings"]} == {1}


# ------------------------------------------------------------------ merging


def test_tier1_merges_identical_file_line_and_class(tmp_path):
    run_dir = write_run(
        tmp_path,
        {
            "review-unit-01": producing_part("review-unit-01", [raw_finding(confidence="Low")]),
            "sweep-01": producing_part("sweep-01", [raw_finding(confidence="High")]),
        },
    )
    assert assemble(run_dir) == UNVERIFIED
    doc = load_doc(run_dir)
    keyed = by_key(doc)
    primary = keyed["sweep-01#0"]
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
    assert assemble(run_dir) == UNVERIFIED
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
    assert assemble(run_dir) == UNVERIFIED
    assert load_doc(run_dir)["stats"]["merged"] == 0


# ------------------------------------------------------------------ tier 1.5


def near_pair(tmp_path, first=None, second=None):
    """Two findings two lines apart in one function, filed under the SAME bug class.

    Same class on purpose. With `integer-overflow` as the default, `CROSS_CLASS_NEARBY_LINES`
    (0) refused every pair before any other rule was consulted, so the tests below for the
    function key, the file key and the file-level skip were all decided by that one cap and
    proved nothing about the rule each names — deleting the cross-class guard, dropping
    `function` from the grouping key and letting file-level findings group all left the suite
    green. Two lines apart and same class merges, so each of those tests now discriminates.
    The cross-class cases pass `bug_class` explicitly.
    """
    later = {"line": 144, "title": "width", "confidence": "Low"}
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
    agent would otherwise be spawned for. Cross-class merging is capped at
    `CROSS_CLASS_NEARBY_LINES` (0), so this pair merges and the one two lines apart below
    does not; see that test for the measurement behind the cap.
    """
    run_dir = near_pair(tmp_path, second={"line": 142, "bug_class": "integer-overflow"})
    assert assemble(run_dir) == UNVERIFIED
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
    run_dir = near_pair(tmp_path, second={"bug_class": "integer-overflow"})
    assert assemble(run_dir) == UNVERIFIED
    doc = load_doc(run_dir)
    assert doc["stats"]["merged"] == 0
    assert all(f.get("merged_into") is None for f in doc["findings"])


def test_tier1_5_keeps_the_pairwise_cross_class_cap_from_swallowing_a_same_class_merge(
    tmp_path,
):
    """Why the PAIRWISE cap exists on top of the component-level `_cross_class_too_far`.

    A(bof,142) B(bof,143) C(integer,144). Pairwise, A-B is same class and merges while B-C
    is cross-class one line apart and is refused, so the component is {A,B} and one merge
    lands. Delete the pairwise cap and all three join one component, which
    `_cross_class_too_far` then refuses whole — so the legitimate A-B merge is lost too and
    the run reports 0 merges. Both two-finding cases are decided by the component guard
    alone, which is why deleting the pairwise one left every other tier-1.5 test green.
    """
    run_dir = write_run(
        tmp_path,
        {
            "review-unit-01": producing_part(
                "review-unit-01",
                [
                    raw_finding(line=142, confidence="High"),
                    raw_finding(line=143, confidence="Low", title="second"),
                    raw_finding(line=144, bug_class="integer-overflow", title="width"),
                ],
            )
        },
    )
    assert assemble(run_dir) == UNVERIFIED
    doc = load_doc(run_dir)
    assert doc["stats"]["merged_auto"] == 1
    keyed = by_key(doc)
    assert keyed["review-unit-01#1"]["merged_into"] == keyed["review-unit-01#0"]["id"]
    assert keyed["review-unit-01#2"].get("merged_into") is None


def test_the_same_pair_in_one_class_two_lines_apart_does_merge(tmp_path):
    """The control for the test above, and for every "does not merge" test using `near_pair`.

    Without it, `CROSS_CLASS_NEARBY_LINES` could be raised to swallow the cross-class case
    and nothing would notice, and the function/file/file-level tests below would be
    indistinguishable from a rule that refuses every pair.
    """
    run_dir = near_pair(tmp_path)  # 142 vs 144, both buffer-overflow
    assert assemble(run_dir) == UNVERIFIED
    assert load_doc(run_dir)["stats"]["merged_auto"] == 1


def test_tier1_5_still_merges_the_same_class_within_the_full_window(tmp_path):
    """The cap is cross-class only. Same class inside NEARBY_LINES is the original case
    this tier exists for, and no measured same-class merge was wrong."""
    run_dir = near_pair(tmp_path, second={"line": 145, "bug_class": "buffer-overflow"})
    assert assemble(run_dir) == UNVERIFIED
    assert load_doc(run_dir)["stats"]["merged_auto"] == 1


def test_tier1_5_normalises_the_function_name_the_way_the_js_does(tmp_path):
    run_dir = near_pair(
        tmp_path, {"function": "Parse_Header"}, {"function": "parse header", "line": 142}
    )
    assert assemble(run_dir) == UNVERIFIED
    assert load_doc(run_dir)["stats"]["merged_auto"] == 1


def test_tier1_5_does_not_merge_four_lines_apart(tmp_path):
    run_dir = near_pair(tmp_path, second={"line": 146})
    assert assemble(run_dir) == UNVERIFIED
    assert load_doc(run_dir)["stats"]["merged"] == 0


def test_tier1_5_does_not_merge_across_functions(tmp_path):
    run_dir = near_pair(tmp_path, second={"function": "parse_body"})
    assert assemble(run_dir) == UNVERIFIED
    assert load_doc(run_dir)["stats"]["merged"] == 0


def test_tier1_5_does_not_merge_across_files(tmp_path):
    run_dir = near_pair(tmp_path, second={"file": "src/other.c"})
    assert assemble(run_dir) == UNVERIFIED
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
    assert assemble(run_dir) == UNVERIFIED
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
    assert assemble(run_dir) == UNVERIFIED
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
    assert assemble(run_dir) == UNVERIFIED
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
                    # Ten lines down, so tier 1.5's three-line window leaves it for the
                    # agent — but still inside one function, so it is a pair the agent was
                    # shown and its merge survives the bucket rule.
                    raw_finding(line=153, title="same construct, further down"),
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
    assert assemble(run_dir) == UNVERIFIED
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
    assert assemble(run_dir) == UNVERIFIED
    doc = load_doc(run_dir)
    keyed = by_key(doc)
    assert doc["stats"]["merged"] == 1
    assert keyed["review-unit-01#1"]["merged_into"] == keyed["review-unit-01#0"]["id"]


def test_a_cross_bucket_agent_merge_is_refused_and_counted(tmp_path, capsys):
    """The workflow rejects this merge in memory; this file is where the artifact is decided.

    The dedup agent writes `parts/dedup-agent.json` as well as returning its answer, and the
    assembler reads the file. Without the same bucket rule here, a merge the run log says was
    rejected still lands in findings.json — and a real use-after-free 890 lines away in
    another function disappears from REPORT.md and REPORT.sarif behind "Also reported as".
    """
    run_dir = write_run(
        tmp_path,
        {
            "review-unit-01": producing_part(
                "review-unit-01",
                [
                    raw_finding(line=10),
                    raw_finding(
                        line=900,
                        function="emit",
                        bug_class="use-after-free",
                        title="use after free on the error path",
                        data_flow="free(chunk) in emit; chunk dereferenced again on retry",
                    ),
                ],
            ),
            "dedup-agent": {
                "part_id": "dedup-agent",
                "merges": [{"primary": "review-unit-01#0", "duplicates": ["review-unit-01#1"]}],
            },
        },
    )
    assert assemble(run_dir, "--no-judge") == UNVERIFIED
    summary = json.loads(capsys.readouterr().out)
    assert summary["ignored_merges"] == 1
    doc = load_doc(run_dir)
    assert doc["stats"]["merged"] == 0
    assert doc["stats"]["primaries"] == 2
    report = (run_dir / "REPORT.md").read_text(encoding="utf-8")
    assert "use after free on the error path" in report


def test_an_agent_merge_of_one_data_flow_chain_is_still_applied(tmp_path):
    """The bucket rule is ported, not approximated — the flow-chain arm has to survive it.

    A cause site and its consequence site are the duplication that actually reaches the dedup
    agent, and they sit in different functions hundreds of lines apart. A constraint that only
    knew about functions and line distance would refuse every merge the agent exists to make.
    """
    chain_a = "strm->avail_in feeds inflate_fast which writes state->window through updatewindow"
    chain_b = "state->window is written by inflate_fast from strm->avail_in without updatewindow"
    run_dir = write_run(
        tmp_path,
        {
            "review-unit-01": producing_part(
                "review-unit-01", [raw_finding(line=142, data_flow=chain_a)]
            ),
            "review-unit-02": producing_part(
                "review-unit-02",
                [
                    raw_finding(
                        line=880,
                        function="updatewindow",
                        title="the same chain, at the sink",
                        data_flow=chain_b,
                    )
                ],
            ),
            "dedup-agent": {
                "part_id": "dedup-agent",
                "merges": [{"primary": "review-unit-01#0", "duplicates": ["review-unit-02#0"]}],
            },
        },
    )
    assert assemble(run_dir, "--no-judge") == UNVERIFIED
    doc = load_doc(run_dir)
    assert doc["stats"]["merged"] == 1
    assert by_key(doc)["review-unit-02#0"]["merged_into"] == by_key(doc)["review-unit-01#0"]["id"]


def test_a_cross_file_agent_merge_is_refused(tmp_path):
    """Different files are never one bucket, whatever the two write-ups have in common."""
    shared = "strm->avail_in feeds inflate_fast which writes state->window through updatewindow"
    run_dir = write_run(
        tmp_path,
        {
            "review-unit-01": producing_part(
                "review-unit-01", [raw_finding(file="src/a.c", data_flow=shared)]
            ),
            "review-unit-02": producing_part(
                "review-unit-02", [raw_finding(file="src/b.c", data_flow=shared)]
            ),
            "dedup-agent": {
                "part_id": "dedup-agent",
                "merges": [{"primary": "review-unit-01#0", "duplicates": ["review-unit-02#0"]}],
            },
        },
    )
    assert assemble(run_dir, "--no-judge") == UNVERIFIED
    assert load_doc(run_dir)["stats"]["merged"] == 0


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
    assert assemble(run_dir) == UNVERIFIED
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
    assert assemble(run_dir) == UNVERIFIED
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
    assert assemble(run_dir) == UNVERIFIED
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
    assert assemble(run_dir) == UNVERIFIED
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


def test_the_reviewer_severity_rationale_reaches_the_artifacts(tmp_path):
    """The schema asks every reviewer for it and the renderer has a branch to print it.

    Nothing else carried it: `apply_verdicts` set it only from a `verdict-*` part, and the
    shipped configuration always passes --no-judge and never dispatches a judge, so the one
    line justifying a HIGH was collected from every reviewer and dropped from every artifact.
    """
    rationale = "reachable from the network parser with no auth"
    run_dir = write_run(
        tmp_path,
        {
            "review-unit-01": producing_part(
                "review-unit-01",
                [raw_finding(severity="HIGH", severity_rationale=rationale)],
            )
        },
    )
    assert assemble(run_dir, "--no-judge") == UNVERIFIED
    assert load_doc(run_dir)["findings"][0]["severity_rationale"] == rationale
    assert rationale in (run_dir / "REPORT.md").read_text(encoding="utf-8")


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
    assert assemble(run_dir, "--no-judge") == UNVERIFIED
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
    assert assemble(run_dir, "--no-judge", "--severity-filter", "high") == UNVERIFIED
    doc = load_doc(run_dir)
    assert doc["stats"]["survivors"] == 2
    assert doc["stats"]["reported"] == 1
    report = (run_dir / "REPORT.md").read_text(encoding="utf-8")
    assert "high one" in report
    assert "low one" not in report.split("## Not reported")[0]
    sarif = json.loads((run_dir / "REPORT.sarif").read_text(encoding="utf-8"))
    assert [r["message"]["text"] for r in sarif["runs"][0]["results"]] == ["high one"]


@pytest.mark.parametrize("severity", [None, "", "Critical!!", 7])
def test_no_judge_defaults_an_unusable_reviewer_severity_to_medium_and_says_nobody_assigned_it(
    tmp_path, severity
):
    """A severity findings_model cannot score would be dropped by a `high` filter.

    MEDIUM is wrong but visible; silently unfiltered is not — and it is NOT validated.
    `severity_validated` means "someone assigned this deliberately", and under `--no-judge`
    that is the reviewer; here the reviewer supplied nothing and this function invented the
    MEDIUM. Stamping it validated withdrew the finding from the unvalidated-survivor
    exemption, so `--severity-filter high` dropped it from REPORT.md and from SARIF with no
    counter and no warning anywhere.
    """
    run_dir = write_run(
        tmp_path,
        {"review-unit-01": producing_part("review-unit-01", [raw_finding(severity=severity)])},
    )
    assert assemble(run_dir, "--no-judge", "--severity-filter", "high") == UNVERIFIED
    finding = load_doc(run_dir)["findings"][0]
    assert finding["severity"] == "MEDIUM"
    assert finding["severity_validated"] is False
    # And it survives the filter it would otherwise be silently deleted by.
    assert load_doc(run_dir)["stats"]["reported"] == 1


def test_no_judge_upper_cases_a_lowercase_reviewer_severity(tmp_path):
    run_dir = write_run(
        tmp_path,
        {"review-unit-01": producing_part("review-unit-01", [raw_finding(severity="high")])},
    )
    assert assemble(run_dir, "--no-judge") == UNVERIFIED
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
    assert assemble(run_dir, "--no-judge") == UNVERIFIED
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
                [
                    raw_finding(
                        severity="CRITICAL",
                        attack_vector="Remote",
                        exploitability="Easy",
                        severity_rationale="remote heap write",
                    )
                ],
            ),
            "verdict-01": {
                "part_id": "verdict-01",
                "verdicts": [verdict("review-unit-01#0", fp_verdict="FALSE_POSITIVE", severity="")],
            },
        },
    )
    assert assemble(run_dir, "--no-judge") == UNVERIFIED
    finding = load_doc(run_dir)["findings"][0]
    assert "severity" not in finding
    assert "attack_vector" not in finding
    assert "exploitability" not in finding
    # The rationale is a justification for a severity that is now gone; leaving it would
    # print "what makes it CRITICAL" beside a finding the judge just rejected.
    assert "severity_rationale" not in finding


def test_no_judge_report_says_the_severity_is_reviewer_assigned(tmp_path):
    run_dir = write_run(
        tmp_path,
        {"review-unit-01": producing_part("review-unit-01", [raw_finding(severity="HIGH")])},
    )
    assert assemble(run_dir, "--no-judge") == UNVERIFIED
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
    assert assemble(run_dir) == UNVERIFIED
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
    assert assemble(run_dir) == UNVERIFIED
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
    assert assemble(run_dir) == UNVERIFIED
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
    assert assemble(run_dir) == UNVERIFIED
    finding = load_doc(run_dir)["findings"][0]
    assert finding["severity"] == "MEDIUM"
    assert finding["severity_validated"] is False


def test_a_merged_duplicate_is_never_judged_or_left_unjudged(tmp_path, capsys):
    run_dir = write_run(
        tmp_path,
        {
            "review-unit-01": producing_part("review-unit-01", [raw_finding(confidence="High")]),
            "sweep-01": producing_part("sweep-01", [raw_finding(confidence="Low")]),
            "verdict-01": {
                "part_id": "verdict-01",
                "verdicts": [verdict("review-unit-01#0"), verdict("sweep-01#0")],
            },
        },
    )
    assert assemble(run_dir) == UNVERIFIED
    summary = json.loads(capsys.readouterr().out)
    assert summary["unjudged"] == 0
    assert summary["ignored_verdicts"] == 1
    duplicate = by_key(load_doc(run_dir))["sweep-01#0"]
    # It is not judged and is not counted as unjudged — but it does not get to inherit
    # "nobody assigned this, so it must be fine" either. `primaries()` resurrects a
    # duplicate whose primary a judge rejects, and with no verdict at all the reviewer's
    # own severity was then reported as judge-validated with `unjudged: 0`.
    assert duplicate["fp_verdict"] == "LIKELY_TP"
    assert duplicate["severity_validated"] is False


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
    assert assemble(run_dir, "--severity-filter", "high") == UNVERIFIED
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
    assert assemble(run_dir) == UNVERIFIED
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
    assert assemble(first) == UNVERIFIED
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
    assert assemble(second) == UNVERIFIED
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
                ledger=[LEDGER_ROW],
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
        # `checks_required` here is the enumerate-time denominator and the gate now
        # compares it against what the same file owes; 180 over a one-unit list is a
        # partition edited after it was generated, which is a different test.
        units={"totals": {"units": 41, "checks_required": 1}, "units": [LEDGER_UNIT]},
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
            "--benchmark-mode",
            "--expect",
            "review-unit-01=1",
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
    assert run["units"] == {"units": 41, "checks_required": 1}
    assert run["judge_ran"] is True
    assert run["ledger"]["checks_required"] == 1
    assert run["hunter_notes"] == ["review-unit-01: could not read generated headers"]
    assert run["hunter_external_sources"] == [
        {
            "group": "review-unit-01",
            "consulted": True,
            "detail": "read zlib upstream",
            "declared": True,
        }
    ]


def test_absent_optional_inputs_leave_null_not_a_crash(tmp_path):
    run_dir = write_run(
        tmp_path, {"review-unit-01": producing_part("review-unit-01", [raw_finding()])}
    )
    assert assemble(run_dir) == UNVERIFIED
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
    # `sites` is the FIXTURE's stand-in for the reparse (see `_reparse_returns_the_fixture`);
    # a production units.json never carries it. `site_counts` is what the enumerator really
    # persists, and the gate binds the reparse to it.
    "sites": {"write": [142, 150]},
    # What the enumerator really persists, and what `_bind_to_enumeration` compares the
    # reparse against.
    "site_counts": {"bounds": 2},
    "required_questions": ["bounds"],
}


def ledger_unit(unit_id, **overrides):
    """A copy of LEDGER_UNIT under another id."""
    return dict(LEDGER_UNIT, id=unit_id, **overrides)


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
    assert assemble(run_dir, "--expect", "review-unit-01=1") == 0
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


def test_rows_over_invented_unit_ids_fail_the_run_and_are_named_in_both_artifacts(tmp_path, capsys):
    """`gate_failure` read only `missing_row_count` and `violation_count`.

    A reviewer whose ledger names unit ids the parse never produced satisfies every check it
    DOES claim, so the run exited 0 with `ok: true` and `coverage_pct: 100.0` — while
    `generate_sarif.lost_work`, built from the same gate report, already counted
    `unknown_units` and wrote `executionSuccessful: false`. Two halves of one run disagreeing
    about whether it passed.
    """
    ghosts = [dict(LEDGER_ROW, unit_id=f"src/ghost{n}.c:1-40", verdict="clean") for n in range(40)]
    run_dir = write_run(
        tmp_path,
        {
            "review-unit-01": producing_part(
                "review-unit-01", [raw_finding()], ledger=[LEDGER_ROW, *ghosts]
            )
        },
        units={"units": [LEDGER_UNIT], "totals": {"units": 1, "checks_required": 1}},
    )
    assert assemble(run_dir, "--expect", "review-unit-01=1") == UNVERIFIED
    capsys.readouterr()
    ledger = load_doc(run_dir)["run"]["ledger"]
    # The real row is still satisfied: this is not the gate rejecting everything.
    assert ledger["checks_satisfied"] == ledger["checks_required"] == 1
    assert ledger["violation_count"] == 0 and ledger["missing_row_count"] == 0
    assert ledger["unknown_unit_count"] == 40
    report = (run_dir / "REPORT.md").read_text(encoding="utf-8")
    assert "40 ledger row(s) name a unit id that is in no unit list" in report
    sarif = json.loads((run_dir / "REPORT.sarif").read_text(encoding="utf-8"))
    assert sarif["runs"][0]["invocations"][0]["executionSuccessful"] is False


def test_the_gate_reports_an_incomplete_ledger_and_ships_the_findings_anyway(tmp_path, capsys):
    """A gap fails the run and the findings still ship, flagged in both artifacts.

    Both halves matter. A gate that runs and rejects every row must not exit 0 with
    `ok: true`, which is what the assemble agent reports success on; a gate that could not
    run at all must not throw away a completed review's artifacts.
    """
    run_dir = write_run(
        tmp_path,
        {"review-unit-01": producing_part("review-unit-01", [raw_finding()], ledger=[])},
        units={"units": [LEDGER_UNIT, ledger_unit("src/parse.c:emit")]},
    )
    # One row present for two owed, so the gate has something to check and reports the gap.
    part = run_dir / "parts" / "review-unit-01.json"
    doc = json.loads(part.read_text(encoding="utf-8"))
    doc["ledger"] = [LEDGER_ROW]
    part.write_text(json.dumps(doc), encoding="utf-8")

    assert assemble(run_dir) == 1
    assert json.loads(capsys.readouterr().out)["ok"] is False
    ledger = load_doc(run_dir)["run"]["ledger"]
    assert ledger["checks_required"] == 2
    assert ledger["checks_completed"] == 1
    assert ledger["missing_row_count"] == 1
    assert (run_dir / "findings.json").exists()
    assert "unanswered row(s)" in (run_dir / "REPORT.md").read_text(encoding="utf-8")


def test_a_gate_that_cannot_check_a_partitioned_run_fails_but_keeps_the_artifacts(tmp_path, capsys):
    """units.json exists, so every reviewer was handed a ledger. Zero rows is not a pass.

    Exit 1, not 2: the review is assembled but unverified. Raising instead throws away a
    completed run's findings.json, REPORT.md and REPORT.sarif over the state of the gate's
    own input, after every review agent has already been paid for.
    """
    run_dir = write_run(
        tmp_path,
        {"review-unit-01": producing_part("review-unit-01", [raw_finding()])},
        units={"units": [LEDGER_UNIT]},
    )
    assert assemble(run_dir) == 1
    out = json.loads(capsys.readouterr().out)
    assert out["ok"] is False and out["artifacts_written"] is True
    assert "zero ledger rows" in out["gate_error"]
    assert (run_dir / "findings.json").exists()
    assert "unmeasured" in (run_dir / "REPORT.md").read_text(encoding="utf-8")
    sarif = json.loads((run_dir / "REPORT.sarif").read_text(encoding="utf-8"))
    notes = sarif["runs"][0]["invocations"][0]["toolExecutionNotifications"]
    assert any("unmeasured" in n["message"]["text"] for n in notes)


@pytest.mark.parametrize(
    ("units", "expected"),
    [
        ({"units": []}, "lists no units"),
        # Trimming the questions a unit owes shrinks the denominator, and `site_counts` is
        # trimmed with it so per-count equality cannot see it. The BINDING can: the source
        # still counts sites for the question the unit no longer admits owing.
        (
            {"units": [dict(LEDGER_UNIT, required_questions=[], site_counts={})]},
            "the source now counts sites for",
        ),
        # A unit the reparse does not reproduce, from either direction: dropping one shrinks
        # the denominator to nothing while the same call has just computed it.
        (
            {"units": [{k: v for k, v in LEDGER_UNIT.items() if k != "sites"}]},
            "The tree moved",
        ),
        # Present but EMPTY is the one tamper that scores: `checks_required` comes from
        # `required_questions`, so it stays at its real value while every row passes on
        # evidence text alone.
        ({"units": [dict(LEDGER_UNIT, sites={})]}, "the source now counts sites for"),
        ({"units": [dict(LEDGER_UNIT, required_questions=7)]}, "the source now counts sites for"),
        ({"units": [{k: v for k, v in LEDGER_UNIT.items() if k != "id"}]}, "The tree moved"),
        # A `sites` value that is not a list of ints raises an uncaught TypeError out of
        # `required_rows`, past `except LedgerError` and past `except AssembleError`.
        ({"units": [dict(LEDGER_UNIT, sites={"write": 5})]}, "the source now counts sites for"),
        (
            {"units": [dict(LEDGER_UNIT, sites={"write": ["5", "6"]})]},
            "the source now counts sites for",
        ),
        # A JSON array root skips the gate in silence and exits 0 unless it is refused,
        # while `{}` and `{"units": []}` are fatal — the same corruption, opposite outcomes.
        ([1, 2, 3], "not an object"),
    ],
)
def test_an_uncheckable_unit_list_fails_the_run_and_is_not_a_100_percent_score(
    tmp_path, capsys, units, expected
):
    """Unrefused, each of these scores 100% coverage, exits 0 silently, or raises a
    TypeError."""
    run_dir = write_run(
        tmp_path,
        {"review-unit-01": producing_part("review-unit-01", [raw_finding()], ledger=[LEDGER_ROW])},
        units=units,
    )
    assert assemble(run_dir) == 1
    summary = json.loads(capsys.readouterr().out)
    assert summary["ok"] is False
    assert expected in summary["gate_error"]
    # The review is unverified, not lost.
    assert (run_dir / "findings.json").exists()
    assert "unmeasured" in (run_dir / "REPORT.md").read_text(encoding="utf-8")


def test_no_unit_list_means_no_gate_and_therefore_no_pass(tmp_path, capsys):
    """Running without a parse is unverified, and exit 0 said the opposite.

    Exit 0 is "the artifacts were written AND the coverage gate accepted the ledger", so the
    hand-assembly path — no units.json at all — must not print `"ok": true` and return it: a
    human reading this script's own summary would see unqualified success over a run nothing
    had checked. `ledger-gate.json` says the same thing rather than being left absent, or
    left holding the previous run's clean sheet.
    """
    run_dir = write_run(
        tmp_path,
        {"review-unit-01": producing_part("review-unit-01", [raw_finding()], ledger=[LEDGER_ROW])},
    )
    assert assemble(run_dir) == UNVERIFIED
    summary = json.loads(capsys.readouterr().out)
    assert summary["ok"] is False
    assert "no units.json" in summary["gate_error"]
    assert load_doc(run_dir)["run"]["ledger"] is None
    assert "no units.json" in json.loads((run_dir / "ledger-gate.json").read_text())["error"]


def test_a_gate_file_left_by_an_earlier_run_is_never_read_back(tmp_path):
    """Nothing compares its unit ids, part list or timestamp against THIS run.

    Reading it back reports a previous run's coverage as this one's: delete units.json,
    re-run into the same directory, and `checks_satisfied: 5` comes out of run 1 with no
    "unmeasured" warning anywhere. Only `parts/` and `assignments/` are ever cleared.
    """
    run_dir = write_run(
        tmp_path,
        {"review-unit-01": producing_part("review-unit-01", [raw_finding()])},
        ledger_gate={"checks_required": 180, "checks_completed": 179, "checks_satisfied": 179},
    )
    assert assemble(run_dir) == UNVERIFIED
    assert load_doc(run_dir)["run"]["ledger"] is None
    assert "unmeasured" in (run_dir / "REPORT.md").read_text(encoding="utf-8")


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
    assert assemble(run_dir) == UNVERIFIED
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
    wrote one. That assembles to `producing_parts: 0`, zero findings, zero coverage, exit 0
    and a clean REPORT.md reading as "no findings" — indistinguishable from a clean
    codebase, and collected by the bench as zero recall for the tool rather than a failed
    run.
    """
    run_dir = write_run(tmp_path, {"detect-01": '{"purpose": "x", "is_cpp": false}'})
    assert assemble(run_dir) == 2
    err = capsys.readouterr().err
    assert "none of them is a dispatched producing part" in err
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
    assert assemble(run_dir) == UNVERIFIED
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
    assert "is not valid UTF-8 JSON" in capsys.readouterr().err
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
    assert (
        assemble(run_dir, "--expect", "review-unit-01", "--expect", "invariant-01.json")
        == UNVERIFIED
    )


def test_a_corrupt_optional_input_exits_2(tmp_path, capsys):
    """Absent is allowed; unparseable is not — "no ledger" must not mean "ledger broke"."""
    run_dir = write_run(
        tmp_path, {"review-unit-01": producing_part("review-unit-01", [raw_finding()])}
    )
    (run_dir / "detect.json").write_text("{oops", encoding="utf-8")
    assert assemble(run_dir) == 2
    assert "detect output" in capsys.readouterr().err
    assert not (run_dir / "findings.json").exists()


def test_an_unrecognised_part_is_counted_and_warned_about(tmp_path, capsys):
    run_dir = write_run(
        tmp_path,
        {
            "review-unit-01": producing_part("review-unit-01", [raw_finding()]),
            "reviewunit02": producing_part("reviewunit02", [raw_finding(line=999)]),
        },
    )
    assert assemble(run_dir) == UNVERIFIED
    captured = capsys.readouterr()
    assert "no rule reads part file(s) reviewunit02" in captured.err
    assert json.loads(captured.out)["unrecognised_parts"] == 1
    assert load_doc(run_dir)["stats"]["raw_findings"] == 1


def test_a_part_from_the_removed_second_pass_is_unrecognised_not_read(tmp_path, capsys):
    """`second-` outlived the second review pass in `PRODUCING_PREFIXES`, so a leftover
    `second-*.json` in a reused run directory was read as this run's output. It is a stale
    file, and a stale file that nothing dispatched has to be REPORTED — `unrecognised_parts`
    is what SKILL.md surfaces — rather than quietly folded into the findings."""
    run_dir = write_run(
        tmp_path,
        {
            "review-unit-01": producing_part("review-unit-01", [raw_finding()]),
            "second-01": producing_part("second-01", [raw_finding(line=999)]),
        },
    )
    assert assemble(run_dir) == UNVERIFIED
    captured = capsys.readouterr()
    assert "no rule reads part file(s) second-01" in captured.err
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
    assert assemble(run_dir) == UNVERIFIED
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
        pytest.fail("workflows/c-review.js is missing, so this drift test checks nothing")
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
        == UNVERIFIED
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
        == UNVERIFIED
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
        == UNVERIFIED
    )
    doc = json.loads((run / "findings.json").read_text())
    assert len([f for f in doc["findings"] if f.get("from_pointer")]) == 1


def test_an_agent_merge_across_one_bucket_is_applied(tmp_path, capsys):
    """A collision bucket is transitive, and refusing that here cost real merges.

    Three findings eight lines apart, in three functions: the workflow unions 10-18 and
    18-26 into one bucket and accepts the agent's merge of 26 into 10. A pairwise port of
    the rule refuses it, so the run log says one merge while findings.json reports two
    primaries and the duplicate the agent identified comes back as its own finding in
    REPORT.md.
    """
    run_dir = write_run(
        tmp_path,
        {
            "review-unit-01": producing_part(
                "review-unit-01",
                [
                    raw_finding(file="src/a.c", line=10, function="alpha", data_flow=""),
                    raw_finding(file="src/a.c", line=18, function="beta", data_flow="", title="b"),
                    raw_finding(file="src/a.c", line=26, function="gamma", data_flow="", title="c"),
                ],
            ),
            "dedup-agent": {
                "part_id": "dedup-agent",
                "merges": [{"primary": "review-unit-01#0", "duplicates": ["review-unit-01#2"]}],
            },
        },
    )
    assert assemble(run_dir, "--no-judge") == UNVERIFIED
    assert json.loads(capsys.readouterr().out)["ignored_merges"] == 0
    doc = load_doc(run_dir)
    assert doc["stats"]["merged"] == 1
    assert doc["stats"]["primaries"] == 2
    assert by_key(doc)["review-unit-01#2"]["merged_into"] == by_key(doc)["review-unit-01#0"]["id"]


def _js_block(src: str, header: str) -> str:
    """One top-level `const`/`function` declaration, header through its closing brace."""
    start = src.find(header)
    if start < 0:
        pytest.fail(f"{header!r} is not in the workflow — the collision rule moved or was renamed")
    end = src.find("\n}\n", start)
    if end < 0:
        pytest.fail(f"{header!r} has no top-level closing brace")
    return src[start : end + 2]


def _js_collision_buckets(findings: list[dict]) -> list[list[str]]:
    """The workflow's own `collisionBuckets` over these findings, run through node."""
    src = WORKFLOW_JS.read_text(encoding="utf-8")
    consts = []
    for name in ("COLLISION_LINES", "NO_FUNCTION"):
        line = re.search(rf"^const {name} = .*$", src, re.M)
        if line is None:
            pytest.fail(f"const {name} is not in the workflow")
        consts.append(line.group(0))
    script = (
        "\n".join(
            consts
            + [
                _js_block(src, "const FLOW_STOPWORDS = new Set(["),
                _js_block(src, "function flowTokens(text) {"),
                _js_block(src, "function flowsIntersect(a, b) {"),
                _js_block(src, "function normFunction(name) {"),
                _js_block(src, "function collisionBuckets(findings, mergedInto) {"),
            ]
        )
        + f"\nconst buckets = collisionBuckets({json.dumps(findings)}, new Map());"
        + "console.log(JSON.stringify(buckets.map((b) => b.map((f) => f.key).sort()).sort()));"
    )
    out = subprocess.run(["node", "-e", script], capture_output=True, text=True, check=True).stdout
    return json.loads(out)


def _js_auto_merge(findings: list[dict]) -> dict[str, str]:
    """The workflow's own `autoMergeNearby` over these findings, run through node."""
    src = WORKFLOW_JS.read_text(encoding="utf-8")
    consts = []
    for name in ("NEARBY_LINES", "CROSS_CLASS_NEARBY_LINES", "NO_FUNCTION", "CONFIDENCE_RANK"):
        line = re.search(rf"^const {name} = .*$", src, re.M)
        if line is None:
            pytest.fail(f"const {name} is not in the workflow")
        consts.append(line.group(0))
    script = (
        "\n".join(
            consts
            + [
                _js_block(src, "function normFunction(name) {"),
                _js_block(src, "function precisionRank(f) {"),
                _js_block(src, "function pickPrimary(a, b) {"),
                _js_block(src, "function crossClassTooFar(component) {"),
                _js_block(src, "function autoMergeNearby(findings, mergedInto) {"),
            ]
        )
        + "\nconst m = new Map();"
        + f"autoMergeNearby({json.dumps(findings)}, m);"
        + "console.log(JSON.stringify(Object.fromEntries([...m].sort())));"
    )
    out = subprocess.run(["node", "-e", script], capture_output=True, text=True, check=True).stdout
    return json.loads(out)


@pytest.mark.parametrize(
    "findings",
    [
        # The case that lets M13 through on the JS side: A and C are same-class and two lines
        # apart, B is cross-class and joins them through A. Both sides must refuse the whole
        # component; merging two of the three on one side drops all three from
        # `collisionBuckets` as already handled, the dedup agent never sees them, and the
        # assembler merges none — three findings in REPORT.md against `auto_merged: 2`.
        [
            {"key": "a", "line": 100, "bug_class": "buffer-overflow"},
            {"key": "b", "line": 100, "bug_class": "integer-overflow"},
            {"key": "c", "line": 102, "bug_class": "buffer-overflow"},
        ],
        # Same class, three lines apart: merged by both.
        [
            {"key": "a", "line": 100, "bug_class": "buffer-overflow"},
            {"key": "b", "line": 103, "bug_class": "buffer-overflow"},
        ],
        # Cross-class on the SAME line: merged by both.
        [
            {"key": "a", "line": 100, "bug_class": "buffer-overflow"},
            {"key": "b", "line": 100, "bug_class": "integer-overflow"},
        ],
        # Cross-class one line apart: left for the dedup agent by both.
        [
            {"key": "a", "line": 100, "bug_class": "buffer-overflow"},
            {"key": "b", "line": 101, "bug_class": "integer-overflow"},
        ],
        # Four lines apart, same class: too far for both.
        [
            {"key": "a", "line": 100, "bug_class": "buffer-overflow"},
            {"key": "b", "line": 104, "bug_class": "buffer-overflow"},
        ],
    ],
)
def test_auto_merge_agrees_with_tier1_5_over_fixtures_not_only_over_constants(findings):
    """Equal constants do not stop the two sides from disagreeing.

    Pinning `NEARBY_LINES` and `CROSS_CLASS_NEARBY_LINES` compares no rule, so a predicate
    like `_cross_class_too_far` can land on one side alone. A pair the JS merges and the
    assembler does not is dropped from the dedup agent's prompt as already handled and then
    merged by nobody.
    """
    full = [
        dict(f, file="src/a.c", function="parse", confidence="Medium", data_flow="")
        for f in findings
    ]
    keyed = {f["key"]: f for f in full}
    py: dict[str, str] = {}
    assemble_findings_mod.tier1_5(keyed, py)
    assert _js_auto_merge(full) == py


def _py_collision_buckets(findings: list[dict]) -> list[list[str]]:
    roots: dict[str, list[str]] = {}
    keyed = {f["key"]: f for f in findings}
    for key, root in assemble_findings_mod.collision_buckets(keyed, {}).items():
        roots.setdefault(root, []).append(key)
    return sorted(sorted(group) for group in roots.values())


@pytest.mark.parametrize(
    "findings,expected",
    [
        # Transitive: 10-18 and 18-26 collide, 10-26 does not. One bucket all the same, and
        # a pairwise port of the rule returns nothing for the (10, 26) merge the agent makes.
        (
            [
                {"key": "a", "file": "src/a.c", "line": 10, "function": "alpha", "data_flow": ""},
                {"key": "b", "file": "src/a.c", "line": 18, "function": "beta", "data_flow": ""},
                {"key": "c", "file": "src/a.c", "line": 26, "function": "gamma", "data_flow": ""},
            ],
            [["a", "b", "c"]],
        ),
        # Different files are never one bucket, however alike the two write-ups are.
        (
            [
                {"key": "a", "file": "src/a.c", "line": 10, "function": "alpha", "data_flow": ""},
                {"key": "b", "file": "src/b.c", "line": 11, "function": "alpha", "data_flow": ""},
            ],
            [],
        ),
        # The flow-chain arm: cause site and consequence site, different functions, 700 lines
        # apart. This is the merge the dedup agent exists to make.
        (
            [
                {
                    "key": "a",
                    "file": "src/a.c",
                    "line": 142,
                    "function": "inflate",
                    "data_flow": "strm->avail_in feeds inflate_fast which writes state->window "
                    "through updatewindow",
                },
                {
                    "key": "b",
                    "file": "src/a.c",
                    "line": 880,
                    "function": "updatewindow",
                    "data_flow": "state->window is written by inflate_fast from strm->avail_in "
                    "without updatewindow",
                },
            ],
            [["a", "b"]],
        ),
    ],
)
def test_the_collision_buckets_match_between_the_js_and_this_module(findings, expected):
    """The rule itself, not just its constants, run on both sides over the same findings.

    The two drift tests below pin `COLLISION_LINES` and `FLOW_STOPWORDS`, and constants
    agreeing is not the same as semantics agreeing: a Python port testing one pair directly
    while the JS compares membership of a transitively-unioned bucket passes every one of
    them. Fixtures rather than a spot check, so a rule that buckets nothing — the shape an
    extraction failure takes — cannot pass.
    """
    assert _js_collision_buckets(findings) == expected
    assert _py_collision_buckets(findings) == expected


def _js_const(name: str) -> int | None:
    """Read `const <name> = <int>` out of the workflow, or None if absent."""
    if not WORKFLOW_JS.is_file():
        pytest.fail("workflows/c-review.js is missing, so this drift test checks nothing")
    m = re.search(rf"^const {name} = (\d+)\s*$", WORKFLOW_JS.read_text(encoding="utf-8"), re.M)
    return int(m.group(1)) if m else None


@pytest.mark.parametrize("name", ["NEARBY_LINES", "CROSS_CLASS_NEARBY_LINES", "COLLISION_LINES"])
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
        pytest.fail(f"{name} is not in the workflow, so nothing keeps the two windows equal")
    assert js == getattr(assemble_findings_mod, name), (
        f"{name} is {js} in c-review.js and "
        f"{getattr(assemble_findings_mod, name)} in assemble_findings.py"
    )


def test_the_flow_stopwords_match_between_the_js_and_this_module():
    """The other half of the collision rule, and the half that is a 60-word list.

    A word in one list and not the other changes which pairs count as one data-flow chain,
    so the workflow shows the agent a pair the assembler will then refuse to merge — or the
    reverse. The list is only meaningful as a copy.
    """
    text = WORKFLOW_JS.read_text(encoding="utf-8")
    body = re.search(r"const FLOW_STOPWORDS = new Set\(\[(.*?)\]\)", text, re.S)
    if body is None:
        pytest.fail("FLOW_STOPWORDS is not in the workflow, so nothing keeps the two lists equal")
    js = set(re.findall(r"'([^']+)'", body.group(1)))
    if len(js) < 40:
        pytest.fail(f"stopword extraction matched {len(js)} words — the regex is broken")
    assert js == set(assemble_findings_mod.FLOW_STOPWORDS)


# ------------------------------------------------- hand assembly loses the bookkeeping


def test_no_expect_warns_and_records_that_coverage_was_never_checked(tmp_path, capsys):
    """A checker handed zero items must not report success.

    The workflow always passes one `--expect` per dispatched agent, so an empty list means
    a hand assembly — the documented recovery path when the assemble agent dies. A review
    agent that never wrote its part file is logged by the workflow and invisible here: the
    hand-assembled document carries `agent_failures: []` with a full `parts_read`, which
    reads as a complete 13-slice run rather than the 12-slice run it is. Nothing can recover
    the expectation after the fact, so the document has to say it was never checked instead
    of letting an empty failure list mean "no failures".
    """
    run_dir = write_run(
        tmp_path, {"review-unit-01": producing_part("review-unit-01", [raw_finding()])}
    )
    assert assemble(run_dir) == UNVERIFIED
    assert "no --expect given" in capsys.readouterr().err
    assert load_doc(run_dir)["run"]["expectations_checked"] is False


def test_expect_marks_the_document_as_checked(tmp_path):
    run_dir = write_run(
        tmp_path, {"review-unit-01": producing_part("review-unit-01", [raw_finding()])}
    )
    assert assemble(run_dir, "--expect", "review-unit-01=1") == UNVERIFIED
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
    """The measured fault, in the exact shape a real container cell produces.

    A sweep agent makes two StructuredOutput calls: the first with 7 findings and no
    `description`, rejected by the schema; the second with all 7 complete, accepted. It has
    already written its part file from the rejected draft and never rewrites it. Only the
    workflow's copy of the accepted return can tell that apart from an agent that simply had
    nothing to say, which is what `--expect-complete` carries.
    """
    run_dir = write_run(
        tmp_path, {"sweep-classes": producing_part("sweep-classes", [_thin(), _thin(line=200)])}
    )
    assert assemble(run_dir, "--expect-complete", "sweep-classes") == UNVERIFIED
    err = capsys.readouterr().err
    assert "STALE part file(s) sweep-classes" in err
    assert load_doc(run_dir)["run"]["stale_part_files"] == ["sweep-classes"]


def test_a_thin_file_that_was_never_certified_is_not_called_stale(tmp_path):
    """Without the certification the two faults are indistinguishable, so do not guess:
    the finding is still reported incomplete, but nothing claims the file is out of date."""
    run_dir = write_run(tmp_path, {"sweep-classes": producing_part("sweep-classes", [_thin()])})
    assert assemble(run_dir) == UNVERIFIED
    doc = load_doc(run_dir)
    assert doc["run"]["stale_part_files"] == []
    assert doc["run"]["incomplete_findings"]


def test_a_certified_part_whose_file_is_complete_is_not_stale(tmp_path):
    """The flag must be inert on a good part, or 'stale' stops meaning anything."""
    run_dir = write_run(
        tmp_path, {"sweep-classes": producing_part("sweep-classes", [raw_finding()])}
    )
    assert assemble(run_dir, "--expect-complete", "sweep-classes") == UNVERIFIED
    doc = load_doc(run_dir)
    assert doc["run"]["stale_part_files"] == []
    assert doc["run"]["incomplete_findings"] == []


def test_required_part_fields_match_between_the_js_and_this_module():
    """The JS uses its copy to decide which parts to certify as complete. If it drifts, a
    part could be certified on a weaker field set than the assembler checks, and every
    finding missing the extra field would be reported stale when it is merely thin."""
    if not WORKFLOW_JS.is_file():
        pytest.fail("workflows/c-review.js is missing, so this drift test checks nothing")
    m = re.search(r"^const REQUIRED_PART_FIELDS = \[([^\]]*)\]", WORKFLOW_JS.read_text(), re.M)
    assert m, "REQUIRED_PART_FIELDS not found in the workflow"
    js = tuple(re.findall(r"'([a-z_]+)'", m.group(1)))
    assert js == assemble_findings_mod.REQUIRED_FINDING_FIELDS


def test_declared_separates_an_honest_no_from_never_being_asked(tmp_path):
    """`consulted: false` is ambiguous on its own.

    The external-source declaration is benchmark-only instrumentation (`benchmarkMode`), so
    with it off every part reports `consulted: false` whether or not the reviewer looked
    anything up. A scored run has to tell "declared nothing" from "was never asked", or the
    anti-cheat silently passes a cell that never posed the question.

    `declared` is therefore gated on benchmark mode — the property stays in the review
    schema outside it, so a model that fills it in unprompted would otherwise mark an
    unasked cell as cleared — but inside benchmark mode it is the part's own ANSWER. A
    constant would make `declarations_seen` equal the number of producing parts whether or
    not a single one answered, which is the blindness the counter exists to expose.
    """
    volunteered = producing_part("review-unit-01", [raw_finding()])
    volunteered["external_sources_consulted"] = False
    silent = producing_part("review-unit-02", [raw_finding(file="src/b.c")])
    silent.pop("external_sources_consulted", None)
    parts = {"review-unit-01": volunteered, "review-unit-02": silent}

    run_dir = write_run(tmp_path, parts)
    assert assemble(run_dir) == UNVERIFIED
    by_group = {e["group"]: e for e in load_doc(run_dir)["run"]["hunter_external_sources"]}
    assert [e["consulted"] for e in by_group.values()] == [False, False]
    # Nobody was asked, so no part may claim it answered — including the one that spoke.
    assert [e["declared"] for e in by_group.values()] == [False, False]

    asked_dir = write_run(tmp_path / "benchmark", parts)
    assert assemble(asked_dir, "--benchmark-mode") == UNVERIFIED
    by_group = {e["group"]: e for e in load_doc(asked_dir)["run"]["hunter_external_sources"]}
    # Asked is not answered: the silent part contributed no record to inspect.
    assert [e["declared"] for e in by_group.values()] == [True, False]


def test_the_declaration_from_the_structured_return_is_not_thrown_away(tmp_path):
    """Benchmark mode REQUIRES the declaration in the schema, so the return is the answer.

    Reading it only from the part file loses it whenever the file is an earlier draft than
    the accepted return — the same staleness `--expect-complete` exists for. A reviewer that
    honestly declared it fetched upstream then scores VALID and its oracle-contaminated
    recall enters the comparison.
    """
    silent = producing_part("review-unit-01", [raw_finding()])
    silent.pop("external_sources_consulted", None)
    stale = producing_part("review-unit-02", [raw_finding(file="src/b.c")])
    stale["external_sources_consulted"] = False
    run_dir = write_run(tmp_path, {"review-unit-01": silent, "review-unit-02": stale})

    assert (
        assemble(
            run_dir,
            "--benchmark-mode",
            "--external-source",
            "review-unit-01=1",
            "--external-source",
            "review-unit-02=1",
        )
        == UNVERIFIED
    )
    by_group = {e["group"]: e for e in load_doc(run_dir)["run"]["hunter_external_sources"]}
    # A `true` from either channel wins, and answering through the return is answering.
    assert [(e["declared"], e["consulted"]) for e in by_group.values()] == [(True, True)] * 2


def test_a_malformed_external_source_argument_is_fatal(tmp_path):
    """Silently ignoring it would report `consulted: false` for an arm that declared true."""
    run_dir = write_run(tmp_path, {"review-unit-01": producing_part("review-unit-01", [])})
    assert assemble(run_dir, "--benchmark-mode", "--external-source", "review-unit-01") == 2
    assert assemble(run_dir, "--benchmark-mode", "--external-source", "review-unit-01=yes") == 2


def test_the_workflow_passes_benchmark_mode_through_to_assembly():
    """`--benchmark-mode` is only load-bearing if the workflow actually sends it.

    Without this the flag defaults to off on every real run, `declared` is false everywhere,
    and a scored benchmark cell reads as one where the question was never posed.
    """
    if not WORKFLOW_JS.is_file():
        pytest.fail("workflows/c-review.js is missing, so this drift test checks nothing")
    assert re.search(
        r"BENCHMARK_MODE \? \['--benchmark-mode'\]", WORKFLOW_JS.read_text(encoding="utf-8")
    )


def test_the_workflow_sends_the_returned_declaration_to_the_assembler():
    """`--external-source` is only load-bearing if the workflow reads it off the return.

    The schema REQUIRES the declaration in benchmark mode, so the runtime already validated
    that the agent answered — and then the producers loop dropped the answer on the floor
    and the assembler fell back to the part file alone.
    """
    if not WORKFLOW_JS.is_file():
        pytest.fail("workflows/c-review.js is missing, so this drift test checks nothing")
    source = WORKFLOW_JS.read_text(encoding="utf-8")
    assert "'--external-source '" in source
    assert re.search(
        r"partsExternal\.push\([^\n]*entry\.result\.external_sources_consulted", source
    )


# ------------------------------------------------- regressions with no other cover


def test_public_ids_sort_by_line_as_a_number_not_as_a_padded_string(tmp_path):
    """`pad3` is an id-suffix formatter, not a sort key.

    Sorted with it, findings at 90, 142 and 1000 in one file number BOF-001@90,
    BOF-002@1000, BOF-003@142: every C file over 999 lines gets ids and a report ordering
    that contradict the file.
    """
    run_dir = write_run(
        tmp_path,
        {
            "review-unit-01": producing_part(
                "review-unit-01",
                [
                    raw_finding(line=90, title="a", function="f90"),
                    raw_finding(line=1000, title="b", function="f1000"),
                    raw_finding(line=142, title="c", function="f142"),
                ],
            )
        },
    )
    assert assemble(run_dir) == UNVERIFIED
    ordered = [(f["id"], f["line"]) for f in load_doc(run_dir)["findings"]]
    assert ordered == [("BOF-001", 90), ("BOF-002", 142), ("BOF-003", 1000)]


def test_a_pointer_with_no_note_is_not_promoted_into_an_empty_finding(tmp_path):
    """Promotion runs after the completeness check, so it could bypass it entirely.

    A pointer with no note otherwise produces `title: "Unreviewed pointer: "`, an empty
    description and `incomplete_findings: []` — exactly the "location and no defect" shape
    REQUIRED_FINDING_FIELDS exists to catch.
    """
    run_dir = write_run(
        tmp_path,
        {
            "review-unit-01": producing_part(
                "review-unit-01",
                [raw_finding()],
                pointers=[
                    {"file": "src/b.c", "line": 400},
                    {"file": "src/b.c", "line": 900, "note": "unchecked realloc result"},
                ],
            )
        },
    )
    assert assemble(run_dir) == UNVERIFIED
    doc = load_doc(run_dir)
    assert doc["run"]["pointers_promoted"] == 1
    assert all(f["description"] for f in doc["findings"])


def test_a_promoted_pointer_survives_a_severity_filter(tmp_path):
    """Its LOW is a placeholder nobody assessed, so a filter must not silently delete it.

    Filtered on it, `--severity-filter medium` leaves the promoted finding as a "Not
    reported" table row alone: the note explaining the suspicion reaches no part of
    REPORT.md and the finding reaches no part of SARIF — the safety net deleted by the
    filter.
    """
    run_dir = write_run(
        tmp_path,
        {
            "review-unit-01": producing_part(
                "review-unit-01",
                [raw_finding()],
                pointers=[{"file": "src/b.c", "line": 900, "note": "unchecked realloc"}],
            )
        },
    )
    assert assemble(run_dir, "--severity-filter", "medium", "--no-judge") == UNVERIFIED
    doc = load_doc(run_dir)
    promoted = next(f for f in doc["findings"] if f.get("from_pointer"))
    assert promoted["severity_validated"] is False
    assert promoted in findings_model.reported_findings(doc)
    assert "unchecked realloc" in (run_dir / "REPORT.md").read_text(encoding="utf-8")


def test_a_cross_class_pair_is_not_merged_through_a_same_class_neighbour(tmp_path):
    """CROSS_CLASS_NEARBY_LINES is pairwise; the merge is by connected component.

    A(buffer-overflow,100) + B(integer-overflow,100) + C(buffer-overflow,102) put B and C
    — cross-class, two lines apart — in one group through A, which is the merge the cap
    was measured to prevent. The component is left whole for the dedup agent instead.
    """
    run_dir = write_run(
        tmp_path,
        {
            "review-unit-01": producing_part(
                "review-unit-01",
                [
                    raw_finding(line=100, title="A", bug_class="buffer-overflow"),
                    raw_finding(line=100, title="B", bug_class="integer-overflow"),
                    raw_finding(line=102, title="C", bug_class="buffer-overflow"),
                ],
            )
        },
    )
    assert assemble(run_dir) == UNVERIFIED
    stats = load_doc(run_dir)["stats"]
    assert stats["merged"] == 0
    assert stats["primaries"] == 3


def test_an_unrecognised_fp_verdict_is_ignored_not_read_as_a_rejection(tmp_path, capsys):
    """`TP` instead of `TRUE_POSITIVE` must not delete the finding from every artifact."""
    run_dir = write_run(
        tmp_path,
        {
            "review-unit-01": producing_part("review-unit-01", [raw_finding()]),
            "verdict-01": {
                "verdicts": [
                    {"key": "review-unit-01#0", "fp_verdict": "TP", "severity": "CRITICAL"}
                ]
            },
        },
    )
    assert assemble(run_dir) == UNVERIFIED
    assert json.loads(capsys.readouterr().out)["ignored_verdicts"] == 1
    doc = load_doc(run_dir)
    assert doc["stats"]["reported"] == 1
    assert doc["findings"][0]["severity"]


@pytest.mark.parametrize(
    ("expect", "message"),
    [
        ("review-unit-01=5", "SHORTER"),
        ("review-unit-02", "absent from"),
        ("review-unit-01=x", "is not an integer"),
    ],
)
def test_an_expect_mismatch_is_fatal_and_writes_no_artifacts(tmp_path, capsys, expect, message):
    """The failure this whole design exists to remove: a part shorter, absent or
    unparseable against what the workflow says it dispatched."""
    run_dir = write_run(
        tmp_path, {"review-unit-01": producing_part("review-unit-01", [raw_finding()])}
    )
    assert assemble(run_dir, "--expect", expect) == 2
    assert message in capsys.readouterr().err
    assert not (run_dir / "findings.json").exists()


def test_a_generated_slice_with_no_part_file_is_named(tmp_path):
    """The fan-out is dispatched from the detect agent's transcription of the slice ids.

    A slice it failed to copy is never dispatched, so it gets no `--expect` and appears in
    no failure list; the only other signal is a drop in `checks_satisfied`. units.json is
    the code-generated list, so it is the one place the drop can be named.
    """
    run_dir = write_run(
        tmp_path,
        {"review-unit-01": producing_part("review-unit-01", [raw_finding()], ledger=[LEDGER_ROW])},
        units={
            "units": [LEDGER_UNIT],
            "assignments": [{"id": "unit-01"}, {"id": "unit-02"}],
        },
    )
    assert assemble(run_dir, "--expect", "review-unit-01=1") == 0
    doc = load_doc(run_dir)
    assert doc["run"]["missing_review_parts"] == ["review-unit-02"]
    report = (run_dir / "REPORT.md").read_text(encoding="utf-8")
    assert "reviewed by **nobody**" in report
    sarif = json.loads((run_dir / "REPORT.sarif").read_text(encoding="utf-8"))
    notes = sarif["runs"][0]["invocations"][0]["toolExecutionNotifications"]
    assert any("review-unit-02" in n["message"]["text"] for n in notes)


def test_the_dedup_phase_can_never_cost_the_whole_run(tmp_path, capsys):
    """No `--expect` for the dedup part, in any branch.

    DEDUP_SCHEMA has no `part_written` field, so an agent that returns merges and never
    writes `parts/dedup-agent.json` is indistinguishable from one that wrote it — and an
    expectation on it raises `AssembleError`, exiting 2 with no findings.json, no REPORT.md
    and no REPORT.sarif, for the most skippable phase in the pipeline.
    """
    src = WORKFLOW_JS.read_text(encoding="utf-8")
    assert "partsExpected.push('dedup-agent')" not in src

    # And the assembler does not need it: a run whose dedup part never landed still
    # assembles, with the duplicates visible as two findings, which is the safe direction.
    run_dir = write_run(
        tmp_path,
        {"review-unit-01": producing_part("review-unit-01", [raw_finding(), raw_finding()])},
    )
    assert assemble(run_dir, "--expect", "review-unit-01=2") == UNVERIFIED
    assert len(load_doc(run_dir)["findings"]) == 2


def test_the_workflow_question_text_covers_every_question_the_gate_owes_a_row_for():
    """The review prompt enumerates the questions; a missing one is an unexplained gap.

    Omit one — `initialisation`, say — and a unit with out-parameters owes a row the agent
    was never told existed, which lands in `missing_rows` with no cause anyone can see.
    """
    src = WORKFLOW_JS.read_text(encoding="utf-8")
    start = src.index("const QUESTION_TEXT = {")
    block = src[start : src.index("\n}\n", start)]
    ids = set(re.findall(r"^  '?([a-z][a-z-]*)'?:", block, re.M))
    assert ids == set(check_ledger.QUESTION_SITE_KINDS), (
        f"only in the prompt {sorted(ids - set(check_ledger.QUESTION_SITE_KINDS))}; "
        f"only in the gate {sorted(set(check_ledger.QUESTION_SITE_KINDS) - ids)}"
    )


def test_the_gate_and_the_enumerator_agree_on_every_question_site_kind():
    """`check_ledger` deliberately mirrors `enumerate_units.QUESTIONS` without importing it.

    The ids alone are not enough: the KIND TUPLES decide the owed population, so renaming
    `outparam` on one side gives `initialisation` an empty population everywhere — and a row
    over an empty population is the free coverage the whole gate exists to refuse.
    """
    import enumerate_units

    mirrored = {qid: kinds for qid, (_, kinds) in enumerate_units.QUESTIONS.items()}
    assert mirrored, "the question set is empty; the comparison below is vacuous"
    assert mirrored == check_ledger.QUESTION_SITE_KINDS


def test_primary_election_matches_between_the_js_and_this_module():
    """Rank on confidence alone in `pickPrimary` while `_election_key` puts location
    precision first and the two implementations elect different survivors on the same pair,
    so findings.json disagrees with the workflow's own log about the merge."""
    src = WORKFLOW_JS.read_text(encoding="utf-8")
    pair = [
        {"key": "review-unit-01#0", "confidence": "High", "function": "(file-level)"},
        {"key": "review-unit-02#0", "confidence": "Medium", "function": "parse_header"},
    ]
    script = "\n".join(
        [
            _js_block(src, "const NO_FUNCTION = new Set(["),
            _js_block(src, "function normFunction(name) {"),
            re.search(r"^const CONFIDENCE_RANK = .*$", src, re.M).group(0),
            _js_block(src, "function precisionRank(f) {"),
            _js_block(src, "function pickPrimary(a, b) {"),
            f"const p = {json.dumps(pair)};",
            "console.log(pickPrimary(p[0], p[1]).key);",
        ]
    )
    js = subprocess.run(
        ["node", "-e", script], capture_output=True, text=True, check=True
    ).stdout.strip()
    keyed = {f["key"]: f for f in pair}
    py = min(keyed, key=lambda k: assemble_findings_mod._election_key(keyed, k))
    assert js == py == "review-unit-02#0"


# --------------------------------------------------- merge-chain resolution


@pytest.mark.parametrize(
    ("merged", "expected"),
    [
        # A stale pointer is a VALUE, not a key: guarding only "is this duplicate already
        # merged" leaves `merged_into` naming a finding that is itself merged.
        ({"A": "B", "B": "C"}, {"A": "C", "B": "C"}),
        ({"A": "B", "B": "C", "C": "D"}, {"A": "D", "B": "D", "C": "D"}),
        # A cycle. Left pointing at itself, `merged_into == own id` makes
        # `findings_model.primaries()` resolve the target to the finding itself, see it
        # survive, and skip it — the finding in findings.json and in no artifact.
        ({"A": "B", "B": "A"}, {"B": "A"}),
        ({"A": "B", "B": "C", "C": "A"}, {"B": "A", "C": "A"}),
        ({"A": "A"}, {}),
        ({"A": "B"}, {"A": "B"}),
    ],
)
def test_resolve_chains_compresses_and_never_leaves_a_self_reference(merged, expected):
    assemble_findings_mod.resolve_chains(merged)
    assert merged == expected
    assert not any(key == target for key, target in merged.items())


def test_an_agent_merge_that_demotes_a_tier1_primary_leaves_no_chain(tmp_path):
    """`merged_into` must never name a finding that is itself merged.

    An agent merge re-elects its primary, so a tier-1 primary can lose — and everything
    tier 1 folded into it then pointed at a duplicate. Without the compression pass the
    document carries `BOF-002 -> BOF-001 -> INT-001`, the report shows a primary that is
    not in the reported set, and `also_known_as` does not round-trip.
    """
    vague = dict(function="(file-level)")
    run_dir = write_run(
        tmp_path,
        {
            "review-unit-01": producing_part(
                "review-unit-01",
                [
                    raw_finding(confidence="High", **vague),
                    raw_finding(confidence="Medium", title="same site again", **vague),
                    raw_finding(bug_class="integer-overflow", title="width", confidence="High"),
                ],
            ),
            "dedup-01": {
                "part_id": "dedup-01",
                "merges": [
                    {
                        "primary": "review-unit-01#0",
                        "duplicates": ["review-unit-01#2"],
                        "rationale": "one defect, two labels",
                    }
                ],
            },
        },
    )
    assert assemble(run_dir) == UNVERIFIED
    doc = load_doc(run_dir)
    merged_ids = {f["id"] for f in doc["findings"] if f.get("merged_into")}
    assert len(merged_ids) == 2, "the fixture stopped exercising the demotion"
    targets = {f["merged_into"] for f in doc["findings"] if f.get("merged_into")}
    assert targets & merged_ids == set(), f"{targets} names a finding that is itself merged"
    assert len(targets) == 1
    primary = by_id(doc)[targets.pop()]
    assert sorted(primary["also_known_as"]) == sorted(merged_ids)


def test_a_self_referential_merge_target_never_deletes_the_finding():
    """The second half of the same defect, in the consumer.

    A `merged_into` equal to the finding's own id resolves to the finding itself, which
    survives, so the finding is skipped: `primaries: []`, `reported: []`, no "Not reported"
    row and zero SARIF results, over a `findings.json` that holds it.
    """
    doc = {
        "findings": [
            {"id": "BOF-001", "merged_into": "BOF-001", "fp_verdict": "TRUE_POSITIVE"},
            {"id": "INT-001"},
        ]
    }
    assert [f["id"] for f in findings_model.primaries(doc)] == ["BOF-001", "INT-001"]


# --------------------------------------------------------- input-shape guards


def test_a_part_whose_findings_are_not_a_list_is_refused_not_counted(tmp_path, capsys):
    """`len()` on it raises an uncaught TypeError in `check_expectations`, one step before
    `collect` would reject it with a precise message."""
    run_dir = write_run(
        tmp_path,
        {
            "review-unit-01": producing_part("review-unit-01", [raw_finding()]),
            "review-unit-02": producing_part("review-unit-02", findings=7),
        },
    )
    assert assemble(run_dir, "--expect", "review-unit-02=1") == 2
    assert "'findings' must be a list" in capsys.readouterr().err


def test_a_part_file_holding_more_than_its_agent_returned_is_noted_never_fatal(tmp_path, capsys):
    """Directional on purpose, and the symmetric version killed a real run.

    An invariant-sweep agent that writes nine findings to disk and returns zero — a
    defensible reading of an ambiguous contract — must not cost nine good findings over a
    disagreement in the safe direction. The FILE is the artifact.
    """
    run_dir = write_run(
        tmp_path,
        {"review-unit-01": producing_part("review-unit-01", [raw_finding(), raw_finding(line=9)])},
    )
    assert assemble(run_dir, "--expect", "review-unit-01=0") == UNVERIFIED
    assert "hold more findings than their agent reported" in capsys.readouterr().err
    assert len(load_doc(run_dir)["findings"]) == 2


def test_a_part_file_shorter_than_its_agent_returned_is_fatal(tmp_path, capsys):
    run_dir = write_run(
        tmp_path, {"review-unit-01": producing_part("review-unit-01", [raw_finding()])}
    )
    assert assemble(run_dir, "--expect", "review-unit-01=4") == 2
    assert "SHORTER" in capsys.readouterr().err


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        ({"a": 1}, '{"a": 1}'),
        ([1, "x"], '[1, "x"]'),
        (True, "true"),
        (None, ""),
        (0, ""),
        ("plain", "plain"),
    ],
)
def test_structured_values_in_prose_fields_stay_valid_json(value, expected):
    """Python's repr of a dict puts single quotes into REPORT.md."""
    assert assemble_findings_mod._text(value) == expected


@pytest.mark.parametrize(
    ("flag", "value"),
    [("--threat-model", "NOT_A_MODEL"), ("--severity-filter", "critical")],
)
def test_an_unusable_run_parameter_is_refused_not_silently_renormalised(tmp_path, flag, value):
    """Accepted, `--severity-filter critical` is recorded in findings.json as
    `severity_filter: "critical"`, applied as `all`, and printed in REPORT.md's frontmatter
    as `all` — so a grader reading `run.severity_filter` concludes a filter ran that did
    not."""
    run_dir = write_run(
        tmp_path, {"review-unit-01": producing_part("review-unit-01", [raw_finding()])}
    )
    args = {"--threat-model": "REMOTE", "--severity-filter": "all", flag: value}
    with pytest.raises(SystemExit) as exc:
        main(["--run-dir", str(run_dir), *[part for pair in args.items() for part in pair]])
    assert exc.value.code == 2
    assert not (run_dir / "findings.json").exists()


# ------------------------------------------- one malformed field must not cost the run


@pytest.mark.parametrize(
    "part",
    [
        {"ledger": 5},
        {"pointers": 5},
        {"ledger": [{"unit_id": "u", "question": "bounds", "sites_accounted": 5}]},
        {"findings": [{"bug_class": ["buffer-overflow"]}]},
        {"findings": [{"confidence": ["High"]}]},
    ],
    ids=["ledger", "pointers", "sites-accounted", "bug-class-list", "confidence-list"],
)
def test_a_malformed_producing_field_is_ignored_rather_than_fatal(tmp_path, part):
    """`x or []` accepts any non-empty non-iterable and `in CLASS_PREFIXES` hashes its key.

    Unchecked, each of these raises a TypeError before a single artifact is written, and the
    process exits 1 — which the contract and the agent prompt both define as "everything WAS
    written, do not re-run" — pointing the user at an empty directory while the part files
    sit intact beside it. Type-checking `findings` alone is not enough.
    """
    findings = [dict(raw_finding(), **f) for f in part.pop("findings", [])] or [raw_finding()]
    run_dir = write_run(
        tmp_path, {"review-unit-01": {"part_id": "u", "findings": findings, **part}}
    )
    assert assemble(run_dir) == UNVERIFIED
    doc = load_doc(run_dir)
    assert len(doc["findings"]) == 1
    # The unhashable values fall back exactly as the JS does, rather than killing the run.
    assert doc["findings"][0]["bug_class"] in CLASS_PREFIXES
    assert doc["findings"][0]["confidence"] in ("High", "Medium")
    assert (run_dir / "REPORT.md").exists() and (run_dir / "REPORT.sarif").exists()


def test_an_unexpected_crash_is_exit_two_and_never_exit_one(tmp_path, monkeypatch, capsys):
    """Exit 1 means "assembled but unverified — the artifacts are complete, do not re-run".

    A traceback exits 1 too, so an unhandled exception tells the caller exactly that over an
    empty directory, and SKILL.md instructs the model to relay it to the user.
    """

    def boom(_doc):
        raise RuntimeError("renderer exploded")

    monkeypatch.setattr(assemble_findings_mod.render_report, "render", boom)
    run_dir = write_run(
        tmp_path, {"review-unit-01": producing_part("review-unit-01", [raw_finding()])}
    )
    assert assemble(run_dir) == 2
    assert "renderer exploded" in capsys.readouterr().err
    assert not (run_dir / "findings.json").exists()


def test_a_generator_failure_leaves_no_artifact_at_all_not_the_previous_runs(
    tmp_path, monkeypatch, capsys
):
    """Write findings.json first and a generator that raises leaves run 2's findings on disk
    beside run 1's REPORT.sarif — two artifacts describing different runs.

    Rendering both before writing either closes that half. The other half is exit 2 with the
    PREVIOUS run's four artifacts still sitting there: the workflow is covered because
    `enumerate_units.write_outputs` clears them at the start of a run, but the hand
    re-assembly SKILL.md and the assemble prompt both send the reader to is not — and the
    assemble agent answers `artifacts_written` from what is in the directory, so it honestly
    reports `true` for a run that wrote nothing and the caller is told not to re-run. Exit 2
    must leave a directory with no artifacts in it.
    """
    run_dir = write_run(
        tmp_path,
        {"review-unit-01": producing_part("review-unit-01", [raw_finding(title="OLD RUN")])},
    )
    assert assemble(run_dir) == UNVERIFIED
    artifacts = ("findings.json", "REPORT.md", "REPORT.sarif", "ledger-gate.json")
    assert all((run_dir / name).exists() for name in artifacts)
    capsys.readouterr()

    (run_dir / "parts" / "review-unit-01.json").write_text(
        json.dumps(producing_part("review-unit-01", [raw_finding(title="NEW RUN")])),
        encoding="utf-8",
    )
    monkeypatch.setattr(
        assemble_findings_mod.generate_sarif,
        "build_sarif",
        lambda _doc: (_ for _ in ()).throw(RuntimeError("sarif exploded")),
    )
    assert assemble(run_dir) == 2
    err = capsys.readouterr().err
    for name in artifacts:
        assert not (run_dir / name).exists(), f"{name} is the PREVIOUS run's and survived"
        assert name in err, f"{name} was removed without saying so"
    assert "A PREVIOUS run's artifacts" in err


@pytest.mark.parametrize(
    ("reported", "expected"),
    [
        ("src/a.c", "src/a.c"),
        ("./src/a.c", "src/a.c"),
        ("src//a.c", "src/a.c"),
        ("[src/a.c](src/a.c)", "src/a.c"),
        ("src/./a.c", "src/a.c"),
        ("src/x/../a.c", "src/a.c"),
    ],
)
def test_every_spelling_of_one_path_normalises_to_one_location(tmp_path, reported, expected):
    """Unnormalised, three findings on `src/a.c`, `<root>/src/a.c` and `src/x/../a.c` at the
    same line and class merge with nothing: the same bug is reported three times, and a
    code-scanning UI cannot resolve an absolute uri under a `%SRCROOT%` base id."""
    assert assemble_findings_mod.normalize_path(reported) == expected


def test_an_absolute_path_inside_the_scope_root_is_relativised(tmp_path):
    root = str(tmp_path)
    assert assemble_findings_mod.normalize_path(f"{root}/src/a.c", root) == "src/a.c"
    run_dir = write_run(
        tmp_path,
        {
            "review-unit-01": producing_part(
                "review-unit-01",
                [raw_finding(file="src/a.c"), raw_finding(file=f"{root}/src/a.c")],
            )
        },
    )
    assert assemble(run_dir, "--scope", root) == UNVERIFIED
    doc = load_doc(run_dir)
    assert {f["file"] for f in doc["findings"]} == {"src/a.c"}
    assert doc["stats"]["merged"] == 1


def test_a_relative_scope_root_strips_both_of_its_spellings(tmp_path):
    """`--scope src` used to be resolved here and nowhere else, so this side stripped
    `/proj/src/` and the workflow's `normalizePath` — which has no filesystem APIs and got
    the relative `src` — stripped `src/`. One bug filed as `a.c` (the unit id, since
    `enumerate_units --root src` names units relative to the root) and `src/a.c` (the path
    the reviewer read through `contextRoots: '.'`) was one primary in the workflow log and
    two in findings.json, which is the disagreement the port exists to prevent.
    """
    run_dir = write_run(
        tmp_path,
        {
            "review-unit-01": producing_part(
                "review-unit-01",
                [
                    raw_finding(file="a.c"),
                    raw_finding(file="src/a.c"),
                    raw_finding(file="/proj/src/a.c"),
                ],
            )
        },
    )
    assert assemble(run_dir, "--scope", "src", "--scope-abs", "/proj/src") == UNVERIFIED
    doc = load_doc(run_dir)
    assert {f["file"] for f in doc["findings"]} == {"a.c"}
    assert doc["stats"]["merged"] == 2


def test_an_explicitly_empty_scope_abs_is_honoured_rather_than_resolved(tmp_path):
    """`--scope-abs ''` is the workflow saying "the skill did not resolve it, so I stripped
    nothing absolute". Falling back to `Path(ns.scope).resolve()` on an empty value puts the
    divergence straight back: this side would strip a root the workflow never saw."""
    run_dir = write_run(
        tmp_path,
        {
            "review-unit-01": producing_part(
                "review-unit-01",
                [raw_finding(file="a.c"), raw_finding(file=str(tmp_path / "src" / "a.c"))],
            )
        },
    )
    assert assemble(run_dir, "--scope", "src", "--scope-abs", "") == UNVERIFIED
    doc = load_doc(run_dir)
    assert {f["file"] for f in doc["findings"]} == {"a.c", str(tmp_path / "src" / "a.c")}
    assert doc["stats"]["merged"] == 0


def test_a_likely_tp_verdict_from_a_judge_is_honoured_rather_than_discarded(tmp_path):
    """`LIKELY_TP` is the verdict every finding carries in the shipped configuration, and
    every other `LIKELY_TP` in this suite comes from the assembler's own fallback rather than
    from a verdict part — so without this one, narrowing `SURVIVOR_VERDICTS` to
    `TRUE_POSITIVE` alone drops the judge's verdict, severity and rationale on the floor with
    the suite green."""
    run_dir = write_run(
        tmp_path,
        {
            "review-unit-01": producing_part("review-unit-01", [raw_finding()]),
            "verdict-1": {
                "verdicts": [
                    verdict("review-unit-01#0", fp_verdict="LIKELY_TP", severity="CRITICAL")
                ]
            },
        },
    )
    assert assemble(run_dir) == UNVERIFIED
    doc = load_doc(run_dir)
    entry = doc["findings"][0]
    assert entry["fp_verdict"] == "LIKELY_TP"
    assert entry["severity"] == "CRITICAL"
    assert entry["severity_validated"] is True
    assert doc["stats"]["reported"] == 1
    assert doc["run"]["unjudged_findings"] == []


def test_the_collision_window_refuses_a_pair_just_outside_it(tmp_path):
    """`COLLISION_LINES` is pinned as a constant against the JS; this pins its USE. Without
    a pair 9 or 10 lines apart the predicate can be widened to `<= COLLISION_LINES + 2` with
    every other fixture still passing, and a merge the workflow's `collisionBuckets` refused
    then reaches findings.json and the two disagree."""
    inside = {
        "file": "src/a.c",
        "function": "(file-level)",
        "line": 100,
        "bug_class": "buffer-overflow",
        "data_flow": "",
    }
    for gap, collides in ((assemble_findings_mod.COLLISION_LINES, True), (9, False), (10, False)):
        other = dict(inside, line=100 + gap, bug_class="integer-overflow")
        assert assemble_findings_mod.collides(inside, other) is collides, gap


# ------------------------------------------------- part-file expectations


@pytest.mark.parametrize("findings_value", [None, 0, "", {}, "ABSENT"])
def test_a_falsy_findings_field_is_a_short_part_not_a_silent_zero(tmp_path, findings_value):
    """`--expect ID=COUNT` was skipped for the exact shape it exists to catch.

    A guard that reads `doc.get("findings")` and skips anything that is not a list cannot
    lean on `collect` to reject the same part: `collect` reads `doc.get("findings") or []`,
    so it rejects only a TRUTHY non-list and `null`, `0`, `""`, `{}` and an absent key all
    become "this agent found nothing". The workflow pushes `review-unit-01=9` from the nine
    findings the agent returned through the schema, and the run then produces rc 0, zero
    findings, no stderr warning and a clean REPORT.md.
    """
    part = producing_part("review-unit-01", [raw_finding()])
    if findings_value == "ABSENT":
        del part["findings"]
    else:
        part["findings"] = findings_value
    run_dir = write_run(tmp_path, {"review-unit-01": part})
    assert assemble(run_dir, "--expect", "review-unit-01=9") == 2
    assert not (run_dir / "findings.json").exists()


def test_a_part_its_agent_says_it_did_not_write_is_still_count_checked(tmp_path, capsys):
    """`part_written: false` must not switch the count check off while the file is read.

    A reviewer that summarises its own 12 findings down to 3 and sets the flag would ship 3
    with nothing comparing them against the 12 it returned. The workflow passes the
    expectation either way, and `--agent-failure` is what keeps an honestly MISSING file
    from failing the whole run.
    """
    run_dir = write_run(
        tmp_path,
        {
            "review-unit-01": producing_part("review-unit-01", [raw_finding()]),
            "review-unit-02": producing_part("review-unit-02", [raw_finding(title="one of nine")]),
        },
    )
    failure = "review-unit-02: did not write its part file"
    assert (
        assemble(
            run_dir,
            "--expect",
            "review-unit-01=1",
            "--expect",
            "review-unit-02=9",
            "--agent-failure",
            failure,
        )
        == 2
    )
    assert "holds 1 finding(s), the agent returned 9" in capsys.readouterr().err


def test_a_missing_part_its_agent_declared_is_not_fatal(tmp_path):
    """The other half: honest self-reporting must not be punished harder than silence.

    An expectation for a file the agent said does not exist must not fail the assembler with
    exit 2 and no artifacts at all, discarding every other reviewer's work.
    """
    run_dir = write_run(
        tmp_path, {"review-unit-01": producing_part("review-unit-01", [raw_finding()])}
    )
    assert (
        assemble(
            run_dir,
            "--expect",
            "review-unit-01=1",
            "--expect",
            "review-unit-02=4",
            "--agent-failure",
            "review-unit-02: did not write its part file",
        )
        == UNVERIFIED
    )
    doc = load_doc(run_dir)
    assert doc["run"]["expectations_checked"] is True
    assert doc["run"]["agent_failures"] == ["review-unit-02: did not write its part file"]
    # And an UNDECLARED missing part is still fatal.
    assert assemble(run_dir, "--expect", "review-unit-01=1", "--expect", "review-unit-03=4") == 2


# ---------------------------------------------------------- line coercion


def test_a_quoted_line_number_is_a_number_not_line_one(tmp_path):
    """`"line": "142"` collapsing to 1 fires no marker either, because 1 is a valid int.

    Two distinct findings quoted that way in one file then share `(file, line, bug_class)`
    and tier 1 merges one of them out of the report entirely — a real bug deleted from
    REPORT.md by a quoting mistake, with `incomplete_findings: []` and exit 0.
    """
    run_dir = write_run(
        tmp_path,
        {
            "review-unit-01": producing_part(
                "review-unit-01",
                [
                    raw_finding(title="first", function="parse_header", line="142"),
                    raw_finding(title="second", function="emit_reply", line="900"),
                ],
            )
        },
    )
    assert assemble(run_dir) == UNVERIFIED
    doc = load_doc(run_dir)
    assert sorted(f["line"] for f in doc["findings"]) == [142, 900]
    assert doc["stats"]["merged"] == 0
    body = (run_dir / "REPORT.md").read_text(encoding="utf-8")
    assert "first" in body and "second" in body


def test_a_line_nobody_can_read_is_marked_invented(tmp_path):
    """`_line` has to return a usable int — SARIF rejects anything else and the tier-1
    bucket is keyed on it — so the invented 1 needs its own field or the marker is dead."""
    run_dir = write_run(
        tmp_path,
        {"review-unit-01": producing_part("review-unit-01", [raw_finding(line="not a line")])},
    )
    assert assemble(run_dir) == UNVERIFIED
    finding = load_doc(run_dir)["findings"][0]
    assert (finding["line"], finding["line_invented"]) == (1, True)
    assert "[LINE NUMBER INVENTED]" in (run_dir / "REPORT.md").read_text(encoding="utf-8")


# ------------------------------------------- fields dropped for the wrong type


@pytest.mark.parametrize(
    ("stem", "part", "key"),
    [
        ("dedup-01", {"merges": {"primary": "a", "duplicates": ["b"]}}, "ignored_merges"),
        ("verdict-01", {"verdicts": {"key": "a"}}, "ignored_verdicts"),
        ("review-unit-02", {"findings": [], "ledger": {"unit_id": "x"}}, "ignored_fields"),
        ("review-unit-02", {"findings": [], "pointers": {"file": "x"}}, "ignored_fields"),
    ],
    ids=["merges", "verdicts", "ledger", "pointers"],
)
def test_a_list_field_with_the_wrong_type_is_counted_not_silently_dropped(
    tmp_path, capsys, stem, part, key
):
    """`_seq` turns a crash into silence unless the drop is counted: `merged_agent: 0`,
    `ignored_merges: 0`, no stderr line and exit 0 — indistinguishable from an agent that
    found nothing. For `ledger` that is a whole reviewer's coverage account, and it feeds
    the gate as well."""
    run_dir = write_run(
        tmp_path,
        {"review-unit-01": producing_part("review-unit-01", [raw_finding()]), stem: part},
    )
    assert assemble(run_dir) == UNVERIFIED
    assert json.loads(capsys.readouterr().out)[key] == 1


# ---------------------------------------------------------- the write phase


def test_a_rejected_ledger_alone_fails_the_run(tmp_path, capsys):
    """`if missing or violations:` — this is the only test behind the violations half.

    Mutating it to `if missing:` otherwise leaves the whole suite green over the case this
    gate is for: every owed row answered, every answer rejected, exit 0 and `ok: true` over
    a ledger of which nothing survived.
    """
    rejected = dict(LEDGER_ROW, sites_accounted=[142], evidence="only 142")
    run_dir = write_run(
        tmp_path,
        {"review-unit-01": producing_part("review-unit-01", [raw_finding()], ledger=[rejected])},
        units={"units": [LEDGER_UNIT]},
    )
    assert assemble(run_dir) == 1
    summary = json.loads(capsys.readouterr().out)
    assert summary["ok"] is False
    # Answered in full, rejected in full: no missing rows at all, so only the violation
    # half of the guard can fail this.
    ledger = load_doc(run_dir)["run"]["ledger"]
    assert (ledger["missing_row_count"], ledger["violation_count"]) == (0, 1)
    assert "1 violation(s)" in summary["gate_error"]


def test_a_write_that_fails_replaces_no_artifact_and_is_not_exit_1(tmp_path, capsys):
    """The three writes have to sit inside a `try`.

    Outside one, an ENOSPC, a read-only output dir or a run dir removed mid-run escapes as a
    traceback, which exits 1 — the code the workflow prompt and SKILL.md both define as
    "everything WAS written, do not re-run" — over a findings.json holding this run beside a
    REPORT.sarif holding the last one.
    """
    parts = {"review-unit-01": producing_part("review-unit-01", [raw_finding(title="run one")])}
    run_dir = write_run(tmp_path, parts)
    assert assemble(run_dir) == UNVERIFIED
    capsys.readouterr()
    first = {
        name: (run_dir / name).read_text(encoding="utf-8")
        for name in ("findings.json", "REPORT.md", "REPORT.sarif", "ledger-gate.json")
    }

    # Run two differs, and REPORT.md cannot be written.
    (run_dir / "parts" / "review-unit-01.json").write_text(
        json.dumps(producing_part("review-unit-01", [raw_finding(title="run two")])),
        encoding="utf-8",
    )
    (run_dir / "REPORT.md").unlink()
    (run_dir / "REPORT.md").mkdir()
    try:
        assert assemble(run_dir) == 2
    finally:
        (run_dir / "REPORT.md").rmdir()
        (run_dir / "REPORT.md").write_text(first["REPORT.md"], encoding="utf-8")
    err = capsys.readouterr().err
    assert "NO artifact was replaced" in err
    # And run one's artifacts are GONE. Exit 2 means "no artifact was written", and
    # `c-review.js` has the assemble agent answer `artifacts_written` by LISTING this
    # directory — so leaving the previous run's copies there makes it honestly report `true`
    # for a run that wrote nothing. Every exit-2 path has to clear them, this one included.
    assert "A PREVIOUS run's artifacts" in err
    for name in ("findings.json", "REPORT.sarif", "ledger-gate.json"):
        assert not (run_dir / name).exists(), name
        assert name in err, name
    assert not list(run_dir.glob("*.partial"))


def test_the_four_artifacts_are_written_in_the_documented_order(tmp_path, monkeypatch):
    """Asserting that four files exist says nothing about the ORDER they were written in:
    reversing the `outputs` tuple to sarif/md/json leaves the rest of the suite green. The
    order is observed here rather than assumed, because findings.json is the document both
    generators render from."""
    written: list[str] = []
    real = Path.write_text
    monkeypatch.setattr(
        Path,
        "write_text",
        lambda self, *a, **k: (written.append(self.name), real(self, *a, **k))[1],
    )
    run_dir = write_run(
        tmp_path, {"review-unit-01": producing_part("review-unit-01", [raw_finding()])}
    )
    assert assemble(run_dir) == UNVERIFIED
    for name in ("findings.json", "REPORT.md", "REPORT.sarif", "ledger-gate.json"):
        assert (run_dir / name).is_file(), name
    staged = [n for n in written if n.endswith(".partial")]
    assert staged == [
        "findings.json.partial",
        "REPORT.md.partial",
        "REPORT.sarif.partial",
        "ledger-gate.json.partial",
    ], staged
    # findings.json is the document both generators were rendered from, so REPORT.md must
    # describe the findings that are in it.
    doc = load_doc(run_dir)
    assert doc["findings"][0]["title"] in (run_dir / "REPORT.md").read_text(encoding="utf-8")


def _good_run(tmp_path):
    """A completed run directory and the text of its four artifacts."""
    run_dir = write_run(
        tmp_path, {"review-unit-01": producing_part("review-unit-01", [raw_finding()])}
    )
    assert assemble(run_dir) == UNVERIFIED
    return run_dir, {
        name: (run_dir / name).read_text(encoding="utf-8")
        for name in ("findings.json", "REPORT.md", "REPORT.sarif", "ledger-gate.json")
    }


def test_a_rename_that_fails_part_way_leaves_no_mixed_directory(tmp_path, monkeypatch):
    """The rename loop has to be a transaction, or the message contradicts the directory.

    A `PermissionError` on the 3rd of 4 renames — a macOS `uchg` flag, a sticky-bit
    directory whose target is owned by another uid, an ACL denying delete, an `EACCES` or
    `ESTALE` from an NFS mount — otherwise leaves run 2's findings.json and REPORT.md beside
    run 1's REPORT.sarif and ledger-gate.json, exits 2, and prints "NO artifact was
    replaced". Exit 2 is defined as "no artifact was written at all"; two of four were, and
    REPORT.md and REPORT.sarif then describe different runs. The rollback puts run 1 back,
    and then
    `_clear_stale_artifacts` removes it — because exit 2 means the directory holds nothing
    this run wrote, and the assemble agent answers `artifacts_written` by listing it. The
    rollback loop itself is pinned by `test_a_failing_rollback_is_reported_and_never_escapes_main`,
    which exercises the branch where restoring fails and nothing may be removed.
    """
    run_dir, first = _good_run(tmp_path)
    # A second run whose findings differ, so a survivor from run 1 is visible.
    part = producing_part("review-unit-01", [raw_finding(title="Second run finding")])
    (run_dir / "parts" / "review-unit-01.json").write_text(json.dumps(part), encoding="utf-8")

    real = Path.replace
    calls = {"n": 0}

    def flaky(self, target):
        if str(self).endswith(".partial"):
            calls["n"] += 1
            if calls["n"] == 3:
                raise PermissionError(13, "Operation not permitted", str(target))
        return real(self, target)

    monkeypatch.setattr(Path, "replace", flaky)
    assert assemble(run_dir) == 2
    for name in first:
        assert not (run_dir / name).exists(), name
    assert not list(run_dir.glob("*.partial"))
    assert not list(run_dir.glob("*.prev"))


def test_a_staging_write_that_fails_leaves_nothing_behind(tmp_path, monkeypatch):
    """The only test that makes a write fail DURING the loop.

    Every other write-phase test reaches the failure through the `is_dir()` pre-flight,
    which short-circuits before any staging file exists — leaving `staged` empty at `except`
    time and the staging, the rename, the cleanup and the `OSError` breadth all unexercised.
    Four mutations of the block survive that: `tmp = path` (which makes the cleanup unlink
    the REAL artifacts), renaming inside the write loop, narrowing `except OSError` to
    `except IsADirectoryError`, and dropping the cleanup.
    """
    run_dir, first = _good_run(tmp_path)
    real = Path.write_text
    calls = {"n": 0}

    def flaky(self, *args, **kwargs):
        if str(self).endswith(".partial"):
            calls["n"] += 1
            if calls["n"] == 3:
                # Created and truncated, THEN failed: the shape ENOSPC produces, and the
                # one that leaves an orphan `.partial` if the cleanup list is appended to
                # only after a successful write.
                real(self, "", encoding="utf-8")
                raise PermissionError(13, "No space left on device", str(self))
        return real(self, *args, **kwargs)

    monkeypatch.setattr(Path, "write_text", flaky)
    assert assemble(run_dir) == 2
    # Nothing this run wrote, and nothing the previous one did either: exit 2 is "no
    # artifact was written", and the assemble agent answers `artifacts_written` from the
    # directory listing.
    for name in first:
        assert not (run_dir / name).exists(), name
    assert not list(run_dir.glob("*.partial"))


def test_a_part_file_nobody_dispatched_reaches_no_artifact(tmp_path, capsys):
    """`--expect` asserts every dispatched part ARRIVED; this is the converse.

    Read any file under `parts/` whose stem starts with a producing prefix and its findings
    are assembled and its ledger rows counted — so with `--expect review-unit-01=0` as the
    only expectation a `parts/sweep-ghost.json` nobody dispatched contributes a CRITICAL that
    renders in REPORT.md as `BOF-001`, with `unrecognised_parts: 0`, `ok: true` and exit 0.
    `ID=COUNT` is what makes a summarised part a detectable lie; an agent wanting to exceed
    its count wrote the surplus to a second file.
    """
    run_dir = write_run(
        tmp_path,
        {
            "review-unit-01": producing_part("review-unit-01", [raw_finding()]),
            "sweep-ghost": producing_part(
                "sweep-ghost", [raw_finding(title="Ghost", severity="CRITICAL")]
            ),
        },
    )
    assert assemble(run_dir, "--expect", "review-unit-01=1") == UNVERIFIED
    doc = load_doc(run_dir)
    assert [f["found_by"] for f in doc["findings"]] == ["review-unit-01"], doc["findings"]
    assert doc["run"]["unrecognised_parts"] == ["sweep-ghost"]
    assert "Ghost" not in (run_dir / "REPORT.md").read_text(encoding="utf-8")


def test_a_dedup_part_nobody_dispatched_reaches_no_artifact(tmp_path, capsys):
    """The dedup carve-out has to be an exact stem, not the `dedup-` PREFIX.

    The workflow dispatches exactly one dedup part and deliberately never `--expect`s it, so
    the carve-out is load-bearing — but as a prefix it is unbounded: any
    `parts/dedup-ghost.json` is read, and a ghost dedup part merges a CRITICAL out of
    REPORT.md under the workflow's own flags and the strictest possible expectation, with
    `unrecognised_parts: 0`, no Run warning, and `dedup-ghost` named nowhere in any artifact.
    """
    low = raw_finding(title="LOW one", line=9, severity="LOW")
    critical = raw_finding(title="REAL critical", line=30, severity="CRITICAL")
    run_dir = write_run(
        tmp_path,
        {
            "review-unit-01": producing_part("review-unit-01", [low, critical]),
            "dedup-ghost": {
                "part_id": "dedup-ghost",
                "merges": [
                    {
                        "primary": "review-unit-01#0",
                        "duplicates": ["review-unit-01#1"],
                        "rationale": "ghost",
                    }
                ],
            },
        },
    )
    assert assemble(run_dir, "--expect", "review-unit-01=2") == UNVERIFIED
    doc = load_doc(run_dir)
    assert "REAL critical" in (run_dir / "REPORT.md").read_text(encoding="utf-8")
    assert doc["run"]["unrecognised_parts"] == ["dedup-ghost"]
    assert doc["stats"]["merged_agent"] == 0


def test_the_one_undispatched_dedup_part_the_workflow_writes_is_still_applied(tmp_path):
    """The exact stem, which is what makes the carve-out bounded rather than absent."""
    low = raw_finding(title="LOW one", line=9, severity="LOW")
    critical = raw_finding(title="REAL critical", line=30, severity="CRITICAL")
    run_dir = write_run(
        tmp_path,
        {
            "review-unit-01": producing_part("review-unit-01", [low, critical]),
            "dedup-agent": {
                "part_id": "dedup-agent",
                "merges": [
                    {
                        "primary": "review-unit-01#1",
                        "duplicates": ["review-unit-01#0"],
                        "rationale": "one construct",
                    }
                ],
            },
        },
    )
    assert assemble(run_dir, "--expect", "review-unit-01=2") == UNVERIFIED
    doc = load_doc(run_dir)
    assert doc["run"]["unrecognised_parts"] == []
    assert doc["stats"]["merged_agent"] == 1


def test_no_expect_at_all_is_reported_as_unverified_not_as_success(tmp_path, capsys):
    """An allowlist handed zero items admits everything, which must not be exit 0 `ok: true`.

    `dispatched_stems` returns None for an empty expectation set and `split_undispatched`
    short-circuits on None, so "no expectations" means "read everything": half of a run's
    certified coverage can come from a `parts/sweep-ghost.json` nobody dispatched, while the
    warning, the `expectations_checked: false` field and the SARIF note leave the two things
    a caller keys off — `ok` and the exit code — saying the run was clean.
    """
    run_dir = write_run(
        tmp_path,
        {
            "review-unit-01": producing_part(
                "review-unit-01", [raw_finding()], ledger=[LEDGER_ROW]
            ),
            "sweep-ghost": producing_part(
                "sweep-ghost",
                [raw_finding(title="Ghost", severity="CRITICAL", file="src/ghost.c", line=77)],
            ),
        },
        units={"units": [LEDGER_UNIT]},
    )
    # The gate itself is clean, so nothing but the missing `--expect` can fail this run.
    assert assemble(run_dir, "--expect", "review-unit-01=1") == 0
    capsys.readouterr()

    assert assemble(run_dir) == 1
    out = json.loads(capsys.readouterr().out)
    assert out["ok"] is False
    assert out["artifacts_written"] is True
    assert "no --expect" in out["gate_error"]
    assert "Ghost" in (run_dir / "REPORT.md").read_text(encoding="utf-8"), (
        "with no expectation the ghost IS read — which is exactly why the run is not ok"
    )


def test_the_producing_part_guard_runs_after_the_allowlist(tmp_path, capsys):
    """Run it before the allowlist and an UNDISPATCHED producing part satisfies it and is
    then filtered out: a real CRITICAL is dropped, REPORT.md says "No findings passed", and
    the run exits 1 with `artifacts_written: true` over zero producing parts."""
    run_dir = write_run(
        tmp_path,
        {
            "sweep-classes": producing_part(
                "sweep-classes", [raw_finding(title="REAL sweep finding", severity="CRITICAL")]
            )
        },
    )
    # `--agent-failure` so the absent expected part is not what fails the run: what this
    # test is about is the part that IS on disk and was never dispatched.
    failure = "review-unit-01: crashed"
    assert assemble(run_dir, "--expect", "review-unit-01=3", "--agent-failure", failure) == 2
    err = capsys.readouterr().err
    assert "none of them is a dispatched producing part" in err
    assert "undispatched: sweep-classes" in err
    assert not (run_dir / "REPORT.md").exists()


def test_a_failing_rollback_is_reported_and_never_escapes_main(tmp_path, monkeypatch, capsys):
    """The rollback does file I/O, so unguarded a failure inside it leaves `main()` entirely.

    `raise SystemExit(main())` then exits 1 — "everything WAS written, do not re-run" — over
    a directory missing artifacts, with no `assemble_findings:` line printed at all.
    """
    run_dir = write_run(
        tmp_path, {"review-unit-01": producing_part("review-unit-01", [raw_finding()])}
    )
    assert assemble(run_dir, "--expect", "review-unit-01=1") == UNVERIFIED
    before = (run_dir / "REPORT.md").read_text(encoding="utf-8")
    capsys.readouterr()

    real_replace = Path.replace

    def flaky(self, target):
        if self.name.endswith(".partial") and self.name.startswith("REPORT.sarif"):
            raise PermissionError(f"rename denied: {self}")
        if self.name.endswith(".prev"):
            raise PermissionError(f"rollback denied: {self}")
        return real_replace(self, target)

    monkeypatch.setattr(Path, "replace", flaky)
    assert assemble(run_dir, "--expect", "review-unit-01=1") == 2
    err = capsys.readouterr().err
    assert "THE OUTPUT DIRECTORY IS INCONSISTENT" in err
    assert "rollback denied" in err
    # And the artifact it could not restore is still ON DISK under its `.prev` name, because
    # the loop no longer unlinks the destination before the restore that may fail.
    assert (run_dir / "REPORT.md.prev").read_text(encoding="utf-8") == before


def test_a_lone_surrogate_in_a_part_file_is_exit_2_not_exit_1(tmp_path, capsys):
    """`"\\ud800"` is valid JSON and `json.loads` decodes it to a LONE SURROGATE.

    `Path.write_text(..., encoding="utf-8")` then raises `UnicodeEncodeError` — a
    `ValueError`, not an `OSError` — so a staged-write handler catching `OSError` alone
    misses it, it escapes `main()`, and `raise SystemExit(main())` exits **1**: the code
    `c-review.js` and SKILL.md both define as "everything WAS written, do not re-run". No
    `assemble_findings:` line is printed at all, and the directory still holds the PREVIOUS
    run's four artifacts, from which the assemble agent honestly reports
    `artifacts_written: true`.
    """
    run_dir, _ = _good_run(tmp_path)
    # `json.dumps` re-escapes it, so what lands on disk is the literal `\ud800` escape —
    # the byte sequence an agent's part file actually carries.
    surrogate = json.dumps(
        producing_part("review-unit-01", [raw_finding(title="overflow in " + chr(0xD800))])
    )
    assert "\\ud800" in surrogate
    (run_dir / "parts" / "review-unit-01.json").write_text(surrogate, encoding="utf-8")
    capsys.readouterr()
    assert assemble(run_dir) == 2
    err = capsys.readouterr().err
    assert "UnicodeEncodeError" in err
    for name in ("findings.json", "REPORT.md", "REPORT.sarif", "ledger-gate.json"):
        assert not (run_dir / name).exists(), name
    assert not list(run_dir.glob("*.partial"))


def test_a_line_too_large_for_a_float_does_not_destroy_the_document(tmp_path, capsys):
    """`math.isfinite(10**400)` raises `OverflowError` — it converts to float first.

    A guard anticipating only `float('inf')` lets a `line` of `10**400`, which `json.loads`
    accepts, exit 2 with "unexpected OverflowError" and delete all four of the previous run's
    artifacts. Every other finding in the document is lost over a display-only field, and
    `pointers[].line` reaches the same helper.
    """
    parts = {
        "review-unit-01": producing_part(
            "review-unit-01",
            [raw_finding(title="huge", line=10**400), raw_finding(title="ordinary", line=12)],
            pointers=[{"file": "src/parse.c", "line": 10**400, "note": "look here"}],
        )
    }
    run_dir = write_run(tmp_path, parts)
    assert assemble(run_dir, "--expect", "review-unit-01=2") == UNVERIFIED
    doc = load_doc(run_dir)
    assert {f["title"] for f in doc["findings"]} == {"huge", "ordinary"}
    # The line is unusable, so both artifacts say so rather than pinning it at line 1.
    huge = next(f for f in doc["findings"] if f["title"] == "huge")
    assert findings_model.line_usable(huge) is False


def test_one_malformed_ledger_row_is_dropped_not_fatal(tmp_path, capsys):
    """A wholly wrong-typed `ledger` is tolerated, so ONE bad row inside it cannot be fatal.

    `"ledger": 5` gives exit 1 with all four artifacts and `ignored_fields: 1`; treating
    `"ledger": [{good}, "oops"]` as fatal gives exit 2, no artifacts, and the previous run's
    four deleted. Coverage rows feed only REPORT.md's display table — `check_ledger` re-reads
    the parts itself — so that would put the strictest response in the file behind its least
    consequential field.
    """
    good = {
        "unit_id": "src/parse.c:1-40",
        "question": "bounds",
        "verdict": "clean",
        "sites_accounted": [10],
        "evidence": "one write, bounded",
    }
    parts = {
        "review-unit-01": producing_part(
            "review-unit-01", [raw_finding()], ledger=[good, "oops", 7]
        )
    }
    run_dir = write_run(tmp_path, parts)
    assert assemble(run_dir, "--expect", "review-unit-01=1") == UNVERIFIED
    doc = load_doc(run_dir)
    assert len(doc["findings"]) == 1
    assert [row["bug_class"] for row in doc["coverage"]] == ["bounds"]
    err = capsys.readouterr().err
    assert "review-unit-01.ledger[1]" in err and "review-unit-01.ledger[2]" in err


def test_a_verdict_part_that_expect_would_drop_is_refused_rather_than_ignored(tmp_path, capsys):
    """Without a way to allowlist a verdict part, the judged configuration is unusable.

    `--expect` is mandatory for exit 0, so in the configuration the `--no-judge` help
    advertises, an unallowlisted judge's FALSE_POSITIVE is thrown away and the finding ships
    as a survivor at `ok: true`, with the part named only in `unrecognised_parts`. Naming it
    in `--expect` is the remedy, and the error message has to say so.
    """
    parts = {
        "review-unit-01": producing_part("review-unit-01", [raw_finding()]),
        "verdict-01": {
            "part_id": "verdict-01",
            "verdicts": [verdict("review-unit-01#0", fp_verdict="FALSE_POSITIVE")],
        },
    }
    run_dir = write_run(tmp_path, parts)
    assert assemble(run_dir, "--expect", "review-unit-01=1") == 2
    err = capsys.readouterr().err
    assert "verdict-01" in err and "--no-judge" in err
    # Named in `--expect`, the judged configuration works and the rejection is applied.
    assert assemble(run_dir, "--expect", "review-unit-01=1", "--expect", "verdict-01") == UNVERIFIED
    assert load_doc(run_dir)["findings"][0]["fp_verdict"] == "FALSE_POSITIVE"
    # And `--no-judge` still says "no judge ran", so the ghost is a warning, not a failure.
    assert assemble(run_dir, "--expect", "review-unit-01=1", "--no-judge") == UNVERIFIED


def test_a_planted_partial_directory_is_refused_up_front(tmp_path, capsys):
    """`<artifact>.partial` is a fixed path inside a directory every producing worker can
    write to, so the pre-flight covers the staging paths as well as the four DESTINATIONS: a
    planted `REPORT.sarif.partial` directory otherwise makes `write_text` raise, the rollback
    raise again, and the whole thing escape `main()` as exit 1 over a directory missing
    artifacts."""
    run_dir = write_run(
        tmp_path, {"review-unit-01": producing_part("review-unit-01", [raw_finding()])}
    )
    (run_dir / "REPORT.sarif.partial").mkdir()
    assert assemble(run_dir, "--expect", "review-unit-01=1") == 2
    err = capsys.readouterr().err
    assert "REPORT.sarif.partial is a directory" in err
    assert "NO artifact was replaced" in err


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-q"]))
