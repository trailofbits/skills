#!/usr/bin/env python3
"""Tests for findings_model loading/selection and the SARIF generator."""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "scripts"))

import findings_model  # noqa: E402
import generate_sarif  # noqa: E402
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
    # Anchored: `match=` is a search over the whole message, and the message begins with
    # the path — which under tmp_path contains this test's own name, so `match="empty"`
    # passes with the guard deleted outright.
    with pytest.raises(FindingsError, match=r"is empty$"):
        load(write(tmp_path, ""))


def test_load_rejects_truncated_json(tmp_path):
    # The realistic failure: an agent transcribed the document into a heredoc and
    # it was cut short. Reporting a clean empty report here would hide the loss.
    # Same anchoring problem as above: `match="truncated"` matches the tmp_path.
    with pytest.raises(FindingsError, match=r"probably truncated or hand-edited"):
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


def test_a_dead_review_agent_becomes_a_notification():
    """A slice reviewer that dies is not a `groups_failed` entry — it loses lines, not bug
    classes — so without its own notification a run that lost most of its reviewers
    produces SARIF indistinguishable from a complete one."""
    sarif = build_sarif(doc([finding()], agent_failures=["slice-03: returned nothing"]))
    invocation = sarif["runs"][0]["invocations"][0]
    assert invocation["properties"]["agent_failures"] == ["slice-03: returned nothing"]
    assert any("slice-03" in n["message"]["text"] for n in invocation["toolExecutionNotifications"])


def test_unjudged_finding_is_marked_and_notified():
    f = finding(id="U", severity_validated=False)
    sarif = build_sarif(doc([f], unjudged_findings=["U"]))
    result = sarif["runs"][0]["results"][0]
    assert result["properties"]["severity_validated"] is False
    assert findings_model.UNVALIDATED_MARKER in result["message"]["text"]
    # Named, not merely non-empty: a bare truthiness assert here is satisfied by the
    # unrelated absent-ledger notification, so deleting the unjudged loop entirely would
    # leave the suite green.
    notes = [
        n["message"]["text"]
        for n in sarif["runs"][0]["invocations"][0]["toolExecutionNotifications"]
    ]
    assert any("Finding U reached no judge" in text for text in notes)


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


# ------------------------------------------------------- drift and lost markers


def test_rule_descriptions_cover_every_emittable_bug_class():
    """Both directions, because the table drifts silently in both.

    A class the assembler can emit but the table does not describe ships
    `shortDescription: "Oob read"` instead of a curated sentence; a description for a class
    nothing emits is dead weight nobody notices. Replacing the whole table with `{}` leaves
    the entire suite green apart from this test.
    """
    import assemble_findings

    described = set(generate_sarif.RULE_DESCRIPTIONS)
    emittable = set(assemble_findings.CLASS_PREFIXES)
    # Two empty sets are equal, so the equality below passes vacuously if the catalogue
    # is ever emptied — the exact zero-item pass this test exists to prevent.
    assert len(emittable) > 40, "the class catalogue collapsed; the check below is vacuous"
    assert described == emittable, (
        f"undescribed classes {sorted(emittable - described)}; "
        f"descriptions for classes nothing emits {sorted(described - emittable)}"
    )
    assert all(text.strip() for text in generate_sarif.RULE_DESCRIPTIONS.values())


def test_a_rule_description_is_the_curated_sentence_not_the_title_cased_id():
    sarif = build_sarif(doc([finding(bug_class="oob-read")]))
    rule = sarif["runs"][0]["tool"]["driver"]["rules"][0]
    assert rule["shortDescription"]["text"] == "Out-of-bounds read"
    assert rule["shortDescription"]["text"] != "Oob read"


def test_a_finding_with_no_location_is_marked_in_the_message_text():
    """`uri: ""` with `startLine: 1` pins the alert at the repository root.

    The marker has to be in `message.text`: a `caveats` property most consumers never read
    leaves nothing saying the location was invented, and REPORT.md renders `:10` with no
    caveat at all. This is the only assertion behind the marker branch.
    """
    sarif = build_sarif(doc([finding(file="")]))
    result = sarif["runs"][0]["results"][0]
    assert "LOCATION MISSING" in result["message"]["text"]
    assert "location missing" in result["properties"]["caveats"]


def test_sarif_says_when_no_judge_ran():
    """REPORT.md says it loudly; SARIF saying nothing lets a CI gate reading only SARIF
    ingest a reviewer-assigned CRITICAL as judge-validated."""
    sarif = build_sarif(
        doc([finding(severity="CRITICAL", severity_source="reviewer")], judge_ran=False)
    )
    invocation = sarif["runs"][0]["invocations"][0]
    assert invocation["properties"]["judge_ran"] is False
    assert any(
        "No false-positive or severity judge ran" in n["message"]["text"]
        for n in invocation["toolExecutionNotifications"]
    )
    caveats = sarif["runs"][0]["results"][0]["properties"]["caveats"]
    assert any("reviewer's own" in c for c in caveats)


def test_a_judged_true_positive_with_no_severity_is_reported_not_dropped():
    """`severity_allowed(None, "all")` is 0 >= 1, which is False, and `severity_validated` is
    absent here so the unvalidated exemption cannot apply either — leaving a confirmed true
    positive under a heading saying it was not reported."""
    document = doc(
        [
            {
                "id": "UAF-001",
                "fp_verdict": "TRUE_POSITIVE",
                "file": "src/lib.c",
                "line": 5,
                "bug_class": "use-after-free",
                "title": "uaf",
            }
        ]
    )
    assert [f["id"] for f in reported_findings(document)] == ["UAF-001"]
    assert len(build_sarif(document)["runs"][0]["results"]) == 1


def test_a_duplicate_whose_primary_was_rejected_comes_back_as_its_own_primary():
    """Skipping every `merged_into` blindly makes a TRUE_POSITIVE CRITICAL vanish from every
    artifact when the finding it was merged into is judged a false positive."""
    document = doc(
        [
            finding(
                id="DUP-A", fp_verdict="TRUE_POSITIVE", severity="CRITICAL", merged_into="DUP-B"
            ),
            finding(id="DUP-B", fp_verdict="FALSE_POSITIVE", severity=None),
        ]
    )
    assert [f["id"] for f in findings_model.primaries(document)] == ["DUP-A", "DUP-B"]
    assert [f["id"] for f in reported_findings(document)] == ["DUP-A"]


def test_a_duplicate_whose_primary_survives_is_still_skipped():
    document = doc(
        [
            finding(id="DUP-A", merged_into="DUP-B"),
            finding(id="DUP-B"),
        ]
    )
    assert [f["id"] for f in findings_model.primaries(document)] == ["DUP-B"]


def test_a_duplicate_whose_primary_is_not_in_the_document_is_still_reported():
    """The `not carriers` term, which nothing else in the suite pinned.

    `merged_into` naming an id no finding carries is a broken merge graph, and the finding
    it points at cannot represent it because it is not there. Without this term the finding
    is skipped as "already represented" and appears in NO artifact — not REPORT.md, not
    SARIF, not the reported set — which is the precise loss `primaries` was split out of
    the renderers to prevent.
    """
    document = doc([finding(id="DUP-A", severity="CRITICAL", merged_into="GHOST")])
    assert [f["id"] for f in findings_model.primaries(document)] == ["DUP-A"]
    assert [f["id"] for f in reported_findings(document)] == ["DUP-A"]
    assert [r["ruleId"] for r in build_sarif(document)["runs"][0]["results"]] == ["buffer-overflow"]


def test_the_coverage_blind_spot_reaches_both_artifacts():
    """A unit whose parse counted no site owes no row, so it is in neither the numerator
    nor the denominator — a quarter of the lines on a real tree, and `coverage_pct: 100.0`
    over the rest read identically to full coverage."""
    warnings = findings_model.ledger_warnings(
        {
            "checks_required": 4,
            "checks_completed": 4,
            "checks_satisfied": 4,
            "violation_count": 0,
            "missing_row_count": 0,
            "unquestioned_unit_count": 22,
            "unquestioned_lines": 906,
            "lines_total": 3469,
        }
    )
    assert len(warnings) == 1
    assert "22 unit(s)" in warnings[0] and "906 line(s)" in warnings[0] and "26%" in warnings[0]


def test_reviewer_notes_and_platform_evidence_reach_sarif_too():
    """`hunter_notes` is where a reviewer says which units it could not finish and which
    files it could not read.

    Carrying it in REPORT.md and not in SARIF is the artifact asymmetry `ledger_warnings`
    exists to eliminate.
    """
    sarif = build_sarif(
        doc(
            [finding()],
            hunter_notes=["review-unit-03: ran out of budget on src/big.c"],
            platform_evidence="src/net.c:12 calls socket()",
        )
    )
    invocation = sarif["runs"][0]["invocations"][0]
    notes = [n["message"]["text"] for n in invocation["toolExecutionNotifications"]]
    assert any("ran out of budget" in text for text in notes)
    assert invocation["properties"]["platform_evidence"] == "src/net.c:12 calls socket()"


def test_a_violation_count_with_no_kinds_does_not_crash_either_renderer():
    """A hand-edited or older `ledger-gate.json` — a shape the loader explicitly supports.

    `kinds` is None here, and a join over it raises an uncaught TypeError out of both
    `render()` and `build_sarif()`.
    """
    warnings = findings_model.ledger_warnings(
        {"checks_required": 3, "checks_completed": 3, "checks_satisfied": 1, "violation_count": 2}
    )
    assert len(warnings) == 1 and "2 violation(s)" in warnings[0]
    assert build_sarif(doc([finding()], ledger={"checks_required": 3, "violation_count": 2}))


# ------------------------------------- what a CI gate reads off the invocation


# A gate that accepted everything, and the ONE definition of it — `invocation()` resolves
# the name at call time, so a second binding anywhere in this file silently replaces it for
# every test above and below. Without a clean ledger `lost_work` is already true because
# `run.ledger` is absent, and every assertion below then holds whatever the term under test
# does — the vacuous-positive shape AGENTS.md calls out.
CLEAN_LEDGER = {
    "checks_required": 4,
    "checks_completed": 4,
    "checks_satisfied": 4,
    "violation_count": 0,
    "missing_row_count": 0,
}


def invocation(**run):
    run.setdefault("ledger", CLEAN_LEDGER)
    return build_sarif(doc([finding()], **run))["runs"][0]["invocations"][0]


def test_a_clean_run_is_execution_successful():
    assert invocation()["executionSuccessful"] is True


@pytest.mark.parametrize(
    "run",
    [
        {"agent_failures": ["review-unit-03: returned nothing"]},
        {"groups_failed": ["memory"]},
        {"missing_review_parts": ["review-unit-02"]},
        {"unrecognised_parts": ["notes"]},
        {"expectations_checked": False},
        {"ledger": None},
        {"ledger": {"error": "units.json is unreadable"}},
        {"ledger": dict(CLEAN_LEDGER, violation_count=3)},
        {"ledger": dict(CLEAN_LEDGER, missing_row_count=12)},
    ],
    ids=[
        "agent-failure",
        "group-failed",
        "slice-nobody-reviewed",
        "part-nothing-reads",
        "expectations-unchecked",
        "no-gate-at-all",
        "gate-could-not-run",
        "gate-found-violations",
        "gate-found-gaps",
    ],
)
def test_a_run_that_lost_work_is_not_execution_successful(run):
    """`executionSuccessful` is what a CI gate keys off.

    Hardcode it true and a run that lost whole reviewers, dropped an agent's entire part
    file, or had every coverage claim rejected reads as a clean invocation.
    """
    assert invocation(**run)["executionSuccessful"] is False


def test_the_reconciliation_warning_reaches_the_sarif_as_well_as_the_report():
    """The loudest integrity check in the report has to reach both artifacts, or a SARIF-only
    consumer reads a document whose stats and merge links disagree as a clean one."""
    document = doc([finding(), finding(id="BOF-002", merged_into="BOF-001")], ledger=CLEAN_LEDGER)
    document["stats"] = {"merged": 0}
    notes = build_sarif(document)["runs"][0]["invocations"][0]["toolExecutionNotifications"]
    assert any("stats block says 0" in n["message"]["text"] for n in notes)


def test_the_platform_flags_reach_the_sarif_and_not_only_the_report():
    """`platform_evidence` is the justification; these are the DECISIONS it justifies, and
    both have to be exported."""
    props = invocation(is_cpp=True, is_posix=False, is_windows=True, context_roots="src,include")[
        "properties"
    ]
    assert (props["is_cpp"], props["is_posix"], props["is_windows"]) == (True, False, True)
    assert props["context_roots"] == "src,include"


def test_every_result_carries_a_content_stable_fingerprint():
    """Without one, GitHub code scanning derives a fingerprint from the location, so every
    alert closes and reopens on an unrelated line shift above it."""
    result = build_sarif(doc([finding()]))["runs"][0]["results"][0]
    assert result["partialFingerprints"] == {"cReviewFindingId/v1": "BOF-001"}


def test_a_path_with_a_uri_metacharacter_is_percent_encoded():
    """Unencoded, `src/a#frag.c` parses as a fragment and the UI resolves the result to
    `src/a`."""
    result = build_sarif(doc([finding(file="src/a#frag.c")]))["runs"][0]["results"][0]
    uri = result["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]
    assert uri == "src/a%23frag.c"


def test_a_bare_string_in_a_list_field_is_one_item_not_its_characters():
    """Iterated as a sequence, `also_known_as: "BOF-002"` comes out as
    ["B","O","F","-","0","0","2"], and a list of ints raises a TypeError out of the whole
    generator."""
    sarif = build_sarif(doc([finding(also_known_as="BOF-002")], hunter_notes="abc"))
    assert sarif["runs"][0]["results"][0]["properties"]["also_known_as"] == ["BOF-002"]
    notes = sarif["runs"][0]["invocations"][0]["toolExecutionNotifications"]
    assert len([n for n in notes if "Reviewer note" in n["message"]["text"]]) == 1
    assert build_sarif(doc([finding(also_known_as=[1, 2])]))["runs"][0]["results"][0]["properties"][
        "also_known_as"
    ] == ["1", "2"]


# --------------------------------------------------- executionSuccessful and rules


@pytest.mark.parametrize(
    "run",
    [
        # Production-reachable: REPORT.md calls these findings degraded and this generator
        # already emits a warning notification for them, so the invocation must not say the
        # tool ran cleanly beside one.
        {"stale_part_files": ["review-unit-02"]},
        {"unjudged_findings": ["BOF-001"]},
        # The full `check_ledger.check` report shape `ledger_warnings` explicitly supports:
        # `violations`/`missing_rows` LISTS and no `*_count` keys at all. Read only the
        # counts and 40 violations are a clean invocation beside a notification saying 0 of
        # 40 satisfied.
        {"ledger": {"checks_required": 40, "checks_satisfied": 0, "violations": [{"kind": "x"}]}},
        {"ledger": {"checks_required": 40, "checks_satisfied": 0, "missing_rows": [{"a": 1}]}},
    ],
    ids=["stale-part", "unjudged", "violations-list", "missing-rows-list"],
)
def test_measurable_lost_work_is_never_a_successful_invocation(run):
    document = doc([finding()], **dict({"ledger": CLEAN_LEDGER}, **run))
    document["stats"] = {"merged": 0}
    invocation = build_sarif(document)["runs"][0]["invocations"][0]
    assert invocation["executionSuccessful"] is False


def test_a_clean_run_is_still_a_successful_invocation():
    """The zero-item guard on the parametrisation above: it has to be the RUN failing it."""
    clean = doc([finding()], ledger=CLEAN_LEDGER)
    clean["stats"] = {"merged": 0}
    assert build_sarif(clean)["runs"][0]["invocations"][0]["executionSuccessful"] is True


@pytest.mark.parametrize("bug_class", [None, 7, ["buffer-overflow"]])
def test_a_rule_level_matches_its_own_results(bug_class):
    """`classes` is built from `str(bug_class)`, so the level loop must compare that too.

    Comparing the RAW value matches nothing, and the rule keeps the `note` floor while its
    own result carries `error`: two levels for one rule, out of one document.
    """
    sarif = build_sarif(doc([finding(bug_class=bug_class, severity="CRITICAL")]))
    rule = sarif["runs"][0]["tool"]["driver"]["rules"][0]
    result = sarif["runs"][0]["results"][0]
    assert rule["id"] == result["ruleId"]
    assert rule["defaultConfiguration"]["level"] == result["level"] == "error"


def test_the_severity_and_line_caveats_are_asserted():
    """These two caveats are the only thing telling a SARIF consumer that a number in the
    result was not assigned by anybody, and this is the only assertion behind either."""

    def caveats(f):
        return build_sarif(doc([f]))["runs"][0]["results"][0]["properties"]["caveats"]

    assert "severity not judge-validated" in caveats(finding(severity_validated=False))
    # `line_invented` is the assembler's record that it had to put a number here: `line`
    # itself is coerced to a usable int before anything reads it, so without the flag an
    # invented 1 and a real line 1 are the same value and this caveat could never fire.
    assert "line number was not usable and has been replaced" in caveats(
        finding(line=1, line_invented=True)
    )
    assert caveats(finding()) == []


def test_incomplete_findings_alone_fails_the_invocation():
    """The `incomplete_findings` term of `lost_work` could be deleted with the suite green."""
    doc_ = doc([finding()], ledger=CLEAN_LEDGER, incomplete_findings=["review-unit-01#0 (impact)"])
    doc_["stats"] = {"merged": 0}
    assert build_sarif(doc_)["runs"][0]["invocations"][0]["executionSuccessful"] is False


def test_a_gate_that_rejected_rows_without_counting_a_violation_is_not_a_success():
    """`checks_satisfied < checks_completed` is the THIRD rejection condition
    `findings_model.ledger_warnings` reports, alongside `violation_count`,
    `missing_row_count`, `violations` and `missing_rows`. Miss it and a ledger of
    `{required: 5, completed: 5, satisfied: 2}` gives `executionSuccessful: true` beside a
    notification saying the gate rejected the run, and a CI gate keying off it passes.
    """
    ledger = {
        "checks_required": 5,
        "checks_completed": 5,
        "checks_satisfied": 2,
        "violation_count": 0,
        "missing_row_count": 0,
    }
    inv = invocation(ledger=ledger)
    assert inv["executionSuccessful"] is False
    assert any("rejected" in n["message"]["text"] for n in inv["toolExecutionNotifications"])


def test_a_row_naming_a_unit_that_is_in_no_unit_list_is_not_a_success():
    """`run.ledger.unknown_units` is the same kind of rejection: ignore it and the
    notification says the rows account for nothing while the invocation says the run
    succeeded."""
    inv = invocation(ledger={**CLEAN_LEDGER, "unknown_units": ["review-01: unit-01"]})
    assert inv["executionSuccessful"] is False


def test_the_unknown_unit_warning_reports_the_whole_count_not_the_truncated_sample():
    """`check_ledger._summary` caps `unknown_units` at ten ids, so a warning counting the
    LIST reports 25 fabricated unit ids to REPORT.md and SARIF as 10. The two warnings above
    it go through `_count`, which has a count-key fallback; this one needs
    `unknown_unit_count` read explicitly."""
    ledger = {
        **CLEAN_LEDGER,
        "unknown_units": [f"review-01: ghost-{n}" for n in range(10)],
        "unknown_unit_count": 25,
    }
    text = " ".join(
        n["message"]["text"] for n in invocation(ledger=ledger)["toolExecutionNotifications"]
    )
    assert "25 ledger row(s) name a unit id" in text, text


def test_an_incomplete_findings_count_that_is_not_a_list_does_not_delete_this_artifact():
    """`len(run['incomplete_findings'])` on a truthy non-list raises a TypeError out of THIS
    generator while `render()` — which reads the same field through its own `_items` — writes
    REPORT.md happily. One artifact on disk without the other is the exact outcome
    `findings_model.load` exists to turn into a clean exit 2."""
    inv = invocation(incomplete_findings=5)
    assert inv["executionSuccessful"] is False
    assert any(
        "missing required" in n["message"]["text"] for n in inv["toolExecutionNotifications"]
    )


def test_an_infinity_literal_in_a_count_does_not_delete_both_artifacts():
    """`json.loads` accepts the bare `Infinity` literal and `int(float('inf'))` raises
    OverflowError, which `except (TypeError, ValueError)` does not catch — so one `Infinity`
    in `ledger.checks_required` takes out both generators with a traceback, over a field
    `as_int`'s docstring promises can never raise."""
    payload = json.loads(
        '{"checks_required": Infinity, "checks_completed": 1, '
        '"checks_satisfied": 1, "violation_count": 0, "missing_row_count": 0}'
    )
    assert build_sarif(doc([finding()], ledger=payload))["runs"][0]["invocations"]


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-q"]))
