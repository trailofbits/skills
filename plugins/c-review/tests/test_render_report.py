#!/usr/bin/env python3
"""Tests for the REPORT.md renderer."""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "scripts"))

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


SATISFIED_LEDGER = {
    "checks_required": 4,
    "checks_completed": 4,
    "checks_satisfied": 4,
    "violation_count": 0,
    "missing_row_count": 0,
}


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
    # Quoted. `threat_model` reaching the frontmatter raw let a newline in it inject a
    # second `severity_filter:` ABOVE the real one, in a block whose purpose is to be read
    # by machine.
    assert 'threat_model: "REMOTE"' in out
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


def test_a_dead_review_agent_is_surfaced_as_a_warning():
    """`groups_failed` covers the class sweep only. A slice reviewer that returns nothing
    loses lines, not classes, so without its own warning a run that lost 13 of 16 reviewers
    renders exactly like a complete one."""
    out = render(doc([finding()], agent_failures=["slice-03: returned nothing"]))
    assert "## Run warnings" in out
    assert "unreviewed" in out
    assert "`slice-03: returned nothing`" in out


def test_assembler_integrity_warnings_reach_the_report_and_the_sarif():
    """A part file no rule reads is one agent's whole output dropped on the floor.

    The assembler records it, but unrendered the only trace is a stderr line nobody
    downstream reads, and a run that lost an agent's entire output produces a report
    indistinguishable from a clean one.
    """
    out = render(
        doc(
            [finding()],
            unrecognised_parts=["sweeps-classes"],
            stale_part_files=["review-unit-02"],
            incomplete_findings=["review-unit-03#1: description"],
            expectations_checked=False,
        )
    )
    assert "## Run warnings" in out
    assert "`sweeps-classes`" in out and "not in this report" in out
    assert "`review-unit-02`" in out and "earlier draft" in out
    assert "`review-unit-03#1: description`" in out
    assert "**unchecked**" in out

    texts = " ".join(
        n["message"]["text"]
        for n in build_sarif(
            doc(
                [finding()],
                unrecognised_parts=["sweeps-classes"],
                stale_part_files=["review-unit-02"],
                incomplete_findings=["review-unit-03#1: description"],
                expectations_checked=False,
            )
        )["runs"][0]["invocations"][0]["toolExecutionNotifications"]
    )
    assert "sweeps-classes" in texts
    assert "review-unit-02" in texts
    assert "missing required" in texts
    assert "expectations" in texts


def test_a_clean_assembly_adds_no_integrity_warning():
    """These must not fire on a clean run, or they stop meaning anything."""
    out = render(
        doc(
            [finding()],
            unrecognised_parts=[],
            stale_part_files=[],
            incomplete_findings=[],
            expectations_checked=True,
            ledger=SATISFIED_LEDGER,
        )
    )
    assert "## Run warnings" not in out


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
    gate = {"checks_required": 1, "checks_completed": 1, "checks_satisfied": 1}
    out = render(doc([finding()], coverage=coverage, ledger=gate))
    assert "## Coverage (self-reported)" in out
    assert "check_ledger.py" in out
    assert "src/parse.c:142" in out


def test_the_coverage_blurb_does_not_claim_an_audit_the_gate_never_ran():
    """The blurb has to be conditional on gate status.

    As a constant, on a stale-tree run line 19 of REPORT.md says "The coverage gate did not
    run, so coverage is **unmeasured**" while line 37 of the same document says
    `check_ledger.py` audits these rows against the unit parse — the opposite of the warning
    eighteen lines above it, to the reader most likely to skim straight to the table.
    """
    coverage = [{"group": "g", "bug_class": "buffer-overflow", "outcome": "reported"}]
    for ledger in ({"error": "the tree moved between the review and this gate"}, None):
        out = render(doc([finding()], coverage=coverage, ledger=ledger))
        table = out[out.index("## Coverage (self-reported)") :]
        assert "check_ledger.py audits" not in table.replace("`", ""), table
        assert "The coverage gate did not run over this document" in table, table


# ------------------------------------------------------------------ the ledger gate


def test_a_rejected_ledger_row_reaches_the_report():
    """The gate's verdict has to be in the artifact the user is handed.

    `assemble_findings` runs `check_ledger` in-process and records the result; this warning
    is the only thing downstream that reads it. Without it, a run whose only coverage claim
    the gate threw out renders identically to a clean one, under a coverage table saying no
    gate depended on those rows.
    """
    ledger = {
        "checks_required": 1,
        "checks_completed": 1,
        "checks_satisfied": 0,
        "violation_count": 1,
        "missing_row_count": 0,
        "violation_kinds": ["population-not-accounted"],
        "gap_units": [],
    }
    out = render(doc([], ledger=ledger))
    assert "## Run warnings" in out
    assert "0 of 1 required check(s) satisfied, 1 answered" in out
    assert "`population-not-accounted`" in out


def test_a_missing_ledger_row_names_its_unit():
    ledger = {
        "checks_required": 2,
        "checks_completed": 1,
        "checks_satisfied": 1,
        "violation_count": 0,
        "missing_row_count": 1,
        "violation_kinds": [],
        "gap_units": ["src/parse.c:1-40"],
    }
    out = render(doc([finding()], ledger=ledger))
    assert "1 unanswered row(s) in `src/parse.c:1-40`" in out


def test_a_full_ledger_gate_report_is_read_too():
    """`run.ledger` holds a whole `ledger-gate.json` when the assembler read one off disk
    instead of running the gate itself. Both shapes have to warn, or the fallback path is
    exactly the one that reports nothing."""
    ledger = {
        "checks_required": 1,
        "checks_completed": 1,
        "checks_satisfied": 0,
        "violations": [{"kind": "evidence-missing", "unit_id": "src/parse.c:1-40"}],
        "missing_rows": [],
    }
    out = render(doc([], ledger=ledger))
    assert "`evidence-missing`" in out


def test_a_gate_that_could_not_run_is_a_warning_not_a_silence():
    out = render(doc([finding()], ledger={"error": "units.json lists no units"}))
    assert "coverage is **unmeasured**" in out
    assert "units.json lists no units" in out


def test_an_absent_ledger_is_unmeasured_not_clean():
    """`run.ledger` is None whenever there was no `units.json` to measure against — a hand
    assembly, or a run whose enumerate step died — and the coverage section below asserts
    that `check_ledger.py` audited these rows. Silence there prints that claim over a set of
    self-reported `clean` outcomes nothing ever checked."""
    coverage = [
        {
            "group": "memory-bounds",
            "bug_class": "buffer-overflow",
            "outcome": "clean",
            "population": "31 memcpy sites",
            "evidence": "src/parse.c:142",
        }
    ]
    out = render(doc([], coverage=coverage))
    assert "## Run warnings" in out
    assert "coverage is **unmeasured**" in out


def test_the_ledger_verdict_reaches_the_sarif_too():
    """REPORT.md and REPORT.sarif have to carry the same verdict. If the gate reaches only
    the Markdown, a CI job that gates on SARIF notifications passes a run whose every
    coverage claim was rejected."""
    ledger = {
        "checks_required": 40,
        "checks_completed": 40,
        "checks_satisfied": 0,
        "violation_count": 40,
        "violation_kinds": ["evidence-missing"],
    }
    invocation = build_sarif(doc([finding()], ledger=ledger))["runs"][0]["invocations"][0]
    texts = " ".join(n["message"]["text"] for n in invocation["toolExecutionNotifications"])
    assert "0 of 40 required check(s) satisfied" in texts
    assert "evidence-missing" in texts
    assert "**" not in texts and "`" not in texts, "SARIF message.text is plain text"
    assert invocation["properties"]["checks_satisfied"] == 0
    assert invocation["properties"]["checks_required"] == 40

    # …and absent must reach it as unmeasured, not as an accepted zero.
    absent = build_sarif(doc([finding()]))["runs"][0]["invocations"][0]
    assert absent["properties"]["checks_required"] is None
    assert any("unmeasured" in n["message"]["text"] for n in absent["toolExecutionNotifications"])


def test_a_satisfied_ledger_adds_no_warning():
    """The warning must not fire on a clean gate, or it stops meaning anything."""
    out = render(doc([finding()], ledger=SATISFIED_LEDGER))
    assert "## Run warnings" not in out
    assert (
        "toolExecutionNotifications"
        not in build_sarif(doc([finding()], ledger=SATISFIED_LEDGER))["runs"][0]["invocations"][0]
    )


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
    # Both renderers go through reported_findings(). Applying the survivor/filter rules
    # separately in each is how the two drift apart.
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


def test_a_lone_surrogate_leaves_no_truncated_report_behind(tmp_path, capsys):
    """`"\\ud800"` is valid JSON; `json.loads` decodes it to a lone surrogate.

    `out.write_text(render(doc), encoding="utf-8")` then raises `UnicodeEncodeError` — a
    `ValueError` — part-way through, exiting 1 with a TRUNCATED REPORT.md on disk. The exit
    code is this CLI's own "the ledger has gaps" neighbour and the file reads as a completed
    render.
    """
    src = tmp_path / "findings.json"
    payload = json.dumps(doc([finding(description="len is " + chr(0xD800) + " unbounded")]))
    assert "\\ud800" in payload
    src.write_text(payload, encoding="utf-8")
    (tmp_path / "REPORT.md").write_text("PREVIOUS RUN\n", encoding="utf-8")

    assert main(["--findings", str(src), "--output-dir", str(tmp_path)]) == 2
    assert "UnicodeEncodeError" in capsys.readouterr().err
    assert (tmp_path / "REPORT.md").read_text(encoding="utf-8") == "PREVIOUS RUN\n"
    assert not list(tmp_path.glob("*.partial"))


def test_main_exits_non_zero_on_bad_input(tmp_path, capsys):
    src = tmp_path / "findings.json"
    src.write_text("{nope", encoding="utf-8")
    assert main(["--findings", str(src), "--output-dir", str(tmp_path)]) == 2
    assert "render_report:" in capsys.readouterr().err
    assert not (tmp_path / "REPORT.md").exists()


# ------------------------------------------------------ markdown that must not break


def test_a_code_fence_inside_the_snippet_does_not_break_out_of_the_block():
    """`code` is agent-authored free text copied out of the source.

    A three-backtick run in it closes a three-backtick block, so the `##` that follows
    becomes a real heading in REPORT.md and the Impact and Recommendation sections are
    swallowed by the orphaned fence.
    """
    md = render(doc([finding(code="int x;\n```\n## FAKE HEADING\n")]))
    lines = md.splitlines()
    open_at = lines.index("````c")
    close_at = lines.index("````", open_at)
    # The injected heading stays inside the block, and the sections after it survive.
    assert open_at < lines.index("## FAKE HEADING") < close_at
    assert "**Impact**" in md
    assert "**Recommendation**" in md


def test_a_newline_in_a_not_reported_cell_does_not_terminate_the_row():
    """A newline ends the row in Markdown: the rest renders as a paragraph and every
    subsequent row falls outside the table. Every cell is escaped, `id`/`file`/`line`/
    `verdict` included, exactly as the coverage table two blocks down does it."""
    md = render(
        doc(
            [
                finding(
                    id="BOF-001",
                    fp_verdict="FALSE_POSITIVE",
                    severity=None,
                    fp_rationale="line one\nline two | piped",
                ),
                finding(
                    id="BOF-002", fp_verdict="FALSE_POSITIVE", severity=None, fp_rationale="second"
                ),
            ]
        )
    )
    rows = [ln for ln in md.splitlines() if ln.startswith("| BOF-")]
    assert len(rows) == 2
    assert "line one line two \\| piped" in rows[0]


def test_the_severity_table_admits_unrated_findings():
    """Without an Unrated row, one reported INFO finding renders CRITICAL 0 / HIGH 0 /
    MEDIUM 0 / LOW 0 above "1 reported after…", followed by an `## Unrated (1)` section with
    no table row. A reader reconciling the two concludes a finding was lost."""
    md = render(doc([finding(severity="INFO", severity_validated=False)]))
    assert "| Unrated | 1 |" in md
    assert "## Unrated (1)" in md


FORGERY = "pwn\n\n## CRITICAL (99)\n\n### FAKE-001 — fabricated\n\n- **Location:** `a.c:1`"


@pytest.mark.parametrize(
    "field",
    [
        "title",
        "fp_rationale",
        "severity_rationale",
        "attack_vector",
        # The six largest free-text fields in the document. Raw, `description` alone can
        # produce a real severity section and a whole finding block that no agent filed.
        "description",
        "data_flow",
        "reachability",
        "impact",
        "mitigations_checked",
        "recommendation",
        # And the id, which sits between two headings beside the already-sanitised title.
        "id",
    ],
)
def test_agent_text_cannot_forge_a_heading_or_a_finding_section(field):
    """Every one of these is agent-authored free text and reaches a heading or a bullet.

    A newline ends the `### ` heading and ends the list item, so whatever follows renders
    as document-level Markdown: a real `## CRITICAL (99)` section and a fabricated finding
    under it, indistinguishable from the tool's own output.
    """
    md = render(doc([finding(**{field: FORGERY})]))
    body = md.split("## Reported findings", 1)[1]
    assert "\n## CRITICAL (99)" not in body
    assert "\n### FAKE-001" not in body
    assert "pwn" in body, "the value was dropped rather than flattened"


def test_a_finding_in_no_section_of_the_report_is_flagged():
    """`N primary … M merged … K reported` needs something checking that it adds up.

    Unchecked, a self-referential `merged_into` gives "0 primary; 0 merged; 0 reported" over
    a findings.json holding one finding, with nothing anywhere flagging it.
    """
    clean = render(doc([finding()]))
    assert "stats block says" not in clean

    document = doc([finding(), finding(id="BOF-002", merged_into="BOF-001")])
    document["stats"]["merged"] = 0  # the count and the links disagree
    assert "stats block says 0" in render(document)


def test_a_resurrected_duplicate_is_named_rather_than_reported_as_lost():
    """The one recovery path `primaries()` supports, and the one the integrity check must
    not cry wolf on — from either side.

    `primaries + merged == total` does not hold when a duplicate whose primary was judged a
    false positive is deliberately rendered on its own: it reports a finding as "in the
    document and in no section below" while both are in fact rendered. Counting
    `len(absorbed) - len(resurrected)` against `stats.merged` fails the same way in reverse,
    because `stats.merged` is `len(merged)` — one per finding carrying `merged_into`,
    resurrected or not — so the loudest integrity check in the report contradicts the
    warning one line above it and `lost_work` flips SARIF's `executionSuccessful` false over
    it. `stats.merged` here is what `assemble_findings.py` actually writes.
    """
    document = doc(
        [
            finding(id="BOF-001", fp_verdict="FALSE_POSITIVE"),
            finding(id="BOF-002", merged_into="BOF-001"),
        ]
    )
    document["stats"]["merged"] = 1
    md = render(document)
    assert "stats block says" not in md
    assert "merged into a primary that is not in the reported set" in md
    assert "### BOF-002" in md


def test_a_confirmed_finding_with_no_severity_keeps_its_body():
    """The judge said TRUE_POSITIVE and left no severity, so it lands in `## Unrated`.

    Rendering it with `embed=False` — the most truncated form available — drops `code`,
    `data_flow`, `reachability`, `impact` and `mitigations_checked` from exactly the
    findings nobody could rank.
    """
    md = render(doc([finding(severity=None, severity_validated=False)]))
    assert "## Unrated (1)" in md
    for section in ("**Code**", "**Data flow**", "**Impact**", "**Mitigations checked**"):
        assert section in md


def test_a_fence_in_a_body_cannot_swallow_the_rest_of_the_finding():
    """An unescaped three-backtick run in `description` opens a block that eats every
    section after it."""
    md = render(doc([finding(description="ok\n```\nnot code\n## CRITICAL (99)\n")]))
    assert "\n## CRITICAL (99)" not in md.split("## Reported findings", 1)[1]
    assert "**Impact**" in md, "the sections after the injected fence were swallowed"


def test_platform_evidence_and_run_warnings_cannot_forge_a_section():
    """`platform_evidence` is a whole paragraph and every warning bullet interpolates an
    agent-authored list member into `- {w}`; all of them need the block sanitiser."""
    md = render(
        doc(
            [finding()],
            platform_evidence=FORGERY,
            hunter_notes=[FORGERY],
            agent_failures=[FORGERY],
            unrecognised_parts=[FORGERY],
        )
    )
    assert "\n## CRITICAL (99)" not in md
    assert "\n### FAKE-001" not in md


def test_the_frontmatter_cannot_be_extended_by_the_threat_model():
    """The block is machine-readable (`stage: final-report`), so every value is quoted: raw,
    a newline in `threat_model` puts a second `severity_filter:` ABOVE the real one."""
    md = render(doc([finding()], threat_model="LOCAL\nseverity_filter: high\nfake_key: yes"))
    head = md.split("---", 2)[1]
    assert len(re.findall(r"^severity_filter:", head, re.M)) == 1
    assert not re.search(r"^fake_key:", head, re.M)
    assert '"LOCAL\\nseverity_filter: high\\nfake_key: yes"' in head


@pytest.mark.parametrize("field", ["file", "function", "bug_class"])
def test_a_backtick_in_a_code_span_field_cannot_close_the_span(field):
    """`_inline` collapses newlines, and leaving backticks live lets `x` **BOLD** `y` in a
    path close the code span and render the middle as emphasis."""
    md = render(doc([finding(**{field: "x` **INJECTED** `y"})]))
    # The value survives, inside its span, and cannot close it.
    assert "`x **INJECTED** y" in md
    assert "x` **INJECTED**" not in md


def test_a_bare_string_in_a_list_field_is_one_item_not_its_characters():
    """Iterated as a sequence, `also_known_as: "BOF-002"` renders as `B, O, F, -, 0, 0, 2`."""
    md = render(doc([finding(also_known_as="BOF-002")], hunter_notes="abc"))
    assert "- **Also reported as:** BOF-002" in md
    assert md.count("Reviewer note — ") == 1


@pytest.mark.parametrize("line", ["abc", -5, 10**20, None])
def test_an_unusable_line_number_is_marked_and_agrees_with_the_sarif(line):
    """Unmarked, REPORT.md prints `src/parse.c:abc` while SARIF pins the same finding at
    line 1 with nothing saying the number was invented, and `10**20` overflows int64."""
    document = doc([finding(line=line)])
    md = render(document)
    sarif = build_sarif(document)
    assert "LINE NUMBER INVENTED" in md
    start = sarif["runs"][0]["results"][0]["locations"][0]["physicalLocation"]["region"][
        "startLine"
    ]
    assert 1 <= start <= 2**31 - 1
    assert f"src/parse.c:{start}`" in md


@pytest.mark.parametrize(
    "document",
    [
        {"findings": ["oops"]},
        {"findings": [], "run": []},
        {"findings": [], "coverage": 5},
        {"findings": [], "stats": "none"},
    ],
    ids=[
        "finding-not-an-object",
        "run-not-an-object",
        "coverage-not-a-list",
        "stats-not-an-object",
    ],
)
def test_a_malformed_document_is_a_findings_error_in_both_generators(tmp_path, document, capsys):
    """`setdefault` does not overwrite a wrong-typed value, so without a type check these
    reach both CLIs as an uncaught AttributeError or TypeError — and `coverage: 5` is fatal
    to one generator and not the other, shipping REPORT.sarif with no REPORT.md."""
    path = tmp_path / "findings.json"
    path.write_text(json.dumps(document), encoding="utf-8")
    import generate_sarif

    assert main(["--findings", str(path), "--output-dir", str(tmp_path)]) == 2
    assert generate_sarif.main(["--findings", str(path), "--output-dir", str(tmp_path)]) == 2
    assert not (tmp_path / "REPORT.md").exists()
    assert not (tmp_path / "REPORT.sarif").exists()


@pytest.mark.parametrize("merged", ["three", None, [1]])
def test_a_malformed_count_degrades_the_text_rather_than_deleting_an_artifact(merged):
    """An unguarded `int(stats["merged"])` raises out of `render()` while SARIF is still
    produced — one artifact on disk without the other."""
    document = doc([finding()])
    document["stats"]["merged"] = merged
    assert "merged as duplicates" in render(document)


def test_a_validated_true_positive_with_an_unrecognised_severity_is_still_reported():
    """`severity_allowed` scoring anything outside the four spellings as 0 puts it below
    every filter INCLUDING `all`, so a judged TRUE_POSITIVE vanishes from every tier with no
    counter and no warning and surfaces only under `## Not reported`."""
    for severity in ("INFO", "HIGH ", ["HIGH"], 3):
        document = doc([finding(severity=severity, severity_validated=True)])
        assert len(reported_findings(document)) == 1, severity
    # A trailing space is the canonical spelling, not an unrated one.
    assert "## HIGH (1)" in render(doc([finding(severity="HIGH ")]))
    assert "## Unrated (1)" in render(doc([finding(severity="INFO")]))


# ------------------------------------------------- the block-level sanitiser


@pytest.mark.parametrize(
    ("body", "rendered"),
    [
        # A CommonMark setext underline needs ONE character, not three: match only
        # `-{3,}`/`={3,}` and `CRITICAL (99)\n==` renders as a real <h1> and
        # `FAKE-001 …\n--` as a real <h2> — the same forged severity section and forged
        # finding the ATX escape exists to close.
        ("ok\n\nCRITICAL (99)\n==\n\nFAKE-001 - fabricated\n--\n", "="),
        ("ok\n\nCRITICAL (99)\n=\n", "="),
        ("ok\n\nFAKE-001 - fabricated\n-\n", "-"),
        ("---\n", "-"),
        ("***\n", "*"),
        ("___\n", "_"),
        # Raw HTML survives every CommonMark renderer GitHub included, so `<h2>` is a real
        # heading and an unterminated `<!--` swallows every finding after it.
        ("<h2>CRITICAL (99)</h2>\n<!-- hide everything after\n", "<"),
        ("# heading\n", "#"),
        ("> quote\n", ">"),
        ("```\nfence\n", "`"),
        ("~~~\nfence\n", "~"),
    ],
)
def test_every_block_opener_in_a_body_is_escaped(body, rendered):
    """One case per alternation in MD_BLOCK_START.

    Mutating the pattern down to `^(\\s{0,3})(#|```)` — dropping the other six — passes the
    whole suite apart from this parametrisation, which is the only thing behind six of the
    eight branches of a security-critical sanitiser.
    """
    md = render(doc([finding(description=body)]))
    # Up to the next section label, so the report's OWN `**Code**` label and code fence are
    # not mistaken for the body's.
    section = md.split("**Description**", 1)[1].split("\n**", 1)[0]
    for line in section.splitlines():
        stripped = line.strip()
        if stripped.startswith(rendered):
            pytest.fail(f"{line!r} reached REPORT.md as a live block opener")
    assert "\\" in section, "nothing was escaped, so the assertion above is vacuous"


def test_mid_line_raw_html_is_escaped_in_bodies_and_inline_fields_but_not_code():
    """MD_BLOCK_START guards column 0 only; CommonMark inline HTML needs no column.

    Unescaped, `ok <h2>CRITICAL (99)</h2>` renders a live heading mid-paragraph and a
    terminated `<!-- … -->` hides everything between the arrows — in the six `_section`
    bodies and in every bare `_inline` field alike. `_code` values render inside
    backticks, where HTML is inert, so a C++ `foo<T>` must NOT grow a visible backslash.
    """
    md = render(
        doc(
            [
                finding(
                    description="ok <h2>CRITICAL (99)</h2> and <!-- hidden --> tail",
                    fp_rationale="benign <h2>CRITICAL (99)</h2> claim",
                    function="parse<T>",
                )
            ]
        )
    )
    live = re.compile(r"(?<!\\)<(?=[A-Za-z/!?])")
    section = md.split("**Description**", 1)[1].split("\n**", 1)[0]
    assert not live.search(section), section
    assert "\\<h2>" in section and "\\<!--" in section, section
    rationale = next(line for line in md.splitlines() if "**Verdict:**" in line)
    assert not live.search(rationale) and "\\<h2>" in rationale, rationale
    assert "`parse<T>`" in md, "a code-span value grew an escape backticks already made moot"
    """The section labels are bold paragraphs, not headings, so they are not block starts.

    A `description` ending in `**Impact**\\n\\nNone; benign.` otherwise renders a second
    Impact section ABOVE the real one, inverting the conclusion for a skimming reader and
    for any tool that splits on the label.
    """
    forged = "Not exploitable.\n\n**Impact**\n\nNone; benign.\n\n**Recommendation**\n\nNo change."
    md = render(doc([finding(description=forged)]))
    body = md.split("**Description**", 1)[1]
    assert body.count("\n**Impact**\n") == 1, "the forged Impact label rendered as a real one"
    assert body.count("\n**Recommendation**\n") == 1
    assert "None; benign." in body, "the text was dropped rather than neutralised"
    # A bold RUN inside a sentence is content and must still render.
    inline = render(doc([finding(description="**Note:** len is unbounded")]))
    assert "**Note:** len is unbounded" in inline


def test_the_platform_flags_cannot_forge_a_section():
    """`_flag` is an interpolation helper like any other, and its three inputs are copied
    verbatim out of the agent-written detect.json — validated only as "is it a dict"."""
    md = render(doc([finding()], is_cpp="x\n\n## CRITICAL (99)\n\n### FAKE-9 - forged\n\nbody"))
    assert "\n## CRITICAL (99)" not in md
    assert "\n### FAKE-9" not in md
    assert "is_cpp=x ## CRITICAL (99) ### FAKE-9 - forged body" in md


def test_the_loudest_coverage_warnings_are_asserted():
    """The two loudest lines in REPORT.md, and the only assertions behind either.

    `missing_review_parts` is the "that code was reviewed by **nobody**" warning; the
    reviewer-assigned severity caveat is the only thing in REPORT.md saying a CRITICAL was
    never independently reviewed. Both survive mutation without this test, because only the
    SARIF twin of the second is covered elsewhere.
    """
    md = render(doc([finding()], missing_review_parts=["review-unit-07"]))
    assert "reviewed by **nobody**" in md and "review-unit-07" in md

    caveat = render(doc([finding(severity_source="reviewer")]))
    assert "reviewer-assigned and unreviewed" in caveat
    assert "reviewer-assigned and unreviewed" not in render(doc([finding()]))


def test_rows_the_gate_could_not_audit_are_not_printed_as_audited():
    """The coverage table says `check_ledger.py` audits these rows against the unit parse.

    It files every sweep and invariant row as `unverifiable` precisely because sweep
    coverage is not checkable against a parse, and every bogus unit id as `unknown_units`.
    Unless both reach the artifact, twelve unaudited rows render as audited ones.
    """
    md = render(
        doc(
            [finding()],
            ledger=dict(SATISFIED_LEDGER, unverifiable_row_count=12, unknown_units=["unit-01"]),
        )
    )
    assert "12 ledger row(s) are outside the generated unit list" in md
    assert "name a unit id that is in no unit list" in md and "unit-01" in md
    assert "outside the generated unit list" not in render(doc([finding()]))


def test_an_underscore_bold_label_cannot_forge_a_section():
    """`MD_BOLD_LABEL` cannot be asterisk-only: CommonMark renders `__Impact__` as exactly
    the same `<strong>Impact</strong>` element as `**Impact**`, so a description ending in
    `__Impact__\n\nNone whatsoever` renders a second, forged Impact paragraph ABOVE the
    genuine one, and any tool splitting on bold-paragraph labels takes the first."""
    body = "benign\n\n__Impact__\n\nNone whatsoever; safe to ignore."
    out = render(doc([finding(severity="CRITICAL", description=body)]))
    assert "\n__Impact__\n" not in out, out
    assert "\\__Impact__" in out, out


@pytest.mark.parametrize("label", ["***Impact***", "___Impact___"])
def test_a_triple_marker_bold_label_cannot_forge_a_section(label):
    """`\\*\\*[^*]+\\*\\*` cannot match `***Impact***` — the inner class excludes the third
    asterisk — so CommonMark renders `<strong><em>Impact</em></strong>`, a second Impact
    label above the real one, straight through the pattern written to stop exactly that."""
    body = f"benign\n\n{label}\n\nNone whatsoever; safe to ignore."
    out = render(doc([finding(severity="CRITICAL", description=body)]))
    assert f"\n{label}\n" not in out, out
    assert "\\" + label in out, out


def test_a_findings_document_whose_coverage_rows_are_not_objects_is_refused(tmp_path):
    """`load()` has to validate the ELEMENT types of `coverage`, not only its container:
    `{"coverage": ["oops"]}` otherwise reaches `render()` as an AttributeError while
    `build_sarif()` — which never reads coverage — writes REPORT.sarif happily, leaving one
    artifact on disk without the other instead of the documented exit 2."""
    payload = {"run": {}, "stats": {}, "findings": [finding()], "coverage": ["oops"]}
    path = tmp_path / "findings.json"
    path.write_text(json.dumps(payload), encoding="utf-8")
    assert main(["--findings", str(path), "--output-dir", str(tmp_path)]) == 2
    assert not (tmp_path / "REPORT.md").exists()


def test_a_duplicate_finding_id_does_not_let_array_order_drop_a_critical():
    """A last-wins `by_id` of `{str(id): f}` lets the array ORDER decide, when two findings
    share `F1`, whether a CRITICAL merged into it is rendered or silently dropped:
    `F1(TP), F1(FP), D1` reports both, `F1(FP), F1(TP), D1` reports one."""
    tp = finding(id="F1", fp_verdict="TRUE_POSITIVE")
    fp = finding(id="F1", fp_verdict="FALSE_POSITIVE")
    dup = finding(id="D1", severity="CRITICAL", merged_into="F1")
    first = {f["id"] for f in reported_findings(doc([tp, fp, dup]))}
    second = {f["id"] for f in reported_findings(doc([fp, tp, dup]))}
    assert first == second, (first, second)
    assert "D1" in first, first


def test_an_infinity_line_does_not_delete_both_artifacts(tmp_path):
    """`json.loads` accepts the bare `Infinity` literal, and `except (TypeError, ValueError)`
    does not catch the OverflowError `int(float('inf'))` raises — so one such line in one
    finding takes out `render()` AND `build_sarif()` with a traceback, deleting every
    artifact of a completed run over a display field."""
    payload = json.loads(
        '{"run": {}, "stats": {}, "coverage": [], "findings": [{"id": "F1", '
        '"title": "t", "file": "src/a.c", "line": Infinity, "severity": "HIGH"}]}'
    )
    out = render(payload)
    assert "src/a.c:" in out
    assert build_sarif(payload)["runs"][0]["results"][0]["locations"]


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-q"]))
