#!/usr/bin/env python3
"""Tests for the Wilson (Claude Code plugin) `final_report.json` converter.

Fixtures are hand-written to match the real shape `final_report.json` has, per
`skills-internal/plugins/wilson/scripts/export_reports.py::normalize_finding()` and the
JSON Schemas beside it — not the standalone `tob/wilson` CLI's schema, which is a
different artifact entirely. No corpus is unsealed and `bench.py` is never invoked;
`lib.result.validate_findings`/`normalise_generic` are imported directly to prove real
interop with the harness's own schema check, which is the thing this converter's output
actually has to survive.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))

from lib import result as result_mod  # noqa: E402
from lib import wilson_result  # noqa: E402


def _evidence(path=None, line_start=None, line_end=None, snippet=None, kind="code"):
    return {
        "type": kind,
        "reasoning": "why this evidence supports the finding",
        "path": path,
        "line_start": line_start,
        "line_end": line_end,
        "snippet": snippet,
    }


def _finding(**overrides):
    base = {
        "id": "VULN-buffer-overflow",
        "title": "Buffer Overflow in Header Parser via Oversized Length Field",
        "description": "The parser copies attacker-controlled bytes into a fixed buffer.",
        "severity": "High",
        "confidence": 82,
        "proof_strength": "strong",
        "priority_score": 9.1,
        "priority_band": "P1",
        "hunter_name": "hunt-appsec-taossa",
        "canonical_source_ids": ["TAOSSA-1-1"],
        "severity_source": "judge_adjusted",
        "confidence_source": "judge",
        "upgrade_rationale": "none",
        "assumptions_required": [],
        "blocking_controls_checked": ["length is validated against a max before the memcpy"],
        "missing_evidence": [],
        "attack_vector": "any caller of parse_header() with attacker-controlled bytes",
        "exploit_scenario": "Send a header whose length field exceeds the 64-byte buffer; "
        "the unchecked memcpy overflows onto the saved return address.",
        "impact": "Remote code execution in the parsing process.",
        "evidence": [
            _evidence(path="src/parse.c", line_start=120, line_end=126, snippet="memcpy(...)")
        ],
    }
    base.update(overrides)
    return base


def _report(findings):
    return {
        "metadata": {
            "pipeline_version": "skill-2.3",
            "generated_at": "2026-08-01T00:00:00+00:00",
            "output_path": ".bughunt/run_001",
            "confidence_threshold": 50,
            "composition_coverage_reduced": False,
        },
        "summary": {
            "total_found": len(findings),
            "total_valid": len(findings),
            "by_severity": {"High": 0, "Medium": 0, "Low": 0, "Informational": 0},
        },
        "findings": findings,
    }


# ------------------------------------------------- realistic multi-finding fixture


def test_realistic_multi_finding_report_converts_and_validates():
    report = _report(
        [
            _finding(id="VULN-1", title="Buffer overflow in header parser"),
            _finding(
                id="VULN-2",
                title="Integer overflow in size calculation",
                severity="Medium",
                confidence=61,
                hunter_name="hunt-appsec-static",
                evidence=[_evidence(path="src/alloc.c", line_start=44, line_end=44)],
            ),
        ]
    )

    converted = wilson_result.convert_report(report)

    assert converted["wilson_conversion"] == {
        "input_findings": 2,
        "converted_findings": 2,
        "skipped_unparseable": 0,
        "with_location": 2,
        "without_location": 0,
    }
    first, second = converted["findings"]
    assert first["file"] == "src/parse.c"
    assert first["line"] == 120
    assert first["found_by"] == "hunt-appsec-taossa"
    assert first["confidence"] == 82
    assert first["severity"] == "High"
    assert first["wilson_has_location"] is True
    assert second["file"] == "src/alloc.c"
    assert second["line"] == 44

    # This is the real thing the converter's output has to survive: lib/result.py's own
    # schema check, unmodified, on findings that came from an arm other than c-review.
    normalised = result_mod.normalise_generic(converted)
    result_mod.validate_findings(normalised["findings"])


# ------------------------------------------------- location only in evidence[]


def test_location_only_in_evidence_is_extracted():
    finding = _finding(id="VULN-ev-only", evidence=[_evidence(path="lib/decode.c", line_start=301)])
    report = _report([finding])

    converted = wilson_result.convert_report(report)

    [out] = converted["findings"]
    assert out["file"] == "lib/decode.c"
    assert out["line"] == 301
    assert out["wilson_has_location"] is True
    assert converted["wilson_conversion"]["with_location"] == 1


def test_evidence_with_path_but_no_line_is_not_a_location():
    """A path with no line is not enough: pairing a placeholder line with a real file
    would be indistinguishable from a genuine claim once graded, which is exactly what
    the converter must not do."""
    finding = _finding(
        id="VULN-partial",
        evidence=[_evidence(path="src/parse.c", line_start=None)],
    )
    report = _report([finding])

    converted = wilson_result.convert_report(report)

    [out] = converted["findings"]
    assert out["wilson_has_location"] is False
    assert out["file"] == wilson_result.NO_LOCATION_FILE_MARKER


# ------------------------------------------------- no location at all


def test_finding_with_no_location_gets_a_marker_not_a_guess():
    finding = _finding(id="VULN-no-loc", evidence=[])
    report = _report([finding])

    converted = wilson_result.convert_report(report)

    [out] = converted["findings"]
    assert out["wilson_has_location"] is False
    assert out["file"] == wilson_result.NO_LOCATION_FILE_MARKER
    assert out["line"] == wilson_result.NO_LOCATION_LINE
    assert converted["wilson_conversion"]["without_location"] == 1

    # The marker must still satisfy lib/result.py's own schema check (non-empty file,
    # non-empty description, line >= 1) -- it is a real, gradeable finding that simply
    # can never match a site, not a dropped one.
    normalised = result_mod.normalise_generic(converted)
    result_mod.validate_findings(normalised["findings"])

    # And it must be structurally unable to match any real corpus file: file_matches is
    # a suffix match on path segments, so the marker cannot collide with a real path.
    from lib import grade

    assert grade.file_matches(out["file"], "src/parse.c") is False


# ------------------------------------------------- exploit_scenario / attack_vector fold-in


def test_exploit_scenario_and_attack_vector_are_folded_into_description():
    finding = _finding(
        description="Short description with no mechanism detail.",
        attack_vector="any caller of parse_header() with attacker-controlled bytes",
        exploit_scenario="Send a header whose length field exceeds the 64-byte buffer; "
        "the unchecked memcpy overflows onto the saved return address.",
    )
    report = _report([finding])

    converted = wilson_result.convert_report(report)

    [out] = converted["findings"]
    # TEXT_FIELDS is what lib/grade.py's mechanism_matches() actually scans; description
    # is in it, attack_vector/exploit_scenario are not, so this is the field that must
    # carry them for keyword matching to see them at all.
    from lib import grade

    assert "description" in grade.TEXT_FIELDS
    assert "attack_vector" not in grade.TEXT_FIELDS
    assert "exploit_scenario" not in grade.TEXT_FIELDS
    text = grade.finding_text(out)
    assert "memcpy overflows onto the saved return address" in text
    assert "parse_header()" in text
    assert "short description with no mechanism detail" in text


# ------------------------------------------------- zero-item guard


def test_empty_findings_is_a_legitimate_clean_result():
    report = _report([])

    converted = wilson_result.convert_report(report)

    assert converted["findings"] == []
    assert converted["wilson_conversion"]["input_findings"] == 0
    assert converted["wilson_conversion"]["converted_findings"] == 0


def test_all_entries_unparseable_from_nonempty_input_is_an_error():
    report = _report(["not-a-finding-object", 42, None])

    with pytest.raises(wilson_result.WilsonConvertError, match="0 converted"):
        wilson_result.convert_report(report)


def test_missing_findings_key_is_an_error():
    with pytest.raises(wilson_result.WilsonConvertError, match="no 'findings' key"):
        wilson_result.convert_report({"metadata": {}})


def test_findings_not_a_list_is_an_error():
    with pytest.raises(wilson_result.WilsonConvertError, match="expected a list"):
        wilson_result.convert_report({"findings": {"oops": "dict, not list"}})


# ------------------------------------------------- mitigations_checked mapping


def test_blocking_controls_checked_maps_to_mitigations_checked():
    finding = _finding(blocking_controls_checked=["input length is bounds-checked before the copy"])
    report = _report([finding])

    converted = wilson_result.convert_report(report)

    [out] = converted["findings"]
    assert "bounds-checked" in out["mitigations_checked"]
