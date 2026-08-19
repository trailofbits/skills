#!/usr/bin/env python3
"""Tests for the ground-truth grader.

Two of these are the controls the harness is judged by:

- `test_positive_control_perfect_run_scores_full_recall` — a synthetic run that
  describes every injected bug correctly must score 100%. If a `mechanism_all_of`
  group stops matching a correct description, this fails instead of every future
  run quietly scoring lower.
- `test_negative_control_right_site_wrong_mechanism_scores_zero` — findings in the
  right files, in the right functions, describing something else entirely must score
  0%. Without this, file-level proximity would pass for a hit and every arm would
  look competent.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))

from lib import grade  # noqa: E402

FIXTURES = HERE / "fixtures"


def load(name):
    return json.loads((FIXTURES / name).read_text(encoding="utf-8"))


@pytest.fixture
def gt():
    return load("gt_demo.json")


def arm(name, **extra):
    doc = load(name)
    doc.update({"arm": "bare", "corpus": "demo", "variant": "bench", **extra})
    return doc


def outcomes(scored):
    return {row["id"]: row["outcome"] for row in scored["results"]}


# ------------------------------------------------------------------- controls


def test_positive_control_perfect_run_scores_full_recall(gt):
    scored = grade.grade(arm("result_perfect.json"), gt)
    assert scored["hits"] == 3, outcomes(scored)
    assert scored["recall"] == 1.0
    assert set(outcomes(scored).values()) == {grade.HIT}


def test_negative_control_right_site_wrong_mechanism_scores_zero(gt):
    scored = grade.grade(arm("result_wrong_mechanism.json"), gt)
    assert scored["hits"] == 0
    assert scored["recall"] == 0.0
    assert set(outcomes(scored).values()) == {grade.NEAR_MISS}


# --------------------------------------------------------------------- guards


def test_zero_findings_is_refused_not_scored(gt):
    with pytest.raises(grade.GradeError, match="zero findings"):
        grade.grade({"arm": "bare", "corpus": "demo", "findings": []}, gt)


def test_zero_ground_truth_items_is_refused(gt):
    gt["items"] = []
    with pytest.raises(grade.GradeError, match="zero items"):
        grade.grade(arm("result_perfect.json"), gt)


# ------------------------------------------------------------------- outcomes


def test_found_then_dropped_is_suppressed_not_missed(gt):
    scored = grade.grade(arm("result_suppressed.json"), gt)
    assert outcomes(scored) == {"D-1": grade.HIT, "D-2": grade.SUPPRESSED, "D-3": grade.SUPPRESSED}
    assert scored["hits"] == 1
    assert scored["suppressed"] == 2


def test_wrong_file_is_a_miss_even_with_the_right_mechanism(gt):
    doc = arm("result_perfect.json")
    doc["findings"][0]["file"] = "src/unrelated.c"
    assert outcomes(grade.grade(doc, gt))["D-1"] == grade.MISS


def test_wrong_function_and_distant_line_is_a_miss(gt):
    doc = arm("result_perfect.json")
    doc["findings"][1]["function"] = "some_helper"
    doc["findings"][1]["line"] = 999
    assert outcomes(grade.grade(doc, gt))["D-2"] == grade.MISS


def test_line_window_is_the_fallback_when_no_function_is_named(gt):
    doc = arm("result_perfect.json")
    doc["findings"][1]["function"] = ""
    doc["findings"][1]["line"] = 88  # within the 12-line window of 80
    assert outcomes(grade.grade(doc, gt))["D-2"] == grade.HIT


def test_line_outside_the_window_does_not_match(gt):
    doc = arm("result_perfect.json")
    doc["findings"][1]["function"] = ""
    doc["findings"][1]["line"] = 200
    assert outcomes(grade.grade(doc, gt))["D-2"] == grade.MISS


def test_path_matching_is_segment_anchored():
    assert grade.file_matches("expat/lib/x.c", "lib/x.c")
    assert grade.file_matches("./src/a.c", "src/a.c")
    assert not grade.file_matches("otherlib/x.c", "lib/x.c")
    assert not grade.file_matches("", "lib/x.c")


# -------------------------------------------------------------- false positives


def test_a_finding_at_a_decoy_is_a_certain_false_positive(gt):
    scored = grade.grade(arm("result_wrong_mechanism.json"), gt)
    decoys = scored["false_positives"][grade.DECOY_FP]
    assert [d["decoy"] for d in decoys] == ["DEC-1"]
    assert decoys[0]["decoy_kind"] == "extra-init"


def test_a_finding_that_matched_a_bug_is_not_also_charged_as_a_decoy(gt):
    # The decoy sits in a different function from every bug, but a finding can still
    # fall inside the line window of both. A correct finding must never be counted as
    # a false positive as well.
    gt["decoys"][0]["line"] = 40
    gt["decoys"][0]["function"] = "parse_header"
    scored = grade.grade(arm("result_perfect.json"), gt)
    assert scored["hits"] == 3
    assert scored["false_positives"][grade.DECOY_FP] == []


def test_a_second_report_of_the_same_bug_is_not_counted_as_unmatched(gt):
    # Found on the first real run: an arm filed three bugs twice, and the duplicates
    # were reported as findings needing triage.
    doc = arm("result_perfect.json")
    duplicate = dict(doc["findings"][0])
    duplicate["id"] = "F-1b"
    doc["findings"].append(duplicate)
    scored = grade.grade(doc, gt)
    assert scored["hits"] == 3
    assert scored["false_positives"][grade.UNMATCHED] == []


def test_a_real_finding_at_a_decoy_site_is_not_charged_as_a_decoy(gt):
    # Also from the real run: a genuine key-disclosure finding shared a function with a
    # widened-type decoy and was billed for a decoy it never mentioned.
    gt["decoys"] = [
        {
            "id": "DEC-2",
            "decoy_kind": "widened-type",
            "file": "src/c.c",
            "line": 12,
            "function": "join_path",
            "safe_because": "a wider local cannot narrow any value it holds, so nothing changes",
        }
    ]
    doc = {
        "arm": "bare",
        "corpus": "demo",
        "variant": "bench",
        "findings": [
            {
                "id": "F-1",
                "file": "src/a.c",
                "line": 41,
                "function": "decode_value",
                "title": "Out-of-bounds write",
                "description": (
                    "value_len is unchecked so the memcpy overruns the destination buffer"
                ),
            },
            {
                "id": "F-2",
                "file": "src/c.c",
                "line": 12,
                "function": "join_path",
                "title": "The separator check is missing entirely",
                "description": "a scope carrying the delimiter makes the joined path ambiguous",
            },
        ],
    }
    scored = grade.grade(doc, gt)
    assert scored["false_positives"][grade.DECOY_FP] == []
    assert scored["hits"] == 2


def test_a_finding_that_does_claim_the_decoy_is_charged(gt):
    # DEC-1 lives in parse_header, which holds no bug — the arrangement the gate
    # enforces. A finding there that describes the mutation is a decoy hit.
    doc = {
        "arm": "bare",
        "corpus": "demo",
        "variant": "bench",
        "findings": [
            {
                "id": "F-9",
                "file": "src/a.c",
                "line": 10,
                "function": "parse_header",
                "title": "Dead store",
                "description": "the initialiser is redundant because the value is overwritten",
            }
        ],
    }
    scored = grade.grade(doc, gt)
    assert [d["decoy"] for d in scored["false_positives"][grade.DECOY_FP]] == ["DEC-1"]


def test_a_known_corpus_weakness_is_neither_a_hit_nor_a_false_positive(gt):
    doc = {
        "arm": "bare",
        "corpus": "demo",
        "variant": "bench",
        "findings": [
            {
                "id": "F-1",
                "file": "src/a.c",
                "line": 41,
                "function": "decode_value",
                "title": "Out-of-bounds write",
                "description": (
                    "value_len is unchecked so the memcpy overruns the destination buffer"
                ),
            },
            {
                "id": "F-7",
                "file": "src/b.c",
                "line": 5,
                "function": "helper_hash",
                "title": "The toy hash leaks its key",
                "description": "an empty message returns the key unchanged",
            },
        ],
    }
    scored = grade.grade(doc, gt)
    assert [e["finding"] for e in scored["false_positives"][grade.KNOWN_EXTRA]] == ["F-7"]
    assert scored["false_positives"][grade.UNMATCHED] == []
    assert "known extra" in grade.format_grade(scored)


def test_unmatched_findings_are_counted_but_not_called_false_positives(gt):
    doc = arm("result_perfect.json")
    doc["findings"].append(
        {
            "id": "F-9",
            "file": "src/z.c",
            "line": 5,
            "function": "helper",
            "title": "A real bug nobody injected",
            "description": "the base code may hold its own bugs",
        }
    )
    scored = grade.grade(doc, gt)
    assert scored["false_positives"][grade.UNMATCHED] == ["F-9"]
    assert scored["false_positives"][grade.DECOY_FP] == []
    assert scored["hits"] == 3


def test_control_variant_turns_every_claim_into_a_false_positive(gt):
    gt["variant"] = "control"
    for item in gt["items"]:
        item["present"] = False
    scored = grade.grade(arm("result_perfect.json", variant="control"), gt)
    assert scored["bugs_present"] is False
    assert scored["recall"] is None
    assert len(scored["false_positives"][grade.CONTROL_FP]) == 3


def test_a_control_claim_the_arm_itself_dropped_is_not_a_false_positive(gt):
    """Same rule as the decoy scan: only findings the arm REPORTED can be false positives.

    `report.py` adds DECOY_FP and CONTROL_FP into one precision number, so the two have to
    count the same thing. Charging a suppressed candidate here while exempting it at a decoy
    penalised exactly the multi-stage arms that filter their own output, against a
    single-shot arm that has no suppressed candidates to be charged for.
    """
    gt["variant"] = "control"
    for item in gt["items"]:
        item["present"] = False
    doc = arm("result_perfect.json", variant="control")
    for finding in doc["findings"]:
        finding["reported"] = False
    scored = grade.grade(doc, gt)
    assert scored["false_positives"][grade.CONTROL_FP] == []
    # Not discarded, just not charged: the rows still print, as FP_DROPPED.
    assert scored["suppressed"] == 3
    assert "FP_DROPPED" in grade.format_grade(scored)


def test_the_control_table_relabels_outcomes_so_a_claim_reads_as_a_claim(gt):
    gt["variant"] = "control"
    for item in gt["items"]:
        item["present"] = False
    text = grade.format_grade(grade.grade(arm("result_perfect.json", variant="control"), gt))
    assert "FP_CLAIMED" in text
    assert "HIT" not in text
    assert "patched control" in text


def test_a_cve_citation_is_recorded_as_a_canary(gt):
    scored = grade.grade(arm("result_canary.json"), gt)
    assert scored["canary_cve_citations"][0]["cves"] == ["CVE-2022-25315"]


# ------------------------------------------------------------------ breakdowns


def test_breakdowns_cover_every_class_and_tier(gt):
    scored = grade.grade(arm("result_suppressed.json"), gt)
    assert scored["by_difficulty"] == {
        "EASY": {"total": 1, "hits": 1, "suppressed": 0, "near": 0, "ambiguous": 0},
        "MEDIUM": {"total": 1, "hits": 0, "suppressed": 1, "near": 0, "ambiguous": 0},
        "HARD": {"total": 1, "hits": 0, "suppressed": 1, "near": 0, "ambiguous": 0},
    }
    assert set(scored["by_class"]) == {"buffer-overflow", "use-after-free", "delimiter-injection"}


def test_report_text_names_the_controls_and_the_canary(gt):
    text = grade.format_grade(grade.grade(arm("result_canary.json"), gt))
    assert "recall: 3/3" in text
    assert "CANARY" in text
    assert "by difficulty: EASY 1/1" in text


# ------------------------------------------------- regressions found by validation
#
# Every test below is named after a defect that was live in the shipped harness and
# that produced a plausible wrong number rather than an error.


def _colocated(gt):
    """Put a second bug in the same function as D-1, the way real corpora do.

    Four of `sigil`'s seventeen bugs share a function with another, and four of
    `zstream`'s fifteen share `inflate()`. That is the configuration in which one
    finding is graded against two bugs.
    """
    twin = json.loads(json.dumps(gt["items"][0]))
    twin.update(
        {
            "id": "D-1B",
            "bug_class": "off-by-one",
            "difficulty": "EASY",
            "line": 44,
            "mechanism": (
                "The name bound is off by one so the terminator lands one byte past the array."
            ),
            "mechanism_all_of": [["off-by-one", "one byte past"], ["name_len", "terminator"]],
        }
    )
    gt["items"].append(twin)
    return gt


def test_one_finding_is_not_the_sole_evidence_for_two_bugs(gt):
    """Demonstrated on the shipped corpus: deleting the only finding that described
    `SGL-B12` left it scored HIT on a finding about `SGL-B17` eleven lines away."""
    gt = _colocated(gt)
    doc = arm("result_perfect.json")
    # One finding whose prose satisfies both bugs' keyword groups at the shared site.
    doc["findings"] = [
        {
            "id": "F-1",
            "file": "src/a.c",
            "line": 41,
            "function": "decode_value",
            "title": "memcpy overrun",
            "description": (
                "value_len is unchecked so memcpy overruns the buffer; the terminator for "
                "name_len also lands one byte past the array"
            ),
        }
    ]
    scored = grade.grade(doc, gt)
    got = outcomes(scored)
    assert sorted([got["D-1"], got["D-1B"]]) == [grade.AMBIGUOUS, grade.HIT], got
    assert scored["hits"] == 1
    assert scored["ambiguous"] == 1
    assert "AMBIGUOUS" in grade.format_grade(scored)


def test_a_bug_with_its_own_second_finding_keeps_its_hit(gt):
    """The ambiguity rule must not cost a run a bug that two findings both describe."""
    gt = _colocated(gt)
    doc = arm("result_perfect.json")
    doc["findings"] = [
        {
            "id": "F-1",
            "file": "src/a.c",
            "line": 41,
            "function": "decode_value",
            "title": "memcpy overrun",
            "description": (
                "value_len is unchecked so memcpy overruns the buffer; the terminator for "
                "name_len also lands one byte past the array"
            ),
        },
        {
            "id": "F-2",
            "file": "src/a.c",
            "line": 44,
            "function": "decode_value",
            "title": "off-by-one on the name",
            "description": "name_len may equal the max, so the terminator is one byte past it",
        },
    ]
    scored = grade.grade(doc, gt)
    assert outcomes(scored)["D-1"] == grade.HIT
    assert outcomes(scored)["D-1B"] == grade.HIT
    assert scored["ambiguous"] == 0


def test_evidence_is_the_finding_that_describes_the_bug_not_the_first_in_the_file(gt):
    """Both real runs attributed a bug to a finding about a different bug, because the
    evidence was `hits[0]` in file order."""
    gt = _colocated(gt)
    doc = arm("result_perfect.json")
    doc["findings"] = [
        {
            "id": "F-1",
            "file": "src/a.c",
            "line": 41,
            "function": "decode_value",
            "title": "both",
            "description": (
                "value_len is unchecked so memcpy overruns the buffer; the terminator for "
                "name_len also lands one byte past the array"
            ),
        },
        {
            "id": "F-2",
            "file": "src/a.c",
            "line": 44,
            "function": "decode_value",
            "title": "off-by-one only",
            "description": "name_len may equal the max, so the terminator is one byte past it",
        },
    ]
    rows = {r["id"]: r for r in grade.grade(doc, gt)["results"]}
    # F-2 matches only D-1B, so it is the better evidence for D-1B even though F-1
    # comes first and also matches.
    assert rows["D-1B"]["evidence"]["id"] == "F-2"
    assert rows["D-1"]["evidence"]["id"] == "F-1"


def test_a_cross_function_line_window_match_is_labelled_as_one(gt):
    """`tags_equal` (SGL-B13) and `tag_check` (SGL-B14) are ten lines apart in different
    functions, so every finding naming one lands at the other's site by window. The match
    is still allowed — the documented rule is an inclusive OR — but it must not be
    indistinguishable from a function-name match."""
    doc = arm("result_perfect.json")
    doc["findings"][1]["function"] = "a_neighbouring_function"
    doc["findings"][1]["line"] = 84  # within 12 of D-2's line 80
    rows = {r["id"]: r for r in grade.grade(doc, gt)["results"]}
    assert rows["D-2"]["outcome"] == grade.HIT
    assert rows["D-2"]["evidence"]["site_kind"] == grade.SITE_LINE_CROSS_FUNCTION
    assert "not index_record" in rows["D-2"]["evidence"]["site"]


def test_an_item_with_no_mechanism_groups_is_refused(gt):
    """`all()` over an empty group list is True, which would turn every finding merely
    near the site into a HIT — the grader's own rule is that proximity is not a hit."""
    gt["items"][0]["mechanism_all_of"] = []
    with pytest.raises(grade.GradeError, match="no mechanism_all_of groups"):
        grade.grade(arm("result_perfect.json"), gt)


def test_a_ground_truth_with_no_decoys_is_refused(gt):
    """Zero decoys inspected reads identically to an arm that fell for none of them."""
    gt["decoys"] = []
    with pytest.raises(grade.GradeError, match="zero decoys"):
        grade.grade(arm("result_perfect.json"), gt)


def test_generic_ordering_words_no_longer_claim_the_reordered_decoy(gt):
    """`DECOY_CLAIM_TERMS['reordered-independent']` used to be ['order', 'reorder',
    'sequence', 'before', 'after'] -- ordinary English that shows up in almost any
    use-after-free description. A correct, unrelated use-after-free finding that merely
    uses the word "after" must not be charged as having claimed this decoy."""
    gt["decoys"][0]["decoy_kind"] = "reordered-independent"
    doc = {
        "arm": "bare",
        "corpus": "demo",
        "variant": "bench",
        "findings": [
            {
                "id": "F-9",
                "file": "src/a.c",
                "line": 10,
                "function": "parse_header",
                "title": "Use-after-free of the parsed header",
                "description": ("the header struct is freed and then read again after being freed"),
            }
        ],
    }
    scored = grade.grade(doc, gt)
    assert scored["false_positives"][grade.DECOY_FP] == []


def test_a_finding_that_names_the_reordering_still_claims_the_decoy(gt):
    """The tightened term list must still catch a finding that genuinely describes the
    reordering mutation, or the decoy costs nothing."""
    gt["decoys"][0]["decoy_kind"] = "reordered-independent"
    doc = {
        "arm": "bare",
        "corpus": "demo",
        "variant": "bench",
        "findings": [
            {
                "id": "F-9",
                "file": "src/a.c",
                "line": 10,
                "function": "parse_header",
                "title": "Statements reordered",
                "description": "these two independent statements were reordered",
            }
        ],
    }
    scored = grade.grade(doc, gt)
    assert [d["decoy"] for d in scored["false_positives"][grade.DECOY_FP]] == ["DEC-1"]


def test_decoy_attribution_uses_a_narrower_window_than_hit_attribution(gt):
    """A decoy always records its own function (the recipe validator requires it), so a
    claim that gives no function name and only a line ten lines away is weak evidence it
    is about the decoy rather than something else in a different function. Before this
    fix, decoys used the same ±12 bug window and this finding was charged."""
    doc = {
        "arm": "bare",
        "corpus": "demo",
        "variant": "bench",
        "findings": [
            {
                "id": "F-9",
                "file": "src/a.c",
                "line": 20,
                "function": "",
                "title": "Unused value written",
                "description": "this initializer produces an unused value on every path",
            }
        ],
    }
    scored = grade.grade(doc, gt)
    assert scored["false_positives"][grade.DECOY_FP] == []


def test_double_free_mechanism_accepts_use_after_free_phrasing(gt):
    """`SGL-B11`'s mechanism_all_of demanded the literal phrase "double free", so a
    correct finding calling the same defect a use-after-free scored NEAR_MISS. The
    synonym table now credits UAF vocabulary for a bug_class == "double-free" item."""
    gt["items"][0]["bug_class"] = "double-free"
    gt["items"][0]["mechanism_all_of"] = [["double free"], ["record_cache"]]
    doc = arm("result_perfect.json")
    doc["findings"][0]["description"] = (
        "record_cache's pointer is freed twice on the error path; describing it as a "
        "use-after-free is the same defect"
    )
    scored = grade.grade(doc, gt)
    assert outcomes(scored)["D-1"] == grade.HIT


def test_double_free_synonym_is_scoped_to_the_double_free_bug_class(gt):
    """The widened equivalence must not leak to other bug classes: a use-after-free
    finding cannot borrow the synonym to satisfy an unrelated bug's literal "double
    free" requirement. Proximity plus borrowed vocabulary still must not manufacture a
    hit -- the mechanism test stays strict everywhere it was not demonstrably wrong."""
    gt["items"][0]["mechanism_all_of"] = [["double free"], ["record_cache"]]
    # bug_class is left as "buffer-overflow" from the fixture, not "double-free".
    doc = arm("result_perfect.json")
    doc["findings"][0]["description"] = (
        "record_cache: use-after-free because the pointer is used after being freed twice"
    )
    scored = grade.grade(doc, gt)
    assert outcomes(scored)["D-1"] == grade.NEAR_MISS


def test_a_ground_truth_missing_the_decoys_key_is_refused(gt):
    del gt["decoys"]
    with pytest.raises(grade.GradeError, match="no `decoys` key"):
        grade.grade(arm("result_perfect.json"), gt)


def test_zero_findings_on_the_control_is_the_correct_outcome_not_an_error(gt):
    """On the patched control there is nothing to find, so an arm that reports nothing has
    scored perfectly. The bench-tree guard used to fire here and make `score` refuse the
    whole run — including every other cell — on the first `--tier full`."""
    gt["variant"] = "control"
    scored = grade.grade(
        {"arm": "bare", "corpus": "demo", "variant": "control", "findings": []}, gt
    )
    assert scored["bugs_present"] is False
    assert scored["false_positives"][grade.CONTROL_FP] == []
    assert set(outcomes(scored).values()) == {grade.MISS}


def test_a_documented_clean_tree_weakness_is_not_a_control_false_positive(gt):
    """A control-tree claim is certain "by construction" only where there is nothing to
    find. Where the recipe records a weakness of the clean code at that function, there is
    — and charging it penalises an arm for being right."""
    gt["variant"] = "control"
    gt["known_extra_findings"].append(
        {
            "file": "src/b.c",
            "function": "index_record",
            "note": "a real weakness of the clean tree at this exact function, recorded so it is "
            "neither credited nor charged",
        }
    )
    doc = arm("result_perfect.json", variant="control")
    scored = grade.grade(doc, gt)
    charged = {row["claimed"] for row in scored["false_positives"][grade.CONTROL_FP]}
    assert "D-2" not in charged, scored["false_positives"]
    assert any(e["finding"] for e in scored["false_positives"][grade.KNOWN_EXTRA])


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-q"]))


def _gt(decoy_line=10):
    return {
        "items": [
            {
                "id": "B-1",
                "bug_class": "buffer-overflow",
                "difficulty": "EASY",
                "file": "src/z.c",
                "line": 5,
                "function": "g",
                "mechanism": "overflow",
                "mechanism_all_of": [["overflow"]],
            }
        ],
        "decoys": [
            {
                "id": "D-1",
                "decoy_kind": "extra-assert",
                "file": "src/a.c",
                "line": decoy_line,
                "function": "f",
                "safe_because": "the dominating clamp above guarantees it" + "." * 20,
            }
        ],
    }


def _decoy_finding(reported):
    return {
        "findings": [
            {
                "id": "F-1",
                "file": "src/a.c",
                "line": 10,
                "function": "f",
                "title": "assertion is redundant",
                "description": "the assert here is redundant and can be removed",
                "reported": reported,
            }
        ]
    }


def test_a_decoy_is_charged_only_when_the_arm_actually_reported_it():
    """`findings` is a superset for a multi-stage arm — it also holds merged duplicates and
    candidates the pipeline itself rejected. Charging those at a decoy penalises exactly the
    arms that filter their own output, while a single-shot arm has no suppressed candidates
    to be charged for. UNMATCHED is already filtered this way."""
    charged = grade.grade(_decoy_finding(True), _gt())["false_positives"]
    assert len(charged["DECOY_FP"]) == 1

    suppressed = grade.grade(_decoy_finding(False), _gt())["false_positives"]
    assert suppressed.get("DECOY_FP", []) == []
