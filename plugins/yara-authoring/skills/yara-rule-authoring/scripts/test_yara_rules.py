"""Tests for the shared YARA rule parsing and analysis helpers.

Deliberately imports only yara_rules, which has no third-party dependencies, so
these run under the repository's `uv run --no-project --with pytest` harness
without the yara-x wheel.

Each parser test pairs a case that must be detected with the input shape that
used to defeat it, so a regression in the scanners fails here rather than
silently reporting a clean rule.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

from yara_rules import ISSUE_CODES
from yara_rules import REPEATED_PATTERNS
from yara_rules import LintResult
from yara_rules import analyze_hex_string
from yara_rules import analyze_text_string
from yara_rules import check_condition_order
from yara_rules import collect_rule_files
from yara_rules import coverage_error
from yara_rules import extract_condition
from yara_rules import extract_metadata
from yara_rules import extract_rule_body
from yara_rules import extract_rule_names
from yara_rules import extract_strings
from yara_rules import find_best_atom
from yara_rules import hex_string_runs
from yara_rules import lint_source
from yara_rules import rule_less_files
from yara_rules import score_atom
from yara_rules import select_exit_code
from yara_rules import strip_comments


def codes(source: str) -> set[str]:
    return {issue.code for issue in lint_source(source)}


# --------------------------------------------------------------------------- #
# String parsing
# --------------------------------------------------------------------------- #

REGEX_RULE = """
rule MAL_Win_Slash_Jan25 {
    strings:
        $url = /https:\\/\\/[a-z0-9]{5,20}\\.onion\\/beacon/ nocase
        $cls = /[/a-z]+\\.php/
    condition:
        filesize < 1MB and any of them
}
"""


def test_regex_value_survives_escaped_slashes():
    """A `\\/` must not terminate the pattern -- the bug that broke every URL regex."""
    strings = {s.name: s for s in extract_strings(REGEX_RULE, "MAL_Win_Slash_Jan25")}

    assert strings["$url"].type == "regex"
    assert strings["$url"].value == r"https:\/\/[a-z0-9]{5,20}\.onion\/beacon"
    assert strings["$url"].modifiers == ["nocase"]


def test_regex_value_survives_slash_in_character_class():
    strings = {s.name: s for s in extract_strings(REGEX_RULE, "MAL_Win_Slash_Jan25")}

    assert strings["$cls"].value == r"[/a-z]+\.php"


def test_unbounded_quantifier_is_flagged_inside_a_url_regex():
    """W008 has to reach past the escaped slashes to see the `.*`."""
    source = """
rule MAL_Win_Unbounded_Jan25 {
    meta:
        description = "Detects a thing via a marker long enough to clear sixty characters easily"
        author = "a@b.c"
        reference = "https://example.com"
        date = "2025-01-01"
    strings:
        $u = /https:\\/\\/evil\\.com\\/.*/
    condition:
        filesize < 1MB and $u
}
"""
    assert "W008" in codes(source)


def test_bounded_repetition_is_not_flagged_as_unbounded():
    source = """
rule MAL_Win_Bounded_Jan25 {
    strings:
        $u = /https:\\/\\/evil\\.com\\/.{0,40}/
    condition:
        filesize < 1MB and $u
}
"""
    assert "W008" not in codes(source)


def test_escaped_quote_does_not_end_a_text_string():
    source = r"""
rule MAL_Win_Quote_Jan25 {
    strings:
        $s = "say \"hello\" now" ascii
    condition:
        filesize < 1MB and $s
}
"""
    strings = extract_strings(source, "MAL_Win_Quote_Jan25")

    assert len(strings) == 1
    assert strings[0].value == r"say \"hello\" now"
    assert strings[0].modifiers == ["ascii"]


def test_trailing_comment_is_not_read_as_a_modifier():
    source = """
rule MAL_Win_Comment_Jan25 {
    strings:
        $s = "unique_marker_value" ascii  // nocase would be wrong here
    condition:
        filesize < 1MB and $s
}
"""
    strings = extract_strings(source, "MAL_Win_Comment_Jan25")

    assert strings[0].modifiers == ["ascii"]


def test_brace_inside_a_string_does_not_truncate_the_rule_body():
    source = """
rule MAL_Win_Brace_Jan25 {
    strings:
        $a = "}"
        $b = "second_unique_marker"
    condition:
        filesize < 1MB and all of them
}
"""
    names = [s.name for s in extract_strings(source, "MAL_Win_Brace_Jan25")]

    assert names == ["$a", "$b"]
    assert "all of them" in extract_condition(source, "MAL_Win_Brace_Jan25")


def test_commented_out_rule_is_not_extracted():
    source = """
// rule MAL_Win_Ghost_Jan25 { condition: true }
rule MAL_Win_Real_Jan25 { condition: filesize < 1MB }
"""
    assert extract_rule_names(source) == ["MAL_Win_Real_Jan25"]


def test_metadata_and_body_are_scoped_to_the_named_rule():
    source = """
rule MAL_Win_First_Jan25 {
    meta:
        description = "Detects the first thing"
    condition:
        filesize < 1MB
}
rule MAL_Win_Second_Jan25 {
    meta:
        description = "Detects the second thing"
    condition:
        filesize < 2MB
}
"""
    assert extract_metadata(source, "MAL_Win_Second_Jan25")["description"] == (
        "Detects the second thing"
    )
    assert "2MB" in extract_rule_body(source, "MAL_Win_Second_Jan25")


def test_tagged_rule_header_is_parsed():
    source = "rule MAL_Win_Tagged_Jan25 : apt loader { condition: filesize < 1MB }"

    assert extract_rule_names(source) == ["MAL_Win_Tagged_Jan25"]
    assert "filesize" in extract_condition(source, "MAL_Win_Tagged_Jan25")


# --------------------------------------------------------------------------- #
# Issue messages
# --------------------------------------------------------------------------- #


def test_messages_contain_no_leftover_double_braces():
    """Implicit f-string/plain-string concatenation used to leak `{{1,N}}` verbatim."""
    source = """
rule badname {
    strings:
        $u = /evil.*/
        $s = "ab"
    condition:
        $u or $s
}
"""
    issues = lint_source(source)

    assert issues, "fixture should produce issues"
    for issue in issues:
        assert "{{" not in issue.message
        assert "}}" not in issue.message


# --------------------------------------------------------------------------- #
# Condition ordering (W009)
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize(
    "condition",
    [
        "filesize < 5MB and uint16(0) == 0x5A4D and $mutex",
        "uint32(0) == 0xFEEDFACF and any of ($lib*)",
        "crx.is_crx and 2 of ($miner*)",
        'filesize < 1MB and pe.imphash() == "abc"',
    ],
)
def test_cheap_prefilter_first_is_accepted(condition):
    assert list(check_condition_order("R", condition)) == []


@pytest.mark.parametrize(
    "condition",
    [
        'pe.imports("kernel32.dll", "VirtualAlloc") and $mutex and filesize < 5MB',
        "any of them",
        "$a and $b and filesize < 1MB",
        "for any i in (0..#s1) : (@s1[i] < 1000) and filesize < 1MB",
    ],
)
def test_expensive_term_before_any_prefilter_is_flagged(condition):
    issues = list(check_condition_order("R", condition))

    assert [i.code for i in issues] == ["W009"]


def test_condition_order_check_is_wired_into_lint_source():
    source = """
rule MAL_Win_Order_Jan25 {
    meta:
        description = "Detects a thing via a marker long enough to clear sixty characters easily"
        author = "a@b.c"
        reference = "https://example.com"
        date = "2025-01-01"
    strings:
        $mutex = "Global\\\\UniqueMarker"
    condition:
        pe.imphash() == "abc" and $mutex and filesize < 5MB
}
"""
    assert "W009" in codes(source)


# --------------------------------------------------------------------------- #
# Atom analysis
# --------------------------------------------------------------------------- #


def test_jump_breaks_byte_adjacency():
    """`4D 5A [2-4] 50 45` is two runs; the bytes either side are never one atom."""
    runs = hex_string_runs("4D 5A [2-4] 50 45")

    assert [run.data for run in runs] == [b"\x4d\x5a", b"\x50\x45"]


def test_alternation_breaks_byte_adjacency():
    runs = hex_string_runs("4D 5A 90 00 ( 50 45 | 4E 45 )")

    assert runs[0].data == b"\x4d\x5a\x90\x00"
    assert len(runs) > 1


def test_hex_string_split_by_a_jump_has_no_four_byte_atom():
    source = """
rule MAL_Win_Jump_Jan25 {
    strings:
        $h = { 4D 5A [2-4] 50 45 }
    condition:
        filesize < 1MB and $h
}
"""
    string = extract_strings(source, "MAL_Win_Jump_Jan25")[0]
    runs = hex_string_runs(string.value)

    assert all(find_best_atom(run.data, run.wildcards) == (None, 0) for run in runs)


def test_nibble_wildcard_counts_as_a_wildcard():
    runs = hex_string_runs("4D 5? 90 00 41 42 43")

    assert runs[0].wildcards == [1]


def test_hex_tokens_without_whitespace_are_parsed():
    runs = hex_string_runs("4D5A9000")

    assert runs[0].data == b"\x4d\x5a\x90\x00"


def test_repeated_bytes_score_worse_than_unique_bytes():
    _, null_score = find_best_atom(b"\x00\x00\x00\x00", [])
    _, unique_score = find_best_atom(b"\x4d\x5a\x91\x03", [])

    assert null_score < unique_score


# --------------------------------------------------------------------------- #
# Scan targets and exit codes
# --------------------------------------------------------------------------- #


def test_directory_with_no_rules_is_an_error_not_a_clean_run(tmp_path):
    (tmp_path / "notes.md").write_text("no rules here")

    files, error = collect_rule_files(tmp_path)

    assert files == []
    assert error is not None and "nothing was inspected" in error


def test_directory_with_rules_collects_them(tmp_path):
    (tmp_path / "a.yar").write_text("rule A { condition: true }")
    (tmp_path / "nested").mkdir()
    (tmp_path / "nested" / "b.yara").write_text("rule B { condition: true }")

    files, error = collect_rule_files(tmp_path)

    assert error is None
    assert [f.name for f in files] == ["a.yar", "b.yara"]


def test_missing_path_is_an_error(tmp_path):
    files, error = collect_rule_files(tmp_path / "absent")

    assert files == []
    assert error is not None


WARNINGS_ONLY_RULE = """
rule badname {
    meta:
        description = "Detects a thing via a marker long enough to clear sixty characters easily"
        author = "a@b.c"
        date = "2025-01-01"
    strings:
        $s = "unique_marker_value"
    condition:
        filesize < 1MB and $s
}
"""


def test_exit_code_reflects_severity():
    clean = LintResult(file="clean.yar")
    warned = LintResult(file="warn.yar")
    warned.issues.extend(lint_source(WARNINGS_ONLY_RULE))

    assert warned.warning_count > 0
    assert warned.error_count == 0
    assert select_exit_code([clean], strict=False) == 0
    assert select_exit_code([warned], strict=False) == 0
    assert select_exit_code([warned], strict=True) == 1


def test_unreadable_file_fails_even_without_issues():
    broken = LintResult(file="x.yar", parse_error="Cannot read file")

    assert select_exit_code([broken], strict=False) == 1
    # lint_file returns early on a read error without setting `rules`, so the
    # default has to be 0 -- otherwise coverage_error credits a rule nobody saw.
    assert broken.rules == 0


# --------------------------------------------------------------------------- #
# Documentation sync
# --------------------------------------------------------------------------- #

STYLE_GUIDE = Path(__file__).resolve().parent.parent / "references" / "style-guide.md"

# Fixtures chosen to drive every check the linter implements at least once.
CODE_FIXTURES = (
    'rule badname { strings: $s = "ab" $h = { 4D 5A } condition: $s and $h }',
    """
rule GHOST_Win_Thing_Jan25 {
    meta:
        description = "short"
    strings:
        $a = "cmd.exe"
        $b = "??? placeholder value" nocase xor
        $c = "ab" base64
        $w = { ?? ?? 4D 5A 90 00 }
        $r = /https:\\/\\/evil\\.com\\/.*/
    condition:
        $a and entrypoint == 0 and @a[-1] > 0
}
""",
    """
rule MAL_Win_Verbose_Jan25 {
    meta:
        description = "Detects %s"
        author = "a@b.c"
        reference = "https://example.com"
        date = "2025-01-01"
    strings:
        $s = "unique_marker_value"
    condition:
        filesize < 1MB and $s
}
""".replace("%s", "x" * 420),
)


def documented_codes() -> set[str]:
    table = STYLE_GUIDE.read_text()
    return set(re.findall(r"^\|\s*([EWI]\d{3})\s*\|", table, re.MULTILINE))


def test_style_guide_table_matches_the_code_registry():
    assert documented_codes() == set(ISSUE_CODES), (
        "references/style-guide.md and yara_rules.ISSUE_CODES have drifted"
    )


def test_every_emitted_code_is_registered():
    emitted = {issue.code for fixture in CODE_FIXTURES for issue in lint_source(fixture)}

    assert emitted, "fixtures should emit codes"
    assert emitted <= set(ISSUE_CODES), f"unregistered codes: {emitted - set(ISSUE_CODES)}"


def test_fixtures_exercise_every_check_except_compilation():
    """E000 comes from yara_x, which these dependency-free tests cannot import."""
    emitted = {issue.code for fixture in CODE_FIXTURES for issue in lint_source(fixture)}

    assert set(ISSUE_CODES) - emitted == {"E000"}


# --------------------------------------------------------------------------- #
# Exit codes
# --------------------------------------------------------------------------- #

ERROR_RULE = """
rule MAL_Win_Short_Jan25 {
    meta:
        description = "Detects a thing via a marker long enough to clear sixty characters easily"
        author = "a@b.c"
        reference = "https://example.com"
        date = "2025-01-01"
    strings:
        $s = "ab"
    condition:
        filesize < 1MB and $s
}
"""


def test_exit_code_fails_on_an_error_severity_issue():
    """The linter's main contract: an error exits 1 even without --strict."""
    result = LintResult(file="err.yar")
    result.issues.extend(lint_source(ERROR_RULE))

    assert result.error_count > 0
    assert select_exit_code([result], strict=False) == 1


# --------------------------------------------------------------------------- #
# Atom scoring
# --------------------------------------------------------------------------- #


def test_null_bytes_lower_the_atom_score():
    assert score_atom(b"\x01\x02\x00\x03") < score_atom(b"\x01\x02\x04\x03")


def test_every_repeated_byte_pattern_scores_zero():
    for pattern, _label in REPEATED_PATTERNS:
        assert score_atom(pattern) == 0, f"{pattern!r} should be unusable as an atom"


def test_a_common_sequence_lowers_the_atom_score():
    assert score_atom(b"This") < score_atom(b"Thiz")


def test_all_printable_atoms_score_below_binary_ones():
    assert score_atom(b"abcd") < score_atom(b"\x01\x02\x03\x04")


def test_a_low_scoring_atom_is_an_error_and_a_middling_one_a_warning():
    repeated = analyze_text_string("$s", "aaaaaa", [])
    middling = analyze_text_string("$s", "abab", [])

    assert [i.severity for i in repeated.issues] == ["error"]
    assert [i.severity for i in middling.issues] == ["warning"]


def test_a_short_text_string_cannot_yield_an_atom():
    analysis = analyze_text_string("$s", "ab", [])

    assert analysis.byte_count == 2
    assert [i.severity for i in analysis.issues] == ["error"]
    assert analysis.best_atom is None
    assert "only 2 bytes" in analysis.issues[0].message


def test_a_short_hex_string_cannot_yield_an_atom():
    """The diagnostic has to say "too short", not blame wildcards there are none of."""
    analysis = analyze_hex_string("$h", "{ 4D 5A }")

    assert analysis.byte_count == 2
    assert [i.severity for i in analysis.issues] == ["error"]
    assert analysis.best_atom is None
    assert "only 2 bytes" in analysis.issues[0].message
    assert "wildcard" not in analysis.issues[0].message


def test_high_wildcard_density_is_flagged():
    analysis = analyze_hex_string("$h", "{ 4D 5A 90 00 ?? ?? ?? ?? ?? }")

    assert analysis.best_atom == "4D5A9000"
    assert any("wildcard density" in i.message for i in analysis.issues)


# --------------------------------------------------------------------------- #
# Scanners
# --------------------------------------------------------------------------- #

BLOCK_COMMENT_SOURCE = """
/* rule GHOST_Win_Commented_Jan25 { condition: true } */
rule MAL_Win_Real_Jan25 { condition: true }
"""


def test_a_rule_inside_a_block_comment_is_not_a_rule():
    assert extract_rule_names(BLOCK_COMMENT_SOURCE) == ["MAL_Win_Real_Jan25"]


def test_block_comments_keep_their_line_breaks():
    blanked = strip_comments(BLOCK_COMMENT_SOURCE)

    assert blanked.count("\n") == BLOCK_COMMENT_SOURCE.count("\n")
    assert "GHOST" not in blanked


CHAR_CLASS_RULE = """
rule MAL_Win_CharClass_Jan25 {
    strings:
        $r = /a[/]bcdef/
    condition:
        $r
}
"""


def test_a_slash_inside_a_character_class_does_not_end_the_regex():
    strings = extract_strings(CHAR_CLASS_RULE, "MAL_Win_CharClass_Jan25")

    assert [s.value for s in strings] == ["a[/]bcdef"]


# --------------------------------------------------------------------------- #
# Rule coverage across a run
# --------------------------------------------------------------------------- #


def test_a_run_that_inspected_no_rules_is_an_error():
    assert coverage_error({"a.yar": 0}) is not None
    assert coverage_error({"a.yar": 0, "b.yar": 0}) is not None


def test_inspecting_no_files_reports_that_rather_than_an_empty_file_list():
    message = coverage_error({})

    assert message is not None
    assert "no files" in message


def test_a_rule_less_file_alongside_real_rules_is_not_an_error():
    """A shared `import "pe"` header holds no rules; the directory is still healthy."""
    assert coverage_error({"imports.yar": 0, "rules.yar": 3}) is None


def test_the_coverage_error_names_the_files_it_inspected():
    message = coverage_error({"b.yar": 0, "a.yar": 0})

    assert message is not None
    assert "a.yar" in message
    assert "b.yar" in message


def test_rule_less_files_are_listed_for_reporting():
    counts = {"imports.yar": 0, "rules.yar": 2, "empty.yar": 0}

    assert rule_less_files(counts) == ["empty.yar", "imports.yar"]
    assert rule_less_files({"rules.yar": 2}) == []
