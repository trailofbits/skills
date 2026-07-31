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
from yara_rules import LintResult
from yara_rules import check_condition_order
from yara_rules import collect_rule_files
from yara_rules import extract_condition
from yara_rules import extract_metadata
from yara_rules import extract_rule_body
from yara_rules import extract_rule_names
from yara_rules import extract_strings
from yara_rules import find_best_atom
from yara_rules import hex_string_runs
from yara_rules import lint_source
from yara_rules import select_exit_code


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
