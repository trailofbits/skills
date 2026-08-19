"""Unit tests for format_goal_prompt.py.

The formatter must produce a single-line /goal command from any messy draft,
and must FAIL (non-zero / ValueError) on empty input and on output past the
length cap — a formatter that emits nothing or an oversized command must
never exit 0.
"""

from __future__ import annotations

import pytest
from format_goal_prompt import (
    DEFAULT_MAX_PROMPT_CHARS,
    format_goal_command,
    has_stop_clause,
    main,
    normalize_objective,
)


def test_collapses_multiline_draft_to_single_line() -> None:
    draft = "Refactor the auth module:\n  - replace MD5\n\t- add tests\n"
    assert format_goal_command(draft) == (
        "/goal Refactor the auth module: - replace MD5 - add tests"
    )


def test_strips_existing_goal_prefix_without_doubling() -> None:
    assert format_goal_command("/goal do the thing") == "/goal do the thing"


def test_strips_surrounding_code_fence_and_quotes() -> None:
    draft = '```text\n"do the thing"\n```'
    assert format_goal_command(draft) == "/goal do the thing"


def test_normalizes_crlf_and_unicode_whitespace() -> None:
    assert normalize_objective("a\r\nb\rc d") == "a b c d"


def test_objective_only_omits_prefix() -> None:
    assert format_goal_command("do it", objective_only=True) == "do it"


def test_empty_input_raises() -> None:
    with pytest.raises(ValueError, match="empty"):
        format_goal_command("/goal \n  \n")


def test_output_over_limit_raises() -> None:
    with pytest.raises(ValueError, match="limit"):
        format_goal_command("x" * DEFAULT_MAX_PROMPT_CHARS)


def test_max_chars_zero_disables_limit() -> None:
    long = "x" * (DEFAULT_MAX_PROMPT_CHARS + 1)
    assert format_goal_command(long, max_chars=0) == f"/goal {long}"


def test_main_fenced_output(tmp_path, capsys) -> None:
    draft = tmp_path / "draft.txt"
    draft.write_text("do\nthe   thing\n", encoding="utf-8")
    assert main([str(draft), "--fenced"]) == 0
    assert capsys.readouterr().out == "```text\n/goal do the thing\n```\n"


def test_main_returns_nonzero_on_empty_draft(tmp_path, capsys) -> None:
    draft = tmp_path / "draft.txt"
    draft.write_text("   \n", encoding="utf-8")
    assert main([str(draft)]) == 1
    assert "empty" in capsys.readouterr().err


def test_stop_clause_detects_turn_bound() -> None:
    assert has_stop_clause("fix the tests, or stop after 20 turns")
    assert has_stop_clause("iterate; pause after 3 attempts")


def test_stop_clause_detects_blocked_clause() -> None:
    assert has_stop_clause("if blocked, stop and report the blocker")


def test_stop_clause_rejects_end_state_only() -> None:
    assert not has_stop_clause("all tests pass and the queue is empty")
    assert not has_stop_clause("keep each file under a 300-line budget")


def test_main_warns_without_stop_clause(tmp_path, capsys) -> None:
    draft = tmp_path / "draft.txt"
    draft.write_text("make npm test exit 0\n", encoding="utf-8")
    assert main([str(draft)]) == 0
    assert "no stop bound or blocked clause" in capsys.readouterr().err


def test_main_does_not_warn_with_stop_clause(tmp_path, capsys) -> None:
    draft = tmp_path / "draft.txt"
    draft.write_text("make npm test exit 0, or stop after 20 turns\n", encoding="utf-8")
    assert main([str(draft)]) == 0
    assert capsys.readouterr().err == ""
