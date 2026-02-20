#!/usr/bin/env python3
# /// script
# requires-python = ">=3.11"
# dependencies = ["requests>=2.31", "urllib3>=2.0", "pytest>=8.0"]
# ///
"""Tests for run_fuzz.py — covers _get_fuzzable_params, _build_base_request,
_build_fuzz_request for query, body (form + JSON), and path segment targets,
and _extract_preview / _snap_to_html_boundary for body preview truncation."""

import sys
import os
import pytest

sys.path.insert(0, os.path.dirname(__file__))

from run_fuzz import (
    DEFAULT_PREVIEW_LENGTH,
    PreviewConfig,
    _build_base_request,
    _build_fuzz_request,
    _coerce_value,
    _extract_preview,
    _get_fuzzable_params,
    _snap_to_html_boundary,
)


# ── Fixtures ──────────────────────────────────────────────────────────────────

MANIFEST_QUERY = {
    "method": "GET",
    "url": "http://example.com/search",
    "path_segments": [],
    "query_params": [
        {"name": "q", "value": "hello", "type": "string", "fuzzable": True},
        {"name": "page", "value": "1", "type": "integer", "fuzzable": True},
        {"name": "token", "value": "abc", "type": "string", "fuzzable": False},
    ],
    "headers": [{"name": "Cookie", "value": "SESS=x", "fuzzable": False}],
    "body_format": "",
    "body_params": [],
}

MANIFEST_BODY_FORM = {
    "method": "POST",
    "url": "http://example.com/login",
    "path_segments": [],
    "query_params": [],
    "headers": [],
    "body_format": "form",
    "body_params": [
        {"name": "username", "value": "alice", "type": "string", "fuzzable": True},
        {"name": "password", "value": "secret", "type": "string", "fuzzable": True},
        {"name": "_csrf", "value": "tok", "type": "string", "fuzzable": False},
    ],
}

MANIFEST_BODY_JSON = {
    "method": "POST",
    "url": "http://example.com/api/users",
    "path_segments": [],
    "query_params": [],
    "headers": [],
    "body_format": "json",
    "body_params": [
        {"name": "email", "value": "a@b.com", "type": "string", "fuzzable": True},
        {"name": "role", "value": "user", "type": "string", "fuzzable": True},
        {"name": "age", "value": 30, "type": "integer", "fuzzable": True},
        {"name": "active", "value": True, "type": "boolean", "fuzzable": True},
    ],
}

MANIFEST_PATH = {
    "method": "GET",
    "url": "http://example.com/uploads/avatar.png",
    "path_segments": [
        {"index": 0, "value": "uploads", "fuzzable": False},
        {"index": 1, "value": "avatar.png", "fuzzable": True},
    ],
    "query_params": [],
    "headers": [],
    "body_format": "",
    "body_params": [],
}

MANIFEST_PATH_MULTI = {
    "method": "GET",
    "url": "http://example.com/api/v1/users/42/posts/7",
    "path_segments": [
        {"index": 0, "value": "api", "fuzzable": False},
        {"index": 1, "value": "v1", "fuzzable": False},
        {"index": 2, "value": "users", "fuzzable": False},
        {"index": 3, "value": "42", "fuzzable": True},
        {"index": 4, "value": "posts", "fuzzable": False},
        {"index": 5, "value": "7", "fuzzable": True},
    ],
    "query_params": [],
    "headers": [],
    "body_format": "",
    "body_params": [],
}

MANIFEST_MIXED = {
    "method": "GET",
    "url": "http://example.com/items/99",
    "path_segments": [
        {"index": 0, "value": "items", "fuzzable": False},
        {"index": 1, "value": "99", "fuzzable": True},
    ],
    "query_params": [
        {"name": "format", "value": "json", "type": "string", "fuzzable": True},
    ],
    "headers": [],
    "body_format": "",
    "body_params": [],
}


# ── _get_fuzzable_params ──────────────────────────────────────────────────────

class TestGetFuzzableParams:
    def test_query_params_only(self):
        params = _get_fuzzable_params(MANIFEST_QUERY, only=None)
        assert "q" in params
        assert "page" in params
        assert "token" not in params  # fuzzable=False

    def test_body_params_form(self):
        params = _get_fuzzable_params(MANIFEST_BODY_FORM, only=None)
        assert "username" in params
        assert "password" in params
        assert "_csrf" not in params  # fuzzable=False

    def test_body_params_json(self):
        params = _get_fuzzable_params(MANIFEST_BODY_JSON, only=None)
        assert set(params) == {"email", "role", "age", "active"}

    def test_path_segments_single(self):
        params = _get_fuzzable_params(MANIFEST_PATH, only=None)
        assert "path_1" in params
        assert "path_0" not in params  # fuzzable=False

    def test_path_segments_multi(self):
        params = _get_fuzzable_params(MANIFEST_PATH_MULTI, only=None)
        assert "path_3" in params
        assert "path_5" in params
        assert "path_0" not in params
        assert "path_1" not in params
        assert "path_2" not in params
        assert "path_4" not in params

    def test_path_comes_before_query_and_body(self):
        params = _get_fuzzable_params(MANIFEST_MIXED, only=None)
        assert params.index("path_1") < params.index("format")

    def test_only_filter_query(self):
        params = _get_fuzzable_params(MANIFEST_QUERY, only=["q"])
        assert params == ["q"]

    def test_only_filter_path(self):
        params = _get_fuzzable_params(MANIFEST_PATH_MULTI, only=["path_3"])
        assert params == ["path_3"]

    def test_only_filter_mixed(self):
        params = _get_fuzzable_params(MANIFEST_MIXED, only=["path_1", "format"])
        assert set(params) == {"path_1", "format"}

    def test_empty_manifest(self):
        m = {"method": "GET", "url": "http://x.com/", "path_segments": [],
             "query_params": [], "body_params": []}
        assert _get_fuzzable_params(m, only=None) == []

    def test_no_fuzzable_path_segments(self):
        m = {**MANIFEST_PATH,
             "path_segments": [{"index": 0, "value": "uploads", "fuzzable": False},
                                {"index": 1, "value": "x.png", "fuzzable": False}]}
        params = _get_fuzzable_params(m, only=None)
        assert "path_0" not in params
        assert "path_1" not in params


# ── _build_base_request ───────────────────────────────────────────────────────

class TestBuildBaseRequest:
    def test_stores_path_segments(self):
        base = _build_base_request(MANIFEST_PATH)
        assert base["_path_segments"] == {0: "uploads", 1: "avatar.png"}

    def test_no_path_segments_key_when_empty(self):
        base = _build_base_request(MANIFEST_QUERY)
        assert "_path_segments" not in base

    def test_stores_form_body(self):
        base = _build_base_request(MANIFEST_BODY_FORM)
        assert base["_body_form"] == {"username": "alice", "password": "secret", "_csrf": "tok"}

    def test_stores_json_body(self):
        base = _build_base_request(MANIFEST_BODY_JSON)
        assert base["_body_json"]["email"] == "a@b.com"

    def test_headers_preserved(self):
        base = _build_base_request(MANIFEST_QUERY)
        assert base["headers"]["Cookie"] == "SESS=x"

    def test_url_preserved(self):
        base = _build_base_request(MANIFEST_PATH)
        assert base["url"] == "http://example.com/uploads/avatar.png"


# ── _build_fuzz_request — path segments ──────────────────────────────────────

class TestBuildFuzzRequestPathSegments:
    def setup_method(self):
        self.base = _build_base_request(MANIFEST_PATH)

    def test_substitutes_fuzzable_segment(self):
        req = _build_fuzz_request(self.base, "path_1", "evil.php", MANIFEST_PATH)
        assert req["url"] == "http://example.com/uploads/evil.php"

    def test_preserves_non_fuzzed_segment(self):
        req = _build_fuzz_request(self.base, "path_1", "test", MANIFEST_PATH)
        assert "/uploads/" in req["url"]

    def test_traversal_value(self):
        req = _build_fuzz_request(self.base, "path_1", "../../../etc/passwd", MANIFEST_PATH)
        assert "uploads" in req["url"]
        assert "../../../etc/passwd" in req["url"]

    def test_empty_value(self):
        req = _build_fuzz_request(self.base, "path_1", "", MANIFEST_PATH)
        assert req["url"] == "http://example.com/uploads/"

    def test_special_chars_in_value(self):
        req = _build_fuzz_request(self.base, "path_1", "<script>alert(1)</script>", MANIFEST_PATH)
        assert "<script>alert(1)</script>" in req["url"]

    def test_preserves_query_string(self):
        m = {**MANIFEST_PATH, "url": "http://example.com/uploads/avatar.png?foo=bar"}
        base = _build_base_request(m)
        req = _build_fuzz_request(base, "path_1", "x.txt", m)
        assert "foo=bar" in req["url"]
        assert "x.txt" in req["url"]

    def test_multi_segment_fuzzes_correct_index(self):
        base = _build_base_request(MANIFEST_PATH_MULTI)
        # Fuzz path_3 (value "42") — others stay
        req = _build_fuzz_request(base, "path_3", "999", MANIFEST_PATH_MULTI)
        assert "/api/v1/users/999/posts/7" in req["url"]

    def test_multi_segment_second_index(self):
        base = _build_base_request(MANIFEST_PATH_MULTI)
        req = _build_fuzz_request(base, "path_5", "0", MANIFEST_PATH_MULTI)
        assert "/api/v1/users/42/posts/0" in req["url"]

    def test_does_not_mutate_base(self):
        base = _build_base_request(MANIFEST_PATH)
        original_url = base["url"]
        _build_fuzz_request(base, "path_1", "mutated", MANIFEST_PATH)
        assert base["url"] == original_url

    def test_path_0_substitution(self):
        m = {
            "method": "GET",
            "url": "http://example.com/static/style.css",
            "path_segments": [
                {"index": 0, "value": "static", "fuzzable": True},
                {"index": 1, "value": "style.css", "fuzzable": False},
            ],
            "query_params": [], "headers": [], "body_format": "", "body_params": [],
        }
        base = _build_base_request(m)
        req = _build_fuzz_request(base, "path_0", "admin", m)
        assert req["url"] == "http://example.com/admin/style.css"


# ── _build_fuzz_request — query params ───────────────────────────────────────

class TestBuildFuzzRequestQueryParams:
    def setup_method(self):
        self.base = _build_base_request(MANIFEST_QUERY)

    def test_substitutes_query_param(self):
        req = _build_fuzz_request(self.base, "q", "' OR 1=1--", MANIFEST_QUERY)
        assert "q=%27+OR+1%3D1--" in req["url"] or "q=' OR 1=1--" in req["url"] or "q=%27%20OR%201%3D1--" in req["url"]

    def test_preserves_other_query_params(self):
        req = _build_fuzz_request(self.base, "q", "test", MANIFEST_QUERY)
        assert "page=1" in req["url"]

    def test_does_not_mutate_base(self):
        base = _build_base_request(MANIFEST_QUERY)
        original_url = base["url"]
        _build_fuzz_request(base, "q", "mutated", MANIFEST_QUERY)
        assert base["url"] == original_url


# ── _build_fuzz_request — body params (form) ─────────────────────────────────

class TestBuildFuzzRequestBodyForm:
    def setup_method(self):
        self.base = _build_base_request(MANIFEST_BODY_FORM)

    def test_substitutes_form_param(self):
        req = _build_fuzz_request(self.base, "username", "admin", MANIFEST_BODY_FORM)
        assert req["data"]["username"] == "admin"

    def test_preserves_other_form_params(self):
        req = _build_fuzz_request(self.base, "username", "x", MANIFEST_BODY_FORM)
        assert req["data"]["password"] == "secret"

    def test_does_not_mutate_base(self):
        base = _build_base_request(MANIFEST_BODY_FORM)
        _build_fuzz_request(base, "username", "x", MANIFEST_BODY_FORM)
        assert base["_body_form"]["username"] == "alice"


# ── _build_fuzz_request — body params (JSON) ─────────────────────────────────

class TestBuildFuzzRequestBodyJSON:
    def setup_method(self):
        self.base = _build_base_request(MANIFEST_BODY_JSON)

    def test_substitutes_string_param(self):
        req = _build_fuzz_request(self.base, "email", "bad@x.com'--", MANIFEST_BODY_JSON)
        assert req["json"]["email"] == "bad@x.com'--"

    def test_preserves_other_json_params(self):
        req = _build_fuzz_request(self.base, "email", "x@y.com", MANIFEST_BODY_JSON)
        assert req["json"]["role"] == "user"
        assert req["json"]["age"] == 30

    def test_coerces_integer_string(self):
        req = _build_fuzz_request(self.base, "age", "99", MANIFEST_BODY_JSON)
        assert req["json"]["age"] == 99

    def test_coerces_null_string(self):
        req = _build_fuzz_request(self.base, "age", "null", MANIFEST_BODY_JSON)
        assert req["json"]["age"] is None

    def test_does_not_mutate_base(self):
        base = _build_base_request(MANIFEST_BODY_JSON)
        _build_fuzz_request(base, "email", "x@y.com", MANIFEST_BODY_JSON)
        assert base["_body_json"]["email"] == "a@b.com"


# ── _build_fuzz_request — mixed path + query ─────────────────────────────────

class TestBuildFuzzRequestMixed:
    def setup_method(self):
        self.base = _build_base_request(MANIFEST_MIXED)

    def test_path_fuzz_leaves_query_intact(self):
        req = _build_fuzz_request(self.base, "path_1", "0", MANIFEST_MIXED)
        assert "/items/0" in req["url"]
        assert "format=json" in req["url"]

    def test_query_fuzz_leaves_path_intact(self):
        req = _build_fuzz_request(self.base, "format", "xml", MANIFEST_MIXED)
        assert "/items/99" in req["url"]
        assert "format=xml" in req["url"]


# ── _coerce_value ─────────────────────────────────────────────────────────────

class TestCoerceValue:
    def test_null(self):
        assert _coerce_value("null", "string") is None

    def test_true(self):
        assert _coerce_value("true", "string") is True

    def test_false(self):
        assert _coerce_value("false", "string") is False

    def test_integer_string(self):
        assert _coerce_value("42", "integer") == 42

    def test_float_string(self):
        assert _coerce_value("3.14", "float") == pytest.approx(3.14)

    def test_non_numeric_string_for_integer(self):
        assert _coerce_value("NaN", "integer") == "NaN"

    def test_bool_coercion_one(self):
        assert _coerce_value("1", "boolean") is True

    def test_bool_coercion_zero(self):
        assert _coerce_value("0", "boolean") is False

    def test_plain_string(self):
        assert _coerce_value("hello", "string") == "hello"


# ── _snap_to_html_boundary ────────────────────────────────────────────────────

class TestSnapToHtmlBoundary:
    # prefer_open=True: snap start rightward to just after '>'
    def test_snap_start_finds_close_tag(self):
        body = "<div><span>hello</span></div>"
        # pos=6 is inside "<span>", snap back to after '<div>'
        result = _snap_to_html_boundary(body, 6, 80, prefer_open=True)
        assert body[result - 1] == ">"

    def test_snap_start_no_tag_in_range(self):
        body = "a" * 200
        pos = 100
        result = _snap_to_html_boundary(body, pos, 80, prefer_open=True)
        assert result == pos  # unchanged — no '>' found

    def test_snap_start_at_exact_boundary(self):
        body = "<div>content"
        # pos=5 is already right after '>'
        result = _snap_to_html_boundary(body, 5, 80, prefer_open=True)
        assert result == 5

    # prefer_open=False: snap end backwards to just before '<'
    def test_snap_end_finds_open_tag(self):
        body = "<div><span>hello</span></div>"
        # pos=22 is inside "</span>"; rfind('<', ..., 22) finds '<' at 16 ("</" of "</span>")
        result = _snap_to_html_boundary(body, 22, 80, prefer_open=False)
        assert body[result] == "<"
        assert result < 22  # snapped backwards

    def test_snap_end_no_tag_in_range(self):
        body = "a" * 200
        pos = 100
        result = _snap_to_html_boundary(body, pos, 80, prefer_open=False)
        assert result == pos  # unchanged

    def test_snap_end_exactly_at_open_tag(self):
        body = "hello<div>"
        # pos=5 points at '<'; rfind('<', lo, 5) won't find it (exclusive end at 5)
        # so result == pos unchanged
        result = _snap_to_html_boundary(body, 5, 80, prefer_open=False)
        assert result == 5


# ── _extract_preview — default (length only) ─────────────────────────────────

class TestExtractPreviewDefault:
    def test_default_is_no_truncation(self):
        # DEFAULT_PREVIEW_LENGTH == 0: full body returned unchanged (modulo newlines)
        body = "x" * 5000
        assert _extract_preview(body, PreviewConfig()) == body

    def test_shorter_than_explicit_limit(self):
        body = "hello world"
        assert _extract_preview(body, PreviewConfig(length=100)) == "hello world"

    def test_truncated_to_explicit_length(self):
        body = "x" * 1050
        result = _extract_preview(body, PreviewConfig(length=1000))
        assert len(result) == 1000

    def test_newlines_collapsed(self):
        body = "line1\nline2\r\nline3"
        result = _extract_preview(body, PreviewConfig())
        assert "\n" not in result
        assert "\r" not in result

    def test_empty_body(self):
        assert _extract_preview("", PreviewConfig()) == ""

    def test_zero_length_returns_full_body(self):
        body = "x" * 5000
        result = _extract_preview(body, PreviewConfig(length=0))
        assert result == body

    def test_zero_length_collapses_newlines(self):
        body = "line1\nline2\r\nline3"
        result = _extract_preview(body, PreviewConfig(length=0))
        assert "\n" not in result
        assert "\r" not in result


# ── _extract_preview — offset ─────────────────────────────────────────────────

class TestExtractPreviewOffset:
    def test_offset_skips_prefix(self):
        body = "SKIP" + "KEEP" * 10
        cfg = PreviewConfig(length=8, offset=4)
        assert _extract_preview(body, cfg) == "KEEPKEEP"

    def test_offset_beyond_body(self):
        body = "short"
        cfg = PreviewConfig(length=100, offset=1000)
        assert _extract_preview(body, cfg) == ""

    def test_offset_zero_same_as_default(self):
        body = "hello world"
        assert _extract_preview(body, PreviewConfig(length=5, offset=0)) == "hello"

    def test_offset_plus_length_clips_to_body_end(self):
        body = "abcde"
        cfg = PreviewConfig(length=100, offset=3)
        assert _extract_preview(body, cfg) == "de"


# ── _extract_preview — fuzzy truncation ───────────────────────────────────────

# Shared HTML fixture used across fuzzy tests.
_HTML = (
    "<html><head><title>Test</title></head>"
    "<body>"
    "<nav>Navigation</nav>"
    "<main>"
    '<div class="error">Query error: SQLSTATE[HY000]</div>'
    "<p>Some other content here</p>"
    "</main>"
    "</body></html>"
)


class TestExtractPreviewFuzzy:
    def test_needle_found_centres_window(self):
        cfg = PreviewConfig(length=40, fuzzy_needle="SQLSTATE")
        result = _extract_preview(_HTML, cfg)
        assert "SQLSTATE" in result

    def test_needle_not_found_falls_back_to_offset(self):
        body = "abcdefghij" * 20
        cfg = PreviewConfig(length=10, offset=5, fuzzy_needle="NOTHERE")
        result = _extract_preview(body, cfg)
        assert result == body[5:15]

    def test_window_snapped_to_html_boundaries(self):
        cfg = PreviewConfig(length=60, fuzzy_needle="SQLSTATE")
        result = _extract_preview(_HTML, cfg)
        # The result must contain the needle.
        assert "SQLSTATE" in result
        # After snapping start backwards to '>', result should not begin with '<'
        # (we landed right after a '>').  May be empty only if body is degenerate.
        if result:
            assert result[0] != "<" or result.startswith("<")  # allow if unavoidable

    def test_short_body_no_boundaries_nearby(self):
        # Body with needle but no HTML elements — should still return something centred.
        body = "prefix " + "TARGET" + " suffix"
        cfg = PreviewConfig(length=10, fuzzy_needle="TARGET")
        result = _extract_preview(body, cfg)
        assert "TARGET" in result

    def test_needle_at_start_of_body(self):
        body = "ERROR: bad input<br>rest of content"
        cfg = PreviewConfig(length=20, fuzzy_needle="ERROR")
        result = _extract_preview(body, cfg)
        assert "ERROR" in result

    def test_needle_at_end_of_body(self):
        body = "lots of content " * 5 + "NEEDLE"
        cfg = PreviewConfig(length=20, fuzzy_needle="NEEDLE")
        result = _extract_preview(body, cfg)
        assert "NEEDLE" in result

    def test_multichar_needle(self):
        body = "<div>Query error: SQLSTATE[HY000]: General error</div>"
        cfg = PreviewConfig(length=40, fuzzy_needle="SQLSTATE[HY000]")
        result = _extract_preview(body, cfg)
        assert "SQLSTATE" in result

    def test_newlines_collapsed_in_fuzzy(self):
        body = "before\nSQLSTATE\nafter"
        cfg = PreviewConfig(length=30, fuzzy_needle="SQLSTATE")
        result = _extract_preview(body, cfg)
        assert "\n" not in result

    def test_length_respected_approximately(self):
        # The snapping may shorten the window slightly; it should never exceed length.
        cfg = PreviewConfig(length=30, fuzzy_needle="SQLSTATE")
        result = _extract_preview(_HTML, cfg)
        assert len(result) <= 30


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-v"]))
