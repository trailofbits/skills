#!/usr/bin/env python3
"""Tests for the injector, the de-identifier and the recipe validator.

These three decide whether a corpus means anything. An anchor that matches twice
patches the wrong function; a de-identifier that leaves an identifier behind hands a
reviewer the upstream file to diff; a recipe with no bugs builds a corpus that grades
every arm 0/0 and reports it as a clean measurement.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))

from lib import deidentify, inject, recipe  # noqa: E402

SIGIL = HERE.parent / "corpora" / "sigil" / "recipe.json"

SAMPLE = """/* Copyright 2001 Some Upstream Project. Version 2.4.3 */
#include <string.h>
#include "widget_table.h"

/* the widget count, as documented upstream */
int widget_count(struct widget_table *table) {
  const char *label = "widget_table overflow";
  return table->widget_total; /* trailing comment */
}
"""


# ------------------------------------------------------------------- injector


def test_an_anchor_that_matches_twice_is_refused():
    text = "int a = 1;\nint a = 1;\n"
    with pytest.raises(inject.InjectError, match="occurs 2 time"):
        inject.apply_patches(
            "x.c", text, [{"id": "P1", "anchor": "int a = 1;", "replacement": "int a = 2;"}]
        )


def test_an_anchor_that_matches_nothing_is_refused():
    with pytest.raises(inject.InjectError, match="occurs 0 time"):
        inject.apply_patches(
            "x.c", "int a = 1;\n", [{"id": "P1", "anchor": "int b;", "replacement": "int c;"}]
        )


def test_overlapping_patches_are_refused():
    text = "alpha beta gamma\n"
    with pytest.raises(inject.InjectError, match="overlap"):
        inject.apply_patches(
            "x.c",
            text,
            [
                {"id": "P1", "anchor": "alpha beta", "replacement": "ALPHA BETA"},
                {"id": "P2", "anchor": "beta gamma", "replacement": "BETA GAMMA"},
            ],
        )


def test_patches_are_spliced_against_the_original_so_order_cannot_matter():
    text = "one\ntwo\nthree\nfour\n"
    forward = inject.apply_patches(
        "x.c",
        text,
        [
            {"id": "A", "anchor": "two", "replacement": "TWO"},
            {"id": "B", "anchor": "four", "replacement": "FOUR"},
        ],
    )
    backward = inject.apply_patches(
        "x.c",
        text,
        [
            {"id": "B", "anchor": "four", "replacement": "FOUR"},
            {"id": "A", "anchor": "two", "replacement": "TWO"},
        ],
    )
    assert forward.text == backward.text == "one\nTWO\nthree\nFOUR\n"
    assert {s.id: s.line for s in forward.sites} == {"A": 2, "B": 4}


def test_the_site_line_is_computed_after_splicing():
    text = "a\nb\nc\n"
    patched = inject.apply_patches(
        "x.c",
        text,
        [{"id": "A", "anchor": "b", "replacement": "x\ny\nTARGET", "site_marker": "TARGET"}],
    )
    assert patched.text.splitlines() == ["a", "x", "y", "TARGET", "c"]
    assert patched.sites[0].line == 4


def test_a_site_marker_outside_its_replacement_is_refused():
    with pytest.raises(inject.InjectError, match="site_marker is not inside"):
        inject.apply_patches(
            "x.c", "a\n", [{"id": "A", "anchor": "a", "replacement": "b", "site_marker": "zzz"}]
        )


# --------------------------------------------------------------- reachability


CALL_TREE = {
    "a.c": """
void leaf(void) { }
void mid(void) { leaf(); }
void top(void) { mid(); }
void lonely(void) { }
void dispatch(void) { void (*f)(void) = leaf; f(); }
"""
}


def test_a_real_call_chain_verifies():
    assert (
        inject.check_edges(
            CALL_TREE,
            [{"from": "top", "to": "mid"}, {"from": "mid", "to": "leaf"}],
            {"top"},
            "leaf",
        )
        == []
    )


def test_a_broken_edge_is_reported():
    problems = inject.check_edges(CALL_TREE, [{"from": "top", "to": "lonely"}], {"top"}, "lonely")
    assert problems and "does not call lonely" in problems[0]


def test_a_chain_that_does_not_start_at_an_entry_point_is_reported():
    problems = inject.check_edges(CALL_TREE, [{"from": "mid", "to": "leaf"}], {"top"}, "leaf")
    assert any("not a declared entry point" in p for p in problems)


def test_a_chain_that_does_not_end_at_the_bug_is_reported():
    problems = inject.check_edges(CALL_TREE, [{"from": "top", "to": "mid"}], {"top"}, "leaf")
    assert any("ends at 'mid'" in p for p in problems)


def test_a_non_contiguous_chain_is_reported():
    problems = inject.check_edges(
        CALL_TREE,
        [{"from": "top", "to": "mid"}, {"from": "dispatch", "to": "leaf"}],
        {"top"},
        "leaf",
    )
    assert any("not contiguous" in p for p in problems)


def test_an_empty_chain_is_reported_rather_than_passing():
    problems = inject.check_edges(CALL_TREE, [], {"top"}, "leaf")
    assert problems and "never established" in problems[0]


def test_an_unbalanced_paren_in_a_string_does_not_hide_later_functions():
    # The defect: `"("` inside a string literal never balances, and the indexer gave up
    # on the rest of the file — reporting that half a real project's functions did not
    # exist. Literals are blanked before indexing now.
    source = (
        'void first(void) { puts("an open ( paren in a string"); }\n'
        'void second(void) { puts("/* not a comment */"); }\n'
        "void third(void) { return; }\n"
    )
    index = inject.index_functions(source)
    assert set(index) == {"first", "second", "third"}, sorted(index)


def test_a_comment_containing_a_brace_does_not_confuse_the_indexer():
    source = "/* } { */\nvoid only_one(void) { return; }\n"
    assert set(inject.index_functions(source)) == {"only_one"}


def test_a_bug_inside_an_entry_point_is_reachable_by_definition():
    # Written as a self-edge so the claim is explicit and the entry point is still
    # checked against the declared list, rather than reachability being skipped.
    assert inject.check_edges(CALL_TREE, [{"from": "top", "to": "top"}], {"top"}, "top") == []
    problems = inject.check_edges(CALL_TREE, [{"from": "mid", "to": "mid"}], {"top"}, "mid")
    assert any("not in the declared entry_points" in p for p in problems)


def test_the_shipped_corpus_covers_the_catalogue_broadly():
    loaded = recipe.load(SIGIL)
    counts = recipe.counts(loaded)
    assert counts["bugs"] >= 15
    assert counts["decoys"] >= 10
    assert len(counts["by_class"]) >= 15
    assert all(counts["by_difficulty"][tier] >= 3 for tier in recipe.DIFFICULTIES)
    assert len(counts["by_decoy_kind"]) >= 5


def test_an_indirect_edge_needs_evidence_in_a_real_file():
    ok = inject.check_edges(
        CALL_TREE,
        [
            {"from": "top", "to": "mid"},
            {"from": "mid", "to": "leaf", "kind": "indirect", "evidence_file": "a.c"},
        ],
        {"top"},
        "leaf",
    )
    assert ok == []
    missing = inject.check_edges(
        CALL_TREE,
        [{"from": "top", "to": "leaf", "kind": "indirect", "evidence_file": "nope.c"}],
        {"top"},
        "leaf",
    )
    assert any("not in the corpus" in p for p in missing)


# ------------------------------------------------------------- de-identifier


def test_comments_identifiers_and_strings_are_all_transformed():
    out = deidentify.deidentify_tree({"widget_table.c": SAMPLE}, seed="test")
    text = next(iter(out.files.values())).text
    assert "Copyright" not in text and "upstream" not in text
    assert "2.4.3" not in text
    assert "widget_count" not in text and "widget_total" not in text
    assert "widget_table overflow" not in text  # renamed inside the string literal too
    assert "#include <string.h>" in text  # system headers left alone
    assert "memcpy" not in text or "memcpy" in text  # reserved names are never renamed
    assert out.file_map["widget_table.c"] != "widget_table.c"


def test_numeric_literals_are_not_renamed():
    # `0x7ff00000` contains `x7ff00000`, which looks exactly like an identifier unless
    # the match is forbidden from starting after a digit. Two corpora passed the gate
    # before one with lettered hex constants turned `0x7ff00000` into `0nexirn`.
    source = (
        "int widget_mask(unsigned v) { return (v & 0xffff) | 0x7ff00000 | 0177 | 1e5; }\n"
        "int widget_two(void) { return 0; }\n"
    )
    assert deidentify.collect_identifiers({"a.c": source}) == {"widget_mask", "widget_two"}
    text = next(iter(deidentify.deidentify_tree({"a.c": source}, seed="t").files.values())).text
    for literal in ("0xffff", "0x7ff00000", "0177", "1e5"):
        assert literal in text, literal


def test_reserved_and_short_identifiers_are_left_alone():
    source = 'int scratch_dup(size_t n) { char *p = malloc(n); memcpy(p, "x", 1); return errno; }\n'
    out = deidentify.deidentify_tree({"a.c": source}, seed="t")
    text = next(iter(out.files.values())).text
    for name in ("size_t", "malloc", "memcpy", "errno", "int", "char"):
        assert name in text
    assert " n)" in text and "*p" in text  # one-letter locals keep their names
    assert "scratch_dup" not in text  # but a real project identifier does not


def test_local_includes_are_rewritten_to_the_renamed_file():
    files = {
        "a.c": '#include "b.h"\nint alpha(void) { return beta(); }\n',
        "b.h": "int beta(void);\n",
    }
    out = deidentify.deidentify_tree(files, seed="t")
    renamed_header = Path(out.file_map["b.h"]).name
    body = out.files[out.file_map["a.c"]].text
    assert f'#include "{renamed_header}"' in body
    assert "beta" not in body


def test_a_line_comment_does_not_swallow_the_rest_of_the_file():
    # The defect this exists for: a `//` comment was treated as an unterminated `/*`
    # block, so every following line was deleted. Two corpora using only /* */ passed
    # while the first file with // comments in it lost 40 lines.
    source = (
        "int alpha_one(void) {\n"
        "  // makes a copy of the input\n"
        "  return beta_two();\n"
        "}\n"
        "int beta_two(void) { return 7; }  // trailing\n"
        "int gamma_three(void) { return 8; }\n"
    )
    out = deidentify.deidentify_tree({"a.c": source}, seed="t")
    text = next(iter(out.files.values())).text
    assert text.count("return") == 3, text
    assert "makes a copy" not in text
    # Five of six source lines survive: the comment-only line is dropped, everything
    # after it is kept, and the map still points at the right source lines.
    surviving = out.files[next(iter(out.files))].line_map
    assert surviving == [1, 3, 4, 5, 6]


def test_a_real_block_comment_still_spans_lines():
    source = (
        "int alpha_one(void) {\n"
        "  /* this comment\n"
        "     runs across lines\n"
        "     and ends here */\n"
        "  return 1;\n"
        "}\n"
        "int beta_two(void) { return 2; }\n"
    )
    out = deidentify.deidentify_tree({"a.c": source}, seed="t")
    text = next(iter(out.files.values())).text
    assert "runs across lines" not in text
    assert text.count("return") == 2, text


def test_the_line_map_survives_comment_removal():
    source = "/* banner */\nint alpha(void) {\n  /* note */\n  return 1;\n}\n"
    out = deidentify.deidentify_text(source, {"alpha": "zeta"})
    assert out.text.splitlines() == ["int zeta(void) {", "  return 1;", "}"]
    assert out.map_line(2) == 1  # the definition moved up one line
    assert out.map_line(4) == 2
    with pytest.raises(deidentify.DeidError, match="does not survive"):
        out.map_line(3)  # the comment-only line is gone, and that is an error to anchor on


def test_the_mapping_is_deterministic_for_a_seed_and_differs_across_seeds():
    a = deidentify.deidentify_tree({"a.c": SAMPLE}, seed="one")
    b = deidentify.deidentify_tree({"a.c": SAMPLE}, seed="one")
    c = deidentify.deidentify_tree({"a.c": SAMPLE}, seed="two")
    assert a.identifier_map == b.identifier_map
    assert a.identifier_map != c.identifier_map


def test_an_empty_tree_is_refused():
    with pytest.raises(deidentify.DeidError, match="no files"):
        deidentify.deidentify_tree({}, seed="t")


def test_a_tree_with_no_renameable_identifiers_is_refused():
    with pytest.raises(deidentify.DeidError, match="zero identifiers"):
        deidentify.deidentify_tree({"a.c": "int f(int n) { return n; }\n"}, seed="t")


def test_a_project_word_inside_a_string_is_renamed_even_though_it_is_not_an_identifier():
    # The leak this closes: "widgetlib: bad slot" gives the project away while
    # `widgetlib` never appears as an identifier on its own. It is a segment of many
    # identifiers, and that is the signal used.
    files = {
        "a.c": (
            'static const char *msg = "widgetlib: bad slot";\n'
            "int widget_load(void) { return widget_count() + widget_total(); }\n"
            "int widget_count(void) { return 1; }\n"
            "int widget_total(void) { return 2; }\n"
        )
    }
    out = deidentify.deidentify_tree(files, seed="t")
    text = next(iter(out.files.values())).text
    assert "widget" not in text.lower()
    assert "bad slot" in text  # ordinary words in the message are left alone


def test_a_one_off_word_in_a_string_is_left_alone():
    files = {
        "a.c": (
            'static const char *msg = "checksum mismatch";\n'
            "int gadget_load(void) { return gadget_count(); }\n"
            "int gadget_count(void) { return 1; }\n"
        )
    }
    out = deidentify.deidentify_tree(files, seed="t")
    text = next(iter(out.files.values())).text
    assert "checksum mismatch" in text
    assert "gadget" not in text.lower()


def test_preprocessor_directives_are_never_renamed():
    files = {
        "a.h": "#ifndef WIDGET_GUARD_H\n#define WIDGET_GUARD_H\nint widget_go(void);\n#endif\n",
        "a.c": '#include "a.h"\n#pragma once\nint widget_go(void) { return 0; }\n',
    }
    out = deidentify.deidentify_tree(files, seed="t")
    text = "\n".join(f.text for f in out.files.values())
    for directive in ("#ifndef", "#define", "#endif", "#include", "#pragma"):
        assert directive in text, directive
    assert "WIDGET_GUARD_H" not in text


def test_string_scrub_rules_apply_after_renaming():
    out = deidentify.deidentify_tree(
        {"a.c": 'const char *v = "libwidget 1.2.3";\nint widget_go(void){return 0;}\n'},
        seed="t",
        string_scrub=[(r"libwidget \d+\.\d+\.\d+", "libtelemetry 0.1.0")],
    )
    text = next(iter(out.files.values())).text
    assert "libtelemetry 0.1.0" in text and "libwidget" not in text


# ------------------------------------------------------------------- recipes


def test_the_shipped_sigil_recipe_validates():
    loaded = recipe.load(SIGIL)
    counts = recipe.counts(loaded)
    assert counts["bugs"] >= 3
    assert counts["decoys"] >= 2
    assert set(counts["by_difficulty"]) == set(recipe.DIFFICULTIES)


def sigil_recipe():
    return json.loads(SIGIL.read_text(encoding="utf-8"))


@pytest.mark.parametrize(
    ("mutate", "match"),
    [
        (lambda r: r.update(bugs=[]), "zero injected bugs"),
        (lambda r: r.update(decoys=[]), "zero decoys"),
        (lambda r: r.update(entry_points=[]), "entry_points is empty"),
        (lambda r: r["bugs"][0].update(bug_class="not-a-real-class"), "not in the catalogue"),
        (lambda r: r["bugs"][0].update(difficulty="TRIVIAL"), "difficulty must be one of"),
        (lambda r: r["bugs"][0].update(mechanism_all_of=[]), "non-empty list of term groups"),
        (lambda r: r["bugs"][0].update(call_path=[]), "non-empty list of edges"),
        (
            lambda r: r["bugs"][0].update(call_path=[{"from": "nobody", "to": "x"}]),
            "not a declared entry point",
        ),
        (lambda r: r["decoys"][0].update(decoy_kind="handwave"), "not one of"),
        (lambda r: r["decoys"][0].update(safe_because="because"), "safe_because"),
        (lambda r: r["decoys"][1].update(id=r["decoys"][0]["id"]), "duplicate patch id"),
        (lambda r: r["build"].update(cflags=["-O1"]), "implicit-function-declaration"),
        (lambda r: r["deidentify"].update(required=None), "must be true or false"),
        (
            lambda r: r["deidentify"].update(required=False, not_required_because="no"),
            "not_required_because",
        ),
        (lambda r: r.update(tier="enormous"), "tier must be one of"),
        (lambda r: r["bugs"][0].update(replacement=r["bugs"][0]["anchor"]), "identical"),
        (lambda r: r["bugs"][0].update(site_marker="not in the replacement"), "site_marker"),
    ],
)
def test_every_recipe_defect_is_rejected(mutate, match):
    broken = sigil_recipe()
    mutate(broken)
    with pytest.raises(recipe.RecipeError, match=match):
        recipe.validate(broken)


def test_a_tarball_base_needs_a_full_digest():
    broken = sigil_recipe()
    broken["base"] = {
        "kind": "tarball",
        "url": "https://example.org/x.tar.gz",
        "sha256": "abc",
        "files": ["*.c"],
    }
    with pytest.raises(recipe.RecipeError, match="64-hex"):
        recipe.validate(broken)


def test_patch_bodies_may_be_written_as_line_lists():
    loaded = recipe.load(SIGIL)
    assert "\n" in loaded["bugs"][0]["anchor"]
    assert not isinstance(loaded["bugs"][0]["anchor"], list)


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-q"]))
