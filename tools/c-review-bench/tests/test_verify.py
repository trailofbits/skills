#!/usr/bin/env python3
"""Tests for the corpus integrity gate.

The gate is the piece most likely to rot into a tick that means nothing, so it is
tested from both directions: the shipped corpus must pass, and a corpus broken in
each specific way must fail *that* check and not merely fail somewhere.

`test_a_vacuous_check_fails_the_gate` is the D14 regression: a check that inspected
zero items reported success in a previous version of this repository while a reviewer
was openly declaring it had fetched upstream.

The three tests that build a corpus need a C compiler. They are skipped without one,
which is why the checks' logic is also tested directly on synthetic manifests — those
run everywhere.
"""

from __future__ import annotations

import json
import shutil
import sys
from pathlib import Path

import pytest

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))

from lib import corpus as corpus_mod  # noqa: E402
from lib import recipe as recipe_mod  # noqa: E402
from lib import verify  # noqa: E402

SIGIL = HERE.parent / "corpora" / "sigil" / "recipe.json"
needs_cc = pytest.mark.skipif(
    shutil.which("cc") is None, reason="the compile gate needs a C compiler"
)


# ----------------------------------------------------------------- the verdict


def test_a_vacuous_check_fails_the_gate():
    assert verify.verdict([verify.Check("x", ok=True, inspected=3)]) is True
    assert verify.verdict([verify.Check("x", ok=True, inspected=0)]) is False
    assert verify.verdict([verify.Check("x", ok=False, inspected=3)]) is False


def test_zero_checks_raises_rather_than_passing():
    with pytest.raises(verify.VerifyError, match="zero checks"):
        verify.verdict([])


def test_a_vacuous_check_says_so_in_its_line():
    assert "VACUOUS" in verify.Check("x", ok=True, inspected=0).line()


# ------------------------------------------------------ checks over manifests


def manifest(**extra):
    base = {
        "variant": "bench",
        "source_files": ["src/a.c"],
        "lines_of_code": 100,
        "items": [
            {
                "id": "B1",
                "file": "src/a.c",
                "line": 40,
                "function": "decode",
                "bug_class": "off-by-one",
                "difficulty": "EASY",
                "mechanism": "the loop writes one element past the end of the array",
                "attacker_control": "the length byte",
                "mechanism_all_of": [["past the end", "off-by-one"], ["loop", "array"]],
            }
        ],
        "decoys": [
            {
                "id": "D1",
                "decoy_kind": "extra-init",
                "file": "src/a.c",
                "line": 10,
                "safe_because": "x" * 30,
            }
        ],
        "file_sha256": {"src/a.c": "aaa", "src/b.c": "bbb"},
    }
    base.update(extra)
    return base


def test_a_decoy_sharing_a_function_with_a_bug_fails_the_decoy_check():
    good = verify.check_decoys(manifest(), recipe_mod.load(SIGIL))
    assert good.ok and good.inspected == 1

    same_function = manifest()
    same_function["decoys"][0]["function"] = "decode"  # the bug's function
    bad = verify.check_decoys(same_function, recipe_mod.load(SIGIL))
    assert not bad.ok
    assert "which also holds a bug" in bad.problems[0]

    adjacent = manifest()
    adjacent["decoys"][0]["line"] = 42  # two lines from the bug at 40
    bad = verify.check_decoys(adjacent, recipe_mod.load(SIGIL))
    assert not bad.ok
    assert "line(s) from a bug site" in bad.problems[0]


def test_a_keyword_group_that_cannot_match_its_own_mechanism_fails(tmp_path):
    tree = tmp_path / "t"
    (tree / "src").mkdir(parents=True)
    (tree / "src" / "a.c").write_text(
        "\n" * 39 + "int decode(void) { return 0; }\n", encoding="utf-8"
    )
    assert verify.check_ground_truth(tree, manifest()).ok

    stale = manifest()
    stale["items"][0]["mechanism_all_of"] = [["a term nobody would write"]]
    bad = verify.check_ground_truth(tree, stale)
    assert not bad.ok
    assert "its own mechanism text does not match" in bad.problems[0]


def test_a_ground_truth_line_outside_the_file_fails(tmp_path):
    tree = tmp_path / "t"
    (tree / "src").mkdir(parents=True)
    (tree / "src" / "a.c").write_text("int decode(void) { return 0; }\n", encoding="utf-8")
    bad = verify.check_ground_truth(tree, manifest())
    assert not bad.ok
    assert "outside" in bad.problems[0]


def test_variants_must_differ_in_exactly_the_bug_files():
    bench = manifest()
    control = manifest(file_sha256={"src/a.c": "zzz", "src/b.c": "bbb"})
    assert verify.check_variants(bench, control).ok

    identical = manifest(file_sha256={"src/a.c": "aaa", "src/b.c": "bbb"})
    same = verify.check_variants(bench, identical)
    assert not same.ok
    assert "identical in the control tree" in same.problems[0]

    drifted = manifest(file_sha256={"src/a.c": "zzz", "src/b.c": "ccc"})
    extra = verify.check_variants(bench, drifted)
    assert not extra.ok
    assert "holds no bug" in " ".join(extra.problems)


def test_a_new_compiler_warning_fails_the_warning_check():
    assert verify.check_warnings({"a: x"}, {"a: x"}, inspected=2).ok
    announced = verify.check_warnings({"a: x", "a: y"}, {"a: x"}, inspected=2)
    assert not announced.ok
    assert "announces itself" in announced.problems[0]


def test_a_fetched_corpus_may_not_skip_de_identification(tmp_path):
    broken = json.loads(SIGIL.read_text(encoding="utf-8"))
    broken["base"] = {"kind": "tarball", "url": "u", "sha256": "0" * 64, "files": ["*.c"]}
    check = verify.check_deidentified(tmp_path, manifest(), broken, tmp_path)
    assert not check.ok
    assert "only an authored corpus" in check.problems[0]


def test_missing_behaviour_check_and_missing_justification_is_vacuous(tmp_path):
    bare = {"build": {}, "decoys": []}
    check = verify.check_behaviour(tmp_path, bare, "bench", timeout=5)
    assert check.vacuous and not check.ok
    excused = {
        "build": {},
        "decoys": [],
        "decoys_unverified_because": "no runnable entry point exists",
    }
    check = verify.check_behaviour(tmp_path, excused, "bench", timeout=5)
    assert check.ok and not check.vacuous


# --------------------------------------------------------------- integration


@pytest.fixture(scope="module")
def gate_result(tmp_path_factory):
    return verify.gate(
        recipe_mod.load(SIGIL), tmp_path_factory.mktemp("sigil"), allow_network=False
    )


@needs_cc
def test_the_shipped_corpus_passes_every_check(gate_result):
    failures = [c for c in gate_result["_checks"] if not c.ok or c.vacuous]
    assert gate_result["verified"] is True, [c.line() for c in failures]
    assert {c.name for c in gate_result["_checks"]} >= {
        "compile[bench]",
        "compile[control]",
        "behaviour[bench]",
        "behaviour[control]",
        "warnings",
        "reachability",
        "decoys",
        "deidentified",
        "ground_truth",
        "variants",
    }
    assert all(c.inspected > 0 for c in gate_result["_checks"])


@needs_cc
def test_the_ground_truth_lines_point_at_the_injected_code(gate_result):
    private = Path(gate_result["workdir"]) / "bench-private"
    ground_truth = corpus_mod.load_ground_truth(private)
    tree = Path(gate_result["workdir"]) / "bench"
    assert len(ground_truth["items"]) == len(recipe_mod.load(SIGIL)["bugs"])
    for item in ground_truth["items"]:
        line = (tree / item["file"]).read_text(encoding="utf-8").splitlines()[item["line"] - 1]
        assert line.strip(), item
    control = corpus_mod.load_ground_truth(Path(gate_result["workdir"]) / "control-private")
    assert all(item["present"] is False for item in control["items"])


@needs_cc
def test_an_injection_the_compiler_points_at_fails_the_gate(tmp_path):
    # A bug that -Wall flags is not a hidden bug: any arm that compiles the corpus is
    # handed the answer, so the gate must refuse it.
    loud = json.loads(SIGIL.read_text(encoding="utf-8"))
    loud["_dir"] = str(SIGIL.parent)
    loud["bugs"] = [
        {
            "id": "LOUD-1",
            "bug_class": "off-by-one",
            "difficulty": "EASY",
            "file": "src/group.c",
            "function": "sgl_group_walk",
            "mechanism": "an unused variable is introduced next to an off-by-one on the loop bound",
            "attacker_control": "the group header bytes",
            "mechanism_all_of": [["off-by-one", "past the end"], ["loop", "bound"]],
            "call_path": [{"from": "sgl_feed", "to": "sgl_group_walk"}],
            "anchor": "  size_t off = 0;",
            "replacement": "  size_t off = 0;\n  int unused_scratch;",
            "site_marker": "  int unused_scratch;",
        }
    ]
    result = verify.gate(recipe_mod.validate(loud), tmp_path / "loud", allow_network=False)
    warnings = next(c for c in result["_checks"] if c.name == "warnings")
    assert result["verified"] is False
    assert not warnings.ok
    assert any("unused" in p.lower() for p in warnings.problems)


@needs_cc
def test_an_injection_that_breaks_benign_input_fails_the_gate(tmp_path):
    # The bugs have to be latent. One that breaks the smoke test would be caught by
    # any test suite, so measuring an arm against it measures nothing.
    obvious = json.loads(SIGIL.read_text(encoding="utf-8"))
    obvious["_dir"] = str(SIGIL.parent)
    obvious["bugs"] = [
        {
            "id": "OBVIOUS-1",
            "bug_class": "off-by-one",
            "difficulty": "EASY",
            "file": "src/frame.c",
            "function": "sgl_frame_parse",
            "mechanism": "the header length check is off by one so every valid frame is rejected",
            "attacker_control": "the frame bytes",
            "mechanism_all_of": [["off-by-one", "off by one"], ["header", "length"]],
            "call_path": [{"from": "sgl_feed", "to": "sgl_frame_parse"}],
            "anchor": "  if (len < SGL_HEADER_LEN) {",
            "replacement": "  if (len < SGL_HEADER_LEN * 4) {",
            "site_marker": "  if (len < SGL_HEADER_LEN * 4) {",
        }
    ]
    result = verify.gate(recipe_mod.validate(obvious), tmp_path / "obvious", allow_network=False)
    behaviour = next(c for c in result["_checks"] if c.name == "behaviour[bench]")
    assert result["verified"] is False
    assert not behaviour.ok


# --------------------------------------------- the grader's negative control
#
# `check_ground_truth` is the positive control: a bug's own description must satisfy its
# own keyword groups. This is the other half, and it was missing — with the consequence
# that one finding could be scored as having found two bugs.


def _twin(first, **extra):
    twin = dict(first)
    twin.update(extra)
    return twin


def test_keyword_groups_that_cannot_tell_two_co_located_bugs_apart_fail():
    first = manifest()["items"][0]
    second = _twin(
        first,
        id="B2",
        bug_class="unbounded-copy",
        # Loose enough to be satisfied by B1's own description of a different bug.
        mechanism_all_of=[["past the end", "unbounded"], ["loop", "copy"]],
        mechanism="the copy is not clamped so it runs past the end of the loop's array",
        line=42,
    )
    check = verify.check_mechanism_discrimination(manifest(items=[first, second]), window=12)
    assert not check.ok
    assert check.inspected == 2
    assert any("would be scored as having found" in p for p in check.problems)


def test_discriminating_groups_over_co_located_bugs_pass():
    first = manifest()["items"][0]
    second = _twin(
        first,
        id="B2",
        bug_class="toctou-race",
        mechanism=(
            "the existence test and the create are two steps, so a symlink can land between them"
        ),
        attacker_control="the filesystem",
        mechanism_all_of=[["symlink", "toctou"], ["existence test", "o_excl"]],
        line=42,
    )
    check = verify.check_mechanism_discrimination(manifest(items=[first, second]), window=12)
    assert check.ok, check.problems
    assert check.inspected == 2


def test_bugs_in_different_functions_and_far_apart_are_not_compared():
    """Two bugs the grader can never confuse need no discrimination, and a corpus whose
    bugs are all in distinct functions must not fail for having zero pairs to check. The
    unit of inspection is the item, so the vacuity guard still means something."""
    first = manifest()["items"][0]
    second = _twin(
        first, id="B2", function="other", line=400, mechanism_all_of=[["past the end"], ["loop"]]
    )
    check = verify.check_mechanism_discrimination(manifest(items=[first, second]), window=12)
    assert check.ok
    assert check.inspected == 2
    assert "0 co-located ordered pair(s)" in check.detail


def test_a_ground_truth_with_no_items_is_vacuous_here_too():
    check = verify.check_mechanism_discrimination(manifest(items=[]), window=12)
    assert check.vacuous


@needs_cc
def test_building_the_same_corpus_twice_emits_the_same_bytes(tmp_path):
    """Non-deterministic injection or renaming would make two runs incomparable, and the
    corpus is rebuilt on every machine that runs the gate. Sources, ground truth and the
    identifier map all have to come out identical — the stamp's `tree_sha256` is the field a
    reader would trust, so it is the one asserted."""
    first = verify.gate(recipe_mod.load(SIGIL), tmp_path / "one", allow_network=False)
    second = verify.gate(recipe_mod.load(SIGIL), tmp_path / "two", allow_network=False)
    assert first["verified"] and second["verified"]
    assert first["tree_sha256"] == second["tree_sha256"]
    assert first["counts"] == second["counts"]
    assert first["lines_of_code"] == second["lines_of_code"]
    for variant in ("bench", "control"):
        for name in ("ground_truth.json", "maps.json"):
            a = (tmp_path / "one" / f"{variant}-private" / name).read_text(encoding="utf-8")
            b = (tmp_path / "two" / f"{variant}-private" / name).read_text(encoding="utf-8")
            # The emitted tree path is the one legitimate difference between two workdirs.
            assert a.replace(str(tmp_path / "one"), "") == b.replace(str(tmp_path / "two"), "")


@needs_cc
def test_the_shipped_corpora_discriminate(tmp_path):
    """The check has to hold on the corpora that ship, not just on synthetic manifests.
    It failed on `zstream` when it was written, which is why the recipe changed."""
    result = verify.gate(recipe_mod.load(SIGIL), tmp_path / "sigil", allow_network=False)
    check = next(c for c in result["_checks"] if c.name == "mechanism_discrim")
    assert check.ok, check.problems
    assert check.inspected == 17
    assert not check.vacuous


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-q"]))
