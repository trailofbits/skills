#!/usr/bin/env python3
"""Tests for the review-unit enumerator.

The pure-logic half imports enumerate_units directly: `make python-tests` runs under
`uv run --no-project`, which does not install the PEP 723 dependencies, and the script
imports tree-sitter lazily so everything below stays reachable without it.

The parser half runs the script as a subprocess under `uv run`, which does install them.
It fails rather than skips when uv is missing: a parser test that quietly inspects
nothing is exactly the zero-item pass AGENTS.md forbids.
"""

from __future__ import annotations

import json
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent))

from enumerate_units import (  # noqa: E402
    QUESTIONS,
    SITE_KINDS,
    contiguous_ranges,
    default_agent_count,
    discover_sources,
    main,
    pack_assignments,
    required_questions,
    split_span,
)

SCRIPT = Path(__file__).parent / "enumerate_units.py"


# ------------------------------------------------------------------- split_span


def assert_tiles(chunks: list[tuple[int, int]], start: int, end: int, cap: int) -> None:
    """Chunks must tile [start, end] with no gap, no overlap and nothing over the cap.

    A gap is a line no agent owns, the one thing the location partition cannot allow;
    an overlap double-bills a line against the ledger.
    """
    assert chunks, f"split_span({start}, {end}) returned nothing; every line must be owned"
    assert (chunks[0][0], chunks[-1][1]) == (start, end)
    for first, last in chunks:
        assert first <= last, f"empty or inverted chunk {(first, last)}"
        assert last - first + 1 <= cap, f"chunk {(first, last)} exceeds the {cap}-line cap"
    for (_, prev_end), (next_start, _) in zip(chunks, chunks[1:]):
        assert next_start == prev_end + 1, f"gap or overlap at {prev_end} -> {next_start}"


def scattered(start: int, end: int, count: int, step: int) -> list[int]:
    """Deterministic pseudo-scattered seams: unsorted, duplicated, some out of range."""
    return [start - 5 + (i * step) % (end - start + 11) for i in range(count)]


def test_span_at_or_under_the_cap_is_a_single_chunk():
    assert split_span(10, 40, [12, 20, 33], 50) == [(10, 40)]
    assert split_span(1, 20, [], 20) == [(1, 20)]
    assert split_span(7, 7, [7], 20) == [(7, 7)]


@pytest.mark.parametrize(
    ("start", "end", "seams", "cap"),
    [
        (1, 1, [], 20),
        (1, 21, [], 20),
        (5, 500, [5, 500], 20),
        (10, 410, [10, 11, 409, 410, 999, -3], 50),
        (100, 137, [110, 120], 20),
        (1, 1000, scattered(1, 1000, 40, 137), 60),
        (1, 1000, scattered(1, 1000, 7, 991), 25),
        (1, 1000, scattered(1, 1000, 200, 3), 40),
    ],
)
def test_chunks_tile_the_span(start, end, seams, cap):
    assert_tiles(split_span(start, end, seams, cap), start, end, cap)


def test_seam_free_oversized_span_hard_splits_on_line_count():
    chunks = split_span(1, 250, [], 100)
    assert chunks == [(1, 100), (101, 200), (201, 250)]
    assert_tiles(chunks, 1, 250, 100)


def test_seams_drive_the_cut_when_they_are_far_enough_apart():
    # 150 is dropped: only 49 lines past the previous boundary, so honouring it would
    # shred the function into slivers far under the cap.
    assert split_span(1, 300, [101, 150, 201], 100) == [(1, 100), (101, 200), (201, 300)]


def test_seam_delimited_chunk_over_the_cap_is_hard_split_not_emitted_oversized():
    # The seam at 121 delimits [1, 120] and [121, 400]; both still exceed the cap.
    chunks = split_span(1, 400, [121], 100)
    assert chunks == [(1, 100), (101, 120), (121, 220), (221, 320), (321, 400)]
    assert_tiles(chunks, 1, 400, 100)


def test_only_seams_inside_the_span_are_usable():
    # `start` is not usable (it would open an empty chunk) and neither is anything past
    # `end`; with all five discarded this falls back to the hard split. A seam on the
    # last line is usable and yields a one-line final chunk.
    assert split_span(50, 200, [1, 49, 50, 201, 500], 100) == [(50, 149), (150, 200)]
    assert split_span(1, 300, [300], 100) == [(1, 100), (101, 200), (201, 299), (300, 300)]


# -------------------------------------------------------------- pack_assignments


def make_units(*counts: int) -> list[dict]:
    return [{"id": f"u{i:02d}", "file": "src/f.c", "lines": n} for i, n in enumerate(counts)]


def assert_partition(buckets: list[dict], units: list[dict]) -> None:
    """Every unit in exactly one bucket, buckets contiguous in input order, none empty."""
    flat = [uid for bucket in buckets for uid in bucket["unit_ids"]]
    assert flat == [u["id"] for u in units], "units dropped, duplicated or reordered"
    assert all(b["unit_ids"] for b in buckets), "an empty bucket was emitted"
    assert [b["id"] for b in buckets] == [f"unit-{i + 1:02d}" for i in range(len(buckets))]
    assert all(b["unit_count"] == len(b["unit_ids"]) for b in buckets)


def test_even_units_split_into_the_requested_number_of_buckets():
    units = make_units(*([100] * 8))
    buckets = pack_assignments(units, 4)
    assert_partition(buckets, units)
    assert [b["total_lines"] for b in buckets] == [200, 200, 200, 200]


def test_one_giant_unit_does_not_starve_the_other_buckets():
    """The giant gets its own agent and does not swallow the small units.

    Asserts the property, not a bucket count. `pack_assignments` folds a trailing runt
    into its neighbour rather than spending a whole agent on a handful of lines, so
    1000+1+1+1+1 over three agents is correctly two buckets, not three.
    """
    units = make_units(1000, 1, 1, 1, 1)
    buckets = pack_assignments(units, 3)
    assert_partition(buckets, units)
    assert len(buckets) >= 2, "the giant absorbed every other unit"
    giant = next(b for b in buckets if "u00" in b["unit_ids"])
    assert giant["unit_ids"] == ["u00"], "small units were packed in behind the giant"


@pytest.mark.parametrize(("agents", "expected"), [(10, 3), (3, 3), (1, 1), (0, 1), (-3, 1)])
def test_agent_count_outside_the_unit_count_degrades_gracefully(agents, expected):
    units = make_units(10, 10, 10)
    buckets = pack_assignments(units, agents)
    assert_partition(buckets, units)
    assert len(buckets) == expected


# ------------------------------------------------------------ required_questions


def sites(**populated: list[int]) -> dict[str, list[int]]:
    base: dict[str, list[int]] = {kind: [] for kind in SITE_KINDS}
    base.update(populated)
    return base


@pytest.mark.parametrize("qid", [q for q in QUESTIONS if q != "caller-contract"])
def test_question_is_required_exactly_when_its_population_is_non_empty(qid):
    for kind in QUESTIONS[qid][1]:
        assert required_questions(sites(**{kind: [7]}), is_function=False) == [qid]
    assert qid not in required_questions(sites(), is_function=False)


def test_a_file_scope_unit_owes_no_rows_for_empty_populations():
    assert required_questions(sites(), is_function=False) == []
    assert "caller-contract" not in required_questions(sites(param=[3]), is_function=False)


def test_caller_contract_is_owed_by_every_function_even_with_no_parameters():
    assert required_questions(sites(), is_function=True) == ["caller-contract"]
    assert required_questions(sites(param=[3]), is_function=True) == ["caller-contract"]


# ------------------------------------------------------------ contiguous_ranges


def test_contiguous_ranges_collapses_runs_and_keeps_gaps():
    assert contiguous_ranges([1, 2, 3, 7, 8, 20]) == [[1, 3], [7, 8], [20, 20]]
    assert contiguous_ranges([5, 7, 9]) == [[5, 5], [7, 7], [9, 9]]
    assert contiguous_ranges([5]) == [[5, 5]]
    assert contiguous_ranges([]) == []


# ----------------------------------------------------------------- discovery

SOURCES = ("build/gen.c", "src/a.c", "src/b.h", "src/deep/c.cpp", "src/upper.CPP")
NON_SOURCES = (".git/evil.c", "node_modules/pkg/index.c", "notes.txt", "src/readme.md")


@pytest.fixture
def tree(tmp_path: Path) -> Path:
    for rel in SOURCES + NON_SOURCES:
        path = tmp_path / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("int x;\n", encoding="utf-8")
    return tmp_path


def rels(paths: list[Path], root: Path) -> list[str]:
    return [str(p.relative_to(root)) for p in paths]


def test_discover_sources_finds_c_and_cpp_and_skips_vcs_and_vendor(tree):
    found = rels(discover_sources(tree, []), tree)
    assert found == sorted(SOURCES), "wrong set, or not returned in sorted order"


def test_discover_sources_honours_glob_and_substring_excludes(tree):
    assert "build/gen.c" not in rels(discover_sources(tree, ["build/*"]), tree)
    assert "src/deep/c.cpp" not in rels(discover_sources(tree, ["deep"]), tree)
    assert discover_sources(tree, ["build/*", "src"]) == []


# ---------------------------------------------------------- default_agent_count


@pytest.mark.parametrize(
    ("total_lines", "expected"),
    [(0, 4), (-5, 4), (1, 4), (800, 4), (3200, 4), (3201, 5), (11200, 14), (100000, 14)],
)
def test_default_agent_count_clamps_at_both_ends(total_lines, expected):
    assert default_agent_count(total_lines, 800, 4, 14) == expected


# --------------------------------------------------------------- failure modes


def test_main_fails_when_the_root_holds_no_sources(tmp_path, capsys):
    (tmp_path / "readme.md").write_text("no code here\n", encoding="utf-8")
    out = tmp_path / "run"
    assert main(["--root", str(tmp_path), "--out-dir", str(out)]) == 2
    assert "no C/C++ source files" in capsys.readouterr().err
    assert not out.exists(), "an empty partition must not leave a units.json behind"


def test_main_fails_when_the_root_is_not_a_directory(tmp_path, capsys):
    lone = tmp_path / "lonely.c"
    lone.write_text("int main(void) { return 0; }\n", encoding="utf-8")
    assert main(["--root", str(lone), "--out-dir", str(tmp_path / "run")]) == 2
    assert "not a directory" in capsys.readouterr().err


def test_main_rejects_a_cap_too_small_to_be_a_review_unit(tmp_path, capsys):
    argv = ["--root", str(tmp_path), "--out-dir", str(tmp_path / "run"), "--max-unit-lines", "19"]
    assert main(argv) == 2
    assert "below 20" in capsys.readouterr().err


# ---------------------------------------------------- the real parse, via uv

SMALL_C = """\
#include <stdlib.h>
#include <string.h>

#define SQUARE(x) ((x) * (x))

int g_counter = 0;

void copy_thing(const char *name, unsigned n) {
    char *buf = malloc(n + 1);
    memcpy(buf, name, n);
    strcpy(buf, name);
    g_counter++;
    free(buf);
}
"""


def _big_c() -> str:
    # A switch-based function far over a 20-line cap, with 12-line case bodies.
    lines = ["int dispatch(int op, int *out) {", "    int acc = 0;", "    switch (op) {"]
    for case in range(3):
        lines.append(f"    case {case}:")
        lines += [f"        acc += {case} * {i};" for i in range(12)]
        lines.append("        break;")
    lines += ["    }", "    *out = acc;", "    return acc;", "}"]
    return "\n".join(lines) + "\n"


BIG_C = _big_c()


def line_of(text: str, needle: str) -> int:
    for number, line in enumerate(text.splitlines(), start=1):
        if needle in line:
            return number
    raise AssertionError(f"fixture no longer contains {needle!r}")


@pytest.fixture(scope="module")
def parsed(tmp_path_factory):
    uv = shutil.which("uv")
    if uv is None:
        pytest.fail(
            "uv is not on PATH, so the only tests that exercise the real tree-sitter parse "
            "cannot run. Install uv instead of skipping: a skipped parser test leaves half of "
            "enumerate_units.py inspecting nothing while the suite reports green."
        )
    root = tmp_path_factory.mktemp("scope")
    (root / "src").mkdir()
    (root / "src" / "small.c").write_text(SMALL_C, encoding="utf-8")
    (root / "src" / "big.c").write_text(BIG_C, encoding="utf-8")
    out = tmp_path_factory.mktemp("run")
    argv = [uv, "run", "--no-project", str(SCRIPT), "--root", str(root)]
    argv += ["--out-dir", str(out), "--max-unit-lines", "20"]
    proc = subprocess.run(argv, capture_output=True, text=True, check=False)
    assert proc.returncode == 0, f"enumerate_units failed:\n{proc.stderr}"
    doc = json.loads((out / "units.json").read_text(encoding="utf-8"))
    assert doc["units"], "the parse produced no units; every assertion below would be vacuous"
    return {"root": root, "out": out, "doc": doc, "proc": proc}


def units_of(parsed, function: str) -> list[dict]:
    found = [u for u in parsed["doc"]["units"] if u["function"] == function]
    assert found, f"no unit for {function!r} in {[u['name'] for u in parsed['doc']['units']]}"
    return found


def test_parser_run_writes_units_and_assigns_every_unit_once(parsed):
    assert parsed["proc"].returncode == 0
    assert (parsed["out"] / "units.json").is_file()
    first = json.loads((parsed["out"] / "assignments" / "unit-01.json").read_text())
    assert first["assignment_id"] == "unit-01"
    assert first["units"] and first["max_unit_lines"] == 20
    assigned = [uid for a in parsed["doc"]["assignments"] for uid in a["unit_ids"]]
    assert sorted(assigned) == sorted(u["id"] for u in parsed["doc"]["units"])
    assert parsed["doc"]["totals"]["checks_required"] > 0


def test_oversized_function_is_split_into_several_capped_units(parsed):
    parts = units_of(parsed, "dispatch")
    assert len(parts) > 1
    # `split` reads "seam" whenever the function had any seam at all, even for cuts made
    # on line count alone — see test_seam_split_does_not_cut_a_switch_case.
    assert {u["split"] for u in parts} == {"seam"}
    assert all(u["lines"] <= 20 for u in parts)
    expected = [f"dispatch [part {i + 1}/{len(parts)}]" for i in range(len(parts))]
    assert [u["name"] for u in parts] == expected


def test_alloc_and_release_calls_land_in_their_site_lists(parsed):
    unit = units_of(parsed, "copy_thing")[0]
    assert unit["parameters"] == ["const char *name", "unsigned n"]
    assert unit["sites"]["alloc"] == [line_of(SMALL_C, "malloc(")]
    assert unit["sites"]["release"] == [line_of(SMALL_C, "free(buf)")]
    assert line_of(SMALL_C, "memcpy(") in unit["sites"]["write"]
    assert line_of(SMALL_C, "strcpy(") in unit["sites"]["banned"]
    assert {"bounds", "alloc-lifetime", "banned-api"} <= set(unit["required_questions"])


def test_function_like_macro_is_owed_by_the_file_scope_unit(parsed):
    units = parsed["doc"]["units"]
    scope = next(u for u in units if u["kind"] == "file-scope" and u["file"].endswith("small.c"))
    assert scope["sites"]["macro"] == [line_of(SMALL_C, "#define SQUARE")]
    assert "macro-contract" in scope["required_questions"]
    assert "caller-contract" not in scope["required_questions"]
    covered = {n for a, b in scope["ranges"] for n in range(a, b + 1)}
    assert line_of(SMALL_C, "int g_counter") in covered, "the file-scope global is unowned"


def test_every_line_of_every_file_is_owned_exactly_once(parsed):
    for rel in parsed["doc"]["files"]:
        text = (parsed["root"] / rel).read_text(encoding="utf-8")
        owned: list[int] = []
        for unit in parsed["doc"]["units"]:
            if unit["file"] != rel:
                continue
            span = [[unit["start_line"], unit["end_line"]]]
            owned += [n for a, b in unit.get("ranges", span) for n in range(a, b + 1)]
        # Exactly the lines the file has, each once. A trailing newline terminates the
        # last line rather than starting another, so a newline-terminated file must not
        # hand a unit ownership of a line that does not exist.
        real_lines = text.count("\n") + (0 if not text or text.endswith("\n") else 1)
        assert sorted(owned) == list(range(1, real_lines + 1)), rel


def test_seam_split_does_not_cut_a_switch_case(parsed):
    """A state machine must not be cut through the middle of a case body.

    This regressed twice, in two different places, and each failure looked like the
    other. First, seam collection did not recurse: a function body is always a
    `compound_statement`, so one level of seams over `{ switch (x) { ... } }` yielded
    only the `switch` line and every case was invisible. Then, with the cases visible,
    boundary selection took the first seam a full cap away instead of the last seam
    that still fitted, skipped every nearer case, and hard-split the oversized
    remainder — landing back inside a case body by a different route.
    """
    seam_markers = ("int acc = 0;", "switch (op)", "*out = acc;", "return acc;")
    allowed = {line_of(BIG_C, f"case {i}:") for i in range(3)}
    allowed |= {line_of(BIG_C, marker) for marker in seam_markers}
    starts = [u["start_line"] for u in units_of(parsed, "dispatch")[1:]]
    assert set(starts) <= allowed, (
        f"chunks start at {sorted(set(starts) - allowed)}, which are inside a case body; "
        f"seam candidates were {sorted(allowed)}"
    )


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-q"]))
