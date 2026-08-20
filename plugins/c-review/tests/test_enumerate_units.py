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
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "scripts"))

from enumerate_units import (  # noqa: E402
    CPP_EXTS,
    QUESTIONS,
    SITE_KINDS,
    SOURCE_EXTS,
    EnumerateError,
    _substitute_outside_directives,
    assignment_unit,
    collect_object_macros,
    contiguous_ranges,
    default_agent_count,
    discover_sources,
    is_out_parameter,
    main,
    pack_assignments,
    required_questions,
    sites_by_id,
    split_span,
    write_outputs,
)

SCRIPT = Path(__file__).resolve().parent.parent / "scripts" / "enumerate_units.py"


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
    for (_, prev_end), (next_start, _) in zip(chunks, chunks[1:], strict=False):
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


@pytest.mark.parametrize("qid", list(QUESTIONS))
def test_question_is_required_exactly_when_its_population_is_non_empty(qid):
    for kind in QUESTIONS[qid][1]:
        assert required_questions(sites(**{kind: [7]})) == [qid]
    assert qid not in required_questions(sites())


def test_a_unit_with_no_sites_at_all_owes_no_rows():
    assert required_questions(sites()) == []


def test_caller_contract_is_not_owed_over_an_empty_population():
    """The rule is uniform, and that is the point.

    Owing `caller-contract` from every function whatever its shape gives a zero-parameter
    function a row whose owed population is EMPTY — closable with a verdict and nothing
    else, at 5% of every required check on a real corpus. The gate cannot falsify a row over
    a population nobody had to read anything to enumerate.
    """
    assert required_questions(sites()) == []
    assert required_questions(sites(param=[3])) == ["caller-contract"]


# ------------------------------------------------------------ contiguous_ranges


def test_contiguous_ranges_collapses_runs_and_keeps_gaps():
    assert contiguous_ranges([1, 2, 3, 7, 8, 20]) == [[1, 3], [7, 8], [20, 20]]
    assert contiguous_ranges([5, 7, 9]) == [[5, 5], [7, 7], [9, 9]]
    assert contiguous_ranges([5]) == [[5, 5]]
    assert contiguous_ranges([]) == []


# ----------------------------------------------------------------- discovery

SOURCES = (
    "build/gen.c",
    "src/a.c",
    "src/b.h",
    "src/deep/c.cpp",
    "src/upper.CPP",
    # `.inl` is the usual name for a C++ inline-implementation header. Leave it out of
    # SOURCE_EXTS and such files are enumerated by nobody, with exit 0.
    "src/tpl.inl",
    "src/latest.c",
    "src/protest.c",
)
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
    found, excluded, refused = discover_sources(tree, [])
    assert refused == []
    assert rels(found, tree) == sorted(SOURCES), "wrong set, or not returned in sorted order"
    assert excluded == []


def test_discover_sources_honours_glob_and_component_excludes(tree):
    """An exclude is a glob or a whole path component, never a bare substring.

    `--exclude test` matching as a substring also drops `src/latest.c` and `src/protest.c`,
    and nothing downstream reports that it did.
    """
    kept, excluded, _ = discover_sources(tree, ["build/*"])
    assert "build/gen.c" not in rels(kept, tree)
    assert excluded == ["build/gen.c"]
    assert "src/deep/c.cpp" not in rels(discover_sources(tree, ["deep"])[0], tree)
    assert discover_sources(tree, ["build/*", "src"])[0] == []

    kept, excluded, _ = discover_sources(tree, ["test"])
    assert "src/latest.c" in rels(kept, tree)
    assert "src/protest.c" in rels(kept, tree)
    assert excluded == []


def test_discover_sources_descends_through_a_symlinked_directory(tmp_path):
    """A symlinked subtree INSIDE the root is walked; `Path.rglob` skips it silently, so the
    walk is hand-rolled."""
    root = tmp_path / "root"
    (root / "src").mkdir(parents=True)
    (root / "src" / "m.c").write_text("int m;\n", encoding="utf-8")
    vendor = root / "third_party" / "vendorlib"
    vendor.mkdir(parents=True)
    (vendor / "v.c").write_text("int v;\n", encoding="utf-8")
    (root / "src" / "vendorlib").symlink_to(vendor, target_is_directory=True)
    found, _, _ = discover_sources(root, [])
    assert rels(found, root) == ["src/m.c", "third_party/vendorlib/v.c"]


def test_a_symlinked_subtree_outside_the_scope_root_is_refused_not_reviewed(tmp_path):
    """One containment rule for files and directories: what is reviewed is under the root.

    One rule for both, or the narrow case is fatal and the wide one silent: following
    `proj/vendor -> /elsewhere` while refusing `proj/src/shared.c -> ../common/shared.c` —
    in scope by both spellings — is exactly backwards. Out-of-root content parsed here is
    billed to an agent, given ledger rows, and has its findings filed at a path that exists
    only through the link.
    """
    root = tmp_path / "proj"
    (root / "src").mkdir(parents=True)
    (root / "src" / "m.c").write_text("int m;\n", encoding="utf-8")
    outside = tmp_path / "elsewhere"
    outside.mkdir()
    (outside / "v.c").write_text("int v;\n", encoding="utf-8")
    (root / "vendor").symlink_to(outside, target_is_directory=True)
    found, _, refused = discover_sources(root, [])
    assert rels(found, root) == ["src/m.c"], "out-of-root source became a review unit"
    assert refused and "outside the scope root" in refused[0], refused
    # And `--exclude` is the remedy the failure names, so it has to work.
    _found, excluded, still = discover_sources(root, ["vendor"])
    assert still == [] and excluded == ["vendor"]


def test_a_file_symlink_that_never_leaves_the_scope_root_is_followed(tmp_path):
    """Containment is against the scope ROOT, never the directory being walked: comparing
    the target's parent against the latter refuses `src/shared.c -> ../common/shared.c`
    under `--root proj` as an escape, and tells the reader to `--exclude` in-scope code out
    of the review."""
    root = tmp_path / "proj"
    (root / "src").mkdir(parents=True)
    (root / "common").mkdir()
    (root / "src" / "m.c").write_text("int m;\n", encoding="utf-8")
    (root / "common" / "shared.c").write_text("int s;\n", encoding="utf-8")
    (root / "src" / "shared.c").symlink_to("../common/shared.c")
    found, _, refused = discover_sources(root, [])
    assert refused == []
    assert rels(found, root) == ["common/shared.c", "src/m.c"]


# ---------------------------------------------------------- default_agent_count


@pytest.mark.parametrize(
    ("total_lines", "expected"),
    [(0, 4), (-5, 4), (1, 4), (800, 4), (3200, 4), (3201, 5), (11200, 14), (100000, 14)],
)
def test_default_agent_count_clamps_at_both_ends(total_lines, expected):
    assert default_agent_count(total_lines, 800, 4, 14) == expected


# ---------------------------------------------------------------- SOURCE_EXTS


def test_source_extensions_are_pinned():
    """A missing extension is a file enumerated by nobody, exit 0 and no warning.

    `.inl` is the usual name for a C++ inline-implementation header; `.ixx`/`.cppm` are
    module interface units; `.tcc`/`.ipp` are template implementation files. Each one is a
    silent coverage hole if it is absent, and dropping any of them leaves the rest of the
    suite green.
    """
    assert {
        ".c",
        ".h",
        ".cc",
        ".cpp",
        ".cxx",
        ".c++",
        ".hpp",
        ".hh",
        ".hxx",
        ".h++",
        ".ipp",
        ".tcc",
        ".inl",
        ".ixx",
        ".cppm",
    } == SOURCE_EXTS
    assert ".c" not in CPP_EXTS and ".h" not in CPP_EXTS


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


# Calls the PRODUCTION `check_ledger.attach_sites` through uv, which is the only
# interpreter here with tree-sitter. A helper that re-derived the populations itself would
# let `attach_sites` — the entire mechanism keeping the answer key off disk — be replaced
# with `return doc` and leave the whole suite green.
ATTACH_SCRIPT = """
# /// script
# requires-python = ">=3.11"
# # Pinned to the versions the shipped scripts pin, so the reparse here counts sites with
# # the same grammars the gate uses — see enumerate_units.py's header.
# dependencies = ["tree-sitter==0.26.0", "tree-sitter-c==0.24.2", "tree-sitter-cpp==0.23.4"]
# ///
import json, sys
sys.path.insert(0, sys.argv[1])
import check_ledger
print(json.dumps(check_ledger.attach_sites(json.loads(open(sys.argv[2]).read()))))
"""
_ATTACH: list[Path] = []


def _attach_proc(units_json: Path) -> subprocess.CompletedProcess:
    uv = shutil.which("uv")
    if uv is None:
        pytest.fail("uv is not on PATH; the site populations are recomputed by a real parse")
    if not _ATTACH:
        path = Path(tempfile.mkdtemp(prefix="c-review-attach-")) / "attach.py"
        path.write_text(ATTACH_SCRIPT, encoding="utf-8")
        _ATTACH.append(path)
    return subprocess.run(
        [uv, "run", "--no-project", str(_ATTACH[0]), str(SCRIPT.parent), str(units_json)],
        capture_output=True,
        text=True,
        check=False,
        timeout=300,
    )


def attach_sites_through_uv(units_json: Path) -> dict:
    """`check_ledger.attach_sites` over a real units.json, in a process that can parse."""
    proc = _attach_proc(units_json)
    assert proc.returncode == 0, f"attach_sites failed:\n{proc.stderr}"
    return json.loads(proc.stdout)


def attach_sites_refusal(units_json: Path) -> str:
    """The message `attach_sites` refused a tampered or stale units.json with.

    Fails when it ACCEPTED one, which is the whole failure mode these tests exist for: a
    gate that scores a run it could not actually check reports 100% and exit 0.
    """
    proc = _attach_proc(units_json)
    assert proc.returncode != 0, (
        f"attach_sites ACCEPTED a units.json that no longer describes the source:\n"
        f"{proc.stdout[:600]}"
    )
    return proc.stderr


def load_units(out: Path) -> dict:
    """units.json with each unit's site population attached, exactly as the gate gets it.

    Nothing on disk carries the site LINE NUMBERS — they are the answer key the coverage
    gate diffs `sites_accounted` against, and every worker agent has Bash and Read over the
    run directory. `check_ledger.attach_sites` recomputes them from the source, and this
    calls that function rather than re-implementing it.
    """
    doc = attach_sites_through_uv(out / "units.json")
    for unit in doc["units"]:
        assert isinstance(unit.get("sites"), dict), (
            f"attach_sites returned no population for {unit['id']}; the gate cannot check it"
        )
    return doc


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
    doc = load_units(out)
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

    Two independent mechanisms have to hold, and a failure in either looks the same here.
    Seam collection has to recurse: a function body is always a `compound_statement`, so one
    level of seams over `{ switch (x) { ... } }` yields only the `switch` line and every case
    is invisible. And boundary selection has to take the LAST seam that still fits rather
    than the first one a full cap away, or it skips every nearer case and hard-splits the
    oversized remainder — back inside a case body by a different route.
    """
    seam_markers = ("int acc = 0;", "switch (op)", "*out = acc;", "return acc;")
    allowed = {line_of(BIG_C, f"case {i}:") for i in range(3)}
    allowed |= {line_of(BIG_C, marker) for marker in seam_markers}
    starts = [u["start_line"] for u in units_of(parsed, "dispatch")[1:]]
    assert set(starts) <= allowed, (
        f"chunks start at {sorted(set(starts) - allowed)}, which are inside a case body; "
        f"seam candidates were {sorted(allowed)}"
    )


def _run_cli(root, out, *extra):
    """Run the real script through uv, which is the only way the parser is available."""
    uv = shutil.which("uv")
    if uv is None:
        pytest.fail("uv is not on PATH; a skipped parser test reports green while checking nothing")
    argv = [uv, "run", "--no-project", str(SCRIPT), "--root", str(root), "--out-dir", str(out)]
    # A timeout, because the failure mode this guards is a HANG rather than a wrong answer:
    # `seam_lines` was exponential in `else if` chain length and a 250-line dispatcher never
    # got past the detect phase. Without it that regression is a test run that never ends.
    return subprocess.run([*argv, *extra], capture_output=True, text=True, check=False, timeout=180)


def test_two_functions_on_one_line_get_distinct_unit_ids(tmp_path):
    """A unit id is `<file>:<start>-<end>`, which collides for siblings on one line.

    The collision is silent and expensive: `write_outputs` keys assignments by id, so one
    function's data overwrites the other's and the loser appears in NO assignment file —
    unreviewed, while the unit list still shows its lines as owned. Both must reach an
    assignment.
    """
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "multi.c").write_text("int a(void){return 1;} int b(void){return 2;}\n")
    out = tmp_path / "out"
    proc = _run_cli(tmp_path, out)
    assert proc.returncode == 0, proc.stderr
    doc = load_units(out)
    functions = [u for u in doc["units"] if u["kind"] == "function"]
    assert len(functions) == 2
    assert len({u["id"] for u in functions}) == 2, "colliding ids: one function is lost"
    assert doc["id_collisions"] == 1

    assigned = set()
    for path in sorted((out / "assignments").glob("*.json")):
        assigned |= {u["id"] for u in json.loads(path.read_text())["units"]}
    assert {u["id"] for u in functions} <= assigned


def test_a_function_inside_an_ifdef_is_not_charged_to_file_scope(tmp_path):
    """File scope must be charged only for the lines it owns.

    A function nested one level deeper than the root — inside `#ifdef`, `extern "C" { }`
    or a C++ `namespace` — is not a direct child of the root, so filtering the root's own
    children leaves it in. Its writes then land on the file-scope unit as well as on the
    function unit: `totals.sites` and `checks_required` double-count, and the file-scope
    owner is handed a `bounds` row it can only answer by reading another agent's lines.
    """
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "g.c").write_text(
        "#include <string.h>\n"
        "#ifdef HAVE_FEATURE\n"
        "int guarded(char *dst, const char *src, unsigned n)\n"
        "{\n"
        "    memcpy(dst, src, n);\n"
        "    dst[n] = 0;\n"
        "    return 0;\n"
        "}\n"
        "#endif\n"
    )
    out = tmp_path / "out"
    proc = _run_cli(tmp_path, out)
    assert proc.returncode == 0, proc.stderr
    doc = load_units(out)

    scope = next(u for u in doc["units"] if u["kind"] == "file-scope")
    owned = {n for a, b in scope["ranges"] for n in range(a, b + 1)}
    charged = {line for lines in scope["sites"].values() for line in lines}
    assert charged <= owned, (
        f"file scope is charged for {sorted(charged - owned)}, which it does not own"
    )
    assert "bounds" not in scope["required_questions"]

    function = next(u for u in doc["units"] if u["kind"] == "function")
    assert function["sites"]["write"] == [5, 6]
    assert doc["totals"]["sites"]["write"] == 2, "the two writes were counted twice"


def test_a_macro_inside_an_include_guard_still_owes_macro_contract(tmp_path):
    """Essentially every real header is guarded, so this is the common case, not the edge.

    A `#ifndef X / #define X / ... / #endif` guard makes the whole body one `preproc_ifdef`,
    and a scan of the root's direct children finds no `preproc_function_def` inside it.
    `macro-contract` is then never asked about any macro in any guarded header, and the gate
    reports full coverage over a question it has structurally stopped asking.
    """
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "hdr.h").write_text(
        "#ifndef HDR_H\n#define HDR_H\n#define SET2(p, v) ((p)[0] = (v))\n#endif\n"
    )
    out = tmp_path / "out"
    proc = _run_cli(tmp_path, out)
    assert proc.returncode == 0, proc.stderr
    doc = load_units(out)
    scope = next(u for u in doc["units"] if u["kind"] == "file-scope")
    assert scope["sites"]["macro"] == [3]
    assert "macro-contract" in scope["required_questions"]


FABRICATION_C = """\
#include <stdlib.h>
#include <string.h>

int copy_into(char *dst, const char *src, unsigned n)
{
    char *tmp = malloc(n + 1);
    memcpy(tmp, src, n);
    dst[0] = tmp[0];
    free(tmp);
    return (int)n;
}
"""


def test_a_ledger_fabricated_from_everything_the_reviewer_can_see_fails_the_gate(tmp_path):
    """The load-bearing property of the whole design, asserted end to end.

    A reviewer is handed `assignments/<id>.json` and can trivially open `units.json` one
    directory up. If the owed site populations are derivable from either, a ledger can be
    written without opening a source file and the gate certifies it — and the derivations
    are not exotic: emitting `caller-contract` and `initialisation` at `start_line` (a
    required display field), or shipping every `sites` list verbatim in `units.json`, is
    enough on its own.

    Every strategy below is one a transcribing agent can actually execute against those
    files. Each is scored separately, because a mixture is only as good as its best part.
    """
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "scripts"))
    import check_ledger

    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "c.c").write_text(FABRICATION_C, encoding="utf-8")
    out = tmp_path / "out"
    proc = _run_cli(tmp_path, out)
    assert proc.returncode == 0, proc.stderr

    truth = load_units(out)
    owed = check_ledger.required_rows(truth["units"])
    key_lines = sorted({n for row in owed.values() for n in row["sites"]})
    assert key_lines, "a vacuous test: the parse counted no site anywhere"

    # 1. NO FILE in the run directory holds an owed POPULATION. Every worker agent has Bash
    #    and Read here, so a population that is on disk at all is one `grep -rn` from being
    #    transcribed, wherever it is kept. Dotfiles included: ripgrep skips them, `cat`,
    #    `ls -a` and `Read` do not.
    #
    #    Populations of two or more, because a one-line population is a single small integer
    #    that matches any `end_line` by coincidence; the structural check below covers those.
    multi = [row for row in owed.values() if len(row["sites"]) > 1]
    assert multi, "the fixture no longer has a multi-site population; this check is vacuous"
    on_disk = [p for p in out.rglob("*") if p.is_file()]
    assert on_disk, "nothing was written; the checks below would be vacuous"
    for path in on_disk:
        packed = path.read_text(encoding="utf-8", errors="replace").replace(" ", "")
        leaked = [row for row in multi if json.dumps(row["sites"]).replace(" ", "") in packed]
        assert not leaked, (
            f"{path.relative_to(out)} carries the owed site lines for "
            f"{[(r['unit_id'], r['question']) for r in leaked[:3]]}; the gate is transcribable"
        )

    # 2. A ledger fabricated from EVERY file an agent can see fails the gate. The
    #    strategies are the ones a transcribing agent can actually execute against them.
    def strategies(unit: dict, question: str) -> dict[str, tuple[str, list[int]]]:
        span = [n for n in (unit.get("start_line"), unit.get("end_line")) if isinstance(n, int)]
        kinds = check_ledger.QUESTION_SITE_KINDS.get(question, ())
        from_file = sorted({n for k in kinds for n in (unit.get("sites") or {}).get(k, [])})
        return {
            # The population as `units.json` would carry it if it shipped `sites` verbatim.
            "the unit's own sites list": ("clean", from_file),
            # The declaration line, where `caller-contract` and `initialisation` sites fall,
            # and which every assignment file prints as `start_line`.
            "start_line": ("clean", span[:1]),
            "the whole span": ("clean", span),
            "nothing at all": ("clean", []),
            "nothing at all, not-applicable": ("not-applicable", []),
        }

    # Every file an agent can see that carries a unit list, grouped so the assignment files
    # are one source: a reviewer holds one of them, but nothing stops it reading them all.
    seen_units: dict[str, list[dict]] = {}
    for path in sorted(on_disk):
        try:
            doc = json.loads(path.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, UnicodeDecodeError):
            continue
        units = doc.get("units") if isinstance(doc, dict) else None
        if isinstance(units, list) and units:
            group = "assignments/" if path.parent.name == "assignments" else path.name
            seen_units.setdefault(group, []).extend(units)
    visible = sorted(seen_units.items())
    assert set(seen_units) >= {"units.json", "assignments/"}, "the fabrication sources vanished"

    for source, units in visible:
        assert all("sites" not in u for u in units), f"{source} ships the site populations"
        for name in strategies(units[0], "bounds"):
            rows = [
                dict(
                    zip(
                        ("verdict", "sites_accounted"),
                        strategies(unit, question)[name],
                        strict=True,
                    ),
                    unit_id=unit["id"],
                    question=question,
                    evidence="read it, nothing wrong",
                )
                for unit in units
                for question in unit.get("required_questions") or []
            ]
            report = check_ledger.check(truth, [("review-fake", {"ledger": rows})])
            assert report["checks_required"] > 0, "a vacuous gate would pass this test"
            assert report["coverage_pct"] == 0.0, (
                f"{report['coverage_pct']}% of the gate is satisfiable by copying "
                f"{name} out of {source} with no source file opened"
            )

    # 3. And the gate is not merely unsatisfiable: a ledger holding the populations a
    #    reader WOULD find passes it. Without this the two assertions above are satisfied
    #    by a gate that rejects everything.
    honest = [
        dict(
            unit_id=row["unit_id"],
            question=row["question"],
            verdict="clean",
            sites_accounted=row["sites"],
            evidence="read every site",
        )
        for row in owed.values()
    ]
    accepted = check_ledger.check(truth, [("review-real", {"ledger": honest})])
    assert accepted["coverage_pct"] == 100.0, accepted["violations"][:3]


def test_a_partitioner_that_partitions_nothing_fails_loudly(tmp_path, capsys):
    """The module docstring's headline promise.

    A source file the parser produces no unit from is not an empty codebase, and treating
    it as one certifies a review of nothing.
    """
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "empty.c").write_text("", encoding="utf-8")
    out = tmp_path / "run"
    proc = _run_cli(tmp_path, out)
    assert proc.returncode == 2, proc.stdout
    assert "produced no units" in proc.stderr
    assert not (out / "units.json").exists()


def test_a_generated_table_thousands_of_terms_deep_is_reviewed_rather_than_blocking_the_run(
    tmp_path,
):
    """One generated table must not block the WHOLE review, or blame I/O for it.

    Recursive site and reference walks exhaust the stack on ~1000 chained operators, and the
    RecursionError is funnelled into `unreadable` and exits 2 — so one generated file makes
    every other file in the tree unreviewable, under a message saying the file could not be
    read. The walks are iterative, so this parses.
    """
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "deep.c").write_text(
        "int deep(void) { return " + " + ".join(["1"] * 4000) + "; }\n", encoding="utf-8"
    )
    out = tmp_path / "out"
    proc = _run_cli(tmp_path, out)
    assert proc.returncode == 0, proc.stderr
    assert "Traceback" not in proc.stderr
    assert [u["function"] for u in load_units(out)["units"] if u["kind"] == "function"] == ["deep"]


def test_stale_part_files_from_a_previous_run_are_cleared(tmp_path):
    """`review-unit-07.json` from a 9-agent run survives a later 6-agent run.

    `load_parts` globs `parts/*.json` and `--expect` only asserts presence, so a survivor's
    findings are assembled as this run's and its ledger rows counted as this run's
    coverage — not `unrecognised`, not `missing`, in no warning. Done here rather than in
    the detect agent's prompt, because a cleanup an LLM is asked to perform can be
    summarised instead of run and nothing downstream can tell.
    """
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "a.c").write_text("int f(int *p) { *p = 1; return 0; }\n", encoding="utf-8")
    out = tmp_path / "out"
    (out / "parts").mkdir(parents=True)
    (out / "parts" / "review-unit-07.json").write_text("{}", encoding="utf-8")
    (out / "parts" / "keep.txt").write_text("not a part file", encoding="utf-8")
    assert _run_cli(tmp_path, out).returncode == 0
    assert list((out / "parts").glob("*.json")) == []
    assert (out / "parts" / "keep.txt").exists()


CPP_SITES = """\
#include <cstddef>
struct Thing { int v; };
int use(std::size_t n, int *out)
{
    Thing *t = new Thing;
    int *a = new int[n];
    *out = static_cast<int>(n);
    *out += int(n);
    delete[] a;
    delete t;
    return 0;
}
"""


def test_cpp_allocation_release_and_casts_are_counted(tmp_path):
    """`new`/`delete` are their own node types and the C++ casts are not `cast_expression`.

    Miss them and the use-after-free, double-free and integer-conversion questions are
    structurally never asked on an idiomatic C++ tree, while the gate reports full coverage
    over the questions it stopped asking. The plugin's description leads with C++.
    """
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "t.cpp").write_text(CPP_SITES, encoding="utf-8")
    out = tmp_path / "out"
    assert _run_cli(tmp_path, out).returncode == 0
    unit = next(u for u in load_units(out)["units"] if u["function"] == "use")
    assert unit["sites"]["alloc"] == [
        line_of(CPP_SITES, "new Thing"),
        line_of(CPP_SITES, "new int"),
    ]
    assert unit["sites"]["release"] == [
        line_of(CPP_SITES, "delete[] a"),
        line_of(CPP_SITES, "delete t"),
    ]
    # `static_cast<T>(x)` parses as a call through a `template_function`, and the
    # functional cast `int(n)` as a call whose callee IS a type. Neither is a
    # `cast_expression`, so a walk that looks only for that node type counts neither.
    assert unit["sites"]["conversion"] == [
        line_of(CPP_SITES, "static_cast"),
        line_of(CPP_SITES, "int(n)"),
    ]
    assert {"alloc-lifetime", "integer"} <= set(unit["required_questions"])


BRANCHY_C = "\n".join(
    ["int branchy(int n, int *out) {", "    if (n) {"]
    + [f"        *out += {i};" for i in range(30)]
    + ["    } else {"]
    + [f"        *out -= {i};" for i in range(30)]
    + ["    }", "    return n;", "}"]
)


def test_branch_bodies_are_seams(tmp_path):
    """tree-sitter names the fields `consequence`/`alternative`, never `body`.

    Asking for `body` returns None, so an `if` contributes no seam and no node type descends
    into an `else` at all — the module docstring promises "loop and branch bodies" and a
    two-armed function is then cut on raw line count straight through both.
    """
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "b.c").write_text(BRANCHY_C + "\n", encoding="utf-8")
    out = tmp_path / "out"
    assert _run_cli(tmp_path, out, "--max-unit-lines", "20").returncode == 0
    parts = [u for u in load_units(out)["units"] if u["function"] == "branchy"]
    assert len(parts) > 1
    statements = {line_of(BRANCHY_C, f"*out += {i}") for i in range(30)}
    statements |= {line_of(BRANCHY_C, f"*out -= {i}") for i in range(30)}
    else_line = line_of(BRANCHY_C, "} else {")
    starts = {u["start_line"] for u in parts[1:]}
    assert starts <= statements | {else_line, line_of(BRANCHY_C, "return n;")}
    # The `} else {` itself, not merely some statement inside an arm. `split_span` takes the
    # LAST candidate under the cap and every statement is a candidate, so on arms holding
    # more than one statement the cap boundary wins and no unit begins at the `else` — the
    # one cut a reader most needs the partition to make. `strong_starts` is what makes an
    # arm boundary beat a later mid-arm statement.
    assert else_line in starts, "no unit begins at the `} else {`; the arm seam lost again"
    assert all(u["split"] == "seam" for u in parts), "cut on line count, not at a seam"


POPULATIONS_C = """\
#include <stdio.h>
#include <string.h>
int probe(char *dst, const char *src, unsigned n)
{
    unsigned long wide = (unsigned long)n;
    size_t want = sizeof(*dst) * n;
    strncpy(dst, src, want);
    printf("%lu\\n", wide);
    free(dst);
    fclose(stdin);
    return 0;
}
"""


@pytest.mark.parametrize(
    ("kind", "marker", "question"),
    [
        ("conversion", "(unsigned long)n", "integer"),
        ("sizeof", "sizeof(*dst)", "sizeof-arith"),
        ("strop", "strncpy(", "nul-termination"),
        ("unchecked_call", "fclose(stdin)", "return-values"),
    ],
)
def test_each_site_population_is_counted_and_drives_its_question(tmp_path, kind, marker, question):
    """`integer`, `nul-termination` and `return-values` are ~40% of all required rows.

    Without an end-to-end assertion on each, emptying `STRING_FNS`, dropping
    `cast_expression` or removing `printf` from `RETURN_IGNORABLE_FNS` all leave the suite
    green while the questions quietly stop being asked.
    """
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "p.c").write_text(POPULATIONS_C, encoding="utf-8")
    out = tmp_path / "out"
    assert _run_cli(tmp_path, out).returncode == 0
    unit = next(u for u in load_units(out)["units"] if u["function"] == "probe")
    assert line_of(POPULATIONS_C, marker) in unit["sites"][kind]
    assert question in unit["required_questions"]
    # `printf` returns a count nobody checks by convention; padding the return-values
    # population with lines that cannot be bugs is not free, because the gate makes the
    # agent account for every line in it.
    assert line_of(POPULATIONS_C, "printf(") not in unit["sites"]["unchecked_call"]
    # `free` is the same waste and is 27 of 291 `unchecked_call` sites on the measured
    # corpus: it returns void, so there is no return value to check and the reviewer would
    # be made to enumerate lines that cannot hold the bug the question asks about.
    assert line_of(POPULATIONS_C, "free(") not in unit["sites"]["unchecked_call"]
    # And it is still an alloc-lifetime release site, so nothing is lost by dropping it here.
    assert line_of(POPULATIONS_C, "free(") in unit["sites"]["release"]


def test_an_unreadable_file_fails_the_run(tmp_path):
    """A file nobody can read is a file nobody reviews.

    With other files still producing units the run otherwise exits 0 and looks complete,
    and coverage is reported over the units that exist — so the unreadable file cannot
    surface as a gap anywhere downstream.
    """
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "ok.c").write_text("int f(int *p){ return *p; }\n")
    bad = tmp_path / "src" / "locked.c"
    bad.write_text("int g(char *d){ return 0; }\n")
    bad.chmod(0o000)
    try:
        proc = _run_cli(tmp_path, tmp_path / "out")
        assert proc.returncode != 0, "an unreadable file was reviewed by nobody and exited 0"
        assert "locked.c" in proc.stderr
    finally:
        bad.chmod(0o644)


# --------------------------------------------------------- the macro repair layer


def test_collect_object_macros_takes_only_decorations_and_never_a_keyword():
    """Substituting a keyword can only lose information; it cannot help a parse.

    Pre-ANSI headers carry `#define const` under an `#ifndef __STDC__` guard, and honouring
    it deletes every `const` in the tree. A function-like macro is excluded because it
    cannot be resolved textually without an argument parser.
    """
    got = collect_object_macros(
        [
            b"#define ZEXPORT\n#define ZAPI static\n",
            b"#define const\n#define MAX(a,b) ((a)>(b)?(a):(b))\n#define BUFSZ 4096\n",
        ]
    )
    assert got == {b"ZEXPORT": b"", b"ZAPI": b"static"}


def test_substitution_never_rewrites_a_preprocessor_line_or_moves_a_line():
    """`#define X static` must not become `#define static static`, which raises the error
    count instead of lowering it. Line numbering is what the ledger gate diffs, so the
    substitution is length-preserving too."""
    source = b"#define ZEXPORT\nint ZEXPORT f(void);\n#undef ZEXPORT\n"
    out = _substitute_outside_directives(source, {b"ZEXPORT": b""})
    assert out.split(b"\n")[0] == b"#define ZEXPORT"
    assert out.split(b"\n")[2] == b"#undef ZEXPORT"
    assert b"ZEXPORT" not in out.split(b"\n")[1]
    assert out.count(b"\n") == source.count(b"\n")
    assert _substitute_outside_directives(source, {}) == source


DECORATED_C = """\
#define ZEXPORT
#define ZBUF 64

int ZEXPORT deflate(int *out, unsigned n)
{
    char tmp[ZBUF];
    memcpy(tmp, &n, sizeof(n));
    *out = (int)n;
    return 0;
}
"""


def test_a_decoration_macro_is_resolved_so_the_function_stays_a_unit(tmp_path):
    """`DECOR int foo(...)` is not valid C to a parser that never saw the `#define`.

    tree-sitter's recovery from it is not local: it flattens the whole body into
    top-level statements, the function drops out of the unit list, and its lines fall
    into the file-scope unit — silently reducing a function-aware partition to arbitrary
    line ranges, over a tree the gate then reports full coverage on.
    """
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "z.c").write_text(DECORATED_C, encoding="utf-8")
    out = tmp_path / "out"
    proc = _run_cli(tmp_path, out)
    assert proc.returncode == 0, proc.stderr
    assert json.loads(proc.stdout)["macros_resolved"] == ["ZEXPORT"]
    doc = load_units(out)
    assert doc["parse_degraded"] == []
    function = next(u for u in doc["units"] if u["kind"] == "function")
    assert function["function"] == "deflate"
    assert function["parameters"] == ["int *out", "unsigned n"]
    assert set(function["required_questions"]) >= {"bounds", "caller-contract", "initialisation"}


# ----------------------------------------------------------- is_out_parameter


@pytest.mark.parametrize(
    ("param", "is_out"),
    [
        ("char *dst", True),
        ("const char *in", False),
        # `const` binds the POINTEE. The outer pointer is still written through.
        ("const char **out", True),
        ("char buf[64]", True),
        ("char buf[]", True),
        ("const char in[]", False),
        # `"const" in prefix` is a SUBSTRING test, so it skips any parameter named
        # `const…` before a `[` — a false negative on exactly the array shapes.
        ("int constants[16]", True),
        ("unsigned char const_table[256]", True),
        # The normal C++ out-parameter.
        ("int &out", True),
        ("std::string &s", True),
        ("const std::string &s", False),
        # An rvalue reference is a source to move FROM, not a destination.
        ("T &&x", False),
        ("std::string &&s", False),
        # A function pointer is an INPUT. A pointer to an ARRAY is not one, and a bare
        # `"(" in s and "*" in s` guard cannot tell them apart.
        ("int (*cb)(void)", False),
        ("void (*h)(int)", False),
        ("int (*out)[10]", True),
        # A callable passed by reference is an input too; its type carries its own
        # balanced parameter list.
        ("std::function<void(int)> &cb", False),
        ("void", False),
        ("", False),
        ("int n", False),
        ("size_t *written", True),
        # A TEMPLATE ARGUMENT is not the parameter's own declarator. A scan taking the
        # first `*`/`&` anywhere and the first `const` left of it comes out exactly
        # INVERTED on idiomatic C++: the real out-parameter is dropped and two by-value
        # parameters are owed instead.
        ("std::vector<const char*> &v", True),
        ("std::pair<int, const char*> &p", True),
        ("std::map<std::string, int> &out", True),
        ("std::vector<int*> v", False),
        ("std::vector<Foo*> out", False),
        ("std::unique_ptr<T[]> p", False),
        # A DEFAULT ARGUMENT is not the declarator either, and neither are the literals in
        # one: `SIZE * 2`, `"a*b"` and `'*'` each supply a sigil the parameter does not have.
        ("int n = SIZE * 2", False),
        ('std::string s = "a*b"', False),
        ("char c = '*'", False),
        ("char *out = nullptr", True),
        # `const char *argv[]`: the ELEMENT is `const char *`, which is assignable. Only a
        # const with no pointer between it and the bracket qualifies the element itself.
        ("const char *argv[]", True),
        # `T *q *x` — it is the qualifier BETWEEN the two stars that decides.
        ("const char * *out", True),
        ("void *const *out", False),
        # An ARRAY of function pointers is written through; one function pointer is not.
        ("int (*tab[4])(void)", True),
        # An attribute is not part of the declarator, and its balanced parens trip the
        # callable-type test.
        ("__attribute__((nonnull)) char *p", True),
    ],
)
def test_is_out_parameter_recognises_every_writable_shape(param, is_out):
    """Which parameters this unit can write THROUGH — the `initialisation` population.

    The C++ shapes are the ones that decide whether the question gets asked at all: miss the
    reference and template forms and `initialisation` is essentially never owed by C++ code,
    while the gate reports full coverage over the question it stopped asking.
    """
    assert is_out_parameter(param) is is_out


# ------------------------------------------- the assignment file the reviewer reads


def test_the_assignment_file_never_carries_the_site_line_numbers(tmp_path):
    """C1: a ledger fabricated from the assignment file alone must not score 100%.

    `check_ledger` accepts a row whose `sites_accounted` equals the population the parse
    counted. If the assignment file carries that population verbatim, both halves of the
    gate are readable straight out of the agent's own input and the diff proves
    transcription rather than reading. The counts stay — the agent has to know when it has
    found them all — but the lines have to come from the source.
    """
    unit = {
        "id": "src/a.c:1-40",
        "file": "src/a.c",
        "name": "f",
        "start_line": 1,
        "end_line": 40,
        "lines": 40,
        "sites": {"write": [10, 20, 30], "conversion": [15], "param": [1]},
        "required_questions": ["bounds", "integer", "caller-contract"],
    }
    doc = {
        "max_unit_lines": 150,
        "questions": {qid: text for qid, (text, _) in QUESTIONS.items()},
        "units": [unit],
        "assignments": [
            {
                "id": "unit-01",
                "unit_ids": [unit["id"]],
                "unit_count": 1,
                "total_lines": 40,
                "files": ["src/a.c"],
            }
        ],
        "totals": {},
        "unreadable": [],
        "excluded": [],
        "id_collisions": 0,
        "parse_degraded": [],
        "macros_resolved": {},
    }
    write_outputs(doc, tmp_path)
    payload = json.loads((tmp_path / "assignments" / "unit-01.json").read_text(encoding="utf-8"))
    shipped = payload["units"][0]
    assert "sites" not in shipped
    assert shipped["site_counts"] == {"bounds": 3, "integer": 1, "caller-contract": 1}
    # And the numbers themselves appear nowhere in the file the reviewer is handed. As
    # TOKENS, not as substrings, so that a field that legitimately holds `3611718b108579a4`
    # is not read as holding the number 10.
    raw = (tmp_path / "assignments" / "unit-01.json").read_text(encoding="utf-8")
    assert not re.search(r"(?<![0-9A-Za-z])(10|20|30)(?![0-9A-Za-z])", raw), raw
    # units.json sits one directory up from the path the reviewer is given, and nothing
    # forbids opening it. It must not carry the lines either.
    public = json.loads((tmp_path / "units.json").read_text(encoding="utf-8"))
    assert "sites" not in public["units"][0]
    assert public["units"][0]["site_counts"] == {"bounds": 3, "integer": 1, "caller-contract": 1}
    # And no OTHER file in the run directory carries them either. There is no gate copy
    # anywhere: any location on disk is one a fabricated ledger can copy from, so the lines
    # are recomputed at gate time and written nowhere.
    for path in tmp_path.rglob("*"):
        if path.is_file():
            body = path.read_text(encoding="utf-8", errors="replace").replace(" ", "")
            assert "10,20,30" not in body, f"{path} carries the answer key"

    # A rerun with a different partition must not leave the previous one's slices behind.
    doc["assignments"] = [
        {
            "id": "unit-A",
            "unit_ids": [unit["id"]],
            "unit_count": 1,
            "total_lines": 40,
            "files": ["src/a.c"],
        }
    ]
    write_outputs(doc, tmp_path)
    assert sorted(p.name for p in (tmp_path / "assignments").glob("*.json")) == ["unit-A.json"]


def test_assignment_unit_drops_only_the_sites_key():
    unit = {
        "id": "x",
        "file": "a.c",
        "name": "f",
        "start_line": 1,
        "end_line": 9,
        "lines": 9,
        "parameters": ["char *p"],
        "sites": {"write": [3]},
        "required_questions": ["bounds"],
    }
    shipped = assignment_unit(unit)
    assert shipped["parameters"] == ["char *p"]
    assert set(unit) - set(shipped) == {"sites"}


def test_sibling_definitions_on_one_line_are_counted_as_an_id_collision(tmp_path):
    """`int a(void){...} int b(void){...}` — two units with the same `<file>:<start>-<end>`.

    `_uniquify_ids` makes the id unique but not the OWNERSHIP: that physical line now has
    two owners and is billed twice against the ledger, which breaks this module's own
    "every line is owned by exactly one agent" invariant. The collision cannot be repaired
    without splitting a line, so the count travels with the output instead of being
    silently repaired — `write_outputs` puts it in the summary the detect agent reports.
    """
    src = tmp_path / "src"
    src.mkdir()
    (src / "multi.c").write_text("int a(void){return 1;} int b(void){return 2;}\n", "utf-8")
    out = subprocess.run(
        [
            "uv",
            "run",
            str(SCRIPT),
            "--root",
            str(tmp_path),
            "--out-dir",
            str(tmp_path / "run"),
            "--agents",
            "1",
        ],
        capture_output=True,
        text=True,
        check=True,
    )
    summary = json.loads(out.stdout)
    assert summary["id_collisions"] == 1, "the ownership collision is invisible downstream"


# ------------------------------------------- the seam walk over an else-if chain


def _else_if_chain(arms: int) -> str:
    """A generated option dispatcher: the shape that hung the enumerator."""
    lines = ["int parse_opt(const char *k, int v) {"]
    for i in range(arms):
        lines.append(f'  {"if" if i == 0 else "} else if"} (streq(k, "opt{i}")) {{')
        lines += [f"    int t{i} = v + {i};", f"    apply(t{i});", f"    return t{i};"]
    lines += ["  } else {", "    return -1;", "  }", "}"]
    return "\n".join(lines) + "\n"


def test_a_long_else_if_chain_does_not_hang_the_enumerator(tmp_path):
    """`seam_lines` must not be exponential in the length of an `else if` chain.

    Every `else_clause` spans the rest of the chain, so it is always over the cap; a walk
    that descends into it and re-expands the remainder gives T(n) = ΣT(n−i). Measured on
    that shape: 45 arms 0.05 s, 55 arms 7.3 s, 58 arms 59 s, 60 arms unfinished after 300 s,
    and 1200 arms a RecursionError. A 250-line option or opcode dispatcher is ordinary
    generated C, and because the coverage gate re-runs this parse the hang recurs at the
    end of the pipeline, after every review agent has been paid for.

    250 arms is ~1000 lines and finishes in well under a second; the `_run_cli` timeout is
    what turns a re-regression into a failure rather than a test run that never ends.
    """
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "opt.c").write_text(_else_if_chain(250), encoding="utf-8")
    proc = _run_cli(tmp_path, tmp_path / "out")
    assert proc.returncode == 0, proc.stderr
    doc = json.loads((tmp_path / "out" / "units.json").read_text(encoding="utf-8"))
    assert doc["totals"]["units"] > 1, "a 1000-line function must still be split"
    assert doc["totals"]["hard_split"] == 0, (
        "every chunk fell back to a raw line-count cut, so the seam walk found nothing — "
        "dropping the else arms is not an acceptable repair (test_an_else_arm_is_a_seam "
        "holds the other half)"
    )


# --------------------------------------------------- directories the walk refuses


def test_an_unreadable_directory_fails_the_run_like_an_unreadable_file(tmp_path):
    """One level up from `test_an_unreadable_file_fails_the_run`, and it must not be silent.

    `except OSError: continue` around `iterdir` gives `totals.files: 1`, `unreadable: []`,
    `excluded: []` and exit 0 over a tree whose second source file is in no unit, no
    assignment and no field of any artifact. Reachable on any root-owned or ACL'd subtree.
    """
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "ok.c").write_text("int f(int *p){ return *p; }\n", encoding="utf-8")
    locked = tmp_path / "secret"
    locked.mkdir()
    (locked / "b.c").write_text("int g(char *d){ return 0; }\n", encoding="utf-8")
    locked.chmod(0o000)
    try:
        proc = _run_cli(tmp_path, tmp_path / "out")
        assert proc.returncode != 0, "a subtree nobody can read exited 0 and named nothing"
        assert "secret" in proc.stderr
        assert not (tmp_path / "out" / "units.json").exists()
    finally:
        locked.chmod(0o755)


def test_an_unreadable_directory_that_exclude_covers_is_not_fatal(tmp_path):
    """The abort has to be escapable, or a tree with one ACL'd directory cannot be reviewed."""
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "ok.c").write_text("int f(int *p){ return *p; }\n", encoding="utf-8")
    locked = tmp_path / "secret"
    locked.mkdir()
    locked.chmod(0o000)
    try:
        proc = _run_cli(tmp_path, tmp_path / "out", "--exclude", "secret")
        assert proc.returncode == 0, proc.stderr
        doc = json.loads((tmp_path / "out" / "units.json").read_text(encoding="utf-8"))
        assert "secret" in doc["excluded"], "the deliberate omission is not recorded anywhere"
    finally:
        locked.chmod(0o755)


def test_a_directory_symlink_above_the_scope_root_is_refused(tmp_path):
    """`inner/up -> ../..` enumerates the whole parent tree as if it were in scope.

    Out-of-scope code becomes units, is assigned to an agent, and has its findings filed at
    paths the finding scope root does not contain. A link to `/` is unbounded. Sibling links
    are the vendoring case and are still followed — the test above proves it.
    """
    root = tmp_path / "proj" / "inner"
    root.mkdir(parents=True)
    (root / "a.c").write_text("int a(void){ return 1; }\n", encoding="utf-8")
    (tmp_path / "proj" / "vendor").mkdir()
    (tmp_path / "proj" / "vendor" / "secret.c").write_text("int s(void){return 2;}\n", "utf-8")
    (root / "up").symlink_to(tmp_path, target_is_directory=True)
    found, excluded, refused = discover_sources(root, [])
    assert rels(found, root) == ["a.c"], "out-of-scope source became a review unit"
    assert refused and "outside the scope root" in refused[0]
    assert excluded == []


# --------------------------------------------------- sites_by_id reads back a file


@pytest.mark.parametrize(
    ("overrides", "needle"),
    [
        ({"root": ""}, "records no scope root"),
        ({"root": None}, "records no scope root"),
        ({"max_unit_lines": -5}, "max_unit_lines"),
        ({"max_unit_lines": "forty"}, "max_unit_lines"),
        ({"max_unit_lines": 5}, "max_unit_lines"),
        ({"exclude": 7}, "exclude"),
        ({"exclude": [""]}, "exclude"),
    ],
    ids=[
        "root-empty",
        "root-null",
        "cap-negative",
        "cap-text",
        "cap-tiny",
        "ex-scalar",
        "ex-empty",
    ],
)
def test_sites_by_id_refuses_a_units_json_it_cannot_trust(tmp_path, overrides, needle):
    """Every one of these arrives from a file every worker agent can write.

    `Path("")` is `PosixPath('.')`, whose `is_dir()` is True, so an unguarded `root: ""`
    enumerates the CURRENT WORKING DIRECTORY. `max_unit_lines: -5` is an infinite loop in
    `split_span`'s hard split; `"forty"` an uncaught ValueError that escapes the gate and
    destroys a completed review's artifacts; `5` silently repartitions the tree so that no
    ledger row can match any unit. `exclude: [""]` raises `ValueError: empty pattern` by the
    same route.
    """
    doc = {"root": str(tmp_path), "max_unit_lines": 150, "exclude": [], **overrides}
    with pytest.raises(EnumerateError) as exc:
        sites_by_id(doc)
    assert needle in str(exc.value)


# ------------------------------------------------- the gate binding, end to end

TAMPER_C = """#include <string.h>

void relay_copy(char *dst, const char *src, unsigned n)
{
    unsigned long wide = (unsigned long)n;
    size_t want = sizeof(*dst) * n;
    dst[0] = src[0];
    dst[1] = src[1];
    dst[2] = src[2];
    memcpy(dst, src, want);
    (void)wide;
}
"""


def _tampered_run(tmp_path):
    """A real run directory over a real tree: (scope root, run dir, units.json path)."""
    root = tmp_path / "tree"
    (root / "src").mkdir(parents=True)
    (root / "src" / "a.c").write_text(TAMPER_C, encoding="utf-8")
    out = tmp_path / "run"
    proc = _run_cli(root, out)
    assert proc.returncode == 0, proc.stderr
    return root, out, out / "units.json"


def _rewrite(path: Path, doc) -> None:
    path.write_text(json.dumps(doc), encoding="utf-8")


def test_a_units_json_that_carries_its_own_sites_is_reparsed_anyway(tmp_path):
    """A `sites` mapping in the file must never be a per-unit opt-out from the recompute.

    Skipping the recompute for a unit that already carries one lets a worker — every one has
    Write and Bash over the run directory — put `"sites": {"write": [<start_line>]}` into
    `units.json` and restore the answer key under its own control, per unit; a ledger
    accounting only the forged line then scores `coverage_pct: 100.0`, `violation_count: 0`,
    exit 0, without a source file being opened.
    """
    _root, _out, units_json = _tampered_run(tmp_path)
    doc = json.loads(units_json.read_text(encoding="utf-8"))
    forged = {"write": [doc["units"][0]["start_line"]]}
    for unit in doc["units"]:
        unit["sites"] = dict(forged)
    _rewrite(units_json, doc)
    attached = attach_sites_through_uv(units_json)
    assert [u["sites"] for u in attached["units"]] != [forged] * len(attached["units"]), (
        "the forged population survived the gate"
    )
    real = next(u["sites"] for u in attached["units"] if u["required_questions"])
    assert len(real.get("write", [])) > 1, "the real write population was not recomputed"


def test_a_source_edit_between_the_review_and_the_gate_fails_the_run(tmp_path):
    """Recomputing alone measures the tree as it is NOW, which the agents can write to.

    Rewriting every body to `(void)param;` with the line count and the function extent
    preserved keeps every unit id alive and empties the populations, and a 22-row ledger
    accounting the 14 lines the attacker leaves then scores 100% with zero violations.
    Leaving one reference alive per unit defeats the "counts no line at all" guard; nothing
    defeats the counts the enumerator recorded.
    """
    root, _out, units_json = _tampered_run(tmp_path)
    source = root / "src" / "a.c"
    lines = source.read_text(encoding="utf-8").splitlines()
    edited = [
        "    (void)src;" if line.startswith("    ") and "unsigned i;" not in line else line
        for line in lines
    ]
    assert len(edited) == len(lines)
    source.write_text("\n".join(edited) + "\n", encoding="utf-8")
    assert "no longer match" in attach_sites_refusal(units_json)


def test_deleting_a_unit_from_units_json_fails_the_run(tmp_path):
    """Otherwise the denominator shrinks to nothing, silently.

    `sites_by_id` computes populations for every unit in the tree, so an `attach_sites` that
    looks up only the ids `units.json` happens to list lets a run delete two of three units,
    answer for the survivor, and report `checks_required: 2`, `coverage_pct: 100.0`, exit 0
    — while the same call has just computed all three.
    """
    _root, _out, units_json = _tampered_run(tmp_path)
    doc = json.loads(units_json.read_text(encoding="utf-8"))
    assert len(doc["units"]) > 1, "the fixture must produce more than one unit"
    doc["units"] = doc["units"][:1]
    _rewrite(units_json, doc)
    assert "The tree moved" in attach_sites_refusal(units_json)


def test_trimming_required_questions_fails_the_run(tmp_path):
    """The other half of the same denominator trim, and per-count equality cannot see it.

    `site_counts` is written per required question, so dropping a question drops its count
    with it and every count that remains still matches.
    """
    _root, _out, units_json = _tampered_run(tmp_path)
    doc = json.loads(units_json.read_text(encoding="utf-8"))
    trimmed = False
    for unit in doc["units"]:
        if len(unit.get("required_questions") or []) > 1:
            dropped = unit["required_questions"].pop()
            unit.get("site_counts", {}).pop(dropped, None)
            trimmed = True
            break
    assert trimmed, "the fixture must own a unit with more than one question"
    _rewrite(units_json, doc)
    assert "the source now counts sites for" in attach_sites_refusal(units_json)


def test_an_untampered_run_still_passes_the_binding(tmp_path):
    """The zero-item guard on the four tests above: they must be rejecting the TAMPER."""
    _root, _out, units_json = _tampered_run(tmp_path)
    attached = attach_sites_through_uv(units_json)
    assert attached["units"], "the fixture produced no units and every assertion above is vacuous"
    for unit in attached["units"]:
        assert isinstance(unit["sites"], dict)


# ------------------------------------------------ shapes the parse must not miss


def test_a_constructor_that_only_uses_its_parameters_in_the_member_init_list_owes_rows(tmp_path):
    """A C++ constructor storing a caller-supplied pointer and length must not owe NOTHING.

    A constructor's member-initializer list is a sibling of the body, so a `_reference_lines`
    that runs over the body alone gives `Buf(char *p, unsigned n) : p_(p), n_(n) {}`
    `required_questions: []` — no ledger row, invisible to the coverage gate, over exactly
    the construct `caller-contract` exists to ask about.
    """
    source = (
        "struct Buf {\n"
        "    Buf(char *p, unsigned n)\n"
        "        : p_(p),\n"
        "          n_(n) {}\n"
        "    char *p_;\n"
        "    unsigned n_;\n"
        "};\n"
    )
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "buf.cpp").write_text(source, encoding="utf-8")
    out = tmp_path / "out"
    assert _run_cli(tmp_path, out).returncode == 0
    unit = next(u for u in load_units(out)["units"] if u["function"] == "Buf")
    assert "caller-contract" in unit["required_questions"]
    assert "initialisation" in unit["required_questions"]
    assert unit["sites"]["param"] == [3, 4]
    assert unit["sites"]["outparam"] == [3]


def test_a_kr_definition_still_has_parameters(tmp_path):
    """`int kr(a, b) int a; char *b; { … }` must not yield `parameters: []`.

    The parameter list holds bare identifiers and the types are `declaration` siblings, so a
    parser that reads only the list asks neither `caller-contract` nor `initialisation` about
    the out-parameter `b`, and the gate reports the function 100% covered.
    """
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "kr.c").write_text(
        "int kr(a, b)\nint a;\nchar *b;\n{\n    b[0] = (char)a;\n    return a;\n}\n",
        encoding="utf-8",
    )
    out = tmp_path / "out"
    assert _run_cli(tmp_path, out).returncode == 0
    unit = next(u for u in load_units(out)["units"] if u["function"] == "kr")
    assert unit["parameters"] == ["int a;", "char *b;"]
    assert "caller-contract" in unit["required_questions"]
    assert "initialisation" in unit["required_questions"]


def test_one_file_reached_by_two_paths_is_enumerated_once_under_its_canonical_path(tmp_path):
    """Cutting symlink cycles on DIRECTORIES alone lets one inode be discovered twice.

    `real/r.c`, `top/link -> ../real` and `top/alias.c -> ../real/r.c` then produce two units
    for one file — double-billed against the ledger — with the canonical path, which is what
    a finding cites, missing from the unit list entirely.
    """
    (tmp_path / "real").mkdir()
    (tmp_path / "top").mkdir()
    (tmp_path / "real" / "r.c").write_text("int r(void) { return 1; }\n", encoding="utf-8")
    (tmp_path / "top" / "link").symlink_to(tmp_path / "real", target_is_directory=True)
    (tmp_path / "top" / "alias.c").symlink_to(tmp_path / "real" / "r.c")
    found, _, _ = discover_sources(tmp_path, [])
    assert sorted(str(p.relative_to(tmp_path)) for p in found) == ["real/r.c"]
    # And the choice does not depend on traversal order, or renaming a directory flips
    # which spelling of the file the unit list carries.
    again, _, _ = discover_sources(tmp_path, [])
    assert found == again


def test_a_void_cast_is_not_a_conversion_site(tmp_path):
    """`(void)x;` is the discard idiom, not a conversion.

    Counting it puts every such line in the `integer` population, and the gate demands set
    equality, so the reviewer has to account for lines that cannot hold a conversion bug.
    """
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "v.c").write_text(
        "int v(int a, int b)\n{\n    (void)a;\n    (void)b;\n    return (int)(long)b;\n}\n",
        encoding="utf-8",
    )
    out = tmp_path / "out"
    assert _run_cli(tmp_path, out).returncode == 0
    unit = next(u for u in load_units(out)["units"] if u["function"] == "v")
    assert unit["sites"]["conversion"] == [5]


def test_an_else_arm_is_a_seam(tmp_path):
    """`} else {` has to be a candidate chunk start, or one unit straddles both arms.

    Returning the inner seams of each branch and not the branch STARTS leaves exactly the
    one cut a reader most needs the partition not to make.
    """
    # One statement per arm, spread over 40 lines: the arms hold no seam of their own, so
    # the only candidate that can separate them is the `else` itself.
    then_body = "    x = 1\n" + "".join("     + 1\n" for _ in range(38)) + "     + 1;\n"
    else_body = "    x = 2\n" + "".join("     + 2\n" for _ in range(38)) + "     + 2;\n"
    source = (
        "int branchy(int x)\n{\n  if (x > 0) {\n"
        + then_body
        + "  } else {\n"
        + else_body
        + "  }\n  return x;\n}\n"
    )
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "b.c").write_text(source, encoding="utf-8")
    out = tmp_path / "out"
    assert _run_cli(tmp_path, out, "--max-unit-lines", "30").returncode == 0
    units = [u for u in load_units(out)["units"] if u["function"] == "branchy"]
    starts = [u["start_line"] for u in units]
    else_line = line_of(source, "} else {")
    assert else_line in starts, f"chunks start at {starts}; the else arm is at {else_line}"
    straddling = [u for u in units if u["start_line"] < else_line < u["end_line"]]
    assert not straddling, "one unit covers both arms of the branch"


@pytest.mark.parametrize(
    "extra",
    [["--lines-per-agent", "0"], ["--agents", "0"], ["--agent-min", "9", "--agent-max", "2"]],
    ids=["lines-per-agent-zero", "agents-zero", "min-above-max"],
)
def test_an_unusable_fan_out_argument_exits_two_rather_than_defaulting(tmp_path, extra):
    """Each escapes the exit-2 contract in its own way if it is not range-checked.

    `--lines-per-agent 0` is an uncaught ZeroDivisionError with no units.json; `--agents 0`
    reads as "not supplied", so a caller pinning the fan-out for a measured comparison
    silently gets the derived count; `--agent-min` above `--agent-max` returns the minimum
    and violates the maximum with no error at all.
    """
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "a.c").write_text("int a(void) { return 1; }\n", encoding="utf-8")
    out = tmp_path / "out"
    proc = _run_cli(tmp_path, out, *extra)
    assert proc.returncode == 2, proc.stdout
    assert "Traceback" not in proc.stderr
    assert not (out / "units.json").exists()


def test_an_explicit_agent_count_is_still_clamped_to_agent_max(tmp_path):
    """`agents or default_agent_count(...)` lets `--agents` bypass `--agent-max` entirely,
    while README.md and SKILL.md both describe the fan-out as clamped."""
    (tmp_path / "src").mkdir()
    for n in range(6):
        (tmp_path / "src" / f"f{n}.c").write_text(f"int f{n}(void) {{ return {n}; }}\n")
    out = tmp_path / "out"
    argv = ("--agents", "40", "--agent-min", "1", "--agent-max", "3")
    assert _run_cli(tmp_path, out, *argv).returncode == 0
    assert len(json.loads((out / "units.json").read_text())["assignments"]) <= 3


def test_a_macro_substitution_that_makes_the_parse_worse_is_discarded(tmp_path):
    """`if errors >= best_errors: break` is the only thing keeping a worse parse out.

    A worse parse flattens function bodies into file-scope units, so sites are lost,
    questions are never asked, and `coverage_pct: 100.0` over the shrunken population reads
    identically to 100% over the true one.
    """
    good = _substitute_outside_directives(b"#define Q\nQ int f(void) { return 1; }\n", {b"Q": b""})
    assert b"Q int" not in good
    # The guard itself: a candidate parse with MORE errors than the best so far is dropped.
    calls: list[bytes] = []

    class FakeNode:
        def __init__(self, errors):
            self.errors = errors
            self.has_error = errors > 0
            self.type = "ERROR" if errors else "translation_unit"
            self.is_missing = False
            self.children = []
            self.start_byte = 0
            self.end_byte = 0

    class FakeTree:
        def __init__(self, errors):
            self.root_node = FakeNode(errors)

    class FakeParser:
        def __init__(self, counts):
            self.counts = list(counts)

        def parse(self, source):
            calls.append(source)
            return FakeTree(self.counts.pop(0))

    import enumerate_units as eu

    original = eu._idents_in_errors
    eu._idents_in_errors = lambda node, src, out: out.add(b"Q")
    try:
        tree, applied = eu.parse_tolerant(FakeParser([2, 5]), b"Q int f(void);\n", {b"Q": b""})
    finally:
        eu._idents_in_errors = original
    assert applied == [], "a substitution that raised the error count was kept"
    assert len(calls) == 2


def test_a_source_edit_that_only_shrinks_a_population_fails_the_run(tmp_path):
    """The recorded population is the only thing that catches this one.

    Deleting three of four write sites while leaving one alive keeps `bounds` non-empty, so
    the unit still owes exactly the questions `units.json` says it owes and every unit id
    survives — every structural check agrees. `site_counts` does not: the enumerator
    recorded four lines and the source now holds one. This is precisely the shape the
    measured bypass uses ("leaving one `param` reference alive per unit defeats the
    counts-no-line guard"), and a ledger accounting only the survivors otherwise scores 100%
    with zero violations.
    """
    root, _out, units_json = _tampered_run(tmp_path)
    source = root / "src" / "a.c"
    lines = source.read_text(encoding="utf-8").splitlines()
    edited = ["    (void)src;" if "] = src[" in line else line for line in lines]
    changed = sum(1 for a, b in zip(lines, edited, strict=True) if a != b)
    assert changed == 3, "the fixture stopped matching"
    source.write_text("\n".join(edited) + "\n", encoding="utf-8")
    message = attach_sites_refusal(units_json)
    assert "site line(s) and the source now holds" in message
    # And the id set and the question set both still agree, so nothing else could have.
    assert "The tree moved" not in message
    assert "the source now counts sites for" not in message


# ------------------------------------------------- what units.json pins about the parse


def test_a_count_preserving_source_edit_is_a_KNOWN_hole_in_the_binding(tmp_path):
    """The accepted cost of having no `site_digests`, pinned so nobody rediscovers it as new.

    A digest per (unit, question) would catch a count-preserving relocation, which
    `site_counts` alone cannot. It would also publish the answer key: an unsalted SHA-256
    over a line list whose bounding parameters, `site_counts` (k) and the unit's line span
    (n), sit in the same object, so the preimage search is C(n, k) — 68.5% of a 154-unit
    corpus recovered in 37 core-seconds from `units.json` and `hashlib` alone. There is no
    third option: any record the gate can compare, an agent with Read can invert or an agent
    with Write can rewrite. This asserts the binding ACCEPTS the edit, so that the day
    someone proposes pinning the lines again, the reason it was not is here.
    """
    root, _out, units_json = _tampered_run(tmp_path)
    source = root / "src" / "a.c"
    lines = source.read_text(encoding="utf-8").splitlines()
    # Swap two adjacent writes with the conversion above them: every per-question count is
    # identical, the unit ids are identical, only the line numbers move.
    i = lines.index("    size_t want = sizeof(*dst) * n;")
    lines[i], lines[i + 1] = lines[i + 1], lines[i]
    source.write_text("\n".join(lines) + "\n", encoding="utf-8")

    doc = json.loads(units_json.read_text(encoding="utf-8"))
    before = {u["id"]: dict(u["site_counts"]) for u in doc["units"]}
    fresh = tmp_path / "fresh"
    assert _run_cli(root, fresh, "--out-dir", str(fresh)).returncode == 0
    after = {
        u["id"]: dict(u["site_counts"])
        for u in json.loads((fresh / "units.json").read_text(encoding="utf-8"))["units"]
    }
    assert before == after, "the fixture no longer preserves the counts; it proves nothing"

    accepted = attach_sites_through_uv(units_json)
    assert [u["id"] for u in accepted["units"]] == list(before), (
        "the binding refused a count-preserving edit — if that is deliberate, the trade-off "
        "in _bind_to_enumeration's docstring and in SKILL.md is now wrong"
    )


def test_a_unit_with_no_recorded_population_is_refused(tmp_path):
    """The 4th rejection branch, and the only test that reaches it.

    Deleting the per-question record from a unit that owes questions leaves every id, every
    `required_questions` entry and the source itself intact, so the three branches above it
    all agree and deleting this one leaves the whole suite green. Relax it and a worker
    deletes the record, rewrites the source, and the gate scores 100% against a tree that no
    longer exists.
    """
    _root, _out, units_json = _tampered_run(tmp_path)
    doc = json.loads(units_json.read_text(encoding="utf-8"))
    owing = [u for u in doc["units"] if u.get("required_questions")]
    assert owing, "the fixture owes no questions; it proves nothing"
    for unit in owing:
        unit.pop("site_counts", None)
    _rewrite(units_json, doc)
    assert "carries no site_counts" in attach_sites_refusal(units_json)


def test_a_denominator_that_shrank_after_generation_is_refused(tmp_path):
    """Without a recorded denominator, a `checks_required` that shrinks leaves no trace.

    It is read exactly once, from this gate, so 6 of 6 satisfied reads identically to
    10 of 10 in every artifact. The reachable shape needs no shell: delete a source file and
    delete its units from `units.json`, and every structural check agrees — the id set the
    reparse produces matches, every surviving unit's population is untouched, and the run
    scores 100% over a partition 40% smaller than the one the review was dispatched from.
    `totals.checks_required` is written when the partition is generated, so the gate can
    derive the same number from the same file and see that it moved.
    """
    root = tmp_path / "tree"
    (root / "src").mkdir(parents=True)
    (root / "src" / "a.c").write_text(TAMPER_C, encoding="utf-8")
    (root / "src" / "b.c").write_text(TAMPER_C.replace("relay_copy", "relay_dup"), "utf-8")
    out = tmp_path / "run"
    assert _run_cli(root, out).returncode == 0
    units_json = out / "units.json"
    doc = json.loads(units_json.read_text(encoding="utf-8"))
    recorded = doc["totals"]["checks_required"]

    (root / "src" / "b.c").unlink()
    doc["files"] = [f for f in doc["files"] if f != "src/b.c"]
    doc["units"] = [u for u in doc["units"] if u["file"] != "src/b.c"]
    kept = sum(len(u["required_questions"]) for u in doc["units"])
    assert 0 < kept < recorded, (kept, recorded)
    _rewrite(units_json, doc)
    parts = out / "parts"
    parts.mkdir(exist_ok=True)
    (parts / "review-unit-01.json").write_text(
        json.dumps({"ledger": [{"unit_id": "x", "question": "bounds", "verdict": "clean"}]}),
        encoding="utf-8",
    )

    uv = shutil.which("uv")
    assert uv, "uv is not on PATH; the gate's reparse cannot run"
    gate = subprocess.run(
        [uv, "run", "--no-project", str(SCRIPT.parent / "check_ledger.py"), "--run-dir", str(out)],
        capture_output=True,
        text=True,
        check=False,
        timeout=300,
    )
    assert gate.returncode == 2, gate.stdout
    assert f"units.json records {recorded} required check(s)" in gate.stderr, gate.stderr
    assert f"now owes {kept}" in gate.stderr


# --------------------------------------------------------- symlinks and the walk


def test_a_non_source_alias_does_not_delete_its_target_from_the_review(tmp_path):
    """Deduplicating on the smallest SPELLING before the extension filter loses the target.

    A non-source spelling wins the tie-break and is then filtered out, taking the real file
    with it: `src/a.txt -> z.c` gives `files: ['src/other.c']`, `unreadable: []`,
    `excluded: []`, exit 0 — `src/z.c` in no unit, in no assignment, named in no field of
    any artifact, and the run reporting success. `src/OLD-parse.bak -> parse.c` kills the
    whole run with "no C/C++ source files".
    """
    src = tmp_path / "src"
    src.mkdir()
    (src / "z.c").write_text("int z(void){return 0;}\n", encoding="utf-8")
    (src / "other.c").write_text("int o(void){return 1;}\n", encoding="utf-8")
    (src / "a.txt").symlink_to("z.c")
    (src / "OLD-z.bak").symlink_to("z.c")
    out = tmp_path / "out"
    proc = _run_cli(tmp_path, out)
    assert proc.returncode == 0, proc.stderr
    doc = json.loads((out / "units.json").read_text(encoding="utf-8"))
    assert sorted(doc["files"]) == ["src/other.c", "src/z.c"], doc["files"]


def test_a_directory_alias_does_not_key_the_units_at_the_alias_path(tmp_path):
    """`seen` is keyed on the resolved directory and the queue pops in path order, so an
    alias that sorts first can be walked and the real directory `continue`d — every unit in
    it keyed at `alink/a.c`, and a finding filed at `src/a.c` (the path the compiler, the
    reviewer and every other tool use) matching no unit id at all."""
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "a.c").write_text("int a(void){return 0;}\n", encoding="utf-8")
    (tmp_path / "alink").symlink_to("src", target_is_directory=True)
    out = tmp_path / "out"
    assert _run_cli(tmp_path, out).returncode == 0
    doc = json.loads((out / "units.json").read_text(encoding="utf-8"))
    assert doc["files"] == ["src/a.c"], doc["files"]


def test_a_file_symlink_out_of_its_directory_is_refused(tmp_path):
    """An above-root guard that runs only on queue-popped DIRECTORIES lets a file symlink
    escape it: out-of-scope content is enumerated, parsed, billed to an agent and given
    ledger rows under a path that looks in-scope."""
    root = tmp_path / "proj" / "inner"
    root.mkdir(parents=True)
    (root / "in.c").write_text("int i(void){return 0;}\n", encoding="utf-8")
    (tmp_path / "proj" / "vendor").mkdir()
    (tmp_path / "proj" / "vendor" / "secret.c").write_text("int s(void){return 1;}\n")
    (root / "leak.c").symlink_to("../vendor/secret.c")
    proc = _run_cli(root, tmp_path / "out")
    assert proc.returncode == 2, proc.stdout
    assert "leak.c" in proc.stderr and "outside" in proc.stderr


def test_a_previous_runs_artifacts_do_not_survive_into_this_one(tmp_path):
    """`assemble_findings.py` exits 2 without writing anything when a part file is
    unreadable, so any surviving artifact of the last run into this directory is one the
    assemble agent — told to answer `artifacts_written` from the DIRECTORY rather than the
    exit code — honestly reports as true, and SKILL.md then says "the artifacts are complete
    and on disk; do not re-run the assembler". The previous run's findings and the previous
    run's coverage would be reported as this run's."""
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "a.c").write_text("int a(int n){char b[4]; b[0]=n; return b[0];}\n")
    out = tmp_path / "out"
    assert _run_cli(tmp_path, out).returncode == 0
    stale = ["findings.json", "REPORT.md", "REPORT.sarif", "ledger-gate.json"]
    for name in stale:
        (out / name).write_text('{"checks_required": 10}', encoding="utf-8")
    assert _run_cli(tmp_path, out).returncode == 0
    assert [n for n in stale if (out / n).exists()] == []


def test_a_long_else_if_chain_is_cut_at_arm_boundaries_not_at_the_cap(tmp_path):
    """`totals.hard_split == 0` cannot fail for the thing it appears to hold.

    `_direct_seams` yields every statement of every arm, so `seam_set` covers nearly every
    line and `at_seam` is essentially always true whether or not a structural seam was
    found. Measured on this fixture at the default cap of 150: `hard_split: 0` and every
    chunk starting at an exact multiple of the cap — `1, 151, 301, 451, …`, not one of them
    on an `if` or `} else if` boundary. Raw line-count cuts wearing the `seam` label, which
    is why this asserts the boundaries themselves.
    """
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "opt.c").write_text(_else_if_chain(250), encoding="utf-8")
    out = tmp_path / "out"
    assert _run_cli(tmp_path, out, "--max-unit-lines", "150").returncode == 0
    doc = json.loads((out / "units.json").read_text(encoding="utf-8"))
    starts = sorted(u["start_line"] for u in doc["units"] if u["kind"] == "function")
    assert len(starts) > 3, starts
    source = _else_if_chain(250).splitlines()
    arms = {n for n, line in enumerate(source, start=1) if "} else if" in line or n == 1}
    assert set(starts) <= arms, [s for s in starts if s not in arms]
    assert doc["totals"]["hard_split"] == 0, "a chunk fell back to a raw line-count cut"


def test_a_try_catch_is_cut_at_the_catch_and_not_through_it(tmp_path):
    """`_direct_seams` needs a `try_statement` case, not only an `else_clause` one.

    Without it the exact failure the `else_clause` case prevents recurs one node type over:
    a 62-line `try { … } catch (…) { … }` at a 20-line cap gives a 2-line runt for the
    signature and then hard-splits BOTH arms, cutting straight through `} catch` — the one
    cut a reader most needs the partition not to make.
    """
    body = "\n".join(f"    t{i}();" for i in range(28))
    tail = "\n".join(f"    c{i}();" for i in range(28))
    src = (
        "void f() {\n  try {\n"
        + body
        + "\n  } catch (const std::exception &e) {\n"
        + tail
        + "\n  }\n}\n"
    )
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "t.cpp").write_text(src, encoding="utf-8")
    out = tmp_path / "out"
    assert _run_cli(tmp_path, out, "--max-unit-lines", "20").returncode == 0
    doc = json.loads((out / "units.json").read_text(encoding="utf-8"))
    starts = sorted(u["start_line"] for u in doc["units"] if u["kind"] == "function")
    catch_line = next(n for n, line in enumerate(src.splitlines(), start=1) if "} catch" in line)
    assert catch_line in starts, (starts, catch_line)
    assert doc["totals"]["hard_split"] == 0, "an arm still fell back to a raw line-count cut"


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-q"]))
