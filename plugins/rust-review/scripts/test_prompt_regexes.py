"""Regression tests for the detector regexes shipped in prompt and skill files.

These extract the actual patterns from the prompt cluster files and SKILL.md so
the tests stay in sync with what workers run, then exercise them against curated
Rust snippets. Python's `re` is the oracle: the boundary/class semantics relied
on here (`\\b`, `[^]]`, `(?:...)`) match ripgrep — the Rust regex engine the
`rg seed` cluster patterns run under. The SKILL.md `grep -rlE` probes lean on
`\\b`/`\\s`, which are GNU-grep extensions, not POSIX ERE (`(?:...)` is not POSIX
either); on non-GNU grep, SKILL.md documents the POSIX-class fallbacks
(`\\s`->`[[:space:]]`, drop `\\b`). This oracle does not validate that grep path.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

PLUGIN_ROOT = Path(__file__).resolve().parent.parent
CLUSTERS = PLUGIN_ROOT / "prompts" / "clusters"
SKILL = PLUGIN_ROOT / "skills" / "rust-review" / "SKILL.md"

PROMPT_PATTERN_RE = re.compile(r'rg seed: "((?:[^"\\]|\\.)*)"')
GREP_E_RE = re.compile(r"grep -rlE '([^']*)'")


def _select(patterns: list[str], needle: str) -> str:
    found = [p for p in patterns if needle in p]
    assert len(found) == 1, f"expected exactly one pattern containing {needle!r}, got {found}"
    return found[0]


def cluster_pattern(name: str, needle: str) -> str:
    patterns = PROMPT_PATTERN_RE.findall((CLUSTERS / name).read_text(encoding="utf-8"))
    return _select(patterns, needle)


def skill_pattern(needle: str) -> str:
    patterns = GREP_E_RE.findall(SKILL.read_text(encoding="utf-8"))
    return _select(patterns, needle)


def matches(pattern: str, text: str) -> bool:
    return re.search(pattern, text) is not None


def test_packed_field_borrow_matches_field_and_tuple_borrows() -> None:
    pattern = cluster_pattern("layout-safety.md", r"[\w.]")
    assert matches(pattern, "let x = &foo.bar;")
    assert matches(pattern, "let x = &foo.0;")
    assert matches(pattern, "let x = &mut foo.bar;")


def test_refcell_inventory_skips_bare_try_borrow_mut() -> None:
    pattern = cluster_pattern("panic-dos.md", r"\.borrow_mut")
    assert matches(pattern, "cell.borrow_mut();")
    assert matches(pattern, "let c = RefCell::new(0);")
    assert not matches(pattern, "cell.try_borrow_mut();")


def test_refcell_crash_chain_matches_unwrap_and_expect() -> None:
    pattern = cluster_pattern("panic-dos.md", "try_borrow_mut")
    assert matches(pattern, "cell.try_borrow_mut().unwrap();")
    assert matches(pattern, 'cell.try_borrow_mut().expect("held");')
    assert not matches(pattern, "cell.try_borrow_mut();")


def test_hashmap_inventory_skips_substring_types() -> None:
    pattern = cluster_pattern("logic-correctness.md", "HashMap")
    assert matches(pattern, "use std::collections::HashMap;")
    assert matches(pattern, "HashSet::new();")
    assert not matches(pattern, "type M = FxHashMap<u8, u8>;")


def test_path_inventory_covers_join_and_push() -> None:
    pattern = cluster_pattern("input-os-safety.md", "PathBuf")
    assert matches(pattern, 'p.join("x");')
    assert matches(pattern, 'p.push("x");')
    assert matches(pattern, "let p = PathBuf::new();")


def test_has_packed_repr_matches_outer_and_inner_attrs() -> None:
    pattern = skill_pattern("packed")
    assert matches(pattern, "#[repr(packed)]")
    assert matches(pattern, "#[repr(C, packed)]")
    assert matches(pattern, "#![repr(packed)]")
    assert not matches(pattern, "#[repr(C)]")


def test_ffi_extern_inventory_matches_bare_extern_fn() -> None:
    pattern = cluster_pattern("ffi-cross-language.md", "efiapi")
    assert matches(pattern, 'extern "C" fn foo();')
    assert matches(pattern, "extern { fn foo(); }")
    assert matches(pattern, "extern fn foo() {}")
    assert not matches(pattern, "let external = 1;")


def test_has_fs_io_path_probe_matches_path_types() -> None:
    pattern = skill_pattern(r"\bPath\b")
    assert matches(pattern, "fn f(p: &Path) {}")
    assert matches(pattern, "use std::path::PathBuf;")
    assert not matches(pattern, "let x = 1;")


def test_has_fs_io_module_probe_matches_fs_and_file_apis() -> None:
    pattern = skill_pattern("symlink_metadata")
    assert matches(pattern, "use std::fs; fs::read(p);")
    assert matches(pattern, 'File::open("x");')
    assert not matches(pattern, "let x = 1;")


if __name__ == "__main__":
    import sys

    raise SystemExit(pytest.main([__file__, *sys.argv[1:]]))
