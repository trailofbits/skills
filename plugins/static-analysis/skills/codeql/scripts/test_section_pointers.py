"""A pointer to a section must land on a section that exists.

Deduplicating the docs replaced inline copies with pointers: the workflow says
`Follow "Method 1: Autobuild" in .../build-database.md` instead of restating the
command, and build-database.md links back to SKILL.md for the fresh-shell rule
rather than repeating it. That trade is only worth making if the pointers are real.

The repo validator resolves file paths, not section names or anchors, so a heading
renamed by one character leaves a pointer aimed at nothing and every check still
green. Both forms are covered here:

    [text](../SKILL.md#each-bash-call-is-a-fresh-shell)   markdown anchor
    Follow "Method 1: Autobuild" in <path>/build-database.md   prose pointer
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

SCRIPTS_DIR = Path(__file__).resolve().parent
SKILL_ROOT = SCRIPTS_DIR.parent
PLUGIN_ROOT = SKILL_ROOT.parent.parent
SKIP_DIRS = {".pytest_cache", "__pycache__", ".venv", ".ruff_cache"}

WORKFLOW_JS = PLUGIN_ROOT / "workflows" / "codeql-build.js"

# `codeql-build.js` cannot know where the skill is installed, so its pointers are written
# against a variable the Detect agent resolves at runtime — `${SKILL_DIR}/references/x.md` in
# a template literal, `$SKILL_DIR/references/x.md` in the one prompt that runs before it is
# known. Both spellings mean this directory.
RUNTIME_ROOT_VAR = "SKILL_DIR"
RUNTIME_PREFIX = re.compile(r"^\$\{?" + RUNTIME_ROOT_VAR + r"\}?/")

HEADING = re.compile(r"^#{1,6}\s+(.+?)\s*$", re.MULTILINE)
# [label](path.md#anchor) — only links carrying an anchor.
ANCHOR_LINK = re.compile(r"\[[^\]]*\]\(([^)#\s]+\.md)#([A-Za-z0-9_-]+)\)")
# `"Section Name" in <something>.md`, the form the workflow prompts use.
PROSE_POINTER = re.compile(r"[\"“]([^\"”\n]{3,80})[\"”]\s+in\s+(\S+?\.md)\b")


def _doc_files() -> list[Path]:
    return sorted(
        p
        for p in PLUGIN_ROOT.rglob("*")
        if p.suffix in {".md", ".js"}
        and not SKIP_DIRS.intersection(p.parts)
        and not p.name.startswith("test_")
    )


def _slug(heading: str) -> str:
    """GitHub's anchor rule: lowercase, drop punctuation, spaces to hyphens."""
    text = heading.strip().lower()
    text = re.sub(r"[^\w\s-]", "", text)
    return re.sub(r"\s+", "-", text).strip("-")


def _headings(path: Path) -> list[str]:
    return HEADING.findall(path.read_text(encoding="utf-8"))


def _js_constants(source: str) -> dict[str, str]:
    """Resolve the path constants a workflow builds its pointers from.

    Read from the source rather than hardcoded, so renaming SKILL_DIR does not quietly
    turn every pointer in that file into an unresolvable string this check skips.
    """
    values: dict[str, str] = {}
    for name, raw in re.findall(r"const (\w+) = [`'\"]([^`'\"]+)[`'\"]", source):
        values[name] = re.sub(r"\$\{(\w+)\}", lambda m: values.get(m.group(1), m.group(0)), raw)
    return values


def _resolve(target: str, source_file: Path, constants: dict[str, str]) -> Path | None:
    """Turn a pointer's path into a real file, or None if it is not one we can check."""
    resolved = re.sub(r"\$\{(\w+)\}", lambda m: constants.get(m.group(1), m.group(0)), target)
    # `${SKILL_DIR}/references/x.md` is a real pointer whose root is only known at runtime.
    # Rewriting it onto this checkout keeps it checkable; without this it reads as an
    # unresolvable string and every pointer in the workflow is skipped in silence.
    resolved = RUNTIME_PREFIX.sub(f"{SKILL_ROOT}/", resolved)
    if "${" in resolved or "{baseDir}" in resolved:
        return None
    candidates = [Path(resolved), PLUGIN_ROOT.parent.parent / resolved]
    if not resolved.startswith("/"):
        candidates.insert(0, (source_file.parent / resolved).resolve())
    for candidate in candidates:
        if candidate.is_file():
            return candidate
    return None


def _collect() -> tuple[list[tuple[Path, str, Path, str]], list[tuple[Path, str, Path, str]]]:
    anchors: list[tuple[Path, str, Path, str]] = []
    prose: list[tuple[Path, str, Path, str]] = []
    for path in _doc_files():
        text = path.read_text(encoding="utf-8")
        constants = _js_constants(text) if path.suffix == ".js" else {}
        for target, anchor in ANCHOR_LINK.findall(text):
            resolved = _resolve(target, path, constants)
            if resolved is not None:
                anchors.append((path, anchor, resolved, target))
        for section, target in PROSE_POINTER.findall(text):
            resolved = _resolve(target, path, constants)
            if resolved is not None:
                prose.append((path, section, resolved, target))
    return anchors, prose


ANCHORS, PROSE = _collect()


def test_pointers_were_found() -> None:
    """Guard the guard: two regexes matching nothing would pass this file in silence."""
    assert ANCHORS, f"no anchored markdown links found under {PLUGIN_ROOT} — the scanner broke"
    assert PROSE, f"no prose section pointers found under {PLUGIN_ROOT} — the scanner broke"


def test_the_workflows_pointers_are_still_checked() -> None:
    """The global guard above is satisfied by markdown alone.

    Every pointer in `codeql-build.js` carries a `${SKILL_DIR}` prefix, so one change to how
    that prefix is spelled makes all of them unresolvable — and `_resolve` returning None
    reports that as "nothing to check here", indistinguishable from a file with no pointers.
    """
    from_workflow = [entry for entry in PROSE if entry[0] == WORKFLOW_JS]
    assert len(from_workflow) >= 4, (
        f"only {len(from_workflow)} prose pointers resolved out of {WORKFLOW_JS.name} — its "
        f"paths are no longer being checked against the sections they name"
    )


def test_the_workflow_does_not_hardcode_a_path_into_this_repo() -> None:
    """A repo-relative skill path resolves only in a checkout of the marketplace.

    `codeql-build.js` shipped `const SKILL_DIR = 'plugins/static-analysis/skills/codeql'`.
    Installed, the first build block sourced a `build_log.sh` that was not there, exited 127,
    and every rung of the ladder reported a build failure for a project that builds. The path
    is now resolved at runtime by the Detect phase; nothing else in this suite would notice it
    being written back down, because CI runs from the repo where the literal does resolve.
    """
    source = WORKFLOW_JS.read_text(encoding="utf-8")
    offenders = [
        line.strip()
        for line in source.splitlines()
        if "plugins/static-analysis" in line and not line.lstrip().startswith("//")
    ]
    assert not offenders, (
        "the workflow names its own path inside this repository, which only resolves when the "
        "run starts in a checkout of it:\n  " + "\n  ".join(offenders)
    )


@pytest.mark.parametrize(
    ("source", "anchor", "target", "raw"),
    ANCHORS,
    ids=[f"{s.relative_to(PLUGIN_ROOT)}->{raw}#{a}" for s, a, _, raw in ANCHORS],
)
def test_anchor_link_lands_on_a_heading(source: Path, anchor: str, target: Path, raw: str) -> None:
    slugs = {_slug(h) for h in _headings(target)}
    assert anchor in slugs, (
        f"{source.relative_to(PLUGIN_ROOT)} links to {raw}#{anchor}, but that file has no "
        f"heading with that anchor. Available: {', '.join(sorted(slugs))}"
    )


@pytest.mark.parametrize(
    ("source", "section", "target", "raw"),
    PROSE,
    ids=[f"{s.relative_to(PLUGIN_ROOT)}->{sec}" for s, sec, _, raw in PROSE],
)
def test_prose_pointer_names_a_real_section(
    source: Path, section: str, target: Path, raw: str
) -> None:
    """Prefix match: "Method 4: No-Build Fallback" may point at a heading that goes on
    to say "(Last Resort)". A pointer that is not even a prefix is aimed at nothing."""
    headings = _headings(target)
    assert any(h.startswith(section) for h in headings), (
        f'{source.relative_to(PLUGIN_ROOT)} points at "{section}" in {raw}, which has no '
        f"heading starting with that. Headings: {'; '.join(headings)}"
    )
