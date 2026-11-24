"""Match warning locations through preserved sources, retaining distinct occurrences."""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass
from difflib import SequenceMatcher
from pathlib import Path

from trace_artifacts import JsonObject, relative

type ContextPair = tuple[JsonObject, JsonObject]
type StructuralIdentity = tuple[tuple[str, str], ...]


@dataclass(frozen=True)
class Declaration:
    identity: StructuralIdentity | None
    start: int
    end: int


@dataclass(frozen=True)
class SourceMapping:
    lines: dict[int, int]
    original_lines: list[str]
    rebound_lines: list[str]
    original_declarations: list[Declaration]
    rebound_declarations: list[Declaration]


def finding_key(item: JsonObject, target: Path) -> tuple:
    return (
        item["rule_id"],
        relative(item["file"], target),
        item["line"],
        item.get("end_line", item["line"]),
    )


def captured_sources(context: JsonObject, target: Path, files: set[str]) -> dict[str, list[str]]:
    return {
        relative(item["file"], target): Path(item["path"])
        .read_text(encoding="utf-8", errors="replace")
        .splitlines()
        for item in context.get("source_snapshots", [])
        if relative(item["file"], target) in files
    }


def source_mapping(
    before: list[str],
    after: list[str],
    *,
    declarations: tuple[list[Declaration], list[Declaration]],
) -> SourceMapping:
    lines = {
        block.b + offset + 1: block.a + offset + 1
        for block in SequenceMatcher(None, before, after).get_matching_blocks()
        for offset in range(block.size)
    }
    return SourceMapping(lines, before, after, *declarations)


def declaration_header(node: JsonObject, lines: list[str]) -> tuple[str, str] | None:
    location = node.get("location") or {}
    start, end = location.get("start_line", 0), location.get("end_line", 0)
    if not 1 <= start <= end or start > len(lines):
        return None
    kind = node.get("kind", "")
    if node.get("origin") == "synthetic":
        return kind, node.get("name", "")
    # Frontend columns count UTF-8 bytes, including for inline anonymous declarations.
    text = lines[start - 1].encode("utf-8")
    stop = location.get("end_col") if start == end else None
    header = text[location.get("start_col") or 0 : stop].decode("utf-8", errors="replace").strip()
    return (kind, header) if header else None


def declaration_identity(
    ident: str,
    graph: JsonObject,
    parents: dict[str, set[str]],
    sources: dict[str, list[str]],
    target: Path,
    *,
    visited: frozenset[str] = frozenset(),
) -> StructuralIdentity | None:
    node = graph.get("nodes", {}).get(ident, {})
    if ident in visited or len(parents.get(ident, set())) > 1:
        return None
    if node.get("kind") == "module":
        return ()
    file = relative((node.get("location") or {}).get("file_path", ""), target)
    header = declaration_header(node, sources.get(file, []))
    if header is None:
        return None
    owner: StructuralIdentity | None = ()
    for parent in parents.get(ident, set()):
        owner = declaration_identity(
            parent, graph, parents, sources, target, visited=visited | {ident}
        )
    return (*owner, header) if owner is not None else None


def file_declarations(
    context: JsonObject, target: Path, sources: dict[str, list[str]]
) -> dict[str, list[Declaration]]:
    graph = context.get("graph", {})
    parents: dict[str, set[str]] = {}
    for edge in graph.get("edges", []):
        if edge.get("kind") == "contains":
            parents.setdefault(edge["target"], set()).add(edge["source"])
    declarations: dict[str, list[Declaration]] = {}
    for ident, node in graph.get("nodes", {}).items():
        location = node.get("location") or {}
        file = relative(location.get("file_path", ""), target)
        if file in sources and node.get("kind") not in {"module", "proxy"}:
            declarations.setdefault(file, []).append(
                Declaration(
                    declaration_identity(ident, graph, parents, sources, target),
                    location.get("start_line", 0),
                    location.get("end_line", 0),
                )
            )
    return declarations


def source_mappings(
    contexts: ContextPair, target: Path, files: set[str]
) -> dict[str, SourceMapping]:
    before, after = (captured_sources(context, target, files) for context in contexts)
    original, rebound = (
        file_declarations(context, target, sources)
        for context, sources in zip(contexts, (before, after), strict=True)
    )
    return {
        file: source_mapping(
            before.get(file, []),
            after.get(file, []),
            declarations=(original.get(file, []), rebound.get(file, [])),
        )
        for file in before.keys() | after.keys()
    }


def declaration_at(declarations: list[Declaration], line: int) -> list[Declaration]:
    candidates = [item for item in declarations if item.start <= line <= item.end]
    smallest = min((item.end - item.start for item in candidates), default=None)
    return [item for item in candidates if item.end - item.start == smallest]


def mapped_boundary(line: int, mapping: SourceMapping) -> int | None:
    # A synthetic PHP script can end at column zero after its final newline.
    # That terminal boundary is absent from splitlines(), but corresponds to EOF.
    if line == len(mapping.rebound_lines) + 1:
        return len(mapping.original_lines) + 1
    return mapping.lines.get(line)


def matching_owners(
    before: list[Declaration], after: list[Declaration], mapping: SourceMapping
) -> bool:
    if len(before) != len(after) or len(before) > 1:
        return False
    if not before:
        return True
    old, new = before[0], after[0]
    if old.identity is None or old.identity != new.identity:
        return False
    if (mapping.lines.get(new.start), mapped_boundary(new.end, mapping)) != (old.start, old.end):
        return False
    # Equal anonymous declarations remain separate occurrences; adding another is ambiguous.
    counts = [
        sum(item.identity == old.identity for item in declarations)
        for declarations in (mapping.original_declarations, mapping.rebound_declarations)
    ]
    return counts[0] == counts[1]


def line_occurrences(lines: list[str], owner: list[Declaration], text: str) -> int:
    if owner:
        return lines[owner[0].start - 1 : owner[0].end].count(text)
    return lines.count(text)


def stable_occurrences(
    mapping: SourceMapping, owners: tuple[list[Declaration], list[Declaration]], text: str
) -> bool:
    before = line_occurrences(mapping.original_lines, owners[0], text)
    after = line_occurrences(mapping.rebound_lines, owners[1], text)
    return before == after and (
        bool(owners[0]) or before < 2 or mapping.original_lines == mapping.rebound_lines
    )


def rebound_line(line: int, mapping: SourceMapping) -> int | None:
    original_line = mapping.lines.get(line)
    if original_line is None:
        return None
    before = declaration_at(mapping.original_declarations, original_line)
    after = declaration_at(mapping.rebound_declarations, line)
    if not matching_owners(before, after, mapping):
        return None
    if not stable_occurrences(mapping, (before, after), mapping.rebound_lines[line - 1]):
        return None
    return original_line


def rebound_key(item: JsonObject, target: Path, mappings: dict[str, SourceMapping]) -> tuple:
    rule, file, start, end = key = finding_key(item, target)
    if file not in mappings:
        return key  # Historical evidence without source copies keeps exact native locations.
    start, end = (rebound_line(line, mappings[file]) for line in (start, end))
    if start is None or end is None:
        return (*key, "unmatched-enriched-location")
    return rule, file, start, end


def finding_counters(
    records: dict[str, JsonObject], target: Path, contexts: ContextPair
) -> tuple[Counter, Counter]:
    files = {
        relative(item["file"], target)
        for phase in ("baseline", "enriched")
        for item in records[phase].get("findings", [])
    }
    mappings = source_mappings(contexts, target, files)
    before = Counter(finding_key(item, target) for item in records["baseline"].get("findings", []))
    after = Counter(
        rebound_key(item, target, mappings) for item in records["enriched"].get("findings", [])
    )
    return before, after
