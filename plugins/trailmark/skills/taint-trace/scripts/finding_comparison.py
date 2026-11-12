"""Match warning locations through preserved sources, retaining distinct occurrences."""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass
from difflib import SequenceMatcher
from pathlib import Path

from trace_artifacts import JsonObject, relative

type ContextPair = tuple[JsonObject, JsonObject]
type Declaration = tuple[str, int, int]


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


def file_declarations(
    context: JsonObject, target: Path, files: set[str]
) -> dict[str, list[Declaration]]:
    declarations: dict[str, list[Declaration]] = {}
    for ident, node in context.get("graph", {}).get("nodes", {}).items():
        location = node.get("location") or {}
        file = relative(location.get("file_path", ""), target)
        if file in files:
            declarations.setdefault(file, []).append(
                (ident, location.get("start_line", 0), location.get("end_line", 0))
            )
    return declarations


def source_mappings(
    contexts: ContextPair, target: Path, files: set[str]
) -> dict[str, SourceMapping]:
    before, after = (captured_sources(context, target, files) for context in contexts)
    original, rebound = (file_declarations(context, target, files) for context in contexts)
    return {
        file: source_mapping(
            before.get(file, []),
            after.get(file, []),
            declarations=(original.get(file, []), rebound.get(file, [])),
        )
        for file in before.keys() | after.keys()
    }


def declaration_at(declarations: list[Declaration], line: int) -> tuple:
    candidates = [
        (end - start, ident) for ident, start, end in declarations if start <= line <= end
    ]
    smallest = min((size for size, _ in candidates), default=None)
    return tuple(sorted(ident for size, ident in candidates if size == smallest))


def line_occurrences(
    lines: list[str], declarations: list[Declaration], owner: tuple, text: str
) -> int:
    if owner:
        _, start, end = next(item for item in declarations if item[0] == owner[0])
        return lines[start - 1 : end].count(text)
    return lines.count(text)


def stable_occurrences(mapping: SourceMapping, owner: tuple, text: str) -> bool:
    before = line_occurrences(mapping.original_lines, mapping.original_declarations, owner, text)
    after = line_occurrences(mapping.rebound_lines, mapping.rebound_declarations, owner, text)
    return before == after and (
        bool(owner) or before < 2 or mapping.original_lines == mapping.rebound_lines
    )


def rebound_line(line: int, mapping: SourceMapping) -> int | None:
    original_line = mapping.lines.get(line)
    if original_line is None:
        return None
    before = declaration_at(mapping.original_declarations, original_line)
    after = declaration_at(mapping.rebound_declarations, line)
    if before != after or len(before) > 1:
        return None
    if not stable_occurrences(mapping, before, mapping.rebound_lines[line - 1]):
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
