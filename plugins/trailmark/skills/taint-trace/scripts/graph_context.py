"""Capture bounded structural context and retain source selection evidence."""

from __future__ import annotations

import contextlib
import io
import json
import shutil
from collections import deque
from pathlib import Path
from typing import TYPE_CHECKING

from catalog import BACKENDS, canonical_language
from trace_artifacts import JsonObject, digest, local_file, relative

if TYPE_CHECKING:
    from trailmark.query.api import QueryEngine

REQUIRED_APIS = (
    "entrypoint_evidence",
    "entrypoint_candidates",
    "source_policy",
    "attack_surface",
    "parse_diagnostics",
    "unresolved_calls",
    "preanalysis",
    "to_json",
    "summary",
    "callers_of",
    "callees_of",
    "entrypoint_paths_to",
)
CONFIG_NAMES = {
    "psalm.xml",
    "psalm.xml.dist",
    ".pyre_configuration",
    "taint.config",
    ".inferconfig",
    ".semgrep.yml",
    ".semgrep.yaml",
    "semgrep.yml",
    "semgrep.yaml",
    "qlpack.yml",
    "qlpack.yaml",
    "codeql-config.yml",
    "codeql-config.yaml",
    "compile_commands.json",
    "pom.xml",
    "build.gradle",
    "build.gradle.kts",
    "composer.json",
    "Cargo.toml",
    "go.mod",
    "Gemfile",
    "Package.swift",
}


def binding_status(matches: list) -> str:
    if not matches:
        return "unresolved"
    return "resolved" if len(matches) == 1 else "ambiguous"


def call_adjacency(graph: JsonObject) -> tuple[dict[str, list[str]], dict[str, list[str]]]:
    incoming: dict[str, list[str]] = {}
    outgoing: dict[str, list[str]] = {}
    for edge in graph["edges"]:
        if edge["kind"] == "calls":
            outgoing.setdefault(edge["source"], []).append(edge["target"])
            incoming.setdefault(edge["target"], []).append(edge["source"])
    return incoming, outgoing


def nearby_nodes(seed: str, incoming: dict, outgoing: dict, limit: int) -> set[str]:
    selected, queue = {seed}, deque([(seed, 0)])
    while queue and len(selected) < limit:
        node, depth = queue.popleft()
        if depth == 2:
            continue
        neighbors = sorted(set(incoming.get(node, []) + outgoing.get(node, [])))
        for neighbor in neighbors:
            if neighbor not in selected:
                selected.add(neighbor)
                queue.append((neighbor, depth + 1))
                if len(selected) >= limit:
                    break
    return selected


def entrypoint_paths(seed: str, incoming: dict, entries: set[str], limit: int) -> list[list[str]]:
    paths = [[seed]] if seed in entries else []
    queue, visited = deque([(seed, [seed])]), {seed}
    while queue and len(visited) < limit:
        node, reverse = queue.popleft()
        if len(reverse) > 8:
            continue
        for parent in sorted(incoming.get(node, [])):
            if parent in visited:
                continue
            visited.add(parent)
            candidate = [*reverse, parent]
            if parent in entries:
                paths.append(list(reversed(candidate)))
            queue.append((parent, candidate))
            if len(visited) >= limit:
                break
    return paths


def structural_slice(
    graph: JsonObject, seed: str, incoming: dict, outgoing: dict, entries: set[str], *, limit: int
) -> JsonObject:
    selected = nearby_nodes(seed, incoming, outgoing, limit)
    return {
        "seed": seed,
        "nodes": sorted(selected),
        "entrypoint_paths": entrypoint_paths(seed, incoming, entries, limit),
        "edges": [
            edge
            for edge in graph["edges"]
            if edge["source"] in selected and edge["target"] in selected
        ],
        "bounded": True,
        "node_limit": limit,
        "neighborhood_depth": 2,
        "entrypoint_path_depth": 8,
    }


def neighborhoods(
    graph: JsonObject, surface: list, queries: list[str], limit: int = 100
) -> list[JsonObject]:
    """Bounded structural slices; references never become execution edges."""
    nodes = graph["nodes"]
    incoming, outgoing = call_adjacency(graph)
    entries = {item["node_id"] for item in surface}
    packets = []
    for query in queries:
        seeds = (
            [query]
            if query in nodes
            else sorted(key for key, node in nodes.items() if node.get("name") == query)
        )
        packets.append(
            {
                "query": query,
                "binding": binding_status(seeds),
                "matches": seeds,
                "slices": [
                    structural_slice(graph, seed, incoming, outgoing, entries, limit=limit)
                    for seed in seeds[:limit]
                ],
            }
        )
    return packets


def checked_engine(target: Path, selection: str) -> tuple[QueryEngine, str]:
    from trailmark.query.api import QueryEngine

    missing = [name for name in REQUIRED_APIS if not callable(getattr(QueryEngine, name, None))]
    if missing:
        raise ValueError(
            "Trailmark lacks required evidence APIs: "
            + ", ".join(missing)
            + ". Install trailmark>=0.7.1,<0.8; the version string alone is insufficient."
        )
    diagnostics = io.StringIO()
    with contextlib.redirect_stdout(diagnostics), contextlib.redirect_stderr(diagnostics):
        engine = QueryEngine.from_directory(str(target), language=selection)
        engine.preanalysis()
    return engine, diagnostics.getvalue()


def source_inventory(policy: JsonObject, target: Path) -> tuple[dict[str, str], list[str]]:
    if not policy.get("roots") or not isinstance(policy.get("files"), list):
        raise ValueError("Trailmark did not retain source-selection evidence")
    hashes, configs = {}, []
    for item in policy["files"]:
        if item.get("unit") != "file":
            continue
        path = Path(item["path"])
        if path.name in CONFIG_NAMES and path.is_file():
            configs.append(relative(str(path), target))
        if item["status"] == "inspected" and path.is_file():
            hashes[relative(str(path), target)] = digest(path)
    if not hashes:
        raise ValueError("Source policy inspected zero readable source files")
    return hashes, sorted(set(configs))


def build_context(
    target: Path, languages: str = "auto", focus: list[str] | None = None
) -> JsonObject:
    import trailmark

    target = target.resolve()
    if not target.is_dir():
        raise ValueError(f"Target is not a directory: {target}")
    selection = (
        languages
        if languages == "auto"
        else ",".join(canonical_language(value) for value in languages.split(","))
    )
    engine, diagnostics = checked_engine(target, selection)
    summary, policy = engine.summary(), engine.source_policy()
    if not sum(summary.get("source_file_counts", {}).values()):
        raise ValueError("Trailmark inspected zero source files")
    hashes, configs = source_inventory(policy, target)
    graph, surface = json.loads(engine.to_json()), engine.attack_surface()
    return {
        "schema_version": 1,
        "target": str(target),
        "languages": selection,
        "trailmark_version": getattr(trailmark, "__version__", "unknown"),
        "capabilities": list(REQUIRED_APIS),
        "summary": summary,
        "source_policy": policy,
        "source_hashes": hashes,
        "parse_diagnostics": engine.parse_diagnostics(),
        "attack_surface": surface,
        "entrypoint_evidence": engine.entrypoint_evidence(),
        "entrypoint_candidates": engine.entrypoint_candidates(),
        "unresolved_calls": engine.unresolved_calls(),
        "graph": graph,
        "focus": neighborhoods(graph, surface, focus or []),
        "configuration_files": configs,
        "executables": {name: shutil.which(spec["executable"]) for name, spec in BACKENDS.items()},
        "diagnostics": diagnostics.splitlines(),
        "limitations": [
            "Call reachability and preanalysis taint are not dataflow results.",
            "Reference bindings, deferred calls, and uncertain edges do not prove execution.",
            "Slices are bounded; the full source policy and graph remain available.",
            "No parse diagnostics does not establish complete language coverage.",
        ],
    }


def context_structure_errors(context: JsonObject, target: Path) -> list[str]:
    errors = []
    if context.get("schema_version") != 1 or context.get("target") != str(target):
        errors.append("Graph snapshot schema/target mismatch")
    if not set(REQUIRED_APIS).issubset(context.get("capabilities", [])):
        errors.append("Graph snapshot lacks required Trailmark capabilities")
    counts = context.get("summary", {}).get("source_file_counts", {})
    invalid_counts = any(not isinstance(value, int) or value < 0 for value in counts.values())
    if not counts or invalid_counts or not sum(counts.values()):
        errors.append("Graph snapshot inspected zero files or has invalid coverage")
    policy = context.get("source_policy", {})
    if not policy.get("roots") or not policy.get("files"):
        errors.append("Graph snapshot lacks source policy")
    if not isinstance(context.get("graph", {}).get("nodes"), dict):
        errors.append("Graph snapshot lacks nodes")
    return errors


def current_source_errors(file: str, sha: str, target: Path) -> list[str]:
    try:
        if digest(local_file(file, target)) != sha:
            return [f"Source differs from graph snapshot: {file}"]
    except ValueError as exc:
        return [str(exc)]
    return []


def source_hash_errors(context: JsonObject, target: Path, current: bool) -> list[str]:
    errors = []
    hashes = context.get("source_hashes", {})
    if not hashes:
        errors.append("Graph snapshot has no inspected-file hashes")
    for file, sha in hashes.items():
        if not isinstance(sha, str) or len(sha) != 64:
            errors.append(f"Invalid source hash: {file}")
        if current:
            errors.extend(current_source_errors(file, sha, target))
    for item in context.get("source_snapshots", []):
        if digest(Path(item["path"])) != item["sha256"]:
            errors.append(f"Original source/configuration snapshot changed: {item['file']}")
    return errors


def context_errors(context: JsonObject, target: Path, *, current: bool = False) -> list[str]:
    return context_structure_errors(context, target) + source_hash_errors(context, target, current)


def rebind_anchor(
    model: JsonObject, original: JsonObject, rebound: JsonObject, target: Path
) -> JsonObject:
    """Rebind declaration locations, keeping multiple matches explicit."""
    old = original["graph"]["nodes"][model["anchor"]["node_id"]]
    matches = []
    for ident, node in rebound["graph"]["nodes"].items():
        location = node.get("location") or {}
        if (node.get("name"), node.get("kind")) == (old.get("name"), old.get("kind")) and (
            relative(location.get("file_path", ""), target) == model["anchor"]["file"]
        ):
            matches.append(
                {
                    "node_id": ident,
                    "file": model["anchor"]["file"],
                    "start_line": location["start_line"],
                    "end_line": location["end_line"],
                }
            )
    return {"binding": binding_status(matches), "matches": matches}
