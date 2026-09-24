#!/usr/bin/env python3
# /// script
# requires-python = ">=3.11"
# dependencies = ["trailmark"]
# ///
"""Build, augment, and cross-reference one Trailmark graph in one process."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

from trailmark.query.api import QueryEngine


def node_id(node: dict[str, Any]) -> str:
    """Return Trailmark's stable node identifier without guessing at node shape."""
    for key in ("id", "node_id", "name", "qualified_name"):
        value = node.get(key)
        if value is not None:
            return str(value)
    return json.dumps(node, sort_keys=True)


def members(engine: QueryEngine, name: str) -> set[str]:
    """Read an existing subgraph only; callers must check its name first."""
    return {node_id(node) for node in engine.subgraph(name)}


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Project audit findings onto a Trailmark graph and cross-reference pre-analysis."
        )
    )
    parser.add_argument("--target", required=True, help="source root; resolved to an absolute path")
    parser.add_argument("--language", default="auto")
    parser.add_argument("--sarif", action="append", default=[])
    parser.add_argument("--weaudit", action="append", default=[])
    parser.add_argument("--binary", action="append", default=[])
    parser.add_argument(
        "--limit", type=int, default=100, help="priority nodes to print; 0 means all"
    )
    parser.add_argument("--out", type=Path, help="also write the complete JSON result to this path")
    parser.add_argument(
        "--summary-out",
        type=Path,
        help="write the compact augmentation and signal-intersection report to this path",
    )
    args = parser.parse_args()
    if args.limit < 0:
        parser.error("--limit must be zero or greater")
    if not (args.sarif or args.weaudit or args.binary):
        parser.error("provide at least one --sarif, --weaudit, or --binary input")
    for option in ("sarif", "weaudit", "binary"):
        values = getattr(args, option)
        if len(values) > 1:
            if option == "binary":
                parser.error(
                    "provide one --binary file; use the programmatic API for multiple artifacts"
                )
            parser.error(
                f"multiple --{option} files would replace earlier {option} augmentation; "
                "merge them before invoking this command"
            )
    return args


def main() -> int:
    args = parse_args()
    target = Path(args.target).expanduser().resolve()
    if not target.is_dir():
        print(f"error: target is not a directory: {target}", file=sys.stderr)
        return 2

    engine = QueryEngine.from_directory(str(target), language=args.language)
    preanalysis = engine.preanalysis()
    augmented: dict[str, dict[str, Any]] = {}

    if args.sarif:
        augmented["sarif"] = engine.augment_sarif(args.sarif[0])
    if args.weaudit:
        augmented["weaudit"] = engine.augment_weaudit(args.weaudit[0])
    if args.binary:
        if not hasattr(engine, "augment_binary"):
            print("error: binary augmentation requires Trailmark >= 0.4.0", file=sys.stderr)
            return 2
        augmented["binary"] = engine.augment_binary(args.binary[0])

    names = sorted(engine.subgraph_names())
    name_set = set(names)
    finding_names = [name for name in names if name.startswith(("sarif:", "weaudit:"))]
    signal_names = [
        name for name in ("tainted", "high_blast_radius", "privilege_boundary") if name in name_set
    ]
    signal_members = {name: members(engine, name) for name in signal_names}
    finding_members = {name: members(engine, name) for name in finding_names}
    priority: dict[str, set[str]] = {}
    for finding_name, identifiers in finding_members.items():
        for identifier in identifiers:
            tags = priority.setdefault(identifier, set())
            tags.add(finding_name)
            for signal_name, identifiers in signal_members.items():
                if identifier in identifiers:
                    tags.add(signal_name)

    ranked = [
        {"node": identifier, "signals": sorted(tags)} for identifier, tags in priority.items()
    ]
    ranked.sort(key=lambda item: (-len(item["signals"]), item["node"]))
    result = {
        "target": str(target),
        "preanalysis": preanalysis,
        "augmentation": augmented,
        "subgraphs": {name: len(members(engine, name)) for name in names},
        "priority_nodes": ranked,
    }
    rendered = json.dumps(result, indent=2, sort_keys=True) + "\n"
    if args.out:
        args.out.parent.mkdir(parents=True, exist_ok=True)
        args.out.write_text(rendered)
    if args.summary_out:
        finding_nodes = set().union(*finding_members.values()) if finding_members else set()
        compact = {
            **augmented,
            "error_on_tainted": sorted(
                finding_members.get("sarif:error", set()) & signal_members.get("tainted", set())
            ),
            "findings_on_high_blast_radius": sorted(
                finding_nodes & signal_members.get("high_blast_radius", set())
            ),
            "findings_on_privilege_boundary": sorted(
                finding_nodes & signal_members.get("privilege_boundary", set())
            ),
        }
        args.summary_out.parent.mkdir(parents=True, exist_ok=True)
        args.summary_out.write_text(json.dumps(compact, indent=2, sort_keys=True) + "\n")
    if args.limit:
        result = {**result, "priority_nodes": ranked[: args.limit]}
        rendered = json.dumps(result, indent=2, sort_keys=True) + "\n"
    sys.stdout.write(rendered)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
