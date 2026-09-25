#!/usr/bin/env -S uv run --script
# /// script
# requires-python = ">=3.12"
# dependencies = ["trailmark>=0.5,<0.6"]
# ///
"""Build the Graph Evidence block for one or more findings from a single Trailmark graph.

Builds the graph and runs preanalysis once, then for each FILE:LINE (or FILE:START-END)
finding binds it to the narrowest enclosing function/method node and reports, as JSON:
every node that matched, entrypoint paths with the trust level of each path's entrypoint,
membership in the tainted / entrypoint_reachable / privilege_boundary / high_blast_radius
subgraphs, direct callers and callees, and downstream reachable nodes. A finding that binds
to nothing is reported with `bound_node: null` and the reason. Nothing is judged here: the
verdict, attacker control and exploitability stay with the reviewer.

    evidence_packet.py --target . --finding src/app.py:42
    evidence_packet.py --target . --finding a.py:10 --finding b.py:5-9 --language python
    evidence_packet.py --target . --finding a.py:10 --out evidence.json

Exit codes: 0 success (unbound findings included), 2 bad arguments or graph build failure.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

SUBGRAPHS = ("tainted", "entrypoint_reachable", "privilege_boundary", "high_blast_radius")
CALLABLE = {"function", "method"}
FINDING_RE = re.compile(r"^(?P<file>.+?):(?P<start>\d+)(?:-(?P<end>\d+))?$")


def node_id(n) -> str:
    return n["id"] if isinstance(n, dict) else str(n)


ROOT = Path(".")


def rel(path: str) -> str:
    """Graph and finding paths relative to --target (Trailmark keeps what it was given)."""
    p = Path(path)
    if p.is_absolute():
        try:
            return p.resolve().relative_to(ROOT).as_posix()
        except ValueError:
            return p.as_posix()
    return p.as_posix().removeprefix("./")


def bind(nodes: dict, file: str, start: int, end: int) -> list[dict]:
    want = rel(file)
    hits = []
    for n in nodes.values():
        loc = n.get("location") or {}
        if n.get("kind") not in CALLABLE or rel(loc.get("file_path", "")) != want:
            continue
        if loc.get("start_line", 0) <= end and start <= loc.get("end_line", -1):
            hits.append(n)
    return sorted(hits, key=lambda n: n["location"]["end_line"] - n["location"]["start_line"])


def build(args: argparse.Namespace) -> dict:
    import trailmark
    from trailmark.query.api import QueryEngine

    global ROOT
    target = ROOT = Path(args.target).resolve()
    engine = QueryEngine.from_directory(str(target), language=args.language)
    engine.preanalysis()
    graph = json.loads(engine.to_json())
    nodes = graph.get("nodes", {})
    members = {name: {node_id(n) for n in engine.subgraph(name)} for name in SUBGRAPHS}
    trust = {s["node_id"]: s.get("trust_level", "unknown") for s in (engine.attack_surface() or [])}
    parser_errors = graph.get("summary", {}).get("errors") if isinstance(graph, dict) else None

    findings = []
    for raw in args.finding:
        m = FINDING_RE.match(raw)
        if not m:
            raise ValueError(f"finding must be FILE:LINE or FILE:START-END, got {raw!r}")
        file = m.group("file")
        start = int(m.group("start"))
        end = int(m.group("end") or start)
        record = {"finding": raw, "file": rel(file), "line_range": [start, end]}
        matches = bind(nodes, file, start, end)
        record["matches"] = [
            {
                "id": n["id"],
                "kind": n["kind"],
                "lines": [n["location"]["start_line"], n["location"]["end_line"]],
            }
            for n in matches
        ]
        if not matches:
            known = any(
                rel(n.get("location", {}).get("file_path", "")) == rel(file) for n in nodes.values()
            )
            record["bound_node"] = None
            record["binding"] = (
                "no function or method in the graph spans this line"
                if known
                else "file is not in the graph (not source, unsupported language, "
                "or outside --target)"
            )
            findings.append(record)
            continue
        primary = matches[0]["id"]
        paths = sorted(engine.entrypoint_paths_to(primary))
        record.update(
            bound_node=primary,
            binding="exact" if len(matches) == 1 else f"ambiguous: {len(matches)} nodes overlap",
            entrypoint_paths=[
                {"path": p, "entrypoint": p[0], "trust_level": trust.get(p[0], "unknown")}
                for p in paths
            ],
            callers=sorted(node_id(c) for c in engine.callers_of(primary)),
            callees=sorted(node_id(c) for c in engine.callees_of(primary)),
            downstream=sorted(node_id(c) for c in engine.reachable_from(primary)),
            **{name: primary in ids for name, ids in members.items()},
        )
        findings.append(record)
    return {
        "trailmark_version": getattr(trailmark, "__version__", "unknown"),
        "target": str(target),
        "language": args.language,
        "graph": {
            "nodes": len(nodes),
            "entrypoints": sorted(trust),
            "parser_errors": parser_errors,
        },
        "findings": findings,
    }


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--target", default=".", help="directory to build the graph from")
    ap.add_argument("--finding", action="append", required=True, help="FILE:LINE[-END]")
    ap.add_argument("--language", default="auto", help="trailmark language (default auto)")
    ap.add_argument("--out", type=Path, help="also write the JSON here")
    args = ap.parse_args()
    if not Path(args.target).is_dir():
        print(f"error: target is not a directory: {args.target}", file=sys.stderr)
        return 2
    try:
        packet = build(args)
    except ValueError as e:
        print(f"error: {e}", file=sys.stderr)
        return 2
    except Exception as e:  # graph build or query failure: report, do not guess
        print(f"error: trailmark failed: {type(e).__name__}: {e}", file=sys.stderr)
        return 2
    text = json.dumps(packet, indent=1)
    if args.out:
        args.out.write_text(text + "\n")
    print(text)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
