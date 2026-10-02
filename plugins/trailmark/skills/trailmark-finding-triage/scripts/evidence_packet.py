#!/usr/bin/env -S uv run --script
# /// script
# requires-python = ">=3.12"
# dependencies = ["trailmark>=0.5,<0.6"]
# ///
"""Build the Graph Evidence block for one or more findings from a single Trailmark graph.

Builds the graph and runs preanalysis once, then for each FILE:LINE (or FILE:START-END)
finding binds it to the narrowest overlapping callable or enclosing container and reports:
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
import contextlib
import io
import json
import re
import sys
from pathlib import Path

SUBGRAPHS = ("tainted", "entrypoint_reachable", "privilege_boundary", "high_blast_radius")
CALLABLE = {"function", "method", "procedure"}
CONTAINERS = {
    "module",
    "class",
    "contract",
    "struct",
    "interface",
    "trait",
    "enum",
    "namespace",
    "library",
    "template",
    "schema",
    "table",
    "view",
}
FINDING_RE = re.compile(r"^(?P<file>.+?):(?P<start>\d+)(?:-(?P<end>\d+))?$")


def node_id(n) -> str:
    return n["id"] if isinstance(n, dict) else str(n)


def rel(path: str, root: Path) -> str:
    """Graph and finding paths relative to --target (Trailmark keeps what it was given)."""
    p = Path(path)
    if p.is_absolute():
        try:
            return p.resolve().relative_to(root).as_posix()
        except ValueError:
            return p.as_posix()
    return p.as_posix().removeprefix("./")


def bind(nodes: dict, file: str, start: int, end: int, root: Path) -> list[dict]:
    want = rel(file, root)
    hits = []
    for n in nodes.values():
        loc = n.get("location") or {}
        if (
            n.get("kind") not in CALLABLE | CONTAINERS
            or rel(loc.get("file_path", ""), root) != want
        ):
            continue
        if loc.get("start_line", 0) <= end and start <= loc.get("end_line", -1):
            hits.append(n)
    # Preserve the callable overlap policy; containers cover declarations and module code.
    callables = [n for n in hits if n["kind"] in CALLABLE]
    return sorted(
        callables or hits,
        key=lambda n: (n["location"]["end_line"] - n["location"]["start_line"], n["id"]),
    )


def parse_findings(args: argparse.Namespace, target: Path) -> list[tuple[str, str, int, int]]:
    parsed = []
    basis = getattr(args, "path_base", "auto")
    for raw in args.finding:
        m = FINDING_RE.fullmatch(raw)
        if not m or re.search(r":\d+$", m.group("file")):
            raise ValueError(
                f"finding must be FILE:LINE or FILE:START-END (no column), got {raw!r}"
            )
        start, end = int(m.group("start")), int(m.group("end") or m.group("start"))
        if not 0 < start <= end:
            raise ValueError(f"finding lines must be positive and ordered: {raw!r}")
        path = Path(m.group("file")).expanduser()
        if not path.is_absolute():
            from_target, from_cwd = (target / path).resolve(), path.resolve()
            if basis == "auto":
                existing = {p for p in (from_target, from_cwd) if p.is_file()}
                if len(existing) > 1:
                    raise ValueError(
                        f"ambiguous path {path}: use --path-base target/cwd or an absolute path"
                    )
                path = next(iter(existing), from_target)
            else:
                path = from_target if basis == "target" else from_cwd
        parsed.append((raw, rel(str(path.resolve()), target), start, end))
    return parsed


def build(args: argparse.Namespace) -> dict:
    import trailmark
    from trailmark.query.api import QueryEngine

    target = Path(args.target).resolve()
    parsed = parse_findings(args, target)
    diagnostics = io.StringIO()
    with contextlib.redirect_stdout(diagnostics), contextlib.redirect_stderr(diagnostics):
        engine = QueryEngine.from_directory(str(target), language=args.language)
        engine.preanalysis()
    graph = json.loads(engine.to_json())
    nodes = graph.get("nodes", {})
    if not nodes:
        raise ValueError("analysis incomplete: graph has no nodes; check language and target")
    available = set(engine.subgraph_names())
    members = {
        name: {node_id(n) for n in engine.subgraph(name)} for name in SUBGRAPHS if name in available
    }
    trust = {s["node_id"]: s.get("trust_level", "unknown") for s in (engine.attack_surface() or [])}
    parser_errors = graph.get("summary", {}).get("errors") if isinstance(graph, dict) else None

    findings = []
    for raw, file, start, end in parsed:
        record = {"finding": raw, "file": file, "line_range": [start, end]}
        matches = bind(nodes, file, start, end, target)
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
                rel((n.get("location") or {}).get("file_path", ""), target) == file
                for n in nodes.values()
            )
            record["bound_node"] = None
            record["binding"] = (
                "no supported callable or container in the graph spans this line"
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
            binding_kind=matches[0]["kind"],
            entrypoint_paths=[
                {"path": p, "entrypoint": p[0], "trust_level": trust.get(p[0], "unknown")}
                for p in paths
            ],
            callers=sorted(node_id(c) for c in engine.callers_of(primary)),
            callees=sorted(node_id(c) for c in engine.callees_of(primary)),
            downstream=sorted(node_id(c) for c in engine.reachable_from(primary)),
            **{name: primary in members[name] if name in members else None for name in SUBGRAPHS},
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
            "parser_diagnostics_available": parser_errors is not None,
            "diagnostics": diagnostics.getvalue().splitlines(),
            "limitations": [
                "Parser error counts are not provided by this Trailmark export; "
                "an empty diagnostics list is not proof of a complete parse."
            ]
            if parser_errors is None
            else [],
            "signals_available": {name: name in available for name in SUBGRAPHS},
        },
        "findings": findings,
    }


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--target", default=".", help="directory to build the graph from")
    ap.add_argument("--finding", action="append", required=True, help="FILE:LINE[-END]")
    ap.add_argument("--language", default="auto", help="trailmark language (default auto)")
    ap.add_argument(
        "--path-base",
        choices=("auto", "target", "cwd"),
        default="auto",
        help="relative anchor basis; auto rejects ambiguous existing paths",
    )
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
    try:
        if args.out:
            args.out.write_text(text + "\n")
    except OSError as e:
        print(f"error: cannot write requested evidence file: {e}", file=sys.stderr)
        return 2
    if args.out:
        print(
            json.dumps(
                {
                    "output": str(args.out),
                    "findings": len(packet["findings"]),
                    "bound": sum(f["bound_node"] is not None for f in packet["findings"]),
                    "complete_evidence_on_disk": True,
                    "console_summary_only": True,
                }
            )
        )
    else:
        print(text)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
