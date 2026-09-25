#!/usr/bin/env -S uv run --script
# /// script
# requires-python = ">=3.12"
# dependencies = ["trailmark>=0.5,<0.6"]
# ///
"""Expand one seed node into bounded, signal-annotated variant candidates in one call.

Builds the Trailmark graph once, binds the seed (FILE:LINE or a node id), and computes the
neighborhood dimensions from references/neighborhood-patterns.md: same caller, same
callee/sink, same entrypoint path, interface/override siblings, same module, and shared type
references. Every candidate carries its dimensions, graph distance, and ranking signals
(entrypoint reachability with trust level, taint, privilege boundary, blast radius) plus
penalty flags (test, mock, generated, vendor, proxy). Test/mock/generated/vendor nodes are
moved to `exclusions` with the reason unless --include-tests. Each dimension is capped
(default 10) after sorting by signals; the number dropped is reported, never silent.

The output is candidates, not findings: whether a candidate shares the seed's root cause
is for the reviewer to decide from the code.

    neighborhood.py --target . --seed src/resize.py:7
    neighborhood.py --target . --seed imgsvc.resize:thumb_cmd --cap 5 --out nbhd.json

Exit codes: 0 success, 2 bad arguments, unbound seed, or graph build failure.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from collections import defaultdict
from pathlib import Path

CALLABLE = {"function", "method"}
PENALTY = {
    "test": re.compile(r"(^|/)(tests?|__tests__|spec)/|(^|/)test_[^/]*$|_test\.[a-z]+$"),
    "mock": re.compile(r"(^|/)(mocks?|fakes?|fixtures?)/|mock", re.I),
    "generated": re.compile(r"(^|/)(gen|generated|build|dist)/|_pb2\.py$|\.g\.[a-z]+$"),
    "vendor": re.compile(r"(^|/)(vendor|third_party|node_modules|external)/"),
}
SUBGRAPHS = ("tainted", "entrypoint_reachable", "privilege_boundary", "high_blast_radius")
FINDING_RE = re.compile(r"^(?P<file>.+?):(?P<line>\d+)$")
ROOT = Path(".")


def nid(n) -> str:
    return n["id"] if isinstance(n, dict) else str(n)


def rel(path: str) -> str:
    p = Path(path)
    if p.is_absolute():
        try:
            return p.resolve().relative_to(ROOT).as_posix()
        except ValueError:
            return p.as_posix()
    return p.as_posix().removeprefix("./")


def build(args: argparse.Namespace) -> dict:
    global ROOT
    import trailmark
    from trailmark.query.api import QueryEngine

    ROOT = Path(args.target).resolve()
    engine = QueryEngine.from_directory(str(ROOT), language=args.language)
    engine.preanalysis()
    graph = json.loads(engine.to_json())
    nodes = graph.get("nodes", {})
    edges = graph.get("edges", [])
    members = {name: {nid(n) for n in engine.subgraph(name)} for name in SUBGRAPHS}
    trust = {s["node_id"]: s.get("trust_level", "unknown") for s in engine.attack_surface() or []}

    def callable_ids(xs) -> list[str]:
        return [nid(x) for x in xs if nid(x) in nodes and nodes[nid(x)].get("kind") in CALLABLE]

    # Bind the seed.
    m = FINDING_RE.match(args.seed)
    if args.seed in nodes:
        seed = args.seed
    elif m:
        file, line = rel(m.group("file")), int(m.group("line"))
        hits = [
            n
            for n in nodes.values()
            if n.get("kind") in CALLABLE
            and rel(n["location"]["file_path"]) == file
            and n["location"]["start_line"] <= line <= n["location"]["end_line"]
        ]
        if not hits:
            raise LookupError(f"seed {args.seed} does not bind to a function or method")
        hits.sort(key=lambda n: n["location"]["end_line"] - n["location"]["start_line"])
        seed = hits[0]["id"]
    else:
        raise LookupError(f"seed must be FILE:LINE or a node id, got {args.seed!r}")

    found: dict[str, dict] = {}

    def add(cand: str, dimension: str, distance: int, why: str) -> None:
        if cand == seed or cand not in nodes or nodes[cand].get("kind") not in CALLABLE:
            return
        entry = found.setdefault(cand, {"dimensions": {}, "distance": distance})
        entry["dimensions"].setdefault(dimension, why)
        entry["distance"] = min(entry["distance"], distance)

    seed_callers = callable_ids(engine.callers_of(seed))
    seed_callees = [nid(c) for c in engine.callees_of(seed)]
    for caller in seed_callers:
        for c in callable_ids(engine.callees_of(caller)):
            add(c, "same_caller", 2, f"also called by {caller}")
    for callee in seed_callees:
        if callee in nodes and nodes[callee].get("kind") in CALLABLE:
            for c in callable_ids(engine.callers_of(callee)):
                add(c, "same_sink", 2, f"also calls {callee}")
    paths = engine.entrypoint_paths_to(seed)
    for p in paths:
        for c in callable_ids(engine.callees_of(p[0])):
            add(c, "same_entrypoint", 2, f"also reached from entrypoint {p[0]}")
    # Interface/override siblings: methods with the seed's name in classes sharing a parent.
    parents = defaultdict(set)
    for e in edges:
        if e.get("kind") == "inherits":
            parents[e["source"]].add(e["target"])
    seed_node = nodes[seed]
    if seed_node.get("kind") == "method" and "." in seed.split(":")[-1]:
        owner, method = seed.rsplit(".", 1)
        family = parents.get(owner, set())
        for cls, ps in parents.items():
            if cls != owner and ps & family:
                add(
                    f"{cls}.{method}",
                    "same_interface",
                    2,
                    f"overrides {method} of {sorted(ps & family)[0]}",
                )
        for p in family:
            add(f"{p}.{method}", "same_interface", 1, f"base definition of {method}")
    # Siblings of classes whose method shares the seed's sink (override families elsewhere).
    for cand in list(found):
        if nodes[cand].get("kind") == "method" and "." in cand.split(":")[-1]:
            owner, method = cand.rsplit(".", 1)
            fam = parents.get(owner, set())
            siblings = [cls for cls, ps in parents.items() if cls != owner and ps & fam]
            if siblings:
                add(
                    cand,
                    "same_interface",
                    found[cand]["distance"],
                    f"overrides {method} alongside {', '.join(sorted(siblings))}",
                )
            for cls in siblings:
                add(f"{cls}.{method}", "same_interface", 3, f"sibling override of {cand}")
    module = seed.split(":")[0]
    for other in nodes:
        if other.split(":")[0] == module:
            add(other, "same_module", 1, f"defined in {module}")
    try:
        seed_types = {t.get("name") for t in engine.type_references(seed) or []}
    except Exception:  # optional API
        seed_types = set()
    seed_types -= {None, "str", "int", "bool", "bytes", "float", "None", "dict", "list"}
    if seed_types:
        for other, n in nodes.items():
            if n.get("kind") in CALLABLE and other != seed:
                try:
                    theirs = {t.get("name") for t in engine.type_references(other) or []}
                except Exception:
                    continue
                shared = seed_types & theirs
                if shared:
                    add(other, "same_type", 2, f"uses {sorted(shared)[0]}")

    def signals(cand: str) -> dict:
        path = rel(nodes[cand]["location"]["file_path"])
        entry = sorted({p[0] for p in engine.entrypoint_paths_to(cand)})
        return {
            "file": path,
            "line": nodes[cand]["location"]["start_line"],
            "entrypoint_reachable": cand in members["entrypoint_reachable"],
            "entrypoints": [{"id": x, "trust_level": trust.get(x, "unknown")} for x in entry],
            "tainted": cand in members["tainted"],
            "privilege_boundary": cand in members["privilege_boundary"],
            "high_blast_radius": cand in members["high_blast_radius"],
            "penalties": sorted(k for k, rx in PENALTY.items() if rx.search(path)),
        }

    candidates, exclusions = [], []
    for cand, info in found.items():
        rec = {
            "node": cand,
            **signals(cand),
            "distance": info["distance"],
            "dimensions": info["dimensions"],
            "status": "candidate",
        }
        excluded = [p for p in rec["penalties"] if p in ("test", "mock", "generated", "vendor")]
        if excluded and not args.include_tests:
            exclusions.append({"node": cand, "file": rec["file"], "reason": ", ".join(excluded)})
        else:
            candidates.append(rec)

    def score(c: dict) -> tuple:
        return (
            not c["entrypoint_reachable"],
            not c["tainted"],
            not c["privilege_boundary"],
            not c["high_blast_radius"],
            -len(c["dimensions"]),
            c["distance"],
            c["node"],
        )

    by_dim: dict[str, list[dict]] = defaultdict(list)
    for c in candidates:
        for d in c["dimensions"]:
            by_dim[d].append(c)
    dimensions = {}
    for d, cs in sorted(by_dim.items()):
        cs = sorted(cs, key=score)
        dimensions[d] = {
            "total": len(cs),
            "shown": [c["node"] for c in cs[: args.cap]],
            "dropped": [c["node"] for c in cs[args.cap :]],
        }
    shown = {n for d in dimensions.values() for n in d["shown"]}
    kept = sorted((c for c in candidates if c["node"] in shown), key=score)
    return {
        "trailmark_version": getattr(trailmark, "__version__", "unknown"),
        "seed": {
            "node": seed,
            **signals(seed),
            "entrypoint_paths": sorted(paths),
            "callers": seed_callers,
            "callees": seed_callees,
        },
        "cap_per_dimension": args.cap,
        "dimensions": dimensions,
        "candidates": kept,
        "candidates_over_cap": sorted(
            {n for d in dimensions.values() for n in d["dropped"]} - shown
        ),
        "exclusions": sorted(exclusions, key=lambda e: e["node"]),
        "flood": len(candidates) > 50,
    }


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--target", default=".")
    ap.add_argument("--seed", required=True, help="FILE:LINE or a Trailmark node id")
    ap.add_argument("--cap", type=int, default=10, help="candidates per dimension (default 10)")
    ap.add_argument("--language", default="auto")
    ap.add_argument("--include-tests", action="store_true", help="keep test/vendor/... nodes")
    ap.add_argument("--out", type=Path, help="also write the JSON here")
    args = ap.parse_args()
    if not Path(args.target).is_dir() or args.cap < 1:
        print("error: --target must be a directory and --cap >= 1", file=sys.stderr)
        return 2
    try:
        result = build(args)
    except LookupError as e:
        print(f"error: {e}", file=sys.stderr)
        return 2
    except Exception as e:
        print(f"error: trailmark failed: {type(e).__name__}: {e}", file=sys.stderr)
        return 2
    text = json.dumps(result, indent=1)
    if args.out:
        args.out.write_text(text + "\n")
    print(text)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
