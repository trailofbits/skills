#!/usr/bin/env -S uv run --script
# /// script
# requires-python = ">=3.12"
# dependencies = ["trailmark>=0.5,<0.6"]
# ///
"""Phase 3 graph triage for survived mutants (and necessist removals) in one call.

Builds the Trailmark graph and preanalysis once, binds each survived mutant to the narrowest
function/method containing its line, and applies the graph rules from
references/graph-analysis.md: no production callers -> false positive (dead code or
test-only); privilege boundary, high blast radius, CC > 10 with an entrypoint path or taint,
or more than 10 production callers with CC > 5 -> fuzzing target; otherwise missing tests.
Each record keeps the evidence (node, CC, production and test callers, entrypoint paths with
trust level, subgraph membership). Necessist removals are mapped to the production function
they call and merged: a function flagged by both tools is corroborated.

The script does not judge semantics. Equivalent mutants and cosmetic (logging/display)
changes are the reviewer's call; lines that look like logging carry `logging_hint`.

    genotoxic_triage.py --target . --mutants outcomes.json
    genotoxic_triage.py --target . --mutants mewt-results.json --necessist removals.json \
        --out triage.json

--mutants accepts a JSON list (or JSONL) of Universal Mutant Records
({"file_path", "line", ...}) or `mewt/muton results --format json` output (0-based
line_offset converted to 1-based lines). --necessist accepts records with
"test_file_path", "line" and "removed_statement".

Exit codes: 0 success, 2 unreadable input or graph build failure.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

CALLABLE = {"function", "method"}
TEST_PATH = re.compile(r"(^|/)(tests?|__tests__|spec)/|(^|/)test_[^/]*$|_test\.[a-z]+$|\.t\.sol$")
LOGGING = re.compile(
    r"\b(log(ger|ging)?|console|print(ln|f)?|eprint(ln)?|warn|debug|trace|emit|stderr|stdout)\b",
    re.I,
)
SUBGRAPHS = ("tainted", "privilege_boundary", "high_blast_radius", "entrypoint_reachable")
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


def load_records(path: Path) -> list[dict]:
    text = path.read_text(encoding="utf8")
    try:
        data = json.loads(text)
    except json.JSONDecodeError:
        data = [json.loads(line) for line in text.splitlines() if line.strip()]
    if isinstance(data, dict) and isinstance(data.get("results"), list):  # mewt / muton
        out = []
        for r in data["results"]:
            if (r.get("outcome") or {}).get("status") not in (None, "Uncaught"):
                continue
            m = r["mutant"]
            out.append(
                {
                    "id": m["id"],
                    "file_path": r["target"]["path"],
                    "line": int(m["line_offset"]) + 1,
                    "mutation_type": m.get("mutation_slug"),
                    "original": m.get("old_text"),
                    "replacement": m.get("new_text"),
                    "status": "survived",
                }
            )
        return out
    if not isinstance(data, list):
        raise ValueError("expected a list of mutant records or mewt results JSON")
    for i, rec in enumerate(data):
        if not isinstance(rec, dict) or "file_path" not in rec or "line" not in rec:
            raise ValueError(f"record {i} lacks file_path/line")
    return [r for r in data if str(r.get("status", "survived")).lower() in ("survived", "uncaught")]


def load_removals(path: Path) -> list[dict]:
    text = path.read_text(encoding="utf8")
    try:
        data = json.loads(text)
    except json.JSONDecodeError:
        data = [json.loads(line) for line in text.splitlines() if line.strip()]
    if not isinstance(data, list):
        raise ValueError("expected a list of necessist removal records")
    for i, rec in enumerate(data):
        if not isinstance(rec, dict) or "removed_statement" not in rec:
            raise ValueError(f"necessist record {i} lacks removed_statement")
    return data


def build(args: argparse.Namespace) -> dict:
    global ROOT
    import trailmark
    from trailmark.query.api import QueryEngine

    ROOT = Path(args.target).resolve()
    mutants = load_records(args.mutants)
    removals = load_removals(args.necessist) if args.necessist else []
    engine = QueryEngine.from_directory(str(ROOT), language=args.language)
    engine.preanalysis()
    nodes = json.loads(engine.to_json())["nodes"]
    members = {name: {nid(n) for n in engine.subgraph(name)} for name in SUBGRAPHS}
    trust = {s["node_id"]: s.get("trust_level", "unknown") for s in engine.attack_surface() or []}
    source_cache: dict[str, list[str]] = {}

    def line_text(file: str, line: int) -> str:
        if file not in source_cache:
            try:
                source_cache[file] = (ROOT / file).read_text(encoding="utf8").splitlines()
            except OSError:
                source_cache[file] = []
        lines = source_cache[file]
        return lines[line - 1] if 0 < line <= len(lines) else ""

    def containing(file: str, line: int) -> dict | None:
        hits = [
            n
            for n in nodes.values()
            if n.get("kind") in CALLABLE
            and rel(n["location"]["file_path"]) == rel(file)
            and n["location"]["start_line"] <= line <= n["location"]["end_line"]
        ]
        hits.sort(key=lambda n: n["location"]["end_line"] - n["location"]["start_line"])
        return hits[0] if hits else None

    def evidence(node_id: str) -> dict:
        callers = [nid(c) for c in engine.callers_of(node_id)]
        test_callers = [
            c
            for c in callers
            if c in nodes and TEST_PATH.search(rel(nodes[c]["location"]["file_path"]))
        ]
        prod_callers = [c for c in callers if c not in test_callers]
        paths = engine.entrypoint_paths_to(node_id)
        cc = nodes[node_id].get("cyclomatic_complexity") or 0
        return {
            "node_id": node_id,
            "cyclomatic_complexity": cc,
            "production_callers": sorted(prod_callers),
            "test_callers": sorted(test_callers),
            "entrypoint_paths": [
                {"path": p, "entrypoint": p[0], "trust_level": trust.get(p[0], "unknown")}
                for p in sorted(paths)
            ],
            **{k: node_id in v for k, v in members.items()},
        }

    def bucket(ev: dict) -> tuple[str, str]:
        cc, prod = ev["cyclomatic_complexity"], len(ev["production_callers"])
        reachable = bool(ev["entrypoint_paths"]) or ev["entrypoint_reachable"]
        if prod == 0 and not ev["entrypoint_paths"]:
            if ev["test_callers"]:
                return "false_positives", "only test callers"
            return "false_positives", "no callers (dead code)"
        if ev["privilege_boundary"]:
            return "fuzzing_targets", "privilege boundary"
        if ev["high_blast_radius"]:
            return "fuzzing_targets", "high blast radius"
        if cc > 10 and (reachable or ev["tainted"]):
            return "fuzzing_targets", f"CC {cc} > 10 and entrypoint-reachable/tainted"
        if prod > 10 and cc > 5:
            return "fuzzing_targets", f"{prod} production callers with CC {cc}"
        return "missing_tests", f"CC {cc}, {prod} production caller(s)"

    triaged = []
    for m in mutants:
        line = int(m["line"])
        node = containing(m["file_path"], line)
        rec = {**m, "line": line, "file_path": rel(m["file_path"])}
        text = line_text(rec["file_path"], line)
        rec["logging_hint"] = bool(LOGGING.search(text))
        if node is None:
            rec.update(graph_bucket="false_positives", reason="no containing function in graph")
        else:
            ev = evidence(node["id"])
            rec.update(ev)
            rec["graph_bucket"], rec["reason"] = bucket(ev)
        triaged.append(rec)

    mapped = []
    for r in removals:
        stmt = str(r.get("removed_statement", ""))
        call = re.search(r"(?:(\w+)\.)?(\w+!?)\s*\(", stmt)
        rec = dict(r)
        target = None
        if call:
            name = call.group(2).rstrip("!")
            cands = [
                n
                for n in nodes.values()
                if n.get("kind") in CALLABLE
                and n.get("name") == name
                and not TEST_PATH.search(rel(n["location"]["file_path"]))
            ]
            target = cands[0] if len(cands) == 1 else None
            if len(cands) > 1:
                rec["ambiguous_candidates"] = sorted(n["id"] for n in cands)
        if target is None:
            rec.update(graph_bucket="false_positives", reason="unmappable to production code")
        else:
            ev = evidence(target["id"])
            rec.update(ev)
            rec["graph_bucket"], rec["reason"] = bucket(ev)
        mapped.append(rec)

    flagged = {
        r["node_id"] for r in mapped if r.get("node_id") and r["graph_bucket"] != "false_positives"
    }
    corroborated = sorted(
        {
            m["node_id"]
            for m in triaged
            if m.get("node_id") in flagged and m["graph_bucket"] != "false_positives"
        }
    )
    counts: dict[str, int] = {}
    for r in triaged + mapped:
        counts[r["graph_bucket"]] = counts.get(r["graph_bucket"], 0) + 1
    return {
        "trailmark_version": getattr(trailmark, "__version__", "unknown"),
        "target": str(ROOT),
        "mutants": triaged,
        "necessist": mapped,
        "corroborated_nodes": corroborated,
        "graph_bucket_counts": counts,
        "note": "graph buckets only; move equivalent and cosmetic mutants to false positives "
        "with a reason after reading the code",
    }


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--target", default=".")
    ap.add_argument("--mutants", type=Path, required=True)
    ap.add_argument("--necessist", type=Path)
    ap.add_argument("--language", default="auto")
    ap.add_argument("--out", type=Path, help="also write the JSON here")
    args = ap.parse_args()
    if not Path(args.target).is_dir():
        print(f"error: target is not a directory: {args.target}", file=sys.stderr)
        return 2
    try:
        result = build(args)
    except (OSError, ValueError, KeyError, TypeError) as e:
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
