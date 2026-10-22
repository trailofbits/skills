#!/usr/bin/env -S uv run --script
# /// script
# requires-python = ">=3.12"
# dependencies = ["trailmark>=0.5,<0.6"]
# ///
"""Phase 3 graph triage for survived mutants (and necessist removals) in one call.

Builds the Trailmark graph and preanalysis once, binds each survived mutant to the narrowest
function/method containing its line, and applies the fuzzing criteria from
references/triage-methodology.md: a function with no production callers that is not an
entrypoint -> false positive (dead code or test-only); privilege boundary, high blast radius
with CC > 5, CC > 10 with an entrypoint path or taint, or more than 10 production callers with
CC > 5 -> fuzzing target; otherwise missing tests. Each record keeps the evidence (node, CC,
production and test callers, entrypoint paths with trust level, subgraph membership).
Necessist removals are mapped to the production function they call and merged: a function
flagged by both tools is corroborated.

Records the graph cannot place are not guessed: a mutant outside every function is `unbound`,
and a removal whose call names several production functions is `needs_review`.

The script does not judge semantics. Equivalent mutants and cosmetic (logging/display)
changes are the reviewer's call; lines that look like logging carry `logging_hint`.

    genotoxic_triage.py --target . --mutants outcomes.json
    genotoxic_triage.py --target . --mutants mewt-results.json --necessist removals.json \
        --out triage.json

--mutants accepts a JSON list (or JSONL) of Universal Mutant Records
({"file_path", "line", ...}) or `mewt/muton results --format json` output (0-based
line_offset converted to 1-based lines). --necessist accepts records with
"test_file_path", "line" and "removed_statement". Relative paths may be relative to --target
or to the working directory.

Exit codes: 0 success, 2 unreadable or empty input, graph build failure, or survived mutants
of which none bind to the graph.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

CALLABLE = {"function", "method"}
TEST_PATH = re.compile(
    r"(^|/)(tests?|Tests?|__tests__)/|^spec/"
    r"|(^|/)test_[^/]*$|_test\.[a-z]+$|\.(test|spec)\.[a-z]+$|_spec\.rb$"
    r"|(^|/)conftest\.py$|\.t\.sol$"
)
LOGGING = re.compile(
    r"\b(log(ger|ging)?|console|print(ln|f)?|eprint(ln)?|warn|debug|trace|stderr|stdout)\b",
    re.I,
)
MATH_LOG = re.compile(r"\b(math|cmath|np|numpy|torch|Math)\.log\w*\s*\(")
CALL = re.compile(r"(?:(\w+)\.)?(\w+!?)\s*\(")
# Statuses that mean the mutant was decided (caught); anything else is an incomplete campaign.
DECIDED = {"killed", "caught", "timeout"}
SUBGRAPHS = ("tainted", "privilege_boundary", "high_blast_radius", "entrypoint_reachable")
FUZZ_BUCKETS = ("missing_tests", "fuzzing_targets")


class TrailmarkError(Exception):
    """The graph could not be built or queried."""


def nid(n) -> str:
    return n["id"] if isinstance(n, dict) else str(n)


def rel(path: str, root: Path) -> str:
    """A record or graph path relative to the target root, forward slashes, no `./`."""
    p = Path(path)
    if p.is_absolute():
        try:
            return p.resolve().relative_to(root).as_posix()
        except ValueError:
            return p.as_posix()
    if not (root / p).exists() and p.exists():  # working-directory-relative
        try:
            return p.resolve().relative_to(root).as_posix()
        except ValueError:
            pass
    return p.as_posix().removeprefix("./")


def is_test(path: str) -> bool:
    return bool(TEST_PATH.search(path))


def logging_hint(text: str) -> bool:
    return bool(LOGGING.search(MATH_LOG.sub("", text)))


def load_json_or_jsonl(path: Path, record_key: str):
    text = path.read_text(encoding="utf8")
    try:
        data = json.loads(text)
    except json.JSONDecodeError:
        return [json.loads(line) for line in text.splitlines() if line.strip()]
    if isinstance(data, dict) and record_key in data:  # a one-line JSONL file
        return [data]
    return data


def load_records(path: Path) -> tuple[list[dict], dict[str, int]]:
    """Survived records, plus a count of every record dropped, by status."""
    data = load_json_or_jsonl(path, "file_path")
    dropped: dict[str, int] = {}
    if isinstance(data, dict) and isinstance(data.get("results"), list):  # mewt / muton
        if not data["results"]:
            raise ValueError("mewt results list is empty")
        out = []
        for r in data["results"]:
            status = (r.get("outcome") or {}).get("status")
            if status != "Uncaught":
                key = str(status).lower() if status else "no_outcome"
                dropped[key] = dropped.get(key, 0) + 1
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
        return out, dropped
    if not isinstance(data, list):
        raise ValueError("expected a list of mutant records or mewt results JSON")
    if not data:
        raise ValueError("mutant record list is empty")
    out = []
    for i, rec in enumerate(data):
        if not isinstance(rec, dict) or "file_path" not in rec or "line" not in rec:
            raise ValueError(f"record {i} lacks file_path/line")
        status = str(rec.get("status", "survived")).lower()
        if status in ("survived", "uncaught"):
            out.append(rec)
        else:
            dropped[status] = dropped.get(status, 0) + 1
    return out, dropped


def load_removals(path: Path) -> list[dict]:
    data = load_json_or_jsonl(path, "removed_statement")
    if not isinstance(data, list):
        raise ValueError("expected a list of necessist removal records")
    for i, rec in enumerate(data):
        if not isinstance(rec, dict) or "removed_statement" not in rec:
            raise ValueError(f"necessist record {i} lacks removed_statement")
    return data


def infer_production_path(test_file_path: str) -> str:
    """tests/test_parser.py -> src/parser.py (same heuristic as graph-analysis.md)."""
    path = re.sub(r"^tests?/", "src/", test_file_path)
    path = re.sub(r"test_(\w+)", r"\1", path)
    path = re.sub(r"(\w+)_test\.", r"\1.", path)
    return re.sub(r"(\w+)\.test\.", r"\1.", path)


def classify(ev: dict) -> tuple[str, str]:
    """Graph bucket and reason from one evidence record."""
    cc, prod = ev["cyclomatic_complexity"], len(ev["production_callers"])
    entry = ev["is_entrypoint"] or ev["entrypoint_reachable"]
    reachable = bool(ev["entrypoint_paths"]) or entry
    if prod == 0 and not ev["entrypoint_paths"] and not entry:
        if ev["test_callers"]:
            return "false_positives", "only test callers"
        return (
            "false_positives",
            "no callers (dead code); callbacks, decorators and dynamic dispatch are not "
            "graph edges, so check before dismissing",
        )
    if ev["privilege_boundary"]:
        return "fuzzing_targets", "privilege boundary"
    if ev["high_blast_radius"] and cc > 5:
        return "fuzzing_targets", f"high blast radius with CC {cc} > 5"
    if cc > 10 and (reachable or ev["tainted"]):
        return "fuzzing_targets", f"CC {cc} > 10 and entrypoint-reachable/tainted"
    if prod > 10 and cc > 5:
        return "fuzzing_targets", f"{prod} production callers with CC {cc}"
    return "missing_tests", f"CC {cc}, {prod} production caller(s)"


def build_graph(root: Path, language: str):
    import trailmark
    from trailmark.query.api import QueryEngine

    try:
        engine = QueryEngine.from_directory(str(root), language=language)
        engine.preanalysis()
        nodes = json.loads(engine.to_json())["nodes"]
        members = {name: {nid(n) for n in engine.subgraph(name)} for name in SUBGRAPHS}
        trust = {
            s["node_id"]: s.get("trust_level", "unknown") for s in engine.attack_surface() or []
        }
    except Exception as e:  # Trailmark's own failures only; script bugs surface normally
        raise TrailmarkError(f"{type(e).__name__}: {e}") from e
    return getattr(trailmark, "__version__", "unknown"), engine, nodes, members, trust


def build(args: argparse.Namespace) -> tuple[dict, list[str]]:
    root = Path(args.target).resolve()
    mutants, dropped = load_records(args.mutants)
    removals = load_removals(args.necessist) if args.necessist else []
    version, engine, nodes, members, trust = build_graph(root, args.language)

    by_file: dict[str, list[dict]] = {}
    for n in nodes.values():
        loc = n.get("location") or {}
        if n.get("kind") in CALLABLE and loc.get("file_path"):
            by_file.setdefault(rel(loc["file_path"], root), []).append(n)
    prod_by_name: dict[str, list[dict]] = {}
    for file, ns in by_file.items():
        if not is_test(file):
            for n in ns:
                prod_by_name.setdefault(n.get("name", ""), []).append(n)
    source_cache: dict[str, list[str]] = {}
    evidence_cache: dict[str, dict] = {}

    def line_text(file: str, line: int) -> str:
        if file not in source_cache:
            try:
                source_cache[file] = (root / file).read_text(encoding="utf8").splitlines()
            except OSError:
                source_cache[file] = []
        lines = source_cache[file]
        return lines[line - 1] if 0 < line <= len(lines) else ""

    def containing(file: str, line: int) -> dict | None:
        hits = [
            n
            for n in by_file.get(file, [])
            if n["location"]["start_line"] <= line <= n["location"]["end_line"]
        ]
        hits.sort(key=lambda n: n["location"]["end_line"] - n["location"]["start_line"])
        return hits[0] if hits else None

    def evidence(node_id: str) -> dict:
        if node_id in evidence_cache:
            return evidence_cache[node_id]
        callers = [c for c in (nid(c) for c in engine.callers_of(node_id)) if c != node_id]
        test_callers = [
            c
            for c in callers
            if c in nodes
            and is_test(rel((nodes[c].get("location") or {}).get("file_path", ""), root))
        ]
        prod_callers = [c for c in callers if c not in test_callers]
        paths = engine.entrypoint_paths_to(node_id)
        ev = {
            "node_id": node_id,
            "cyclomatic_complexity": nodes[node_id].get("cyclomatic_complexity") or 0,
            "production_callers": sorted(prod_callers),
            "test_callers": sorted(test_callers),
            "is_entrypoint": node_id in trust,
            "entrypoint_paths": [
                {"path": p, "entrypoint": p[0], "trust_level": trust.get(p[0], "unknown")}
                for p in sorted(paths)
            ],
            **{k: node_id in v for k, v in members.items()},
        }
        evidence_cache[node_id] = ev
        return ev

    def apply(rec: dict, node_id: str) -> None:
        ev = evidence(node_id)
        rec.update(ev)
        rec["graph_bucket"], rec["reason"] = classify(ev)

    triaged = []
    for m in mutants:
        line = int(m["line"])
        rec = {**m, "line": line, "file_path": rel(m["file_path"], root)}
        rec["logging_hint"] = logging_hint(line_text(rec["file_path"], line))
        node = containing(rec["file_path"], line)
        if node is None:
            reason = (
                "no function or method in the graph contains this line"
                if rec["file_path"] in by_file
                else "file is not in the graph (path, language or --target mismatch)"
            )
            rec.update(graph_bucket="unbound", reason=reason)
        else:
            apply(rec, node["id"])
        triaged.append(rec)

    mapped = []
    for r in removals:
        rec = dict(r)
        stmt = str(r.get("removed_statement", ""))
        cands: list[dict] = []
        cheatcode = None
        for call in CALL.finditer(stmt):  # outermost first; skip wrappers like assertEqual
            receiver, name = call.group(1), call.group(2).rstrip("!")
            if receiver == "vm":
                cheatcode = name
                break
            if prod_by_name.get(name):
                cands = prod_by_name[name]
                break
        if cheatcode is not None:
            if cheatcode == "label":
                rec.update(graph_bucket="false_positives", reason="cosmetic cheatcode vm.label")
            else:
                rec.update(
                    graph_bucket="missing_tests",
                    reason=f"cheatcode vm.{cheatcode} removed and the test still passes",
                )
        elif not cands:
            rec.update(graph_bucket="false_positives", reason="unmappable to production code")
        else:
            if len(cands) > 1:
                prod_path = infer_production_path(rel(str(r.get("test_file_path", "")), root))
                same = [n for n in cands if rel(n["location"]["file_path"], root) == prod_path]
                cands = same if len(same) == 1 else cands
            if len(cands) == 1:
                apply(rec, cands[0]["id"])
            else:
                rec.update(
                    graph_bucket="needs_review",
                    reason=f"call matches {len(cands)} production functions",
                    ambiguous_candidates=sorted(n["id"] for n in cands),
                )
        mapped.append(rec)

    flagged = {
        r["node_id"] for r in mapped if r.get("node_id") and r["graph_bucket"] in FUZZ_BUCKETS
    }
    corroborated = sorted(
        {m["node_id"] for m in triaged if m.get("node_id") in flagged}
        & {m["node_id"] for m in triaged if m["graph_bucket"] in FUZZ_BUCKETS}
    )
    counts: dict[str, int] = {}
    for r in triaged + mapped:
        counts[r["graph_bucket"]] = counts.get(r["graph_bucket"], 0) + 1
    problems = []
    undecided = {k: v for k, v in dropped.items() if k not in DECIDED}
    if not mutants and undecided:
        raise ValueError(
            f"no survived mutants, and {sum(undecided.values())} record(s) have no decided "
            f"outcome {undecided}; the campaign is incomplete, not clean"
        )
    if not mutants:
        problems.append(f"no survived mutants to triage (dropped by status: {dropped})")
    elif all(m["graph_bucket"] == "unbound" for m in triaged):
        problems.append(
            f"none of {len(mutants)} survived mutants bind to the graph; check --target, "
            "--language and the record paths"
        )
    result = {
        "trailmark_version": version,
        "target": str(root),
        "mutants": triaged,
        "necessist": mapped,
        "corroborated_nodes": corroborated,
        "graph_bucket_counts": counts,
        "dropped_statuses": dropped,
        "note": "graph buckets only; move equivalent and cosmetic mutants to false positives "
        "with a reason after reading the code, and resolve unbound and needs_review records",
    }
    return result, problems


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--target", default=".")
    ap.add_argument("--mutants", type=Path, required=True)
    ap.add_argument("--necessist", type=Path)
    ap.add_argument("--language", default="auto")
    ap.add_argument("--out", type=Path, help="write the full JSON here; stdout gets a summary")
    args = ap.parse_args()
    if not Path(args.target).is_dir():
        print(f"error: target is not a directory: {args.target}", file=sys.stderr)
        return 2
    try:
        result, problems = build(args)
    except TrailmarkError as e:
        print(f"error: trailmark failed: {e}", file=sys.stderr)
        return 2
    except (OSError, ValueError, KeyError, TypeError) as e:
        print(f"error: bad input: {e}", file=sys.stderr)
        return 2
    text = json.dumps(result, indent=1)
    if args.out:
        try:
            args.out.write_text(text + "\n")
        except OSError as e:
            print(f"error: cannot write {args.out}: {e}", file=sys.stderr)
            print(text)
            return 2
        summary = {
            "out": str(args.out),
            "mutants": len(result["mutants"]),
            "necessist": len(result["necessist"]),
            "graph_bucket_counts": result["graph_bucket_counts"],
            "dropped_statuses": result["dropped_statuses"],
            "corroborated_nodes": result["corroborated_nodes"],
        }
        print(json.dumps(summary, indent=1))
    else:
        print(text)
    for problem in problems:
        print(f"note: {problem}", file=sys.stderr)
    unbound_only = result["mutants"] and all(
        m["graph_bucket"] == "unbound" for m in result["mutants"]
    )
    return 2 if unbound_only else 0


if __name__ == "__main__":
    raise SystemExit(main())
