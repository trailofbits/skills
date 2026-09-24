#!/usr/bin/env -S uv run --script
# /// script
# requires-python = ">=3.12"
# dependencies = ["trailmark>=0.5,<0.6"]
# ///
"""Compare Trailmark code graphs at two snapshots and write complete evidence plus a report.

Three input modes, one required ``--language``:

  evolve.py --repo REPO --before REF --after REF --language auto --output-dir OUT
  evolve.py --before-dir DIR --after-dir DIR --language auto --output-dir OUT
  evolve.py --before-graph B.json --after-graph A.json --native-diff D.json \
      --language auto --output-dir OUT

Outputs under OUT:

  evidence/before_graph.json, evidence/after_graph.json   complete graph exports after pre-analysis
  evidence/trailmark_diff.json                            complete native diff (nodes, edges,
                                                          entrypoints)
  evidence/subgraph_diff.json                             complete membership diff (graph_diff.py)
  summary.json                                            compact review packet (counts, changes,
                                                          candidates)
  findings.md                                             the candidate findings, one block each,
                                                          with ``TODO`` where the reviewer writes
                                                          from the source
  GRAPH_EVOLUTION_<name>.md                               report: every deterministic section filled
                                                          from the evidence; its findings region is
                                                          a copy of findings.md

Then ``evolve.py --assemble --output-dir OUT`` copies the reviewed findings.md into the report
and fails while any ``TODO`` remains, so one rewritten file completes the report.

The graph is built and diffed exactly as the Trailmark API does it; nothing is summarised away.
"""

from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any

SCRIPT_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(SCRIPT_DIR))
from graph_diff import compute_diff as compute_subgraph_diff  # noqa: E402

SUMMARY_METRICS = (
    ("Total nodes", "total_nodes"),
    ("Functions", "functions"),
    ("Classes", "classes"),
    ("Call edges", "call_edges"),
    ("Entrypoints", "entrypoints"),
)
LANGUAGE_BY_EXTENSION = {
    ".py": "Python",
    ".rs": "Rust",
    ".go": "Go",
    ".sol": "Solidity",
    ".ts": "TypeScript",
    ".tsx": "TypeScript",
    ".js": "JavaScript",
    ".c": "C",
    ".h": "C",
    ".cpp": "C++",
    ".cc": "C++",
    ".hpp": "C++",
    ".java": "Java",
    ".kt": "Kotlin",
    ".swift": "Swift",
    ".rb": "Ruby",
    ".php": "PHP",
    ".cairo": "Cairo",
    ".circom": "Circom",
    ".move": "Move",
    ".cs": "C#",
}
SENSITIVE_NAME = re.compile(
    r"(?i)(exec|query|sql|system|popen|spawn|shell|eval|deserial|pickle|unsafe|"
    r"auth|login|token|secret|password|crypt|sign|verify|write|delete|drop|upload|download)"
)
TODO = "TODO"


# --- graph access -------------------------------------------------------------------


def node_info(graph: dict[str, Any], node_id: str) -> tuple[str, Any, str]:
    node = graph.get("nodes", {}).get(node_id, {})
    return (
        node.get("kind", "?"),
        node.get("cyclomatic_complexity"),
        (node.get("location") or {}).get("file_path", "?"),
    )


def languages_of(*graphs: dict[str, Any]) -> list[str]:
    names = set()
    for graph in graphs:
        for node in graph.get("nodes", {}).values():
            suffix = Path((node.get("location") or {}).get("file_path", "")).suffix.lower()
            if suffix in LANGUAGE_BY_EXTENSION:
                names.add(LANGUAGE_BY_EXTENSION[suffix])
    return sorted(names)


def check_health(graph: dict[str, Any], label: str) -> None:
    summary = graph.get("summary", {})
    if (
        summary.get("total_nodes", 0) == 0
        or (summary.get("functions", 0) + summary.get("classes", 0)) == 0
    ):
        raise SystemExit(
            f"error: the {label} graph has no functions or classes; pass an explicit --language "
            f"(the Python default parses nothing in other languages) and check the snapshot path"
        )


# --- building -----------------------------------------------------------------------


def build_snapshots(before_dir: Path, after_dir: Path, language: str) -> tuple[dict, dict, dict]:
    """Build both graphs; diff before pre-analysis, export after it, as the Trailmark API does."""
    from trailmark.query.api import QueryEngine

    before = QueryEngine.from_directory(str(before_dir), language=language)
    after = QueryEngine.from_directory(str(after_dir), language=language)
    native = after.diff_against(before)
    before.preanalysis()
    after.preanalysis()
    return json.loads(before.to_json()), json.loads(after.to_json()), native


def git(repo: Path, *args: str) -> str:
    result = subprocess.run(
        ["git", "-C", str(repo), *args], text=True, capture_output=True, check=False
    )
    if result.returncode:
        raise SystemExit(f"error: git {' '.join(args)}: {result.stderr.strip() or 'failed'}")
    return result.stdout


def checkout_worktrees(repo: Path, refs: tuple[str, str], temporary: Path) -> list[Path]:
    """Create detached worktrees for both refs; the caller removes whatever was created."""
    created: list[Path] = []
    try:
        for label, ref in zip(("before", "after"), refs, strict=True):
            target = temporary / label
            git(repo, "worktree", "add", "--detach", str(target), ref)
            created.append(target)
    except BaseException:
        remove_worktrees(repo, created)
        raise
    return created


def remove_worktrees(repo: Path, created: list[Path]) -> None:
    for target in created:
        subprocess.run(
            ["git", "-C", str(repo), "worktree", "remove", "--force", str(target)],
            capture_output=True,
            check=False,
        )
    subprocess.run(["git", "-C", str(repo), "worktree", "prune"], capture_output=True, check=False)


# --- classification -----------------------------------------------------------------


def cc_change(node: dict[str, Any]) -> tuple[int, int, int] | None:
    change = node.get("changes", {}).get("cyclomatic_complexity")
    if not change or change.get("before") is None or change.get("after") is None:
        return None
    return change["before"], change["after"], change["after"] - change["before"]


def candidates(native: dict, subgraph: dict, before: dict, after: dict) -> list[dict[str, Any]]:
    """Pre-classify structural signals. Severities are proposals for the reviewer to confirm."""
    memberships = subgraph.get("subgraphs", {})
    tainted_added = set(memberships.get("tainted", {}).get("added", []))
    blast_added = set(memberships.get("high_blast_radius", {}).get("added", []))
    boundary_added = memberships.get("privilege_boundary", {}).get("added", [])
    boundary_removed = memberships.get("privilege_boundary", {}).get("removed", [])
    added_edges = native.get("edges", {}).get("added", [])
    found: list[dict[str, Any]] = []

    for entry in native.get("entrypoints", {}).get("added", []):
        node = entry["id"]
        untrusted = entry.get("trust_level") == "untrusted_external"
        out = [e for e in added_edges if e["source"] == node and e["kind"] == "calls"]
        found.append(
            {
                "severity": "HIGH" if untrusted else "MEDIUM",
                "kind": "new_entrypoint",
                "title": f"New {entry.get('trust_level', '?')} entrypoint `{node}`",
                "what": (
                    f"`{node}` ({entry.get('kind', '?')}, {node_info(after, node)[2]}) is a new "
                    f"entrypoint with trust level `{entry.get('trust_level')}`."
                ),
                "evidence": [f"entrypoints.added: `{node}`"]
                + [f"new call edge `{e['source']}` -> `{e['target']}`" for e in out]
                + ([f"`{node}` is in `tainted`"] if node in tainted_added else [])
                + ([f"`{node}` is in `high_blast_radius`"] if node in blast_added else []),
                "nodes": [node] + [e["target"] for e in out],
            }
        )
    for entry in native.get("entrypoints", {}).get("modified", []):
        node = entry["id"]
        b, a = entry["before"].get("trust_level"), entry["after"].get("trust_level")
        if b != a:
            found.append(
                {
                    "severity": "MEDIUM",
                    "kind": "entrypoint_trust_changed",
                    "title": f"Entrypoint `{node}` trust level changed `{b}` -> `{a}`",
                    "what": (
                        f"`{node}` remains an entrypoint but its trust level moved "
                        f"from `{b}` to `{a}`."
                    ),
                    "evidence": [f"entrypoints.modified: `{node}` before={b} after={a}"],
                    "nodes": [node],
                }
            )
    sensitive = sorted(n for n in tainted_added if SENSITIVE_NAME.search(n.rsplit(":", 1)[-1]))
    for node in sensitive:
        callers = [e for e in added_edges if e["target"] == node and e["kind"] == "calls"]
        found.append(
            {
                "severity": "HIGH",
                "kind": "tainted_sensitive_node",
                "title": f"Untrusted data now reaches `{node}`",
                "what": (
                    f"`{node}` ({node_info(after, node)[2]}) entered the `tainted` subgraph: it is "
                    "reachable from an untrusted entrypoint after this change."
                ),
                "evidence": [f"tainted.added: `{node}`"]
                + [f"new call edge `{e['source']}` -> `{e['target']}`" for e in callers],
                "nodes": [node] + [e["source"] for e in callers],
            }
        )
    other_tainted = sorted(tainted_added - set(sensitive))
    if other_tainted:
        found.append(
            {
                "severity": "MEDIUM",
                "kind": "newly_tainted",
                "title": f"{len(other_tainted)} node(s) newly reachable from untrusted input",
                "what": "These nodes entered the `tainted` subgraph.",
                "evidence": [f"tainted.added: {', '.join(f'`{n}`' for n in other_tainted)}"],
                "nodes": other_tainted,
            }
        )
    if blast_added:
        found.append(
            {
                "severity": "MEDIUM",
                "kind": "new_high_blast_radius",
                "title": f"{len(blast_added)} node(s) entered `high_blast_radius`",
                "what": "Changes to these nodes now affect more downstream code.",
                "evidence": [
                    f"high_blast_radius.added: {', '.join(f'`{n}`' for n in sorted(blast_added))}"
                ],
                "nodes": sorted(blast_added),
            }
        )
    if boundary_removed:
        found.append(
            {
                "severity": "MEDIUM",
                "kind": "privilege_boundary_removed",
                "title": f"{len(boundary_removed)} node(s) left `privilege_boundary`",
                "what": (
                    "These nodes no longer sit on a trust transition. That can mean an "
                    "authorization check was removed, or that the boundary moved elsewhere."
                ),
                "evidence": [
                    f"privilege_boundary.removed: {', '.join(f'`{n}`' for n in boundary_removed)}"
                ]
                + [
                    f"privilege_boundary.added: {', '.join(f'`{n}`' for n in boundary_added)}"
                    if boundary_added
                    else "privilege_boundary.added: none"
                ],
                "nodes": list(boundary_removed),
            }
        )
    elif boundary_added:
        found.append(
            {
                "severity": "MEDIUM",
                "kind": "privilege_boundary_added",
                "title": f"{len(boundary_added)} new `privilege_boundary` node(s)",
                "what": "New call edges cross a trust level.",
                "evidence": [
                    f"privilege_boundary.added: {', '.join(f'`{n}`' for n in boundary_added)}"
                ],
                "nodes": list(boundary_added),
            }
        )
    for node in native.get("nodes", {}).get("modified", []):
        change = cc_change(node)
        if change and change[2] > 3:
            after_tainted = node["id"] in set(after.get("subgraphs", {}).get("tainted", []))
            found.append(
                {
                    "severity": "HIGH" if after_tainted else "MEDIUM",
                    "kind": "complexity_increase",
                    "title": f"Complexity of `{node['id']}` rose {change[0]} -> {change[1]}",
                    "what": f"Cyclomatic complexity increased by {change[2]}"
                    + (" on a node reachable from untrusted input." if after_tainted else "."),
                    "evidence": [
                        f"nodes.modified: `{node['id']}` cyclomatic_complexity "
                        f"{change[0]} -> {change[1]}"
                    ],
                    "nodes": [node["id"]],
                }
            )
    for entry in native.get("entrypoints", {}).get("removed", []):
        found.append(
            {
                "severity": "LOW",
                "kind": "removed_entrypoint",
                "title": f"Entrypoint `{entry['id']}` removed",
                "what": (
                    f"`{entry['id']}` ({entry.get('trust_level')}) is no longer an entrypoint; "
                    "check whether its callers moved to a new route."
                ),
                "evidence": [f"entrypoints.removed: `{entry['id']}`"],
                "nodes": [entry["id"]],
            }
        )
    return found


# --- report ---------------------------------------------------------------------------


def table(headers: tuple[str, ...], rows: list[tuple]) -> str:
    if not rows:
        return "No changes."
    lines = ["| " + " | ".join(headers) + " |", "|" + "|".join("---" for _ in headers) + "|"]
    lines += ["| " + " | ".join(str(c) for c in row) + " |" for row in rows]
    return "\n".join(lines)


def signed(value: int) -> str:
    return f"+{value}" if value > 0 else str(value)


FINDINGS_BEGIN = "<!-- findings:begin -->"
FINDINGS_END = "<!-- findings:end -->"


def render_findings(found: list[dict], before: dict, after: dict) -> str:
    """The candidate findings as the reviewer edits them: one block per finding."""
    if not found:
        return (
            "No pre-classified candidates. Review the report sections against the source; if "
            "nothing is security-relevant, state that the comparison is structurally neutral "
            "and why.\n"
        )
    out: list[str] = []
    for f in found:
        first = f["nodes"][0] if f["nodes"] else None
        graph = after if first in after.get("nodes", {}) else before
        source_file = node_info(graph, first)[2] if first else "?"
        out += [
            f"### [{f['severity']}] {f['title']}",
            "",
            f"**What changed:** {f['what']}",
            "**Evidence:** " + "; ".join(f["evidence"]) + f". Source: {source_file}.",
            f"**Security impact:** {TODO} — explain from the source what an attacker gains or "
            "loses; if nothing, delete this finding or mark it INFO with the reason.",
            f"**Recommendation:** {TODO} — what to review, fix, or test.",
            "",
        ]
    return "\n".join(out)


def assemble(out: Path) -> dict[str, Any]:
    """Copy findings.md into the report's findings region; refuse to leave any TODO behind."""
    reports = sorted(out.glob("GRAPH_EVOLUTION_*.md"))
    if len(reports) != 1:
        raise SystemExit(
            f"error: expected exactly one GRAPH_EVOLUTION_*.md in {out}, found {len(reports)}"
        )
    findings_path = out / "findings.md"
    if not findings_path.is_file():
        raise SystemExit(f"error: {findings_path} is missing; run the build step first")
    findings = findings_path.read_text().strip()
    report = reports[0].read_text()
    begin, end = report.find(FINDINGS_BEGIN), report.find(FINDINGS_END)
    if begin < 0 or end < begin:
        raise SystemExit("error: the report has no findings region; regenerate it")
    report = report[: begin + len(FINDINGS_BEGIN)] + "\n" + findings + "\n" + report[end:]
    reports[0].write_text(report)
    remaining = report.count(TODO)
    if remaining:
        raise SystemExit(
            f"error: {remaining} {TODO} marker(s) remain in {reports[0].name}; write the security "
            "impact, recommendation, and limitations from the source, then assemble again"
        )
    count = len(re.findall(r"^### \[(?:CRITICAL|HIGH|MEDIUM|LOW|INFO)\] ", report, re.M))
    return {"report": str(reports[0]), "findings": count, "todo_markers": 0}


def render_report(
    *,
    name: str,
    project: str,
    before_label: str,
    after_label: str,
    language: str,
    before: dict,
    after: dict,
    native: dict,
    subgraph: dict,
    found: list[dict],
    evidence_dir: str,
    tool_version: str,
) -> str:
    memberships = subgraph.get("subgraphs", {})
    nodes = native.get("nodes", {})
    edges = native.get("edges", {})
    entrypoints = native.get("entrypoints", {})
    detected = languages_of(before, after)
    out: list[str] = [
        "# Graph Evolution Report",
        "",
        f"**Project:** {project}",
        f"**Before:** {before_label}",
        f"**After:** {after_label}",
        f"**Language:** {language} (detected: {', '.join(detected) or 'none'})",
        "",
        "## Summary",
        "",
        table(
            ("Metric", "Before", "After", "Delta"),
            [
                (
                    label,
                    before["summary"].get(key, 0),
                    after["summary"].get(key, 0),
                    signed(after["summary"].get(key, 0) - before["summary"].get(key, 0)),
                )
                for label, key in SUMMARY_METRICS
            ],
        ),
        "",
        "## Critical Structural Changes",
        "",
        "Changes with direct security implications, with the structural evidence and affected",
        "nodes.",
        "Severities are structural proposals confirmed against the source.",
        "",
    ]
    out += [FINDINGS_BEGIN, render_findings(found, before, after).rstrip(), FINDINGS_END, ""]

    def ep_rows(items: list[dict]) -> list[tuple]:
        rows = []
        for e in items:
            graph = after if e["id"] in after.get("nodes", {}) else before
            rows.append(
                (
                    e["id"],
                    e.get("kind", "?"),
                    e.get("trust_level", "?"),
                    node_info(graph, e["id"])[2],
                )
            )
        return rows

    out += [
        "## Attack Surface Evolution",
        "",
        "### New Entrypoints",
        "",
        table(("Node", "Kind", "Trust Level", "File"), ep_rows(entrypoints.get("added", []))),
        "",
        "### Removed Entrypoints",
        "",
        table(("Node", "Kind", "Trust Level", "File"), ep_rows(entrypoints.get("removed", []))),
        "",
        "### Modified Entrypoints",
        "",
        table(
            ("Node", "Before Trust Level", "After Trust Level", "Kind", "File"),
            [
                (
                    e["id"],
                    e["before"].get("trust_level", "?"),
                    e["after"].get("trust_level", "?"),
                    e["after"].get("kind", "?"),
                    node_info(after, e["id"])[2],
                )
                for e in entrypoints.get("modified", [])
            ],
        ),
        "",
    ]
    inc, dec, other = [], [], []
    for node in nodes.get("modified", []):
        change = cc_change(node)
        if change and change[2] > 0:
            inc.append(
                (
                    node["id"],
                    change[0],
                    change[1],
                    signed(change[2]),
                    node_info(after, node["id"])[2],
                )
            )
        elif change and change[2] < 0:
            dec.append(
                (
                    node["id"],
                    change[0],
                    change[1],
                    signed(change[2]),
                    node_info(after, node["id"])[2],
                )
            )
        else:
            other.append(
                (
                    node["id"],
                    ", ".join(sorted(node.get("changes", {}).keys())) or "?",
                    node_info(after, node["id"])[2],
                )
            )
    out += [
        "## Complexity Evolution",
        "",
        "### Increased Complexity (CC delta > 0)",
        "",
        table(("Node", "Before CC", "After CC", "Delta", "File"), inc),
        "",
        "### Decreased Complexity (CC delta < 0)",
        "",
        table(("Node", "Before CC", "After CC", "Delta", "File"), dec),
        "",
        "### Other Modified Nodes",
        "",
        table(("Node", "Changed fields", "File"), other),
        "",
    ]

    def member_rows(ids: list[str], graph: dict) -> list[tuple]:
        return [(n, node_info(graph, n)[0], node_info(graph, n)[2]) for n in ids]

    for section, name_, (h_add, h_rem) in (
        ("Taint Propagation Changes", "tainted", ("Newly Tainted Nodes", "De-Tainted Nodes")),
        (
            "Blast Radius Shifts",
            "high_blast_radius",
            ("Nodes Entering high_blast_radius", "Nodes Leaving high_blast_radius"),
        ),
        (
            "Privilege Boundary Changes",
            "privilege_boundary",
            ("New Boundary Crossings", "Removed Boundary Crossings"),
        ),
    ):
        change = memberships.get(name_, {})
        out += [
            f"## {section}",
            "",
            f"### {h_add}",
            "",
            table(("Node", "Kind", "File"), member_rows(change.get("added", []), after)),
            "",
            f"### {h_rem}",
            "",
            table(("Node", "Kind", "File"), member_rows(change.get("removed", []), before)),
            "",
        ]
        if name_ == "privilege_boundary":
            out += [
                "Membership changes are structural signals. A removed crossing can mean an",
                "authorization check was removed, or that the boundary moved to another node;",
                "confirm in the source before concluding.",
                "",
            ]
    out += [
        "## Subgraph Membership Changes",
        "",
        table(
            ("Subgraph", "Added", "Removed"),
            [
                (
                    name_,
                    ", ".join(f"`{n}`" for n in c.get("added", [])) or "—",
                    ", ".join(f"`{n}`" for n in c.get("removed", [])) or "—",
                )
                for name_, c in sorted(memberships.items())
            ],
        ),
        "",
    ]

    def node_rows(items: list[dict]) -> list[tuple]:
        rows = []
        for n in items:
            cc = n.get("cyclomatic_complexity")
            rows.append(
                (n["id"], n.get("kind", "?"), cc if cc is not None else "—", n.get("file", "?"))
            )
        return rows

    def edge_rows(items: list[dict]) -> list[tuple]:
        return [(e["source"], e["target"], e["kind"]) for e in items]

    out += [
        "## New Code (Added Nodes)",
        "",
        table(("Node", "Kind", "CC", "File"), node_rows(nodes.get("added", []))),
        "",
        "## Removed Code (Deleted Nodes)",
        "",
        table(("Node", "Kind", "CC", "File"), node_rows(nodes.get("removed", []))),
        "",
        "## New Call Relationships (Added Edges)",
        "",
        table(("Source", "Target", "Kind"), edge_rows(edges.get("added", []))),
        "",
        "## Removed Call Relationships (Deleted Edges)",
        "",
        table(("Source", "Target", "Kind"), edge_rows(edges.get("removed", []))),
        "",
        "## Methodology",
        "",
        f"- **Tool:** Trailmark graph-evolution `evolve.py` (Trailmark {tool_version})",
        f"- **Before snapshot:** {before_label}",
        f"- **After snapshot:** {after_label}",
        "- **Pre-analysis:** blast radius, taint propagation, privilege boundaries, entrypoints",
        f"- **Languages detected:** {', '.join(detected) or 'none'} (requested: `{language}`)",
        f"- **Evidence:** `{evidence_dir}/before_graph.json`, `{evidence_dir}/after_graph.json`, "
        f"`{evidence_dir}/trailmark_diff.json`, `{evidence_dir}/subgraph_diff.json`",
        "- **Limitations:** Structural analysis only: it shows reachability and membership",
        "  changes, not exploitability or deployment reachability. Entrypoint detection depends",
        "  on framework markers and `.trailmark/entrypoints.toml` overrides; unresolved calls",
        "  appear as proxy nodes and are not followed. A membership change is a review signal,",
        f"  not a finding. {TODO}: add limitations specific to this comparison.",
        "",
    ]
    return "\n".join(out)


def review_packet(
    *,
    before: dict,
    after: dict,
    native: dict,
    subgraph: dict,
    found: list[dict],
    evidence: dict[str, str],
    report: str,
) -> dict:
    return {
        "summary": {
            key: {
                "before": before["summary"].get(key, 0),
                "after": after["summary"].get(key, 0),
                "delta": after["summary"].get(key, 0) - before["summary"].get(key, 0),
            }
            for _, key in SUMMARY_METRICS
        },
        "languages_detected": languages_of(before, after),
        "entrypoints": native.get("entrypoints", {}),
        "nodes": {k: len(v) for k, v in native.get("nodes", {}).items()},
        "edges": {k: len(v) for k, v in native.get("edges", {}).items()},
        "complexity_changes": [
            {"id": n["id"], "before": c[0], "after": c[1], "delta": c[2]}
            for n in native.get("nodes", {}).get("modified", [])
            if (c := cc_change(n))
        ],
        "subgraph_changes": subgraph.get("subgraphs", {}),
        "candidates": found,
        "evidence": evidence,
        "report": report,
        "findings": "findings.md",
        "next": (
            "Read the source of the nodes named in candidates; rewrite findings.md in one pass "
            "(confirm or change severities, replace every TODO, add findings the "
            "pre-classification cannot see); then run evolve.py --assemble --output-dir <dir>."
        ),
    }


# --- CLI ------------------------------------------------------------------------------


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument("--repo", type=Path, help="git repository; use with --before/--after refs")
    parser.add_argument("--before", help="before git ref (with --repo)")
    parser.add_argument("--after", help="after git ref (with --repo)")
    parser.add_argument("--before-dir", type=Path, help="before source directory")
    parser.add_argument("--after-dir", type=Path, help="after source directory")
    parser.add_argument("--before-graph", type=Path, help="pre-exported before graph JSON")
    parser.add_argument("--after-graph", type=Path, help="pre-exported after graph JSON")
    parser.add_argument(
        "--native-diff", type=Path, help="pre-exported `trailmark diff --json` output (with graphs)"
    )
    parser.add_argument(
        "--language",
        required=False,
        help="explicit language or `auto`; never rely on the Python default",
    )
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument(
        "--name", help="report label: GRAPH_EVOLUTION_<name>.md (default from the snapshots)"
    )
    parser.add_argument("--project", help="project name for the report header")
    parser.add_argument(
        "--assemble",
        action="store_true",
        help="copy the reviewed findings.md into the report and fail if any TODO remains",
    )
    return parser.parse_args(argv)


def slug(value: str) -> str:
    return re.sub(r"[^A-Za-z0-9]+", "_", value).strip("_") or "snapshot"


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    if args.assemble:
        print(json.dumps(assemble(args.output_dir), indent=2))
        return 0
    if not args.language:
        raise SystemExit("error: --language is required (use `auto` or an explicit list)")
    modes = [
        bool(args.repo or args.before or args.after),
        bool(args.before_dir or args.after_dir),
        bool(args.before_graph or args.after_graph or args.native_diff),
    ]
    if sum(modes) != 1:
        raise SystemExit(
            "error: choose one mode: --repo/--before/--after, --before-dir/--after-dir, "
            "or --before-graph/--after-graph/--native-diff"
        )
    out = args.output_dir
    evidence_dir = out / "evidence"
    evidence_dir.mkdir(parents=True, exist_ok=True)
    if modes[0]:
        if not (args.repo and args.before and args.after):
            raise SystemExit("error: --repo, --before and --after are all required for ref mode")
        repo = args.repo.resolve()
        before_label, after_label = args.before, args.after
        project = args.project or repo.name
        with tempfile.TemporaryDirectory(prefix="trailmark-evolve-") as temporary:
            created = checkout_worktrees(repo, (args.before, args.after), Path(temporary))
            try:
                before, after, native = build_snapshots(created[0], created[1], args.language)
            finally:
                remove_worktrees(repo, created)
    elif modes[1]:
        if not (args.before_dir and args.after_dir):
            raise SystemExit("error: both --before-dir and --after-dir are required")
        before_dir, after_dir = args.before_dir.resolve(), args.after_dir.resolve()
        for d in (before_dir, after_dir):
            if not d.is_dir():
                raise SystemExit(f"error: not a directory: {d}")
        before_label, after_label = str(before_dir), str(after_dir)
        project = args.project or (
            before_dir.parent.name
            if before_dir.parent == after_dir.parent
            else f"{before_dir.name} -> {after_dir.name}"
        )
        before, after, native = build_snapshots(before_dir, after_dir, args.language)
    else:
        if not (args.before_graph and args.after_graph and args.native_diff):
            raise SystemExit(
                "error: --before-graph, --after-graph and --native-diff are all required "
                "for pre-exported mode"
            )
        before = json.loads(args.before_graph.read_text())
        after = json.loads(args.after_graph.read_text())
        native = json.loads(args.native_diff.read_text())
        before_label, after_label = str(args.before_graph), str(args.after_graph)
        project = args.project or "pre-exported graphs"
    check_health(before, "before")
    check_health(after, "after")
    subgraph = compute_subgraph_diff(before, after)
    name = args.name or "_".join(
        slug(Path(label).name if modes[1] else label) for label in (before_label, after_label)
    )
    report_path = out / f"GRAPH_EVOLUTION_{name}.md"
    evidence = {
        "before_graph": "evidence/before_graph.json",
        "after_graph": "evidence/after_graph.json",
        "trailmark_diff": "evidence/trailmark_diff.json",
        "subgraph_diff": "evidence/subgraph_diff.json",
    }
    (evidence_dir / "before_graph.json").write_text(json.dumps(before, indent=2) + "\n")
    (evidence_dir / "after_graph.json").write_text(json.dumps(after, indent=2) + "\n")
    (evidence_dir / "trailmark_diff.json").write_text(
        json.dumps(native, indent=2, default=str) + "\n"
    )
    (evidence_dir / "subgraph_diff.json").write_text(json.dumps(subgraph, indent=2) + "\n")
    found = candidates(native, subgraph, before, after)
    try:
        from importlib.metadata import version

        tool_version = version("trailmark")
    except Exception:  # noqa: BLE001 - version is informational
        tool_version = "unknown"
    report = render_report(
        name=name,
        project=project,
        before_label=before_label,
        after_label=after_label,
        language=args.language,
        before=before,
        after=after,
        native=native,
        subgraph=subgraph,
        found=found,
        evidence_dir="evidence",
        tool_version=tool_version,
    )
    report_path.write_text(report)
    (out / "findings.md").write_text(render_findings(found, before, after))
    packet = review_packet(
        before=before,
        after=after,
        native=native,
        subgraph=subgraph,
        found=found,
        evidence=evidence,
        report=str(report_path.name),
    )
    (out / "summary.json").write_text(json.dumps(packet, indent=2, default=str) + "\n")
    print(
        json.dumps(
            {
                "report": str(report_path),
                "summary": str(out / "summary.json"),
                "findings": str(out / "findings.md"),
                "evidence": str(evidence_dir),
                "candidates": len(found),
                "todo_markers": report.count(TODO),
                "languages_detected": packet["languages_detected"],
                "summary_delta": packet["summary"],
            },
            indent=2,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
