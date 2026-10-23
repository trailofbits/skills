# /// script
# requires-python = ">=3.13"
# dependencies = ["calcifier==0.2.0"]
# ///

import json
import re
from pathlib import Path
from typing import Any, Literal

import calcifier as c

BUILD = (
    "import json,sys; from importlib.metadata import version; "
    "from trailmark.query.api import QueryEngine; "
    "e=QueryEngine.from_directory(sys.argv[1],language=sys.argv[2]); e.preanalysis(); "
    "print(json.dumps(dict(graph=json.loads(e.to_json()),summary=e.summary(),"
    "version=version('trailmark'))))"
)
TABLES = {
    "new_entrypoints": ("Attack Surface Evolution/New Entrypoints", "Node|Kind|Trust Level|File"),
    "entry_old": ("Attack Surface Evolution/Removed Entrypoints", "Node|Kind|Trust Level|File"),
    "cc_increased": ("Complexity Evolution/Increased Complexity", "Node|Before|After|Delta|File"),
    "cc_decreased": ("Complexity Evolution/Decreased Complexity", "Node|Before|After|Delta|File"),
    "tainted": ("Taint Propagation Changes/Newly Tainted Nodes", "Node|Kind|Tainted Via|File"),
    "detainted": ("Taint Propagation Changes/De-Tainted Nodes", "Node|Kind|File"),
    "blast": ("Blast Radius Shifts/Entering high_blast_radius", "Node|Kind|Downstream Count|File"),
    "blast_removed": ("Blast Radius Shifts/Leaving high_blast_radius", "Node|Kind|File"),
    "bnew": ("Privilege Boundary Changes/New Boundary Crossings", "Node|Trust Transition|File"),
    "bold": ("Privilege Boundary Changes/Removed Boundary Crossings", "Node|Trust Transition|File"),
    "nodes_added": ("New Code (Added Nodes)", "Node|Kind|CC|File"),
    "nodes_removed": ("Removed Code (Deleted Nodes)", "Node|Kind|CC|File"),
    "edges_added": ("New Call Relationships (Added Edges)", "Source|Target|Kind|Confidence"),
    "old_edges": ("Removed Call Relationships (Deleted Edges)", "Source|Target|Kind|Confidence"),
}


@c.output_type
class Finding:
    severity: Literal["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
    title: str
    what_changed: str
    evidence: str
    security_impact: str
    recommendation: str


@c.output_type
class Analysis:
    findings: list[Finding]
    tables: tuple[
        list[list[str]],
        list[list[str]],
        list[list[str]],
        list[list[str]],
        list[list[str]],
        list[list[str]],
        list[list[str]],
        list[list[str]],
        list[list[str]],
        list[list[str]],
        list[list[str]],
        list[list[str]],
        list[list[str]],
        list[list[str]],
    ]
    limitations: str


def table(columns: list[str], rows: list[list[str]]) -> str:
    def row(cells: list[str]) -> str:
        return (
            "| "
            + " | ".join(cell.replace("|", "&#124;").replace("\n", "<br>") for cell in cells)
            + " |"
        )

    return "\n".join([row(columns), row(["---"] * len(columns)), *[row(r) for r in rows]])


@c.step
def render(meta: dict[str, Any], summaries: list[dict[str, Any]], result: Analysis) -> str:
    tables = dict(zip(TABLES, result.tables, strict=True))
    parts = ["# Graph Evolution Report", *[f"**{k}:** {v}" for k, v in meta.items()]]
    rows = []
    for key in ("total_nodes", "functions", "classes", "call_edges", "entrypoints"):
        values = [s.get(key, "Unavailable") for s in summaries]
        delta = f"{values[1] - values[0]:+d}" if all(isinstance(v, int) for v in values) else "N/A"
        rows.append([key.replace("_", " ").title(), *map(str, values), str(delta)])
    parts.extend(["## Summary", table(["Metric", "Before", "After", "Delta"], rows)])
    parts.append("## Critical Structural Changes")
    for finding in result.findings:
        parts.append(f"### [{finding.severity}] {finding.title}")
        parts.extend(
            f"**{label}:** {text}"
            for label, text in (
                ("What changed", finding.what_changed),
                ("Evidence", finding.evidence),
                ("Security impact", finding.security_impact),
                ("Recommendation", finding.recommendation),
            )
        )
    group = ""
    for key, (title, fields) in TABLES.items():
        headings = title.split("/", 1)
        if headings[0] != group:
            group = headings[0]
            parts.append("## " + group)
        if len(headings) == 2:
            parts.append("### " + headings[1])
        columns = fields.split("|") + ["Severity"]
        if any(
            len(r) != len(columns) or r[-1] not in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO")
            for r in tables[key]
        ):
            c.fail(f"Invalid columns or severity in {key}")
        parts.append(table(columns, tables[key]))
    parts.extend(
        [
            "## Methodology",
            "**Tool:** Trailmark graph-evolution",
            "**Pre-analysis:** blast radius, taint, privilege boundaries, entrypoints",
            "**Limitations:** " + result.limitations,
            "Evidence: [native diff](trailmark_diff.json), "
            "[subgraph diff](subgraph_diff.json), [source context](source.diff), "
            "[provenance and diagnostics](preparation.json).",
        ]
    )
    return "\n\n".join(parts) + "\n"


@c.recipe(
    name="graph-evolution",
    version="1",
    agents=("worker",),
    capabilities=("Bash",),
    budget=c.Budget(2, 3600),
    output_root="graph-evolution-artifacts",
)
def graph_evolution(
    project: str,
    before: str,
    after: str,
    mode: Literal["git_refs", "directories"] = "git_refs",
    repository: str = ".",
    language: str = "auto",
    fallback_language: str = "",
    preanalyzed_exports: tuple[str, str, str, str] | None = None,
) -> str:
    """Export tuple: before JSON, after JSON, version, language; sources remain required."""
    records: list[dict[str, Any]] = []
    repo = Path(repository).resolve()

    def command(
        argv: list[str], cwd: Path, *, mutate: bool = True, check: bool = True
    ) -> c.CommandResult:
        result = c.run_command(argv, working_directory=cwd, mutating=mutate, timeout_seconds=600)
        records.append({"argv": argv, "exit_code": result.exit_code, "stderr": result.stderr})
        if check and result.exit_code:
            c.fail(f"Command failed ({result.exit_code}): {argv}: {result.stderr}")
        return result

    def slug(text: str) -> str:
        return re.sub(r"[^A-Za-z0-9._-]+", "_", text)[:60] or "snapshot"

    report_name = f"GRAPH_EVOLUTION_{slug(project)}_{slug(before)}_{slug(after)}.md"
    files = [
        "before_graph.json",
        "after_graph.json",
        "trailmark_diff.json",
        "subgraph_diff.json",
        "source.diff",
        "preparation.json",
        "execution.json",
        report_name,
    ]
    commits, dates = [], ["unavailable (directory snapshot)"] * 2
    sources = [Path(before).resolve(), Path(after).resolve()] if mode == "directories" else []
    if mode == "git_refs":
        dates = []
        for label, ref in zip(("before", "after"), (before, after), strict=True):
            commit = command(
                ["git", "rev-parse", "--verify", "--end-of-options", ref + "^{commit}"],
                repo,
                mutate=False,
            ).stdout.strip()
            commits.append(commit)
            names = command(
                ["git", "ls-tree", "-rz", "--name-only", commit], repo, mutate=False
            ).stdout.split("\0")
            files.extend(f"{label}-source/{name}" for name in names if name)
            files.append(f"{label}-source/.git")
            dates.append(
                command(
                    ["git", "show", "-s", "--format=%cI", commit], repo, mutate=False
                ).stdout.strip()
            )
    elif not all(path.is_dir() for path in sources):
        c.fail("Both directory snapshots must exist")
    out = c.ensure_directory(
        "run", output_files=tuple(files), exclude_roots=tuple(sources) if sources else (repo,)
    )
    created: list[Path] = []
    try:
        if mode == "git_refs":
            sources = [out / "before-source", out / "after-source"]
            for path, commit in zip(sources, commits, strict=True):
                command(["git", "worktree", "add", "--detach", str(path), commit], repo)
                created.append(path)
        version_args = [
            "uv",
            "run",
            "--no-project",
            "--with",
            "trailmark",
            "python",
            "-c",
            "from importlib.metadata import version; print(version('trailmark'))",
        ]
        probe = command(version_args, out, check=False)
        if probe.exit_code:
            command(["uv", "tool", "install", "trailmark"], out)
            probe = command(version_args, out)
        version = probe.stdout.strip()
        runner = ["uv", "run", "--no-project", "--with", "trailmark==" + version]
        exports = preanalyzed_exports or ("", "", "", "")
        reuse = exports[2:] == (version, language)
        if reuse:
            graphs = [json.loads(Path(p).read_text(encoding="utf-8")) for p in exports[:2]]
            summaries = [g.get("summary", {}) for g in graphs]
        else:
            builds = [
                command(runner + ["python", "-c", BUILD, str(p), language], out, check=False)
                for p in sources
            ]
            if any(b.exit_code for b in builds) and fallback_language:
                if fallback_language == "auto":
                    c.fail("Fallback language must be explicit")
                language = fallback_language
                builds = [
                    command(runner + ["python", "-c", BUILD, str(p), language], out)
                    for p in sources
                ]
            if any(b.exit_code for b in builds):
                c.fail("Graph build/pre-analysis failed; set an explicit language: " + str(records))
            built = [json.loads(b.stdout) for b in builds]
            if any(
                b.get("version") != version or not isinstance(b.get("summary"), dict) for b in built
            ):
                c.fail("Graph summaries or matching version provenance are missing")
            graphs = [b["graph"] for b in built]
            summaries = [b["summary"] for b in built]
        for label, graph in zip(("before", "after"), graphs, strict=True):
            if not all(
                isinstance(graph.get(k), t)
                for k, t in (("nodes", dict), ("edges", list), ("subgraphs", dict))
            ):
                c.fail(f"{label}: invalid graph or absent pre-analysis; rebuild both snapshots")
            c.write_json(out / f"{label}_graph.json", graph)
        native = json.loads(
            command(
                runner
                + ["trailmark", "diff", "--json", "--language", language, *map(str, sources)],
                out,
            ).stdout
        )
        supplemental = json.loads(
            command(
                [
                    "uv",
                    "run",
                    "--no-project",
                    str(c.resource("scripts/graph_diff.py")),
                    "--before",
                    str(out / "before_graph.json"),
                    "--after",
                    str(out / "after_graph.json"),
                ],
                out,
            ).stdout
        )
        if not {"nodes", "edges", "entrypoints"} <= set(native) or "subgraphs" not in supplemental:
            c.fail("Incomplete native or supplemental structural diff")
        for label, graph in zip(("before", "after"), graphs, strict=True):
            count = native.get("source_coverage", {}).get(label, {}).get("source_files")
            if (isinstance(count, int) and count <= 0) or (count is None and not graph["nodes"]):
                c.fail(f"{label}: no inspected files, or empty graph without coverage evidence")
        c.write_json(out / "trailmark_diff.json", native)
        c.write_json(out / "subgraph_diff.json", supplemental)
        args = (
            ["git", "diff", "--no-ext-diff", "--no-textconv", *commits, "--"]
            if commits
            else ["git", "diff", "--no-index", "--", *map(str, sources)]
        )
        diff = command(args, repo if commits else out, mutate=False, check=False)
        if diff.exit_code not in ((0,) if commits else (0, 1)):
            c.fail("Source diff failed: " + diff.stderr)
        c.write_text(out / "source.diff", diff.stdout)
        meta = {
            "Project": project,
            "Before": f"{before} ({dates[0]})",
            "After": f"{after} ({dates[1]})",
            "Language": language,
            "Trailmark version (both snapshots)": version,
        }
        c.write_json(
            out / "preparation.json",
            {
                "metadata": meta,
                "exports_reused": reuse,
                "summaries": summaries,
                "commands": records,
            },
        )
        evidence = tuple(out / name for name in files[:6])
        refs = tuple(
            c.resource(p)
            for p in ("references/evolution-metrics.md", "references/report-format.md")
        )
        context = c.prepare_context(
            "Perform the source skill's complete, connected interpretation and checks in order. "
            "Use both full diffs, graphs, diagnostics and snapshot source context. Classify every "
            "change, including removals and modifications. Return findings and tables in the "
            "supplied table order. Rows follow column order plus Severity; empty groups are []. "
            "Retain native signature/default/type/attribute/origin and confidence evidence. "
            "Missing coverage is unavailable; node counts do not prove source coverage. "
            "State honest limitations and assess empty diffs only as instructed by the source.",
            prior_results=json.dumps({"metadata": meta, "tables": TABLES}),
            files=evidence + refs,
            readable_roots=(out, *refs),
        )
        result = c.agent(
            "worker",
            "Interpret the complete prepared assignment and references.",
            context=context,
            working_directory=out,
            readable_paths=tuple(sources),
            output=Analysis,
            timeout=3600,
        )
        markdown = render(meta, summaries, result)
        c.emit(str(c.verify_artifact(c.write_text(out / report_name, markdown))), name="path")
    finally:
        errors = []
        for path in created:
            cleanup = command(["git", "worktree", "remove", str(path)], repo, check=False)
            if cleanup.exit_code:
                errors.append(cleanup.stderr)
        c.write_json(out / "execution.json", {"commands": records, "cleanup_errors": errors})
    if errors:
        c.fail("Report written, but worktree cleanup failed; see execution.json")
    return c.emit(markdown, name="report")


if __name__ == "__main__":
    raise SystemExit(graph_evolution.cli())


# --- calcifier metadata (skill provenance + sha256) ---
_CALCIFIER_COMPILATION = "compiled"
_CALCIFIER_SKILL = {
    "path": "../SKILL.md",
    "sha256": ("c5939e80f0c05f3fe38066e088a8fc9a490d5613a684f47ab35c19747b2cebf7"),
}
_CALCIFIER_RESOURCES = [
    {
        "path": "agents/code-slice-worker.md",
        "sha256": ("6b427cf3aa5caf357cd0fb18eca324b4207706bcd7e79eaff157590cd5816cb7"),
        "size": 1912,
        "source": "../../agents/code-slice-worker.md",
    },
    {
        "path": "references/evolution-metrics.md",
        "sha256": ("ec26ea932290be3490227025705296126e446743a64b604e11f7a50fd649f722"),
        "size": 5205,
        "source": None,
    },
    {
        "path": "references/report-format.md",
        "sha256": ("cc44977216b7e90075c6fca845b630d7156e72d88f1234fa3f0026d367d1a0db"),
        "size": 4340,
        "source": None,
    },
    {
        "path": "scripts/graph_diff.py",
        "sha256": ("4cb00ee257d45e464e7679f654261791b3b21f2c92f7887e5b306b1de62faa55"),
        "size": 7845,
        "source": None,
    },
]
_CALCIFIER_INTERFACE = {
    "text": (
        "The destination repository uses Ruff rules E, F, I, UP, B,"
        " and SIM, target-version py311, and line-length 100. The g"
        "enerated recipe must satisfy those checks, including B007,"
        " B905, and SIM102. Keep the Python 3.13 minimum required b"
        "y Calcifier in its generated PEP 723 header. This skill is"
        " distributed independently: do not require another unmerge"
        "d skill recipe. Referenced prose and explicitly provided r"
        "esources may be packaged, while the generated recipe belon"
        "gs only to the requested skill. Repository contribution ru"
        "le: a checker that inspects zero items must fail with an e"
        "xplanation rather than return a successful clean report. T"
        "his applies to an empty inspection scope, not to a complet"
        "ed inspection that finds zero issues."
    ),
    "sha256": ("12c73b0662a6bdb615688c499f4e3e22540e4788549e5ad24bb7e01f76c25fcc"),
}
_CALCIFIER_SUBRECIPES = []
