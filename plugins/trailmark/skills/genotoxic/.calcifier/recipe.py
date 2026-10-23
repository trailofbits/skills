# /// script
# requires-python = ">=3.13"
# dependencies = ["calcifier==0.2.0"]
# ///

import json
from pathlib import Path
from typing import Any, Literal

from calcifier import (
    Budget,
    agent,
    emit,
    ensure_directory,
    fail,
    output_type,
    prepare_context,
    recipe,
    resource,
    step,
    verify_artifact,
    write_text,
)


@output_type
class Finding:
    evidence_id: str
    bucket: Literal["false_positive", "missing_tests", "fuzzing_target", "needs_manual_review"]
    node_id: str
    function: str
    reason: str
    cc: int | None
    callers: int | None
    suggested_test: str
    entrypoint_paths: list[str]
    blast_radius: str


@output_type
class Review:
    blocker: str
    mutation_format: Literal["elements", "universal"]
    necessist_status: Literal["completed", "not_applicable"]
    notes: str
    findings: list[Finding]


def load(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


@step
def collect(directory: Path, kind: str, necessist: bool) -> dict[str, Any]:
    graph = load(directory / "genotoxic-graph.json")
    analysis = load(directory / "genotoxic-preanalysis.json")
    required = {
        "source_file_count",
        "trailmark_version",
        "parse_diagnostics",
        "call_resolution_gaps",
        "preanalysis",
    }
    count = analysis.get("source_file_count")
    if not required.issubset(analysis) or not isinstance(count, int) or count <= 0:
        fail("Trailmark evidence must retain its analysis metadata and a positive inspected scope.")
    if not isinstance(graph.get("nodes"), dict) or not graph["nodes"]:
        fail("The graph inspection contains zero nodes; inspect coverage and parsing failures.")
    raw = load(directory / "genotoxic-mutations.json")
    if kind == "elements":
        mutations = [
            item | {"file_path": filename, "line": item["location"]["start"]["line"]}
            for filename, details in sorted(raw["files"].items())
            for item in details["mutants"]
        ]
    else:
        mutations = raw
    mutations = [item for item in mutations if str(item["status"]).lower() == "survived"]
    removals = load(directory / "genotoxic-necessist.json") if necessist else []
    removals = [item for item in removals if item["status"] == "passed_after_removal"]
    records: dict[str, Any] = {}
    for source, prefix, items in (("mutation", "m", mutations), ("necessist", "n", removals)):
        for index, item in enumerate(items):
            filename = item["file_path"] if prefix == "m" else item["test_file_path"]
            line = item["line"] if prefix == "m" else item["test_line"]
            if not filename or not isinstance(line, int) or isinstance(line, bool) or line <= 0:
                fail("A selected finding lacks a valid source file and positive line number.")
            signal = item.get("mutation_type", item.get("mutatorName", ""))
            change = f"{item.get('original', '')} -> {item.get('replacement', '')}"
            signal = f"{signal}: {change}" if prefix == "m" else item["removed_statement"]
            records[f"{prefix}:{index}"] = item | {
                "file_path": filename,
                "line": line,
                "source": source,
                "signal": signal,
            }
    return {"graph": graph, "analysis": analysis, "records": records}


def table(headers: str, rows: list[list[Any]]) -> str:
    def cell(value: Any) -> str:
        text = "Unknown" if value is None else str(value)
        return text.replace("|", "\\|").replace("\r", " ").replace("\n", "<br>")

    rule = "|" + "|".join("---" for _ in headers.split("|")) + "|"
    body = ["| " + " | ".join(cell(value) for value in row) + " |" for row in rows]
    return "\n".join(["| " + headers + " |", rule, *body])


@step
def render(review: Review, evidence: dict[str, Any]) -> str:
    records, nodes = evidence["records"], evidence["graph"]["nodes"]
    ids = [item.evidence_id for item in review.findings]
    if len(ids) != len(set(ids)) or set(ids) != set(records):
        fail("Triage must cover every captured survivor and removal exactly once.")
    by_node: dict[str, list[Finding]] = {}
    rows: dict[str, list[list[Any]]] = {
        "false_positive": [],
        "missing_tests": [],
        "fuzzing_target": [],
        "needs_manual_review": [],
    }
    for item in review.findings:
        record = records[item.evidence_id]
        if not item.reason.strip() or (item.node_id and item.node_id not in nodes):
            fail("A disposition lacks a justification or references an unknown graph node.")
        if (
            record["source"] == "mutation"
            and not item.node_id
            and item.bucket != "needs_manual_review"
        ):
            fail("An unmapped production mutation requires explicit manual review.")
        actionable = item.bucket in ("missing_tests", "fuzzing_target")
        if actionable and (not item.node_id or not item.function.strip()):
            fail("Actionable findings require a production function binding.")
        if actionable:
            by_node.setdefault(item.node_id, []).append(item)
        if item.bucket == "missing_tests" and not item.suggested_test.strip():
            fail("A missing-test finding has no suggested test strategy.")
        if item.bucket == "fuzzing_target" and not item.blast_radius.strip():
            fail("A fuzzing target has no blast-radius context.")
    corroborated = {
        node: items
        for node, items in by_node.items()
        if {records[item.evidence_id]["source"] for item in items} == {"mutation", "necessist"}
    }
    corroborated_ids = {item.evidence_id for items in corroborated.values() for item in items}
    for item in review.findings:
        record = records[item.evidence_id]
        source = "corroborated" if item.evidence_id in corroborated_ids else record["source"]
        location = [record["file_path"], record["line"]]
        paths = "; ".join(item.entrypoint_paths) or "No observed entrypoint path"
        tails = {
            "false_positive": [record["signal"], item.reason, source],
            "missing_tests": [
                item.function,
                item.cc,
                item.callers,
                item.suggested_test + "; " + item.reason,
                source,
            ],
            "fuzzing_target": [
                item.function,
                item.cc,
                paths,
                item.blast_radius + "; " + item.reason,
                source,
            ],
            "needs_manual_review": [record["signal"], item.reason, source],
        }
        rows[item.bucket].append(location + tails[item.bucket])

    def signals(items: list[Finding], source: str) -> str:
        selected = [records[item.evidence_id] for item in items]
        return "; ".join(record["signal"] for record in selected if record["source"] == source)

    cor_rows = [
        [
            nodes[node]["location"]["file_path"],
            nodes[node]["location"]["start_line"],
            nodes[node].get("name", ""),
            signals(items, "mutation"),
            signals(items, "necessist"),
            "; ".join(item.suggested_test or item.reason for item in items),
        ]
        for node, items in corroborated.items()
    ]
    summary = [
        f"- Total survived mutants: {sum(r['source'] == 'mutation' for r in records.values())}",
        f"- Total necessist removals: {sum(r['source'] == 'necessist' for r in records.values())}",
        f"- Corroborated findings: {len(corroborated)} functions",
        f"- Inspected source files: {evidence['analysis']['source_file_count']}",
    ]
    sections = [
        ("False Positives", "false_positive", "File | Line | Mutation | Reason | Source"),
        (
            "Missing Test Coverage",
            "missing_tests",
            "File | Line | Function | CC | Callers | Suggested Test | Source",
        ),
        (
            "Fuzzing Targets",
            "fuzzing_target",
            "File | Line | Function | CC | Entrypoint Path | Blast Radius | Source",
        ),
        ("Needs Manual Review", "needs_manual_review", "File | Line | Signal | Reason | Source"),
    ]
    for title, bucket, _headers in sections:
        count = len(rows[bucket])
        summary.append(f"- {title}: {count} ({100 * count / (len(records) or 1):.1f}%)")
    parts = [
        "# Genotoxic Triage Report",
        "## Summary\n\n" + "\n".join(summary),
        "Percentages count individual findings; corroboration groups production functions.",
        f"Necessist: {review.necessist_status}.\n\n{review.notes}",
        "## Corroborated Findings\n\n"
        + table("File | Line | Function | Mutation Signal | Necessist Signal | Action", cor_rows),
    ]
    for title, bucket, headers in sections:
        parts.append(f"## {title}\n\n{table(headers, rows[bucket])}")
    return "\n\n".join(parts) + "\n"


@recipe(
    version="1",
    agents=("worker",),
    output_root=".",
    budget=Budget(max_agent_calls=2, max_wall_seconds=3600),
)
def genotoxic(request: str = "Analyze the complete working directory.") -> str:
    root = Path.cwd().resolve()
    files = (
        "GENOTOXIC_REPORT.md",
        "genotoxic-graph.json",
        "genotoxic-preanalysis.json",
        "genotoxic-mutations.json",
        "genotoxic-necessist.json",
        "genotoxic-mutation.log",
        "genotoxic-necessist.log",
    )
    directory = ensure_directory(".", output_files=files)
    references = tuple(
        resource(name)
        for name in (
            "references/graph-analysis.md",
            "references/mutation-frameworks.md",
            "references/triage-methodology.md",
        )
    )
    context = prepare_context(
        f"Request: {request}\nProject: {root}\nEvidence directory: {directory}\n"
        "Follow the entire Genotoxic workflow and complete references in one session. "
        "Retain phase ordering, preanalysis, installation policy, scope, and graph caveats. "
        "Python renders the report; preserve tool evidence in these fixed files:\n"
        "genotoxic-graph.json: full engine.to_json() export. genotoxic-preanalysis.json: "
        "source_file_count (actual inspected count), trailmark_version, parse_diagnostics, "
        "call_resolution_gaps, preanalysis (complete actual engine.preanalysis() result).\n"
        "genotoxic-mutations.json: native Elements JSON (elements), or universal records "
        "from an executed parser (universal) with file_path, line, mutation_type, original, "
        "replacement, function_name, status. Keep all statuses and complete actual outputs "
        "and native exports in genotoxic-mutation.log, without model reconstruction.\n"
        "When supported run necessist; genotoxic-necessist.json has test_file_path, test_line, "
        "removed_statement, test_function, status, source; retain genotoxic-necessist.log.\n"
        "IDs m:0, m:1, etc. index survived mutations; n:0, n:1, etc. index "
        "passed_after_removal records. Elements files sort by filename; preserve other order. "
        "Return one Finding per selected record with full graph context and suggested actions. "
        "Bind mutations to smallest containing nodes; unmapped mutations need manual review. "
        "Interpret removal mappings and uncertainty. Empty paths never prove unreachability. "
        "Notes explain framework execution, necessist applicability, and limitations. "
        "Return a nonempty blocker on failure; never manufacture evidence.",
        files=references,
        readable_roots=references,
    )
    review = agent(
        "worker",
        "Complete the assignment using the authoritative skill and full references.",
        working_directory=root,
        readable_paths=(root, directory, *references),
        writable_paths=(root, directory),
        required_capabilities=("commands",),
        output=Review,
        timeout=3600,
        context=context,
    )
    if review.blocker.strip() or not review.notes.strip():
        fail(review.blocker or "Execution and applicability notes are required.")
    required_files = files[1:4] + ("genotoxic-mutation.log",)
    if review.necessist_status == "completed":
        required_files += ("genotoxic-necessist.json", "genotoxic-necessist.log")
    for filename in required_files:
        verify_artifact(directory / filename)
    evidence = collect(directory, review.mutation_format, review.necessist_status == "completed")
    report = render(review, evidence)
    destination = write_text(directory / "GENOTOXIC_REPORT.md", report)
    emit(str(destination), name="report-file")
    return emit(report, name="report")


if __name__ == "__main__":
    raise SystemExit(genotoxic.cli())


# --- calcifier metadata (skill provenance + sha256) ---
_CALCIFIER_COMPILATION = "compiled"
_CALCIFIER_SKILL = {
    "path": "../SKILL.md",
    "sha256": ("b93c04de9da3e21f91b8b10bdf9750aa1d111918a3dba793f677cbd7823420f1"),
}
_CALCIFIER_RESOURCES = [
    {
        "path": "agents/code-slice-worker.md",
        "sha256": ("6b427cf3aa5caf357cd0fb18eca324b4207706bcd7e79eaff157590cd5816cb7"),
        "size": 1912,
        "source": "../../agents/code-slice-worker.md",
    },
    {
        "path": "references/graph-analysis.md",
        "sha256": ("356f25ff8f4cb85b0bbc3d900a2630bd4970be425a076dd96cd5352d6783431c"),
        "size": 13759,
        "source": None,
    },
    {
        "path": "references/mutation-frameworks.md",
        "sha256": ("87b17aad65a9a9b1e337e67131c9d288239ca7f7254778b9a4890428d8cef0cd"),
        "size": 28786,
        "source": None,
    },
    {
        "path": "references/triage-methodology.md",
        "sha256": ("16291b0de766c6cdcef03402dbb5e74ab264cbbe40e6d69f96cfc93b07c84b87"),
        "size": 12256,
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
