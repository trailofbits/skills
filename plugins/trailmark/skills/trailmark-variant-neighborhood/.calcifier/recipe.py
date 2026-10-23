# /// script
# requires-python = ">=3.13"
# dependencies = ["calcifier==0.2.0"]
# ///

"""Prepare a complete graph review scope and render the worker's neighborhood analysis."""

import json
from collections import Counter
from collections.abc import Iterable
from pathlib import Path
from typing import Literal, get_args

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
    write_json,
    write_text,
)

Dimension = Literal[
    "Shared Callers",
    "Shared Callees / Sinks",
    "Entrypoint Path Neighbors",
    "Interface Or Implementation Siblings",
    "File / Module Cluster Neighbors",
    "Taint / Boundary Peers",
    "Type / State Neighbors",
]
Followup = Literal["variant-analysis", "semgrep-rule-creator", "static-analysis", "manual review"]


@output_type
class Candidate:
    node_id: str
    file: str
    line: int
    dimensions: list[Dimension]
    rank: Literal["High", "Medium", "Low", "Excluded"]
    confidence: Literal["High", "Medium", "Low"]
    graph_reason: str
    root_cause_similarity: str
    reachability: str
    trust: str
    taint: str
    privilege_boundary: str
    distance: int | None
    shared_relationship: str
    exclusion_or_penalty: str


@output_type
class Handoff:
    followups: list[Followup]
    keep_specific: list[str]
    abstract: list[str]
    suggested_searches: list[str]
    positive_examples: list[str]
    negative_examples: list[str]
    codeql_semgrep_direction: str
    static_analysis_query: str
    sarif_expectation: str


@output_type
class Neighborhood:
    status: Literal["complete", "stopped"]
    message: str
    finding: str
    bound_node: str
    seed_file: str
    seed_line: int
    root_cause: str
    surviving_first_pass_count: int
    language: str
    trailmark_version: str
    source_file_coverage: list[str]
    parse_diagnostics: list[str]
    unresolved_call_gaps: list[str]
    inspected_node_ids: list[str]
    limitations: list[str]
    candidates: list[Candidate]
    handoff: Handoff
    exclusions: list[str]


def cell(value: str) -> str:
    return value.replace("|", "\\|").replace("\r", " ").replace("\n", "<br>")


def bullets(values: Iterable[str]) -> str:
    return "\n".join("- " + value for value in values) or "- None reported."


def render(report: Neighborhood) -> str:
    parts = [
        "# Trailmark Variant Neighborhood\n\n## Seed\n\n"
        f"- Finding: {report.finding}\n- Bound node: {report.bound_node}\n"
        f"- Location: {report.seed_file}:{report.seed_line}\n"
        f"- Root cause: {report.root_cause}\n- Status: {report.status}: {report.message}\n"
        f"- Language: {report.language}\n- Trailmark: {report.trailmark_version}\n"
        "\n## Candidate Summary\n\n"
        "| Rank | Candidate | Reason | Reachability | Confidence |\n"
        "|---|---|---|---|---|\n"
    ]
    for item in report.candidates:
        location = f"{item.node_id} ({item.file}:{item.line})"
        reason = f"Graph: {item.graph_reason}; root cause: {item.root_cause_similarity}"
        columns = [item.rank, location, reason, item.reachability, item.confidence]
        parts.append("| " + " | ".join(cell(value) for value in columns) + " |\n")
    if not report.candidates:
        parts.append("\nNo candidate review targets were retained.\n")
    parts.append("\n## Graph Neighborhoods\n")
    for dimension in get_args(Dimension):
        parts.append(f"\n### {dimension}\n\n")
        matching = [item for item in report.candidates if dimension in item.dimensions]
        if not matching:
            parts.append("No retained review targets in this dimension.\n")
        for item in matching:
            parts.append(f"- {item.node_id} — {item.file}:{item.line}\n")
            parts.extend(
                f"  - {key.replace('_', ' ')}: {value}\n"
                for key, value in item.model_dump().items()
            )
    parts.append(f"\n## Variant-Analysis Handoff\n\n- Root cause: {report.root_cause}\n")
    for label, value in report.handoff.model_dump().items():
        body = bullets(value) if isinstance(value, list) else str(value)
        parts.append(f"\n### {label.replace('_', ' ')}\n\n{body}\n")
    useful = sorted(
        {
            dimension
            for item in report.candidates
            for dimension in item.dimensions
            if item.rank != "Excluded"
        }
    )
    parts.append("\nUseful graph dimensions: " + ", ".join(useful) + "\n")
    parts.append(
        "\nCandidate files and functions are listed above.\n\n## Exclusions And Limitations\n"
        f"\n{bullets(report.exclusions)}\n\n{bullets(report.limitations)}\n"
    )
    for label, values in (
        ("Source-file coverage", report.source_file_coverage),
        ("Parse diagnostics", report.parse_diagnostics),
        ("Unresolved-call gaps", report.unresolved_call_gaps),
    ):
        parts.append(f"\n### {label}\n\n{bullets(values)}\n")
    return "".join(parts)


@recipe(
    version="1",
    agents=("worker",),
    budget=Budget(max_agent_calls=2, max_wall_seconds=3600),
    output_root="trailmark-variant-neighborhood",
)
def variant_neighborhood(
    project_directory: str,
    seed: str,
    output_format: Literal["markdown", "json"] = "markdown",
    include_nonproduction: bool = False,
    dimension_limit: int = 10,
    language_hint: str = "",
) -> Neighborhood:
    root = Path(project_directory).expanduser().resolve()
    if not root.is_dir() or not seed.strip() or dimension_limit < 1:
        fail("Supply a project directory, a concrete seed issue, and a positive dimension limit.")
    inventory = sorted(
        path.relative_to(root).as_posix()
        for path in root.rglob("*")
        if ".git" not in path.relative_to(root).parts
        and path.is_file()
        and path.resolve().is_relative_to(root)
    )
    if not inventory:
        fail("The inspection scope contains zero files; no graph analysis can be reported.")
    filename = "handoff.md" if output_format == "markdown" else "handoff.json"
    ensure_directory(output_files=(filename,))
    references = (
        resource("references/neighborhood-patterns.md"),
        resource("references/ranking.md"),
        resource("references/output-format.md"),
    )
    task = json.dumps(
        {
            "seed": seed,
            "language_hint": language_hint,
            "include_test_mock_generated_vendor": include_nonproduction,
            "top_candidates_per_dimension": dimension_limit,
            "requested_output_format": output_format,
        },
        ensure_ascii=False,
    )
    context = prepare_context(
        task,
        files=references,
        readable_roots=references,
        prior_results=json.dumps({"complete_project_file_inventory": inventory}),
    )
    report = agent(
        "worker",
        "Execute the complete authoritative skill workflow in one session using full references. "
        "Use embedded context directly; read backing text if absent. Inventory is scope data, "
        "not a semantic screen. Discover installed Trailmark registry/API/CLI with commands. "
        "Work without writes; if unavailable return stopped and explain required configuration. "
        "Return source-relative locations, actual inspected node IDs and all evidence fields, "
        "including unknowns. Count first-pass survivors before per-dimension truncation; "
        "stop above 50 and request a narrower root cause. Keep interpretation, ranking, checks "
        "and follow-up selection together, preserving original stop conditions and limits. "
        "Provide supported examples and required guidance; report only work actually performed.",
        context=context,
        working_directory=root,
        readable_paths=(root, *references),
        required_capabilities=("commands",),
        output=Neighborhood,
        timeout=3600,
    )
    report.finding = seed
    emit(report, name="neighborhood")
    if report.status == "stopped":
        fail(report.message or "Neighborhood analysis stopped before completion.")
    if not report.bound_node.strip() or report.bound_node not in report.inspected_node_ids:
        fail("A completed inspection must contain the concretely bound seed among inspected nodes.")
    if report.seed_file not in inventory or report.seed_line < 1 or not report.root_cause.strip():
        fail("The completed seed requires an in-scope source location and a stated root cause.")
    if not report.source_file_coverage or not report.language or not report.trailmark_version:
        fail("A complete result must retain language, Trailmark version and source coverage.")
    included = [item for item in report.candidates if item.rank != "Excluded"]
    if report.surviving_first_pass_count > 50 or len(included) > 50:
        fail("More than 50 candidates survive; ask for a narrower root cause.")
    if report.surviving_first_pass_count < len(included):
        fail("First-pass survivors cannot be fewer than retained candidates.")
    counts = Counter(dimension for item in included for dimension in set(item.dimensions))
    if any(count > dimension_limit for count in counts.values()):
        fail("The returned neighborhood exceeds the requested per-dimension bound.")
    ids = [item.node_id for item in report.candidates]
    if len(ids) != len(set(ids)) or any(
        not item.node_id or not item.dimensions for item in report.candidates
    ):
        fail("Candidates must be unique nodes with explicit neighborhood dimensions.")
    if any(item.file not in inventory or item.line < 1 for item in included):
        fail("An included candidate has no valid in-scope source location.")
    if not report.handoff.followups:
        fail("The handoff must recommend a follow-up workflow.")
    if any(
        name in report.handoff.followups
        for name in (
            "variant-analysis",
            "semgrep-rule-creator",
        )
    ) and (not report.handoff.positive_examples or not report.handoff.negative_examples):
        fail("The selected follow-up requires supported positive and negative examples.")
    order = {"High": 0, "Medium": 1, "Low": 2, "Excluded": 3}
    report.candidates.sort(key=lambda item: order[item.rank])
    if output_format == "markdown":
        text = render(report)
        path = write_text(filename, text)
        emit(text, name="handoff")
    else:
        path = write_json(filename, report.model_dump())
    emit(str(path), name="handoff-file")
    return report


if __name__ == "__main__":
    raise SystemExit(variant_neighborhood.cli())


# --- calcifier metadata (skill provenance + sha256) ---
_CALCIFIER_COMPILATION = "compiled"
_CALCIFIER_SKILL = {
    "path": "../SKILL.md",
    "sha256": ("7bb560a46c8ab80021930ff6f7fa2b2d2e9f9cd66ba2981123b8d227c724e07c"),
}
_CALCIFIER_RESOURCES = [
    {
        "path": "agents/code-slice-worker.md",
        "sha256": ("6b427cf3aa5caf357cd0fb18eca324b4207706bcd7e79eaff157590cd5816cb7"),
        "size": 1912,
        "source": "../../agents/code-slice-worker.md",
    },
    {
        "path": "references/neighborhood-patterns.md",
        "sha256": ("602d25c031a1e54f188d986954d0a4632017a8bef97fd1f5f88f62491589c40f"),
        "size": 2785,
        "source": None,
    },
    {
        "path": "references/output-format.md",
        "sha256": ("f2381c0728c7273fafaaac1882c601491e9850c238e44b60d5106fb3459bf614"),
        "size": 1469,
        "source": None,
    },
    {
        "path": "references/ranking.md",
        "sha256": ("ed0a957618e25cb77e6003a44351884ba73351b9eb2bab2b0ff5ff6b1661a57f"),
        "size": 1628,
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
