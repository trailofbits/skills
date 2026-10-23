# /// script
# requires-python = ">=3.13"
# dependencies = ["calcifier==0.2.0"]
# ///

import json
import re
from pathlib import Path
from typing import Literal

from calcifier import (
    Budget,
    agent,
    emit,
    fail,
    output_type,
    prepare_context,
    recipe,
    resource,
    run_command,
    step,
)


@output_type
class Candidate:
    title: str
    source_type: Literal["manual", "sarif", "weaudit", "report", "function"]
    file: str | None
    line_range: tuple[int, int] | None
    function_hint: str
    suspected_source: str
    suspected_sink: str
    suspected_asset: str
    claimed_impact: str


@output_type
class ReviewTarget:
    target: str
    why_it_matters: str


@output_type
class GraphEvidence:
    bound_node: str | None
    binding: str
    matches: list[str]
    entrypoint_reachable: str
    entry_paths: list[str]
    tainted: str
    privilege_boundary: str
    blast_radius: str
    direct_callers: list[str]
    direct_callees: list[str]
    relevant_sinks: list[str]
    nearby_nodes: list[str]
    evidence_sources: list[str]


@output_type
class EvidencePacket:
    status: Literal["Promote", "Needs manual review", "Deprioritize", "Blocked"]
    confidence: Literal["High", "Medium", "Low"]
    candidate: Candidate
    graph: GraphEvidence
    manual_review_targets: list[ReviewTarget]
    limitations: list[str]
    recommended_next_step: str


@output_type
class Observations:
    anchor: str
    existing_artifacts: list[str]
    exit_code: int | None
    stdout: str
    stderr: str
    note: str


@step
def collect(target: str, anchor: str, language: str, path_base: str, manual: bool) -> Observations:
    root = Path(target)
    names = (".trailmark", "trailmark.json", "graph.json", "trailmark-graph.json")
    artifacts = [str(root / name) for name in names if (root / name).exists()]
    if manual or artifacts or not anchor:
        return Observations(
            anchor,
            artifacts,
            None,
            "",
            "",
            "Bundled helper not run. Inspect available artifacts and use the manual route.",
        )
    argv = [
        "uv",
        "run",
        "--no-project",
        str(resource("scripts/evidence_packet.py")),
        "--target",
        target,
        "--finding=" + anchor,
        "--language=" + language,
        "--path-base=" + path_base,
    ]
    try:
        result = run_command(argv, timeout_seconds=600, working_directory=root, mutating=False)
    except Exception as error:
        if getattr(error, "command_failure", None) not in ("launch", "timeout"):
            raise
        return Observations(anchor, artifacts, None, "", str(error), "Helper failed.")
    if result.exit_code == 0:
        try:
            data = json.loads(result.stdout)
        except ValueError:
            fail("The evidence helper returned invalid JSON; no evidence was accepted.")
        if not isinstance(data, dict) or not isinstance(data.get("graph"), dict):
            fail("The evidence helper returned no usable graph record.")
        if data["graph"].get("nodes", 0) <= 0:
            fail("The graph contains zero nodes; graph inspection cannot be completed.")
        findings = data.get("findings")
        if not isinstance(findings, list) or len(findings) != 1:
            fail("Expected exactly one inspected finding in the helper output.")
        emit(data, name="bundled-evidence")
    return Observations(
        anchor,
        artifacts,
        result.exit_code,
        result.stdout,
        result.stderr,
        "Complete helper output follows; it supplies observations, not a verdict.",
    )


def table_cell(value: str) -> str:
    return value.replace("|", "\\|").replace("\n", "<br>")


@step
def render(packet: EvidencePacket) -> str:
    candidate = packet.candidate.model_dump()
    candidate["bound_node"] = packet.graph.bound_node
    lines = [
        f"# Trailmark Finding Triage: {packet.candidate.title}",
        "",
        "## Verdict",
        "",
        f"Status: {packet.status}",
        f"Confidence: {packet.confidence}",
    ]
    for heading, record in (
        ("Candidate", candidate),
        ("Graph Evidence", packet.graph.model_dump()),
    ):
        lines.extend(["", f"## {heading}", ""])
        for key, value in record.items():
            label = key.replace("_", " ").capitalize()
            text = value if isinstance(value, str) else json.dumps(value, ensure_ascii=False)
            lines.append(f"- {label}: {text}")
    lines.extend(
        [
            "",
            "## Manual Review Targets",
            "",
            "| Target | Why it matters |",
            "|---|---|",
        ]
    )
    for item in packet.manual_review_targets:
        lines.append(f"| {table_cell(item.target)} | {table_cell(item.why_it_matters)} |")
    lines.extend(
        [
            "",
            "## Limitations",
            "",
            *("- " + item for item in packet.limitations),
            "",
            "## Recommended Next Step",
            "",
            packet.recommended_next_step,
        ]
    )
    return "\n".join(lines)


@recipe(
    version="1",
    agents=("worker",),
    capabilities=("Bash",),
    budget=Budget(max_agent_calls=2, max_wall_seconds=3600),
)
def trailmark_finding_triage(
    target_directory: str,
    candidate: str,
    anchor: str = "",
    language: str = "auto",
    path_base: Literal["auto", "target", "cwd"] = "auto",
    analysis_mode: Literal["auto", "manual"] = "auto",
    graph_export: str = "",
    output_format: Literal["markdown", "json"] = "markdown",
) -> EvidencePacket:
    root = Path(target_directory).expanduser().resolve()
    if not root.is_dir():
        fail("Target must be an existing project directory.")
    if not candidate.strip() and not anchor.strip():
        fail("Provide one candidate finding with a concrete file, line, function, or symbol.")
    if not any(
        path.is_file() for path in root.rglob("*") if ".git" not in path.relative_to(root).parts
    ):
        fail("The inspection scope contains zero files; provide a nonempty target project.")
    pattern = r".+?:[1-9]\d*(?:-[1-9]\d*)?"
    selected = anchor.strip()
    if selected and re.fullmatch(pattern, selected) is None:
        fail("The explicit anchor must be FILE:LINE or FILE:START-END with positive lines.")
    if not selected and re.fullmatch(pattern, candidate.strip()):
        selected = candidate.strip()
    extra_paths: tuple[Path, ...] = ()
    if graph_export:
        exported = (root / Path(graph_export).expanduser()).resolve()
        if not exported.is_file():
            fail("The supplied graph export must be an existing regular file.")
        extra_paths = (exported,)
    observations = collect(
        str(root),
        selected,
        language,
        path_base,
        analysis_mode == "manual" or bool(extra_paths),
    )
    files = tuple(
        resource(name)
        for name in (
            "references/input-normalization.md",
            "references/query-recipes.md",
            "references/output-format.md",
            "scripts/evidence_packet.py",
        )
    )
    task = json.dumps(
        {
            "request": candidate,
            "explicit_anchor": anchor,
            "target": str(root),
            "language": language,
            "path_base": path_base,
            "analysis_mode": analysis_mode,
            "graph_export": str(extra_paths[0]) if extra_paths else None,
        },
        ensure_ascii=False,
    )
    context = prepare_context(
        task,
        prior_results=observations.model_dump_json(),
        files=files,
        readable_roots=files,
    )
    packet = agent(
        "worker",
        "Perform the source skill's complete connected triage workflow for this one request. "
        "The attached helper output and artifact paths are mechanical observations only. "
        "Normalize the request before using them; they do not complete interpretation. "
        "Use complete embedded context directly, reading task.txt and attachments when absent. "
        "Understand the complete references. Artifact names are not an exhaustive search. "
        "Assess graph freshness and prefer suitable existing evidence. Use commands for the "
        "manual API route, missing queries, or newer language/storage/diagnostic requirements; "
        "the bundled helper remains on 0.5.x. Inspect bound code and callers. Preserve actual "
        "versions, every matching node, trust classifications, direct entrypoint membership, "
        "path bounds, and evidence limitations. Apply all original reasoning and checks in "
        "their stated order. Stop and request an anchor when required; honor scope handoffs. "
        "Return the final packet using the declared fields, with explicit unknown or "
        "unavailable evidence rather than omitted required explanations. Keep reasoning "
        "internal. Evidence sources identifies versions, probes, coverage and resolution "
        "evidence; limitations preserves their uncertainty. Follow the original verdict, "
        "confidence, wording and handoff requirements. Do not modify the target. If analysis "
        "cannot be performed, report Blocked with the concrete reason and next step.",
        working_directory=root,
        readable_paths=(root, *files, *extra_paths),
        required_capabilities=("commands",),
        output=EvidencePacket,
        timeout=3600,
        context=context,
    )
    required = [
        packet.candidate.title,
        packet.graph.binding,
        packet.graph.entrypoint_reachable,
        packet.graph.tainted,
        packet.graph.privilege_boundary,
        packet.graph.blast_radius,
        packet.recommended_next_step,
    ]
    if any(not value.strip() for value in required):
        fail("The triage packet omitted a required result or explanation.")
    emit(packet, name="evidence-packet")
    if output_format == "markdown":
        emit(render(packet), name="report")
    return packet


if __name__ == "__main__":
    raise SystemExit(trailmark_finding_triage.cli())


# --- calcifier metadata (skill provenance + sha256) ---
_CALCIFIER_COMPILATION = "compiled"
_CALCIFIER_SKILL = {
    "path": "../SKILL.md",
    "sha256": ("b36defaaf94bed1150806cb5c2265e51b41e1474b2d03304367dedd8ffb208c5"),
}
_CALCIFIER_RESOURCES = [
    {
        "path": "agents/code-slice-worker.md",
        "sha256": ("6b427cf3aa5caf357cd0fb18eca324b4207706bcd7e79eaff157590cd5816cb7"),
        "size": 1912,
        "source": "../../agents/code-slice-worker.md",
    },
    {
        "path": "references/input-normalization.md",
        "sha256": ("12ff637d5817f93db5c1b29f2ae6e0789cbf720e3c537576f4be035a02bca99c"),
        "size": 1842,
        "source": None,
    },
    {
        "path": "references/output-format.md",
        "sha256": ("69deec7c2510445db418ec9f05a8c29eaee35d6bb94041167814b13b1c85a35d"),
        "size": 1756,
        "source": None,
    },
    {
        "path": "references/query-recipes.md",
        "sha256": ("3e8080b078c04a01b8ad0b54cc7f5a254e12681a0d9d932a2634e789b87682ca"),
        "size": 3551,
        "source": None,
    },
    {
        "path": "scripts/evidence_packet.py",
        "sha256": ("7dbd5cbd10bc34154468f6d9d25941c4b8d7b4612e967beb0d64b7241b3d8c70"),
        "size": 10476,
        "source": None,
    },
    {
        "path": "scripts/test_evidence_packet.py",
        "sha256": ("5f268588bf83fcaab7e6ab67fb2089ed38db61e92efeef87e4c8fbc4bdaf9f89"),
        "size": 10521,
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
