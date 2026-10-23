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
    ensure_directory,
    fail,
    output_type,
    prepare_context,
    recipe,
    resource,
    run_command,
    step,
    verify_artifact,
    write_json,
    write_text,
)

PATTERNS = {
    "upgrades": r"proxy|delegatecall|upgrade|initializer|implementation",
    "tokens": r"ERC\d+|transfer|balanceOf|allowance|approve",
    "privacy": r"private|secret|commit|reveal",
    "ordering": r"slippage|minOut|deadline|price|order|swap",
    "cryptography": r"random|block\.timestamp|blockhash|ecrecover|keccak|sha256",
    "defi": r"oracle|flash|price|swap|lend|borrow|\.call|delegatecall",
}


@output_type
class Section:
    status: Literal["complete", "partial", "blocked"]
    details: str


@output_type
class Diagram:
    status: Literal["generated", "blocked"]
    analysis: str


@output_type
class Review:
    step1: Section
    step2: Section
    step3: Section
    step4: Section
    step5: Section
    inheritance: Diagram
    functions: Diagram
    authorization: Diagram
    action_plan: str


@output_type
class Preparation:
    source_files: list[str]
    search_observations: dict[str, list[str]]
    scan_exit_code: int | None
    scan_stdout: str
    scan_stderr: str
    command_blocker: str
    detector_counts: dict[str, int]
    parsing_observation: str


@step
def prepare_project(project_directory: str) -> Preparation:
    root = Path(project_directory).resolve()
    if not root.is_dir():
        fail("The project directory does not exist or is not a directory.")
    sources = sorted(
        path
        for path in root.rglob("*")
        if path.suffix.lower() in (".sol", ".vy")
        and ".git" not in path.relative_to(root).parts
        and path.is_file()
    )
    if not sources:
        fail("Empty inspection scope: no Solidity or Vyper source files were found.")
    observations: dict[str, list[str]] = {name: [] for name in PATTERNS}
    for path in sources:
        if not path.resolve().is_relative_to(root):
            fail(f"Source file escapes the authorized project: {path}")
        text = path.read_text(encoding="utf-8")
        for number, line in enumerate(text.splitlines(), 1):
            for name, pattern in PATTERNS.items():
                if re.search(pattern, line, re.IGNORECASE):
                    observations[name].append(f"{path.relative_to(root)}:{number}: {line}")
    code = None
    stdout = ""
    stderr = ""
    blocker = ""
    try:
        result = run_command(
            ["slither", ".", "--exclude-dependencies", "--json", "-"],
            timeout_seconds=300,
            working_directory=root,
            mutating=True,
        )
        code, stdout, stderr = result.exit_code, result.stdout, result.stderr
    except Exception as error:
        if getattr(error, "command_failure", None) not in ("launch", "timeout"):
            raise
        blocker = str(error)
    counts: dict[str, int] = {}
    observation = "No detector JSON parsed; this does not establish a clean scan."
    try:
        payload = json.loads(stdout)
        if isinstance(payload, dict) and isinstance(payload.get("results"), dict):
            detectors = payload["results"].get("detectors")
            if isinstance(detectors, list):
                for detector in detectors:
                    if isinstance(detector, dict):
                        impact = str(detector.get("impact", "Unknown"))
                        counts[impact] = counts.get(impact, 0) + 1
                observation = "Counts summarize detector records, not validated security findings."
    except json.JSONDecodeError:
        pass
    return Preparation(
        [str(path) for path in sources],
        observations,
        code,
        stdout,
        stderr,
        blocker,
        counts,
        observation,
    )


def render_report(review: Review, project: Path, destination: Path) -> str:
    phases = (
        ("Known security issues", review.step1),
        ("Special features", review.step2),
        ("Visual security inspection", review.step3),
        ("Security properties and testing", review.step4),
        ("Manual review areas", review.step5),
    )
    lines = ["# Secure Development Workflow Report", f"Project: {project}", ""]
    for number, (title, section) in enumerate(phases, 1):
        lines.extend(
            [
                f"## Step {number}: {title}",
                f"Status: {section.status}",
                "",
                section.details,
                "",
            ]
        )
        if number == 3:
            for slug, diagram in (
                ("inheritance", review.inheritance),
                ("functions", review.functions),
                ("authorization", review.authorization),
            ):
                lines.extend([f"### {slug.title()}", diagram.analysis, ""])
                if diagram.status == "generated":
                    lines.extend([f"Diagram: {destination / (slug + '.png')}", ""])
    lines.extend(["## Action plan", review.action_plan, "", "## Workflow checklist", ""])
    for number, (title, section) in enumerate(phases, 1):
        mark = "x" if section.status == "complete" else " "
        lines.append(f"- [{mark}] Step {number}: {title} ({section.status})")
    return "\n".join(lines) + "\n"


@recipe(
    name="secure_workflow_guide",
    version="1.0",
    agents=("worker",),
    capabilities=("Bash",),
    budget=Budget(max_agent_calls=2, max_wall_seconds=3600),
    output_root="secure-workflow-review",
)
def secure_workflow_guide(project_directory: str, request: str = "") -> Review:
    root = Path(project_directory).resolve()
    planned = ("report.md", "report.json", "preparation.json") + tuple(
        f"{slug}.{extension}"
        for slug in ("inheritance", "functions", "authorization")
        for extension in ("png", "dot", "txt")
    )
    destination = ensure_directory(".", output_files=planned)
    prepared = prepare_project(project_directory)
    write_json("preparation.json", prepared.model_dump())
    references = (
        resource("resources/WORKFLOW_STEPS.md"),
        resource("resources/EXAMPLE_REPORT.md"),
    )
    assignment = (
        "Complete the source skill's entire connected security workflow in one session, "
        "preserving its order, reasoning, checks, and required outputs. The inventory, "
        "search observations, and initial Slither execution are mechanical preparation; "
        "they do not complete interpretation or triage. Understand the full project and "
        "finish Step 1 before proceeding through the remaining source-defined steps. "
        "Search matches are observations, never exhaustive semantic candidates or proof "
        "that a feature is absent. Use the complete embedded context directly; read its "
        "backing files when contents are absent or a file check is needed. "
        "Use execution for applicability-dependent checks, the actual Slither print "
        "commands, testing infrastructure, and campaigns. If Slither is unavailable, "
        "attempt project-local installation when feasible or document the exact blocker. "
        "Keep installations and project changes inside the writable project. Do not commit. "
        "Do not replace required testing setup with recommendations for later. Distinguish "
        "properties documented, infrastructure implemented, checks executed, and blockers. "
        "Return all five report sections, including severity, file:line evidence, fixes, "
        "false-positive triages, verified feature applicability, diagram interpretation, "
        "properties, testing results, manual findings, and prioritized effort estimates. "
        "Use the example for report coverage, never as evidence about this project. "
        "Generate actual PNG diagrams named inheritance.png, functions.png, and "
        "authorization.png in the output directory. Review their actual contents. "
        "DOT/text intermediates there must use the same basenames; no other intermediate "
        "output files are planned there. Project testing files belong in the project. "
        "Each diagram analysis must describe findings or its concrete blocker. A complete "
        "Step 3 requires all three diagrams. Mark incomplete or blocked work truthfully. "
        "Host file verification establishes existence only, not semantic completeness.\n"
        f"Project: {root}\nOutput directory: {destination}\nUser context: {request}"
    )
    context = prepare_context(
        assignment,
        prior_results=prepared.model_dump_json(),
        files=tuple(Path(path) for path in prepared.source_files) + references,
        readable_roots=(root, *references),
    )
    review = agent(
        "worker",
        "Execute the complete assigned workflow using the authoritative source instructions. "
        "Return the requested structured report; keep intermediate reasoning internal.",
        working_directory=root,
        readable_paths=(root, *references),
        writable_paths=(root, destination),
        required_capabilities=("commands",),
        output=Review,
        timeout=3600,
        context=context,
    )
    sections = (review.step1, review.step2, review.step3, review.step4, review.step5)
    if any(not section.details.strip() for section in sections) or not review.action_plan.strip():
        fail("The security report omitted a required section or action plan.")
    verified: list[str] = []
    for slug, diagram in (
        ("inheritance", review.inheritance),
        ("functions", review.functions),
        ("authorization", review.authorization),
    ):
        if not diagram.analysis.strip():
            fail(f"Missing diagram analysis or blocker: {slug}")
        if diagram.status == "generated":
            verified.append(str(verify_artifact(f"{slug}.png")))
        elif review.step3.status == "complete":
            fail("Visual inspection was marked complete despite a blocked diagram.")
    rendered = render_report(review, root, destination)
    write_text("report.md", rendered)
    write_json("report.json", review.model_dump())
    emit(rendered, name="security-report")
    emit(verified, name="diagrams")
    emit(str(destination / "preparation.json"), name="mechanical-observations")
    return review


if __name__ == "__main__":
    raise SystemExit(secure_workflow_guide.cli())


# --- calcifier metadata (skill provenance + sha256) ---
_CALCIFIER_COMPILATION = "compiled"
_CALCIFIER_SKILL = {
    "path": "../SKILL.md",
    "sha256": ("7c0e7fb45f97c073ec9599cbe0b2acf44f31bbece38636bc5c3fcc9bc7703015"),
}
_CALCIFIER_RESOURCES = [
    {
        "path": "resources/EXAMPLE_REPORT.md",
        "sha256": ("c55fb9e549a38c9bebc9b23f5f16fb498bd20a8f867868232623a4bd721df340"),
        "size": 7374,
        "source": None,
    },
    {
        "path": "resources/WORKFLOW_STEPS.md",
        "sha256": ("8b048011407a9a123a01ba4548b62a944f8cd5f271e4e0cdfe58b09583bd9291"),
        "size": 3058,
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
