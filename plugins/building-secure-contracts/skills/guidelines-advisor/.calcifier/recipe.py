# /// script
# requires-python = ">=3.13"
# dependencies = ["calcifier==0.2.0"]
# ///

from __future__ import annotations

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
    step,
)

SEARCHES = {
    "upgrades_and_storage": r"proxy|delegatecall|upgrade|ownable|initializ|storage|selfdestruct",
    "computation_and_calls": r"sort|loop|verify|proof|oracle|off.?chain|external|call\b",
    "access_and_ordering": r"owner|role|auth|permit|approve|nonce|commit|reveal|mempool",
    "reentrancy": r"call|transfer|send|callback|reentran|fallback|receive",
    "arithmetic": r"pragma|unchecked|SafeMath|overflow|underflow|\+\+|--",
    "oracle_time_and_state": r"oracle|price|timestamp|block\.|now\b|mapping|storage",
    "initialization": r"initializ|uninitializ|constructor|\b(let|var|uint\d*|address)\b",
    "implementation": r"function|contract|event|emit|virtual|override|assembly|inherit|impl\b",
    "dependencies": r"import|dependenc|openzeppelin|version|package|require",
    "testing": r"test|fuzz|invariant|assert|coverage|echidna|slither|foundry|workflow",
    "deployment": r"deploy|migrat|initializ|admin|upgrade|verify",
}


@output_type
class Recommendation:
    priority: Literal["CRITICAL", "HIGH", "MEDIUM", "LOW"]
    title: str
    references: list[str]
    rationale: str
    action: str
    effort: str


@output_type
class Assessment:
    project_name: str
    platform: str
    scope: str
    inspected_modules: list[str]
    documentation: str
    diagrams: str
    onchain_offchain: str
    upgradeability: str
    proxy_patterns: str
    function_composition: str
    inheritance: str
    events: str
    pitfalls: str
    dependencies: str
    testing: str
    platform_guidance: str
    recommendations: list[Recommendation]
    overall_assessment: str
    production_roadmap: str
    questions: list[str]
    limitations: str


@output_type
class Discovery:
    files: list[str]
    text_files: list[str]
    binary_files: list[str]
    matches: dict[str, list[str]]


@step
def discover(root: Path) -> Discovery:
    patterns = {name: re.compile(pattern, re.IGNORECASE) for name, pattern in SEARCHES.items()}
    matches: dict[str, list[str]] = {name: [] for name in SEARCHES}
    files: set[str] = set()
    text_files: list[str] = []
    binary_files: list[str] = []
    pending = [root]
    visited: set[Path] = set()
    while pending:
        directory = pending.pop()
        if directory in visited:
            continue
        visited.add(directory)
        for path in sorted(directory.iterdir()):
            if path.name == ".git":
                continue
            resolved = path.resolve()
            if not resolved.is_relative_to(root):
                fail(f"Project entry escapes the authorized project root: {path}")
            if resolved.is_dir():
                pending.append(resolved)
                continue
            if not resolved.is_file():
                continue
            relative = resolved.relative_to(root).as_posix()
            if relative in files:
                continue
            files.add(relative)
            try:
                text = resolved.read_text(encoding="utf-8")
            except UnicodeDecodeError:
                binary_files.append(relative)
                continue
            text_files.append(relative)
            for number, line in enumerate(text.splitlines(), 1):
                for name, pattern in patterns.items():
                    if pattern.search(line):
                        matches[name].append(f"{relative}:{number}")
    if not text_files:
        fail("Inspection scope contains no UTF-8 files; a codebase assessment cannot run.")
    return Discovery(sorted(files), sorted(text_files), sorted(binary_files), matches)


@step
def render_report(assessment: Assessment, discovery: Discovery) -> str:
    if not assessment.inspected_modules:
        fail(f"No implementation modules were inspected. Scope: {assessment.scope}")
    if any(path not in discovery.text_files for path in assessment.inspected_modules):
        fail("Reported inspected modules must name UTF-8 files in the project inventory.")
    for name, value in assessment.model_dump().items():
        if isinstance(value, str) and not value.strip():
            fail(f"Assessment omitted required content: {name}")
    for recommendation in assessment.recommendations:
        for name, value in recommendation.model_dump().items():
            if isinstance(value, str) and not value.strip():
                fail(f"Recommendation omitted required content: {name}")
        if not recommendation.references or any(
            re.search(r":\d+", reference) is None for reference in recommendation.references
        ):
            fail("Every recommendation requires project-specific file:line references.")
    sections = (
        ("Documentation & Specifications", assessment.documentation),
        ("Architectural Diagrams", assessment.diagrams),
        ("On-Chain / Off-Chain Architecture", assessment.onchain_offchain),
        ("Upgradeability", assessment.upgradeability),
        ("Delegatecall Proxy Patterns", assessment.proxy_patterns),
        ("Function Composition", assessment.function_composition),
        ("Inheritance", assessment.inheritance),
        ("Events", assessment.events),
        ("Common Pitfalls", assessment.pitfalls),
        ("Dependencies", assessment.dependencies),
        ("Testing & Verification", assessment.testing),
        ("Platform-Specific Guidance", assessment.platform_guidance),
    )
    lines = [
        f"# Development Guidelines Analysis: {assessment.project_name}",
        "",
        f"Platform: {assessment.platform}",
        "",
        assessment.scope,
        "",
        "## Inspected Implementation Modules",
        "",
    ]
    lines.extend(f"- {path}" for path in assessment.inspected_modules)
    for title, content in sections:
        lines.extend(["", f"## {title}", "", content])
    lines.extend(["", "## Prioritized Recommendations"])
    for priority in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
        lines.extend(["", f"### {priority}", ""])
        group = [item for item in assessment.recommendations if item.priority == priority]
        if not group:
            lines.append("No recommendations reported at this priority.")
        for item in group:
            lines.extend(
                [
                    f"#### {item.title}",
                    "",
                    item.rationale,
                    "",
                    item.action,
                    "",
                    f"Effort: {item.effort}",
                    "",
                    "References: " + ", ".join(item.references),
                    "",
                ]
            )
    lines.extend(
        [
            "",
            "## Overall Assessment",
            "",
            assessment.overall_assessment,
            "",
            "## Path to Production",
            "",
            assessment.production_roadmap,
            "",
            "## Design Questions",
            "",
        ]
    )
    lines.extend(
        [f"- {question}" for question in assessment.questions]
        or ["No unresolved design questions reported."]
    )
    lines.extend(["", "## Limitations", "", assessment.limitations])
    return "\n".join(lines) + "\n"


@recipe(
    name="guidelines-advisor",
    version="1",
    agents=("worker",),
    capabilities=(),
    budget=Budget(max_agent_calls=2, max_wall_seconds=3600),
)
def guidelines_advisor(
    project_directory: str,
    project_goals: str = "",
    deployment_plans: str = "",
) -> str:
    root = Path(project_directory).resolve()
    if not root.is_dir():
        fail("project_directory must identify an accessible project directory.")
    discovery = discover(root)
    references = (
        resource("resources/ASSESSMENT_AREAS.md"),
        resource("resources/DELIVERABLES.md"),
        resource("resources/EXAMPLE_REPORT.md"),
    )
    context = prepare_context(
        "Assess the complete project using the authoritative Guidelines Advisor skill. "
        "Keep its connected discovery, documentation, architecture, implementation, "
        "and recommendations workflow in one session and preserve its checks. "
        "Use embedded instructions and references directly; read the complete declared "
        "reference files if their text is absent. The supplied inventory covers regular "
        "files excluding .git, with confined symlinks resolved and deduplicated. Python "
        "search matches are observations, not exhaustive semantic candidates or completed "
        "reasoning. Inspect the whole project, including documentation, dependencies, "
        "tests, configuration, and deployment scripts. Verify applicability with explicit "
        "code searches and understanding before reporting N/A. Systematically examine "
        "all reference pitfalls, trust boundaries, and test quality. Use available "
        "read-only tools, including Slither printers and upgradeability checks when "
        "applicable. The project is read-only: do not modify it or run commands that "
        "write build products. Explain tools or checks that cannot run within this view. "
        "Provide architecture, inheritance, and applicable state diagrams as Mermaid, "
        "DOT, or text in diagrams; distinguish manual diagrams from actual tool output. "
        "Populate every deliverable field and cite project file:line evidence for all "
        "findings. Documentation must include purpose, components, assumptions, "
        "interactions, critical operations, and documentation gaps. Return actual "
        "inspected implementation modules as inventory-relative paths; use an empty "
        "list if there is no implementation to inspect. Prioritize actionable findings "
        "using all source priority categories as appropriate. Put unresolved design "
        "questions in questions without assuming answers. State unavailable measurements "
        "and verification honestly; example findings, versions, savings, and timelines "
        "are illustrative. Return the complete Assessment, keeping reasoning internal.",
        prior_results=json.dumps(
            {
                "project_root": str(root),
                "project_goals": project_goals,
                "deployment_plans": deployment_plans,
                "search_patterns": SEARCHES,
                "discovery": discovery.model_dump(),
            }
        ),
    )
    assessment = agent(
        "worker",
        "Complete the assessment assignment and return its structured deliverables.",
        working_directory=root,
        readable_paths=(root, *references),
        required_capabilities=("commands",),
        output=Assessment,
        timeout=3600,
        context=context,
    )
    report = render_report(assessment, discovery)
    emit(assessment, name="assessment")
    return emit(report, name="report")


if __name__ == "__main__":
    raise SystemExit(guidelines_advisor.cli())


# --- calcifier metadata (skill provenance + sha256) ---
_CALCIFIER_COMPILATION = "compiled"
_CALCIFIER_SKILL = {
    "path": "../SKILL.md",
    "sha256": ("5bb8ba34d363c419e1769a59d0fcc7444a04dc6d9e59032cb93019befdc2e464"),
}
_CALCIFIER_RESOURCES = [
    {
        "path": "resources/ASSESSMENT_AREAS.md",
        "sha256": ("951352a5e7c3afa717ed62770ae1b7c152c4792480e3beebefc68f9c96d2a46c"),
        "size": 7997,
        "source": None,
    },
    {
        "path": "resources/DELIVERABLES.md",
        "sha256": ("5a9a6e14acb0be5dd8e15440227d5cf659931ec79cca346661f9ef22bc5f21c2"),
        "size": 2338,
        "source": None,
    },
    {
        "path": "resources/EXAMPLE_REPORT.md",
        "sha256": ("4c31c1718afaece6c7ba2c3519373167ca5d81f937fb4356c8d9b45d280833f0"),
        "size": 8433,
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
