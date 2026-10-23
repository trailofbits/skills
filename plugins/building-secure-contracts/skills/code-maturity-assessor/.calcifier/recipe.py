# /// script
# requires-python = ">=3.13"
# dependencies = ["calcifier==0.2.0"]
# ///

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Literal

import calcifier as cf

CATEGORIES = [
    "Arithmetic",
    "Auditing",
    "Authentication / Access Controls",
    "Complexity Management",
    "Decentralization",
    "Documentation",
    "Transaction Ordering Risks",
    "Low-Level Manipulation",
    "Testing & Verification",
]
SCORES = {"Missing": 0, "Weak": 1, "Moderate": 2, "Satisfactory": 3, "Strong": 4}
PATTERNS = (
    r"unchecked|SafeMath|checked_|saturating_|round|precision|overflow|underflow|[+*/%-]",
    r"event|emit|monitor|alert|incident|log",
    r"onlyOwner|onlyRole|modifier|AccessControl|privilege|multisig|revoke",
    r"\b(if|for|while|case|match|function|fn|contract|class)\b|complexity|inherit",
    r"proxy|upgrade|timelock|govern|owner|withdraw|exit",
    r"specification|architecture|invariant|glossary|user.story|NatSpec|rustdoc",
    r"slippage|deadline|oracle|front.?run|MEV|sandwich|order|commit|reveal",
    r"assembly|unsafe|delegatecall|staticcall|callcode|[.]call|<<|>>|bitwise|asm|[&|^~]",
    r"test|coverage|fuzz|mutation|formal|invariant|assert|CI",
)


@cf.output_type
class FileObservation:
    path: str
    line_count: int | None
    hits: dict[str, list[int]]


@cf.output_type
class Evidence:
    path: str
    first_line: int
    last_line: int
    finding: str


@cf.output_type
class CategoryAssessment:
    number: Literal[1, 2, 3, 4, 5, 6, 7, 8, 9]
    rating: Literal["Missing", "Weak", "Moderate", "Satisfactory", "Strong"]
    notes: str
    justification: str
    evidence: list[Evidence]
    gaps: str
    next_level_actions: str


@cf.output_type
class Recommendation:
    priority: Literal["CRITICAL", "HIGH", "MEDIUM"]
    action: str
    effort: str
    impact: str


@cf.output_type
class Assessment:
    project: str
    platform: str
    strengths: tuple[str, str, str]
    critical_gaps: tuple[str, str, str]
    priority_recommendations: list[str]
    categories: list[CategoryAssessment]
    roadmap: list[Recommendation]
    owner_discussion: str
    questions: list[str]


@cf.step
def discover(root: Path) -> list[FileObservation]:
    patterns = [re.compile(pattern, re.IGNORECASE) for pattern in PATTERNS]
    rows: list[FileObservation] = []
    for path in sorted(root.rglob("*")):
        relative = path.relative_to(root)
        if ".git" in relative.parts:
            continue
        if not path.resolve().is_relative_to(root):
            cf.fail("Project path escapes the declared root: " + str(relative))
        if not path.is_file():
            continue
        try:
            text = path.read_text(encoding="utf-8")
        except UnicodeDecodeError:
            rows.append(FileObservation(path=relative.as_posix(), line_count=None, hits={}))
            continue
        lines = text.splitlines()
        hits = {
            name: [number for number, line in enumerate(lines, 1) if pattern.search(line)]
            for name, pattern in zip(CATEGORIES, patterns, strict=True)
        }
        rows.append(FileObservation(path=relative.as_posix(), line_count=len(lines), hits=hits))
    return rows


@cf.step
def validate(answer: Assessment, inventory: list[FileObservation]) -> Assessment:
    if sorted(category.number for category in answer.categories) != list(range(1, 10)):
        cf.fail("The assessment must contain each of the nine categories exactly once.")
    counts = {item.path: item.line_count for item in inventory}
    texts = [answer.project, answer.platform, answer.owner_discussion]
    texts.extend(answer.strengths + answer.critical_gaps)
    texts.extend(answer.priority_recommendations + answer.questions)
    if not answer.priority_recommendations or not answer.roadmap:
        cf.fail("Priority recommendations and an actionable roadmap are required.")
    for category in answer.categories:
        texts.extend((category.notes, category.justification, category.gaps))
        texts.append(category.next_level_actions)
        if not category.evidence:
            cf.fail(f"Category {category.number} lacks required file:line evidence.")
        for evidence in category.evidence:
            count = counts.get(evidence.path)
            if count is None or not 1 <= evidence.first_line <= evidence.last_line <= count:
                cf.fail(f"Invalid indexed evidence range: {evidence.path}")
            texts.append(evidence.finding)
    for recommendation in answer.roadmap:
        texts.extend((recommendation.action, recommendation.effort, recommendation.impact))
    if any(not text.strip() for text in texts):
        cf.fail("Required report content is empty; do not render this as complete.")
    return answer


@cf.step
def render(answer: Assessment, provisional: bool) -> str:
    average = sum(SCORES[item.rating] for item in answer.categories) / len(CATEGORIES)
    status = "Provisional; owner discussion pending." if provisional else "Complete."
    parts = [
        "# Code Maturity Assessment\n",
        f"Project: {answer.project}\n\nPlatform: {answer.platform}\n\nStatus: {status}\n",
        f"## Executive Summary\n\nOverall maturity: {average:.1f} / 4.0",
    ]
    for title, values in (
        ("Top 3 strengths", answer.strengths),
        ("Top 3 critical gaps", answer.critical_gaps),
        ("Priority recommendations", answer.priority_recommendations),
    ):
        parts.append(f"\n### {title}\n")
        parts.extend(f"- {value}" for value in values)
    parts.append(
        "\n## Maturity Scorecard\n\n| Category | Rating | Score | Notes |\n|---|---|---|---|"
    )
    categories = sorted(answer.categories, key=lambda category: category.number)
    for category in categories:
        name = CATEGORIES[category.number - 1]
        score = SCORES[category.rating]
        notes = category.notes.replace("|", r"\|").replace("\n", "<br>")
        parts.append(f"| {name} | {category.rating} | {score}/4 | {notes} |")
    parts.append("\n## Detailed Analysis")
    for category in categories:
        name = CATEGORIES[category.number - 1]
        title = f"### {category.number}. {name} - {category.rating}"
        parts.extend([f"\n{title}\n", category.justification, "\n**Evidence:**\n"])
        parts.extend(
            f"- `{item.path}:{item.first_line}-{item.last_line}`: {item.finding}"
            for item in category.evidence
        )
        parts.extend(
            [f"\n**Gaps:** {category.gaps}\n", f"**Next level:** {category.next_level_actions}"]
        )
    parts.append("\n## Improvement Roadmap")
    for priority, timing in (
        ("CRITICAL", "immediate"),
        ("HIGH", "1-2 months"),
        ("MEDIUM", "2-4 months"),
    ):
        selected = [item for item in answer.roadmap if item.priority == priority]
        if selected:
            parts.append(f"\n### {priority} ({timing})\n")
            for item in selected:
                parts.append(f"- {item.action}; effort: {item.effort}; impact: {item.impact}.")
    parts.append(f"\n## Owner Discussion\n\n{answer.owner_discussion}")
    if answer.questions:
        parts.append("\n### Questions for the owner\n")
        parts.extend(f"- {question}" for question in answer.questions)
    if provisional:
        parts.append("\nProvide answers or corrections via owner_answers, then rerun.")
    return "\n".join(parts) + "\n"


@cf.recipe(
    name="code-maturity-assessor",
    version="1",
    capabilities=(),
    agents=("worker",),
    budget=cf.Budget(max_agent_calls=2, max_wall_seconds=3600),
)
def assess(project_directory: str = ".", project_context: str = "", owner_answers: str = "") -> str:
    root = Path(project_directory).resolve()
    if not root.is_dir():
        cf.fail("project_directory must identify the complete accessible codebase.")
    inventory = discover(root)
    references = (
        cf.resource("resources/ASSESSMENT_CRITERIA.md"),
        cf.resource("resources/REPORT_FORMAT.md"),
        cf.resource("resources/EXAMPLE_REPORT.md"),
    )
    context = cf.prepare_context(
        task=(
            f"Assess the full project at {root}.\nProject context:\n{project_context}\n"
            f"Owner answers and corrections:\n{owner_answers}"
        ),
        instructions=(
            "Apply the authoritative SKILL.md workflow in one connected assessment of the whole "
            "project. Use complete embedded references, or read their bundled files if absent. "
            "The regex inventory is a navigation aid, not exhaustive semantic candidates. Read "
            "implementations, tests, and documentation beyond those matches as needed. Return "
            "all nine categories, citing relative project paths and inclusive line ranges. "
            "Use owner input for discussion; return questions about unseen processes and "
            "borderline cases. Never invent dialogue, facts, evidence, or completed tests. "
            "Keep conclusions provisional while owner questions remain unresolved. "
            "Treat the example as format guidance, never as evidence about this project."
        ),
        prior_results=json.dumps([item.model_dump() for item in inventory], ensure_ascii=False),
        files=references,
        readable_roots=(root, *references),
    )
    answer = cf.agent(
        "worker",
        "Complete the supplied assignment; read task.txt if the full assignment is not embedded.",
        working_directory=root,
        readable_paths=(root, *references),
        output=Assessment,
        context=context,
        timeout=3600,
    )
    answer = validate(answer, inventory)
    cf.emit(answer, name="assessment")
    report = render(answer, bool(answer.questions) or not owner_answers.strip())
    return cf.emit(report, name="maturity-report")


if __name__ == "__main__":
    raise SystemExit(assess.cli())


# --- calcifier metadata (skill provenance + sha256) ---
_CALCIFIER_COMPILATION = "compiled"
_CALCIFIER_SKILL = {
    "path": "../SKILL.md",
    "sha256": ("a5e1427ae04cb0ed32b003c332becc0c8adb8e382d8d1d489edc997148b57ab1"),
}
_CALCIFIER_RESOURCES = [
    {
        "path": "resources/ASSESSMENT_CRITERIA.md",
        "sha256": ("0ffe131842b209de7910cc2ac77fc1e2cdea1e16455bfba79505c8ba8179009f"),
        "size": 9876,
        "source": None,
    },
    {
        "path": "resources/EXAMPLE_REPORT.md",
        "sha256": ("47f37a7460cf281cb4ca2aeb3abced762ce4b7dd4db21e7b12772b2202e4fc42"),
        "size": 7595,
        "source": None,
    },
    {
        "path": "resources/REPORT_FORMAT.md",
        "sha256": ("28474cce17be996e839353978fc06a830ac3fbd1219efbacc914de567fcdd7dc"),
        "size": 726,
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
        "gs only to the requested skill."
    ),
    "sha256": ("46bb4ed4c424344f76192480d2444ca2e0c43d841ba604cdcf68ab9140c9162c"),
}
_CALCIFIER_SUBRECIPES = []
