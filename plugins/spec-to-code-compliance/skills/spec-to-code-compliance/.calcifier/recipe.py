# /// script
# requires-python = ">=3.13"
# dependencies = ["calcifier==0.2.0"]
# ///

import json
from pathlib import Path
from typing import Any, Literal

import calcifier as c

Severity = Literal["Critical", "High", "Medium", "Low"]


@c.output_type
class Requirement:
    title: str
    quote: str
    citation: str
    force: str


@c.output_type
class Scope:
    description: str
    documents: list[str]
    unreadable_documents: list[str]
    requirements: list[Requirement]
    blocked: str


@c.output_type
class Search:
    pattern: str
    scope: str
    result: str


@c.output_type
class Analysis:
    verdict: Literal[
        "implemented", "partial", "contradicted", "stronger-than-spec", "absent", "undecidable"
    ]
    confidence: str
    body: str
    lines_read: list[str]
    searched: list[Search]
    document_problem: str
    is_finding: bool
    severity: Severity | None


@c.output_type
class Behavior:
    title: str
    analysis: str
    severity: Severity


@c.output_type
class Reverse:
    behaviors: list[Behavior]
    lines_read: list[str]
    searched: list[Search]
    open_questions: list[str]


@c.output_type
class Review:
    identifier: str
    status: Literal["confirmed", "refuted", "unverified"]
    explanation: str


def bullets(values: list[str]) -> str:
    return "\n".join("- " + value for value in values) or "None recorded."


def state(reviews: list[Review]) -> str:
    return next(
        (s for s in ("refuted", "unverified", "confirmed") if any(r.status == s for r in reviews)),
        "not applicable",
    )


def render(name: str, req: Requirement, a: Analysis, reviews: list[Review]) -> str:
    quote = "\n".join("> " + line for line in req.quote.splitlines())
    searches = bullets([f"{s.pattern} [{s.scope}]: {s.result}" for s in a.searched])
    return (
        f"## {name} — {req.title}\n\n{quote}\n> — {req.citation}\n\n"
        f"**Verdict:** {a.verdict} · confidence: {a.confidence}; force: {req.force}\n\n"
        f"{a.body}\n\n**Lines read:**\n{bullets(a.lines_read)}\n\n"
        f"**Searched:**\n{searches}\n\n**Document problem:** {a.document_problem or 'None.'}\n\n"
        f"**Proposed finding:** {a.is_finding}; severity: {a.severity or 'unassigned'}\n\n"
        f"**Independent refutation:** {state(reviews)} (code, then document)\n\n"
        f"{bullets([r.model_dump_json() for r in reviews])}\n"
    )


@c.recipe(
    name="spec-to-code-compliance",
    version="1",
    agents=("worker",),
    capabilities=(),
    output_root="spec-compliance",
    budget=c.Budget(max_agent_calls=608, max_wall_seconds=3600),
)
def compliance(path: str, spec: str = "", limit: int = 30) -> dict[str, Any]:
    root = Path(path).expanduser().resolve()
    if not root.is_dir() or not 1 <= limit <= 100:
        c.fail("Provide a code directory and a requirement limit between 1 and 100.")
    leaves = tuple(f"REQ-{i + 1:03d}.md" for i in range(limit))
    files = tuple("requirements/" + leaf for leaf in leaves)
    refs = (
        c.resource("agents/spec-compliance-checker.md"),
        c.resource("resources/ANALYSIS_FORMAT.md"),
        c.resource("resources/DIVERGENCE_RUBRIC.md"),
        c.resource("resources/DOMAIN_NOTES.md"),
        c.resource("resources/WORKED_EXAMPLE.md"),
    )
    supplied = Path(spec).expanduser() if spec else root
    supplied = (supplied if supplied.is_absolute() else root / supplied).resolve()
    if spec and not supplied.is_file():
        c.fail("The explicit specification must be a readable file.")
    views = (root, *refs, supplied)

    def context(task: str, data: Any) -> c.PreparedContext:
        prior = json.dumps(data)
        return c.prepare_context(task, prior_results=prior, files=refs, readable_roots=refs)

    prepared = context(
        "Scope/extract all requirements in priority order; do not audit. Discover specs if needed. "
        "Read full documents/definitions; quote verbatim with citation/force. Record exclusions "
        "and unreadable reasons. Block without code/specs. Keep all requirements beyond the limit.",
        {"target": str(root), "explicit_spec": str(supplied) if spec else "", "limit": limit},
    )
    scope = c.agent(
        "worker",
        prepared.prompt,
        context=prepared,
        working_directory=root,
        readable_paths=views,
        required_capabilities=("commands",),
        output=Scope,
    )
    if scope.blocked or not scope.documents or not scope.requirements:
        c.fail(scope.blocked or "Zero specification requirements: no clean report is possible.")
    c.ensure_directory(".", output_files=("REPORT.md", *files))
    c.ensure_directory("requirements", output_files=leaves)
    selected = [(f"REQ-{i + 1:03d}", r) for i, r in enumerate(scope.requirements) if i < limit]

    def refute(data: Any, ids: list[str]) -> list[Review]:
        answers: list[Review] = []
        for perspective in ("code", "document"):
            prepared = context(
                f"Independently refute each candidate from {perspective}, using original guidance. "
                "Reread relevant code or full docs/definitions. Return one cited Review per id: "
                "confirmed survives, refuted disproved, unverified incomplete. Judge finding too.",
                data,
            )
            results = c.agent(
                "worker",
                prepared.prompt,
                context=prepared,
                working_directory=root,
                readable_paths=views,
                required_capabilities=("commands",),
                output=list[Review],
            )
            if len(results) != len(ids) or {r.identifier for r in results} != set(ids):
                c.fail("Independent review omitted or duplicated a candidate.")
            answers.extend(results)
        return answers

    def inspect(item: tuple[str, Requirement]) -> tuple[Analysis, list[Review]]:
        identifier, req = item
        data = {"id": identifier, "requirement": req.model_dump(), "scope": scope.model_dump()}
        prepared = context(
            "Analyze this requirement in one session under the full checker/original workflow. "
            "Body: ANALYSIS_FORMAT, demands through questions, separated; quote/verdict outside. "
            "Include citations, paths, reasoning, consequence/fix owner and actual read/search "
            "records. Search hits never bound coverage. Judge findings by force and context.",
            data,
        )
        a = c.agent(
            "worker",
            prepared.prompt,
            context=prepared,
            working_directory=root,
            readable_paths=views,
            required_capabilities=("commands",),
            output=Analysis,
        )
        if a.is_finding and a.severity is None:
            c.fail(f"{identifier}: finding has no severity.")
        if a.verdict != "undecidable" and not a.lines_read:
            c.fail(f"{identifier}: inspected zero code items.")
        if a.verdict == "absent" and not a.searched:
            c.fail(f"{identifier}: absent verdict has no search record.")
        data["analysis"] = a.model_dump()
        divergent = a.verdict != "implemented" or bool(a.document_problem) or a.is_finding
        return a, refute(data, [identifier]) if divergent else []

    records = c.parallel(inspect, selected, max_workers=4)
    prepared = context(
        "Inspect the entire target for undocumented behavior using original guidance/full refs. "
        "Read full docs; record coverage, searches, questions and consequences/fix owner.",
        {"scope": scope.model_dump()},
    )
    reverse = c.agent(
        "worker",
        prepared.prompt,
        context=prepared,
        working_directory=root,
        readable_paths=views,
        required_capabilities=("commands",),
        output=Reverse,
    )
    if not reverse.lines_read:
        c.fail("Reverse inspection read zero code items; no clean report is possible.")
    reverse_names = [f"UNDOC-{i + 1:03d}" for i in range(len(reverse.behaviors))]
    reverse_reviews = (
        refute(
            {
                "scope": scope.model_dump(),
                "reverse": reverse.model_dump(),
                "id_order": reverse_names,
            },
            reverse_names,
        )
        if reverse_names
        else []
    )
    findings, unverified, rows, reverse_parts = [], [], [], []
    for i in range(limit):
        if i >= len(records):
            break
        name, file = f"REQ-{i + 1:03d}", files[i]
        a, reviews = records[i]
        result = state(reviews)
        if result == "confirmed" and a.is_finding:
            findings.append(name)
        if result == "unverified":
            unverified.append(name)
        rows.append(f"[{name}]({file}) — {a.verdict}; review: {result}")
        c.write_text(file, render(name, scope.requirements[i], a, reviews))
        c.verify_artifact(file)
    for name, b in zip(reverse_names, reverse.behaviors, strict=True):
        reviews = [r for r in reverse_reviews if r.identifier == name]
        result = state(reviews)
        if result == "confirmed":
            findings.append(name)
        if result == "unverified":
            unverified.append(name)
        if result != "refuted":
            reverse_parts.append(
                f"### {name} — {b.title}\n\n{b.severity}; review: {result}\n\n{b.analysis}\n\n"
                f"Reviews (code, document):\n\n{bullets([r.model_dump_json() for r in reviews])}"
            )
    unchecked = [
        f"{r.title} ({r.citation}; {r.force}): {r.quote}" for r in scope.requirements[limit:]
    ]
    report = (
        "\n\n".join(
            [
                "# Specification compliance",
                scope.description,
                "## Documents read\n\n" + bullets(scope.documents),
                "## Findings surviving independent refutation\n\n" + bullets(findings),
                "## Requirement records\n\n" + bullets(rows),
                "## notChecked\n\n" + bullets(unchecked),
                "## unverified\n\n" + bullets(unverified),
                "## unreadableDocuments\n\n" + bullets(scope.unreadable_documents),
                "## Reverse inspection\n\n"
                + ("\n\n".join(reverse_parts) or "No retained findings."),
                "**Code read:**\n\n" + bullets(reverse.lines_read),
                "**Searches:**\n\n" + bullets([s.model_dump_json() for s in reverse.searched]),
                "**Open questions:**\n\n" + bullets(reverse.open_questions),
                "Refuted records are excluded from findings; unverified candidates remain uncon"
                "firmed.",
            ]
        )
        + "\n"
    )
    c.write_text("REPORT.md", report)
    return c.emit(
        {
            "report": str(c.verify_artifact("REPORT.md")),
            "checked": len(selected),
            "notChecked": len(unchecked),
            "findings": findings,
            "unverified": unverified,
        },
        name="report",
    )


if __name__ == "__main__":
    raise SystemExit(compliance.cli())


# --- calcifier metadata (skill provenance + sha256) ---
_CALCIFIER_COMPILATION = "compiled"
_CALCIFIER_SKILL = {
    "path": "../SKILL.md",
    "sha256": ("eb0d91b50a9c06f50baf8763d1e23566897b9fa3e7ffcf13134eee4e1ccaefe5"),
}
_CALCIFIER_RESOURCES = [
    {
        "path": "agents/spec-compliance-checker.md",
        "sha256": ("20dbf4d9b8013e8c42691dab08bd4df1ac0250eb715f3a02b2270be78bc287c4"),
        "size": 5854,
        "source": "../../agents/spec-compliance-checker.md",
    },
    {
        "path": "resources/ANALYSIS_FORMAT.md",
        "sha256": ("802674d5a0622fba7c32d1e480fd236f4bddcd2435841fcf48b17044d5d4d273"),
        "size": 2855,
        "source": None,
    },
    {
        "path": "resources/DIVERGENCE_RUBRIC.md",
        "sha256": ("c7192803ae5c489501788ae5be56a5dd36b3f0b64f88982bf41f69a4245303f1"),
        "size": 3421,
        "source": None,
    },
    {
        "path": "resources/DOMAIN_NOTES.md",
        "sha256": ("435459c75d21208ea73a6cda7dfc6910efc468a903f62e20f4837d5bd8b92c4a"),
        "size": 5810,
        "source": None,
    },
    {
        "path": "resources/WORKED_EXAMPLE.md",
        "sha256": ("7b9ff43b20ba83e1ce934bc9161b14ce58617b65a9ae9c4583026dbf0299e927"),
        "size": 4238,
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
