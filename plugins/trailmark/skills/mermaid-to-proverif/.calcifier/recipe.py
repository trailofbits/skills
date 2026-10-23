# /// script
# requires-python = ">=3.13"
# dependencies = ["calcifier==0.2.0"]
# ///

"""Translate a complete Mermaid protocol diagram without claiming verifier results."""

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
    step,
    verify_artifact,
    write_text,
)

REFERENCE_FILES = (
    "references/crypto-to-proverif-mapping.md",
    "references/proverif-syntax.md",
    "references/security-properties.md",
)


@output_type
class Observations:
    line_count: int
    diagram_lines: list[int]
    participant_lines: list[int]
    arrow_lines: list[int]
    note_lines: list[int]


@output_type
class Query:
    statement: str
    property_tested: str


@output_type
class ModelDraft:
    disposition: Literal["ready", "needs_input"]
    explanation: str
    model: str
    queries: list[Query]
    assumptions: list[str]


@output_type
class Delivery:
    protocol: str
    model_file: str
    summary_file: str
    summary: str
    queries: list[Query]
    assumptions: list[str]


def resolve_inputs(names: tuple[str, ...]) -> tuple[Path, ...]:
    paths = tuple(Path(name).resolve() for name in names)
    for path in paths:
        if not path.is_file():
            fail(f"Expected a regular input file: {path}")
    return paths


@step
def inspect_diagram(diagram_path: str) -> Observations:
    text = Path(diagram_path).read_text(encoding="utf-8")
    if not text.strip():
        fail("The input is empty; there are no protocol steps to inspect.")
    lines = text.splitlines()
    markers = [i for i, line in enumerate(lines, 1) if re.match(r"\s*sequenceDiagram\b", line)]
    if not markers:
        fail(
            "Please provide the Mermaid sequenceDiagram, or run the "
            "crypto-protocol-diagram skill first."
        )
    return Observations(
        line_count=len(lines),
        diagram_lines=markers,
        participant_lines=[
            i for i, line in enumerate(lines, 1) if re.match(r"\s*(participant|actor)\b", line)
        ],
        arrow_lines=[i for i, line in enumerate(lines, 1) if re.search(r"-->>|->>|--x|-x", line)],
        note_lines=[i for i, line in enumerate(lines, 1) if re.match(r"\s*Note\s+over\b", line)],
    )


def active_queries(model: str) -> list[str]:
    characters: list[str] = []
    index = 0
    depth = 0
    while index < len(model):
        if model.startswith("(*", index):
            depth += 1
            index += 2
        elif depth and model.startswith("*)", index):
            depth -= 1
            index += 2
            characters.append(" ")
        else:
            if depth == 0:
                characters.append(model[index])
            index += 1
    if depth:
        fail("The model contains an unterminated ProVerif comment.")
    text = "".join(characters)
    return [re.sub(r"\s+", "", match.group(0)) for match in re.finditer(r"\bquery\b[^.]*\.", text)]


@step
def validate_delivery(draft: ModelDraft) -> ModelDraft:
    if draft.disposition == "needs_input":
        emit(draft.explanation, name="requested-input")
        fail(draft.explanation.strip() or "More protocol information is required.")
    if draft.explanation.strip():
        fail("A ready draft must put modeling qualifications in assumptions.")
    if not draft.model.strip():
        fail("The worker returned no ProVerif model.")
    found = active_queries(draft.model)
    if not found:
        fail("No active queries were inspected; reachability queries are required.")
    if not draft.queries or any(
        not item.statement.strip() or not item.property_tested.strip() for item in draft.queries
    ):
        fail("Every query must have its complete statement and property description.")
    listed = [re.sub(r"\s+", "", item.statement) for item in draft.queries]
    if found != listed:
        fail("The summary must list every active model query exactly once in file order.")
    if not draft.assumptions or any(not item.strip() for item in draft.assumptions):
        fail("The modeling assumptions and simplifications must be supplied.")
    return draft


@recipe(
    name="mermaid-to-proverif",
    version="1.0",
    agents=("worker",),
    capabilities=(),
    budget=Budget(max_agent_calls=2, max_wall_seconds=3600),
    output_root="proverif-output",
)
def mermaid_to_proverif(
    diagram_path: str,
    protocol_name: str,
    request: str = "",
    source_paths: tuple[str, ...] = (),
    example_paths: tuple[str, ...] = (),
) -> Delivery:
    if not diagram_path.strip():
        fail("Please provide a Mermaid sequenceDiagram, or run crypto-protocol-diagram first.")
    slug = re.sub(r"[^a-z0-9]+", "-", protocol_name.lower()).strip("-")
    if not slug:
        fail("Provide a protocol name containing letters or digits.")
    filename = f"protocol-{slug[:80]}.pv"
    diagram = resolve_inputs((diagram_path,))[0]
    sources = resolve_inputs(source_paths)
    examples = resolve_inputs(example_paths)
    observations = inspect_diagram(str(diagram))
    references = tuple(resource(name) for name in REFERENCE_FILES)
    files = (diagram, *sources, *examples, *references)
    source_names = "\n".join(str(path) for path in sources) or "(none supplied)"
    example_names = "\n".join(str(path) for path in examples) or "(none supplied)"
    task = (
        f"Translate the complete diagram file: {diagram}\n"
        f"Protocol name: {protocol_name}\nUser request: {request}\n"
        f"Cited source/specification files:\n{source_names}\n"
        f"Worked-example files:\n{example_names}\n"
    )
    instructions = (
        "Follow the authoritative source skill's complete workflow in order, including its "
        "decision tree and all pre-delivery checks. Keep connected reasoning and review "
        "in this session and keep the checklist internal. The attached line numbers are "
        "syntactic observations, not an exhaustive inventory or a semantic filter. Analyze "
        "the entire diagram and understand the complete applicable reference texts. Use "
        "complete embedded files directly; read their backing files when text is absent "
        "or a file check is needed. Do not infer protocol ordering or reachability from "
        "Trailmark language support or possible deferred callbacks. Resolve uncertainties "
        "using the diagram and supplied source/specification; request missing evidence. "
        "The skill's examples/simple-handshake files are not packaged. Study the supplied "
        "worked example before an unfamiliar protocol; if it is unavailable, return "
        "needs_input identifying the missing example instead of claiming it was studied. "
        "For missing, ambiguous, empty, or unsuitable protocol input, return needs_input "
        "with the information needed in explanation. Do not fabricate a model or findings. "
        "For ready output, leave explanation empty and return the complete .pv module. "
        "Perform the skill's semantic and structural review before returning the model. "
        "Keep reachability sanity queries active and first. Include the required forward "
        "secrecy test and witness when applicable. Return every active query exactly once "
        "in file order, with its complete statement including final period and the property "
        "it tests. Include all modeling assumptions and simplifications. No ProVerif run "
        "is performed here: do not claim proven reachability, security, or attack results. "
        "Return file contents through ModelDraft; Python writes and renders the delivery."
    )
    context = prepare_context(
        task,
        instructions=instructions,
        prior_results=observations.model_dump_json(),
        files=files,
        readable_roots=files,
    )
    draft = agent(
        "worker",
        context.prompt,
        working_directory=diagram.parent,
        readable_paths=files,
        output=ModelDraft,
        timeout=3600,
        context=context,
    )
    draft = validate_delivery(draft)
    lines = [f"Protocol:   {protocol_name}", f"Output:     {filename}", "Queries:"]
    lines.extend(f"  - {item.statement} — {item.property_tested}" for item in draft.queries)
    lines.append("Assumptions:")
    lines.extend(f"  - {item}" for item in draft.assumptions)
    lines.append("Verification: ProVerif not run; reachability and security remain unverified.")
    summary = "\n".join(lines) + "\n"
    destination = ensure_directory(".", output_files=(filename, "summary.md"))
    model_file = write_text(destination / filename, draft.model)
    summary_file = write_text(destination / "summary.md", summary)
    verify_artifact(model_file)
    verify_artifact(summary_file)
    return emit(
        Delivery(
            protocol=protocol_name,
            model_file=str(model_file),
            summary_file=str(summary_file),
            summary=summary,
            queries=draft.queries,
            assumptions=draft.assumptions,
        ),
        name="proverif-model",
    )


if __name__ == "__main__":
    raise SystemExit(mermaid_to_proverif.cli())


# --- calcifier metadata (skill provenance + sha256) ---
_CALCIFIER_COMPILATION = "compiled"
_CALCIFIER_SKILL = {
    "path": "../SKILL.md",
    "sha256": ("5e65285b3188ccc1bebf9d21f1fca3a554657e7e6105b35ee8b180a23b77e108"),
}
_CALCIFIER_RESOURCES = [
    {
        "path": "agents/code-slice-worker.md",
        "sha256": ("6b427cf3aa5caf357cd0fb18eca324b4207706bcd7e79eaff157590cd5816cb7"),
        "size": 1912,
        "source": "../../agents/code-slice-worker.md",
    },
    {
        "path": "references/crypto-to-proverif-mapping.md",
        "sha256": ("6a74edc1b644d51de628b2f324ed10176b9697155a267f46f203a2c2b9014707"),
        "size": 10317,
        "source": None,
    },
    {
        "path": "references/proverif-syntax.md",
        "sha256": ("5a481e54cbf5ec718d1342f8443ab654bd36c907736ca5137d61af346d7efa74"),
        "size": 14233,
        "source": None,
    },
    {
        "path": "references/security-properties.md",
        "sha256": ("5916485d1a36afcfadfcc52243e06fca259d97feb7489a5871f0bc99f15734c9"),
        "size": 12361,
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
