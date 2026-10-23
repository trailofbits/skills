# /// script
# requires-python = ">=3.13"
# dependencies = ["calcifier==0.2.0"]
# ///

import json
from pathlib import Path
from time import monotonic
from typing import Any, Literal, TypeVar

import calcifier as c

T = TypeVar("T")


@c.output_type
class Module:
    name: str
    path: str
    role: str


@c.output_type
class Entrypoint:
    name: str
    file: str
    reachableBy: str


@c.output_type
class Actor:
    name: str
    trust: Literal["untrusted", "semi-trusted", "trusted", "unclear"]


@c.output_type
class State:
    name: str
    file: str
    writtenBy: list[str]


@c.output_type
class Candidate:
    name: str
    file: str
    why: str


@c.output_type
class Orientation:
    modules: list[Module]
    entrypoints: list[Entrypoint]
    actors: list[Actor]
    state: list[State]
    candidates: list[Candidate]
    language: str
    coverage: str


@c.output_type
class Invariant:
    claim: str
    evidence: str


@c.output_type
class Assumption:
    claim: str
    establishedBy: str


@c.output_type
class Call:
    callee: str
    kind: Literal["internal", "external-source-available", "external-black-box"]
    propagates: str


@c.output_type
class Record:
    function: str
    file: str
    lines: str
    analysisFile: str
    invariants: list[Invariant]
    assumptions: list[Assumption]
    calls: list[Call]
    callers: list[str]
    sharedState: list[str]
    openQuestions: list[str]


@c.output_type
class Analysis:
    prose: str
    record: Record | None
    error: str


@c.output_type
class Boundary:
    actor: str
    entrypoint: str
    reaches: str


@c.output_type
class Cluster:
    area: str
    why: str


@c.output_type
class Synthesis:
    prose: str
    trustBoundaries: list[Boundary]
    fragilityClusters: list[Cluster]
    unresolved: list[str]


@c.recipe(agents=("worker",), budget=c.Budget(84, 3600), output_root="audit-context")
def audit_context(
    project: str = ".",
    target: str = ".",
    mode: Literal["codebase", "function"] = "codebase",
    function: str = "",
    focus: str = "",
    limit: int | None = None,
    budget_seconds: int | None = None,
) -> dict[str, Any]:
    start, root = monotonic(), Path(project).resolve()
    scope = (root / target).resolve()
    if not root.is_dir() or not scope.exists() or not scope.is_relative_to(root):
        c.fail("Project must be a directory and target must exist within it.")
    if (limit is not None and limit < 1) or (budget_seconds is not None and budget_seconds < 1):
        c.fail("Limit and selection budget must be positive when supplied.")
    rf = (
        c.resource("agents/function-analyzer.md"),
        c.resource("resources/ANALYSIS_FORMAT.md"),
        c.resource("resources/FUNCTION_MICRO_ANALYSIS_EXAMPLE.md"),
        c.resource("resources/DOMAIN_NOTES.md"),
        c.resource("workflows/audit-context.js"),
    )
    paths = tuple(f"functions/{i:02d}-function.md" for i in range(1, 41))
    directory = c.ensure_directory(".", output_files=("INDEX.json", "DOSSIER.md", *paths))
    c.ensure_directory("functions", output_files=tuple(Path(p).name for p in paths))

    def ask(text: str, output: type[T], data: object) -> T:
        ctx = c.prepare_context(text, prior_results=json.dumps(data), files=rf, readable_roots=rf)
        return c.agent(
            "worker",
            "Apply the full bundled assignment; read task.txt if not embedded.",
            working_directory=root,
            readable_paths=(root, directory, *rf),
            context=ctx,
            output=output,
            timeout=3600,
        )

    orientation: Orientation | None = None
    if mode == "function":
        if not function.strip() or not scope.is_file():
            c.fail("Single-function mode requires a function name and a target source file.")
        candidates = [Candidate(function, scope.relative_to(root).as_posix(), "Direct request.")]
    else:
        orientation = ask(
            "Perform the pinned workflow's full Orient phase with its ranking and 40 cap. "
            "Restrict to focus and callees when given; otherwise cover the whole target. Record "
            "domain/build/recovery and task/handler coverage. Exclude the output directory.",
            Orientation,
            {"target": str(scope), "focus": focus, "outputDirectory": str(directory)},
        )
        candidates = orientation.candidates
    if not candidates or len(candidates) > 40:
        c.fail("No functions selected, or orientation exceeded 40 candidates; cannot inspect.")
    elapsed = monotonic() - start
    budgeted = 12 if budget_seconds is None else max(4, int((budget_seconds - elapsed) // 60))
    cut = min(limit if limit is not None else budgeted, 40)
    selected, dropped = candidates[:cut], candidates[cut:]
    background = orientation.model_dump() if orientation else {"target": str(scope)}

    @c.step
    def inspect(slot: int) -> Analysis:
        if slot >= len(selected):
            return Analysis("", None, "Not selected.")
        try:
            return ask(
                "Apply the full pinned function-analyzer method and references, with its checks. "
                "Return full cited prose and the distinct compact RECORD. Host persists prose at "
                "analysisFile; do not write files. Use a null record and error if inspection fa"
                "ils.",
                Analysis,
                {
                    "candidate": selected[slot].model_dump(),
                    "analysisFile": paths[slot],
                    "system": background,
                },
            )
        except Exception as exc:
            if type(exc).__name__ == "BudgetExceeded":
                raise
            return Analysis("", None, str(exc))

    results = c.parallel(inspect, list(range(cut)), max_workers=4)
    records: list[Record] = []
    failed: list[dict[str, Any]] = []
    for slot in range(cut):
        if slot >= len(selected):
            break
        candidate, result = selected[slot], results[slot]
        record = result.record
        if record and [record.function, record.file] != [candidate.name, candidate.file]:
            result.error = "Record target mismatch."
        if result.error or record is None or not result.prose.strip():
            failed.append({"target": candidate.model_dump(), "error": result.error or "Empty"})
            continue
        record.analysisFile = str(directory / paths[slot])
        c.write_text(paths[slot], result.prose)
        c.verify_artifact(paths[slot])
        records.append(record)
    index: dict[str, Any] = {
        "root": str(root),
        "orientation": background,
        "selection": {
            "limit": cut,
            "budgetSeconds": budget_seconds,
            "rule": "Default 12; budget max(4,floor(remaining_seconds/60)); "
            "explicit limit overrides; maximum 40.",
        },
        "analyzed": [r.model_dump() for r in records],
        "notAnalyzed": [v.model_dump() for v in dropped],
        "failedAnalyses": failed,
        "unenforcedAssumptions": [
            f"{r.function}: {a.claim}"
            for r in records
            for a in r.assumptions
            if "nothing found" in a.establishedBy.casefold()
        ],
        "openQuestions": [f"{r.function}: {q}" for r in records for q in r.openQuestions],
    }
    if records and mode == "codebase":
        syn = ask(
            "Perform the pinned workflow's full Synthesize phase after the analysis barrier. "
            "Read prose as needed. Retain every conflict with both citations, every open question "
            "and unenforced assumption verbatim. Document cuts and failures; avoid full coverag"
            "e claims.",
            Synthesis,
            index,
        )
        if not syn.prose.strip():
            c.fail("Synthesis returned no dossier prose.")
        index.update(
            {
                "dossier": str(directory / "DOSSIER.md"),
                "trustBoundaries": [v.model_dump() for v in syn.trustBoundaries],
                "fragilityClusters": [v.model_dump() for v in syn.fragilityClusters],
                "unresolved": syn.unresolved + index["openQuestions"],
            }
        )
        tail = "\n\n## Coverage and retained records\n\n```json\n"
        c.write_text("DOSSIER.md", syn.prose + tail + json.dumps(index, indent=2) + "\n```\n")
        c.verify_artifact("DOSSIER.md")
    c.write_json("INDEX.json", index)
    c.verify_artifact("INDEX.json")
    c.emit(index, name="audit-context")
    if not records:
        c.fail("Every selected function analysis failed; see INDEX.json.")
    return index


if __name__ == "__main__":
    raise SystemExit(audit_context.cli())


# --- calcifier metadata (skill provenance + sha256) ---
_CALCIFIER_COMPILATION = "compiled"
_CALCIFIER_SKILL = {
    "path": "../SKILL.md",
    "sha256": ("33fa693dc6e166cfa4919e4373cb6578c009d296234c2ae7cb3cd4e79b443765"),
}
_CALCIFIER_RESOURCES = [
    {
        "path": "agents/function-analyzer.md",
        "sha256": ("d450f462b63dac6858015340a2e047293851d7e3c671725792d9770dca107d29"),
        "size": 4372,
        "source": "../../agents/function-analyzer.md",
    },
    {
        "path": "resources/ANALYSIS_FORMAT.md",
        "sha256": ("029532945776fb0fcbc866f19cd6114fe4152cd3dea1c0f44b266ec13a2cc6e8"),
        "size": 2613,
        "source": None,
    },
    {
        "path": "resources/DOMAIN_NOTES.md",
        "sha256": ("ca3090f7f8d18f7145b253b283f5d33c36b314cea231aae8466bf23f122e2ed1"),
        "size": 5040,
        "source": None,
    },
    {
        "path": "resources/FUNCTION_MICRO_ANALYSIS_EXAMPLE.md",
        "sha256": ("3351010d83b61bfb34a0359498f153817fdfa6528cead54536b06e035ff2399c"),
        "size": 9056,
        "source": None,
    },
    {
        "path": "workflows/audit-context.js",
        "sha256": ("71cd025216e2589fee1e1a0ffe215fb7bbeaf22751dc7417ca6ce74497e6d0b3"),
        "size": 12229,
        "source": "../../workflows/audit-context.js",
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
        "ed inspection that finds zero issues.\n\nUse native Python"
        " orchestration and Calcifier agent()/run_command() for the"
        " source mechanics. Workflow, Skill, Agent, AskUserQuestion"
        ", TaskOutput, TaskStop and TaskCreate/TaskUpdate/TaskList "
        "are platform orchestration names, not shipped Calcifier 0."
        "2.0 built-in adapters: do not emit generic tool() adapters"
        " for these names. Use validated recipe inputs for choices,"
        " await native calls, and persist host-owned bookkeeping. T"
        "he built-in Claude worker has read/search/write tools but "
        "no Bash; host Python/run_command must perform mechanical c"
        "ommands and artifact persistence. Use pinned resources rat"
        "her than searching home/plugin caches or invoking an unpin"
        "ned installation. Preserve the complete source method, wit"
        "h explicit unsupported outcomes if an essential external d"
        "ependency cannot be represented. Generic research tools su"
        "ch as WebSearch/WebFetch are separate legitimate adapters;"
        " this guidance does not replace them.\n\nThe source entry "
        "point delegates most of the method to the pinned workflows"
        "/audit-context.js and agents/function-analyzer.md. Port th"
        "at actual workflow into Python; simply asking one general "
        "worker to build a dossier drops the skill. Preserve the si"
        "ngle-function direct analyzer path and the broader-codebas"
        "e orientation -> selected per-function analyses -> synthes"
        "is barrier.\nOrientation records modules, entrypoints, act"
        "ors/trust and persistent state, ranks meaningful functions"
        " (at most 40), and applies the source limit (12 default, m"
        "aximum 40, with documented budget-aware selection). Report"
        " functions ranked below the cut and failed analyses; never"
        " imply exhaustive coverage. Fail when no functions are sel"
        "ected or every analysis fails. Each selected function must"
        " produce full cited prose on disk plus the compact source "
        "RECORD_SCHEMA: invariants, assumptions with establishedBy "
        '(including verbatim "nothing found"), callee kinds/propaga'
        "tes, shared state and open questions. Preserve the pinned "
        "function-analyzer's deep call-following method. Host-appro"
        "ved artifact names should be deterministic, collision resi"
        "stant, and filename safe as in the source slug/index patte"
        "rn.\nSynthesize only after the selected analyses return, r"
        "etaining conflicting records, every open question, and all"
        " unenforced assumptions. Produce DOSSIER.md and per-functi"
        "on files as actual verified artifacts, not model-returned "
        "paths without files. A typed prose+record return persisted"
        " by the host is acceptable when a worker cannot write the "
        "required layout. This is context building: no vulnerabilit"
        "y claims, severity, exploits, fixes or source edits. Prese"
        "rve the existing ANALYSIS_FORMAT and examples rather than "
        "inventing a reduced report.\n"
    ),
    "sha256": ("750596f41556485bb14f79c4eb62096fa28573f31dc32f3cc186048354c71437"),
}
_CALCIFIER_SUBRECIPES = []
