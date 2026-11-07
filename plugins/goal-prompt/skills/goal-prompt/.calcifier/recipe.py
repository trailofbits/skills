# /// script
# requires-python = ">=3.13"
# dependencies = ["calcifier==0.2.0"]
# ///

import json
from pathlib import Path

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
    write_text,
)


@output_type
class GoalDraft:
    objective: str
    missing: list[str]
    use_goal_file: bool


def draft_problem(draft: GoalDraft, goal_path: Path, require_file: bool) -> str:
    if not draft.objective.strip():
        return "Return a nonempty objective grounded in the supplied brief."
    if any(not gap.strip() for gap in draft.missing):
        return "Each Missing item must identify a gap and tell the user what to supply."
    if require_file and not draft.use_goal_file:
        return "The brief exceeds 4,000 characters; reference the prepared GOAL.md."
    references_goal_file = str(goal_path) in draft.objective
    if draft.use_goal_file and not references_goal_file:
        return "Reference the exact supplied GOAL.md path when selecting that file."
    if references_goal_file and not draft.use_goal_file:
        return "Select use_goal_file when the objective references the prepared GOAL.md."
    return ""


def checked_block(stdout: str) -> str:
    block = stdout.strip()
    lines = block.splitlines()
    if len(lines) != 3 or lines[0] != "```text" or lines[2] != "```":
        fail("The supplied formatter did not return one fenced, single-line text block.")
    command = lines[1]
    if not command.startswith("/goal ") or not command[6:].strip():
        fail("The supplied formatter returned an empty or invalid /goal command.")
    if len(command) > 4000:
        fail("The supplied formatter returned a command exceeding 4,000 characters.")
    return block


@recipe(
    name="goal_prompt",
    version="1",
    capabilities=("Bash",),
    agents=("worker",),
    budget=Budget(max_agent_calls=6, max_wall_seconds=3600),
    output_root="goal-prompt-output",
)
def goal_prompt(
    brief: str,
    project_directory: str = ".",
    conversation: str = "",
    reference_files: list[str] | None = None,
) -> str:
    if not brief.strip():
        fail("Provide a nonempty goal brief; there is no objective to draft or inspect.")
    project = Path(project_directory).resolve()
    if not project.is_dir():
        fail("The supplied project_directory must be an existing directory.")

    references: list[Path] = []
    for filename in reference_files or []:
        path = Path(filename)
        references.append(path if path.is_absolute() else project / path)

    sections = ["# Original goal brief", brief]
    if conversation:
        sections.extend(["# Conversation context", conversation])
    if references:
        sections.extend(["# Supplied reference paths", "\n".join(str(path) for path in references)])
    task_text = "\n\n".join(sections) + "\n"
    context = prepare_context(
        task=task_text,
        files=tuple(references),
        readable_roots=(project, *references),
    )
    directory = ensure_directory(
        ".",
        output_files=(
            "draft-1.txt",
            "draft-2.txt",
            "draft-3.txt",
            "GOAL.md",
            "goal-prompt.txt",
        ),
    )
    goal_path = directory / "GOAL.md"
    formatter = resource("scripts/format_goal_prompt.py")
    require_file = len(brief) > 4000
    assignment = (
        "Draft the requested goal prompt under the authoritative source skill. Complete "
        "its connected grounding, drafting, easy-out review, and applicable security-goal "
        "reasoning together. This assignment prepares a command; do not perform its "
        "underlying task. Inspect the available repository and complete relevant "
        "references to ground the draft. The repository view is read-only.\n"
        "Use the embedded task directly. Read task.txt when its text is absent or a "
        "file check is required. Complete reference text is available through the "
        "context and declared filesystem view; reading it does not replace interpreting "
        "it.\n"
        "Python will run the supplied formatter and render the final response. Return "
        "objective as the draft objective without a /goal prefix or fences. Return "
        "missing as one item per ungrounded checklist element or unresolved easy-out, "
        "each explaining what the user must supply. Preserve every applicable source "
        "requirement, including requirements that belong inside the drafted command.\n"
        "The optional details file is {goal_path}. If selected, Python writes the "
        "complete original brief, conversation context, and explicit reference paths "
        "there, exactly as provided in the task. It will not contain additional "
        "repository findings or synthesized instructions. Set use_goal_file when "
        "referencing its exact path. A details file is mandatory for this brief: "
        "{require_file}. Keep the normalized /goal command within 4,000 characters.\n"
        "Previous attempts and mechanical feedback follow. Continue the same drafting "
        "task, retaining its grounding and semantic review when repairing a draft:\n"
        "{previous}"
    )
    history: list[dict[str, object]] = []
    last_problem = "No valid draft was produced."
    for attempt in range(3):
        draft = agent(
            "worker",
            assignment,
            working_directory=project,
            readable_paths=(project, *references),
            output=GoalDraft,
            context=context,
            timeout=3600,
            goal_path=str(goal_path),
            require_file=require_file,
            previous=json.dumps(history, ensure_ascii=False),
        )
        record: dict[str, object] = {
            "objective": draft.objective,
            "missing": draft.missing,
            "use_goal_file": draft.use_goal_file,
        }
        history.append(record)
        problem = draft_problem(draft, goal_path, require_file)
        if problem:
            record["feedback"] = problem
            last_problem = problem
            continue

        draft_path = directory / f"draft-{attempt + 1}.txt"
        write_text(draft_path, draft.objective)
        result = run_command(
            [
                "uv",
                "run",
                "--no-project",
                str(formatter),
                str(draft_path),
                "--fenced",
            ],
            working_directory=directory,
            timeout_seconds=60,
            mutating=False,
        )
        if result.exit_code != 0:
            if "limit is 4000" not in result.stderr:
                fail("The goal formatter failed: " + (result.stderr or result.stdout))
            last_problem = (
                "Shorten the objective or reference GOAL.md, preserving grounded "
                "requirements and the original semantic review. Formatter feedback: "
                + result.stderr
            )
            record["feedback"] = last_problem
            continue

        answer = checked_block(result.stdout)
        if draft.use_goal_file:
            write_text(goal_path, task_text)
        if draft.missing:
            gaps = ["- " + " ".join(gap.split()) for gap in draft.missing]
            answer += "\n\nMissing:\n" + "\n".join(gaps)
        write_text(directory / "goal-prompt.txt", answer + "\n")
        return emit(answer, name="goal-prompt")

    fail("Unable to format a valid goal after three attempts. " + last_problem)


if __name__ == "__main__":
    raise SystemExit(goal_prompt.cli())


# --- calcifier metadata (skill provenance + sha256) ---
_CALCIFIER_COMPILATION = "compiled"
_CALCIFIER_SKILL = {
    "path": "../SKILL.md",
    "sha256": ("684bd98d836f88e7b7ec552cc329e4e4cc1fd51cb0d4ef23e83036992f6ef6cc"),
}
_CALCIFIER_RESOURCES = [
    {
        "path": "scripts/format_goal_prompt.py",
        "sha256": ("b0c8841a825ecb96ff3188285fe2af4c8d10756f6ea80b57f87d173bd6b2cbe9"),
        "size": 3620,
        "source": None,
    },
    {
        "path": "scripts/test_format_goal_prompt.py",
        "sha256": ("d2a6a2d06656fe40c9a4d10677d4673c7dd9af82a5251229893916e31061122d"),
        "size": 3331,
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
