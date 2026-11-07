# /// script
# requires-python = ">=3.13"
# dependencies = ["calcifier==0.2.0"]
# ///

"""Write or improve a fuzzing harness with repository-specific reasoning in one session."""

from hashlib import sha256
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
    run_command,
    step,
)


@output_type
class HarnessWork:
    outcome: Literal["implemented", "not_applicable", "blocked"]
    report: str


@output_type
class CommandCheck:
    argv: list[str]
    exit_code: int
    stdout: str
    stderr: str


@output_type
class HarnessResult:
    outcome: Literal["implemented", "not_applicable", "blocked"]
    report: str
    harness_file: str
    inventory_file_count: int
    harness_sha256: str | None
    independent_checks: list[CommandCheck]


def harness_location(root: Path, harness_file: str) -> Path:
    relative = Path(harness_file)
    if not harness_file.strip() or relative.is_absolute():
        fail("harness_file must be a nonempty path relative to the project.")
    candidate = (root / relative).resolve()
    if not candidate.is_relative_to(root) or candidate == root:
        fail("The harness must remain inside the project directory.")
    if ".git" in candidate.relative_to(root).parts:
        fail("The harness cannot be placed inside Git metadata.")
    return candidate


@step
def inventory_project(directory: str) -> list[str]:
    result = run_command(
        ["rg", "--files", "--hidden", "--glob", "!.git", "--null"],
        working_directory=directory,
        timeout_seconds=120,
        mutating=False,
    )
    if result.exit_code not in (0, 1):
        fail("Project inventory failed: " + result.stderr)
    files = sorted({name for name in result.stdout.split("\0") if name})
    if not files:
        fail(
            "Project inventory inspected zero files. Select a populated project or "
            "adjust its ignore rules before running this recipe."
        )
    return files


@step
def inspect_harness(directory: str, harness_file: str) -> str:
    harness = harness_location(Path(directory), harness_file)
    if not harness.is_file():
        fail("The requested harness file was not produced; no harness was inspected.")
    contents = harness.read_bytes()
    if not contents.strip():
        fail("The requested harness is empty.")
    return sha256(contents).hexdigest()


@step
def run_independent_checks(directory: str, commands: list[list[str]]) -> list[CommandCheck]:
    checks: list[CommandCheck] = []
    for argv in commands:
        result = run_command(
            argv,
            working_directory=directory,
            timeout_seconds=300,
            mutating=True,
        )
        checks.append(
            CommandCheck(
                argv=argv,
                exit_code=result.exit_code,
                stdout=result.stdout,
                stderr=result.stderr,
            )
        )
    return checks


@recipe(
    name="harness-writing",
    version="1",
    agents=("worker",),
    capabilities=("Bash",),
    budget=Budget(max_agent_calls=2, max_wall_seconds=3600),
    output_root="harness-writing-output",
)
def harness_writing(
    project_directory: str,
    harness_file: str,
    request: str,
    engine: Literal["libfuzzer", "aflpp", "cargo-fuzz", "go-fuzz"],
    check_commands: list[list[str]] | None = None,
) -> HarnessResult:
    """Apply the technique and optionally replay caller-supplied bounded checks."""
    root = Path(project_directory).expanduser().resolve()
    if not root.is_dir():
        fail("project_directory must identify an existing directory.")
    if not request.strip():
        fail("Describe the target API, desired harness, or campaign problem in request.")
    harness = harness_location(root, harness_file)
    commands = check_commands if check_commands is not None else []
    for argv in commands:
        if not argv or not argv[0].strip():
            fail("Every independent check must contain a nonempty executable name.")
    directory = str(root)
    relative_harness = str(harness.relative_to(root))
    files = inventory_project(directory)
    context = prepare_context(
        task=(
            "Apply the authoritative harness-writing skill to this project.\n"
            f"User request: {request}\n"
            f"Fuzzing engine: {engine}\n"
            f"Requested harness path: {relative_harness}\n"
            "Keep target understanding, harness design, implementation, and iterative "
            "validation together in this session, following the source workflow. "
            "You may edit the project and its build integration. Do not commit.\n"
            "The inventory is a discovery observation produced by rg with ignore rules; "
            "it is not an exhaustive set of semantic candidates. Inspect the complete "
            "relevant target and dependencies through the declared project view. "
            "Read any needed reference completely before interpreting it.\n"
            "Adapt examples to the actual API and preserve the practical harness rules. "
            "Use your command tools for repository-dependent builds, manual inputs, "
            "bounded fuzz runs, coverage investigation, crash reproduction, and iteration. "
            "Do not treat file discovery, source patterns, or a successful build as proof "
            "of behavioral correctness or coverage.\n"
            "The caller's independent check argv values are supplied below. You may use "
            "them during iteration; Python will replay them after implementation. Each "
            "replayed command has a 300-second timeout and runs in the project directory.\n"
            "Return implemented only after implementing and exercising the harness. "
            "Return not_applicable when a source-stated skip condition applies, explaining "
            "why. Return blocked when required implementation or validation cannot be "
            "completed, identifying the concrete missing prerequisite.\n"
            "Your report must describe the selected entry point, input mapping, related "
            "operations grouped or separated, changes, and validation evidence. Explain "
            "determinism, state reset, resource cleanup, and edge-input handling as relevant. "
            "Distinguish measured coverage, execution rate, and crash reproducibility from "
            "unmeasured properties. Include actual failures, limitations, and remaining work. "
            "Keep internal reasoning and checklists internal."
        ),
        prior_results=(
            "Complete discovered file inventory:\n"
            + repr(files)
            + "\nCaller-supplied independent check argv values:\n"
            + repr(commands)
        ),
    )
    work = agent(
        "worker",
        "Use the complete assignment in context and the authoritative source skill. "
        "Read task.txt if the assignment is not fully embedded. Return the requested outcome "
        "and complete user-facing report.",
        context=context,
        working_directory=root,
        readable_paths=(root,),
        writable_paths=(root,),
        required_capabilities=("commands",),
        output=HarnessWork,
        timeout=3600,
    )
    if not work.report.strip():
        fail("The worker returned no report.")
    digest: str | None = None
    checks: list[CommandCheck] = []
    outcome = work.outcome
    if outcome == "implemented":
        digest = inspect_harness(directory, relative_harness)
        checks = run_independent_checks(directory, commands)
        if any(check.exit_code != 0 for check in checks):
            outcome = "blocked"
    result = HarnessResult(
        outcome=outcome,
        report=work.report,
        harness_file=relative_harness,
        inventory_file_count=len(files),
        harness_sha256=digest,
        independent_checks=checks,
    )
    emit(result, name="harness-report")
    if outcome == "blocked":
        fail("Harness work is blocked; see harness-report for findings and check output.")
    return result


if __name__ == "__main__":
    raise SystemExit(harness_writing.cli())


# --- calcifier metadata (skill provenance + sha256) ---
_CALCIFIER_COMPILATION = "compiled"
_CALCIFIER_SKILL = {
    "path": "../SKILL.md",
    "sha256": ("8efda12f4ab61a7eef4daae88affc7649695d8db5fb2c2a33a78dab2a3fe36c0"),
}
_CALCIFIER_RESOURCES = []
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
