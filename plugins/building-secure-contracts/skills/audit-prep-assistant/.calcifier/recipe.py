# /// script
# requires-python = ">=3.13"
# dependencies = ["calcifier==0.2.0"]
# ///

import json
from pathlib import Path
from shutil import which
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
    run_command,
    step,
    write_json,
    write_text,
)


@output_type
class ScopedFile:
    path: str
    scope: Literal["in", "out"]
    reason: str


@output_type
class Checklist:
    review_goals: bool
    static_analysis: bool
    test_coverage: bool
    dead_code: bool
    build_instructions: bool
    flowcharts: bool
    user_stories: bool
    assumptions: bool
    actors_privileges: bool
    function_docs: bool
    glossary: bool


@output_type
class PrepReport:
    review_goals: str
    static_analysis: str
    test_coverage: str
    dead_code: str
    scope_notes: str
    build_instructions: str
    boilerplate: str
    architecture: str
    flowchart: str
    sequence_diagram: str
    user_stories: str
    assumptions: str
    actors_privileges: str
    developer_docs: str
    function_docs: str
    glossary: str
    files: list[ScopedFile]
    coverage_percent: float | None
    checklist: Checklist
    remaining_work: list[str]


def git(root: Path, args: list[str], mutating: bool = False) -> str:
    result = run_command(
        ["git", *args], timeout_seconds=120, working_directory=root, mutating=mutating
    )
    if result.exit_code != 0:
        fail(f"Git operation failed: {args!r}\n{result.stderr}")
    return result.stdout


@step
def inventory(root: str) -> list[str]:
    project = Path(root)
    names = git(project, ["ls-files", "--cached", "--others", "--exclude-standard", "-z"])
    removed = git(project, ["ls-files", "--deleted", "-z"])
    return sorted(set(names.split("\0")) - set(removed.split("\0")) - {""})


@step
def initial_scan(root: str, platform: str) -> str:
    commands = {
        "solidity": ["slither", ".", "--exclude-dependencies"],
        "rust": ["dylint", "--all"],
        "go": ["golangci-lint", "run"],
    }
    argv = commands.get(platform)
    if argv is None:
        return "No fixed scan command for this platform; select appropriate analyzers."
    if which(argv[0]) is None:
        return f"Command: {argv!r}\nUnavailable tool: {argv[0]}"
    result = run_command(argv, timeout_seconds=600, working_directory=root, mutating=True)
    return (
        f"Command: {argv!r}\nExit code: {result.exit_code}\n"
        f"STDOUT:\n{result.stdout}\nSTDERR:\n{result.stderr}"
    )


def render(report: PrepReport, commit: str, branch: str, tag: str) -> str:
    checks = report.checklist.model_dump()
    checks["stable_version"] = True
    ready = all(checks.values()) and not report.remaining_work
    lines = [
        "# Audit preparation package",
        "Status: " + ("Complete" if ready else "Incomplete"),
        f"Commit: {commit}\nBranch: {branch}\nTag: {tag}",
        f"Measured coverage (%): {report.coverage_percent}",
        "",
    ]
    for section_key, section_text in report.model_dump().items():
        if isinstance(section_text, str):
            if section_key in ("flowchart", "sequence_diagram"):
                section_text = "```mermaid\n" + section_text + "\n```"
            lines.extend(["## " + section_key.replace("_", " ").title(), section_text, ""])
    lines.extend(["## Code scope", "| File | Scope | Reason |", "| --- | --- | --- |"])
    for row in report.files:
        cells = [row.path, row.scope, row.reason]
        cells = [cell.replace("|", "&#124;").replace("\n", " ") for cell in cells]
        lines.append("| " + " | ".join(cells) + " |")
    lines.extend(["", "## Audit prep checklist"])
    for check_name, check_done in checks.items():
        mark = "x" if check_done else " "
        lines.append(f"- [{mark}] " + check_name.replace("_", " "))
    lines.extend(["", "## Remaining work"])
    lines.extend("- " + item for item in report.remaining_work)
    return "\n".join(lines) + "\n"


@recipe(
    version="1",
    capabilities=("Bash",),
    agents=("worker",),
    budget=Budget(max_agent_calls=2, max_wall_seconds=3600),
    output_root="audit-prep-output",
)
def audit_prep(
    project_directory: str,
    platform: Literal["solidity", "rust", "go", "cpp", "other"],
    security_objectives: str,
    areas_of_concern: str,
    worst_case_scenario: str,
    review_branch: str,
    release_tag: str,
    audit_date: str = "Not supplied",
) -> str:
    root = Path(project_directory).resolve()
    destination = ensure_directory(
        ".", output_files=("AUDIT_PREP.md", "REPORT.json"), exclude_roots=(root,)
    )
    if git(root, ["status", "--porcelain=v1", "--untracked-files=normal"]):
        fail("Use a clean Git checkout so this recipe commits only its preparation changes.")
    for ref_kind, ref_value in (("heads", review_branch), ("tags", release_tag)):
        reference = f"refs/{ref_kind}/{ref_value}"
        git(root, ["check-ref-format", reference])
        if reference in git(root, ["for-each-ref", "--format=%(refname)", reference]).splitlines():
            fail(f"Review reference already exists: {reference}")
    goals = {
        "security_objectives": security_objectives,
        "areas_of_concern": areas_of_concern,
        "worst_case_scenario": worst_case_scenario,
        "audit_date": audit_date,
    }
    emit(goals, name="owner-review-goals")
    scan = initial_scan(str(root), platform)
    context = prepare_context(
        "Prepare the entire repository under the authoritative skill, preserving its four-step "
        "order and all required checks in this single session. Owner answers establish the "
        "goals; refine them without inventing intent. Inventory and initial scan are only "
        "observations, not semantic conclusions. Interpret all findings; fix easy issues, "
        "measure coverage, run the full suite and automated dead-code detection, and verify "
        "a build in a fresh environment. Run CodeQL and Semgrep for Go/Rust/C++; rerun checks "
        "after changes. Lock dependencies and update inline documentation. At step 3 record "
        "the source commit; Python will seal the final branch, commit, and tag after your "
        "changes. Never commit or alter Git metadata yourself. Return complete report fields "
        "with raw Mermaid flowchart and sequence_diagram. Classify every final Git-visible "
        "file exactly once; explain ignored and generated files. Review the full repository, "
        "including dependencies and existing docs. Base completion on actual evidence; "
        "coverage must exceed 80 percent. Record missing tools, owner decisions and remaining "
        "work; never assert unperformed checks succeeded.",
        prior_results=json.dumps(
            {
                "owner_answers": goals,
                "platform": platform,
                "source_commit": git(root, ["rev-parse", "HEAD"]).strip(),
                "files": inventory(str(root)),
                "initial_scan": scan,
            }
        ),
    )
    report = agent(
        "worker",
        "Complete the preparation assignment and return the requested package.",
        working_directory=root,
        readable_paths=(root,),
        writable_paths=(root,),
        required_capabilities=("commands", "write"),
        output=PrepReport,
        timeout=3600,
        context=context,
    )
    paths = [item.path for item in report.files]
    if len(paths) != len(set(paths)) or set(paths) != set(inventory(str(root))):
        fail("Scope must classify every final Git-visible file exactly once.")
    for report_key, report_value in report.model_dump().items():
        if isinstance(report_value, str) and not report_value.strip():
            fail(f"Required report section is empty: {report_key}")
    percent = report.coverage_percent
    if percent is not None and not 0 <= percent <= 100:
        fail("Coverage must be a measured percentage between zero and 100, or null.")
    report.checklist.test_coverage = (
        report.checklist.test_coverage and percent is not None and percent > 80
    )
    emit(report, name="preparation-findings")
    git(root, ["switch", "-c", review_branch], mutating=True)
    git(root, ["add", "--all"], mutating=True)
    git(root, ["diff", "--cached", "--check"])
    if git(root, ["diff", "--cached", "--name-only"]):
        git(root, ["commit", "-m", "Prepare codebase for security review"], mutating=True)
    if git(root, ["status", "--porcelain=v1", "--untracked-files=normal"]):
        fail("The checkout is dirty; a stable review version has not been frozen.")
    commit = git(root, ["rev-parse", "HEAD"]).strip()
    git(root, ["tag", "--", release_tag, commit], mutating=True)
    package = {
        "report": report.model_dump(),
        "initial_scan": scan,
        "commit": commit,
        "branch": review_branch,
        "tag": release_tag,
    }
    markdown = render(report, commit, review_branch, release_tag)
    write_text(destination / "AUDIT_PREP.md", markdown)
    write_json(destination / "REPORT.json", package)
    return emit(markdown, name="audit-prep")


if __name__ == "__main__":
    raise SystemExit(audit_prep.cli())


# --- calcifier metadata (skill provenance + sha256) ---
_CALCIFIER_COMPILATION = "compiled"
_CALCIFIER_SKILL = {
    "path": "../SKILL.md",
    "sha256": ("d639b411a315ea9420e40afabe75bbf4b1bfed6ea5c8601a3e963343ac9924f2"),
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
        "gs only to the requested skill."
    ),
    "sha256": ("46bb4ed4c424344f76192480d2444ca2e0c43d841ba604cdcf68ab9140c9162c"),
}
_CALCIFIER_SUBRECIPES = []
