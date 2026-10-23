# /// script
# requires-python = ">=3.13"
# dependencies = ["calcifier==0.2.0"]
# ///

"""Collect timing-test evidence and retain target-specific analysis in one session."""

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
    run_command,
    step,
    write_json,
    write_text,
)


@output_type
class CommandObservation:
    label: str
    argv: list[str]
    exit_code: int
    stdout: str
    stderr: str
    t_values: list[float]
    marker_counts: dict[str, int]


@output_type
class Assessment:
    inspected_targets: list[str]
    outcome: Literal["leak_detected", "no_leak_observed", "inconclusive", "not_applicable"]
    report: str
    blockers: list[str]


def _target(root: Path, value: str) -> Path:
    path = (root / value).resolve()
    if not path.is_relative_to(root):
        fail(f"Target escapes the declared project: {value}")
    if not path.is_file():
        fail(f"Target is not an existing regular file: {value}")
    return path


@step
def capture(
    label: str,
    argv: list[str],
    directory: Path,
    seconds: int,
) -> CommandObservation:
    result = run_command(
        argv,
        timeout_seconds=seconds + 30,
        working_directory=directory,
        mutating=True,
    )
    text = result.stdout + "\n" + result.stderr
    pattern = (
        r"\bt(?:[-_ ]?value)?\s*[:=]\s*"
        r"([+-]?\d+(?:\.\d+)?(?:[eE][+-]?\d+)?)"
    )
    markers = (
        "Conditional jump or move depends on uninitialised value",
        "Use of uninitialised value",
        "Uninitialised value was created",
    )
    return CommandObservation(
        label=label,
        argv=result.argv,
        exit_code=result.exit_code,
        stdout=result.stdout,
        stderr=result.stderr,
        t_values=[float(value) for value in re.findall(pattern, text, re.IGNORECASE)],
        marker_counts={marker: text.count(marker) for marker in markers},
    )


INSTRUCTIONS = (
    "Apply the authoritative source SKILL.md to every declared target in one connected "
    "session, preserving its reasoning order, conditional follow-ups, and checks. "
    "Use the complete embedded assignment and evidence directly; read task.txt if they "
    "are not embedded. The complete project is available in your filesystem view. "
    "The host validated paths and optionally collected runs of supplied prebuilt "
    "harnesses. These records are preparation, not completed reasoning phases. "
    "First understand the targets and establish whether each supplied harness actually "
    "measures the intended operation, secrets, and input classes. Reject irrelevant "
    "measurements with an explanation and perform the necessary testing yourself. "
    "Own harness construction, builds, interpretation, adaptive tracing, root-cause "
    "analysis, and the remaining source workflow. Reuse applicable existing evidence. "
    "Operation test permits harness/build changes but no production implementation edits. "
    "Operation remediate authorizes implementation fixes and the prescribed verification. "
    "Operation ci authorizes test and CI integration. Follow the user's request for "
    "additional assurance, distributions, configurations, and deployment platforms. "
    "Keep reasoning internal. Report concrete findings, evidence, configurations, actual "
    "commands and durations, limitations, and remaining work. Numeric regex matches and "
    "Valgrind message counts are observations, not exhaustive semantic candidates. "
    "Timeouts, empty logs, and unmatched patterns do not establish a clean result. "
    "Statistical non-detection and executed-path tracing do not prove constant-time. "
    "Do not mark unperformed checks complete. Missing mandatory execution, dependencies, "
    "or platform access must produce an inconclusive result with explicit blockers. "
    "Return inspected_targets using the exact absolute names actually inspected. "
    "An empty inspection scope must never produce a successful clean report. "
    "No companion recipe is available; do not assume unprovided companion guidance."
)


@recipe(
    name="constant_time_testing",
    version="1",
    capabilities=("Bash",),
    agents=("worker",),
    budget=Budget(max_agent_calls=2, max_wall_seconds=3600),
    output_root="constant-time-testing",
)
def constant_time_testing(
    project_directory: str,
    targets: tuple[str, ...],
    request: str = "Test the declared implementation for timing leakage.",
    operation: Literal["test", "remediate", "ci"] = "test",
    dudect_binary: str = "",
    timecop_binary: str = "",
    initial_seconds: Literal[300, 600] = 600,
    timeout_program: str = "timeout",
    valgrind_program: str = "valgrind",
) -> Assessment:
    """Optional binaries are existing harnesses; supplying Timecop requests baseline tracing."""
    root = Path(project_directory).resolve()
    if not root.is_dir():
        fail("The declared project directory does not exist.")
    if not targets:
        fail("Inspection scope is empty; supply at least one source or binary target.")
    target_paths = tuple(dict.fromkeys(_target(root, value) for value in targets))
    target_names = [str(path) for path in target_paths]
    dudect = _target(root, dudect_binary) if dudect_binary else None
    timecop = _target(root, timecop_binary) if timecop_binary else None
    ensure_directory(
        ".",
        output_files=("observations.json", "assessment.json", "report.md"),
    )
    observations: list[CommandObservation] = []
    if dudect is not None:
        observations.append(
            capture(
                "dudect-baseline",
                [timeout_program, str(initial_seconds), str(dudect)],
                root,
                initial_seconds,
            )
        )
    if timecop is not None:
        observations.append(
            capture(
                "secret-trace-baseline",
                [
                    timeout_program,
                    str(initial_seconds),
                    valgrind_program,
                    "--leak-check=full",
                    "--track-origins=yes",
                    "--error-exitcode=97",
                    str(timecop),
                ],
                root,
                initial_seconds,
            )
        )
    serialized = [observation.model_dump() for observation in observations]
    write_json("observations.json", serialized)
    emit(observations, name="baseline-evidence")
    assignment = {
        "request": request,
        "operation": operation,
        "project_directory": str(root),
        "targets": target_names,
        "dudect_binary": str(dudect) if dudect is not None else None,
        "timecop_binary": str(timecop) if timecop is not None else None,
        "initial_seconds": initial_seconds,
        "timeout_program": timeout_program,
        "valgrind_program": valgrind_program,
    }
    context = prepare_context(
        task=json.dumps(assignment, indent=2),
        instructions=INSTRUCTIONS,
        prior_results=json.dumps(serialized, indent=2),
        readable_roots=(root,),
    )
    result = agent(
        "worker",
        "Complete the assigned constant-time testing task and return its assessment.",
        working_directory=root,
        readable_paths=(root,),
        writable_paths=(root,),
        required_capabilities=("commands",),
        output=Assessment,
        timeout=3600,
        context=context,
    )
    if not result.inspected_targets:
        fail("The worker inspected zero targets; no successful assessment can be returned.")
    if set(result.inspected_targets) != set(target_names):
        fail("The assessment does not cover the complete declared target scope.")
    if not result.report.strip():
        fail("The worker returned no substantive assessment report.")
    write_json("assessment.json", result.model_dump())
    write_text("report.md", result.report)
    emit(result, name="assessment")
    return result


if __name__ == "__main__":
    raise SystemExit(constant_time_testing.cli())


# --- calcifier metadata (skill provenance + sha256) ---
_CALCIFIER_COMPILATION = "compiled"
_CALCIFIER_SKILL = {
    "path": "../SKILL.md",
    "sha256": ("d294126ee90dbb949261145fbf1fb05dbbeb1a986320ba597b746fa4068f0028"),
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
