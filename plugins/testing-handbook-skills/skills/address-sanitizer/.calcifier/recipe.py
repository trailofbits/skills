# /// script
# requires-python = ">=3.13"
# dependencies = ["calcifier==0.2.0"]
# ///

"""Build and run finite C/C++ tests or reproducers, or interpret existing ASan logs.

Use report mode for existing fuzzing-campaign and Rust diagnostics. Native execution
uses an isolated output directory. Declare every additional program output through
expected_output_files, and supply absolute paths for runtime input files.
"""

import json
import re
import sys
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
)


@output_type
class Execution:
    stage: str
    argv: list[str]
    exit_code: int
    stdout: str
    stderr: str


@output_type
class Observation:
    label: str
    error_headers: list[str]
    summaries: list[str]
    stack_frame_count: int
    startup_marker_found: bool


@output_type
class Assessment:
    summary: str
    instrumentation: str
    findings: list[str]
    leak_review: str
    recommendations: list[str]
    limitations: list[str]


@step
def observe(label: str, text: str) -> Observation:
    return Observation(
        label=label,
        error_headers=re.findall(
            r"^.*(?:ERROR|WARNING):\s*(?:AddressSanitizer|LeakSanitizer):.*$",
            text,
            re.MULTILINE,
        ),
        summaries=re.findall(r"^SUMMARY:.*$", text, re.MULTILINE),
        stack_frame_count=len(re.findall(r"^\s*#\d+\s", text, re.MULTILINE)),
        startup_marker_found=bool(
            re.search(r"AddressSanitizer Init done|libc interceptors initialized", text)
        ),
    )


@step
def execute(stage: str, argv: list[str], directory: Path, seconds: int) -> Execution:
    result = run_command(
        argv,
        timeout_seconds=seconds,
        working_directory=directory,
        mutating=True,
    )
    return Execution(
        stage=stage,
        argv=result.argv,
        exit_code=result.exit_code,
        stdout=result.stdout,
        stderr=result.stderr,
    )


@recipe(
    name="address-sanitizer",
    version="1",
    agents=("worker",),
    capabilities=("Bash",),
    budget=Budget(max_agent_calls=2, max_wall_seconds=3600),
    output_root="asan-output",
)
def address_sanitizer(
    project_directory: str,
    request: str,
    mode: Literal["test", "reproducer", "report"] = "test",
    source_files: tuple[str, ...] = (),
    report_files: tuple[str, ...] = (),
    compiler: Literal["clang", "clang++", "gcc", "g++"] = "clang",
    arguments: tuple[str, ...] = (),
    libraries: tuple[str, ...] = (),
    optimization: Literal["none", "O2", "O3"] = "O2",
    leaks: Literal["auto", "on", "off"] = "auto",
    undefined_behavior: bool = False,
    execution_seconds: int = 60,
    expected_output_files: tuple[str, ...] = (),
) -> Assessment:
    project = Path(project_directory).resolve()
    if not project.is_dir():
        fail("project_directory must be an existing directory.")
    if not request.strip():
        fail("Describe the target, testing context, and question in request.")
    if not 1 <= execution_seconds <= 1800:
        fail("execution_seconds must be between 1 and 1800; executions must terminate.")
    if mode == "report" and not report_files:
        fail("No inspection scope: report mode requires at least one report file.")
    if mode != "report" and not source_files:
        fail("No inspection scope: native execution requires selected C/C++ sources.")
    if mode != "report" and sys.platform in {"darwin", "win32"}:
        fail("The source technique skips native execution on Windows and macOS.")

    sources: list[Path] = []
    reports: list[Path] = []
    observations: list[Observation] = []
    executions: list[Execution] = []
    for supplied in source_files:
        path = (project / supplied).resolve()
        if not path.is_relative_to(project) or not path.is_file():
            fail(f"Selected source must be a regular file within the project: {supplied}")
        sources.append(path)
    nonempty_reports = 0
    for supplied in report_files:
        path = (project / supplied).resolve()
        if not path.is_file():
            fail(f"Report is not a regular file: {supplied}")
        text = path.read_text(encoding="utf-8")
        nonempty_reports += bool(text.strip())
        reports.append(path)
        observations.append(observe(str(path), text))
    if mode == "report" and nonempty_reports == 0:
        fail("No inspection scope: every supplied report is empty.")

    if mode != "report":
        for library in libraries:
            if re.fullmatch(r"[A-Za-z0-9_+.-]+", library) is None:
                fail("libraries must contain library names suitable for compiler -l options.")
        directory = ensure_directory("native", output_files=("asan-target", *expected_output_files))
        binary = directory / "asan-target"
        sanitizer = "address,undefined" if undefined_behavior else "address"
        build_argv = [compiler, f"-fsanitize={sanitizer}", "-g"]
        if optimization != "none":
            build_argv.append(f"-{optimization}")
        build_argv.extend(str(path) for path in sources)
        build_argv.extend(["-o", str(binary)])
        build_argv.extend(f"-l{library}" for library in libraries)
        build = execute("compile-and-link", build_argv, directory, 180)
        executions.append(build)
        observations.append(observe("compiler output", build.stdout + "\n" + build.stderr))
        if build.exit_code == 0:
            detect_leaks = leaks == "on" or (leaks == "auto" and mode == "test")
            options = "ASAN_OPTIONS=verbosity=1:abort_on_error=1:detect_leaks=" + (
                "1" if detect_leaks else "0"
            )
            run_argv = ["env", options, str(binary), *arguments]
            execution = execute("run", run_argv, directory, execution_seconds)
            executions.append(execution)
            observations.append(
                observe("program output", execution.stdout + "\n" + execution.stderr)
            )

    emit(executions, name="commands")
    emit(observations, name="observations")
    files = tuple(dict.fromkeys([*sources, *reports]))
    evidence = json.dumps(
        {
            "mode": mode,
            "sources": [str(path) for path in sources],
            "reports": [str(path) for path in reports],
            "commands": [item.model_dump() for item in executions],
            "observations": [item.model_dump() for item in observations],
            "runtime_arguments": list(arguments),
        },
        ensure_ascii=False,
    )
    context = prepare_context(
        request,
        prior_results=evidence,
        files=files,
        readable_roots=files,
    )
    assessment = agent(
        "worker",
        "Assess the selected target and complete diagnostics in one connected session, "
        "following the authoritative source technique and its applicable checks in order. "
        "Python has performed only the recorded native commands and regex observations. "
        "Use the complete prepared evidence and supplied files; read their backing copies "
        "when complete text is not embedded. The project view supplies surrounding context. "
        "Regex matches are observations, never an exhaustive semantic candidate set. "
        "Interpret applicability, instrumentation, build failures, runtime failures, and "
        "every report. Explain each finding's error type, access, error stack, allocation "
        "and deallocation traces, and shadow-memory evidence when present; identify absent "
        "evidence explicitly. Review leaks and leave campaign-end leak review outstanding "
        "when detection was disabled or campaign evidence is absent. Distinguish no errors "
        "observed from proven memory safety or verified instrumentation. Preserve relevant "
        "platform, overhead, production, language, sanitizer-combination, fuzzer-memory, "
        "tool-integration, and troubleshooting guidance from the source. Tool-specific "
        "integration recommendations remain recommendations unless execution is recorded. "
        "Return the Assessment fields with concrete findings, recommendations, and limits. "
        "This assignment is interpretation; no additional builds or project changes are "
        "authorized through this agent session.",
        working_directory=project,
        readable_paths=files,
        context=context,
        output=Assessment,
        timeout=3600,
    )
    if not assessment.summary.strip():
        fail("The interpretation did not provide a substantive summary.")
    return emit(assessment, name="assessment")


if __name__ == "__main__":
    raise SystemExit(address_sanitizer.cli())


# --- calcifier metadata (skill provenance + sha256) ---
_CALCIFIER_COMPILATION = "compiled"
_CALCIFIER_SKILL = {
    "path": "../SKILL.md",
    "sha256": ("eb9ea8210fa55d50477fbe52993a704e320c88739c10d619864b6ce377ebce25"),
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
