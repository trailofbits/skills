# /// script
# requires-python = ">=3.13"
# dependencies = ["calcifier==0.2.0"]
# ///

import json
import re
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
)


@output_type
class Log:
    argv: list[str]
    exit_code: int
    stdout: str
    stderr: str


@output_type
class Assessment:
    ready: bool
    report: str


@output_type
class Result:
    report: str
    commands: list[Log]


@step
def execute(argv: list[str], directory: str, mutating: bool, seconds: float) -> Log:
    result = run_command(
        argv, working_directory=directory, mutating=mutating, timeout_seconds=seconds
    )
    return Log(
        argv=result.argv,
        exit_code=result.exit_code,
        stdout=result.stdout,
        stderr=result.stderr,
    )


@recipe(
    agents=("worker",),
    capabilities=("Bash",),
    budget=Budget(max_agent_calls=2, max_wall_seconds=3600),
    output_root="ossfuzz-output",
)
def ossfuzz(
    request: str,
    oss_fuzz_directory: str,
    project: str,
    action: Literal["enroll", "run", "coverage", "reproduce"] = "run",
    harness: str = "",
    source_directory: str = "",
    testcase: str = "",
    clone: bool = False,
    local_corpus_only: bool = False,
    fuzz_seconds: int = 60,
) -> Result:
    name_pattern = r"[A-Za-z0-9][A-Za-z0-9_.+-]*"
    if not re.fullmatch(name_pattern, project):
        fail("Supply a project name containing only letters, numbers, underscores, dots or dashes.")
    if action != "coverage" and not re.fullmatch(name_pattern, harness):
        fail("Supply the exact harness name for enrollment, running or reproduction.")
    if not 1 <= fuzz_seconds <= 1800:
        fail("fuzz_seconds must be between 1 and 1800 for a bounded local run.")
    checkout = Path(oss_fuzz_directory).expanduser().resolve()
    source = Path(source_directory).expanduser().resolve() if source_directory else None
    case = Path(testcase).expanduser().resolve() if testcase else None
    if source is not None and not source.is_dir():
        fail("source_directory must be an existing project or harness repository.")
    if action == "enroll" and source is None:
        fail("Enrollment needs a local project or harness repository in source_directory.")
    if action == "reproduce" and (case is None or not case.is_file()):
        fail("Reproduction requires an existing testcase file and the report in request.")
    paths = tuple(str(path) for path in (checkout, source, case) if path is not None)
    ensure_directory(".", output_files=(), exclude_roots=paths)
    logs: list[Log] = []
    problems: list[str] = []
    if not checkout.exists():
        if not clone or not checkout.parent.is_dir():
            fail("Provide an OSS-Fuzz checkout, or enable clone beneath an existing directory.")
        logs.append(
            execute(
                ["git", "clone", "https://github.com/google/oss-fuzz", str(checkout)],
                str(checkout.parent),
                True,
                600.0,
            )
        )
        if logs[-1].exit_code:
            emit(logs[-1], name="clone")
            fail("Cloning OSS-Fuzz failed; see the emitted command output.")
    helper = checkout / "infra" / "helper.py"
    integration = checkout / "projects" / project
    if not helper.is_file() or not helper.resolve().is_relative_to(checkout):
        fail("The checkout must contain infra/helper.py within its filesystem boundary.")
    if not integration.resolve().is_relative_to(checkout):
        fail("The project integration path escapes the OSS-Fuzz checkout.")
    base = ["uv", "run", "--no-project", "python", "infra/helper.py"]

    def run(args: list[str], seconds: float = 1200.0, mutating: bool = True) -> bool:
        record = execute(base + args, str(checkout), mutating, seconds)
        logs.append(record)
        return record.exit_code == 0

    def analyze(phase: str, writable: tuple[str, ...] = ()) -> Assessment:
        observations = {
            "action": action,
            "project": project,
            "harness": harness,
            "sanitizer": "coverage" if action == "coverage" else "address",
            "source_directory": str(source) if source is not None else "",
            "testcase": str(case) if case is not None else "",
            "problems": problems,
            "commands": [log.model_dump() for log in logs],
        }
        context = prepare_context(request, prior_results=json.dumps(observations))
        return agent(
            "worker",
            (
                "Handle {phase} using the complete original reasoning workflow. The runtime "
                "supplies source instructions and references. Inspect the complete declared "
                "project, not just mechanical observations. Use the embedded task directly; "
                "read task.txt if absent or a file check is needed. Keep connected reasoning "
                "in this session. The recipe owns the fixed helper pipeline. For enrollment "
                "prepare integration and harness changes; ready means ready for local tests. "
                "For other actions interpret all evidence; ready means the requested work "
                "is complete, including crash-signature matching when reproducing a report. "
                "Return a user-facing report of findings/changes, evidence, limitations "
                "and pending acceptance or monitoring work. Never claim unperformed checks."
            ),
            working_directory=str(checkout),
            readable_paths=paths,
            writable_paths=writable,
            required_capabilities=("commands",),
            context=context,
            output=Assessment,
            timeout=3600,
            phase=phase,
        )

    if not run(["--help"], 60.0, False):
        problems.append("Cannot read the installed helper.py command interface.")
    assessment: Assessment | None = None
    if action == "enroll" and not problems:
        assert source is not None
        assessment = analyze(
            f"enrollment preparation for {project}, using harness name {harness}",
            (str(checkout), str(source)),
        )
        if not assessment.ready:
            problems.append("Enrollment preparation is blocked; see the agent report.")
    components = [integration / name for name in ("project.yaml", "Dockerfile", "build.sh")]
    missing = [str(path) for path in components if not path.is_file()]
    if len(missing) == len(components):
        problems.append("Inspection scope is empty: no OSS-Fuzz project components exist.")
    elif missing:
        problems.append("Missing project components: " + ", ".join(missing))
    if any(path.is_file() and not path.resolve().is_relative_to(checkout) for path in components):
        problems.append("A project component escapes the checkout.")
    if action == "coverage":
        if not run(["coverage", "--help"], 60.0, False):
            problems.append("Cannot read coverage command options.")
        elif "--no-serve" not in logs[-1].stdout + logs[-1].stderr:
            problems.append("Installed helper lacks --no-serve; cannot run bounded coverage.")
        if not local_corpus_only and which("gsutil") is None:
            problems.append("Install gsutil (skip gcloud initialization), or use local corpus.")
    if not problems:
        sanitizer = "coverage" if action == "coverage" else "address"
        commands = [
            ["build_image", "--pull", project],
            ["build_fuzzers", f"--sanitizer={sanitizer}", project],
        ]
        for command in commands:
            if not run(command):
                problems.append("Helper failed: " + " ".join(command))
                break
    if not problems:
        if action == "coverage":
            args = ["coverage", "--no-serve"]
            if local_corpus_only:
                args.append("--no-corpus-download")
            args.append(project)
        elif action == "reproduce":
            args = ["reproduce", project, harness, str(case)]
        else:
            args = ["run_fuzzer", project, harness, f"-max_total_time={fuzz_seconds}"]
        if action != "coverage":
            binary = checkout / "build" / "out" / project / harness
            if not binary.is_file() or not binary.resolve().is_relative_to(checkout):
                problems.append("The selected harness was not produced inside build/out.")
        if not problems:
            passed = run(args, 1800.0 if action == "coverage" else fuzz_seconds + 120.0)
            if not passed and action in ("coverage", "enroll"):
                problems.append("The final local helper command failed.")
    if action == "coverage" and not problems:
        report_root = checkout / "build" / "out" / project / "report"
        html = [
            path
            for path in report_root.rglob("*.html")
            if path.is_file() and path.resolve().is_relative_to(checkout)
        ]
        if not html:
            problems.append("Coverage inspection scope is empty: no HTML report was produced.")
    if action != "enroll":
        assessment = analyze(f"interpretation of local {action} results for {project}")
    elif assessment is None:
        fail("\n".join(problems) or "Enrollment preparation did not run.")
    assert assessment is not None
    lines = [assessment.report, "\nLocal command outcomes:"]
    for log in logs:
        lines.append(f"- exit {log.exit_code}: {' '.join(log.argv)}")
    if problems:
        lines.extend(["\nUnresolved problems:", *("- " + problem for problem in problems)])
    result = Result(report="\n".join(lines), commands=logs)
    emit(result, name="ossfuzz")
    if problems or not assessment.ready:
        fail("OSS-Fuzz work is incomplete; see the emitted report and complete command logs.")
    return result


if __name__ == "__main__":
    raise SystemExit(ossfuzz.cli())


# --- calcifier metadata (skill provenance + sha256) ---
_CALCIFIER_COMPILATION = "compiled"
_CALCIFIER_SKILL = {
    "path": "../SKILL.md",
    "sha256": ("aeb1abbcac5ae5e4a73be4bb923fc9cca20d8d1073630c2e0a1ff37fccbec598"),
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
