# /// script
# requires-python = ">=3.13"
# dependencies = ["calcifier==0.2.0"]
# ///

import json
import shlex
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
class Campaign:
    state_directory: str
    statistics: dict[str, dict[str, str]]
    queue_counts: dict[str, int]
    crashes: list[str]
    hangs: list[str]
    evidence_files: list[str]


@output_type
class Review:
    report: str


@output_type
class Result:
    report: str
    campaign: Campaign | None
    command_exit_code: int | None
    minimized_directory: str
    minimized_files: int


def local_path(root: Path, value: str) -> Path:
    path = (root / value).resolve()
    if not path.is_relative_to(root):
        fail(f"Project path escapes the declared project: {value}")
    return path


def command(
    root: Path,
    views: tuple[Path, ...],
    mode: str,
    image: str,
    arguments: list[str],
    environment: list[str],
) -> list[str]:
    if mode == "host":
        return ["env", *environment, *arguments]
    prefix = ["docker", "run", "--rm", "-i", "--workdir", str(root)]
    for view in views:
        prefix.extend(["--volume", f"{view}:{view}"])
    return [*prefix, image, "env", *environment, *arguments]


@step
def inspect_campaign(state: Path) -> Campaign:
    if not state.is_dir():
        fail(f"Campaign directory does not exist: {state}")
    data = Campaign(str(state), {}, {}, [], [], [])
    for stats_file in sorted(state.rglob("fuzzer_stats")):
        if not stats_file.resolve().is_relative_to(state):
            fail(f"Campaign statistics escape the inspection scope: {stats_file}")
        text = stats_file.read_text(encoding="utf-8")
        values = {
            line.partition(":")[0].strip(): line.partition(":")[2].strip()
            for line in text.splitlines()
            if ":" in line
        }
        if not values:
            fail(f"No statistics could be parsed from {stats_file}")
        instance = str(stats_file.parent.relative_to(state))
        data.statistics[instance] = values
        for name in ("fuzzer_stats", "cmdline", "plot_data"):
            evidence = stats_file.parent / name
            if evidence.is_file():
                data.evidence_files.append(str(evidence))
        for name in ("queue", "crashes", "hangs"):
            directory = stats_file.parent / name
            files = sorted(directory.iterdir()) if directory.is_dir() else []
            paths = [str(p) for p in files if p.is_file() and p.name != "README.txt"]
            if name == "queue":
                data.queue_counts[instance] = len(paths)
            elif name == "crashes":
                data.crashes.extend(paths)
            else:
                data.hangs.extend(paths)
    if not data.statistics:
        fail("Inspected zero campaign instances: no fuzzer_stats files were found.")
    return data


@recipe(
    name="aflpp",
    version="1",
    agents=("worker",),
    capabilities=("Bash",),
    budget=Budget(max_agent_calls=2, max_wall_seconds=3600),
    output_root="aflpp-output",
)
def aflpp(
    project: str,
    task: str = "",
    operation: Literal["setup", "run", "analyze", "minimize"] = "setup",
    mode: Literal["host", "docker"] = "docker",
    binary: str = "fuzz",
    seeds: str = "seeds",
    state_directory: str = "state",
    queue_instance: str = "primary",
    target_arguments: list[str] | None = None,
    instances: int = 1,
    duration_seconds: int = 60,
    dictionary: str = "",
    fast_calibration: bool = False,
    image: str = "aflplusplus/aflplusplus:stable",
) -> Result:
    """Set up a project, or operate and interpret an already instrumented target."""
    root = Path(project).resolve()
    if not root.is_dir() or not any(root.iterdir()):
        fail("The project scope is absent or empty; supply the C/C++ project to inspect.")
    if instances < 1 or not 1 <= duration_seconds <= 1800:
        fail("Use at least one instance and a campaign duration of 1–1800 seconds.")
    names = ["primary", *[f"secondary{i:02d}" for i in range(1, instances)]]
    logs = tuple(f"{name}.{suffix}" for name in names for suffix in ("log", "error"))
    planned = logs if operation == "run" else ()
    if operation == "minimize":
        planned = ("minimized",)
    work = ensure_directory(operation, output_files=planned)
    state = (root / state_directory).resolve()
    target = local_path(root, binary)
    arguments = target_arguments or []
    views = (root, work)
    data: Campaign | None = None
    exit_code: int | None = None
    minimized_directory = ""
    minimized_files = 0
    execution_notes = ""
    if operation in ("run", "minimize") and not target.is_file():
        fail("The instrumented binary is missing; use setup before this operation.")
    if operation == "run":
        if state.exists() or state.is_symlink():
            fail("The campaign destination already exists; analyze it or choose a fresh path.")
        if not state.is_relative_to(root) or state == root:
            fail("A new campaign must be in a fresh directory beneath the project.")
        seed_path = local_path(root, seeds)
        seed_files = list(seed_path.iterdir()) if seed_path.is_dir() else []
        if not any(p.is_file() and p.stat().st_size > 0 for p in seed_files):
            fail("AFL++ requires at least one nonempty seed file.")
        extra: list[str] = []
        if dictionary:
            dictionary_path = local_path(root, dictionary)
            if not dictionary_path.is_file():
                fail("The requested dictionary does not exist.")
            extra = ["-x", str(dictionary_path)]
        script = [
            "set -eu",
            "pids=()",
            'cleanup() { for pid in "${pids[@]}"; do',
            '  kill -INT "$pid" 2>/dev/null || true',
            "done; }",
            "trap cleanup EXIT INT TERM",
        ]
        for index, name in enumerate(names):
            environment = [
                "AFL_TMPDIR=/dev/shm",
                "AFL_TESTCACHE_SIZE=100",
                "AFL_NO_UI=1",
            ]
            if fast_calibration:
                environment.append("AFL_FAST_CAL=1")
            if index == 0:
                environment.append("AFL_FINAL_SYNC=1")
            seconds = duration_seconds + (10 if index == 0 and instances > 1 else 0)
            options = [
                "afl-fuzz",
                "-V",
                str(seconds),
                "-i",
                str(seed_path),
                "-o",
                str(state),
                "-M" if index == 0 else "-S",
                name,
                *extra,
                "--",
                str(target),
                *arguments,
            ]
            argv = command(root, views, mode, image, options, environment)
            stdout = shlex.quote(str(work / f"{name}.log"))
            stderr = shlex.quote(str(work / f"{name}.error"))
            script.append(f"{shlex.join(argv)} >{stdout} 2>{stderr} </dev/null &")
            script.append('pids+=("$!")')
        script.extend(
            [
                "result=0",
                'for pid in "${pids[@]}"; do',
                '  wait "$pid" || result=1',
                "done",
                "pids=()",
                'exit "$result"',
            ]
        )
        executed = run_command(
            ["bash", "-c", "\n".join(script)],
            working_directory=root,
            timeout_seconds=duration_seconds + 90,
            mutating=True,
        )
        exit_code = executed.exit_code
        execution_notes = executed.stderr
    if operation != "setup":
        data = inspect_campaign(state)
    if operation == "minimize":
        queue = local_path(state, queue_instance) / "queue"
        if not queue.is_dir() or not any(p.is_file() for p in queue.iterdir()):
            fail("The selected queue contains zero corpus files; minimization cannot proceed.")
        destination = work / "minimized"
        argv = command(
            root,
            (root, state, work),
            mode,
            image,
            [
                "afl-cmin",
                "-i",
                str(queue),
                "-o",
                str(destination),
                "--",
                str(target),
                *arguments,
            ],
            ["AFL_TMPDIR=/dev/shm"],
        )
        executed = run_command(argv, working_directory=root, timeout_seconds=600, mutating=True)
        exit_code = executed.exit_code
        execution_notes = executed.stderr
        if exit_code != 0:
            fail(f"Corpus minimization failed: {executed.stderr}")
        minimized_files = sum(p.is_file() for p in destination.rglob("*"))
        if minimized_files == 0:
            fail("Minimization produced zero corpus files; no successful result can be reported.")
        minimized_directory = str(destination)
    scope = {
        "setup": "Inspect the complete project and perform the requested AFL++ setup and build.",
        "run": "Interpret the completed bounded campaign and triage its crashes and hangs.",
        "analyze": "Interpret all supplied campaign instances and triage their crashes and hangs.",
        "minimize": "Assess the minimized corpus and interpret the source campaign and findings.",
    }[operation]
    observations = {
        "operation": operation,
        "mode": mode,
        "image": image,
        "binary": str(target),
        "target_arguments": arguments,
        "campaign": data.model_dump() if data else None,
        "command_exit_code": exit_code,
        "command_stderr": execution_notes,
        "log_directory": str(work),
        "minimized_directory": minimized_directory,
        "minimized_files": minimized_files,
    }
    evidence = tuple(Path(p) for p in data.evidence_files) if data else ()
    readable = (root, work, state) if data else (root, work)
    context = prepare_context(
        task=task or scope,
        instructions=scope,
        prior_results=json.dumps(observations),
        files=evidence,
        readable_roots=readable,
    )
    review = agent(
        "worker",
        "Complete the assigned scope using the authoritative skill's connected workflow. "
        "Use the embedded assignment directly; read task.txt if it is not embedded. "
        "Read complete supplied evidence and the relevant project sources. Parsed statistics "
        "and file lists are observations, not completed interpretation or triage. For setup, "
        "make the project-specific harness, installation and instrumentation decisions and "
        "perform the requested build, preserving compiler fallback and harness checks. "
        "For other modes, interpret every instance, review harness stability, and reproduce "
        "and assess all crash candidates with bounded commands where feasible. Explain "
        "unreproduced cases and blockers. Do not claim unperformed checks or empty inspections "
        "are successful. Apply host-kernel tuning only on a dedicated VM under the task's "
        "authorization. Report findings, limitations and relevant next steps in report; "
        "keep internal reasoning internal. Use the provided mode and image for reproduction.",
        working_directory=root,
        readable_paths=readable,
        writable_paths=(root, work),
        required_capabilities=("commands",),
        context=context,
        output=Review,
        timeout=1800,
    )
    if not review.report.strip():
        fail("The agent returned no setup or analysis report.")
    return emit(
        Result(
            review.report,
            data,
            exit_code,
            minimized_directory,
            minimized_files,
        ),
        name="aflpp-result",
    )


if __name__ == "__main__":
    raise SystemExit(aflpp.cli())


# --- calcifier metadata (skill provenance + sha256) ---
_CALCIFIER_COMPILATION = "compiled"
_CALCIFIER_SKILL = {
    "path": "../SKILL.md",
    "sha256": ("0a31023527808e68a53b81b89c7a6c10c6f84755a410df820facef44252e518d"),
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
