# /// script
# requires-python = ">=3.13"
# dependencies = ["calcifier==0.2.0"]
# ///

"""Implement, build, and smoke-test a target-specific LibAFL fuzzer."""

import json
import re
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
class Implementation:
    report: str
    blocking_reason: str


@output_type
class CommandCheck:
    phase: str
    argv: list[str]
    exit_code: int
    stdout: str
    stderr: str


@output_type
class FuzzerResult:
    implementation: str
    executable: str
    campaign_command: list[str]
    checks: list[CommandCheck]


@step
def inspect_project(directory: str) -> list[str]:
    root = Path(directory)
    if not root.is_dir():
        fail("The project directory must already exist.")
    files = []
    for path in root.rglob("*"):
        relative = path.relative_to(root)
        if not {".git", ".libafl-fuzzer"}.intersection(relative.parts) and path.is_file():
            files.append(str(relative))
    if not files:
        fail("The inspection scope contains no project files; supply a populated target project.")
    return sorted(files)


@step
def check_command(phase: str, argv: list[str], directory: str, mutating: bool) -> CommandCheck:
    result = run_command(
        argv,
        working_directory=directory,
        timeout_seconds=600,
        mutating=mutating,
    )
    check = CommandCheck(phase, argv, result.exit_code, result.stdout, result.stderr)
    emit(check, name=phase)
    if result.exit_code != 0:
        fail(
            f"{phase} exited with status {result.exit_code}. Inspect its emitted output "
            "for build errors, startup failures, or a discovered target failure."
        )
    return check


@step
def require_files(paths: list[str]) -> list[str]:
    if not paths:
        fail("No files were selected for verification.")
    for filename in paths:
        path = Path(filename)
        if not path.is_file() or path.stat().st_size == 0:
            fail(f"Required file is missing or empty: {filename}")
    return paths


@recipe(
    version="1.0",
    capabilities=("Bash",),
    agents=("worker",),
    budget=Budget(max_agent_calls=2, max_wall_seconds=3600),
)
def libafl(
    project_directory: str,
    task: str,
    mode: Literal["custom", "libfuzzer"] = "custom",
    libafl_checkout: str = "",
    compiler: Literal[
        "clang++", "clang++-15", "clang++-16", "clang++-17", "clang++-18"
    ] = "clang++",
    link_inputs: tuple[str, ...] = (),
    link_flags: tuple[str, ...] = (),
    cores: str = "0",
    execution_timeout_ms: int = 1000,
    smoke_runs: int = 1000,
) -> FuzzerResult:
    root = Path(project_directory).resolve()
    inventory = inspect_project(str(root))
    if not task.strip():
        fail("Describe the target and the requested fuzzer behavior.")
    if smoke_runs < 1 or execution_timeout_ms < 1:
        fail("Smoke runs and the per-execution timeout must be positive.")
    if re.fullmatch(r"\d+(?:-\d+)?(?:,\d+(?:-\d+)?)*", cores) is None:
        fail("Cores must be a comma-separated list of core numbers or ranges.")
    workspace = root / ".libafl-fuzzer"
    if workspace.is_symlink():
        fail("The generated fuzzer directory must not be a symlink.")
    readable = (root,)
    checkout = None
    runtime = None
    if libafl_checkout:
        checkout = Path(libafl_checkout).resolve()
        if not checkout.is_dir():
            fail("The supplied LibAFL checkout does not exist.")
        readable = (root, checkout)
        runtime = checkout / "libafl_libfuzzer_runtime"
    if mode == "libfuzzer" and runtime is None:
        fail("Drop-in mode requires an existing LibAFL checkout to build its runtime.")
    sources = [str((root / filename).resolve()) for filename in link_inputs]
    if sources:
        require_files(sources)
    settings = {
        "mode": mode,
        "project": str(root),
        "generated_workspace": str(workspace),
        "libafl_checkout": str(checkout) if checkout else None,
        "compiler": compiler,
        "link_inputs": sources,
        "link_flags": list(link_flags),
        "cores": cores,
        "execution_timeout_ms": execution_timeout_ms,
        "smoke_runs": smoke_runs,
        "project_file_inventory": inventory,
    }
    context = prepare_context(
        task,
        prior_results=json.dumps(settings),
        instructions=(
            "Implement the requested target-specific fuzzer using the authoritative LibAFL "
            "skill. Keep its connected understanding, design, implementation, and review "
            "workflow together. Inspect the whole relevant target; the inventory is only a "
            "mechanical observation. Resolve harness semantics, target integration, versions, "
            "instrumentation, feedback, objectives, state, mutation, scheduling, execution, "
            "and requested advanced features yourself. The source snippets are incomplete "
            "examples: produce complete compilable implementations, defining missing values "
            "and checking actual APIs. Related skills are optional, not dependencies.\n"
            "The project is writable; preserve unrelated work and never commit. Put generated "
            "files in generated_workspace. Use commands for target-specific investigation or "
            "integration when necessary. Python owns the standard version checks, runtime "
            "build, cargo build, final compilation, and bounded smoke execution. Do not claim "
            "those host checks have run. Do not install system packages or toolchains; report "
            "missing prerequisites and their applicable installation guidance instead.\n"
            "Both modes must provide harness.cc and main.cc, and a nonempty corpus directory "
            "inside generated_workspace. Use suitable existing seeds or construct meaningful "
            "target-specific seeds. Arrange target integration for the supplied link inputs "
            "and flags; report a blocker if required integration cannot be completed.\n"
            "In libfuzzer mode, integrate LLVMFuzzerTestOneInput and the supplied checkout's "
            "compatibility runtime. Python builds libafl_libfuzzer_runtime/build.sh, expects "
            "libFuzzer.a there, and compiles the generated C++ files and supplied link inputs. "
            "Its smoke command uses -runs and -timeout. Verify this interface against the "
            "checkout; report incompatible assumptions rather than pretending they work.\n"
            "In custom mode, create an isolated Cargo project named my_fuzzer, with staticlib "
            "output and a complete libafl_cxx compiler wrapper binary. Use the skill's 0.13 "
            "dependency family unless the task explicitly requires another version. The "
            "wrapper must use the selected compiler and link the static library with the "
            "required coverage and sanitizer instrumentation. main.cc must enter the Rust "
            "fuzzer. Support --cores, --input, --output, and --timeout in milliseconds. Also "
            "implement --iterations N as a bounded single-process execution mode for the host "
            "smoke test; normal execution should retain the requested campaign behavior.\n"
            "Review the complete generated implementation and its target integration before "
            "answering. Return report with design choices, generated changes, prerequisites, "
            "campaign usage, relevant output interpretation and troubleshooting, and remaining "
            "limitations. Put any unresolved implementation blocker in blocking_reason; "
            "otherwise leave that field empty. Keep reasoning and checklists internal."
        ),
    )
    implementation = agent(
        "worker",
        "Complete the assigned LibAFL implementation using the task bundle and original skill.",
        working_directory=root,
        readable_paths=readable,
        writable_paths=(root,),
        required_capabilities=("commands",),
        context=context,
        output=Implementation,
        timeout=3600,
    )
    emit(implementation, name="implementation")
    if implementation.blocking_reason.strip():
        fail(implementation.blocking_reason)
    require_files([str(workspace / "harness.cc"), str(workspace / "main.cc")])
    corpus = workspace / "corpus"
    if not corpus.is_dir() or not any(path.is_file() for path in corpus.rglob("*")):
        fail("No seed files are available for the smoke test.")
    checks = [check_command("clang-version", [compiler, "--version"], str(root), False)]
    match = re.search(r"(?:clang|LLVM) version\s+(\d+)", checks[0].stdout)
    if match is None or int(match.group(1)) not in {15, 16, 17, 18}:
        fail("The source skill requires LLVM 15–18; select a compatible installed compiler.")
    binary = workspace / "fuzz"
    compilation = ["-DNO_MAIN", "-g", "-O2", "main.cc", "harness.cc", *sources]
    if mode == "custom":
        require_files([str(workspace / "Cargo.toml")])
        checks.append(
            check_command("cargo-build", ["cargo", "build", "--release"], str(workspace), True)
        )
        wrapper = workspace / "target/release/libafl_cxx"
        require_files([str(wrapper), str(workspace / "target/release/libmy_fuzzer.a")])
        command = [str(wrapper), *compilation, *link_flags, "-o", str(binary)]
        campaign = [
            str(binary),
            "--cores",
            cores,
            "--input",
            str(corpus),
            "--output",
            str(workspace / "crashes"),
            "--timeout",
            str(execution_timeout_ms),
        ]
        smoke = [*campaign, "--iterations", str(smoke_runs)]
    else:
        if runtime is None:
            fail("The compatibility runtime directory is unavailable.")
        require_files([str(runtime / "build.sh")])
        checks.append(check_command("runtime-build", ["./build.sh"], str(runtime), True))
        archive = runtime / "libFuzzer.a"
        require_files([str(archive)])
        command = [
            compiler,
            "-fsanitize=fuzzer-no-link",
            *compilation,
            str(archive),
            *link_flags,
            "-o",
            str(binary),
        ]
        campaign = [str(binary), "-fork=1", "-ignore_crashes=1", str(corpus)]
        seconds = (execution_timeout_ms + 999) // 1000
        smoke = [str(binary), f"-runs={smoke_runs}", f"-timeout={seconds}", str(corpus)]
    checks.append(check_command("link-fuzzer", command, str(workspace), True))
    require_files([str(binary)])
    checks.append(check_command("smoke-test", smoke, str(workspace), True))
    result = FuzzerResult(implementation.report, str(binary), campaign, checks)
    return emit(result, name="libafl-result")


if __name__ == "__main__":
    raise SystemExit(libafl.cli())


# --- calcifier metadata (skill provenance + sha256) ---
_CALCIFIER_COMPILATION = "compiled"
_CALCIFIER_SKILL = {
    "path": "../SKILL.md",
    "sha256": ("2f7f261439c2d87a15ddbb8a04a387fb8c211b9f20b00baf28b1466e036fc0d5"),
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
