# /// script
# requires-python = ">=3.13"
# dependencies = ["calcifier==0.2.0"]
# ///

"""Prepare Rust fuzz targets and execute bounded cargo-fuzz workflows on Linux/macOS."""

import json
import re
import tomllib
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
    verify_artifact,
    write_text,
)


@output_type
class Preparation:
    completed: bool
    summary: str
    safe_without_sanitizers: bool


@output_type
class Execution:
    argv: list[str]
    exit_code: int
    stdout: str
    stderr: str


@output_type
class Report:
    action: str
    preparation: Preparation
    inspected_source_files: int
    commands: list[Execution]
    corpus_files: list[str]
    artifact_files: list[str]
    coverage_html: str


@step
def execute(
    argv: list[str], directory: str, timeout: float = 900, *, check: bool = True
) -> Execution:
    result = run_command(argv, timeout_seconds=timeout, working_directory=directory, mutating=True)
    record = Execution(argv, result.exit_code, result.stdout, result.stderr)
    emit(record, name="command")
    if check and result.exit_code != 0:
        fail(f"Command failed: {argv!r}\n{result.stdout}\n{result.stderr}")
    return record


def within(root: Path, value: str) -> Path:
    path = (root / value).resolve()
    if not path.is_relative_to(root):
        fail(f"Input must remain within the selected project: {value}")
    return path


@recipe(
    name="cargo_fuzz",
    version="1",
    capabilities=("Bash",),
    agents=("worker",),
    budget=Budget(max_agent_calls=2, max_wall_seconds=3600),
    output_root="cargo-fuzz-results",
)
def cargo_fuzz(
    project_directory: str,
    task: str,
    action: Literal["setup", "run", "replay", "corpus", "coverage"] = "run",
    target: str = "fuzz_target_1",
    install_tools: bool = False,
    sanitizer: Literal["address", "none"] = "address",
    test_case: str = "",
    dictionary: str = "",
    coverage_source: str = "src/lib.rs",
    campaign_seconds: int = 60,
    input_timeout: int = 10,
    max_input_length: int = 1024,
) -> Report:
    root = Path(project_directory).resolve()
    if not root.is_dir() or not (root / "Cargo.toml").is_file():
        fail("Select an existing Cargo package directory containing Cargo.toml.")
    package = tomllib.loads((root / "Cargo.toml").read_text(encoding="utf-8"))
    if "package" not in package:
        fail("Select a package directory within the workspace, rather than a virtual workspace.")
    if re.fullmatch(r"[A-Za-z0-9_][A-Za-z0-9_-]*", target) is None:
        fail("The fuzz target must be a Cargo binary name without path components.")
    if not 1 <= campaign_seconds <= 1200 or min(input_timeout, max_input_length) < 1:
        fail("Use a campaign of 1–1200 seconds and positive timeout and input-size limits.")
    sources = [
        p
        for p in root.rglob("*.rs")
        if p.is_file() and not {".git", "target"}.intersection(p.relative_to(root).parts)
    ]
    if not sources:
        fail("No Rust source files were found; an empty inspection cannot establish readiness.")
    if action == "coverage" and sanitizer == "none":
        fail("This coverage workflow uses the default sanitizer; select sanitizer='address'.")
    edit = action in ("setup", "run")
    commands: list[Execution] = []
    directory = str(root)
    if install_tools:
        commands.append(execute(["rustup", "install", "nightly"], directory))
        commands.append(execute(["cargo", "install", "cargo-fuzz"], directory))
        if action == "coverage":
            for argv in (
                ["rustup", "toolchain", "install", "nightly", "--component", "llvm-tools-preview"],
                ["cargo", "install", "cargo-binutils"],
                ["cargo", "install", "rustfilt"],
            ):
                commands.append(execute(argv, directory))
    commands.append(execute(["cargo", "+nightly", "--version"], directory))
    commands.append(execute(["cargo", "fuzz", "--version"], directory))
    fuzz_manifest = within(root, "fuzz/Cargo.toml")
    if not fuzz_manifest.is_file():
        if not edit:
            fail(
                "Initialize a fuzz crate with the setup action before inspecting existing targets."
            )
        commands.append(execute(["cargo", "fuzz", "init"], directory))
    if not fuzz_manifest.is_file():
        fail("cargo fuzz init did not produce fuzz/Cargo.toml.")
    if sanitizer == "none":
        if install_tools:
            commands.append(execute(["cargo", "install", "cargo-geiger"], directory))
        commands.append(execute(["cargo", "geiger"], directory))
    corpus = within(root, f"fuzz/corpus/{target}")
    seeds = sorted(str(p) for p in corpus.rglob("*") if p.is_file())
    if action in ("corpus", "coverage") and not seeds:
        fail("The selected corpus contains no files; add seeds or run a campaign first.")
    case = within(root, test_case) if test_case else None
    if action == "replay" and (case is None or not case.is_file()):
        fail("Replay requires an existing test_case file within the project.")
    dictionary_path = within(root, dictionary) if dictionary else None
    if dictionary_path is not None and not dictionary_path.is_file():
        fail("The requested dictionary is not a regular file.")
    context = prepare_context(
        task=(
            f"User request:\n{task}\nAction: {action}\nTarget: {target}\n"
            f"Sanitizer: {sanitizer}\nTest case: {test_case}\nDictionary: {dictionary}\n"
            f"Coverage source: {coverage_source}\nProject: {root}"
        ),
        instructions=(
            "Follow the authoritative cargo-fuzz skill's applicable reasoning and checks in "
            "one connected session. Inspect the complete crate and relevant dependencies. "
            "Source counts and geiger results are observations, not exhaustive semantic checks. "
            "For setup/run, select the useful surface requested by the user, adapt a binary "
            "to a library if necessary, and implement or improve the named deterministic "
            "fuzz_target! harness at fuzz/fuzz_targets/<target>.rs. Register it in the existing "
            "fuzz manifest, updating dependencies as needed. Handle expected errors gracefully; "
            "use Arbitrary-derived structured inputs where appropriate. Preserve unrelated "
            "targets and corpus data. For replay/corpus/coverage, inspect the existing target "
            "and relevant inputs without editing. Interpret existing crash evidence supplied "
            "in the task, without predicting subsequent execution results. Determine whether "
            "sanitizer-free execution is justified for the full target and dependency surface; "
            "return false when evidence is incomplete. Installation, initialization, builds, "
            "campaigns, reproduction and coverage commands belong to Python. Return completed "
            "only when the assigned preparation or existing-target assessment is complete. "
            "Summarize that work and any limitations; later command results are separate facts."
        ),
        prior_results=json.dumps(
            {
                "source_file_count": len(sources),
                "commands": [item.model_dump() for item in commands],
                "corpus_files": seeds,
            }
        ),
    )
    preparation = agent(
        "worker",
        "Complete the assigned preparation using the original skill and this context.",
        working_directory=root,
        readable_paths=(root,),
        writable_paths=(root,) if edit else (),
        output=Preparation,
        context=context,
        timeout=3600,
    )
    if not preparation.completed:
        fail(f"Required preparation remains incomplete: {preparation.summary}")
    if sanitizer == "none" and not preparation.safe_without_sanitizers:
        fail("Sanitizer-free execution was not justified. Repeat with sanitizer='address'.")
    configured = tomllib.loads(fuzz_manifest.read_text(encoding="utf-8"))
    if not any(item.get("name") == target for item in configured.get("bin", [])):
        fail(f"The fuzz manifest does not register the requested target: {target}")
    if not within(root, f"fuzz/fuzz_targets/{target}.rs").is_file():
        fail("The requested harness file is missing after preparation.")
    flags = ["--sanitizer", "none"] if sanitizer == "none" else []
    base = ["cargo", "+nightly", "fuzz", "run", *flags, target]
    html = ""
    if edit:
        build = ["cargo", "+nightly", "fuzz", "build", *flags, target]
        commands.append(execute(build, directory))
    if action == "run":
        options = [
            f"-max_total_time={campaign_seconds}",
            f"-timeout={input_timeout}",
            f"-max_len={max_input_length}",
        ]
        if dictionary_path is not None:
            options.append(f"-dict={dictionary_path}")
        commands.append(
            execute([*base, "--", *options], directory, campaign_seconds + 900, check=False)
        )
    elif action == "replay":
        assert case is not None
        commands.append(execute([*base, str(case)], directory, check=False))
    elif action == "corpus":
        commands.append(execute([*base, str(corpus), "--", "-runs=0"], directory, check=False))
    elif action == "coverage":
        source = within(root, coverage_source)
        if not source.is_file():
            fail("The coverage source filter must select an existing project file.")
        commands.append(execute(["cargo", "+nightly", "fuzz", "coverage", target], directory))
        rustc = execute(["rustc", "+nightly", "-vV"], directory)
        commands.append(rustc)
        hosts = [
            line[6:].strip() for line in rustc.stdout.splitlines() if line.startswith("host: ")
        ]
        if len(hosts) != 1 or re.fullmatch(r"[A-Za-z0-9_.-]+", hosts[0]) is None:
            fail("Could not determine one valid nightly host triple.")
        host = hosts[0]
        binary = within(root, f"target/{host}/coverage/{host}/release/{target}")
        profile = within(root, f"fuzz/coverage/{target}/coverage.profdata")
        if not binary.is_file() or not profile.is_file():
            fail("Coverage generation did not produce the binary and profile required for HTML.")
        rendered = execute(
            [
                "cargo",
                "+nightly",
                "cov",
                "--",
                "show",
                "-Xdemangler=rustfilt",
                str(binary),
                f"-instr-profile={profile}",
                "-show-line-counts-or-regions",
                "-show-instantiations",
                "-format=html",
                str(source),
            ],
            directory,
        )
        commands.append(rendered)
        if not rendered.stdout.strip():
            fail("Coverage rendering returned no HTML.")
        html = str(verify_artifact(write_text("coverage.html", rendered.stdout)))
    artifacts = within(root, f"fuzz/artifacts/{target}")
    report = Report(
        action,
        preparation,
        len(sources),
        commands,
        sorted(str(p) for p in corpus.rglob("*") if p.is_file()),
        sorted(str(p) for p in artifacts.rglob("*") if p.is_file()),
        html,
    )
    return emit(report, name="fuzz-report")


if __name__ == "__main__":
    raise SystemExit(cargo_fuzz.cli())


# --- calcifier metadata (skill provenance + sha256) ---
_CALCIFIER_COMPILATION = "compiled"
_CALCIFIER_SKILL = {
    "path": "../SKILL.md",
    "sha256": ("8e8f882604f68c682afde3562ba1bd3828264fd226f427ff7d9ba50617268db1"),
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
