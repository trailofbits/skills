# /// script
# requires-python = ">=3.13"
# dependencies = ["calcifier==0.2.0"]
# ///

import platform
from pathlib import Path
from typing import Literal

from calcifier import (
    Budget,
    CommandResult,
    agent,
    emit,
    ensure_directory,
    fail,
    output_type,
    recipe,
    run_command,
    step,
    verify_artifact,
    write_text,
)

ASAN_OPTIONS = "allocator_may_return_null=1:detect_leaks=0:use_sigaltstack=0"


@output_type
class HarnessDesign:
    harness: str
    rationale: str
    caveats: list[str]


@output_type
class FuzzingReport:
    design: HarnessDesign
    source_file_count: int
    mode: str
    sanitizer: str
    commands: list[CommandResult]
    observations: list[str]
    harness_path: str
    artifact_destination: str


@step
def execute(
    argv: list[str],
    directory: Path,
    timeout: float,
    mutating: bool = True,
    allow_failure: bool = False,
) -> CommandResult:
    result = run_command(
        argv, working_directory=directory, timeout_seconds=timeout, mutating=mutating
    )
    emit(result, name="command")
    if result.exit_code != 0 and not allow_failure:
        fail("Command failed. Inspect the command artifact for diagnostics.")
    return result


@step
def install_gem(
    environment: list[str], gem: str, package: str, directory: Path
) -> list[CommandResult]:
    results: list[CommandResult] = []
    for debug in (False, True):
        argv = environment + (["RUZZY_DEBUG=1"] if debug else [])
        argv += [gem, "install"] + (["--verbose"] if debug else []) + [package]
        result = execute(argv, directory, 600, allow_failure=True)
        results.append(result)
        if result.exit_code == 0:
            return results
    fail("Gem installation failed, including the verbose RUZZY_DEBUG retry.")


@recipe(
    name="ruzzy",
    version="1",
    agents=("worker",),
    capabilities=("Bash",),
    budget=Budget(max_agent_calls=2, max_wall_seconds=3600),
    output_root="ruzzy-results",
)
def ruzzy(
    project_directory: str,
    target_description: str,
    target_kind: Literal["pure-ruby", "c-extension"] = "pure-ruby",
    mode: Literal["campaign", "reproduce"] = "campaign",
    sanitizer: Literal["asan", "ubsan"] = "asan",
    install_dependencies: bool = False,
    target_gem: str = "",
    gem_directory: str = "",
    ruby: str = "ruby",
    gem: str = "gem",
    clang: str = "/usr/bin/clang",
    clangxx: str = "/usr/bin/clang++",
    corpus_directory: str = "",
    crash_file: str = "",
    campaign_seconds: int = 60,
    max_len: int = 1024,
    input_timeout: int = 10,
) -> FuzzingReport:
    root = Path(project_directory).resolve()
    if not root.is_dir() or not target_description.strip():
        fail("Provide an existing project directory and a concrete target description.")
    if not 1 <= campaign_seconds <= 600 or max_len < 1 or not 1 <= input_timeout <= 60:
        fail("Use campaign_seconds 1..600, positive max_len, and input_timeout 1..60.")
    sources = [
        path
        for path in root.rglob("*")
        if path.is_file()
        and path.suffix in {".rb", ".c", ".cc", ".cpp", ".h", ".gemspec"}
        and ".git" not in path.parts
        and ".ruzzy-gems" not in path.parts
    ]
    if not sources:
        fail("Inspection scope is empty: no Ruby, gemspec, or C-extension source files found.")
    corpus = Path(corpus_directory).resolve() if corpus_directory else None
    crash = Path(crash_file).resolve() if crash_file else None
    if corpus is not None and not corpus.is_dir():
        fail("The supplied corpus directory must already exist.")
    if mode == "reproduce" and (crash is None or not crash.is_file()):
        fail("Reproduction requires an existing crash input file.")
    if install_dependencies and target_kind == "c-extension" and not target_gem.strip():
        fail("Provide target_gem to install a native extension with sanitizer instrumentation.")
    home = Path(gem_directory).resolve() if gem_directory else root / ".ruzzy-gems"
    design = agent(
        "worker",
        "Apply the authoritative Ruzzy skill to {description}. Inspect the complete project "
        "and relevant target code through filesystem reads. The source-file count is an "
        "inventory observation, not a semantic candidate filter. Keep target understanding, "
        "exception policy, deterministic harness design, and review together. Return a full "
        "Ruby harness requiring ruzzy, defining test_one_input, returning 0 from its lambda, "
        "and calling Ruzzy.fuzz. For C extensions catch Ruby exceptions as the skill directs; "
        "for pure Ruby preserve unexpected failures and handle expected malformed inputs "
        "appropriately. Python supplies the pure-Ruby tracer separately. Use "
        "ENV.fetch('RUZZY_TARGET_ROOT') for project-relative target loading; the harness "
        "will live outside the source directory. Target kind: {kind}; sanitizer: {sanitizer}; "
        "dependency installation: {install}; target gem: {package}; gem home: {home}. "
        "When installing a native gem, target its installed instrumented implementation. "
        "Explain the chosen target, loading assumptions, and unresolved limitations. "
        "Return an empty harness with an explanation if a runnable target cannot be "
        "established. Do not install dependencies, execute commands, or modify files.",
        working_directory=root,
        readable_paths=(root,),
        output=HarnessDesign,
        description=target_description,
        kind=target_kind,
        sanitizer=sanitizer,
        install=install_dependencies,
        package=target_gem,
        home=str(home),
    )
    emit(design, name="harness-design")
    if not design.harness.strip():
        fail("No runnable harness was established. Review the harness-design artifact.")
    if platform.system() != "Linux" or platform.machine().lower() not in {
        "x86_64",
        "amd64",
        "aarch64",
        "arm64",
    }:
        fail("Ruzzy requires Linux x86-64 or ARM64. Use its Docker or development environment.")
    out = ensure_directory(
        ".",
        output_files=("harness.rb", "tracer.rb", "launcher.rb", "toy-crash", "finding"),
    )
    harness = write_text("harness.rb", design.harness)
    tracer = write_text(
        "tracer.rb",
        "# frozen_string_literal: true\nrequire 'ruzzy'\nRuzzy.trace(ENV.fetch('RUZZY_HARNESS'))\n",
    )
    launcher = write_text(
        "launcher.rb",
        "# frozen_string_literal: true\nrequire 'ruzzy'\nrequire 'rbconfig'\n"
        "kind = ARGV.shift\n"
        "library = kind == 'asan' ? Ruzzy::ASAN_PATH : Ruzzy::UBSAN_PATH\n"
        "exec({'LD_PRELOAD' => library}, RbConfig.ruby, *ARGV)\n",
    )
    environment = [
        "env",
        "-u",
        "LD_PRELOAD",
        f"ASAN_OPTIONS={ASAN_OPTIONS}",
        f"RUZZY_TARGET_ROOT={root}",
        f"RUZZY_HARNESS={harness}",
    ]
    if install_dependencies or gem_directory:
        environment += [f"GEM_HOME={home}", f"GEM_PATH={home}"]
    records: list[CommandResult] = []
    if install_dependencies:
        records.append(execute([clang, "--version"], root, 30, mutating=False))
        records.append(execute([clangxx, "--version"], root, 30, mutating=False))
        compiler = environment + [
            "MAKE=make --environment-overrides V=1",
            f"CC={clang}",
            f"CXX={clangxx}",
            f"LDSHARED={clang} -shared",
            f"LDSHAREDXX={clangxx} -shared",
        ]
        records.extend(install_gem(compiler, gem, "ruzzy", root))
        if target_gem:
            instrument = "address" if sanitizer == "asan" else "undefined"
            flags = (
                f"-fsanitize={instrument},fuzzer-no-link "
                "-fno-omit-frame-pointer -fno-common -fPIC -g"
            )
            native = compiler + [f"CFLAGS={flags}", f"CXXFLAGS={flags}"]
            records.extend(install_gem(native, gem, target_gem, root))
    scripts = (harness, tracer, launcher) if target_kind == "pure-ruby" else (harness, launcher)
    for script in scripts:
        records.append(execute([ruby, "-c", str(script)], out, 30, mutating=False))
    toy = environment + [ruby, str(launcher), "asan", "-e", "require 'ruzzy'; Ruzzy.dummy"]
    toy += ["--", "-max_total_time=10", f"-exact_artifact_path={out / 'toy-crash'}"]
    records.append(execute(toy, out, 40, allow_failure=True))
    verify_artifact("toy-crash")
    entry = tracer if target_kind == "pure-ruby" else harness
    argv = environment + [ruby, str(launcher), sanitizer, str(entry)]
    if mode == "reproduce":
        argv.append(str(crash))
    elif corpus is not None:
        argv.append(str(corpus))
    argv += [
        f"-max_len={max_len}",
        f"-timeout={input_timeout}",
        f"-max_total_time={campaign_seconds}",
        f"-exact_artifact_path={out / 'finding'}",
    ]
    result = execute(argv, out, campaign_seconds + input_timeout + 30, allow_failure=True)
    records.append(result)
    text = result.stdout + "\n" + result.stderr
    meanings = {
        "INFO: Running with entropic power schedule": "Campaign startup message observed.",
        "ERROR: AddressSanitizer: heap-use-after-free": "ASan reported heap-use-after-free.",
        "SUMMARY: libFuzzer: fuzz target exited": "Ruby-exception exit marker observed.",
        "Test unit written to": "The fuzzer reported saving an input.",
        "Base64:": "The fuzzer emitted a Base64 input representation.",
    }
    observations = [meaning for marker, meaning in meanings.items() if marker in text]
    observations.append(f"Target process exit code: {result.exit_code}.")
    observations.append("Marker matches are observations; review full output to triage failures.")
    if mode == "campaign" and corpus is not None:
        observations.append("libFuzzer may have added inputs to the supplied corpus directory.")
    return emit(
        FuzzingReport(
            design=design,
            source_file_count=len(sources),
            mode=mode,
            sanitizer=sanitizer,
            commands=records,
            observations=observations,
            harness_path=str(harness),
            artifact_destination=str(out / "finding"),
        ),
        name="ruzzy-report",
    )


if __name__ == "__main__":
    raise SystemExit(ruzzy.cli())


# --- calcifier metadata (skill provenance + sha256) ---
_CALCIFIER_COMPILATION = "compiled"
_CALCIFIER_SKILL = {
    "path": "../SKILL.md",
    "sha256": ("46374463b7ff99b028692ed8d30f1c9f488597597e5a2af4ad3919e2a47d6ce9"),
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
