# /// script
# requires-python = ">=3.13"
# dependencies = ["calcifier==0.2.0"]
# ///

import ast
import hashlib
import json
import platform
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
    resource,
    run_command,
    step,
    write_text,
)


@output_type
class Preparation:
    ready: bool
    report: str
    harness: str
    seeds: list[str]


@output_type
class Execution:
    argv: list[str]
    exit_code: int
    stdout: str
    stderr: str
    stdout_log: str
    stderr_log: str


@output_type
class FileObservation:
    path: str
    size: int
    sha256: str


@output_type
class Result:
    action: str
    preparation: str
    executions: list[Execution]
    observations: dict[str, list[str]]
    corpus: list[FileObservation]
    artifacts: list[FileObservation]
    limitation: str


LAUNCHER = (
    "import importlib\n"
    "import importlib.machinery\n"
    "import json\n"
    "import os\n"
    "import runpy\n"
    "import sys\n"
    "from pathlib import Path\n\n"
    "root = Path(__file__).resolve().parent\n"
    "config = json.loads((root / 'runtime.json').read_text(encoding='utf-8'))\n"
    "environment = dict(os.environ)\n"
    "if config['source_path']:\n"
    "    environment['PYTHONPATH'] = config['source_path']\n"
    "if config['preload']:\n"
    "    environment['LD_PRELOAD'] = config['preload']\n"
    "    environment['ASAN_OPTIONS'] = 'allocator_may_return_null=1:detect_leaks=0'\n"
    "    environment['ASAN_SYMBOLIZER_PATH'] = config['symbolizer']\n"
    "if '--child-verify' in sys.argv:\n"
    "    import atheris\n"
    "    scope = runpy.run_path(str(root / 'fuzz.py'), run_name='atheris_verification')\n"
    "    assert callable(scope.get('TestOneInput')), 'Missing TestOneInput'\n"
    "    if config['preload']:\n"
    "        module = importlib.import_module(config['target_module'])\n"
    "        origin = str(module.__file__)\n"
    "        assert any(origin.endswith(s) for s in importlib.machinery.EXTENSION_SUFFIXES)\n"
    "        print('Native extension:', origin)\n"
    "    print('Atheris:', atheris.__file__)\n"
    "    print('Harness import verification completed')\n"
    "else:\n"
    "    if sys.argv[1:] == ['--verify']:\n"
    "        arguments = [str(root / 'launcher.py'), '--child-verify']\n"
    "    else:\n"
    "        arguments = [str(root / 'fuzz.py'), *sys.argv[1:]]\n"
    "    os.execve(sys.executable, [sys.executable, *arguments], environment)\n"
)


def inventory(directory: Path) -> list[FileObservation]:
    found = []
    for path in sorted(directory.rglob("*")):
        if path.is_symlink():
            fail("Symlink encountered in an output or corpus directory: " + str(path))
        if path.is_file():
            data = path.read_bytes()
            found.append(FileObservation(str(path), len(data), hashlib.sha256(data).hexdigest()))
    return found


def validate_harness(source: str, target_module: str, allow_broad: bool) -> None:
    try:
        tree = ast.parse(source)
    except SyntaxError as error:
        fail("Invalid harness syntax: " + str(error))
    functions = [node for node in ast.walk(tree) if isinstance(node, ast.FunctionDef)]
    tests = [node for node in functions if node.name == "TestOneInput"]
    if len(tests) != 1:
        fail("The harness must define exactly one TestOneInput function.")
    decorators = [ast.unparse(item) for item in tests[0].decorator_list]
    if "atheris.instrument_func" not in decorators:
        fail("TestOneInput must use @atheris.instrument_func.")
    imported = []
    instrumented = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            if any(item.name == target_module for item in node.names):
                imported.append(node)
        elif isinstance(node, ast.ImportFrom) and node.module == target_module:
            imported.append(node)
        if isinstance(node, ast.With) and any(
            ast.unparse(item.context_expr) == "atheris.instrument_imports()" for item in node.items
        ):
            instrumented.extend(ast.walk(node))
        if isinstance(node, ast.ExceptHandler):
            if node.type is None:
                fail("Bare exception handlers would hide fuzzing failures.")
            caught = {item.id for item in ast.walk(node.type) if isinstance(item, ast.Name)}
            if "BaseException" in caught or ("Exception" in caught and not allow_broad):
                fail("The selected objective requires precise expected exception handling.")
    if not imported or any(node not in instrumented for node in imported):
        fail("The selected target must be imported inside atheris.instrument_imports().")
    if not any(node.name == "main" for node in functions):
        fail("The harness must provide a guarded main entry point.")


@step
def execute(
    root: str,
    label: Literal["compiler", "symbolizer", "install", "runtime", "verify", "campaign"],
    argv: list[str],
    timeout: int,
) -> Execution:
    directory = Path(root)
    command = run_command(argv, working_directory=directory, timeout_seconds=timeout, mutating=True)
    stdout_path = directory / (label + ".stdout.log")
    stderr_path = directory / (label + ".stderr.log")
    write_text(stdout_path, command.stdout)
    write_text(stderr_path, command.stderr)
    return emit(
        Execution(
            argv,
            command.exit_code,
            command.stdout,
            command.stderr,
            str(stdout_path),
            str(stderr_path),
        ),
        name=label,
    )


def require_success(execution: Execution) -> None:
    if execution.exit_code != 0:
        fail("Command failed; inspect the recorded stdout and stderr: " + execution.stderr_log)


def parse_observations(text: str) -> dict[str, list[str]]:
    patterns = {
        "coverage": r"\bcov:\s*(\d+)",
        "features": r"\bft:\s*(\d+)",
        "executions": r"^#(\d+)\s",
        "throughput": r"\bexec/s:\s*(\d+)",
        "corpus": r"\bcorp:\s*(\S+)",
        "new_coverage_events": r"^.*\bNEW\b.*$",
        "progress": r"^.*\bpulse\b.*$",
        "diagnostics": (
            r"^.*(?:ERROR: libFuzzer|ERROR: AddressSanitizer|runtime error:|"
            r"SUMMARY:|Traceback|DEADLYSIGNAL).*$"
        ),
        "reproduction": r"^.*(?:Running:|Executed .* in .*).*$",
        "merge": r"^.*MERGE.*$",
    }
    return {name: re.findall(pattern, text, re.MULTILINE) for name, pattern in patterns.items()}


@recipe(
    name="atheris",
    version="1",
    agents=("worker",),
    capabilities=("Bash",),
    budget=Budget(max_agent_calls=2, max_wall_seconds=3600),
    output_root="atheris-output",
)
def atheris(
    project_directory: str,
    task: str,
    target_module: str,
    action: Literal["advise", "setup", "run", "minimize", "reproduce"] = "run",
    target_kind: Literal["python", "native"] = "python",
    objective: Literal["bugs", "memory"] = "bugs",
    sanitizer: Literal["address", "address-undefined"] = "address",
    native_distribution: str = "",
    dependencies: tuple[str, ...] = (),
    install_project: bool = True,
    campaign_seconds: int = 600,
    max_length: int = 1024,
    workers: int = 1,
    corpus_directory: str = "",
    crash_file: str = "",
) -> Result:
    project = Path(project_directory).resolve()
    if not project.is_dir() or not task.strip() or not target_module.strip():
        fail("An existing project, a nonempty task, and a target module are required.")
    excluded = {".git", ".venv", "venv", "node_modules", "__pycache__"}
    source_count = sum(
        1
        for path in project.rglob("*")
        if path.is_file()
        and path.suffix in {".py", ".pyx", ".c", ".cc", ".cpp", ".h"}
        and not excluded.intersection(path.relative_to(project).parts)
    )
    if not source_count:
        fail("The inspection scope contains no Python or native source files.")
    if not 1 <= campaign_seconds <= 2400 or not 1 <= workers <= 8 or max_length < 1:
        fail("Use 1..2400 seconds, 1..8 workers, and a positive maximum input length.")
    corpus_input = Path(corpus_directory).resolve() if corpus_directory else None
    crash_input = Path(crash_file).resolve() if crash_file else None
    if corpus_input is not None and (not corpus_input.is_dir() or not inventory(corpus_input)):
        fail("The supplied corpus directory must contain at least one regular file.")
    if action == "minimize" and corpus_input is None:
        fail("Minimization requires a nonempty source corpus.")
    if action == "reproduce" and (
        crash_input is None or not crash_input.is_file() or not crash_input.stat().st_size
    ):
        fail("Reproduction requires an existing, nonempty crash input.")
    if (
        target_kind == "native"
        and action != "advise"
        and (platform.system() != "Linux" or not native_distribution or not install_project)
    ):
        fail("This native launcher requires Linux, a distribution, and a source installation.")
    references = (resource("examples.md"), resource("structured-input.md"))
    settings = {
        "action": action,
        "target_kind": target_kind,
        "objective": objective,
        "target_module": target_module,
        "sanitizer": sanitizer,
        "native_distribution": native_distribution,
        "dependencies": dependencies,
        "install_project": install_project,
        "source_file_count": source_count,
        "corpus_directory": str(corpus_input) if corpus_input else None,
        "crash_file": str(crash_input) if crash_input else None,
    }
    context = prepare_context(
        task, prior_results=json.dumps(settings), files=references, readable_roots=references
    )
    preparation = agent(
        "worker",
        "Apply the authoritative Atheris instructions to the complete task and settings. "
        "Keep target understanding, tool choice, harness design, and source review connected "
        "in this session. Interpret both complete references. Inspect the whole relevant "
        "target and existing configuration; the source count is only a scope observation. "
        "Use read-only commands for inspection when needed. Return the complete fuzz.py "
        "as harness content, plus at most eight small UTF-8 seed contents appropriate to "
        "this target. Do not write files or install dependencies. Host Python will install, "
        "validate, verify imports, and execute the selected bounded operation. For advise, "
        "return advice and an empty harness and seeds. For other actions, use canonical "
        "import atheris, import the selected target inside atheris.instrument_imports(), "
        "decorate TestOneInput with atheris.instrument_func, and provide main guarded by "
        'if __name__ == "__main__" with Setup and Fuzz. Keep execution deterministic. '
        "Derive precise expected exceptions from the target; broad Exception is permitted "
        "only for an explicitly native memory-only objective, with its limitations stated. "
        "Follow the full structured-input reference, including fixed draws, bounded sizes, "
        "surrogate handling, exhaustion checks, and consuming remaining bytes correctly. "
        "Review import ordering, actual target coverage, harness validity, and exception "
        "policy against the source. Native targets must select the actual extension module. "
        "Report prerequisites, dependencies missing from the supplied inputs, actual checks, "
        "limitations, relevant corpus and performance advice, and troubleshooting. Preserve "
        "the source guidance on Docker, sanitizer choices, alternative fuzzers, and related "
        "techniques where relevant; do not invent unavailable integrations. Use modern uv "
        "commands in any advice: uv run --no-project, uv run --with, or uv add as appropriate. "
        "ready describes source-based preparation only; all installation and campaign "
        "results remain pending. Set ready false if required inputs or design checks fail.",
        working_directory=project,
        readable_paths=(project, *references),
        required_capabilities=("commands",),
        context=context,
        output=Preparation,
        timeout=3600,
    )
    emit(preparation.report, name="preparation")
    if not preparation.ready:
        fail("Preparation is incomplete; see the preparation report.")
    result = Result(
        action,
        preparation.report,
        [],
        {},
        [],
        [],
        "Source review and mechanical observations do not establish exhaustive coverage "
        "or crash root cause. Only recorded executions were performed.",
    )
    if action == "advise":
        return emit(result, name="result")
    validate_harness(
        preparation.harness, target_module, target_kind == "native" and objective == "memory"
    )
    if len(preparation.seeds) > 8:
        fail("Preparation returned more than eight seed contents.")
    if action == "run" and corpus_input is None and not preparation.seeds:
        fail("A campaign requires a supplied corpus or at least one prepared seed.")
    labels = ("compiler", "symbolizer", "install", "runtime", "verify", "campaign")
    planned = ["fuzz.py", "launcher.py", "runtime.json", "pyproject.toml", "uv.lock"]
    planned += [label + suffix for label in labels for suffix in (".stdout.log", ".stderr.log")]
    planned += ["fuzz-" + str(index) + ".log" for index in range(8)]
    protected = (project,)
    if corpus_input is not None:
        protected += (corpus_input,)
    if crash_input is not None:
        protected += (crash_input,)
    root = ensure_directory(".", output_files=tuple(planned), exclude_roots=protected)
    corpus = ensure_directory(
        "corpus",
        output_files=tuple("seed" + str(index) for index in range(8)),
        exclude_roots=protected,
    )
    minimized = ensure_directory("minimized", exclude_roots=protected)
    artifacts = ensure_directory("artifacts", exclude_roots=protected)
    cache = ensure_directory("cache", exclude_roots=protected)
    environment = ensure_directory(".venv", exclude_roots=protected)
    for index, seed in enumerate(preparation.seeds):
        write_text(corpus / ("seed" + str(index)), seed)
    write_text(root / "fuzz.py", preparation.harness)
    write_text(root / "launcher.py", LAUNCHER)
    configuration = (
        '[project]\nname = "atheris-campaign"\nversion = "0.0.0"\n'
        'requires-python = ">=3.11"\ndependencies = []\n'
    )
    if target_kind == "native":
        configuration += (
            "\n[tool.uv]\nno-binary-package = "
            + json.dumps(["atheris", native_distribution])
            + "\n"
        )
    write_text(root / "pyproject.toml", configuration)
    build = [
        "env",
        "UV_CACHE_DIR=" + str(cache),
        "UV_PROJECT_ENVIRONMENT=" + str(environment),
    ]
    symbolizer = ""
    if target_kind == "native":
        compiler = execute(
            str(root),
            "compiler",
            ["clang", "-print-file-name=libclang_rt.fuzzer_no_main-" + platform.machine() + ".a"],
            60,
        )
        result.executions.append(compiler)
        require_success(compiler)
        library = Path(compiler.stdout.strip()).resolve()
        if not library.is_file():
            fail("Clang did not locate the libFuzzer archive required to build Atheris.")
        symbols = execute(str(root), "symbolizer", ["which", "llvm-symbolizer"], 60)
        result.executions.append(symbols)
        require_success(symbols)
        symbolizer = str(Path(symbols.stdout.strip()).resolve())
        if not Path(symbolizer).is_file():
            fail("A usable llvm-symbolizer is required for this native setup.")
        flags = "-fsanitize=address,fuzzer-no-link"
        if sanitizer == "address-undefined":
            flags = "-fsanitize=address,undefined,fuzzer-no-link"
        build += [
            "CC=clang",
            "CXX=clang++",
            "CFLAGS=" + flags,
            "CXXFLAGS=" + flags,
            "LDSHARED=clang -shared",
            "LDSHAREDXX=clang++ -shared",
            "LIBFUZZER_LIB=" + str(library),
            "ASAN_SYMBOLIZER_PATH=" + symbolizer,
        ]
    install = build + ["uv", "add", "--project", str(root)]
    if target_kind == "native":
        install += ["--no-binary-package", "atheris", "--no-binary-package", native_distribution]
    install += ["atheris", *dependencies]
    if install_project:
        install.append(str(project))
    installed = execute(str(root), "install", install, 600)
    result.executions.append(installed)
    require_success(installed)
    invocation = [
        "env",
        "UV_CACHE_DIR=" + str(cache),
        "uv",
        "run",
        "--no-project",
        "--python",
        str(environment / "bin" / "python"),
        "python",
    ]
    preload = ""
    if target_kind == "native":
        locator = (
            "import atheris; from pathlib import Path; "
            'p=Path(atheris.__file__).parent/"asan_with_fuzzer.so"; '
            "assert p.is_file(), p; print(p.resolve())"
        )
        located = execute(str(root), "runtime", invocation + ["-c", locator], 60)
        result.executions.append(located)
        require_success(located)
        preload_path = Path(located.stdout.strip()).resolve()
        if not preload_path.is_file() or preload_path.name != "asan_with_fuzzer.so":
            fail("The installed Atheris sanitizer runtime could not be verified.")
        preload = str(preload_path)
    write_text(
        root / "runtime.json",
        json.dumps(
            {
                "preload": preload,
                "symbolizer": symbolizer,
                "target_module": target_module,
                "source_path": "" if install_project else str(project),
            }
        ),
    )
    verified = execute(
        str(root), "verify", invocation + [str(root / "launcher.py"), "--verify"], 120
    )
    result.executions.append(verified)
    require_success(verified)
    if action == "setup":
        result.limitation += " Setup completed; no fuzz campaign was launched."
        return emit(result, name="result")
    argv = invocation + [str(root / "launcher.py")]
    if action == "minimize":
        argv += ["-merge=1", str(minimized), str(corpus_input)]
    elif action == "reproduce":
        argv += ["-runs=1", str(crash_input)]
    else:
        argv.append(str(corpus))
        if corpus_input is not None:
            argv.append(str(corpus_input))
        if workers > 1:
            argv += [f"-workers={workers}", f"-jobs={workers}"]
    argv += [
        f"-max_total_time={campaign_seconds}",
        f"-max_len={max_length}",
        "-timeout=" + str(min(30, campaign_seconds)),
        "-rss_limit_mb=2048",
        "-artifact_prefix=" + str(artifacts) + "/",
        "-print_final_stats=1",
    ]
    campaign = execute(str(root), "campaign", argv, campaign_seconds + 120)
    result.executions.append(campaign)
    text = campaign.stdout + "\n" + campaign.stderr
    for index in range(workers):
        worker_log = root / ("fuzz-" + str(index) + ".log")
        if worker_log.is_file():
            text += "\n" + worker_log.read_text(encoding="utf-8", errors="replace")
    result.observations = parse_observations(text)
    result.corpus = inventory(minimized if action == "minimize" else corpus)
    result.artifacts = inventory(artifacts)
    result.observations["exit_code"] = [str(campaign.exit_code)]
    if campaign.exit_code:
        result.limitation += " The operation exited nonzero; inspect logs and preserved artifacts."
    emit(result, name="result")
    if campaign.exit_code == 0:
        if action == "run" and not result.observations["executions"]:
            fail("The command reported success without observable fuzz executions; inspect logs.")
        if action == "minimize" and not result.corpus:
            fail("Merge returned success but produced no corpus files.")
        if action == "reproduce" and not result.observations["reproduction"]:
            fail("No crash-input execution was observed; reproduction is unverified.")
    return result


if __name__ == "__main__":
    raise SystemExit(atheris.cli())


# --- calcifier metadata (skill provenance + sha256) ---
_CALCIFIER_COMPILATION = "compiled"
_CALCIFIER_SKILL = {
    "path": "../SKILL.md",
    "sha256": ("133306875d88bb063636a9165c56141ac8b30d3b993db3740f166693dfeecbb5"),
}
_CALCIFIER_RESOURCES = [
    {
        "path": "examples.md",
        "sha256": ("e5ed1413286ca10ea238b9952a3ef19db13e2f4b24b2aaf18ec908bfaacfc815"),
        "size": 1280,
        "source": None,
    },
    {
        "path": "structured-input.md",
        "sha256": ("0f33bf58db91eaabc2bbff2e4eec5c3811ab5a74866ce4698320dfa384d76f4b"),
        "size": 3368,
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
        "ed inspection that finds zero issues.\n\nFocused repair of"
        " the complete supplied native Atheris candidate. Preserve "
        "every public input, validation, host output path, command,"
        " agent prompt, launcher, corpus/minimize/reproduction oper"
        "ation and report, except the following two fixes. First co"
        "mbine exactly the four nested if statements flagged by rep"
        "ository Ruff SIM102: validate_harness ast.With/instrument_"
        "imports; corpus_input validity; reproduce/crash_input vali"
        "dity; native action/platform requirements. Use short-circu"
        "it conjunctions preserving behavior. Second fix invocation"
        ": the current uv run --no-project --python ENV_PYTHON foll"
        "owed directly by -c fails with unexpected argument. Append"
        " the explicit command token python to the invocation prefi"
        "x, after ENV_PYTHON, so locator becomes uv run --no-projec"
        "t --python ENV_PYTHON python -c CODE, and launcher command"
        "s also use that explicit interpreter. This exact corrected"
        " CLI prefix was verified locally to use the selected inter"
        "preter and installed environment. No other redesign or beh"
        "avioral changes. Keep current packaged SKILL/resources aut"
        "horitative, published Calcifier0.2 APIs, fixed trusted pat"
        "h/argv selectors, native orchestration, Python>=3.13 and c"
        "alcifier==0.2.0. No platform adapters, delegated whole-ski"
        "ll baseline, or unavailable stub. Do not emit provenance c"
        "onstants; host owns fresh metadata. Ruff E,F,I,UP,B,SIM py"
        "311 maxline100.\n"
    ),
    "sha256": ("b28ba1bf407395cc9e2dd3932130b03a903f48677fe1e8b62cb2f3216e2689b5"),
}
_CALCIFIER_SUBRECIPES = []
