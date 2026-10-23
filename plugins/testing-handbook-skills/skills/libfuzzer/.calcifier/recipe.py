# /// script
# requires-python = ">=3.13"
# dependencies = ["calcifier==0.2.0"]
# ///

import json
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
    verify_artifact,
    write_text,
)


@output_type
class Observation:
    stage: str
    argv: list[str]
    exit_code: int
    stdout: str
    stderr: str


@output_type
class Harness:
    source: str
    dictionary: str
    explanation: str


@output_type
class Report:
    operation: str
    assessment: str
    observations: list[Observation]
    artifacts: list[str]
    unperformed: list[str]


def checked(root: Path, name: str, directory: bool = False) -> Path:
    path = (root / name).resolve()
    exists = path.is_dir() if directory else path.is_file()
    if not path.is_relative_to(root) or not exists:
        fail(f"Expected an existing {'directory' if directory else 'file'} inside {root}: {name}")
    return path


@step
def execute(
    stage: str, argv: list[str], cwd: Path, seconds: float, mutating: bool = True
) -> Observation:
    result = run_command(argv, working_directory=cwd, timeout_seconds=seconds, mutating=mutating)
    return emit(
        Observation(stage, result.argv, result.exit_code, result.stdout, result.stderr),
        name=stage,
    )


@recipe(
    version="1",
    agents=("worker",),
    capabilities=("Bash",),
    budget=Budget(max_agent_calls=2, max_wall_seconds=3600),
    output_root="libfuzzer-results",
)
def libfuzzer(
    project_directory: str,
    source_files: tuple[str, ...],
    request: str,
    operation: Literal[
        "prepare", "campaign", "reproduce", "minimize", "coverage", "diagnose"
    ] = "prepare",
    harness_file: str = "harness.cc",
    evidence_files: tuple[str, ...] = (),
    seed_directory: str = "",
    dictionary_file: str = "",
    crash_file: str = "",
    compiler: str = "clang++",
    compile_flags: tuple[str, ...] = (),
    sanitizer: Literal["address", "undefined", "address,undefined", "memory", "none"] = "address",
    seconds: int = 60,
    max_len: int = 4000,
) -> Report:
    root = Path(project_directory).resolve()
    if not root.is_dir() or not request.strip():
        fail("Supply an existing project directory and a nonempty target/task description.")
    if not 1 <= seconds <= 600 or max_len < 1:
        fail("Use a bounded experiment of 1..600 seconds and a positive maximum input length.")
    sources = [checked(root, name) for name in source_files]
    evidence = [checked(root, name) for name in evidence_files]
    seed = checked(root, seed_directory, True) if seed_directory else None
    dictionary = checked(root, dictionary_file) if dictionary_file else None
    crash = checked(root, crash_file) if crash_file else None
    out = ensure_directory(
        ".",
        output_files=("harness.cc", "format.dict", "fuzz", "coverage.profdata", "coverage.html"),
    ).resolve()
    corpus = ensure_directory("corpus").resolve()
    artifacts = ensure_directory("artifacts").resolve()
    profiles = ensure_directory("profiles").resolve()
    harness = out / "harness.cc"
    if operation not in {"prepare", "diagnose"}:
        harness = checked(root, harness_file)
    targets = sources + evidence
    if operation not in {"prepare", "diagnose"} and harness not in targets:
        targets.append(harness)
    if not targets:
        fail("The inspection scope contains zero files; select target sources or evidence.")
    if operation == "prepare" and not sources:
        fail("Harness preparation needs the complete target sources, not an empty target scope.")
    if operation == "reproduce" and crash is None:
        fail("Reproduction requires crash_file.")
    if operation == "minimize" and (
        seed is None or not any(path.is_file() for path in seed.rglob("*"))
    ):
        fail("Corpus minimization would inspect zero inputs; supply a nonempty seed directory.")
    notes: list[Observation] = []
    unperformed: list[str] = []
    assessment = ""
    config: dict[str, object] = {
        "operation": operation,
        "target_and_evidence_files": [str(path) for path in targets],
        "seed_directory": str(seed) if seed else None,
        "dictionary": str(dictionary) if dictionary else None,
        "crash": str(crash) if crash else None,
        "compile_flags": list(compile_flags),
        "sanitizer": sanitizer,
        "output_directory": str(out),
    }
    instructions = (
        "Follow the authoritative skill's applicable workflow in order, retaining its checks. "
        "Read all declared targets/evidence in full; project and output are readable for context. "
        "Searches do not narrow semantic scope. Keep reasoning internal and uncertainty explicit. "
        "Do not install software or change project files. State unavailable references and "
        "remaining work. Do not claim related skills or online research were consulted."
    )
    if operation == "prepare":
        context = prepare_context(
            request, instructions=instructions, prior_results=json.dumps(config)
        )
        draft = agent(
            "worker",
            "Design one focused LLVMFuzzerTestOneInput harness for the complete target, "
            "following all source-skill harness checks. Return complete C++ source, an optional "
            "dictionary, and integration guidance. Python compiles the supplied sources/flags "
            "with O2, debug symbols and selected sanitizers. Do not invent APIs or claim the "
            "future compilation or campaign has passed.",
            working_directory=root,
            readable_paths=(root, out),
            context=context,
            output=Harness,
        )
        if not draft.source.strip() or not draft.explanation.strip():
            fail("Harness design is incomplete; target understanding and integration need review.")
        write_text("harness.cc", draft.source)
        if draft.dictionary.strip():
            dictionary = write_text("format.dict", draft.dictionary).resolve()
        assessment = draft.explanation
    if operation != "diagnose":
        flags = ["-fsanitize=fuzzer" + ("," + sanitizer if sanitizer != "none" else "")]
        flags += ["-g", "-O2", "-U_FORTIFY_SOURCE"]
        if operation == "coverage":
            flags += ["-fprofile-instr-generate", "-fcoverage-mapping"]
        binary = out / "fuzz"
        units = sources if harness in sources else [harness, *sources]
        argv = [compiler, *flags, *[str(path) for path in units], *compile_flags, "-o", str(binary)]
        built = execute("build", argv, out, 180)
        notes.append(built)
        if built.exit_code != 0:
            unperformed.append(f"{operation}: build failed; no dependent execution was attempted.")
        else:
            verify_artifact(binary)
            if operation != "prepare":
                argv = [str(binary), f"-artifact_prefix={artifacts}/"]
                if operation == "reproduce":
                    argv.append(str(crash))
                elif operation == "minimize":
                    argv += ["-merge=1", str(corpus), str(seed)]
                else:
                    argv += [f"-max_total_time={seconds}", "-timeout=2", f"-max_len={max_len}"]
                    if dictionary is not None:
                        argv.append(f"-dict={dictionary}")
                    if operation == "coverage":
                        profile_env = f"LLVM_PROFILE_FILE={profiles}/coverage-%p.profraw"
                        argv = ["env", profile_env, *argv, "-runs=10000"]
                    argv += [str(corpus)] + ([str(seed)] if seed else [])
                notes.append(execute(operation, argv, out, seconds + 60))
                if operation == "coverage":
                    raw = sorted(profiles.glob("*.profraw"))
                    if not raw:
                        fail("Coverage produced zero profiles; no coverage check occurred.")
                    merged = execute(
                        "profile-merge",
                        [
                            "llvm-profdata",
                            "merge",
                            "-sparse",
                            *[str(path) for path in raw],
                            "-o",
                            str(out / "coverage.profdata"),
                        ],
                        out,
                        120,
                    )
                    notes.append(merged)
                    if merged.exit_code == 0:
                        base = [
                            "llvm-cov",
                            "show",
                            str(binary),
                            f"-instr-profile={out / 'coverage.profdata'}",
                        ]
                        notes.append(execute("coverage-text", base, out, 120, False))
                        html = execute("coverage-html", [*base, "-format=html"], out, 120, False)
                        notes.append(html)
                        if html.exit_code == 0:
                            write_text("coverage.html", html.stdout)
                            verify_artifact(out / "coverage.html")
                    else:
                        unperformed.append("Coverage rendering: profile merging failed.")
    if operation != "prepare":
        config["observations"] = [note.model_dump() for note in notes]
        config["unperformed"] = unperformed
        context = prepare_context(
            request, instructions=instructions, prior_results=json.dumps(config)
        )
        assessment = agent(
            "worker",
            "Apply the skill to the complete target and experiment evidence for the requested "
            "diagnosis/triage. Inspect artifacts; distinguish observations from hypotheses. "
            "Give actionable harness/build/corpus/dictionary/coverage advice. Campaign crashes "
            "without replay remain unconfirmed; reproduction mode supplies a replay log. "
            "State remaining execution/changes. A bounded run cannot establish bug absence.",
            working_directory=root,
            readable_paths=(root, out),
            context=context,
            output=str,
        )
    if not assessment.strip():
        fail("The agent returned no assessment of the nonempty inspection scope.")
    files = [str(path) for path in sorted(out.rglob("*")) if path.is_file()]
    return emit(Report(operation, assessment, notes, files, unperformed), name="libfuzzer-report")


if __name__ == "__main__":
    raise SystemExit(libfuzzer.cli())


# --- calcifier metadata (skill provenance + sha256) ---
_CALCIFIER_COMPILATION = "compiled"
_CALCIFIER_SKILL = {
    "path": "../SKILL.md",
    "sha256": ("56b2c68b193f7fed4ae00ade6c6395196d44612d140ad51de43d150404dde2eb"),
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
