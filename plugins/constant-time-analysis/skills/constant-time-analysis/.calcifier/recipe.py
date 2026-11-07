# /// script
# requires-python = ">=3.13"
# dependencies = ["calcifier==0.2.0"]
# ///

"""Statically audit sources using an explicitly supplied ct_analyzer installation."""

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
    resource,
    run_command,
    step,
)

Architecture = Literal["x86_64", "arm64", "arm", "riscv64", "ppc64le", "s390x", "i386"]
NativeLanguage = Literal["c", "cpp", "go", "rust", "swift"]
ROUTES = {
    extension: (language, f"references/{guide}.md")
    for language, guide, extensions in (
        ("c", "compiled", (".c",)),
        ("cpp", "compiled", (".C", ".cc", ".cpp", ".cxx")),
        ("go", "compiled", (".go",)),
        ("rust", "compiled", (".rs",)),
        ("swift", "swift", (".swift",)),
        ("java", "vm-compiled", (".java",)),
        ("cs", "vm-compiled", (".cs",)),
        ("kotlin", "kotlin", (".kt", ".kts")),
        ("php", "php", (".php",)),
        ("javascript", "javascript", (".js",)),
        ("typescript", "javascript", (".ts",)),
        ("python", "python", (".py",)),
        ("ruby", "ruby", (".rb",)),
    )
    for extension in extensions
}
COMPILERS: dict[str, tuple[str, ...]] = {
    "c": ("clang",),
    "cpp": ("clang",),
    "go": ("go",),
    "rust": ("rustc",),
    "swift": ("swiftc",),
}


@output_type
class Execution:
    index: int
    configuration: dict[str, str]
    exit_code: int
    stdout: str
    stderr: str
    json_valid: bool


@output_type
class Finding:
    location: str
    operation: str
    verdict: Literal["true_positive", "false_positive", "unresolved"]
    data_flow: str
    remediation: str


@output_type
class RunReview:
    index: int
    assessment: str
    findings: list[Finding]


@output_type
class Review:
    applicability: str
    summary: str
    runs: list[RunReview]
    remediation: str
    fix_verification: str
    limitations: str


@output_type
class Report:
    executions: list[Execution]
    review: Review


def select_sources(root: Path, sources: tuple[str, ...]) -> list[Path]:
    candidates = [root / name for name in sources] if sources else root.rglob("*")
    selected = sorted(
        {
            path
            for path in candidates
            if path.is_file() and ".git" not in path.parts and path.suffix in ROUTES
        }
    )
    if sources and len(selected) != len(set(sources)):
        fail("Every explicit source must be a supported regular file outside .git.")
    if not selected:
        fail(f"No supported source files to inspect in {root}.")
    if any(not path.resolve().is_relative_to(root) for path in selected):
        fail("A selected source escapes its project directory.")
    return selected


@step
def sweep(plan: list[dict[str, str]], analyzer: str, cwd: str) -> list[Execution]:
    executions: list[Execution] = []
    for index, config in enumerate(plan):
        argv = ["uv", "run", analyzer, "--warnings", "--json"]
        if config["compiler"]:
            argv.extend(["--compiler", config["compiler"], "--arch", config["architecture"]])
            argv.extend(["--opt-level", config["optimization"]])
        argv.append(config["source"])
        result = run_command(argv, timeout_seconds=180, working_directory=cwd, mutating=True)
        try:
            valid = isinstance(json.loads(result.stdout), (dict, list))
        except json.JSONDecodeError:
            valid = False
        executions.append(
            Execution(index, config, result.exit_code, result.stdout, result.stderr, valid)
        )
    return executions


@recipe(
    version="1",
    agents=("worker",),
    capabilities=("Bash",),
    budget=Budget(max_agent_calls=2, max_wall_seconds=3600),
    output_root="constant-time-analysis",
)
def constant_time_analysis(
    project_directory: str,
    analyzer_path: str,
    request: str,
    sources: tuple[str, ...] = (),
    architectures: tuple[Architecture, ...] = ("x86_64", "arm64"),
    compilers: dict[NativeLanguage, dict[Architecture, list[str]]] | None = None,
    fixed_project_directory: str | None = None,
) -> Report:
    """Audit selected files, or every supported source; optionally compare a supplied fix."""
    analyzer = Path(analyzer_path).resolve()
    if not analyzer.is_file() or not analyzer.read_text(encoding="utf-8").strip():
        fail("Supply an installed ct_analyzer/analyzer.py; the analyzer is not packaged.")
    projects = [("original", Path(project_directory).resolve())]
    if fixed_project_directory is not None:
        projects.append(("fixed", Path(fixed_project_directory).resolve()))
    arches = tuple(dict.fromkeys(architectures))
    choices: dict[str, dict[str, tuple[str, ...]]] = {
        language: {arch: binaries for arch in arches} for language, binaries in COMPILERS.items()
    }
    for language, targets in (compilers or {}).items():
        for arch, binaries in targets.items():
            if arch not in arches or not binaries or any(not binary.strip() for binary in binaries):
                fail(f"Invalid compiler configuration for {language}/{arch}.")
            choices[language][arch] = tuple(dict.fromkeys(binaries))
    plan: list[dict[str, str]] = []
    files: list[Path] = [analyzer]
    guides: set[Path] = set()
    for snapshot, root in projects:
        if not root.is_dir():
            fail(f"Project directory does not exist: {root}")
        for source in select_sources(root, sources):
            language, guide = ROUTES[source.suffix]
            files.append(source)
            guides.add(resource(guide))
            configurations = [("", "", "")]
            if language in choices:
                if len(arches) < 2:
                    fail("Native analysis requires at least two distinct architectures.")
                configurations = [
                    (compiler, arch, level)
                    for arch in arches
                    for compiler in choices[language][arch]
                    for level in ("O0", "O1", "O2", "O3", "Os", "Oz")
                ]
            for compiler, arch, level in configurations:
                plan.append(
                    {
                        "snapshot": snapshot,
                        "project": str(root),
                        "source": str(source),
                        "language": language,
                        "compiler": compiler,
                        "architecture": arch,
                        "optimization": level,
                    }
                )
    work = ensure_directory("work", output_files=())
    executions = sweep(plan, str(analyzer), str(work))
    emit(executions, name="analyzer-sweep")
    if not any(item.json_valid and item.exit_code in (0, 1) for item in executions):
        fail("No configuration produced analyzable JSON; inspect the emitted toolchain failures.")
    readable = tuple(root for _, root in projects) + (analyzer.parent,) + tuple(sorted(guides))
    context = prepare_context(
        task=request,
        instructions=(
            "Follow all authoritative skill instructions in one session. Python selected "
            "full sources and guides and attempted the sweep. Read complete applicable "
            "guides before interpretation, trace callers, and triage every error and warning. "
            "Return one RunReview per execution; include false positives and unresolved "
            "items with justified data flow. Account for failures and requested versus "
            "actual settings. Assess any fix's full sweep and prove full-domain arithmetic "
            "equivalence or leave it unresolved; without a fix, verification is pending. "
            "Never execute code under test or change projects. Use embedded context directly, "
            "reading complete backing files when absent or checking files."
        ),
        prior_results=json.dumps([item.model_dump() for item in executions]),
        files=tuple(files) + tuple(sorted(guides)),
        readable_roots=readable,
    )
    review = agent(
        "worker",
        "Complete the assigned audit and return the structured review.",
        working_directory=projects[0][1],
        readable_paths=readable,
        required_capabilities=("commands",),
        context=context,
        output=Review,
        timeout=3600,
    )
    indices = [row.index for row in review.runs]
    if len(indices) != len(executions) or set(indices) != set(range(len(executions))):
        fail("The review omitted or duplicated configurations; complete triage is required.")
    for row in review.runs:
        if not row.assessment.strip():
            fail(f"Missing interpretation for execution {row.index}.")
        for finding in row.findings:
            fields = (finding.location, finding.operation, finding.data_flow)
            if not all(value.strip() for value in fields):
                fail(f"A finding lacks its location, operation, or data flow in run {row.index}.")
            if finding.verdict == "true_positive" and not finding.remediation.strip():
                fail(f"A confirmed finding lacks remediation in run {row.index}.")
    review.runs.sort(key=lambda row: row.index)
    return emit(Report(executions, review), name="constant-time-review")


if __name__ == "__main__":
    raise SystemExit(constant_time_analysis.cli())


# --- calcifier metadata (skill provenance + sha256) ---
_CALCIFIER_COMPILATION = "compiled"
_CALCIFIER_SKILL = {
    "path": "../SKILL.md",
    "sha256": ("4807f710a234e2520d7e163cc5a0e55785a495b2790dadcd7f0952dd6bff8d07"),
}
_CALCIFIER_RESOURCES = [
    {
        "path": "references/compiled.md",
        "sha256": ("7c6f69897fc9629c4f26011507685e6cb4b79f1e1881f6f3a23d8e136f1d42fb"),
        "size": 4108,
        "source": None,
    },
    {
        "path": "references/javascript.md",
        "sha256": ("77cf536e1a123cf05927deb21a8da26e72308296370af314475c50f59eadd5ac"),
        "size": 4449,
        "source": None,
    },
    {
        "path": "references/kotlin.md",
        "sha256": ("798bc4c6d9ba1195e93d8371780866b09bccf2e096ccfa8aeb20dcc9af0a8c9f"),
        "size": 6784,
        "source": None,
    },
    {
        "path": "references/php.md",
        "sha256": ("59dcadfb56202fe6ecaeed933b968c44311adf51366e6cc2720342a880334d33"),
        "size": 5258,
        "source": None,
    },
    {
        "path": "references/python.md",
        "sha256": ("6f89ca8a5e54a2aa50e1c39783d2bc0f8b1fdbd6e771700b4b8325069fdc565b"),
        "size": 5261,
        "source": None,
    },
    {
        "path": "references/ruby.md",
        "sha256": ("51f08d9c9d74a1630866ed5b2867e39aa77b5f9f5a3a6153d215b98669b1b5f0"),
        "size": 5391,
        "source": None,
    },
    {
        "path": "references/swift.md",
        "sha256": ("419f8a9a3fc0944a064b3d4a9e473a91bd38d907a37b234d819cd8de62441226"),
        "size": 8194,
        "source": None,
    },
    {
        "path": "references/vm-compiled.md",
        "sha256": ("dc6b012f43e383ed30047642673e23d91b73cca49efdabcb940550d9edb30a0b"),
        "size": 11557,
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
        "ed inspection that finds zero issues."
    ),
    "sha256": ("12c73b0662a6bdb615688c499f4e3e22540e4788549e5ad24bb7e01f76c25fcc"),
}
_CALCIFIER_SUBRECIPES = []
