# /// script
# requires-python = ">=3.13"
# dependencies = ["calcifier==0.2.0"]
# ///

"""Apply the Lean workflow and independently replay build and kernel checks."""

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
    write_text,
)

REFERENCES = (
    "references/anti-patterns.md",
    "references/library-design.md",
    "references/linting.md",
    "references/llm-techniques.md",
    "references/naming-conventions.md",
    "references/performance.md",
    "references/proof-style.md",
    "references/tactics.md",
)


@output_type
class WorkReport:
    answer: str
    incomplete_requirements: list[str]


@output_type
class Check:
    label: str
    argv: list[str]
    exit_code: int
    stdout: str
    stderr: str


@output_type
class Result:
    work: WorkReport
    checks: list[Check]
    source_count: int
    host_checks_passed: bool


def require_name(name: str) -> None:
    parts = name.split(".")
    if not name or any(not part.replace("'", "").isidentifier() for part in parts):
        fail("Use unquoted, dotted Lean identifiers for module and axiom names.")


@step
def source_inventory(project: Path, artifacts: Path) -> list[str]:
    files: list[str] = []
    for candidate in project.rglob("*.lean"):
        relative = candidate.relative_to(project)
        if any(part in {".git", ".lake"} for part in relative.parts):
            continue
        resolved = candidate.resolve()
        if resolved.is_relative_to(artifacts):
            continue
        if not resolved.is_relative_to(project):
            fail(f"Lean source escapes the project: {relative}")
        if candidate.is_file():
            files.append(relative.as_posix())
    return sorted(files)


@step
def make_axiom_check(modules: list[str], axioms: list[str]) -> str:
    reference = resource("references/linting.md").read_text(encoding="utf-8")
    blocks = [part.split("```", 1)[0] for part in reference.split("```lean\n")[1:]]
    candidates = [
        block for block in blocks if "def expectedAxioms" in block and "collectAxioms n" in block
    ]
    if len(candidates) != 1:
        fail("The linting reference must contain exactly one axiom-audit program.")
    source = candidates[0]
    expected = [line for line in source.splitlines() if line.startswith("def expectedAxioms ")]
    marker = "(`MyProject).isPrefixOf m"
    if len(expected) != 1 or source.count("import MyProject") != 1 or source.count(marker) != 1:
        fail("The supplied axiom-audit interface changed; review its adaptation.")
    imports = "import Lean\n" + "\n".join(f"import {module}" for module in modules)
    prefixes = sorted({module.split(".", 1)[0] for module in modules})
    predicate = " || ".join(f"(`{prefix}).isPrefixOf m" for prefix in prefixes)
    names = ", ".join("``" + name for name in axioms)
    declaration = f"def expectedAxioms : List Name := [{names}]"
    source = source.replace("import MyProject", imports)
    source = source.replace(marker, f"({predicate})")
    source = source.replace(expected[0], declaration)
    return source + '\n  logInfo m!"axiom audit checked {checked} declarations"\n'


@step
def run_check(label: str, argv: list[str], project: Path) -> Check:
    result = run_command(argv, timeout_seconds=600, working_directory=project, mutating=True)
    return Check(
        label=label,
        argv=result.argv,
        exit_code=result.exit_code,
        stdout=result.stdout,
        stderr=result.stderr,
    )


@recipe(
    name="writing_lean_proofs",
    version="1",
    agents=("worker",),
    capabilities=("Bash",),
    budget=Budget(max_agent_calls=2, max_wall_seconds=3600),
    output_root="lean-proof-artifacts",
)
def writing_lean_proofs(
    project_directory: str,
    task: str,
    modules: list[str],
    intent: Literal["finish", "skeleton", "review", "diagnose"] = "finish",
    build_targets: list[str] | None = None,
    expected_axioms: list[str] | None = None,
) -> Result:
    project = Path(project_directory).expanduser().resolve()
    if not project.is_dir() or not task.strip():
        fail("Supply an existing project directory and a nonempty task.")
    if not modules:
        fail("The axiom inspection requires at least one project entry module.")
    axioms = (
        ["propext", "Classical.choice", "Quot.sound"]
        if expected_axioms is None
        else expected_axioms
    )
    for name in modules + axioms:
        require_name(name)
    targets = [] if build_targets is None else build_targets
    if any(not target or target.startswith("-") for target in targets):
        fail("Build targets must be nonempty Lake target names, not options.")
    artifacts = ensure_directory(".", output_files=("AxiomCheck.lean",)).resolve()
    if project.is_relative_to(artifacts):
        fail("The project must be outside the managed recipe output directory.")
    before = source_inventory(project, artifacts)
    if not before and intent in {"review", "diagnose"}:
        fail("The inspection scope contains zero Lean source files.")
    references = tuple(resource(name) for name in REFERENCES)
    observations = {
        "project": str(project),
        "intent": intent,
        "source_files": before,
        "audit_imports": modules,
        "audit_module_prefixes": sorted({module.split(".", 1)[0] for module in modules}),
        "expected_axioms": axioms,
        "build_targets": targets,
        "reserved_output_directory": str(artifacts),
    }
    context = prepare_context(
        task,
        instructions=(
            "Carry out the task using the authoritative SKILL.md and complete references. "
            "Keep its connected reasoning workflow and required checks in one session. "
            "Apply project contribution rules and the source's conditional guidance. "
            "The supplied source inventory is preparation; inspect the full task scope. "
            "Finish the source-required searches, compiler feedback, and linter/gate tests. "
            "Use embedded context directly, reading task.txt when it is absent. "
            "For review or diagnosis, preserve sources except temporary, cleaned-up probes. "
            "Reserve the output directory for host artifacts. Do not commit. "
            "The host reruns Lake build and the reference-derived axiom audit of the listed "
            "entry modules and their imported modules matching the listed prefixes. "
            "Perform any additional verification required for task results outside that scope, "
            "including files outside default build targets, and explain coverage limits. "
            "Do not present uncompiled proof code as a completed proof. "
            "Return a user-facing answer and unfinished requested requirements. "
            "A measured negative diagnosis may be a completed deliverable."
        ),
        prior_results=json.dumps(observations, ensure_ascii=False),
        files=references,
        readable_roots=references,
    )
    work = agent(
        "worker",
        "Complete the supplied task and authoritative workflow in this session. "
        "Return the requested answer, findings, and genuine limits in the answer field.",
        working_directory=project,
        readable_paths=references,
        writable_paths=(project,),
        required_capabilities=("commands",),
        output=WorkReport,
        timeout=3600,
        context=context,
    )
    emit(work, name="work-report")
    if not work.answer.strip():
        fail("The worker returned an empty answer.")
    after = source_inventory(project, artifacts)
    if not after:
        fail("Verification reached zero Lean source files; no clean claim is possible.")
    audit = write_text("AxiomCheck.lean", make_axiom_check(modules, axioms))
    emit(str(audit), name="axiom-check-source")
    build = run_check("lake-build", ["lake", "build", *targets], project)
    emit(build, name="build")
    audit_argv = ["lake", "env", "lean", f"--root={artifacts}", str(audit.resolve())]
    kernel = run_check("axiom-audit", audit_argv, project)
    emit(kernel, name="axioms")
    checks = [build, kernel]
    checks_passed = all(check.exit_code == 0 for check in checks)
    result = Result(
        work=work,
        checks=checks,
        source_count=len(after),
        host_checks_passed=checks_passed,
    )
    emit(result, name="result")
    if "module filter matched nothing" in kernel.stdout + kernel.stderr:
        fail("The axiom audit checked zero declarations; check entry modules and scope.")
    if work.incomplete_requirements:
        fail("Requested work remains incomplete; see the emitted work report.")
    if build.exit_code != 0 and intent in {"finish", "skeleton"}:
        fail("The requested development does not compile; see the build diagnostics.")
    if kernel.exit_code != 0 and intent == "finish":
        fail("The finished development failed its kernel axiom gate.")
    return result


if __name__ == "__main__":
    raise SystemExit(writing_lean_proofs.cli())


# --- calcifier metadata (skill provenance + sha256) ---
_CALCIFIER_COMPILATION = "compiled"
_CALCIFIER_SKILL = {
    "path": "../SKILL.md",
    "sha256": ("fb2ad9c463ac5185a014892ce33202460b3423d64405024b95b534f0d3b4d3e0"),
}
_CALCIFIER_RESOURCES = [
    {
        "path": "references/anti-patterns.md",
        "sha256": ("58f1bc88b4882db7a606f606e61adf44b4cb08466e17687619561728e5e91ed3"),
        "size": 7020,
        "source": None,
    },
    {
        "path": "references/library-design.md",
        "sha256": ("23310d7a0f1d7aef86d1c4e333ec97b5569b344bf9f26c61e958ca00d0f23f99"),
        "size": 7852,
        "source": None,
    },
    {
        "path": "references/linting.md",
        "sha256": ("0ec7a48f8ffba4de4fe06d3eeb2202ca4c9a3be1bb738a33ada869afade48818"),
        "size": 22615,
        "source": None,
    },
    {
        "path": "references/llm-techniques.md",
        "sha256": ("65e4b40ebb78075cc7d383716687983fbb99f2d44933af6f70797e3d3935e112"),
        "size": 5522,
        "source": None,
    },
    {
        "path": "references/naming-conventions.md",
        "sha256": ("0b32766eff8f3ca2c4c72b20337be9ece046aad8e267f2d27b815412eadd7c6d"),
        "size": 2566,
        "source": None,
    },
    {
        "path": "references/performance.md",
        "sha256": ("f108a3e8dc1882684759ddbbad0ca5a521c84a80493246256acc82d8250e395b"),
        "size": 5417,
        "source": None,
    },
    {
        "path": "references/proof-style.md",
        "sha256": ("d631ddb9dc607229e025a53807e8dca63a9865f59e2f67b265d36888a0c39424"),
        "size": 7952,
        "source": None,
    },
    {
        "path": "references/tactics.md",
        "sha256": ("68786c8dc7dc4ad0f0743717c72472efb6179d3f78cbbfc16a980e96a6d8db0e"),
        "size": 16530,
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
