# /// script
# requires-python = ">=3.13"
# dependencies = ["calcifier==0.2.0"]
# ///

"""Apply and assess fuzzing-obstacle patches in one connected worker session."""

import hashlib
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
    step,
)

_MARKERS = re.compile(
    r"\b(checksum|crc\w*|hash\w*|validat\w*|verif\w*|magic|"
    r"rand|srand|random\w*|time|getenv)\b|"
    r"FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION|cfg!\s*\(\s*fuzzing",
    re.IGNORECASE,
)


@output_type
class FileObservation:
    path: str
    sha256: str
    matching_lines: list[int]


@output_type
class TreeSnapshot:
    files: list[FileObservation]
    skipped_symlinks: list[str]


@output_type
class FileChange:
    path: str
    kind: Literal["added", "modified", "removed"]
    before_sha256: str | None
    after_sha256: str | None


@output_type
class Measurement:
    baseline: float | None
    patched: float | None
    unit: str
    evidence: str


@output_type
class Patch:
    location: str
    description: str
    production_behavior: str
    invariant_risk: str


@output_type
class Assessment:
    outcome: Literal["skipped", "patched", "incomplete"]
    summary: str
    inspected_targets: list[str]
    patches: list[Patch]
    line_coverage: Measurement
    basic_block_coverage: Measurement
    function_coverage: Measurement
    corpus_size: Measurement
    build_and_run_evidence: str
    production_behavior: str
    determinism: str
    false_positive_risk: str
    limitations: list[str]


@output_type
class RunReport:
    assessment: Assessment
    observed_changes: list[FileChange]
    coverage_deltas: dict[str, float | None]


@step
def snapshot_tree(directory: str) -> TreeSnapshot:
    root = Path(directory).resolve()
    files: list[FileObservation] = []
    links: list[str] = []
    for path in sorted(root.rglob("*")):
        relative = path.relative_to(root)
        if ".git" in relative.parts:
            continue
        name = relative.as_posix()
        if path.is_symlink():
            links.append(name)
            continue
        if not path.is_file():
            continue
        if not path.resolve().is_relative_to(root):
            fail(f"Inspection path escapes the project: {name}")
        data = path.read_bytes()
        try:
            text = data.decode("utf-8")
        except UnicodeDecodeError:
            text = ""
        matches = [
            number for number, line in enumerate(text.splitlines(), 1) if _MARKERS.search(line)
        ]
        files.append(
            FileObservation(
                path=name,
                sha256=hashlib.sha256(data).hexdigest(),
                matching_lines=matches,
            )
        )
    if not files:
        fail("Inspection scope has no regular files outside .git; provide a nonempty SUT.")
    return TreeSnapshot(files=files, skipped_symlinks=links)


@step
def compare_trees(before: TreeSnapshot, after: TreeSnapshot) -> list[FileChange]:
    left = {item.path: item.sha256 for item in before.files}
    right = {item.path: item.sha256 for item in after.files}
    changes: list[FileChange] = []
    for name in sorted(left.keys() | right.keys()):
        old = left.get(name)
        new = right.get(name)
        if old == new:
            continue
        kind: Literal["added", "modified", "removed"] = "modified"
        if old is None:
            kind = "added"
        elif new is None:
            kind = "removed"
        changes.append(FileChange(path=name, kind=kind, before_sha256=old, after_sha256=new))
    return changes


@step
def coverage_deltas(assessment: Assessment) -> dict[str, float | None]:
    measures = {
        "line_coverage": assessment.line_coverage,
        "basic_block_coverage": assessment.basic_block_coverage,
        "function_coverage": assessment.function_coverage,
        "corpus_size": assessment.corpus_size,
    }
    deltas: dict[str, float | None] = {}
    for name, measure in measures.items():
        baseline = measure.baseline
        patched = measure.patched
        deltas[name] = None if baseline is None or patched is None else patched - baseline
    return deltas


@recipe(
    name="fuzzing-obstacles",
    version="1",
    agents=("worker",),
    budget=Budget(max_agent_calls=2, max_wall_seconds=3600),
)
def overcome_fuzzing_obstacles(project_directory: str, target: str) -> RunReport:
    root = Path(project_directory).resolve()
    if not root.is_dir():
        fail("project_directory must be an existing project directory.")
    if not target.strip():
        fail("Specify the fuzzer, harness, entry point, or obstacle to investigate.")
    before = snapshot_tree(str(root))
    context = prepare_context(
        task=(
            f"Project directory: {root}\nRequested target and task: {target}\n"
            "Apply the authoritative fuzzing-obstacles skill in this single session. "
            "Follow its applicability criteria and original ordered workflow, including "
            "baseline investigation, incremental patches, coverage verification, and "
            "downstream invariant and false-positive analysis. Keep this reasoning connected.\n"
            "The full-tree inventory supplies hashes and heuristic matching line numbers. "
            "Matches are observations, not an exhaustive set of semantic candidates. "
            "Inspect the complete relevant files and the whole requested target. "
            "The project filesystem view preserves their full contents.\n"
            "Use project-specific commands for instrumented builds and short fuzz runs. "
            "Establish the unpatched baseline before changing the SUT. Verify actual build "
            "flags, production behavior, and reproducibility. Apply the source's safeguards "
            "and documentation requirements, refining unsafe patches when necessary. "
            "You may edit within the project; do not commit.\n"
            "Return Assessment with inspected locations, patches, measurement evidence, "
            "build/run results, production behavior, determinism, risk, and limitations. "
            "Metrics must use comparable baseline and patched units. Unavailable values "
            "must be null with reasons in evidence. Use skipped for a reasoned decision "
            "not to patch, patched only after the required verification succeeds, and "
            "incomplete for unfinished work. Never invent measurements or completed checks. "
            "Filesystem hashes and computed deltas do not replace your required analysis."
        ),
        prior_results=before.model_dump_json(),
    )
    assessment = agent(
        "worker",
        "Use the complete prepared assignment and inventory directly. Read task.txt in "
        "the context bundle if the complete assignment was not embedded. Follow the "
        "authoritative source instructions and return the requested Assessment.",
        working_directory=root,
        readable_paths=(root,),
        writable_paths=(root,),
        required_capabilities=("commands",),
        output=Assessment,
        timeout=3600,
        context=context,
    )
    after = snapshot_tree(str(root))
    changes = compare_trees(before, after)
    deltas = coverage_deltas(assessment)
    report = RunReport(
        assessment=assessment,
        observed_changes=changes,
        coverage_deltas=deltas,
    )
    emit(report, name="fuzzing-obstacles")
    if not assessment.inspected_targets:
        fail("The worker inspected zero targets; no completed assessment can be reported.")
    if assessment.outcome == "incomplete":
        fail("Fuzzing-obstacle work remains incomplete: " + assessment.summary)
    if assessment.outcome == "patched":
        if not assessment.patches or not changes:
            fail("A patched outcome requires documented patches and observed file changes.")
        comparable = any(
            delta is not None for name, delta in deltas.items() if name != "corpus_size"
        )
        if not comparable:
            fail("A patched outcome requires comparable baseline and patched coverage evidence.")
    return report


if __name__ == "__main__":
    raise SystemExit(overcome_fuzzing_obstacles.cli())


# --- calcifier metadata (skill provenance + sha256) ---
_CALCIFIER_COMPILATION = "compiled"
_CALCIFIER_SKILL = {
    "path": "../SKILL.md",
    "sha256": ("7d77500c3e0a2db1ce5fd5dbb0559b802a621c63110dd8fd4664f0bf1634a3b2"),
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
