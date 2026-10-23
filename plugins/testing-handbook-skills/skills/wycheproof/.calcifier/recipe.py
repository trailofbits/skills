# /// script
# requires-python = ">=3.13"
# dependencies = ["calcifier==0.2.0"]
# ///

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Literal
from xml.etree import ElementTree

import calcifier as cf


@cf.output_type
class Inventory:
    filename: str
    algorithm: str
    total: int
    selected_ids: list[int]
    results: dict[str, int]


@cf.output_type
class Assessment:
    summary: str
    changed_files: list[str]
    result_policy: str
    findings: list[str]
    acceptable_warnings: list[str]
    ci_integration: str
    limitations: list[str]


@cf.output_type
class Report:
    assessment: Assessment
    inventory: list[Inventory]
    executed: int
    failures: int
    skipped: int
    exit_code: int


def checked(argv: list[str], root: Path) -> None:
    result = cf.run_command(argv, timeout_seconds=180, working_directory=root)
    if result.exit_code != 0:
        cf.fail(f"Setup command failed: {argv!r}\n{result.stdout}\n{result.stderr}")


@cf.step
def acquire(
    project: str,
    filenames: list[str],
    mode: Literal["existing", "submodule", "fetch"],
    directory: str,
) -> str:
    root = Path(project)
    vectors = (root / (".wycheproof" if mode == "fetch" else directory)).resolve()
    if not vectors.is_relative_to(root):
        cf.fail("The vector directory must be inside the project.")
    if mode == "submodule":
        if not vectors.is_relative_to(root / "wycheproof"):
            cf.fail("Submodule vectors must be under project/wycheproof.")
        if not (root / "wycheproof").exists():
            checked(
                ["git", "submodule", "add", "https://github.com/C2SP/wycheproof.git"],
                root,
            )
        checked(["git", "submodule", "update", "--init", "--", "wycheproof"], root)
    if mode == "fetch":
        checked(["mkdir", "-p", str(vectors)], root)
        for name in filenames:
            target = vectors / name
            if target.is_symlink():
                cf.fail(f"Refusing a symlink vector destination: {target}")
            if not target.exists():
                url = "https://raw.githubusercontent.com/C2SP/wycheproof/master/testvectors_v1/"
                checked(["curl", "--fail", "--location", "--output", str(target), url + name], root)
    return str(vectors)


@cf.step
def inspect_vectors(
    directory: str, filenames: list[str], filters: dict[str, list[int | str]]
) -> list[Inventory]:
    inventory: list[Inventory] = []
    for name in filenames:
        path = Path(directory) / name
        if path.is_symlink() or not path.is_file():
            cf.fail(f"Missing or nonregular vector file: {path}")
        raw = path.read_bytes()
        data = json.loads(raw.decode("utf-8"))
        counts = {"valid": 0, "invalid": 0, "acceptable": 0}
        seen: set[int] = set()
        selected: list[int] = []
        for group in data["testGroups"]:
            included = all(group.get(key) in values for key, values in filters.items())
            for case in group["tests"]:
                tc_id, result = case["tcId"], case["result"]
                if not isinstance(tc_id, int) or tc_id in seen or result not in counts:
                    cf.fail(f"{name}: invalid or duplicate tcId/result: {tc_id!r}, {result!r}")
                seen.add(tc_id)
                if included:
                    selected.append(tc_id)
                    counts[result] += 1
        if data["numberOfTests"] != len(seen):
            cf.fail(f"{name}: numberOfTests disagrees with the complete test inventory.")
        if not selected:
            cf.fail(f"{name}: zero vectors selected; check implementation constraints.")
        inventory.append(
            Inventory(
                filename=name,
                algorithm=data["algorithm"],
                total=len(seen),
                selected_ids=selected,
                results=counts,
            )
        )
    return inventory


@cf.recipe(
    name="wycheproof",
    version="1",
    capabilities=("Bash",),
    agents=("worker",),
    budget=cf.Budget(2, 3600),
    output_root="wycheproof-results",
)
def wycheproof(
    task: str,
    vector_files: list[str],
    project: str = ".",
    setup: Literal["existing", "submodule", "fetch"] = "existing",
    vector_directory: str = "wycheproof/testvectors_v1",
    runner: Literal["pytest", "mocha"] = "pytest",
    group_filters: dict[str, list[int | str]] | None = None,
) -> Report:
    root = Path(project).resolve()
    if not root.is_dir():
        cf.fail("The project must be an existing directory.")
    if not vector_files or len(set(vector_files)) != len(vector_files):
        cf.fail("Select a nonempty list of distinct vector filenames.")
    if any(re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]*\.json", n) is None for n in vector_files):
        cf.fail("Vector inputs must be JSON basenames without directory components.")
    out = cf.ensure_directory(
        ".", output_files=("junit.xml", "mocha.json", "stdout.txt", "stderr.txt", "report.json")
    )
    vectors = Path(acquire(str(root), vector_files, setup, vector_directory))
    filters = group_filters or {}
    inventory = inspect_vectors(str(vectors), vector_files, filters)
    harness = "tests/test_wycheproof_calcifier.py" if runner == "pytest" else "test/wycheproof.cjs"
    argv = (
        ["python", "-m", "pytest", "-q", harness]
        if runner == "pytest"
        else ["npx", "--no-install", "mocha", harness]
    )
    metadata = {
        "setup": setup,
        "vector_directory": str(vectors),
        "harness": harness,
        "execution_argv": argv,
        "group_filters": filters,
        "inventory": [item.model_dump() for item in inventory],
    }
    context = cf.prepare_context(
        task,
        prior_results=json.dumps(metadata),
        files=tuple(vectors / name for name in vector_files),
        readable_roots=(root,),
    )
    assessment = cf.agent(
        "worker",
        (
            "Implement the task under the authoritative source in one connected session. "
            "Setup and indexing are prepared; interpret complete vectors, headers, notes "
            "and group attributes. Use embedded context; read full bundle files when absent. "
            "Write the parameterized harness at harness, cover every selected case and "
            "applicable direction, run execution_argv, investigate failures against code, "
            "propose fixes and integrate CI vector updates. Respect declared group_filters; "
            "explain unsupported constraints and acceptable/result-policy ambiguities. "
            "Each finding: file, tcId, operation, comment, flags and meanings from notes, "
            "expected/actual behavior, root cause or uncertainty, proposed fix. "
            "Change implementation only when authorized. Report actual checks, CI changes, "
            "acceptable warnings and all unperformed work or limitations."
        ),
        working_directory=root,
        readable_paths=(root,),
        writable_paths=(root,),
        required_capabilities=("commands",),
        output=Assessment,
        context=context,
        timeout=3600,
    )
    cf.emit(assessment, name="integration")
    options = (
        ["--junitxml", str(out / "junit.xml")]
        if runner == "pytest"
        else ["--reporter", "json", "--reporter-option", "output=" + str(out / "mocha.json")]
    )
    result = cf.run_command(argv + options, timeout_seconds=600, working_directory=root)
    cf.write_text("stdout.txt", result.stdout)
    cf.write_text("stderr.txt", result.stderr)
    try:
        if runner == "pytest":
            xml = (out / "junit.xml").read_text(encoding="utf-8")
            cases = list(ElementTree.fromstring(xml).iter("testcase"))
            skipped = sum(case.find("skipped") is not None for case in cases)
            executed = len(cases) - skipped
            failures = sum(
                case.find("failure") is not None or case.find("error") is not None for case in cases
            )
        else:
            stats = json.loads((out / "mocha.json").read_text(encoding="utf-8"))["stats"]
            failures, skipped = int(stats["failures"]), int(stats["pending"])
            executed = int(stats["passes"]) + failures
    except (OSError, ValueError, KeyError, ElementTree.ParseError) as error:
        cf.fail(f"Cannot inspect test results: {error}. See stdout.txt and stderr.txt.")
    report = Report(
        assessment=assessment,
        inventory=inventory,
        executed=executed,
        failures=failures,
        skipped=skipped,
        exit_code=result.exit_code,
    )
    cf.write_json("report.json", report.model_dump())
    cf.emit(report, name="wycheproof")
    if executed == 0:
        cf.fail("Zero non-skipped tests ran; no cryptographic validation was performed.")
    if result.exit_code != 0 or failures:
        cf.fail("Wycheproof tests failed; inspect the emitted report and execution logs.")
    return report


if __name__ == "__main__":
    raise SystemExit(wycheproof.cli())


# --- calcifier metadata (skill provenance + sha256) ---
_CALCIFIER_COMPILATION = "compiled"
_CALCIFIER_SKILL = {
    "path": "../SKILL.md",
    "sha256": ("d092dc70fbd0f86d1f755857bf57172a6593cae0bff5d052443fc60b8d675a33"),
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
