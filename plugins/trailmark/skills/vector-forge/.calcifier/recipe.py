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
    resource,
    run_command,
    step,
    verify_artifact,
    write_json,
    write_text,
)

Status = Literal["killed", "survived", "not_covered", "timed_out", "unviable"]
STATUSES: tuple[Status, ...] = ("killed", "survived", "not_covered", "timed_out", "unviable")


@output_type
class Run:
    outcomes: dict[str, Status]
    log: str


@output_type
class Implementation:
    name: str
    language: str
    kind: Literal["pure", "native", "generated"]
    framework: str
    api_surface: str
    existing_tests: str
    graph_notes: str
    graph_log: str
    baseline: Run
    new_only: Run
    combined: Run
    escapes: dict[str, str]


@output_type
class Vector:
    tc_id: int
    code_path: str
    expected_kill: str
    cross_checks: dict[str, str]


@output_type
class Findings:
    blocked_reason: str
    algorithm: str
    specification: str
    implementations: list[Implementation]
    verifiers: dict[str, str]
    vectors_json: str
    vectors: list[Vector]
    fault_simulation: str
    conclusions: str


def counts(run: Run) -> list[int]:
    return [len(run.outcomes), *(list(run.outcomes.values()).count(s) for s in STATUSES)]


def pct(numerator: int, denominator: int) -> str:
    return f"{100 * numerator / denominator:.2f}%" if denominator else "n/a"


def table(headers: list[str], rows: list[list[str]]) -> str:
    return "\n".join(
        "| " + " | ".join(cell.replace("|", r"\|").replace("\n", "<br>") for cell in row) + " |"
        for row in [headers, ["---"] * len(headers), *rows]
    )


def metrics(implementations: list[Implementation], mode: str) -> str:
    rows: list[list[str]] = []
    for item in implementations:
        runs = {"baseline": item.baseline, "new_only": item.new_only, "combined": item.combined}
        n, k, s, u, t, v = counts(runs[mode])
        rows.append([item.name, *map(str, [n, k, s, u, t, v]), pct(k, k + s), pct(n - u, n)])
    headers = "Library|Total|Killed|Survived|Not covered|Timeouts|Unviable|Efficacy|Coverage"
    return table(headers.split("|"), rows)


@step
def check_results(result: Findings) -> list[int]:
    data = json.loads(result.vectors_json)
    if not isinstance(data, dict) or not data.get("algorithm"):
        fail("The new vector suite must be a Wycheproof JSON object with an algorithm.")
    groups = data.get("testGroups")
    if not isinstance(groups, list) or not groups:
        fail("No new test groups were supplied.")
    ids: list[int] = []
    for group in groups:
        if not isinstance(group, dict) or not isinstance(group.get("tests"), list):
            fail("Each test group needs a tests array.")
        for vector in group["tests"]:
            required = {"tcId", "comment", "result", "flags"}
            if not isinstance(vector, dict) or not required.issubset(vector):
                fail("A vector lacks required Wycheproof fields.")
            if type(vector["tcId"]) is not int or not vector["comment"]:
                fail("Each vector needs an integer tcId and a purpose.")
            if not isinstance(vector["flags"], list) or not isinstance(vector["result"], str):
                fail("Invalid vector flags or result.")
            ids.append(vector["tcId"])
    supplied = [vector.tc_id for vector in result.vectors]
    if not ids or len(ids) != len(set(ids)) or sorted(ids) != sorted(supplied):
        fail("Every new vector must have exactly one verification and targeting record.")
    if "numberOfTests" in data and data["numberOfTests"] != len(ids):
        fail("numberOfTests disagrees with the new suite.")
    for vector in result.vectors:
        checks = vector.cross_checks
        if len(checks) < 2 or any(not value.strip() for value in checks.values()):
            fail("Every vector requires actual verification results from two implementations.")
        if not set(checks).issubset(result.verifiers):
            fail("Unknown verification implementation.")
        if len({result.verifiers[name] for name in checks}) < 2:
            fail("Verification must use independent codebases.")
    implementations = result.implementations
    if not implementations or not any(item.kind == "pure" for item in implementations):
        fail("At least one pure implementation must be mutation-tested.")
    for item in implementations:
        if not item.graph_log.strip() or not item.graph_notes.strip():
            fail("Missing Trailmark output or coverage, diagnostic, and resolution analysis.")
        baseline = item.baseline.outcomes
        for run in (item.baseline, item.new_only, item.combined):
            if not run.log.strip() or not run.outcomes or "timed_out" in run.outcomes.values():
                fail("Missing mutation evidence or unresolved timeouts.")
            if set(run.outcomes) != set(baseline):
                fail("The three runs must use identical inventories and stable source IDs.")
        escaped = {key for key, value in baseline.items() if value in ("survived", "not_covered")}
        if set(item.escapes) != escaped or not all(map(str.strip, item.escapes.values())):
            fail("Every escaped mutant requires individual graph-informed triage.")
        if any(
            value == "killed" and item.combined.outcomes[key] != "killed"
            for key, value in baseline.items()
        ):
            fail("The combined run regressed a baseline kill.")
    if not result.fault_simulation.strip() or not result.conclusions.strip():
        fail("Missing fault simulation analysis or conclusions.")
    return ids


def render(result: Findings) -> str:
    parts = [
        "# Vector Forge Report",
        "## Target Algorithm",
        f"{result.algorithm}\n\n{result.specification}",
        "## Implementations Tested",
    ]
    parts.append(
        table(
            ["Library", "Language", "Type", "Framework", "API", "Existing tests"],
            [
                [
                    item.name,
                    item.language,
                    item.kind,
                    item.framework,
                    item.api_surface,
                    item.existing_tests,
                ]
                for item in result.implementations
            ],
        )
    )
    parts.extend(
        [
            "## Baseline Results (Existing Vectors Only)",
            metrics(result.implementations, "baseline"),
            "## Escape Analysis",
        ]
    )
    for item in result.implementations:
        parts.extend(
            [
                f"### {item.name}",
                item.graph_notes,
                f"Total escaped: {len(item.escapes)}",
                table(["Mutant", "Analysis"], [list(pair) for pair in item.escapes.items()]),
            ]
        )
    parts.extend(
        [
            "## New Vectors Generated",
            table(
                ["Vector ID", "Target Code Path", "Expected Kill", "Cross-verification"],
                [
                    [str(v.tc_id), v.code_path, v.expected_kill, json.dumps(v.cross_checks)]
                    for v in result.vectors
                ],
            ),
            "## Fault Simulation",
            result.fault_simulation,
            "## New Vectors Only",
        ]
    )
    parts.append(metrics(result.implementations, "new_only"))
    parts.extend(
        [
            "## After Results (With New Vectors)",
            metrics(result.implementations, "combined"),
            "## Before/After Comparison",
        ]
    )
    rows: list[list[str]] = []
    for item in result.implementations:
        b, a = counts(item.baseline), counts(item.combined)
        b_rate = 100 * b[1] / (b[1] + b[2]) if b[1] + b[2] else None
        a_rate = 100 * a[1] / (a[1] + a[2]) if a[1] + a[2] else None
        delta = "n/a"
        if b_rate is not None and a_rate is not None:
            delta = f"{a_rate - b_rate:.2f} pp"
        rows.append([item.name, str(a[1] - b[1]), str(b[2] - a[2]), str(b[3] - a[3]), delta])
    parts.extend(
        [
            table(
                [
                    "Library",
                    "Kill increase",
                    "Survivor decrease",
                    "Uncovered decrease",
                    "Efficacy pp",
                ],
                rows,
            ),
            "## Conclusions",
            result.conclusions,
        ]
    )
    return "\n\n".join(parts) + "\n"


@recipe(
    version="1",
    agents=("worker",),
    capabilities=("Bash",),
    output_root=".",
    budget=Budget(max_agent_calls=2, max_wall_seconds=3600),
)
def vector_forge(
    algorithm: str,
    project_directory: str = ".",
    specification: str = "",
    genotoxic_skill_file: str = "",
    wycheproof_contribution: bool = False,
) -> Findings:
    project = Path(project_directory).resolve()
    if not project.is_dir():
        fail("The project directory does not exist.")
    ensure_directory(output_files=("evidence.json", "vectors.json", "VECTOR_FORGE_REPORT.md"))
    inventory = run_command(
        ["rg", "--files", "--hidden", "-g", "!.git"],
        timeout_seconds=60,
        working_directory=project,
        mutating=False,
    )
    references = tuple(
        resource(name)
        for name in (
            "references/mutation-frameworks.md",
            "references/vector-patterns.md",
            "references/fault-simulation.md",
            "references/lessons-learned.md",
            "references/report-template.md",
        )
    )
    extra = (Path(genotoxic_skill_file).resolve(),) if genotoxic_skill_file else ()
    context = prepare_context(
        task=json.dumps(
            {
                "algorithm": algorithm,
                "specification": specification,
                "wycheproof_contribution": wycheproof_contribution,
            }
        ),
        instructions=(
            "Execute the complete authoritative workflow with full references and whole project; "
            "inventory is only an observation. Keep connected reasoning in this session. Read "
            "genotoxic prose supplied or discoverable locally; if unavailable report a blocker. "
            "Return Findings with complete raw logs and stable source mutation IDs across runs. "
            "Each escapes value includes code path, graph evidence, classification, security "
            "priority, vector strategy and grouping. verifiers identifies independent codebases; "
            "cross_checks records actual results with disagreements investigated. Return unchanged "
            "standard-format JSON containing only new vectors. Perform all original checks. "
            "Set blocked_reason for failures. Edit and run tools inside the project; never commit. "
            "Python owns evidence.json, vectors.json and VECTOR_FORGE_REPORT.md."
        ),
        prior_results=json.dumps({"inventory": inventory.stdout, "errors": inventory.stderr}),
        files=references + extra,
        readable_roots=(project, *references, *extra),
    )
    result = agent(
        "worker",
        "Complete the task and return Findings using the supplied context.",
        working_directory=project,
        readable_paths=references + extra,
        writable_paths=(project,),
        required_capabilities=("commands",),
        context=context,
        output=Findings,
        timeout=3600,
    )
    write_json("evidence.json", result.model_dump())
    if result.blocked_reason:
        emit(result, name="incomplete")
        fail(result.blocked_reason)
    check_results(result)
    write_text("vectors.json", result.vectors_json)
    report = render(result)
    write_text("VECTOR_FORGE_REPORT.md", report)
    for name in ("evidence.json", "vectors.json", "VECTOR_FORGE_REPORT.md"):
        emit(str(verify_artifact(name)), name=name.replace(".", "-"))
    emit(report, name="report")
    return result


if __name__ == "__main__":
    raise SystemExit(vector_forge.cli())


# --- calcifier metadata (skill provenance + sha256) ---
_CALCIFIER_COMPILATION = "compiled"
_CALCIFIER_SKILL = {
    "path": "../SKILL.md",
    "sha256": ("19ea6491e391b0464da44851e36655692e4ce42fd0de3f04e783e4f00081a593"),
}
_CALCIFIER_RESOURCES = [
    {
        "path": "agents/code-slice-worker.md",
        "sha256": ("6b427cf3aa5caf357cd0fb18eca324b4207706bcd7e79eaff157590cd5816cb7"),
        "size": 1912,
        "source": "../../agents/code-slice-worker.md",
    },
    {
        "path": "references/fault-simulation.md",
        "sha256": ("2e39c262e4cb1f7c8f9737e6ed02d45c3c69c556c7003b077a1aae24d06ea308"),
        "size": 5831,
        "source": None,
    },
    {
        "path": "references/lessons-learned.md",
        "sha256": ("bb92f8744839a60afb2d3c8a5ba3704f0db48fc2dbac019e00946e7f7359026f"),
        "size": 7785,
        "source": None,
    },
    {
        "path": "references/mutation-frameworks.md",
        "sha256": ("ae781ebc35637c0c46cdee448bc8bad98a7e3676007039c7ed1eca7f612e82d9"),
        "size": 20281,
        "source": None,
    },
    {
        "path": "references/report-template.md",
        "sha256": ("9fb727aa0f8f6dde0b4f533a0de0641848cdb0cffff2d47eba9c4335b6da9727"),
        "size": 912,
        "source": None,
    },
    {
        "path": "references/vector-patterns.md",
        "sha256": ("641edba466cfdf0ae8cd93b5009b6861b1f6aaa593b84fd5abcd5b468a8b91b1"),
        "size": 9867,
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
        "gs only to the requested skill."
    ),
    "sha256": ("46bb4ed4c424344f76192480d2444ca2e0c43d841ba604cdcf68ab9140c9162c"),
}
_CALCIFIER_SUBRECIPES = []
