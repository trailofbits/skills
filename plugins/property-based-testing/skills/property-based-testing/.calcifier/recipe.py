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
    fail,
    output_type,
    prepare_context,
    recipe,
    resource,
    run_command,
    step,
)

LIBRARY_PATTERN = (
    r"from hypothesis import|fast-check|use proptest|pgregory.net/rapid|net\.jqwik"
    r"|echidna_|invariant_"
)
TEST_PATTERN = r"@given\(|from hypothesis import|fc\.(assert|property)|proptest!|#\[quickcheck\]"


@output_type
class ReviewFinding:
    location: str
    severity: Literal["CRITICAL", "HIGH", "MEDIUM", "LOW"]
    explanation: str
    recommendation: str


@output_type
class FailureFinding:
    classification: Literal[
        "code bug",
        "over-broad strategy",
        "wrong property",
        "ambiguous spec",
        "test artifact",
        "possible inconsistency",
    ]
    counterexample: str
    contract_basis: str
    explanation: str
    action: str


@output_type
class Assessment:
    report: str
    inspected_items: list[str]
    review_findings: list[ReviewFinding]
    failure_findings: list[FailureFinding]


@step
def inspect_scope(root: str, targets: list[str]) -> dict[str, str]:
    base = ["rg", "--hidden", "--glob", "!.git", "--color", "never"]
    inventory = run_command(
        base + ["--files", "--", *targets],
        timeout_seconds=60,
        working_directory=root,
        mutating=False,
    )
    if inventory.exit_code not in (0, 1):
        fail("Repository inventory failed: " + inventory.stderr)
    observations = {"inventory": inventory.stdout}
    for label, pattern in (("libraries", LIBRARY_PATTERN), ("tests", TEST_PATTERN)):
        result = run_command(
            base + ["--line-number", "--no-heading", "-e", pattern, "--", *targets],
            timeout_seconds=60,
            working_directory=root,
            mutating=False,
        )
        if result.exit_code not in (0, 1):
            fail("Repository search failed: " + result.stderr)
        observations[label] = result.stdout
    return observations


@step
def render_assessment(result: Assessment) -> str:
    lines = [result.report, "", "Inspected items:"]
    lines.extend(f"- {item}" for item in result.inspected_items)
    for issue in result.review_findings:
        lines.extend(
            [
                "",
                f"{issue.severity}: {issue.location}",
                issue.explanation,
                "Recommendation: " + issue.recommendation,
            ]
        )
    for failure in result.failure_findings:
        lines.extend(
            [
                "",
                "Classification: " + failure.classification,
                "Counterexample: " + failure.counterexample,
                "Contract: " + failure.contract_basis,
                failure.explanation,
                "Action: " + failure.action,
            ]
        )
    return "\n".join(lines)


@recipe(
    name="property-based-testing",
    version="1",
    capabilities=("Bash",),
    agents=("worker",),
    budget=Budget(max_agent_calls=2, max_wall_seconds=3600),
)
def property_based_testing(
    project_directory: str,
    task: Literal["write", "review", "debug", "library"],
    request: str,
    targets: list[str] | None = None,
    apply_changes: bool = True,
    allow_new_dependency: bool = False,
    allow_production_refactor: bool = False,
    validation_argv: list[str] | None = None,
) -> str:
    root = Path(project_directory).resolve()
    if not root.is_dir():
        fail("project_directory must be an existing project directory.")
    names = ["."] if targets is None else targets
    if not names:
        fail("Inspection scope is empty; supply at least one project target.")
    selected = []
    for name in names:
        path = (root / name).resolve()
        if not path.is_relative_to(root) or not path.exists():
            fail("Each target must exist within project_directory: " + name)
        selected.append(str(path))
    if validation_argv is not None and not validation_argv:
        fail("validation_argv must contain a command when provided.")
    observations = inspect_scope(str(root), selected)
    references = [
        resource("references/libraries.md"),
        resource("references/refactoring.md"),
    ]
    if task == "write":
        references.append(resource("references/generating.md"))
    elif task == "review":
        references.append(resource("references/reviewing.md"))
    elif task == "debug":
        references.append(resource("references/interpreting-failures.md"))
    editing = apply_changes and task in ("write", "debug")
    context = prepare_context(
        request,
        instructions=(
            "Perform the requested task under the runtime SKILL.md and full selected references. "
            "Keep property discovery, contract interpretation, strategy design, edits, and checks "
            "in this one connected session. Use embedded context directly; read task.txt and "
            "complete bundled reference texts if their content is absent. The mechanical inventory "
            "and searches are observations, not exhaustive semantic candidates. Inspect the full "
            "declared target scope, including relevant tests not matched by searches. "
            "Use the existing PBT library. Approval flags and explicit instructions in request "
            "are user authorizations. Without authorization, offer a new dependency or production "
            "refactor once with the specific property it unlocks and leave it unapplied. "
            "Make project edits only if apply_changes is true; never commit. Run appropriate "
            "project tests when editing, and existing tests after any authorized refactor. "
            "Use commands for reasoning-dependent investigation and testing; the recipe separately "
            "runs validation_argv if provided. Report actual checks and unresolved limitations. "
            "For reviews, inspected_items must name actual property tests inspected; include "
            "every issue with severity and discuss the strongest missing property for each test. "
            "For debugging, classify every finding, include its shrunk counterexample and "
            "contract basis, and surface ambiguous specifications and uncertain inconsistencies. "
            "For other tasks, inspected_items names the actual code or manifests inspected. "
            "Return Assessment: report is the complete answer; review_findings and failure_find"
            "ings "
            "contain all applicable findings and are empty when inapplicable. If no items could "
            "be inspected, leave inspected_items empty and explain the incomplete scope."
        ),
        prior_results=json.dumps(
            {
                "task": task,
                "targets": selected,
                "apply_changes": editing,
                "allow_new_dependency": allow_new_dependency,
                "allow_production_refactor": allow_production_refactor,
                "validation_argv": validation_argv,
                "observations": observations,
            }
        ),
        files=tuple(references),
        readable_roots=(root, *references),
    )
    result = agent(
        "worker",
        context.prompt,
        working_directory=root,
        readable_paths=(root, *references),
        writable_paths=(root,) if editing else (),
        required_capabilities=("commands",),
        output=Assessment,
        timeout=3600,
        context=context,
    )
    emit(result, name="assessment")
    if not result.report.strip():
        fail("The assessment omitted its required answer.")
    if not result.inspected_items:
        fail("Inspection covered zero items; a successful clean report cannot be issued.")
    report = render_assessment(result)
    validation_failed = False
    if validation_argv is not None:
        validation = run_command(
            validation_argv,
            timeout_seconds=300,
            working_directory=root,
            mutating=True,
        )
        report += (
            "\n\nValidation command: "
            + json.dumps(validation.argv)
            + f"\nExit code: {validation.exit_code}\n"
            + validation.stdout
            + "\n"
            + validation.stderr
        )
        validation_failed = validation.exit_code != 0
    emit(report, name="report")
    if validation_failed:
        fail("Validation failed; the emitted report retains the assessment and command output.")
    return report


if __name__ == "__main__":
    raise SystemExit(property_based_testing.cli())


# --- calcifier metadata (skill provenance + sha256) ---
_CALCIFIER_COMPILATION = "compiled"
_CALCIFIER_SKILL = {
    "path": "../SKILL.md",
    "sha256": ("9448cacb65c6237a7c22dc59602667177ecae405524079ae9ff92240590b995a"),
}
_CALCIFIER_RESOURCES = [
    {
        "path": "references/generating.md",
        "sha256": ("c0e72dfc89babe3c32de718b81b94044362c85e776d7475e950dfeaab78bb58e"),
        "size": 2634,
        "source": None,
    },
    {
        "path": "references/interpreting-failures.md",
        "sha256": ("dbae7db8773712ba03268a3d56ea5aa6720af0650a5189580bfd88aa2edc3f9a"),
        "size": 3426,
        "source": None,
    },
    {
        "path": "references/libraries.md",
        "sha256": ("f7218acf8e668130ef3048983472579d04e12030c5401926f666363e5f69c686"),
        "size": 2952,
        "source": None,
    },
    {
        "path": "references/refactoring.md",
        "sha256": ("6eb5c206f575704791f089608bb06e41d6eed91b9d3c7fb27912f969aed07a18"),
        "size": 4854,
        "source": None,
    },
    {
        "path": "references/reviewing.md",
        "sha256": ("110b08118a1e7b1a2566def6e9d2a0bf43fc2deefce857d2ce3b4382b07bc774"),
        "size": 2859,
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
