# /// script
# requires-python = ">=3.13"
# dependencies = ["calcifier==0.2.0"]
# ///

"""Verify supplied findings while retaining the source reasoning workflow."""

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
    step,
)

REFERENCES = (
    "agents/data-flow-analyzer.md",
    "agents/exploitability-verifier.md",
    "agents/poc-builder.md",
    "references/bug-class-verification.md",
    "references/deep-verification.md",
    "references/evidence-templates.md",
    "references/false-positive-patterns.md",
    "references/gate-reviews.md",
    "references/standard-verification.md",
)
GATES = (
    "Process",
    "Reachability",
    "Real Impact",
    "PoC Validation",
    "Math Bounds",
    "Environment",
)


@output_type
class ClaimContext:
    claim: str
    root_cause: str
    trigger: str
    claimed_impact: str
    threat_model: str
    bug_class: str
    execution_context: str
    callers: str
    architecture: str
    history: str


@output_type
class Gate:
    name: Literal[
        "Process", "Reachability", "Real Impact", "PoC Validation", "Math Bounds", "Environment"
    ]
    passed: bool
    evidence: str


@output_type
class Finding:
    number: int
    context: ClaimContext
    route: Literal["standard", "deep"]
    description: str
    phase_evidence: str
    pseudocode_poc: str
    additional_pocs: str
    devils_advocate: str
    gates: list[Gate]
    rejection_reason: str


@output_type
class Verification:
    findings: list[Finding]
    inspected_files: list[str]
    exploit_chain_review: str
    clarification_questions: list[str]
    configuration_blockers: list[str]


@step
def inventory(project: str) -> list[str]:
    root = Path(project).resolve()
    if not root.is_dir():
        fail("The audited project must be an existing directory.")
    files = sorted(
        str(path.relative_to(root))
        for path in root.rglob("*")
        if path.is_file()
        and ".git" not in path.relative_to(root).parts
        and path.resolve().is_relative_to(root)
    )
    if not files:
        fail("The inspection scope contains no project files; zero items cannot pass.")
    return files


@step
def render(result: Verification, claims: list[str], files: list[str]) -> str:
    emit(result, name="verification-evidence")
    blockers = result.clarification_questions + result.configuration_blockers
    if blockers:
        fail("Verification is incomplete: " + "; ".join(blockers))
    numbers = [finding.number for finding in result.findings]
    if sorted(numbers) != list(range(1, len(claims) + 1)):
        fail("Every supplied finding needs exactly one complete result; none may be added.")
    if not result.inspected_files or any(name not in files for name in result.inspected_files):
        fail("Verification must identify actual inspected project files from the full inventory.")
    if not result.exploit_chain_review.strip():
        fail("The final exploit-chain review is missing.")
    positives: list[str] = []
    negatives: list[str] = []
    details: list[str] = []
    ordered = sorted(result.findings, key=lambda item: (item.route == "deep", item.number))
    for finding in ordered:
        context = finding.context.model_dump()
        fields = (
            finding.description,
            finding.phase_evidence,
            finding.pseudocode_poc,
            finding.devils_advocate,
            *context.values(),
        )
        if any(not value.strip() for value in fields):
            fail(f"BUG #{finding.number}: required documented evidence is missing.")
        if finding.route == "deep" and not finding.additional_pocs.strip():
            fail(f"BUG #{finding.number}: deep PoCs or feasibility evidence are missing.")
        names = [gate.name for gate in finding.gates]
        if len(names) != 6 or set(names) != set(GATES):
            fail(f"BUG #{finding.number}: all six unique gate reviews are required.")
        if any(not gate.evidence.strip() for gate in finding.gates):
            fail(f"BUG #{finding.number}: a gate lacks documented evidence.")
        positive = all(gate.passed for gate in finding.gates)
        label = "TRUE POSITIVE" if positive else "FALSE POSITIVE"
        if not positive and not finding.rejection_reason.strip():
            fail(f"BUG #{finding.number}: a brief rejection reason is required.")
        brief = finding.description if positive else finding.rejection_reason
        verdict = f"BUG #{finding.number} {label} — {brief}"
        if positive:
            positives.append(verdict)
        else:
            negatives.append(verdict)
        parts = [
            verdict,
            "Original claim: " + claims[finding.number - 1],
            "Verification path: " + finding.route,
        ]
        parts.extend(f"{key}: {value}" for key, value in context.items())
        parts.extend(
            (
                finding.phase_evidence,
                "Pseudocode PoC:\n" + finding.pseudocode_poc,
                "Additional PoCs and feasibility:\n" + finding.additional_pocs,
                "Devil's advocate:\n" + finding.devils_advocate,
            )
        )
        gates = sorted(finding.gates, key=lambda item: GATES.index(item.name))
        for index, gate in enumerate(gates, 1):
            state = "PASS" if gate.passed else "FAIL"
            parts.append(f"Gate {index} ({gate.name}) {state}: {gate.evidence}")
        details.append("\n\n".join(parts))
    summary = [
        f"{len(positives)} TRUE POSITIVES, {len(negatives)} FALSE POSITIVES",
        "TRUE POSITIVE list:\n" + ("\n".join(positives) or "None."),
        "FALSE POSITIVE list:\n" + ("\n".join(negatives) or "None."),
        "Exploit-chain review:\n" + result.exploit_chain_review,
    ]
    return "\n\n".join(details + ["Final Summary"] + summary)


@recipe(name="fp-check", version="1", agents=("worker",), budget=Budget(2, 3600))
def fp_check(
    project_directory: str,
    findings: list[str],
    verification: Literal["auto", "full"] = "auto",
) -> str:
    if not findings or any(not claim.strip() for claim in findings):
        fail("Supply at least one nonempty, specific suspected security finding.")
    root = Path(project_directory).resolve()
    files = inventory(str(root))
    references = tuple(resource(name) for name in REFERENCES)
    task = {
        "project": str(root),
        "findings": [
            {"number": number, "claim": claim} for number, claim in enumerate(findings, 1)
        ],
        "verification_request": verification,
        "complete_project_inventory": files,
    }
    context = prepare_context(
        json.dumps(task, ensure_ascii=False),
        instructions=(
            "Verify the entire supplied batch under the authoritative source skill and "
            "complete references, including the three analysis-agent definitions. "
            "The inventory is observational; the entire project is readable. Use embedded "
            "context directly; read full backing files when absent or a check requires it. "
            "Keep the source reasoning workflow intact in this session: all Step 0 work "
            "before routing, standard findings before deep findings, original escalation "
            "checkpoints, phase dependencies, mandated parallel delegation, task tracking, "
            "and checks. Full requests require deep verification. Preserve prior evidence "
            "on escalation and complete remaining phases even after a failed check. "
            "Return one Finding per input number. Document Step 0, phase evidence using "
            "the supplied templates, pseudocode with diagrams, additional PoCs or actual "
            "feasibility limits, devil's advocate answers, and six evidence-backed gates. "
            "Apply the complete false-positive checklist including 1a internally. "
            "Context fields need evidence or explicit unknowns. Review exploit chains "
            "after all findings, including findings rejected individually. Inspected "
            "files must be inventory-relative names of files actually examined. "
            "Do not hunt for bugs or modify the audited project. Return PoC code in the "
            "documentation; use commands for appropriate nonmutating verification. "
            "Never invent execution, research, delegation, mitigations, or completion. "
            "Return clarification questions when a claim cannot be coherently restated. "
            "If mandatory deep-path task tracking or parallel delegated analysis lacks "
            "actual provider support, return the required configuration as a blocker; "
            "do not substitute solo analysis. Likewise report unavailable mandatory "
            "research or execution support. Blockers mean no final affected verdict."
        ),
        files=references,
        readable_roots=references,
    )
    result = agent(
        "worker",
        "Perform the complete assigned verification and return the documented batch results.",
        working_directory=root,
        readable_paths=(root, *references),
        required_capabilities=("commands",),
        context=context,
        output=Verification,
        timeout=3600,
    )
    return emit(render(result, findings, files), name="report")


if __name__ == "__main__":
    raise SystemExit(fp_check.cli())


# --- calcifier metadata (skill provenance + sha256) ---
_CALCIFIER_COMPILATION = "compiled"
_CALCIFIER_SKILL = {
    "path": "../SKILL.md",
    "sha256": ("129223b79b8cb1e7c289c90cbe4ba288d9b210e318a0d1464f319e30329481b3"),
}
_CALCIFIER_RESOURCES = [
    {
        "path": "agents/data-flow-analyzer.md",
        "sha256": ("77f952fe020ede16f4b2ff8f00bdb7d1c6aa65b85a6e3251c4a29396177dc4fa"),
        "size": 5130,
        "source": "../../agents/data-flow-analyzer.md",
    },
    {
        "path": "agents/exploitability-verifier.md",
        "sha256": ("a00e1498aac837421db2b09b28e4dbcfcd273a159223ef2999a7b7959c5b6da6"),
        "size": 5383,
        "source": "../../agents/exploitability-verifier.md",
    },
    {
        "path": "agents/poc-builder.md",
        "sha256": ("236188b682275f48dbaeeacc75ece6d4276851757a2ab0807c2d35998d9ad2f1"),
        "size": 6710,
        "source": "../../agents/poc-builder.md",
    },
    {
        "path": "references/bug-class-verification.md",
        "sha256": ("b687b0fddb945354175b653a86653087110717ffe21f0bb6b8ce95535643fdde"),
        "size": 8041,
        "source": None,
    },
    {
        "path": "references/deep-verification.md",
        "sha256": ("653ee21c3ab73f8ca6aa0a7c8e51a9195c90bcfa76533cb966c41d16baa52ffa"),
        "size": 8810,
        "source": None,
    },
    {
        "path": "references/evidence-templates.md",
        "sha256": ("340346b9c6b3b43aa7edc71ff09351c910bc8aefec62647d2284bdf637a59e3d"),
        "size": 2973,
        "source": None,
    },
    {
        "path": "references/false-positive-patterns.md",
        "sha256": ("868c4e3f794c95a11c177ff4999c30eb71ebafcbc0e30ab826761b0d17b17a7e"),
        "size": 7052,
        "source": None,
    },
    {
        "path": "references/gate-reviews.md",
        "sha256": ("de4fd3680496b6f622b25dd5d8459eee1fe95e2cf61aa533c5ff86c548d6acc9"),
        "size": 1936,
        "source": None,
    },
    {
        "path": "references/standard-verification.md",
        "sha256": ("09032334d472b0fd796fc13f6d95cf6f0ae98cce34f1aa8dbd0c3fdce2854710"),
        "size": 4521,
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
