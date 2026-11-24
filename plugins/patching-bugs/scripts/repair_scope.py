"""Limit repair claims to declared cases with retained native proof."""

import json
from dataclasses import dataclass
from pathlib import Path

from native_proof import assess_proof
from records import load


class CoverageGap(ValueError):
    """The declared class lacks usable case-level proof."""


@dataclass(frozen=True)
class RepairScope:
    label: str
    detail: str
    plan: dict | None
    evidence_paths: tuple[Path, ...] = ()


def canonical(value: object) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False)


def _has_incomplete_fix(run_dir: Path) -> bool:
    path = run_dir / "regression/regression.json"
    return path.is_file() and any(
        item["outcome"] == "INCOMPLETE_FIX" for item in load(path, "regression")["outcomes"]
    )


def assess_scope(run_dir: Path, attempt: int, target_proved: bool) -> RepairScope:
    """Read case evidence after the caller has validated step manifests."""
    plan = load(run_dir / "finding.json", "finding").get("repair_scope")
    if not target_proved:
        return RepairScope("Repair not established", "The target lacks complete proof.", plan)
    if plan is None:
        return RepairScope(
            "Exact example repaired",
            "Only the reproduced input is established; no case-level coverage plan was recorded.",
            None,
        )
    if plan["mode"] == "exact_example":
        return RepairScope("Exact example repaired", "The declared scope is one example.", plan)
    assessment = assess_proof(run_dir, attempt)
    if _has_incomplete_fix(run_dir):
        return RepairScope(
            "Exact example repaired", "Bounded coverage has an unresolved incomplete fix.", plan
        )
    if assessment.case_findings or assessment.case_gaps:
        detail = "; ".join((*assessment.case_findings, *assessment.case_gaps))
        return RepairScope(
            "Exact example repaired", f"Bounded coverage incomplete: {detail}.", plan
        )
    return RepairScope(
        "Bounded class repaired",
        "Retained observations support the boundary; case selection requires review.",
        plan,
        assessment.case_paths,
    )
