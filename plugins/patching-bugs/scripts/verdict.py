# /// script
# requires-python = ">=3.13"
# dependencies = []
# ///
"""Compute the patch readiness verdict from validated records."""

from pathlib import Path

from native_proof import ProofAssessment, assess_proof
from records import RecordError, load


class MissingRecord(RecordError):
    """An uncompleted workflow lacks a required decision record."""


def _required(run_dir: Path, relative: str, kind: str) -> dict:
    path = run_dir / relative
    if not path.is_file():
        raise MissingRecord(f"required {kind} record missing: {path}")
    return load(path, kind)


def _proof_failures(proof: dict, assessment: ProofAssessment, outcomes: list[str]) -> list[str]:
    failures = [*assessment.findings, *assessment.gaps]
    identity = "not_applicable" if proof.get("failure_type") == "compile" else "pass"
    failures.extend(
        f"{key}: {proof[key]}"
        for key, expected in (
            ("reverted", "pass"),
            ("build_identity", identity),
        )
        if proof[key] != expected
    )
    if any(value in {"REPRODUCED_REGRESSION", "INCOMPLETE_FIX"} for value in outcomes):
        failures.append("regression or incomplete fix")
    return failures


def _concerns(patch: dict, regression: dict, outcomes: list[str]) -> list[str]:
    concerns = []
    if "UNRESOLVED" in outcomes:
        concerns.append("unresolved regression candidate")
    if regression["coverage"] == "INCOMPLETE":
        concerns.append("incomplete regression coverage")
    if any(item["status"] == "not_fixed" for item in patch["variants"]):
        concerns.append("unfixed variant")
    return concerns


def _latest_attempt(
    run_dir: Path, attempt: int, failure_type: str
) -> tuple[dict | None, dict | None, str | None]:
    patch_path = run_dir / f"patch/attempt-{attempt}/patch.json"
    if not patch_path.is_file():
        return None, None, "latest patch record missing"
    patch = load(patch_path, "patch")
    if patch["patch_commit"] is None:
        return patch, None, "latest patch has no commit"
    proof_path = run_dir / f"prove/attempt-{attempt}/prove.json"
    if not proof_path.is_file():
        return patch, None, "latest proof record missing"
    proof = load(proof_path, "prove")
    if patch["agent"] == proof["agent"]:
        return patch, proof, "patcher and prover have the same agent"
    if proof.get("failure_type", "runtime") != failure_type:
        return patch, proof, "proof failure type differs from reproduction"
    return patch, proof, None


def verdict(run_dir: Path) -> tuple[str, list[str]]:
    """Return a verdict and concise reasons for the latest patch attempt."""
    reproduce = _required(run_dir, "reproduce/reproduce.json", "reproduce")
    if reproduce["outcome"] != "reproduced":
        return "NOT_REPRODUCED", [f"reproduction: {reproduce['outcome']}"]
    validation = _required(run_dir, "validate/validate.json", "validate")
    if validation["outcome"] != "confirmed":
        return "NOT_REPRODUCED", [f"validation: {validation['outcome']}"]
    if reproduce["agent"] == validation["agent"]:
        return "NOT_READY", ["reproducer and validator have the same agent"]
    run = _required(run_dir, "run.json", "run")
    attempt = run["attempts"]
    if attempt < 1:
        return "NOT_READY", ["no patch attempt"]
    patch, proof, problem = _latest_attempt(
        run_dir, attempt, reproduce.get("failure_type", "runtime")
    )
    if problem:
        return "NOT_READY", [problem]
    assert patch is not None and proof is not None
    assessment = assess_proof(run_dir, attempt)
    failures = _proof_failures(proof, assessment, [])
    if failures:
        return "NOT_READY", failures
    regression = _required(run_dir, "regression/regression.json", "regression")
    outcomes = [item["outcome"] for item in regression["outcomes"]]
    failures = _proof_failures(proof, assessment, outcomes)
    if failures:
        return "NOT_READY", failures
    concerns = _concerns(patch, regression, outcomes)
    return ("READY_WITH_CONCERNS", concerns) if concerns else ("READY", [])
