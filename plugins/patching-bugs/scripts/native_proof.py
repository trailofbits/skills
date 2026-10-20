"""Assess retained scoped cases and project checks without a second validation workflow."""

import json
import re
from dataclasses import dataclass
from pathlib import Path, PurePosixPath

from records import attempt_gaps, load, repair_scope_gaps, verify_manifest


@dataclass(frozen=True)
class ProofAssessment:
    arm_gaps: tuple[str, ...]
    case_findings: tuple[str, ...]
    case_gaps: tuple[str, ...]
    project_findings: tuple[str, ...]
    project_gaps: tuple[str, ...]
    case_paths: tuple[Path, ...]
    project_paths: tuple[Path, ...]

    @property
    def findings(self) -> tuple[str, ...]:
        return self.case_findings + self.project_findings

    @property
    def gaps(self) -> tuple[str, ...]:
        return self.arm_gaps + self.case_gaps + self.project_gaps


def _receipt(directory: Path, name: str, manifest: dict[str, str]) -> bytes:
    relative = PurePosixPath(name)
    if relative.is_absolute() or ".." in relative.parts or not name.startswith("receipts/"):
        raise ValueError(f"unsafe proof receipt: {name}")
    path = directory / relative
    if name not in manifest or not path.is_file() or path.is_symlink():
        raise ValueError(f"proof receipt is not retained: {name}")
    return path.read_bytes()


def _read_run(
    directory: Path, run: dict, manifest: dict[str, str]
) -> tuple[bytes, tuple[Path, Path]]:
    stdout = _receipt(directory, run["stdout"], manifest)
    _receipt(directory, run["stderr"], manifest)
    return stdout, (directory / run["stdout"], directory / run["stderr"])


def _case_observation(stdout: bytes) -> dict:
    lines = stdout.splitlines()
    if b"PATCH_REACHED" not in lines:
        raise ValueError("assertion was not reached")
    if lines.count(b"PATCH_REACHED") != 1 or lines[-1] != b"PATCH_REACHED":
        raise ValueError("assertion marker must be the final stdout line")
    lines = [
        line.removeprefix(b"PATCH_CASE ") for line in lines[:-1] if line.startswith(b"PATCH_CASE ")
    ]
    if len(lines) != 1:
        raise ValueError("expected one PATCH_CASE observation")
    observation = json.loads(lines[0])
    if not isinstance(observation, dict) or set(observation) != {"input", "actual"}:
        raise ValueError("PATCH_CASE needs input and actual")
    return observation


def _observe_case_side(
    directory: Path, check: dict, side: str, expected_input: object, manifest: dict[str, str]
) -> tuple[tuple[int, object] | None, list[Path], str | None]:
    run = check["runs"][side]
    try:
        stdout, receipts = _read_run(directory, run, manifest)
        if run["exit_code"] is None:
            raise ValueError("execution did not complete")
        observation = _case_observation(stdout)
        if observation["input"] != expected_input:
            raise ValueError("observed input differs from the repair plan")
    except (OSError, ValueError) as exc:
        return None, [], f"{check['check_id']} {side}: {exc}"
    return (run["exit_code"], observation["actual"]), list(receipts), None


def _case_outcome(
    case: dict, baseline: tuple[int, object], patched: tuple[int, object]
) -> tuple[str, str]:
    name = case["check_id"]
    baseline_code, baseline_actual = baseline
    patched_code, patched_actual = patched
    expected = case["expected"]
    if case["role"] == "representative":
        if baseline_code == 0 or baseline_actual == expected:
            return "gap", f"{name}: baseline did not establish the reported failure"
        if patched_code != 0 and patched_actual != expected:
            return "finding", f"{name}: scoped failure remains after the patch"
        if patched_code != 0 or patched_actual != expected:
            return "gap", f"{name}: patched exit and observation disagree"
    else:
        if baseline_code != 0 or baseline_actual != expected:
            return "gap", f"{name}: baseline control did not pass"
        if patched_code != 0 and patched_actual != expected:
            return "finding", f"{name}: valid control fails after the patch"
        if patched_code != 0 or patched_actual != expected:
            return "gap", f"{name}: patched control exit and observation disagree"
    return "pass", ""


def _case_result(
    directory: Path, case: dict, check: dict, manifest: dict[str, str]
) -> tuple[list[str], list[str], list[Path]]:
    name = case["check_id"]
    if not check["argv"]:
        return [], [f"{name}: check command is empty"], []
    try:
        _receipt(directory, check["source"], manifest)
    except ValueError as exc:
        return [], [f"{name}: {exc}"], []
    paths = [directory / check["source"]]
    observations = {}
    gaps = []
    for side in ("baseline", "patched"):
        observation, receipts, gap = _observe_case_side(
            directory, check, side, case["input"], manifest
        )
        paths.extend(receipts)
        if gap or observation is None:
            gaps.append(gap or f"{name} {side}: observation is missing")
        else:
            observations[side] = observation
    if gaps:
        return [], gaps, paths
    kind, message = _case_outcome(case, observations["baseline"], observations["patched"])
    return ([message] if kind == "finding" else []), ([message] if kind == "gap" else []), paths


def _observe_project_side(
    directory: Path, check: dict, side: str, manifest: dict[str, str]
) -> tuple[tuple[int, bytes] | None, list[Path], str | None]:
    run = check[side]
    if run is None:
        return None, [], None
    try:
        stdout, receipts = _read_run(directory, run, manifest)
        if run["exit_code"] is None:
            raise ValueError("execution did not complete")
    except (OSError, ValueError) as exc:
        return None, [], f"{check['check_id']} {side}: {exc}"
    return (run["exit_code"], stdout), list(receipts), None


def _project_outcome(
    check: dict, baseline: tuple[int, bytes] | None, patched: tuple[int, bytes]
) -> tuple[str, str]:
    name = check["check_id"]
    patched_code, patched_output = patched
    if baseline is None:
        if check["kind"] != "suite":
            return "gap", f"{name}: baseline comparison is required"
        if patched_code != 0:
            return "gap", f"{name}: failed project check has no baseline attribution"
        return "pass", ""
    baseline_code, baseline_output = baseline
    if baseline_code != 0:
        return "gap", f"{name}: baseline project check did not pass"
    if patched_code != 0:
        return "finding", f"{name}: project check fails after the patch"
    if check["kind"] == "behavior" and patched_output != baseline_output:
        return "finding", f"{name}: preserved behavior changed after the patch"
    return "pass", ""


def _project_result(
    directory: Path, check: dict, manifest: dict[str, str]
) -> tuple[list[str], list[str], list[Path]]:
    name = check["check_id"]
    if not check["argv"]:
        return [], [f"{name}: project command is empty"], []
    paths = []
    patched, receipts, gap = _observe_project_side(directory, check, "patched", manifest)
    paths.extend(receipts)
    if gap:
        return [], [gap], paths
    baseline, receipts, gap = _observe_project_side(directory, check, "baseline", manifest)
    paths.extend(receipts)
    if gap:
        return [], [gap], paths
    assert patched is not None
    kind, message = _project_outcome(check, baseline, patched)
    return ([message] if kind == "finding" else []), ([message] if kind == "gap" else []), paths


def _scope_gaps(plan: dict, checks: list[dict]) -> list[str]:
    gaps = repair_scope_gaps(plan)
    ids = [case["check_id"] for case in plan["cases"]]
    check_ids = [check["check_id"] for check in checks]
    if len(set(check_ids)) != len(check_ids):
        gaps.append("proof repeats a case ID")
    extra = set(check_ids) - set(ids)
    if extra:
        gaps.append("proof has undeclared cases: " + ", ".join(sorted(extra)))
    return gaps


def _source_tree_gaps(directory: Path, proof: dict, manifest: dict[str, str]) -> list[str]:
    try:
        source = json.loads(_receipt(directory, "receipts/source.json", manifest))
        trees = source["trees"]
        if (
            source["baseline_commit"] != proof["baseline_commit"]
            or source["patch_commit"] != proof["patch_commit"]
        ):
            return ["source tree commits differ from the proof record"]
        if not isinstance(trees, dict) or any(
            not isinstance(trees.get(side), str)
            or re.fullmatch(r"[0-9a-f]{40}", trees[side]) is None
            for side in ("baseline", "patched", "reverted")
        ):
            return ["source tree identities are missing or malformed"]
        if trees["reverted"] != trees["baseline"]:
            return ["reverted tree differs from the original baseline"]
        if trees["patched"] == trees["baseline"]:
            return ["patched tree does not differ from the baseline"]
    except (OSError, ValueError, KeyError, TypeError) as exc:
        return [f"source tree receipt is unusable: {exc}"]
    return []


def _assess_cases(
    directory: Path, plan: dict, checks: list[dict], manifest: dict[str, str]
) -> tuple[list[str], list[str], list[Path]]:
    findings = []
    gaps = _scope_gaps(plan, checks)
    paths = []
    by_id = {check["check_id"]: check for check in checks}
    for case in plan["cases"]:
        check = by_id.get(case["check_id"])
        if check is None:
            gaps.append(f"{case['check_id']}: planned case is missing")
            continue
        found, missing, retained = _case_result(directory, case, check, manifest)
        findings.extend(found)
        gaps.extend(missing)
        paths.extend(retained)
    return findings, gaps, paths


def assess_proof(run_dir: Path, attempt: int) -> ProofAssessment:
    """Derive findings and gaps from a manifest-covered native proof record."""
    directory = run_dir / f"prove/attempt-{attempt}"
    verify_manifest(directory)
    proof = load(directory / "prove.json", "prove")
    finding = load(run_dir / "finding.json", "finding")
    patch = load(run_dir / f"patch/attempt-{attempt}/patch.json", "patch")
    manifest = json.loads((directory / "manifest.json").read_text())["files"]
    case_findings: list[str] = []
    case_gaps: list[str] = []
    project_findings: list[str] = []
    project_gaps: list[str] = []
    case_paths: list[Path] = []
    project_paths: list[Path] = []
    arm_gaps = _source_tree_gaps(directory, proof, manifest)
    run = load(run_dir / "run.json", "run")
    arm_gaps.extend(attempt_gaps(run_dir, run["attempts"]))
    if (
        proof["baseline_commit"] != patch["baseline_commit"]
        or proof["patch_commit"] != patch["patch_commit"]
    ):
        case_gaps.append("proof commits differ from the recorded patch")
    plan = finding.get("repair_scope")
    if plan is None:
        case_gaps.append("repair scope is missing")
    else:
        found, missing, retained = _assess_cases(directory, plan, proof["cases"], manifest)
        case_findings.extend(found)
        case_gaps.extend(missing)
        case_paths.extend(retained)
    if not proof["project_checks"]:
        project_gaps.append("no independent project check was recorded")
    if not proof["unproven"]:
        project_gaps.append("unproven limits were not recorded")
    ids = [check["check_id"] for check in proof["project_checks"]]
    if len(set(ids)) != len(ids):
        project_gaps.append("project check IDs are repeated")
    for check in proof["project_checks"]:
        found, missing, retained = _project_result(directory, check, manifest)
        project_findings.extend(found)
        project_gaps.extend(missing)
        project_paths.extend(retained)
    return ProofAssessment(
        tuple(arm_gaps),
        tuple(case_findings),
        tuple(case_gaps),
        tuple(project_findings),
        tuple(project_gaps),
        tuple(case_paths),
        tuple(project_paths),
    )
