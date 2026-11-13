"""Assess an unchanged baseline without treating a failed experiment as absence."""

import json
from dataclasses import replace
from pathlib import Path

from records import load, retained_file, step_directories
from repair_scope import CoverageGap, RepairScope, canonical


def has_attempt_evidence(run_dir: Path) -> bool:
    return any(step.parent.name in {"patch", "prove"} for step in step_directories(run_dir))


def _check_loaded_paths(lines: list[bytes], artifact: str) -> None:
    """Reject available loader paths that contradict the named artifact."""
    target = Path(artifact)
    for line in lines:
        if not line.startswith(b"PATCH_LOADED "):
            continue
        observation = json.loads(line.removeprefix(b"PATCH_LOADED "))
        if not isinstance(observation, dict) or not isinstance(observation.get("path"), str):
            raise CoverageGap("runtime loader observation has no path")
        loaded = Path(observation["path"])
        if not loaded.is_absolute() or loaded.parts[-len(target.parts) :] != target.parts:
            raise CoverageGap("runtime loader path contradicts the named target artifact")


def _require_final_marker(lines: list[bytes], label: str) -> None:
    if b"PATCH_REACHED" not in lines:
        raise CoverageGap(f"{label}: target assertion was not reached")
    if lines.count(b"PATCH_REACHED") != 1 or lines[-1] != b"PATCH_REACHED":
        raise CoverageGap(f"{label}: assertion marker is not final")


def _healthy_observation(
    run_dir: Path, step: str, refs: dict, case: dict, artifact: str | None
) -> None:
    if any(not name.startswith(f"{step}/receipts/") for name in refs.values()):
        raise CoverageGap(f"{step} {case['check_id']}: check reference is not a receipt")
    paths = {key: retained_file(run_dir, name, step) for key, name in refs.items()}
    if any(path is None for path in paths.values()):
        raise CoverageGap(f"{step} {case['check_id']}: evidence is not retained in that step")
    exit_path, stdout_path = paths["exit"], paths["stdout"]
    assert exit_path is not None and stdout_path is not None
    status = json.loads(exit_path.read_text())
    if (
        not isinstance(status, dict)
        or type(status.get("exit_code")) is not int
        or status["exit_code"] != 0
    ):
        raise CoverageGap(f"{step} {case['check_id']}: baseline check did not succeed")
    lines = stdout_path.read_bytes().splitlines()
    if artifact is not None:
        _require_final_marker(lines, f"{step} {case['check_id']}")
        _check_loaded_paths(lines, artifact)
    observations = [line[11:] for line in lines if line.startswith(b"PATCH_CASE ")]
    if len(observations) != 1:
        raise CoverageGap(f"{step} {case['check_id']}: expected one case observation")
    observation = json.loads(observations[0])
    expected = {"input": case["input"], "actual": case["expected"]}
    if canonical(observation) != canonical(expected):
        raise CoverageGap(
            f"{step} {case['check_id']}: observed input or result differs from the plan"
        )


def _baseline_cases(scope: RepairScope, checks: list[dict]) -> list[dict]:
    if scope.plan is None or not scope.plan["cases"]:
        raise CoverageGap("no planned baseline cases")
    cases = scope.plan["cases"]
    representatives = sum(case["role"] == "representative" for case in cases)
    controls = sum(case["role"] == "control" for case in cases)
    required_representatives = 2 if scope.plan["mode"] == "bounded_class" else 1
    if representatives < required_representatives or (
        scope.plan["mode"] == "bounded_class" and not controls
    ):
        raise CoverageGap("planned baseline needs representative cases and a valid control")
    if scope.plan["mode"] == "bounded_class" and len(
        {canonical(case["input"]) for case in cases}
    ) != len(cases):
        raise CoverageGap("planned baseline needs distinct representative and control inputs")
    planned = {case["check_id"] for case in cases}
    observed = {check["check_id"] for check in checks}
    missing = planned - observed
    if missing:
        raise CoverageGap(f"missing baseline check references for {', '.join(sorted(missing))}")
    if len(planned) != len(cases) or len(observed) != len(checks) or planned != observed:
        raise CoverageGap("baseline checks must cover each planned case exactly once")
    return cases


def _case_receipts(run_dir: Path, step: str, case: dict, artifact: str | None) -> dict | None:
    """Link only a unique, passing case observation in this step's retained receipts."""
    manifest = json.loads((run_dir / step / "manifest.json").read_text())["files"]
    matches = []
    for name in sorted(manifest):
        if not name.startswith("receipts/") or not name.endswith(".stdout"):
            continue
        base = name.removesuffix(".stdout")
        if f"{base}.exit.json" not in manifest:
            continue
        refs = {
            "stdout": f"{step}/{name}",
            "exit": f"{step}/{base}.exit.json",
        }
        try:
            _healthy_observation(run_dir, step, refs, case, artifact)
        except (OSError, ValueError):
            continue
        matches.append(refs)
    return matches[0] if len(matches) == 1 else None


def prepare_report_input(run_dir: Path) -> None:
    """Write explicit baseline links from unique retained observations when absent."""
    path = run_dir / "report-input.json"
    report_input = load(path, "report-input")
    if "baseline_checks" in report_input or load(run_dir / "run.json", "run")["attempts"]:
        return
    plan = load(run_dir / "finding.json", "finding").get("repair_scope")
    reproduce_path = run_dir / "reproduce/reproduce.json"
    validate_path = run_dir / "validate/validate.json"
    if plan is None or not reproduce_path.is_file() or not validate_path.is_file():
        return
    reproduce = load(reproduce_path, "reproduce")
    if reproduce["outcome"] != "not_reproduced":
        return
    links = []
    for case in plan["cases"]:
        try:
            source = _case_receipts(run_dir, "reproduce", case, reproduce["target_artifact"])
            independent = _case_receipts(run_dir, "validate", case, reproduce["target_artifact"])
        except (OSError, ValueError, KeyError):
            continue
        if source is not None and independent is not None:
            links.append(
                {"check_id": case["check_id"], "reproduce": source, "validate": independent}
            )
    report_input["baseline_checks"] = links
    path.write_text(json.dumps(report_input, indent=2) + "\n")


def assess_baseline(run_dir: Path, scope: RepairScope, checks: list[dict]) -> RepairScope:
    """Require independent successful case observations before declaring no patch needed."""
    try:
        if has_attempt_evidence(run_dir):
            raise CoverageGap("zero attempts conflicts with retained patch or proof evidence")
        reproduce = load(run_dir / "reproduce/reproduce.json", "reproduce")
        validation = load(run_dir / "validate/validate.json", "validate")
        if reproduce["outcome"] != "not_reproduced" or validation["outcome"] != "not_confirmed":
            raise CoverageGap("independent baseline checks did not establish the expected behavior")
        if reproduce["agent"] == validation["agent"]:
            raise CoverageGap("baseline checks reused the same agent")
        cases = _baseline_cases(scope, checks)
        by_id = {item["check_id"]: item for item in checks}
        for case in cases:
            for step in ("reproduce", "validate"):
                _healthy_observation(
                    run_dir, step, by_id[case["check_id"]][step], case, reproduce["target_artifact"]
                )
    except (OSError, ValueError) as exc:
        return replace(scope, detail=f"Baseline conclusion is inconclusive: {exc}.")
    return replace(
        scope,
        label="No patch required",
        detail="Independent retained observations match the planned inputs and expected results "
        "on the unchanged baseline. This conclusion covers only those observed cases.",
    )
