"""Execute and revalidate independent Psalm 7 modeling contracts."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

from activation import invocation
from psalm_features import (
    FEATURES,
    diagnostic_expectations,
    feature_expectations,
    feature_files,
    write_feature,
)
from psalm_version import psalm_major
from runner_artifacts import artifact, check_artifact
from runner_startup import CONFIG_OPTIONS, check_execution, extract_options, version_identity

JsonObject = dict[str, Any]
PROFILE = "psalm-taint-contracts-v4"


def run_feature(name: str, root: Path, argv: list[str]) -> JsonObject:
    from runner import run_native

    paths = write_feature(root, name)
    fixture_files = [artifact(path) for path in paths]
    prefix, args = invocation("psalm", argv)
    args, _ = extract_options(args, CONFIG_OPTIONS)
    output = root.parent / (name + ".run.json")
    run_native(
        backend="psalm",
        language="php",
        phase="probe",
        scope="intraprocedural",
        output=output,
        cwd=root,
        argv=prefix + args + [f"--config={root / 'psalm.xml'}"],
        models=[path for path in paths if path.suffix == ".phpstub"],
    )
    return {
        "fixture_root": str(root),
        "fixture_files": fixture_files,
        "expect": feature_expectations(name),
        "diagnostics": diagnostic_expectations(name),
        "run": artifact(output),
    }


def run_features(proof: JsonObject, core: JsonObject, argv: list[str]) -> None:
    if psalm_major(core.get("version", {}).get("output", "")) != 7:
        return
    root = Path(proof["fixture_root"]) / "features"
    proof["profile"] = PROFILE
    proof["feature_runs"] = {name: run_feature(name, root / name, argv) for name in FEATURES}


def diagnostic_errors(evidence: JsonObject, run: JsonObject) -> list[str]:
    from runner_contracts import matches

    root = Path(evidence["fixture_root"])
    issues = json.loads(Path(run["native_output"]["path"]).read_text(encoding="utf-8"))
    actual = {
        (item.get("file_path", item.get("file_name", "")), item.get("line_from"), item.get("type"))
        for item in issues
    }
    errors = []
    for category, sites in evidence["diagnostics"].items():
        for site in sites:
            expected = (str((root / site["file"]).resolve()), site["line"], site["rule_id"])
            present = matches(expected, actual)
            if present != (category == "positive"):
                errors.append(f"Native {category} diagnostic expectation failed at {expected}")
    return errors


def feature_capability(name: str, evidence: JsonObject) -> JsonObject:
    from runner import check_run
    from runner_contracts import expected_sites

    path = Path(evidence["run"]["path"])
    run = json.loads(path.read_text(encoding="utf-8"))
    errors = check_artifact(evidence["run"], "feature run") + check_run(run, path)
    errors.extend(expected_sites({**evidence, "scope": "intraprocedural"}, run))
    if run.get("status") != "failed":
        errors.extend(diagnostic_errors(evidence, run))
    return {
        "status": "limited" if errors else "passed",
        "limitations": [f"Optional capability {name}: {error}" for error in errors]
        + [f"Native capability {name}: {item}" for item in run.get("limitations", [])],
        "run": evidence["run"],
    }


def feature_capabilities(proof: JsonObject) -> dict[str, JsonObject]:
    if proof.get("profile") != PROFILE:
        return {}
    return {
        name: feature_capability(name, evidence)
        for name, evidence in proof.get("feature_runs", {}).items()
    }


def fixture_errors(name: str, evidence: JsonObject, root: Path) -> list[str]:
    expected = {
        str((root / filename).resolve()): hashlib.sha256(source.encode()).hexdigest()
        for filename, source in feature_files(name).items()
    }
    captured = {item["path"]: item["sha256"] for item in evidence["fixture_files"]}
    errors = []
    if captured != expected:
        errors.append(f"Psalm feature {name} fixtures disagree with the built-in contract")
    for item in evidence["fixture_files"]:
        errors.extend(check_artifact(item, "feature fixture"))
    if evidence.get("expect") != feature_expectations(name):
        errors.append(f"Psalm feature {name} expectations disagree with the built-in contract")
    if evidence.get("diagnostics") != diagnostic_expectations(name):
        errors.append(f"Psalm feature {name} diagnostic expectations disagree with the contract")
    return errors


def feature_identity_errors(
    evidence: JsonObject, run: JsonObject, core: JsonObject, root: Path
) -> list[str]:
    errors = []
    if evidence["fixture_root"] != str(root) or Path(run["cwd"]).resolve() != root:
        errors.append("Psalm feature fixture directory disagrees with its native run")
    expected = {"backend": "psalm", "language": "php", "scope": "intraprocedural", "phase": "probe"}
    if any(run.get(key) != value for key, value in expected.items()):
        errors.append("Psalm feature run has an invalid backend, language, scope or phase")
    if version_identity(run) != version_identity(core):
        errors.append("Psalm feature native executable/version disagrees with the core probe")
    return errors


def feature_snapshot_errors(name: str, run: JsonObject, root: Path) -> list[str]:
    snapshots = {
        item["original_path"]: item["sha256"]
        for key in ("config_files", "model_files")
        for item in run[key]
    }
    expected = {
        str((root / filename).resolve()): hashlib.sha256(source.encode()).hexdigest()
        for filename, source in feature_files(name).items()
        if filename != "probe.php"
    }
    if any(snapshots.get(path) != sha for path, sha in expected.items()):
        return [f"Psalm feature {name} configuration/model snapshots disagree with its fixture"]
    return []


def check_feature(name: str, evidence: JsonObject, core: JsonObject, root: Path) -> list[str]:
    from runner import check_run, check_run_artifacts

    errors = fixture_errors(name, evidence, root)
    errors.extend(check_artifact(evidence["run"], "feature run"))
    run = json.loads(Path(evidence["run"]["path"]).read_text(encoding="utf-8"))
    errors.extend(feature_identity_errors(evidence, run, core, root))
    errors.extend(check_run_artifacts(run))
    errors.extend(check_execution(run))
    errors.extend(feature_snapshot_errors(name, run, root))
    # A genuine unsupported feature is a limited capability. A completed run
    # whose stored findings disagree with its native output is corrupt evidence.
    if run.get("status") != "failed":
        errors.extend(check_run(run, Path(evidence["run"]["path"])))
    return errors


def check_feature_runs(proof: JsonObject, core: JsonObject) -> list[str]:
    runs = proof.get("feature_runs", {})
    if proof.get("profile") != PROFILE:
        return ["Psalm 7 feature evidence requires the v4 profile"] if runs else []
    errors = []
    if psalm_major(core.get("version", {}).get("output", "")) != 7:
        errors.append("Psalm 7 capability profile requires a captured Psalm 7 version")
    if not FEATURES or not isinstance(runs, dict) or set(runs) != set(FEATURES):
        return errors + ["Psalm 7 capability proof lacks the exact built-in feature inventory"]
    for name, evidence in runs.items():
        root = (Path(proof["fixture_root"]) / "features" / name).resolve()
        errors.extend(check_feature(name, evidence, core, root))
    return errors
