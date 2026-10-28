"""Check native capability anchors and retain optional capability limitations."""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

from contracts import psalm_core_expectations, psalm_optional_expectations
from runner_artifacts import check_artifact

JsonObject = dict[str, Any]
Site = tuple[str, int, str | None]
CATEGORIES = ("positive", "negative", "cross_function", "cross_file")
PSALM_PROFILES = {
    "psalm-conditional-nodes-v1",
    "psalm-taint-contracts-v2",
    "psalm-taint-contracts-v3",
}


def anchor(root: Path, site: JsonObject) -> Site:
    path, line = (root / site["file"]).resolve(), site["line"]
    if not path.is_relative_to(root) or type(line) is not int or line < 1:
        raise ValueError("Anchor must stay inside the fixture with a positive line")
    if line > len(path.read_text(encoding="utf-8").splitlines()):
        raise ValueError("Anchor exceeds fixture source")
    rule = site.get("rule_id")
    if rule is not None and (not isinstance(rule, str) or not rule):
        raise ValueError("Fixture rule_id must be a nonempty string")
    return str(path), line, rule


def read_sites(proof: JsonObject) -> tuple[dict[str, set[Site]], list[str]]:
    root = Path(proof["fixture_root"]).resolve()
    expected = proof.get("expect", {})
    if not isinstance(expected, dict):
        return {}, ["Capability expectations must be an object"]
    sites: dict[str, set[Site]] = {}
    errors = []
    for category in CATEGORIES:
        values = expected.get(category, [])
        if not isinstance(values, list) or (category in {"positive", "negative"} and not values):
            errors.append(f"Capability contract needs nonempty {category} anchors")
            continue
        sites[category] = set()
        for site in values:
            try:
                sites[category].add(anchor(root, site))
            except (OSError, KeyError, TypeError, ValueError) as exc:
                errors.append(f"Invalid {category} fixture anchor: {exc}")
    return sites, errors


def matches(site: Site, actual: set[Site]) -> bool:
    return any(item[:2] == site[:2] and (site[2] is None or item[2] == site[2]) for item in actual)


def site_findings(sites: dict[str, set[Site]], run: JsonObject) -> list[str]:
    actual = {(item["file"], item["line"], item.get("rule_id")) for item in run.get("findings", [])}
    errors = []
    for category in ("positive", "cross_function", "cross_file"):
        for site in sorted(sites.get(category, set()), key=lambda item: str(item)):
            if not matches(site, actual):
                errors.append(f"Native capability finding missing for {category} at {site}")
    positive_files = {site[0] for site in sites.get("positive", set())}
    for site in sorted(sites.get("negative", set()), key=lambda item: str(item)):
        if matches(site, actual):
            errors.append(f"Native analyzer reported literal/sanitized negative at {site}")
        if site[0] not in positive_files and site[0] not in (run.get("scanned_files") or []):
            errors.append(f"Negative fixture was not observably scanned: {site[0]}")
    return errors


def site_scope(sites: dict[str, set[Site]], scope: str) -> list[str]:
    errors = []
    if scope in {
        "intrafile",
        "interprocedural",
        "translation-unit",
        "cross-translation-unit",
    } and not sites.get("cross_function"):
        errors.append("Claimed scope needs a real cross-function positive finding")
    if scope == "cross-translation-unit" and not sites.get("cross_file"):
        errors.append("Claimed scope needs a real cross-file positive finding")
    if any(
        positive[:2] == negative[:2]
        and (positive[2] is None or negative[2] is None or positive[2] == negative[2])
        for positive in sites.get("positive", set())
        for negative in sites.get("negative", set())
    ):
        errors.append("Positive and negative fixture anchors overlap")
    return errors


def trace_enters_method(finding: JsonObject, method: str) -> bool:
    trace = finding.get("trace")
    if not isinstance(trace, list):
        return False
    pattern = rf"(?<![\w$]){re.escape(method)}(?![\w$])"
    return any(
        isinstance(node, dict) and re.search(pattern, str(node.get("method", ""))) for node in trace
    )


def trace_site_errors(
    site: JsonObject, root: Path, run: JsonObject, *, required: bool
) -> list[str]:
    methods = site.get("trace_methods", [])
    if not isinstance(methods, list) or not all(
        isinstance(method, str) and method.strip() for method in methods
    ):
        return ["Capability trace_methods must be a list of nonempty method names"]
    if required and not methods:
        return ["Joern cross-function capability needs native trace_methods expectations"]
    try:
        expected = anchor(root, site)
    except (OSError, KeyError, TypeError, ValueError):
        return []  # read_sites reports invalid source anchors.
    findings = [
        item
        for item in run.get("findings", [])
        if matches(expected, {(item["file"], item["line"], item.get("rule_id"))})
    ]
    if methods and not any(
        all(trace_enters_method(finding, method) for method in methods) for finding in findings
    ):
        return [f"Native capability trace does not enter required methods {methods} at {expected}"]
    return []


def native_trace_errors(proof: JsonObject, run: JsonObject) -> list[str]:
    expected = proof.get("expect", {})
    if not isinstance(expected, dict):
        return []  # read_sites reports invalid expectation structures.
    errors = []
    for category in ("cross_function", "cross_file"):
        sites = expected.get(category, [])
        if not isinstance(sites, list):
            continue
        for site in sites:
            if not isinstance(site, dict):
                continue
            errors.extend(
                trace_site_errors(
                    site,
                    Path(proof["fixture_root"]).resolve(),
                    run,
                    required=proof.get("backend") == "joern",
                )
            )
    return errors


def expected_sites(proof: JsonObject, run: JsonObject) -> list[str]:
    sites, errors = read_sites(proof)
    errors.extend(site_findings(sites, run))
    errors.extend(site_scope(sites, proof.get("scope", "")))
    errors.extend(native_trace_errors(proof, run))
    return errors


def optional_capabilities(proof: JsonObject, run: JsonObject) -> dict[str, JsonObject]:
    capabilities = {}
    for name, expect in proof.get("optional_expect", {}).items():
        checks = expected_sites({**proof, "scope": "intraprocedural", "expect": expect}, run)
        limitations = [f"Optional capability {name}: {error}" for error in checks]
        capabilities[name] = {
            "status": "limited" if checks else "passed",
            "limitations": limitations,
        }
    return capabilities


def capability_limitations(capabilities: dict[str, JsonObject]) -> list[str]:
    return [item for result in capabilities.values() for item in result["limitations"]]


def check_optional_capabilities(proof: JsonObject, run: JsonObject) -> list[str]:
    actual = optional_capabilities(proof, run)
    errors = []
    if actual != proof.get("optional_capabilities", {}):
        errors.append("Recorded optional capabilities disagree with native analyzer findings")
    limitations = capability_limitations(actual)
    if any(item not in proof.get("limitations", []) for item in limitations):
        errors.append("Capability proof omits native optional capability limitations")
    if any(item not in run.get("limitations", []) for item in limitations):
        errors.append("Native run omits optional capability limitations")
    if limitations and run.get("status") != "limited":
        errors.append("Native run with unsupported optional capabilities must be limited")
    return errors


def check_probe_baseline(proof: JsonObject, run: JsonObject) -> list[str]:
    """Validate the annotation-gap control with the same native executable/version."""
    from runner import check_run

    if proof.get("profile") not in PSALM_PROFILES:
        return []
    if proof.get("backend") != "psalm":
        return ["Psalm capability profile requires the Psalm backend"]
    errors = []
    try:
        path = Path(proof["baseline_run"])
        baseline = json.loads(path.read_text(encoding="utf-8"))
        errors.extend(check_run(baseline, path))
        for key in ("backend", "language", "scope", "version"):
            if baseline.get(key) != run.get(key):
                errors.append(f"Capability baseline {key} disagrees with enriched probe")
        if baseline.get("phase") != "baseline":
            errors.append("Capability annotation control must reference a baseline invocation")
        if baseline.get("findings"):
            errors.append("Unmodeled capability baseline unexpectedly reported taint findings")
    except (OSError, ValueError, KeyError, TypeError, AttributeError) as exc:
        errors.append(f"Capability baseline cannot be validated: {exc}")
    return errors


def check_profile(proof: JsonObject) -> list[str]:
    if proof.get("profile") != "psalm-taint-contracts-v3":
        return []
    errors = []
    if proof.get("expect") != psalm_core_expectations():
        errors.append(
            "Built-in Psalm required expectations disagree with the native fixture contract"
        )
    if proof.get("optional_expect") != psalm_optional_expectations():
        errors.append(
            "Built-in Psalm optional expectations disagree with the native fixture contract"
        )
    return errors


def check_fixture_binding(proof: JsonObject, run: JsonObject) -> list[str]:
    errors = []
    root = Path(proof["fixture_root"]).resolve()
    if Path(run["cwd"]).resolve() != root:
        errors.append("Capability fixture directory disagrees with native run working directory")
    captured = {
        Path(item["path"]).resolve(): item["sha256"] for item in proof.get("fixture_files", [])
    }
    for values in proof.get("expect", {}).values():
        for site in values:
            if (root / site["file"]).resolve() not in captured:
                errors.append("Capability anchor has no immutable fixture capture")
    for item in run.get("model_files", []):
        original = Path(item["original_path"]).resolve()
        if original.is_relative_to(root) and captured.get(original) != item["sha256"]:
            errors.append("Probe model snapshot disagrees with captured fixture")
    return errors


def check_probe_artifacts(proof: JsonObject) -> list[str]:
    errors = []
    if not proof.get("fixture_files"):
        errors.append("Capability proof has no captured fixture files")
    for item in proof.get("fixture_files", []):
        errors.extend(check_artifact(item, "fixture"))
    for step in proof.get("preparation", []):
        for key in ("stdout", "stderr"):
            errors.extend(check_artifact(step.get(key, {}), "preparation"))
        if step.get("returncode") != 0:
            errors.append("Probe preparation failed")
    return errors


def check_probe_header(proof: JsonObject, proof_path: Path) -> list[str]:
    errors = []
    if (
        proof.get("schema_version") != 1
        or proof.get("kind") != "probe"
        or proof.get("status") != "passed"
    ):
        errors.append(f"Native capability probe did not pass: {proof_path}")
    if proof.get("errors"):
        errors.append("Capability proof contains errors")
    return errors


def check_probe(proof: JsonObject, proof_path: Path) -> list[str]:
    from runner import check_run

    if not isinstance(proof, dict):
        return ["Native capability proof must be a JSON object"]
    errors = check_probe_header(proof, proof_path)
    try:
        run_path = Path(proof["run"])
        run = json.loads(run_path.read_text(encoding="utf-8"))
        errors.extend(check_run(run, run_path))
        for key in ("backend", "language", "scope"):
            if proof.get(key) != run.get(key):
                errors.append(f"Probe {key} disagrees with native run")
        if run.get("phase") != "probe":
            errors.append("Capability proof must reference a probe invocation")
        errors.extend(expected_sites(proof, run))
        errors.extend(check_probe_baseline(proof, run))
        errors.extend(check_profile(proof))
        errors.extend(check_fixture_binding(proof, run))
        errors.extend(check_optional_capabilities(proof, run))
        errors.extend(check_probe_artifacts(proof))
    except (OSError, ValueError, KeyError, TypeError, AttributeError) as exc:
        errors.append(f"Capability proof cannot be validated: {exc}")
    return errors
