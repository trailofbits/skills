"""Validate immutable graph, native execution, and model provenance records."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import TypedDict

from catalog import SCOPES, allowed_backend, canonical_language, language_source
from graph_context import context_errors, rebind_anchor
from trace_artifacts import JsonObject, digest, local_file, read_json, record_path, relative

ACTIVE = {"analyzed", "limited"}
ROLES = {"source", "sink", "sanitizer", "propagator", "type"}
type EnrichedRecords = dict[tuple[str, str], list[JsonObject]]


class ValidationResult(TypedDict):
    valid: bool
    stage: str
    active_components: int
    failed_components: int
    limited_components: int
    skipped_components: int
    status: str
    errors: list[str]
    limitations: list[str]


@dataclass
class ManifestEvidence:
    base: Path
    target: Path
    context: JsonObject
    rebound: JsonObject
    stage: str
    result: ValidationResult

    @property
    def errors(self) -> list[str]:
        return self.result["errors"]

    @property
    def limitations(self) -> list[str]:
        return self.result["limitations"]


def validate_manifest(path: Path, stage: str = "complete") -> ValidationResult:
    """Validate preserved native evidence, never infer taint from the graph."""
    result: ValidationResult = {
        "valid": False,
        "stage": stage,
        "active_components": 0,
        "failed_components": 0,
        "limited_components": 0,
        "skipped_components": 0,
        "status": "failed",
        "errors": [],
        "limitations": [],
    }
    try:
        _validate_manifest(path.resolve(), stage, result)
    except (OSError, ValueError, TypeError, KeyError, AttributeError) as exc:
        result["errors"].append(str(exc))
    result["valid"] = not result["errors"]
    if result["valid"]:
        limited = result["limitations"] or any(
            (
                result["limited_components"],
                result["skipped_components"],
                result["failed_components"],
            )
        )
        result["status"] = "limited" if limited else "analyzed"
    return result


def manifest_structure(manifest: JsonObject) -> Path:
    if manifest.get("schema_version") != 1:
        raise ValueError("Unsupported manifest schema_version")
    target = Path(manifest["target"]).resolve()
    if not target.is_dir():
        raise ValueError("Manifest target is not a directory")
    models, components = manifest["models"], manifest["components"]
    if not isinstance(models, list) or not isinstance(components, list) or not components:
        raise ValueError("Manifest needs model/component arrays and at least one component")
    return target


def changed_source_errors(models: list[JsonObject], context: JsonObject, target: Path) -> list[str]:
    # Canonical paths bind './src/x.php' and 'src/x.php' to the same retained source.
    artifacts = {relative(model["artifact"], target) for model in models}
    errors = []
    for file, sha in context["source_hashes"].items():
        if digest(local_file(file, target)) != sha and relative(file, target) not in artifacts:
            errors.append(f"Changed source has no model provenance: {file}")
    return errors


def load_rebound(manifest: JsonObject, evidence: ManifestEvidence) -> JsonObject:
    models, context = manifest["models"], evidence.context
    if evidence.stage != "complete" or not models:
        return context
    rebound_path = record_path(manifest.get("rebound_context"), evidence.base)
    if rebound_path == record_path(manifest["context"], evidence.base):
        evidence.errors.append("Rebound context must preserve a separate original snapshot")
    rebound = read_json(rebound_path)
    evidence.errors.extend(context_errors(rebound, evidence.target, current=True))
    if rebound.get("trailmark_version") != context.get("trailmark_version"):
        evidence.errors.append("Rebound context used a different Trailmark version")
    if rebound.get("languages") != context.get("languages"):
        evidence.errors.append("Rebound context changed the graph language-selection policy")
    evidence.errors.extend(changed_source_errors(models, context, evidence.target))
    for model in models:
        binding = rebind_anchor(model, context, rebound, evidence.target)
        if binding["binding"] != "resolved":
            evidence.limitations.append(
                f"{model['id']}: rebound declaration is {binding['binding']}"
            )
    return rebound


def _validate_manifest(path: Path, stage: str, result: ValidationResult) -> None:
    manifest = read_json(path)
    target = manifest_structure(manifest)
    context = read_json(record_path(manifest["context"], path.parent))
    evidence = ManifestEvidence(path.parent, target, context, context, stage, result)
    models = manifest["models"]
    if stage == "baseline" and models:
        evidence.errors.append("Baseline gate forbids generated models before baseline validation")
    evidence.errors.extend(
        context_errors(context, target, current=stage == "baseline" or not models)
    )
    if context.get("parse_diagnostics"):
        evidence.limitations.append(
            "Trailmark reported parse diagnostics; inspect original context"
        )
    evidence.rebound = load_rebound(manifest, evidence)
    for item in manifest.get("limitations", []):
        if not isinstance(item, str):
            raise ValueError("Manifest limitations must be strings")
        evidence.limitations.append(item)
    identities: set[str] = set()
    enriched: EnrichedRecords = {}
    for component in manifest["components"]:
        if component_is_active(component, identities, result):
            validate_component(component, evidence, enriched)
    if not result["active_components"]:
        evidence.errors.append(
            "No successfully analyzed components; fully skipped/failed is not success"
        )
    _validate_models(models, context, target, enriched, stage, errors=evidence.errors)


def string_array(value: object, *, nonempty: bool = False) -> bool:
    if not isinstance(value, list) or (nonempty and not value):
        return False
    return all(isinstance(item, str) and (not nonempty or bool(item.strip())) for item in value)


def component_is_active(
    component: JsonObject, identities: set[str], result: ValidationResult
) -> bool:
    ident, status = component["id"], component["status"]
    if not isinstance(ident, str) or not ident or ident in identities:
        raise ValueError("Component IDs must be nonempty and unique")
    identities.add(ident)
    if not isinstance(component.get("reason", ""), str):
        raise ValueError(f"{ident}: component reason must be a string")
    if not string_array(component.get("gaps", [])):
        raise ValueError(f"{ident}: component gaps must be a string array")
    if status in ACTIVE:
        result["active_components"] += 1
        result["limited_components"] += status == "limited"
        return True
    count_inactive_component(component, result)
    return False


def count_inactive_component(component: JsonObject, result: ValidationResult) -> None:
    ident, status = component["id"], component["status"]
    if status == "skipped":
        result["skipped_components"] += 1
    elif status == "failed":
        result["failed_components"] += 1
    else:
        result["errors"].append(f"{ident}: unknown component status {status}")
        return
    reason = component.get("reason")
    if not isinstance(reason, str) or not reason.strip():
        result["errors"].append(f"{ident}: {status} component needs a reason")


def component_inventory(component: JsonObject, evidence: ManifestEvidence) -> tuple[Path, set[str]]:
    ident, target = component["id"], evidence.target
    language = canonical_language(component["language"])
    if not allowed_backend(component["backend"], language) or component["scope"] not in SCOPES:
        evidence.errors.append(f"{ident}: unsupported language/backend/scope")
    counts = {
        canonical_language(name): count
        for name, count in evidence.context["summary"]["source_file_counts"].items()
    }
    if not counts.get(language):
        evidence.errors.append(f"{ident}: no Trailmark graph coverage for {language}")
    root = Path(component.get("root", target)).resolve()
    if not root.is_dir() or not root.is_relative_to(target):
        evidence.errors.append(f"{ident}: component root is not a directory within target")
    graph_files = {
        str((target / file).resolve())
        for file in evidence.context["source_hashes"]
        if language_source(file, language, set(counts))
        and (target / file).resolve().is_relative_to(root)
    }
    if not graph_files:
        evidence.errors.append(f"{ident}: component has zero graphed source files for {language}")
    return root, graph_files


def component_proof(component: JsonObject, evidence: ManifestEvidence) -> str | None:
    from runner import check_probe

    ident, scope = component["id"], component["scope"]
    proof_path = record_path(component["probe"], evidence.base)
    proof = read_json(proof_path)
    evidence.errors.extend(f"{ident}: {error}" for error in check_probe(proof, proof_path))
    evidence.limitations.extend(f"{ident}/probe: {item}" for item in proof.get("limitations", []))
    language = canonical_language(component["language"])
    if (
        proof.get("backend") != component["backend"]
        or canonical_language(proof.get("language", "")) != language
    ):
        evidence.errors.append(f"{ident}: probe identity mismatch")
    if scope != "intraprocedural" and not proof.get("expect", {}).get("cross_function"):
        evidence.errors.append(f"{ident}: claimed scope needs a real cross-function positive")
    if scope == "cross-translation-unit" and not proof.get("expect", {}).get("cross_file"):
        evidence.errors.append(f"{ident}: claimed scope needs a real cross-file positive")
    if proof.get("run"):
        run = read_json(record_path(proof["run"], proof_path.parent))
        return run.get("version", {}).get("output", "").strip()
    return None


def run_identity_errors(
    component: JsonObject, run: JsonObject, phase: str, version: str | None, root: Path
) -> list[str]:
    errors = []
    if version is not None and run.get("version", {}).get("output", "").strip() != version:
        errors.append("analyzer version differs from capability proof")
    expected = {
        "backend": component["backend"],
        "language": canonical_language(component["language"]),
        "phase": phase,
        "scope": component["scope"],
    }
    if any(run.get(key) != value for key, value in expected.items()):
        errors.append("run identity/scope mismatch")
    if run.get("status") not in ACTIVE:
        errors.append("native run failed")
    if Path(run["cwd"]).resolve() != root:
        errors.append("analyzer cwd differs from component root")
    return errors


def scan_overlap(
    run: JsonObject, graph_files: set[str], prefix: str, evidence: ManifestEvidence
) -> None:
    scanned = run.get("scanned_files")
    if scanned is None:
        return
    native_files = {str(Path(file).resolve()) for file in scanned}
    if not graph_files.intersection(native_files):
        evidence.errors.append(
            f"{prefix}: native scan has zero overlap with graphed target sources"
        )
    if native_files - graph_files:
        evidence.limitations.append(f"{prefix}: native files extend beyond the graph inventory")


def component_run(
    component: JsonObject,
    phase: str,
    evidence: ManifestEvidence,
    root: Path,
    graph_files: set[str],
    *,
    version: str | None,
) -> JsonObject:
    from runner import check_run

    run_path = record_path(component[phase], evidence.base)
    run = read_json(run_path)
    prefix = f"{component['id']}/{phase}"
    errors = check_run(run, run_path)
    errors.extend(run_identity_errors(component, run, phase, version, root))
    context = evidence.context if phase == "baseline" else evidence.rebound
    errors.extend(finding_source_errors(run, context, evidence.target))
    evidence.errors.extend(f"{prefix}: {error}" for error in errors)
    scan_overlap(run, graph_files, prefix, evidence)
    evidence.limitations.extend(f"{prefix}: {item}" for item in run.get("limitations", []))
    return run


def validate_component(
    component: JsonObject, evidence: ManifestEvidence, enriched: EnrichedRecords
) -> None:
    root, graph_files = component_inventory(component, evidence)
    version = component_proof(component, evidence)
    phases = ["baseline"] if evidence.stage == "baseline" else ["baseline", "enriched"]
    records = {
        phase: component_run(component, phase, evidence, root, graph_files, version=version)
        for phase in phases
    }
    if evidence.stage == "complete":
        language = canonical_language(component["language"])
        enriched.setdefault((language, component["backend"]), []).append(
            {**records["enriched"], "component_root": str(root)}
        )
        before, after = (records[phase].get("scanned_files") for phase in phases)
        if before is not None and after is not None and set(before) - set(after):
            evidence.errors.append(
                f"{component['id']}: enriched scan dropped files from the baseline coverage"
            )
    limited = component["scope"] in {"intraprocedural", "intrafile", "translation-unit"}
    limited |= any(run.get("status") == "limited" for run in records.values())
    if limited and component["status"] != "limited":
        evidence.errors.append(
            f"{component['id']}: limited native coverage/scope must be reported as limited"
        )
    if limited:
        evidence.limitations.append(
            f"{component['id']}: effective analysis scope {component['scope']}; "
            "inspect native coverage"
        )


def finding_snapshot_errors(
    finding: JsonObject, snapshot: JsonObject, expected_hash: str | None, file: str
) -> list[str]:
    if expected_hash is not None and snapshot["sha256"] != expected_hash:
        return [f"Finding source snapshot differs from graph source hash: {file}"]
    lines = Path(snapshot["path"]).read_text(encoding="utf-8", errors="replace").splitlines()
    line = finding["line"]
    expected = lines[line - 1].strip() if 0 < line <= len(lines) else ""
    if finding.get("source_line") != expected:
        return [f"Finding source snippet disagrees with preserved source: {file}:{line}"]
    return []


def finding_source_errors(run: JsonObject, context: JsonObject, target: Path) -> list[str]:
    """Bind delta identities to preserved bytes, including an edited baseline's old lines."""
    snapshots = {
        relative(item["file"], target): item for item in context.get("source_snapshots", [])
    }
    errors = []
    for finding in run.get("findings", []):
        file = relative(finding["file"], target)
        snapshot = snapshots.get(file)
        if snapshot is None:
            if file in context.get("source_hashes", {}):
                errors.append(f"Finding source snippet has no preserved source snapshot: {file}")
            continue  # Findings outside graph coverage remain an explicit limitation.
        expected_hash = context.get("source_hashes", {}).get(file)
        errors.extend(finding_snapshot_errors(finding, snapshot, expected_hash, file))
    return errors


def validate_model_fields(model: JsonObject, errors: list[str]) -> None:
    ident = model["id"]
    if model["role"] not in ROLES:
        errors.append(f"{ident}: unsupported model role")
    for key in ("contexts", "evidence"):
        if not string_array(model[key], nonempty=True):
            raise ValueError(f"{ident}: {key} must contain nonempty strings")
    if not string_array(model["assumptions"]):
        errors.append(f"{ident}: assumptions must be a string array")
    if not isinstance(model["value"], str) or not model["value"].strip():
        errors.append(f"{ident}: affected value binding is missing")


def model_anchor_errors(model: JsonObject, context: JsonObject, target: Path) -> list[str]:
    ident, anchor = model["id"], model["anchor"]
    node = context["graph"]["nodes"].get(anchor["node_id"])
    if not node:
        return [f"{ident}: anchor node is absent from original graph"]
    errors, location = [], node.get("location") or {}
    if relative(location.get("file_path", ""), target) != anchor["file"]:
        errors.append(f"{ident}: anchor file differs from graph declaration")
    start, end = anchor["start_line"], anchor["end_line"]
    valid_lines = isinstance(start, int) and isinstance(end, int)
    if not valid_lines or not (
        0 < location.get("start_line", 0) <= start <= end <= location.get("end_line", 0)
    ):
        errors.append(f"{ident}: anchor span is outside graph declaration")
    return errors


def unsafe_sanitizer(model: JsonObject) -> bool:
    if model["role"] != "sanitizer":
        return False
    erases_kinds = model["backend"] in {"clang", "checker-framework"}
    wildcard = any(value.lower().strip() in {"*", "all", "any"} for value in model["contexts"])
    return erases_kinds or wildcard


def model_snapshot_matches(model: JsonObject, target: Path, enriched: EnrichedRecords) -> bool:
    artifact = local_file(model["artifact"], target)
    language = canonical_language(model["language"])
    anchor = (target / model["anchor"]["file"]).resolve()
    for run in enriched.get((language, model["backend"]), []):
        if not anchor.is_relative_to(Path(run.get("component_root", target))):
            continue
        for item in run.get("model_files", []):
            original = Path(item.get("original_path", item["path"])).resolve()
            if artifact == original and digest(artifact) == item["sha256"]:
                return True
    return False


def model_binding(model: JsonObject) -> tuple:
    return (
        model["backend"],
        model["anchor"]["node_id"],
        model["role"],
        model["value"],
        tuple(sorted(model["contexts"])),
    )


def _validate_models(
    models: list[JsonObject],
    context: JsonObject,
    target: Path,
    enriched: EnrichedRecords,
    stage: str,
    *,
    errors: list[str],
) -> None:
    ids, bindings = set(), set()
    for model in models:
        ident = model["id"]
        if not isinstance(ident, str) or not ident or ident in ids:
            raise ValueError("Model IDs must be nonempty and unique")
        ids.add(ident)
        validate_model_fields(model, errors)
        if unsafe_sanitizer(model):
            errors.append(f"{ident}: sanitizer cannot safely erase independent vulnerability kinds")
        errors.extend(model_anchor_errors(model, context, target))
        binding = model_binding(model)
        if binding in bindings:
            errors.append(f"{ident}: duplicate annotation/model binding")
        bindings.add(binding)
        local_file(model["artifact"], target)
        if stage == "complete" and not model_snapshot_matches(model, target, enriched):
            errors.append(f"{ident}: native enriched run did not snapshot the model artifact")
