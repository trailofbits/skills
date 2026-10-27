"""Render reviewed native evidence without exposing unvalidated finding summaries."""

from __future__ import annotations

import json
from collections import Counter
from pathlib import Path

from graph_context import rebind_anchor
from manifest_validation import ACTIVE, ValidationResult, validate_manifest
from trace_artifacts import JsonObject, read_json, record_path, relative


def finding_key(item: JsonObject, target: Path) -> tuple:
    # Captured source text survives inserted docblocks; Counter preserves duplicates.
    return (
        item["rule_id"],
        relative(item["file"], target),
        item.get("source_line") or f"line:{item['line']}",
    )


def recorded_components(manifest: JsonObject, base: Path) -> list[str]:
    lines = []
    components = manifest.get("components")
    for component in components if isinstance(components, list) else []:
        if not isinstance(component, dict):
            continue
        lines.append(
            f"- {component.get('id', '?')}: {component.get('status', 'failed')}; "
            f"{component.get('reason', '')}"
        )
        for phase in ("probe", "baseline", "enriched"):
            if isinstance(component.get(phase), str):
                record = record_path(component[phase], base)
                lines.append(f"  - {phase} record: [{record.name}]({record.as_posix()}).")
    return lines


def failed_report(path: Path, manifest: JsonObject, result: ValidationResult) -> list[str]:
    # Failed inputs remain reviewable without presenting unvalidated findings or deltas.
    return [
        "# Taint trace",
        "",
        "Status: **failed**.",
        "",
        "Native artifacts failed validation; finding summaries and changes are unavailable.",
        "",
        "## Validation errors",
        "",
        *[f"- {error}" for error in result["errors"]],
        "",
        f"Manifest: [{path.name}]({path.resolve().as_posix()}).",
        "",
        "## Recorded components",
        "",
        *recorded_components(manifest, path.resolve().parent),
        "",
    ]


def component_table(components: list[JsonObject]) -> list[str]:
    return [
        "## Components",
        "",
        "| Component | Language / backend | Status | Scope |",
        "| --- | --- | --- | --- |",
        *[
            f"| {component.get('id', '?')} | {component.get('language', '?')} / "
            f"{component.get('backend', 'none')} | {component.get('status', 'failed')} | "
            f"{component.get('scope', 'none')} |"
            for component in components
        ],
    ]


def native_links(run: JsonObject, run_path: Path) -> list[str]:
    lines = []
    for key in ("native_output", "stdout", "stderr"):
        if run.get(key, {}).get("path"):
            raw = record_path(run[key]["path"], run_path.parent)
            lines.append(f"- Native {key}: [{raw.name}]({raw.as_posix()})")
    return lines


def native_run_lines(run: JsonObject, run_path: Path, phase: str, target: Path) -> list[str]:
    coverage = run.get("scanned_files")
    measured = f"{len(coverage)} files" if coverage is not None else "unknown (limited)"
    return [
        "",
        f"**{phase}**: {len(run.get('findings', []))} findings; "
        f"native coverage {measured}; scope {run.get('scope', '?')}.",
        f"Version: {run.get('version', {}).get('output', 'unknown').strip()}",
        f"Record: [{run_path.name}]({run_path.as_posix()}).",
        *native_links(run, run_path),
        *[
            f"- `{item['rule_id']}` at {relative(item['file'], target)}:"
            f"{item['line']}: {item['message']}"
            for item in run.get("findings", [])
        ],
    ]


def finding_changes(records: dict[str, JsonObject], target: Path) -> list[str]:
    if set(records) != {"baseline", "enriched"}:
        return []
    before, after = (
        Counter(finding_key(item, target) for item in records[phase].get("findings", []))
        for phase in ("baseline", "enriched")
    )
    return [
        "",
        f"Finding changes: {sum((after - before).values())} newly reported; "
        f"{sum((before - after).values())} no longer reported. "
        "These changes describe analyzer output, not confirmed fixes.",
    ]


def component_report(component: JsonObject, base: Path, target: Path) -> list[str]:
    lines = ["", f"### {component.get('id', '?')}", "", component.get("reason", "")]
    records = {}
    for phase in ("baseline", "enriched"):
        if component.get("status") not in ACTIVE or not component.get(phase):
            continue
        try:
            run_path = record_path(component[phase], base)
            run = records[phase] = read_json(run_path)
            lines.extend(native_run_lines(run, run_path, phase, target))
        except (OSError, ValueError, KeyError, TypeError) as exc:
            lines.extend(["", f"Cannot read {phase} artifact: {exc}"])
    lines.extend(finding_changes(records, target))
    if component.get("gaps"):
        lines.extend(["", "Unresolved gaps:", "", *[f"- {gap}" for gap in component["gaps"]]])
    return lines


def model_report(
    model: JsonObject, original: JsonObject, rebound: JsonObject, target: Path
) -> list[str]:
    lines = [
        f"- **{model.get('id', '?')}**: {model.get('role')} "
        f"`{model.get('value')}`; contexts {', '.join(model.get('contexts', []))}; "
        f"artifact `{model.get('artifact')}`.",
        *[f"  - Evidence: {evidence}" for evidence in model.get("evidence", [])],
        *[f"  - Assumption: {assumption}" for assumption in model.get("assumptions", [])],
    ]
    if rebound and model.get("anchor", {}).get("node_id") in original.get("graph", {}).get(
        "nodes", {}
    ):
        binding = rebind_anchor(model, original, rebound, target)
        lines.append(
            f"  - Rebound declaration: {binding['binding']}; {json.dumps(binding['matches'])}"
        )
    return lines


def coverage_report(manifest: JsonObject, result: ValidationResult) -> list[str]:
    return [
        "",
        "## Coverage and graph gaps",
        "",
        f"Original graph snapshot: `{manifest.get('context', 'missing')}`.",
        f"Rebound graph snapshot: `{manifest.get('rebound_context', 'none')}`.",
        "Source roots, exclusions, parse diagnostics, unresolved calls, candidate bindings,",
        "and reference/deferred edges remain in those snapshots. Native command arguments",
        "and model snapshots remain in run records. Language boundaries are separate.",
        "",
        *[f"- {limitation}" for limitation in result["limitations"]],
        "",
    ]


def validated_report(path: Path, manifest: JsonObject, result: ValidationResult) -> list[str]:
    base, target = path.resolve().parent, Path(manifest["target"]).resolve()
    original = read_json(record_path(manifest["context"], base))
    rebound = (
        read_json(record_path(manifest["rebound_context"], base))
        if manifest.get("rebound_context")
        else {}
    )
    lines = [
        "# Taint trace",
        "",
        f"Status: **{result['status']}**.",
        "",
        "Trailmark supplies structural evidence. Findings below come from native analyzers",
        "under the recorded model snapshots; graph reachability is not a taint trace.",
        "",
        *component_table(manifest["components"]),
    ]
    for component in manifest["components"]:
        lines.extend(component_report(component, base, target))
    lines.extend(["", "## Models and assumptions", ""])
    if not manifest["models"]:
        lines.append("No generated models.")
    for model in manifest["models"]:
        lines.extend(model_report(model, original, rebound, target))
    return [*lines, *coverage_report(manifest, result)]


def render_report(path: Path, output: Path) -> JsonObject:
    result = validate_manifest(path)
    try:
        manifest = read_json(path)
    except (OSError, ValueError):
        manifest = {}
    lines = (
        validated_report(path, manifest, result)
        if result["valid"]
        else failed_report(path, manifest, result)
    )
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text("\n".join(lines), encoding="utf-8")
    return {**result, "report": str(output.resolve())}
