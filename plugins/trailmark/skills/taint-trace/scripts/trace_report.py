"""Render reviewed native evidence without exposing unvalidated finding summaries."""

from __future__ import annotations

import json
import re
from collections import Counter
from html import escape
from pathlib import Path
from urllib.parse import quote

from graph_context import rebind_anchor
from manifest_validation import ACTIVE, ValidationResult, validate_manifest
from trace_artifacts import JsonObject, read_json, record_path, relative


def report_text(value: object) -> str:
    """Keep target-derived text inside one Markdown block or table cell."""
    text = " ".join(str(value).split())
    return escape(re.sub(r"([\\`*_{}\[\]()#+\-.!|~])", r"\\\1", text), quote=False)


def report_code(value: object) -> str:
    """Choose a delimiter source text cannot close; raw artifacts retain whitespace."""
    text = " ".join(str(value).split())
    width = max((len(match[0]) for match in re.finditer(r"`+", text)), default=0) + 1
    delimiter = "`" * width
    return f"{delimiter} {text} {delimiter}"


def report_link(path: Path) -> str:
    # Encode destination syntax independently from the visible Markdown label.
    return f"[{report_text(path.name)}]({quote(path.as_posix(), safe='/')})"


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
            f"- {report_text(component.get('id', '?'))}: "
            f"{report_text(component.get('status', 'failed'))}; "
            f"{report_text(component.get('reason', ''))}"
        )
        for phase in ("probe", "baseline", "enriched"):
            if isinstance(component.get(phase), str):
                record = record_path(component[phase], base)
                lines.append(f"  - {phase} record: {report_link(record)}.")
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
        *[f"- {report_text(error)}" for error in result["errors"]],
        "",
        f"Manifest: {report_link(path.resolve())}.",
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
            f"| {report_text(component.get('id', '?'))} | "
            f"{report_text(component.get('language', '?'))} / "
            f"{report_text(component.get('backend', 'none'))} | "
            f"{report_text(component.get('status', 'failed'))} | "
            f"{report_text(component.get('scope', 'none'))} |"
            for component in components
        ],
    ]


def native_links(run: JsonObject, run_path: Path) -> list[str]:
    lines = []
    for key in ("native_output", "stdout", "stderr"):
        if run.get(key, {}).get("path"):
            raw = record_path(run[key]["path"], run_path.parent)
            lines.append(f"- Native {key}: {report_link(raw)}")
    return lines


def native_run_lines(run: JsonObject, run_path: Path, phase: str, target: Path) -> list[str]:
    coverage = run.get("scanned_files")
    measured = f"{len(coverage)} files" if coverage is not None else "unknown (limited)"
    return [
        "",
        f"**{phase}**: {len(run.get('findings', []))} findings; "
        f"native coverage {measured}; scope {report_text(run.get('scope', '?'))}.",
        f"Version: {report_text(run.get('version', {}).get('output', 'unknown'))}",
        f"Record: {report_link(run_path)}.",
        *native_links(run, run_path),
        *[
            f"- {report_code(item['rule_id'])} at {report_text(relative(item['file'], target))}:"
            f"{report_text(item['line'])}: {report_text(item['message'])}"
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
    lines = [
        "",
        f"### {report_text(component.get('id', '?'))}",
        "",
        report_text(component.get("reason", "")),
    ]
    records = {}
    for phase in ("baseline", "enriched"):
        if component.get("status") not in ACTIVE or not component.get(phase):
            continue
        try:
            run_path = record_path(component[phase], base)
            run = records[phase] = read_json(run_path)
            lines.extend(native_run_lines(run, run_path, phase, target))
        except (OSError, ValueError, KeyError, TypeError) as exc:
            lines.extend(["", f"Cannot read {phase} artifact: {report_text(exc)}"])
    lines.extend(finding_changes(records, target))
    if component.get("gaps"):
        lines.extend(
            ["", "Unresolved gaps:", "", *[f"- {report_text(gap)}" for gap in component["gaps"]]]
        )
    return lines


def model_report(
    model: JsonObject, original: JsonObject, rebound: JsonObject, target: Path
) -> list[str]:
    lines = [
        f"- **{report_text(model.get('id', '?'))}**: {report_text(model.get('role'))} "
        f"{report_code(model.get('value'))}; "
        f"contexts {report_text(', '.join(model.get('contexts', [])))}; "
        f"artifact {report_code(model.get('artifact'))}.",
        *[f"  - Evidence: {report_text(evidence)}" for evidence in model.get("evidence", [])],
        *[
            f"  - Assumption: {report_text(assumption)}"
            for assumption in model.get("assumptions", [])
        ],
    ]
    if rebound and model.get("anchor", {}).get("node_id") in original.get("graph", {}).get(
        "nodes", {}
    ):
        binding = rebind_anchor(model, original, rebound, target)
        lines.append(
            f"  - Rebound declaration: {report_text(binding['binding'])}; "
            f"{report_text(json.dumps(binding['matches']))}"
        )
    return lines


def coverage_report(manifest: JsonObject, result: ValidationResult) -> list[str]:
    return [
        "",
        "## Coverage and graph gaps",
        "",
        f"Original graph snapshot: {report_code(manifest.get('context', 'missing'))}.",
        f"Rebound graph snapshot: {report_code(manifest.get('rebound_context', 'none'))}.",
        "Source roots, exclusions, parse diagnostics, unresolved calls, candidate bindings,",
        "and reference/deferred edges remain in those snapshots. Native command arguments",
        "and model snapshots remain in run records. Language boundaries are separate.",
        "",
        *[f"- {report_text(limitation)}" for limitation in result["limitations"]],
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
        f"Status: **{report_text(result['status'])}**.",
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
