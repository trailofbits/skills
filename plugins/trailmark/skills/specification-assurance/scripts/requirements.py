# /// script
# requires-python = ">=3.11"
# dependencies = ["tomli-w>=1.2"]
# ///
"""Extract Duvet legacy-JSON requirements and gate an assurance evidence ledger.

Checks accounting and artifact presence, not the truth of semantic judgments.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import subprocess
import sys
import tempfile
import tomllib
from collections import Counter
from pathlib import Path
from typing import Any

import tomli_w

VERDICTS = {
    "supported",
    "partial",
    "violated",
    "missing",
    "unknown",
    "not_applicable",
    "not_checked",
}
SEVERITIES = {"critical", "high", "medium", "low", "info"}
DIVERGENCES = {"partial", "violated", "missing"}
ANALYSIS_ARTIFACTS = (
    "graph.json",
    "source-policy.json",
    "diagnostics.json",
    "graph-scope.json",
    "duvet-before.json",
    "inventory.json",
)


def read_json(path: Path) -> Any:
    return json.loads(path.read_text())


def file_sha256(path: Path) -> str:
    with path.open("rb") as source:
        return hashlib.file_digest(source, "sha256").hexdigest()


def access_state(path: Path) -> dict[str, int]:
    state = path.stat()
    return {"mode": state.st_mode & 0o7777, "uid": state.st_uid, "gid": state.st_gid}


def file_state(path: Path) -> dict[str, Any]:
    if not path.is_file():
        raise ValueError(f"Snapshot input is not a regular file: {path}")
    state = {"sha256": file_sha256(path), **access_state(path)}
    resolved = path.resolve()
    if resolved != path.absolute():
        state["resolved"] = str(resolved)
    if path.is_symlink():
        state["symlink"] = os.readlink(path)
    return state


def nonempty(value: Any) -> bool:
    return isinstance(value, str) and bool(value.strip())


def implementation_spans(spec: dict[str, Any], annotations: list[Any]) -> dict[int, list[int]]:
    """Count each SPEC span once, taking the union of citation/implication coverage.

    Duvet's legacy sections contain lines of [annotation IDs, status ID, text]
    spans. Its status counts measure UTF-8 bytes, not normalized quotation length.
    Exceptions, tests, and TODOs cannot supply implementation traceability.
    """
    counts: dict[int, list[int]] = {}
    for section in spec.get("sections", []):
        for line in section["lines"]:
            if isinstance(line, str):
                continue
            for ids, _, text in line:
                if (
                    not isinstance(ids, list)
                    or not isinstance(text, str)
                    or any(
                        type(index) is not int
                        or not 0 <= index < len(annotations)
                        or not isinstance(annotations[index], dict)
                        for index in ids
                    )
                ):
                    raise ValueError("Invalid Duvet coverage span")
                types = {annotations[index].get("type", "CITATION") for index in ids}
                size = len(text.encode("utf-8"))
                for index in ids:
                    if annotations[index].get("type") == "SPEC":
                        total, covered = counts.setdefault(index, [0, 0])
                        counts[index] = [
                            total + size,
                            covered + (size if types & {"CITATION", "IMPLICATION"} else 0),
                        ]
    return counts


def specification_key(value: str, root: Path) -> str:
    return value if "://" in value else str((root / value).resolve())


def inventory(
    path: Path, specifications: list[str] | None = None, root: Path | None = None
) -> list[dict[str, Any]]:
    """Retain the full requirement denominator, including uncited obligations."""
    report = read_json(path)
    if not isinstance(report, dict) or not isinstance(report.get("specifications"), dict):
        raise ValueError("Expected Duvet legacy JSON from --json, not --json-v2")
    if any("://" in value for value in [*(specifications or []), *report["specifications"]]):
        raise ValueError("Pin remote specifications to local files before assessment")
    annotations = report.get("annotations")
    if not isinstance(annotations, list) or not isinstance(report.get("statuses"), dict):
        raise ValueError("Missing Duvet annotations or statuses")
    root = root or Path.cwd()
    configured = {specification_key(value, root) for value in report["specifications"]}
    missing = [
        value for value in specifications or [] if specification_key(value, root) not in configured
    ]
    if missing:
        raise ValueError(f"Requested specifications absent from Duvet report: {missing}")
    requirements = []
    referenced = set()
    for specification, spec in report["specifications"].items():
        if not isinstance(spec, dict) or not isinstance(spec.get("requirements"), list):
            raise ValueError(f"Invalid requirement inventory for {specification}")
        if not spec["requirements"]:
            raise ValueError(f"Duvet extracted zero requirements from {specification}")
        coverage = implementation_spans(spec, annotations)
        for index in spec["requirements"]:
            if type(index) is not int or not 0 <= index < len(annotations):
                raise ValueError("Invalid Duvet requirement annotation index")
            annotation = annotations[index]
            if not isinstance(annotation, dict) or annotation.get("type") != "SPEC":
                raise ValueError("Requirement index does not reference a SPEC annotation")
            if annotation.get("target_path") != specification or not nonempty(
                annotation.get("comment")
            ):
                raise ValueError(
                    "Requirement has no quotation or targets a different specification"
                )
            quote = " ".join(annotation["comment"].split())
            section = annotation.get("target_section", "")
            level = annotation.get("level", "AUTO")
            if not isinstance(section, str) or not nonempty(level):
                raise ValueError("Requirement section and level must be strings")
            identity = json.dumps([specification, section, level, quote], ensure_ascii=False)
            status = report["statuses"].get(str(index), {})
            if not isinstance(status, dict) or any(
                type(status.get(key, 0)) is not int or status.get(key, 0) < 0
                for key in (
                    "spec",
                    "incomplete",
                    "citation",
                    "test",
                    "implication",
                    "exception",
                    "todo",
                )
            ):
                raise ValueError("Duvet status character counts must be nonnegative integers")
            related = status.get("related", [])
            if not isinstance(related, list) or any(
                type(item) is not int or not 0 <= item < len(annotations) for item in related
            ):
                raise ValueError("Invalid related Duvet annotation indices")
            referenced.add(index)
            requirements.append(
                {
                    "id": hashlib.sha256(identity.encode()).hexdigest()[:20],
                    "specification": specification,
                    "section": section,
                    "level": level,
                    "quote": quote,
                    "annotation_index": index,
                    "citation_characters": status.get("citation", 0),
                    "test_characters": status.get("test", 0),
                    "implication_characters": status.get("implication", 0),
                    "implementation_complete": (
                        status.get("spec", 0) > 0
                        and coverage.get(index) == [status["spec"], status["spec"]]
                    ),
                    "related_annotations": related,
                }
            )
    if not requirements:
        raise ValueError("Duvet extracted zero requirements; no assurance assessment was performed")
    ids = [requirement["id"] for requirement in requirements]
    if len(ids) != len(set(ids)):
        raise ValueError("Duplicate requirement identities; resolve ambiguous extraction")
    if referenced != {
        index
        for index, annotation in enumerate(annotations)
        if isinstance(annotation, dict) and annotation.get("type") == "SPEC"
    }:
        raise ValueError("Duvet inventory omitted SPEC annotations; retain every requirement")
    return requirements


def local_file(root: Path, value: Any, *, canonical: bool = True) -> Path:
    if not nonempty(value):
        raise ValueError("Evidence file path is empty")
    path = root / value
    resolved = path.resolve()
    if not resolved.is_relative_to(root) or not resolved.is_file():
        raise ValueError(f"Evidence file is missing or outside target: {value}")
    return resolved if canonical else path


def location(root: Path, value: Any) -> None:
    if not isinstance(value, dict):
        raise ValueError("Evidence location must be an object with file and line")
    path = local_file(root, value.get("file"))
    line = value.get("line")
    if type(line) is not int or not 1 <= line <= len(path.read_text().splitlines()):
        raise ValueError(f"Invalid source line in {value.get('file')}")


def evidence_files(record: dict[str, Any]) -> set[str]:
    return (
        {anchor["file"] for anchor in record["implementation"]}
        | {check["location"]["file"] for check in record["checks"]}
        | {check["log"] for check in record["checks"] if check["result"] != "not_run"}
        | set(record.get("inputs", []))
    )


def verify_files(root: Path, record: dict[str, Any], required: set[str], cache: dict) -> None:
    hashes = record.get("files")
    if not isinstance(hashes, dict) or not required <= set(hashes):
        raise ValueError("Missing SHA-256 bindings for referenced evidence files")
    for name, expected in hashes.items():
        path = local_file(root, name, canonical=False)
        if path not in cache:
            cache[path] = file_state(path)
        if cache[path] != expected:
            raise ValueError(f"Evidence file changed since assessment: {name}")


def record_errors(
    root: Path,
    record: dict[str, Any],
    requirement: dict[str, Any],
    traceability: bool = True,
    cache: dict | None = None,
) -> list[str]:
    errors = []
    try:
        verdict = record.get("verdict")
        if verdict not in VERDICTS or not nonempty(record.get("rationale")):
            raise ValueError("Missing verdict or rationale")
        if verdict in DIVERGENCES and (
            record.get("severity") not in SEVERITIES or not nonempty(record.get("consequence"))
        ):
            raise ValueError(
                "Divergence needs severity (critical/high/medium/low/info) and consequence"
            )
        if not isinstance(record.get("assumptions"), list) or not all(
            nonempty(item) for item in record["assumptions"]
        ):
            raise ValueError("assumptions must be an array of nonempty strings")
        implementations, checks = record.get("implementation"), record.get("checks")
        if not isinstance(implementations, list) or not isinstance(checks, list):
            raise ValueError("implementation and checks must be arrays")
        if not isinstance(record.get("inputs", []), list) or not all(
            nonempty(item) for item in record.get("inputs", [])
        ):
            raise ValueError("inputs must be an array of file paths")
        for anchor in implementations:
            location(root, anchor)
            if anchor.get("role") not in {"production", "model"}:
                raise ValueError("Implementation location needs production/model role")
        passing = 0
        for check in checks:
            if not isinstance(check, dict) or check.get("kind") not in {"test", "formal"}:
                raise ValueError("Check kind must be test or formal")
            if check.get("scope") not in {"implementation", "model"}:
                raise ValueError("Check scope must be implementation or model")
            if check.get("result") not in {"pass", "fail", "unknown", "not_run"}:
                raise ValueError("Invalid native check result")
            if not nonempty(check.get("property")) or not nonempty(check.get("command")):
                raise ValueError("Check needs its exact property and command")
            location(root, check.get("location"))
            if check["result"] != "not_run":
                log = local_file(root, check.get("log"))
                if log.stat().st_size == 0:
                    raise ValueError("Native evidence log is empty")
            if check["result"] == "pass":
                if type(check.get("exit_code")) is not int or check["exit_code"] != 0:
                    raise ValueError("A passing check needs native exit_code 0")
                if check["scope"] == "implementation":
                    if check["kind"] == "formal" and not nonempty(check.get("binding")):
                        raise ValueError(
                            "Formal implementation evidence needs a model-to-code binding"
                        )
                    passing += 1
        if verdict == "supported":
            if not any(anchor["role"] == "production" for anchor in implementations):
                raise ValueError("Supported requirement has no production enforcement location")
            if not passing:
                raise ValueError("Supported requirement has no passing implementation check")
            if any(check["result"] == "fail" for check in checks):
                raise ValueError("Supported requirement has contradictory native failures")
            if traceability and not requirement["implementation_complete"]:
                raise ValueError(
                    "Supported requirement lacks complete Duvet implementation traceability"
                )
        verify_files(root, record, evidence_files(record), {} if cache is None else cache)
    except (ValueError, TypeError, KeyError) as error:
        errors.append(f"{requirement['id']}: {error}")
    return errors


def check_ledger(
    baseline: Path,
    report: Path,
    ledger_path: Path,
    root: Path,
    specifications: list[str] | None = None,
    expected_ids: list[str] | None = None,
    failed_ids: list[str] | None = None,
    limitations: list[str] | None = None,
    traceability: bool = True,
) -> dict[str, Any]:
    before = {item["id"] for item in inventory(baseline, specifications, root)}
    current = {item["id"]: item for item in inventory(report, specifications, root)}
    errors = []
    if before != set(current):
        errors.append(
            "Specification inventory changed; retain the assessed specification and denominator"
        )
    if expected_ids is not None and (
        len(expected_ids) != len(before) or set(expected_ids) != before
    ):
        errors.append("Workflow requirement IDs differ from the retained baseline inventory")
    ledger = read_json(ledger_path)
    if not isinstance(ledger, dict) or not isinstance(ledger.get("requirements"), list):
        raise ValueError("Ledger needs a requirements array")
    recorded_limitations = ledger.get("limitations")
    if not isinstance(recorded_limitations, list) or not all(
        nonempty(item) for item in recorded_limitations
    ):
        raise ValueError("Ledger needs a limitations array of nonempty strings")
    if any(item not in recorded_limitations for item in limitations or []):
        errors.append("Setup limitations were lost from the final ledger")
    records = ledger["requirements"]
    if any(not isinstance(record, dict) or not nonempty(record.get("id")) for record in records):
        raise ValueError("Every requirement record needs an id")
    ids = [record["id"] for record in records]
    if len(ids) != len(set(ids)):
        errors.append("Duplicate ledger requirement records")
    if set(ids) != set(current):
        errors.append("Ledger omitted or invented requirements")
    by_id = {record["id"]: record for record in records}
    for failed_id in failed_ids or []:
        if failed_id not in before or by_id.get(failed_id, {}).get("verdict") != "not_checked":
            errors.append(f"Failed worker {failed_id} must retain its own not_checked record")
    cache = {}
    for record in records:
        if record["id"] in current:
            errors.extend(record_errors(root, record, current[record["id"]], traceability, cache))
    counts = Counter(record.get("verdict", "invalid") for record in records)
    if records and counts.get("not_applicable", 0) == len(records):
        errors.append("No applicable requirements were assessed")
    gaps = any(verdict not in {"supported", "not_applicable"} for verdict in counts) or bool(
        recorded_limitations
    )
    return {
        "valid": not errors,
        "status": "invalid" if errors else "gaps" if gaps else "supported",
        "total": len(current),
        "verdicts": dict(sorted(counts.items())),
        "limitations": recorded_limitations,
        "errors": errors,
    }


def graph_evidence(
    run: Path, root: Path, expected_production_files: int, snapshot: dict[str, Any]
) -> tuple[dict[str, Any], set[Path], set[Path]]:
    """Reconcile native graph counts, inspected paths, and production scope."""
    paths = {
        name: local_file(root, str(run / f"{name}.json"))
        for name in (
            "graph",
            "source-policy",
            "diagnostics",
            "graph-scope",
        )
    }
    graph, policy, diagnostics, scope = (read_json(path) for path in paths.values())
    if (
        not isinstance(graph, dict)
        or graph.get("schema_version") != 1
        or not isinstance(graph.get("nodes"), dict)
        or (not graph["nodes"] and not diagnostics)
        or not isinstance(graph.get("summary"), dict)
    ):
        raise ValueError("Missing or empty native Trailmark graph")
    summary = graph["summary"]
    if not isinstance(policy, dict) or not policy or graph.get("source_policy") != policy:
        raise ValueError("Retained source policy differs from the native graph")
    if not isinstance(diagnostics, list) or summary.get("parse_diagnostics") != diagnostics:
        raise ValueError("Retained diagnostics differ from the native graph")
    captured = {root / name for name, state in snapshot.items() if "sha256" in state}

    def captured_file(value: Any) -> Path:
        path = local_file(root, value)
        if root / value not in captured:
            raise ValueError("Inspected graph files lack source snapshot bindings")
        return path

    selected = []
    pending = [policy]
    while pending:
        manifest = pending.pop()
        if not isinstance(manifest, dict):
            raise ValueError("Invalid Trailmark source-policy manifest")
        if "components" in manifest:
            components = manifest["components"]
            if not isinstance(components, list) or not components:
                raise ValueError("Empty or invalid merged source policy")
            pending.extend(components)
            continue
        if not isinstance(manifest.get("files"), list):
            raise ValueError("Missing inspected-file evidence in source policy")
        for item in manifest["files"]:
            if not isinstance(item, dict):
                raise ValueError("Invalid source-policy file record")
            if item.get("status") == "inspected" and item.get("unit") == "file":
                selected.append(captured_file(item.get("path")))
    count = summary.get("source_files")
    if (
        not selected
        or len(selected) != len(set(selected))
        or type(count) is not int
        or count != len(selected)
    ):
        raise ValueError("Native graph source count disagrees with inspected files or is zero")
    production = scope.get("production_files") if isinstance(scope, dict) else None
    if not isinstance(production, list) or not production:
        raise ValueError("Graph scope needs a nonempty production_files array")
    production = [captured_file(path) for path in production]
    if (
        len(set(production)) != len(production)
        or not set(production) <= set(selected)
        or type(expected_production_files) is not int
        or expected_production_files != len(production)
    ):
        raise ValueError("Production source count or scope disagrees with inspected files")
    parsed = set()
    for node in graph["nodes"].values():
        if not isinstance(node, dict):
            raise ValueError("Invalid graph node")
        if node.get("origin", "source") == "source" and node.get("kind") != "proxy":
            anchor = node.get("location")
            if not isinstance(anchor, dict):
                raise ValueError("Graph source node has no source location")
            parsed.add(captured_file(anchor.get("file_path")))
    diagnosed = {
        captured_file(item["location"]["file_path"])
        for item in diagnostics
        if isinstance(item, dict)
        and isinstance(item.get("location"), dict)
        and nonempty(item["location"].get("file_path"))
    }
    if not set(production) <= parsed | diagnosed:
        raise ValueError("Production scope has no parsed source nodes in the retained graph")
    return (
        {
            "graph": str(paths["graph"]),
            "source_policy": str(paths["source-policy"]),
            "graph_diagnostics": str(paths["diagnostics"]),
            "graph_scope": str(paths["graph-scope"]),
            "graph_source_files": count,
            "production_source_files": len(production),
        },
        set(production),
        set(selected),
    )


def configured_specifications(root: Path) -> set[Path]:
    config = tomllib.loads((root / ".duvet/config.toml").read_text())
    sources = [item["source"] for item in config.get("specification", [])]
    if not sources or any("://" in value for value in sources):
        raise ValueError("Configure every specification as a pinned local file")
    return {local_file(root, value, canonical=False) for value in sources}


def snapshot_files(root: Path, run: Path, artifacts: bool = True) -> dict[str, Any]:
    """Capture names and contents, including untracked and ignored build inputs."""

    def traversal_error(error: OSError) -> None:
        raise error

    excluded = {
        root / ".trailmark",
        root / ".duvet/reports",
        root / ".duvet/assurance-citations",
        run,
    }
    paths = set()
    states = {}
    for directory, directories, files in os.walk(root, followlinks=False, onerror=traversal_error):
        parent = Path(directory)
        states[str(parent.relative_to(root))] = access_state(parent)
        directories[:] = [
            name
            for name in directories
            if name not in {".git", "__pycache__", ".pytest_cache"}
            and parent / name not in excluded
        ]
        for name in directories:
            link = parent / name
            if link.is_symlink():
                resolved = link.resolve()
                if not resolved.is_relative_to(root):
                    raise ValueError(f"Directory symlink points outside target: {link}")
                states[str(link.relative_to(root))] = {
                    **access_state(link),
                    "resolved": str(resolved),
                    "symlink": os.readlink(link),
                }
        paths.update(parent / name for name in files)
    if artifacts:
        paths.update(run / name for name in ANALYSIS_ARTIFACTS)
    paths.update(configured_specifications(root))
    if not paths:
        raise ValueError("Source snapshot inspected zero files")
    states.update(
        {
            (str(path.relative_to(root)) if path.is_relative_to(root) else str(path)): file_state(
                path
            )
            for path in sorted(paths)
        }
    )
    return states


def begin_snapshot(root: Path, run: Path) -> dict[str, str]:
    path = run / "source-inputs.json"
    with path.open("x") as output:
        json.dump(snapshot_files(root, run, artifacts=False), output, indent=2)
        output.write("\n")
    return {"source_inputs": str(path)}


def freeze_snapshot(root: Path, run: Path) -> dict[str, str]:
    original = read_json(run / "source-inputs.json")
    if original != snapshot_files(root, run, artifacts=False):
        raise ValueError("Inputs changed during baseline/graph analysis; start a new run")
    scope = read_json(run / "graph-scope.json")["production_files"]
    graph_evidence(run, root, len(scope), original)
    if not {
        local_file(root, item["specification"])
        for item in read_json(run / "inventory.json")["requirements"]
    } <= {path.resolve() for path in configured_specifications(root)}:
        raise ValueError("Configure all inventoried specifications before beginning analysis")
    # Keep the original input states, rather than accepting later edits into the
    # snapshot while attaching native artifacts from the guarded analysis window.
    combined = {
        **original,
        **{
            str((run / name).relative_to(root)): file_state(
                local_file(root, str(run / name), canonical=False)
            )
            for name in ANALYSIS_ARTIFACTS
        },
    }
    path = run / "source-snapshot.json"
    with path.open("x") as output:
        json.dump(combined, output, indent=2)
        output.write("\n")
    digest = file_sha256(path)
    (run / "source-snapshot.sha256").write_text(digest + "\n")
    return {"snapshot_sha256": digest}


def seal_record(root: Path, run: Path, path: Path) -> dict[str, str]:
    record = read_json(path)
    record["snapshot_sha256"] = (run / "source-snapshot.sha256").read_text().strip()
    record["files"] = {
        name: file_state(local_file(root, name, canonical=False))
        for name in sorted(evidence_files(record))
    }
    path.write_text(json.dumps(record, indent=2) + "\n")
    return {
        "id": record["id"],
        "record_path": str(path),
        "record_sha256": file_sha256(path),
    }


def finalize(args: argparse.Namespace, root: Path) -> dict[str, Any]:
    """Run the native artifact gate in the caller's process, outside the workflow VM."""
    run = args.run.resolve(strict=True)
    if not run.is_dir() or not run.is_relative_to(root) or run == root:
        raise ValueError("Run directory must exist inside the target root")
    graph, production, _ = graph_evidence(
        run, root, args.production_source_files, read_json(run / "source-snapshot.json")
    )
    for name in ("report.md", "inventory.json", "duvet-before.json", "ledger.json"):
        path = local_file(root, str(run / name))
        if not path.stat().st_size:
            raise ValueError(f"Empty run artifact: {name}")
    before = inventory(run / "duvet-before.json", args.specification, root)
    ids = {item["id"] for item in before}
    retained = read_json(run / "inventory.json")
    if not isinstance(retained, dict) or retained.get("requirements") != before:
        raise ValueError("Retained inventory differs from the native baseline")
    seals = args.assessments
    if set(seals) != ids - set(args.failed_requirement):
        raise ValueError("Assessment SHA-256 bindings must cover exactly the completed workers")
    workers = {}
    for item in before:
        if item["id"] not in args.failed_requirement:
            path = local_file(root, str(run / "requirements" / f"{item['id']}.json"))
            content = path.read_bytes()
            if hashlib.sha256(content).hexdigest() != seals[item["id"]]:
                raise ValueError(f"Retained worker assessment changed: {item['id']}")
            record = json.loads(content)
            if not isinstance(record, dict) or record.get("id") != item["id"]:
                raise ValueError(f"Missing or mismatched worker record: {item['id']}")
            workers[item["id"]] = record
    if len(args.requirement) != len(ids) or set(args.requirement) != ids:
        raise ValueError("Workflow requirement IDs differ from the retained baseline inventory")
    if not set(args.failed_requirement) <= ids:
        raise ValueError("Failed worker IDs are absent from the baseline inventory")

    def preflight(report: Path, traceability: bool) -> dict[str, Any]:
        result = check_ledger(
            run / "duvet-before.json",
            report,
            run / "ledger.json",
            root,
            args.specification,
            args.requirement,
            args.failed_requirement,
            args.limitation,
            traceability=traceability,
        )
        snapshot = local_file(root, str(run / "source-snapshot.json"))
        snapshot_digest = file_sha256(snapshot)
        if read_json(snapshot) != snapshot_files(root, run):
            raise ValueError(
                "Target snapshot changed since assessment: added, removed, or modified files"
            )
        for record in read_json(run / "ledger.json")["requirements"]:
            if record["id"] in workers:
                worker = workers[record["id"]]
                path = run / "requirements" / f"{record['id']}.json"
                if file_sha256(path) != seals[record["id"]]:
                    raise ValueError(f"Retained worker assessment changed: {record['id']}")
                if worker.get("snapshot_sha256") != snapshot_digest:
                    raise ValueError("Worker source snapshot binding is missing or changed")
                if record != worker:
                    result["errors"].append(
                        f"Ledger changed retained worker assessment {record['id']}; "
                        "preserve the complete record"
                    )
            if record.get("verdict") == "supported" and any(
                local_file(root, anchor.get("file")) not in production
                for anchor in record.get("implementation", [])
                if anchor.get("role") == "production"
            ):
                result["errors"].append(
                    f"Supported requirement {record['id']} has enforcement "
                    "outside the inspected production graph scope"
                )
        diagnostics = read_json(run / "diagnostics.json")
        if diagnostics:
            limitation = (
                f"Trailmark reported {len(diagnostics)} parse diagnostics; "
                f"see {run / 'diagnostics.json'}"
            )
            result["limitations"] = [*result["limitations"], limitation]
            result["status"] = "gaps"
        if result["errors"]:
            result.update(valid=False, status="invalid")
        result.update(graph)
        return result

    result = preflight(run / "duvet-before.json", traceability=False)
    if not result["valid"]:
        return result
    native = Path(tempfile.mkdtemp(prefix="gate-native-", dir=run))
    attempt = native_report(
        root, native, native / "duvet-after.json", native / "duvet-after.html", args.duvet
    )
    if attempt["valid"]:
        try:
            result = preflight(Path(attempt["duvet_report"]), traceability=True)
        except (OSError, RuntimeError, ValueError, TypeError, KeyError, AttributeError) as error:
            result.update(valid=False, status="invalid")
            result["errors"].append(str(error))
    else:
        result.update(valid=False, status="invalid")
        result["errors"].extend(attempt["errors"])
    result.update({key: value for key, value in attempt.items() if key.startswith("duvet_")})
    return result


def native_report(root: Path, native: Path, report: Path, html: Path, duvet: str) -> dict[str, Any]:
    """Isolate every report write and preserve metadata even when launch fails."""
    snapshot = native / "snapshot.txt"
    config_path = native / "config.toml"
    log_path = native / "duvet.log"
    execution_path = native / "execution.json"
    command = [
        duvet,
        "report",
        "--config-path",
        str(config_path),
        "--json",
        str(report),
        "--html",
        str(html),
        "--require-citations",
        "true",
        "--require-tests",
        "true",
        "--ci",
        "false",
    ]
    execution = {"command": command, "exit_code": None}
    result = {
        "valid": True,
        "status": "reported",
        "errors": [],
        "duvet_report": str(report),
        "duvet_html": str(html),
        "duvet_log": str(log_path),
        "duvet_snapshot": str(snapshot),
        "duvet_execution": str(execution_path),
    }
    try:
        config = tomllib.loads((root / ".duvet/config.toml").read_text())
        for name, path in (("json", report), ("html", html), ("snapshot", snapshot)):
            config.setdefault("report", {}).setdefault(name, {}).update(
                enabled=True, path=str(path)
            )
        config_path.write_text(tomli_w.dumps(config))
        with log_path.open("w") as log:
            completed = subprocess.run(
                command, cwd=root, stdout=log, stderr=subprocess.STDOUT, check=False
            )
        execution["exit_code"] = completed.returncode
        if completed.returncode:
            raise ValueError(f"Native Duvet exited {completed.returncode}; see {log_path}")
        for artifact in (report, html, snapshot):
            if not local_file(root, str(artifact)).stat().st_size:
                raise ValueError(f"Native Duvet artifact is empty: {artifact}")
    except (OSError, RuntimeError, ValueError, TypeError, KeyError, AttributeError) as error:
        execution["error"] = str(error)
        result.update(valid=False, status="invalid", errors=[str(error)])
        with log_path.open("a") as log:
            log.write(f"{error}\n")
    execution_path.write_text(json.dumps(execution, indent=2) + "\n")
    result["duvet_exit_code"] = execution["exit_code"]
    return result


def load_request(path: Path) -> argparse.Namespace:
    request = read_json(path)
    fields = {
        "schema_version",
        "root",
        "run",
        "specifications",
        "requirements",
        "failed_requirements",
        "assessments",
        "limitations",
        "production_source_files",
    }
    if not isinstance(request, dict) or set(request) != fields or request["schema_version"] != 1:
        raise ValueError("Invalid validation request schema")
    for name in ("specifications", "requirements", "failed_requirements", "limitations"):
        if not isinstance(request[name], list) or not all(nonempty(item) for item in request[name]):
            raise ValueError(f"Invalid validation request {name}")
    if not request["specifications"] or not request["requirements"]:
        raise ValueError("Validation request needs specifications and requirements")
    seals = request["assessments"]
    if not isinstance(seals, dict) or any(
        not isinstance(value, str)
        or len(value) != 64
        or any(character not in "0123456789abcdef" for character in value)
        for value in seals.values()
    ):
        raise ValueError("Invalid assessment SHA-256 bindings")
    return argparse.Namespace(
        root=Path(request["root"]),
        run=Path(request["run"]),
        specification=request["specifications"],
        requirement=request["requirements"],
        failed_requirement=request["failed_requirements"],
        limitation=request["limitations"],
        assessments=seals,
        production_source_files=request["production_source_files"],
    )


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)
    extract = subparsers.add_parser("inventory")
    extract.add_argument("--report", type=Path, required=True)
    extract.add_argument(
        "--root",
        type=Path,
        default=Path.cwd(),
        help="Target root for specification paths (default: current directory)",
    )
    seal = subparsers.add_parser("seal", help="Bind a worker record to its evidence file contents")
    seal.add_argument("--root", type=Path, required=True)
    seal.add_argument("--run", type=Path, required=True)
    seal.add_argument("--record", type=Path, required=True)
    freeze = subparsers.add_parser("freeze", help="Retain one source snapshot before assessment")
    freeze.add_argument("--root", type=Path, required=True)
    freeze.add_argument("--run", type=Path, required=True)
    begin = subparsers.add_parser(
        "begin", help="Capture inputs before native baseline and graph analysis"
    )
    begin.add_argument("--root", type=Path, required=True)
    begin.add_argument("--run", type=Path, required=True)
    baseline = subparsers.add_parser(
        "baseline", help="Generate baseline without changing project reports"
    )
    baseline.add_argument("--root", type=Path, required=True)
    baseline.add_argument("--run", type=Path, required=True)
    baseline.add_argument("--duvet", default="duvet")
    baseline.add_argument("--output", type=Path, required=True)
    finish = subparsers.add_parser("finalize")
    finish.add_argument("--request", type=Path, required=True)
    finish.add_argument("--output", type=Path, required=True)
    finish.add_argument("--duvet", default="duvet", help="Duvet executable (no shell arguments)")
    extract.add_argument(
        "--specification",
        action="append",
        required=True,
        help="Pinned local specification path; repeat for every document",
    )
    extract.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    try:
        request = load_request(args.request) if args.command == "finalize" else args
        root = request.root.resolve(strict=True)
        if not root.is_dir():
            raise ValueError("Target root must be a directory")
        if args.command in {"seal", "freeze", "baseline", "begin"}:
            run = args.run.resolve(strict=True)
            if not run.is_dir() or not run.is_relative_to(root) or run == root:
                raise ValueError("Run directory must exist inside the target root")
        if args.command == "begin":
            result = begin_snapshot(root, run)
            code = 0
        elif args.command == "freeze":
            result = freeze_snapshot(root, run)
            code = 0
        elif args.command == "baseline":
            native = Path(tempfile.mkdtemp(prefix="baseline-native-", dir=run))
            result = native_report(
                root, native, native / "duvet-before.json", native / "duvet-before.html", args.duvet
            )
            for name in ("duvet-before.json", "duvet-before.html"):
                (run / name).unlink(missing_ok=True)
                if result["valid"]:
                    shutil.copyfile(native / name, run / name)
            code = 0 if result["valid"] else 2
        elif args.command == "seal":
            result = seal_record(
                root, args.run.resolve(strict=True), args.record.resolve(strict=True)
            )
            code = 0
        elif args.command == "inventory":
            result = {"requirements": inventory(args.report, args.specification, root)}
            code = 0
        else:
            request.duvet = args.duvet
            result = finalize(request, root)
            code = 2 if not result["valid"] else 1 if result["status"] == "gaps" else 0
    except (OSError, RuntimeError, ValueError, TypeError, KeyError, AttributeError) as error:
        result = {
            "valid": False,
            "status": "invalid",
            "total": 0,
            "verdicts": {},
            "limitations": [],
            "errors": [str(error)],
        }
        code = 2
    if args.command not in {"seal", "freeze", "begin"}:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps(result))
    return code


if __name__ == "__main__":
    sys.exit(main())
