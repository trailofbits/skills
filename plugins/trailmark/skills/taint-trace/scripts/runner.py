"""Execute native analyzers and retain independently checkable evidence.

Capability assertions describe findings produced by the selected stock executable.
This module does not implement or repair an analyzer's taint propagation.
"""

from __future__ import annotations

import xml.etree.ElementTree as ET
from collections.abc import Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

from activation import command_contract, invocation, reported_engine_errors
from catalog import BACKENDS, SCOPES, allowed_backend, canonical_language
from native import COVERAGE_UNKNOWN, Finding, NormalizedResult, normalize
from runner_artifacts import artifact as artifact
from runner_artifacts import check_artifact as check_artifact
from runner_artifacts import digest, execute, reserve, write_json
from runner_config import SEMGREP, capture_configuration, check_configuration, snapshot_files
from runner_config import argument_binds as argument_binds
from runner_config import psalm_config as psalm_config
from runner_config import psalm_model_errors as psalm_model_errors
from runner_config import taint_rules as taint_rules

# Preserve the public runner interface used by the CLI and artifact validators.
from runner_contracts import check_probe as check_probe
from runner_contracts import check_probe_baseline as check_probe_baseline
from runner_contracts import expected_sites as expected_sites
from runner_probe import probe as probe
from runner_probe import semgrep_command as semgrep_command
from runner_startup import capture_execution, check_execution, psalm_root_arguments, startup_plan

JsonObject = dict[str, Any]
ARTIFACT_ERRORS = (
    OSError,
    ValueError,
    TypeError,
    KeyError,
    IndexError,
    AttributeError,
    yaml.YAMLError,
    ET.ParseError,
)


def version_command(backend: str, argv: list[str]) -> list[str]:
    try:
        prefix, _ = invocation(backend, argv)
        roots = psalm_root_arguments(argv) if backend == "psalm" else []
    except ValueError:
        prefix = argv[:1] or [BACKENDS[backend]["executable"]]
        roots = []
    return prefix + roots + BACKENDS[backend]["version_args"]


def version_binding_errors(backend: str, argv: list[str], version_argv: list[str]) -> list[str]:
    try:
        prefix, _ = invocation(backend, argv)
        version_prefix, args = invocation(backend, version_argv)
        if prefix != version_prefix:
            return ["Version command must identify the same native executable and environment"]
        if not all(arg in args for arg in BACKENDS[backend]["version_args"]):
            return ["Version command must request the selected native tool's version"]
        if backend == "psalm" and psalm_root_arguments(argv) != psalm_root_arguments(version_argv):
            return ["Psalm version command must use the same startup --root as analysis"]
    except ValueError as exc:
        return [str(exc)]
    return []


def taint_findings(normalized: NormalizedResult, ids: list[str]) -> NormalizedResult:
    if ids:
        normalized["findings"] = [
            item
            for item in normalized["findings"]
            if any(item["rule_id"] == rule or item["rule_id"].endswith("." + rule) for rule in ids)
        ]
    return normalized


def permitted_exit(backend: str, returncode: int | None, normalized: NormalizedResult) -> bool:
    if returncode == 0:
        return True
    if backend in SEMGREP and returncode == 1 and normalized["findings"]:
        return True
    if backend == "psalm" and returncode == 2:
        return bool(normalized["findings"] or normalized["limitations"])
    return backend == "checker-framework" and returncode == 1 and bool(normalized["findings"])


def psalm_coverage(normalized: NormalizedResult, stderr: str, cwd: Path) -> NormalizedResult:
    """Retain Psalm's native per-file processing evidence, without inferring coverage."""
    files = set()
    for line in stderr.splitlines():
        if not line.startswith("Analyzing "):
            continue
        path = Path(line.removeprefix("Analyzing "))
        if path.is_absolute() and path.resolve().is_relative_to(cwd) and path.is_file():
            files.add(str(path.resolve()))
    if files:
        normalized["scanned_files"] = sorted(files)
        normalized["limitations"] = [
            item for item in normalized["limitations"] if item != COVERAGE_UNKNOWN
        ]
    return normalized


def psalm_scan_errors(stderr: str, findings: list[Finding], cwd: Path) -> list[str]:
    """Psalm's empty JSON is also emitted for zero files; require native source evidence."""
    files = [item["file"] for item in findings]
    files.extend(
        line.removeprefix("Analyzing ")
        for line in stderr.splitlines()
        if line.startswith("Analyzing ")
    )
    for file in files:
        path = Path(file)
        if path.is_absolute() and path.resolve().is_relative_to(cwd) and path.is_file():
            return []
    return [
        "Psalm did not establish a nonempty target scan. Use --debug to preserve native "
        "per-file analysis evidence; an empty JSON array does not prove a nonempty scan."
    ]


@dataclass
class RunRequest:
    backend: str
    language: str
    phase: str
    scope: str
    output: Path
    argv: list[str]
    cwd: Path
    native_output: Path | None = None
    models: Sequence[Path] = ()
    timeout: int = 300
    version_argv: list[str] | None = None
    execution: JsonObject = field(default_factory=dict)


@dataclass
class RunState:
    errors: list[str] = field(default_factory=list)
    limitations: list[str] = field(default_factory=list)
    models: list[JsonObject] = field(default_factory=list)
    configs: list[JsonObject] = field(default_factory=list)
    ids: list[str] = field(default_factory=list)
    normalized: NormalizedResult = field(
        default_factory=lambda: {
            "findings": [],
            "errors": [],
            "scanned_files": None,
            "limitations": [],
        }
    )


def initialize_run(request: RunRequest, state: RunState) -> str:
    backend = request.backend
    if backend not in BACKENDS or not allowed_backend(backend, request.language):
        state.errors.append(
            f"Unsupported language/backend combination: {request.language}/{backend}"
        )
    if request.scope not in SCOPES or request.phase not in {"baseline", "enriched", "probe"}:
        state.errors.append("Invalid analysis scope or phase")
    if not request.cwd.is_dir():
        state.errors.append(f"Working directory does not exist: {request.cwd}")
    engine, errors = command_contract(backend, request.argv, request.scope)
    state.errors.extend(errors)
    return engine


def capture_inputs(request: RunRequest, state: RunState) -> None:
    try:
        paths = [(request.cwd / path).resolve() for path in request.models]
        state.models = snapshot_files(request.output, paths, "model")
        state.configs, state.ids, errors, limitations = capture_configuration(
            request.backend,
            request.language,
            request.argv,
            request.cwd,
            request.output,
            models=state.models,
        )
        state.errors.extend(errors)
        state.limitations.extend(limitations)
    except ARTIFACT_ERRORS as exc:
        state.errors.append(str(exc))


def capture_version(request: RunRequest, state: RunState) -> JsonObject:
    argv = request.version_argv
    if not argv:
        argv = version_command(request.backend, request.argv) if request.backend in BACKENDS else []
    state.errors.extend(version_binding_errors(request.backend, request.argv, argv))
    rc, stdout, stderr = None, "", ""
    if not state.errors:
        rc, stdout, stderr, errors = execute(argv, request.cwd, min(request.timeout, 30))
        state.errors.extend(errors)
    if rc != 0 or not (stdout + stderr).strip():
        state.errors.append("Native tool version could not be established")
    if request.backend == "checker-framework":
        state.limitations.append(
            "The recorded javac version identifies the compiler, not the Checker JAR."
        )
    return {"argv": argv, "output": stdout + stderr, "returncode": rc}


def output_fingerprint(path: Path | None) -> tuple[int, str] | None:
    if path and path.is_file():
        return path.stat().st_mtime_ns, digest(path)
    return None


def read_native_output(
    path: Path | None, before: tuple[int, str] | None, raw: str, errors: list[str]
) -> str:
    if path is None:
        return raw
    try:
        if before == output_fingerprint(path):
            errors.append("Native output was not refreshed by this invocation")
        return path.read_text(encoding="utf-8")
    except (OSError, UnicodeError) as exc:
        errors.append(f"Native output is missing or unreadable: {exc}")
        return ""


def capture_streams(output: Path, stdout: str, stderr: str, raw: str) -> JsonObject:
    paths = {}
    for name, value in (("stdout", stdout), ("stderr", stderr), ("native_output", raw)):
        path = output.with_name(f"{output.name}.{name}")
        path.write_text(value, encoding="utf-8")
        paths[name] = artifact(path)
    return paths


def execute_target(request: RunRequest, state: RunState) -> JsonObject:
    path = (request.cwd / request.native_output).resolve() if request.native_output else None
    before = output_fingerprint(path)
    returncode, stdout, stderr = None, "", ""
    if not state.errors:
        returncode, stdout, stderr, errors = execute(request.argv, request.cwd, request.timeout)
        state.errors.extend(errors)
    raw = stdout + ("\n" + stderr if request.backend == "checker-framework" else "")
    raw = read_native_output(path, before, raw, state.errors)
    paths = capture_streams(request.output, stdout, stderr, raw)
    if returncode is not None:
        normalize_execution(request, state, returncode, raw, stderr)
    state.errors.extend(state.normalized["errors"])
    state.limitations.extend(state.normalized["limitations"])
    if state.normalized["scanned_files"] is None and not state.normalized["limitations"]:
        state.limitations.append(COVERAGE_UNKNOWN)
    return {"returncode": returncode, **paths}


def normalized_output(
    backend: str, raw: str, stderr: str, cwd: Path, ids: list[str]
) -> NormalizedResult:
    normalized = taint_findings(normalize(raw, backend, cwd), ids)
    return psalm_coverage(normalized, stderr, cwd) if backend == "psalm" else normalized


def normalize_execution(
    request: RunRequest, state: RunState, returncode: int, raw: str, stderr: str
) -> None:
    state.errors.extend(reported_engine_errors(raw, request.backend))
    try:
        state.normalized = normalized_output(request.backend, raw, stderr, request.cwd, state.ids)
        if request.backend == "psalm":
            state.errors.extend(
                psalm_scan_errors(stderr, state.normalized["findings"], request.cwd)
            )
    except ARTIFACT_ERRORS as exc:
        state.errors.append(f"Invalid native output: {exc}")
    if not permitted_exit(request.backend, returncode, state.normalized):
        state.errors.append(f"Native command failed with exit status {returncode}")


def run_record(
    request: RunRequest, state: RunState, engine: str, version: JsonObject, streams: JsonObject
) -> JsonObject:
    return {
        "schema_version": 1,
        "backend": request.backend,
        "engine": engine,
        "language": canonical_language(request.language),
        "phase": request.phase,
        "scope": request.scope,
        "status": "failed" if state.errors else "limited" if state.limitations else "analyzed",
        "argv": request.argv,
        "cwd": str(request.cwd),
        "version": version,
        "execution": request.execution,
        **streams,
        "model_files": state.models,
        "config_files": state.configs,
        "taint_rule_ids": state.ids,
        "scanned_files": state.normalized["scanned_files"],
        "findings": state.normalized["findings"],
        "native_errors": state.normalized["errors"],
        "errors": state.errors,
        "limitations": state.limitations,
    }


def run_native(
    *,
    backend: str,
    language: str,
    phase: str,
    scope: str,
    output: Path,
    argv: list[str],
    cwd: Path,
    native_output: Path | None = None,
    models: Sequence[Path] = (),
    timeout: int = 300,
    version_argv: list[str] | None = None,
) -> JsonObject:
    request = RunRequest(
        backend,
        language,
        phase,
        scope,
        reserve(output),
        list(argv),
        cwd.resolve(),
        native_output,
        models,
        timeout,
        list(version_argv) if version_argv is not None else None,
    )
    return execute_request(request)


def execute_request(request: RunRequest) -> JsonObject:
    requested = {
        "argv": list(request.argv),
        "version_argv": request.version_argv,
        "cwd": str(request.cwd),
    }
    with startup_plan(
        request.backend, request.argv, request.cwd, version_argv=request.version_argv
    ) as startup:
        request.argv, request.version_argv = startup.argv, startup.version_argv
        state = RunState(errors=list(startup.errors))
        engine = initialize_run(request, state)
        capture_inputs(request, state)
        if request.version_argv is None and request.backend in BACKENDS:
            request.version_argv = version_command(request.backend, request.argv)
        request.execution = capture_execution(
            request.output,
            startup,
            requested=requested,
            effective={
                "argv": request.argv,
                "version_argv": request.version_argv,
                "cwd": str(request.cwd),
                "config_files": state.configs,
            },
        )
        version = capture_version(request, state)
        streams = execute_target(request, state)
        record = run_record(request, state, engine, version, streams)
        write_json(request.output, record)
        return record


def check_run_header(record: JsonObject, path: Path) -> list[str]:
    errors = []
    if record.get("schema_version") != 1 or record.get("status") not in {"analyzed", "limited"}:
        errors.append(f"Run did not complete successful native analysis: {path}")
    if record.get("backend") not in BACKENDS or not allowed_backend(
        record.get("backend", ""), record.get("language", "")
    ):
        errors.append("Run has an unsupported language/backend combination")
    if record.get("scope") not in SCOPES or record.get("phase") not in {
        "baseline",
        "enriched",
        "probe",
    }:
        errors.append("Run has an invalid scope or phase")
    if record.get("errors"):
        errors.append("Run contains native or execution errors")
    return errors


def check_run_command(record: JsonObject) -> list[str]:
    errors = []
    if (
        not isinstance(record.get("argv"), list)
        or not record.get("argv")
        or not isinstance(record.get("cwd"), str)
    ):
        errors.append("Run lacks its actual command and working directory")
    version = record.get("version")
    if (
        not isinstance(version, dict)
        or version.get("returncode") != 0
        or not version.get("output")
        or not version.get("argv")
    ):
        errors.append("Run has no successful native version capture")
    return errors


def check_run_artifacts(record: JsonObject) -> list[str]:
    errors = []
    for key in ("stdout", "stderr", "native_output"):
        errors.extend(check_artifact(record.get(key, {}), key))
    for key in ("model_files", "config_files"):
        items = record.get(key, [])
        if not isinstance(items, list):
            errors.append(f"Run {key} must be an artifact array")
        else:
            for item in items:
                errors.extend(check_artifact(item, "model/configuration"))
    return errors


def check_activation(record: JsonObject) -> list[str]:
    backend, argv = record["backend"], record["argv"]
    engine, errors = command_contract(backend, argv, record["scope"])
    if record.get("engine") != engine:
        errors.append("Recorded engine disagrees with the native command activation")
    errors.extend(version_binding_errors(backend, argv, record["version"]["argv"]))
    return errors


def without_snippets(findings: list[Finding]) -> list[JsonObject]:
    return [
        {key: value for key, value in item.items() if key != "source_line"} for item in findings
    ]


def check_normalized_record(record: JsonObject, normalized: NormalizedResult) -> list[str]:
    errors = []
    if without_snippets(normalized["findings"]) != without_snippets(record["findings"]):
        errors.append("Recorded findings disagree with native analyzer output")
    if normalized["scanned_files"] != record.get("scanned_files"):
        errors.append("Recorded coverage disagrees with native analyzer output")
    if normalized["errors"] or normalized["errors"] != record.get("native_errors", []):
        errors.append("Native analyzer reported errors")
    if not permitted_exit(record["backend"], record.get("returncode"), normalized):
        errors.append("Native command exit status does not establish successful analysis")
    if normalized["limitations"] and record.get("status") != "limited":
        errors.append("Unknown native coverage or limitations cannot be reported as analyzed")
    return errors


def check_run_native_output(record: JsonObject, cwd: Path) -> list[str]:
    backend = record["backend"]
    raw = Path(record["native_output"]["path"]).read_text(encoding="utf-8")
    stderr = Path(record["stderr"]["path"]).read_text(encoding="utf-8")
    errors = reported_engine_errors(raw, backend)
    normalized = normalized_output(backend, raw, stderr, cwd, record.get("taint_rule_ids", []))
    if backend == "psalm":
        errors.extend(psalm_scan_errors(stderr, normalized["findings"], cwd))
    errors.extend(check_normalized_record(record, normalized))
    return errors


def check_run(record: JsonObject, record_path: Path) -> list[str]:
    """Re-read native artifacts while retaining historical source snippets."""
    if not isinstance(record, dict):
        return ["Native run record must be a JSON object"]
    errors = check_run_header(record, record_path)
    errors.extend(check_run_command(record))
    errors.extend(check_run_artifacts(record))
    if errors:
        return errors
    try:
        cwd = Path(record["cwd"])
        errors.extend(check_activation(record))
        errors.extend(check_configuration(record, cwd))
        errors.extend(check_run_native_output(record, cwd))
        errors.extend(check_execution(record))
    except ARTIFACT_ERRORS as exc:
        errors.append(f"Run artifact cannot be validated: {exc}")
    return errors
