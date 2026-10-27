"""Read native findings and coverage. No propagation or taint inference lives here."""

from __future__ import annotations

import json
import plistlib
import re
from collections.abc import Callable
from pathlib import Path
from typing import TypedDict, cast
from urllib.parse import unquote, urlparse

COVERAGE_UNKNOWN = "Native output does not establish scanned-file coverage; coverage is unknown."
type JsonObject = dict[str, object]


class Finding(TypedDict):
    rule_id: str
    file: str
    line: int
    end_line: int
    message: str
    source_line: str
    trace: object


class NormalizedResult(TypedDict):
    findings: list[Finding]
    errors: list[str]
    scanned_files: list[str] | None
    limitations: list[str]


def _object(value: object, label: str) -> JsonObject:
    if not isinstance(value, dict) or any(not isinstance(key, str) for key in value):
        raise ValueError(f"{label} must be an object with string keys")
    return cast(JsonObject, value)


def _array(value: object, label: str) -> list[object]:
    if not isinstance(value, list):
        raise ValueError(f"{label} must be an array")
    return cast(list[object], value)


def _records(value: object, label: str) -> list[JsonObject]:
    return [_object(item, label) for item in _array(value, label)]


def _text(value: object, label: str) -> str:
    if not isinstance(value, str):
        raise ValueError(f"{label} must be a string")
    return value


def _integer(value: object, label: str) -> int:
    if not isinstance(value, int) or isinstance(value, bool):
        raise ValueError(f"{label} must be an integer")
    return value


def _empty() -> NormalizedResult:
    return {"findings": [], "errors": [], "scanned_files": None, "limitations": []}


def absolute_file(value: str, cwd: Path) -> str:
    if value.startswith("file:"):
        value = unquote(urlparse(value).path)
    path = Path(value)
    return str((cwd / path).resolve() if not path.is_absolute() else path.resolve())


def _source_line(file: str, line: int) -> str:
    try:
        lines = Path(file).read_text(encoding="utf-8").splitlines()
        return lines[line - 1].strip() if line <= len(lines) else ""
    except (OSError, UnicodeError):
        return ""


def finding(
    rule: str,
    file: str,
    line: int,
    message: str,
    cwd: Path,
    *,
    end: int | None = None,
    trace: object = None,
) -> Finding:
    if not file or line < 1:
        raise ValueError("Native finding has no source file and positive line")
    file = absolute_file(file, cwd)
    return {
        "rule_id": rule,
        "file": file,
        "line": line,
        "end_line": end or line,
        "message": message,
        "source_line": _source_line(file, line),
        "trace": trace,
    }


def _optional_end(value: object) -> int | None:
    return None if value is None else _integer(value, "Native end line")


def _artifact_location(location: JsonObject, artifacts: list[JsonObject]) -> JsonObject:
    if "index" not in location or location.get("uri"):
        return location
    index = _integer(location["index"], "SARIF artifact index")
    if not 0 <= index < len(artifacts):
        raise ValueError("SARIF artifact index is invalid")
    return {**_object(artifacts[index].get("location", {}), "SARIF artifact"), **location}


def _sarif_uri(
    location: JsonObject,
    artifacts: list[JsonObject],
    bases: JsonObject,
    seen: frozenset[str] = frozenset(),
) -> str:
    location = _artifact_location(location, artifacts)
    value = _text(location.get("uri", ""), "SARIF artifact URI")
    base = _text(location.get("uriBaseId", ""), "SARIF URI base")
    if base not in bases:
        # CodeQL can omit originalUriBaseIds for %SRCROOT%. Resolve its relative
        # source URI against the caller's cwd/source root in finding().
        return value
    if base in seen:
        raise ValueError("SARIF URI base is cyclic")
    parent = _sarif_uri(_object(bases[base], "SARIF URI base"), artifacts, bases, seen | {base})
    if not value.startswith("file:") and not Path(value).is_absolute():
        value = parent.rstrip("/") + "/" + value if parent else value
    return value


def _sarif_notifications(run: JsonObject, normalized: NormalizedResult) -> None:
    for invocation in _records(run.get("invocations", []), "SARIF invocations"):
        if invocation.get("executionSuccessful") is False:
            normalized["errors"].append("Native SARIF invocation failed")
        notes = _records(invocation.get("toolExecutionNotifications", []), "SARIF notifications")
        notes += _records(
            invocation.get("toolConfigurationNotifications", []), "SARIF notifications"
        )
        for note in notes:
            message = _object(note.get("message", {}), "SARIF notification message")
            text = _text(message.get("text", str(note)), "SARIF notification text")
            target = "errors" if note.get("level") == "error" else "limitations"
            normalized[target].append(text)


def _sarif_finding(
    result: JsonObject,
    cwd: Path,
    artifacts: list[JsonObject],
    bases: JsonObject,
) -> Finding:
    locations = _records(result.get("locations", []), "SARIF finding locations")
    if not locations:
        raise ValueError("SARIF finding has no source location")
    physical = _object(locations[0].get("physicalLocation", {}), "SARIF physical location")
    region = _object(physical.get("region", {}), "SARIF region")
    message = _object(result.get("message", {}), "SARIF finding message")
    location = _object(physical.get("artifactLocation", {}), "SARIF artifact location")
    return finding(
        _text(result.get("ruleId", "unknown"), "SARIF rule ID"),
        _sarif_uri(location, artifacts, bases),
        _integer(region.get("startLine", 0), "SARIF start line"),
        _text(message.get("text", ""), "SARIF message"),
        cwd,
        end=_optional_end(region.get("endLine")),
        trace=result.get("codeFlows"),
    )


def sarif(
    data: JsonObject,
    cwd: Path,
    *,
    backend: str = "",
) -> tuple[list[Finding], list[str], list[str] | None, list[str]]:
    normalized = _empty()
    runs = _records(data.get("runs", []), "SARIF runs")
    if not runs:
        raise ValueError("SARIF contains zero analyzer runs")
    for run in runs:
        tool = _object(run.get("tool", {}), "SARIF tool")
        if not _object(tool.get("driver", {}), "SARIF driver").get("name"):
            raise ValueError("SARIF run has no native tool identity")
        artifacts = _records(run.get("artifacts", []), "SARIF artifacts")
        bases = _object(run.get("originalUriBaseIds", {}), "SARIF URI bases")
        _sarif_notifications(run, normalized)
        for result in _records(run.get("results", []), "SARIF results"):
            if backend == "codeql" and not _array(result.get("codeFlows", []), "SARIF code flows"):
                continue
            normalized["findings"].append(_sarif_finding(result, cwd, artifacts, bases))
    # artifacts is a referenced-file list, not proof of scanned-file coverage.
    return normalized["findings"], normalized["errors"], None, normalized["limitations"]


def _checker_framework(text: str, cwd: Path) -> NormalizedResult:
    normalized = _empty()
    blocks = re.split(r"(?m)(?=^.+\.java:\d+: (?:error|warning):)", text)
    for block in blocks:
        header = re.match(r"(.+\.java):(\d+): (?:error|warning): \[([^]]+)\]", block)
        taint_mismatch = "@Tainted" in block and "@Untainted" in block
        if header and taint_mismatch:
            normalized["findings"].append(
                finding(header[3], header[1], int(header[2]), block.strip(), cwd)
            )
        elif re.search(r"\berror:", block):
            normalized["errors"].append(block.strip())
    if text.strip() and not any((normalized["findings"], normalized["errors"])):
        raise ValueError("No recognizable Checker Framework diagnostics")
    # Successful javac is silent; the runner also checks the process exit status.
    return normalized


def _clang_plist(text: str, cwd: Path) -> NormalizedResult:
    data = _object(plistlib.loads(text.encode()), "Clang analyzer plist")
    files = _array(data.get("files"), "Clang source files")
    normalized = _empty()
    for item in _records(data.get("diagnostics"), "Clang diagnostics"):
        rule = _text(item.get("check_name", ""), "Clang checker name")
        if "taint" not in rule.lower():
            continue
        loc = _object(item.get("location"), "Clang finding location")
        index = _integer(loc.get("file"), "Clang source file index")
        if not 0 <= index < len(files):
            raise ValueError("Clang source file index is invalid")
        normalized["findings"].append(
            finding(
                rule or _text(item.get("type", "clang"), "Clang issue type"),
                _text(files[index], "Clang source file"),
                _integer(loc.get("line", 0), "Clang source line"),
                _text(item.get("description", ""), "Clang description"),
                cwd,
                trace=item.get("path"),
            )
        )
    return normalized


def _semgrep_finding(item: JsonObject, cwd: Path) -> Finding:
    start = _object(item.get("start"), "Native finding start")
    end = _object(item.get("end", {}), "Native finding end")
    extra = _object(item.get("extra", {}), "Native finding extra")
    return finding(
        _text(item.get("check_id"), "Native finding rule ID"),
        _text(item.get("path"), "Native finding path"),
        _integer(start.get("line", 0), "Native finding line"),
        _text(extra.get("message", ""), "Native finding message"),
        cwd,
        end=_optional_end(end.get("line")),
        trace=extra.get("dataflow_trace"),
    )


def _semgrep(data: object, cwd: Path) -> NormalizedResult:
    root = _object(data, "Native Semgrep/OpenGrep scan result")
    if not all(key in root for key in ("results", "errors", "paths")):
        raise ValueError("Not a native Semgrep/OpenGrep scan result")
    paths = _object(root["paths"], "Native scan paths")
    scanned = _array(paths.get("scanned"), "Native scanned-file inventory")
    normalized = _empty()
    normalized["scanned_files"] = [absolute_file(_text(p, "Scanned file"), cwd) for p in scanned]
    normalized["errors"] = [
        _text(e.get("message", str(e)), "Native scan error")
        for e in _records(root["errors"], "Native scan errors")
    ]
    if root.get("skipped_rules"):
        normalized["errors"].append(
            f"Native analyzer skipped configured rules: {root['skipped_rules']}"
        )
    normalized["findings"] = [
        _semgrep_finding(item, cwd) for item in _records(root["results"], "Native scan findings")
    ]
    return normalized


def _psalm_finding(item: JsonObject, cwd: Path) -> Finding:
    return finding(
        _text(item["type"], "Psalm issue type"),
        _text(item.get("file_path", item.get("file_name", "")), "Psalm source file"),
        _integer(item.get("line_from", 0), "Psalm source line"),
        _text(item.get("message", ""), "Psalm message"),
        cwd,
        end=_optional_end(item.get("line_to")),
        trace=item.get("taint_trace", item.get("other_references")),
    )


def _psalm(data: object, cwd: Path) -> NormalizedResult:
    normalized = _empty()
    for item in _records(data, "Psalm JSON issue array"):
        kind = _text(item.get("type"), "Psalm issue type")
        if kind.startswith("Tainted"):
            normalized["findings"].append(_psalm_finding(item, cwd))
        elif kind in {"ParseError", "InvalidDocblock", "ConfigIssue", "PluginIssue"}:
            normalized["errors"].append(f"{kind}: {item.get('message', '')}")
        else:
            normalized["limitations"].append(f"Psalm {kind}: {item.get('message', '')}")
    return normalized


def _infer(data: object, cwd: Path) -> NormalizedResult:
    normalized = _empty()
    for item in _records(data, "Infer report.json issue array"):
        rule = _text(item.get("bug_type"), "Infer bug type")
        if "TAINT" in rule:
            normalized["findings"].append(
                finding(
                    rule,
                    _text(item.get("file", ""), "Infer source file"),
                    _integer(item.get("line", 0), "Infer source line"),
                    _text(item.get("qualifier", ""), "Infer qualifier"),
                    cwd,
                    trace=item.get("bug_trace"),
                )
            )
    return normalized


def _pysa_stdout_finding(issue: JsonObject, cwd: Path) -> Finding:
    # pyre analyze's stdout issue array uses path/description, unlike saved JSONL.
    if not all(key in issue for key in ("code", "path", "line", "description")):
        raise ValueError("Unknown Pysa stdout issue shape")
    return finding(
        str(_integer(issue["code"], "Pysa issue code")),
        _text(issue["path"], "Pysa source path"),
        _integer(issue["line"], "Pysa source line"),
        _text(issue["description"], "Pysa description"),
        cwd,
    )


def _pysa_saved_finding(record: JsonObject, cwd: Path) -> Finding | None:
    if "file_version" in record:
        if _integer(record["file_version"], "Pysa output file version") < 1:
            raise ValueError("Pysa output file version must be positive")
        return None
    kind = _text(record.get("kind"), "Pysa taint-output record kind")
    if kind not in {"model", "issue"}:
        raise ValueError("Unknown Pysa taint-output record")
    issue = _object(record.get("data"), "Pysa taint-output data")
    if kind == "model":
        return None
    return finding(
        str(_integer(issue.get("code"), "Pysa issue code")),
        _text(issue.get("filename", ""), "Pysa source filename"),
        _integer(issue.get("line", 0), "Pysa source line"),
        _text(issue.get("message", ""), "Pysa message"),
        cwd,
        trace=issue.get("traces"),
    )


def _pysa_error_output(root: JsonObject) -> NormalizedResult:
    errors = _records(root["errors"], "Pysa errors")
    if not errors:
        raise ValueError("Pysa error output contains zero errors")
    normalized = _empty()
    normalized["errors"] = [str(item.get("description", item)) for item in errors]
    return normalized


def _pysa(data: object, cwd: Path) -> NormalizedResult:
    normalized = _empty()
    if isinstance(data, dict):
        root = _object(data, "Pysa output")
        if "errors" in root:
            return _pysa_error_output(root)
        if {"kind", "file_version"}.isdisjoint(root):
            raise ValueError("Pysa stdout output must be an issue array")
        records = [root]  # Saved JSONL can contain only its header or one record.
    else:
        records = _records(data, "Pysa stdout issue array or taint-output JSONL records")
    for record in records:
        if "kind" in record or "file_version" in record:
            item = _pysa_saved_finding(record, cwd)
        else:
            item = _pysa_stdout_finding(record, cwd)
        if item is not None:
            normalized["findings"].append(item)
    return normalized


def _joern(data: object, cwd: Path) -> NormalizedResult:
    root = _object(data, "Joern output")
    if root.get("tool") != "joern":
        raise ValueError("Joern script must emit {tool:joern,findings,scanned_files,errors}")
    normalized = _empty()
    normalized["scanned_files"] = [
        absolute_file(_text(p, "Joern scanned file"), cwd)
        for p in _array(root.get("scanned_files"), "Joern scanned files")
    ]
    normalized["errors"] = [
        _text(e, "Joern error") for e in _array(root.get("errors"), "Joern errors")
    ]
    for item in _records(root.get("findings"), "Joern findings"):
        normalized["findings"].append(
            finding(
                _text(item.get("rule_id", "joern"), "Joern rule ID"),
                _text(item.get("file", ""), "Joern source file"),
                _integer(item.get("line", 0), "Joern source line"),
                _text(item.get("message", ""), "Joern message"),
                cwd,
                trace=item.get("trace"),
            )
        )
    return normalized


def _json_output(text: str, backend: str) -> object:
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        if backend != "pysa":
            raise ValueError("Native output is not JSON/SARIF") from None
    try:
        return [json.loads(line) for line in text.splitlines() if line.strip()]
    except json.JSONDecodeError:
        raise ValueError(
            "Pysa output is not a JSON issue array or valid taint-output JSONL"
        ) from None


def _normalize_json(data: object, backend: str, cwd: Path) -> NormalizedResult:
    if isinstance(data, dict) and "runs" in data:
        findings, errors, scanned, limitations = sarif(_object(data, "SARIF"), cwd, backend=backend)
        if backend in {"clang", "infer", "psalm"}:
            findings = [item for item in findings if "taint" in item["rule_id"].lower()]
        return {
            "findings": findings,
            "errors": errors,
            "scanned_files": scanned,
            "limitations": limitations,
        }
    parsers: dict[str, Callable[[object, Path], NormalizedResult]] = {
        "semgrep": _semgrep,
        "semgrep-pro": _semgrep,
        "opengrep": _semgrep,
        "psalm": _psalm,
        "infer": _infer,
        "pysa": _pysa,
        "joern": _joern,
    }
    if backend not in parsers:
        raise ValueError(f"{backend} must emit native SARIF (or a supported backend format)")
    return parsers[backend](data, cwd)


def normalize(text: str, backend: str, cwd: Path) -> NormalizedResult:
    """Normalize the documented native format; reject unknown/empty output shapes."""
    if not text.strip() and backend != "checker-framework":
        raise ValueError("Native output is empty")
    if backend == "checker-framework":
        normalized = _checker_framework(text, cwd)
    elif backend == "clang" and text.lstrip().startswith("<?xml"):
        normalized = _clang_plist(text, cwd)
    else:
        normalized = _normalize_json(_json_output(text, backend), backend, cwd)
    if normalized["scanned_files"] == []:
        normalized["errors"].append("Analyzer scanned zero source files")
    if normalized["scanned_files"] is None:
        normalized["limitations"].append(COVERAGE_UNKNOWN)
    return normalized
