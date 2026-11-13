# /// script
# requires-python = ">=3.13"
# dependencies = []
# ///
"""Validate versioned records and hash receipt files."""

import argparse
import hashlib
import json
import re
import sys
from pathlib import Path, PurePosixPath

SCHEMA_DIR = Path(__file__).resolve().parents[1] / "schemas"
KEYWORDS = {
    "type",
    "required",
    "properties",
    "additionalProperties",
    "enum",
    "const",
    "items",
    "minLength",
    "maxLength",
    "pattern",
    "minimum",
    "maximum",
    "maxItems",
}
TYPE_MAP = {
    "object": dict,
    "array": list,
    "string": str,
    "integer": int,
    "boolean": bool,
    "null": type(None),
}


class RecordError(ValueError):
    """A record, schema or receipt manifest is invalid."""


def validate(record: object, schema: dict, where: str = "$") -> None:
    """Validate the supported JSON Schema subset, rejecting unknown schema keywords."""
    unsupported = set(schema) - KEYWORDS
    if unsupported:
        raise RecordError(f"{where}: unsupported schema keyword {sorted(unsupported)[0]}")
    _validate_scalar(record, schema, where)
    if isinstance(record, dict):
        _validate_object(record, schema, where)
    elif isinstance(record, list):
        _validate_array(record, schema, where)


def _validate_scalar(record: object, schema: dict, where: str) -> None:
    _validate_type(record, schema, where)
    if "const" in schema and (
        type(record) is not type(schema["const"]) or record != schema["const"]
    ):
        raise RecordError(f"{where}: expected {schema['const']!r}")
    if "enum" in schema and record not in schema["enum"]:
        raise RecordError(f"{where}: invalid enum value {record!r}")
    if isinstance(record, str):
        _validate_string(record, schema, where)
    if isinstance(record, int) and not isinstance(record, bool):
        _validate_integer(record, schema, where)


def _validate_type(record: object, schema: dict, where: str) -> None:
    kinds = schema.get("type")
    if kinds is not None:
        kinds = [kinds] if isinstance(kinds, str) else kinds
        if any(kind not in TYPE_MAP for kind in kinds):
            raise RecordError(f"{where}: unsupported type {kinds}")
        if not any(
            isinstance(record, TYPE_MAP[kind])
            and (kind != "integer" or not isinstance(record, bool))
            for kind in kinds
        ):
            raise RecordError(f"{where}: expected {kinds}")


def _validate_string(record: str, schema: dict, where: str) -> None:
    if len(record) < schema.get("minLength", 0):
        raise RecordError(f"{where}: string too short")
    if len(record) > schema.get("maxLength", float("inf")):
        raise RecordError(f"{where}: string too long")
    if "pattern" in schema and re.search(schema["pattern"], record) is None:
        raise RecordError(f"{where}: pattern mismatch")


def _validate_integer(record: int, schema: dict, where: str) -> None:
    if record < schema.get("minimum", -float("inf")):
        raise RecordError(f"{where}: below minimum")
    if record > schema.get("maximum", float("inf")):
        raise RecordError(f"{where}: above maximum")


def _validate_object(record: dict, schema: dict, where: str) -> None:
    for key in schema.get("required", []):
        if key not in record:
            raise RecordError(f"{where}.{key}: required field missing")
    properties = schema.get("properties", {})
    for key, value in record.items():
        child = f"{where}.{key}"
        if key in properties:
            validate(value, properties[key], child)
        elif schema.get("additionalProperties") is False:
            raise RecordError(f"{child}: unknown field")


def _validate_array(record: list, schema: dict, where: str) -> None:
    if len(record) > schema.get("maxItems", float("inf")):
        raise RecordError(f"{where}: too many items")
    for index, value in enumerate(record):
        if "items" in schema:
            validate(value, schema["items"], f"{where}[{index}]")


def load(path: Path, kind: str) -> dict:
    """Load and validate a record against its bundled schema."""
    if not re.fullmatch(r"[a-z-]+", kind):
        raise RecordError(f"invalid record kind: {kind}")
    try:
        schema = json.loads((SCHEMA_DIR / f"{kind}.schema.json").read_text())
        record = json.loads(path.read_text())
    except (OSError, json.JSONDecodeError) as exc:
        raise RecordError(f"cannot load {path}: {exc}") from exc
    validate(record, schema)
    if not isinstance(record, dict):
        raise RecordError(f"{path}: expected object")
    if kind == "reproduce":
        _reproduction_type(record)
    elif kind == "prove":
        _proof_type(record)
    return record


def _reproduction_type(record: dict) -> None:
    if record.get("failure_type", "runtime") == "runtime":
        if record["target_artifact"] is None:
            raise RecordError("$.target_artifact: runtime proof requires an artifact")
        return
    if not record.get("expected_diagnostic", "").strip():
        raise RecordError("$.expected_diagnostic: compile proof requires a target diagnostic")
    if record["target_artifact"] is not None:
        raise RecordError("$.target_artifact: compile proof requires null")
    if record["poc_argv"]:
        raise RecordError("$.poc_argv: compile proof requires an empty array")
    if not record["build_argv"]:
        raise RecordError("$.build_argv: compile proof requires a compiler command")


def _proof_type(record: dict) -> None:
    if record.get("failure_type", "runtime") == "runtime":
        if record["build_identity"] == "not_applicable":
            raise RecordError("$.build_identity: runtime proof requires pass or fail")
        hashes = record["hashes"]
        if record["build_identity"] == "pass" and (
            any(value is None for value in hashes.values())
            or hashes["baseline"] == hashes["patched"]
        ):
            raise RecordError("$.hashes: passing runtime identity needs distinct complete hashes")
        return
    if record["build_identity"] != "not_applicable":
        raise RecordError("$.build_identity: compile proof requires not_applicable")
    if any(value is not None for value in record["hashes"].values()):
        raise RecordError("$.hashes: compile proof has no runtime artifact hashes")


def _file_hashes(directory: Path) -> dict[str, str]:
    if not directory.is_dir() or directory.is_symlink():
        raise RecordError(f"{directory}: step directory missing or linked")
    files = {}
    for path in sorted(directory.rglob("*")):
        if path.is_symlink():
            raise RecordError(f"{path}: symlink step file rejected")
        if path.is_file() and path != directory / "manifest.json":
            files[path.relative_to(directory).as_posix()] = hashlib.sha256(
                path.read_bytes()
            ).hexdigest()
    return files


def write_manifest(directory: Path) -> Path:
    """Write SHA-256 digests for every regular step file except the manifest."""
    path = directory / "manifest.json"
    path.write_text(
        json.dumps(
            {"schema_version": 1, "files": _file_hashes(directory)}, indent=2, sort_keys=True
        )
        + "\n"
    )
    return path


def verify_manifest(directory: Path) -> None:
    """Reject changed, missing, or extra step files."""
    path = directory / "manifest.json"
    try:
        manifest = json.loads(path.read_text())
    except (OSError, json.JSONDecodeError) as exc:
        raise RecordError(f"cannot load {path}: {exc}") from exc
    if set(manifest) != {"schema_version", "files"} or manifest["schema_version"] != 1:
        raise RecordError(f"{path}: invalid manifest")
    actual = _file_hashes(directory)
    expected = manifest["files"]
    if not isinstance(expected, dict):
        raise RecordError(f"{path}: files must be an object")
    for name in sorted(set(actual) | set(expected)):
        if actual.get(name) != expected.get(name):
            raise RecordError(f"{directory / name}: step file missing, extra or changed")


def retained_file(run_dir: Path, name: str, step: str) -> Path | None:
    """Resolve a run-relative artifact only when this step's manifest retains it."""
    relative = PurePosixPath(name)
    if relative.is_absolute() or ".." in relative.parts:
        return None
    try:
        local = relative.relative_to(step).as_posix()
        directory = run_dir / step
        manifest = json.loads((directory / "manifest.json").read_text())["files"]
        path = run_dir / relative
        if local not in manifest or not path.is_file() or path.is_symlink():
            return None
        if not path.resolve().is_relative_to(directory.resolve()):
            return None
        return path if hashlib.sha256(path.read_bytes()).hexdigest() == manifest[local] else None
    except (OSError, ValueError, KeyError):
        return None


def step_directories(run_dir: Path) -> list[Path]:
    """Return the existing top-level step directories with manifests."""
    steps = [run_dir / name for name in ("reproduce", "validate", "regression")]
    for kind in ("patch", "prove"):
        steps.extend(sorted((run_dir / kind).glob("attempt-*")))
    return [step for step in steps if step.exists()]


def attempt_gaps(run_dir: Path, count: int) -> list[str]:
    """Keep contradictory run counts reportable while preventing readiness."""
    gaps = []
    for step in step_directories(run_dir):
        if step.parent.name not in {"patch", "prove"}:
            continue
        match = re.fullmatch(r"attempt-([1-3])", step.name)
        if match is None:
            gaps.append(f"{step.relative_to(run_dir)}: malformed attempt directory")
        elif int(match[1]) > count:
            gaps.append(
                f"{step.relative_to(run_dir)}: retained attempt exceeds run.attempts ({count})"
            )
    return gaps


def repair_scope_gaps(plan: dict) -> list[str]:
    """Assess the declared case plan for both repair entry and native proof."""
    cases = plan["cases"]
    representatives = [case for case in cases if case["role"] == "representative"]
    controls = [case for case in cases if case["role"] == "control"]
    gaps = []
    if not representatives or (
        plan["mode"] == "bounded_class" and (len(representatives) < 2 or not controls)
    ):
        gaps.append("repair scope lacks representative cases or a valid control")
    ids = [case["check_id"] for case in cases]
    if len(set(ids)) != len(ids):
        gaps.append("repair scope repeats a check ID")
    inputs = [json.dumps(case["input"], sort_keys=True) for case in cases]
    if plan["mode"] == "bounded_class" and len(set(inputs)) != len(inputs):
        gaps.append("bounded repair scope repeats an input")
    return gaps


def _attempt_records(run_dir: Path) -> list[tuple[str, str]]:
    records = []
    for kind in ("patch", "prove"):
        for attempt in sorted((run_dir / kind).glob("attempt-*")):
            if re.fullmatch(r"attempt-[1-3]", attempt.name) is None:
                raise RecordError(f"{attempt}: expected attempt-1, attempt-2 or attempt-3")
            records.append((f"{kind}/{attempt.name}/{kind}.json", kind))
    return records


def _check_repair_entry(run_dir: Path) -> None:
    finding = load(run_dir / "finding.json", "finding")
    if "repair_scope" not in finding:
        raise RecordError("$.repair_scope: required before repair; record the repair brief first")
    run = load(run_dir / "run.json", "run")
    gaps = repair_scope_gaps(finding["repair_scope"]) + attempt_gaps(run_dir, run["attempts"])
    if gaps:
        raise RecordError("; ".join(gaps))


def check(run_dir: Path, *, before_repair: bool = False) -> None:
    """Validate records and manifests, optionally requiring a usable repair brief."""
    records = [
        ("run.json", "run"),
        ("finding.json", "finding"),
        ("report-input.json", "report-input"),
        ("reproduce/reproduce.json", "reproduce"),
        ("validate/validate.json", "validate"),
        ("regression/regression.json", "regression"),
        *_attempt_records(run_dir),
    ]
    for relative, kind in records:
        path = run_dir / relative
        if path.is_file():
            record = load(path, kind)
            if kind in {"patch", "prove"} and path.parent.name != f"attempt-{record['attempt']}":
                raise RecordError(f"{path}: attempt {record['attempt']} differs from its directory")
    for step in step_directories(run_dir):
        verify_manifest(step)
    if before_repair:
        _check_repair_entry(run_dir)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=["check", "manifest"])
    parser.add_argument("path", type=Path)
    parser.add_argument(
        "--before-repair", action="store_true", help="require the repair brief before patching"
    )
    args = parser.parse_args()
    if args.before_repair and args.command != "check":
        parser.error("--before-repair requires check")
    try:
        if args.command == "check":
            check(args.path, before_repair=args.before_repair)
        else:
            write_manifest(args.path)
    except RecordError as exc:
        print(exc, file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
