"""Shared paths and immutable artifact operations for taint trace evidence."""

from __future__ import annotations

import hashlib
import json
import shutil
from pathlib import Path
from typing import Any

# JSON artifacts are validated at their consumers; unknown fields remain preserved.
type JsonObject = dict[str, Any]


def read_json(path: Path) -> JsonObject:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError(f"Expected a JSON object: {path}")
    return value


def write_json(path: Path, value: JsonObject) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")


def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def relative(value: str, target: Path) -> str:
    path = (target / value).resolve()
    return path.relative_to(target).as_posix() if path.is_relative_to(target) else str(path)


def local_file(value: str, root: Path) -> Path:
    if not isinstance(value, str) or not value:
        raise ValueError("File path must be a nonempty string")
    path = (root / value).resolve()
    if not path.is_relative_to(root) or not path.is_file():
        raise ValueError(f"File must exist within target: {value}")
    return path


def record_path(value: object, base: Path) -> Path:
    if not isinstance(value, str) or not value:
        raise ValueError("Artifact record path must be a nonempty string")
    return (base / value).resolve()


def snapshot_sources(context: JsonObject, output: Path) -> None:
    """Retain original bytes outside JSON, including existing native configuration."""
    target = Path(context["target"])
    directory = output.resolve().with_name(output.name + ".sources")
    directory.mkdir(parents=True, exist_ok=False)
    records = []
    for file in sorted(set(context["source_hashes"]) | set(context["configuration_files"])):
        source = local_file(file, target)
        destination = directory / source.relative_to(target)
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(source, destination)
        sha = digest(destination)
        if file in context["source_hashes"] and sha != context["source_hashes"][file]:
            raise ValueError(f"Source changed during graph extraction: {file}; extract again")
        records.append({"file": file, "path": str(destination), "sha256": sha})
    context["source_snapshots"] = records
