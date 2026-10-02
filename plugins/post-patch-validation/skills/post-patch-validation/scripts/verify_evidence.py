#!/usr/bin/env python3
"""Verify the deterministic, content-addressed parts of post-patch evidence."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
from typing import Any


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def load_json(path: Path) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ValueError(f"cannot read {path}: {exc}") from exc


def safe_relative(root: Path, value: str) -> Path:
    path = Path(value)
    if path.is_absolute() or ".." in path.parts:
        raise ValueError(f"unsafe evidence path: {value!r}")
    return root / path


def verify_manifest(root: Path, errors: list[str]) -> int:
    manifest = load_json(root / "artifact-manifest.json")
    entries = manifest.get("files") if isinstance(manifest, dict) else None
    if not isinstance(entries, list):
        errors.append("artifact-manifest.json has no files array")
        return 0
    checked = 0
    for entry in entries:
        if not isinstance(entry, dict) or not isinstance(entry.get("path"), str):
            errors.append("artifact manifest has an invalid entry")
            continue
        try:
            artifact = safe_relative(root, entry["path"])
        except ValueError as exc:
            errors.append(str(exc))
            continue
        if not artifact.is_file():
            errors.append(f"manifest file is missing: {entry['path']}")
            continue
        if sha256_file(artifact) != entry.get("sha256"):
            errors.append(f"manifest hash differs: {entry['path']}")
            continue
        checked += 1
    return checked


def verify_argv_files(root: Path, result: Any, errors: list[str], warnings: list[str]) -> int:
    checks = result.get("checks") if isinstance(result, dict) else None
    if not isinstance(checks, list):
        errors.append("result.json has no checks array")
        return 0
    checked = 0
    for check in checks:
        check_id = check.get("id", "<unknown>") if isinstance(check, dict) else "<unknown>"
        runs = check.get("runs", {}) if isinstance(check, dict) else {}
        if not isinstance(runs, dict):
            errors.append(f"{check_id}: runs is not an object")
            continue
        for side, run in runs.items():
            records = run.get("argv_files", []) if isinstance(run, dict) else []
            if not isinstance(records, list):
                errors.append(f"{check_id}/{side}: argv_files is not an array")
                continue
            for record in records:
                if not isinstance(record, dict):
                    errors.append(f"{check_id}/{side}: invalid argv_files record")
                    continue
                digest = record.get("sha256")
                artifact_name = record.get("artifact")
                if digest is None:
                    continue
                if not isinstance(digest, str) or len(digest) != 64:
                    errors.append(f"{check_id}/{side}: invalid helper digest")
                    continue
                if artifact_name is None:
                    reason = record.get("archive_reason") or "not archived"
                    warnings.append(
                        f"{check_id}/{side}: helper {record.get('index')} cannot be rechecked: "
                        f"{reason}"
                    )
                    continue
                if not isinstance(artifact_name, str):
                    errors.append(f"{check_id}/{side}: invalid helper artifact path")
                    continue
                try:
                    artifact = safe_relative(root, artifact_name)
                except ValueError as exc:
                    errors.append(f"{check_id}/{side}: {exc}")
                    continue
                if not artifact.is_file():
                    errors.append(f"{check_id}/{side}: helper artifact is missing: {artifact_name}")
                    continue
                if sha256_file(artifact) != digest:
                    errors.append(f"{check_id}/{side}: helper hash differs: {artifact_name}")
                    continue
                checked += 1
    return checked


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--results", required=True, help="Runner output directory")
    args = parser.parse_args(argv)
    root = Path(args.results).resolve()
    errors: list[str] = []
    warnings: list[str] = []
    try:
        result = load_json(root / "result.json")
        manifest_count = verify_manifest(root, errors)
        helper_count = verify_argv_files(root, result, errors, warnings)
    except ValueError as exc:
        errors.append(str(exc))
        manifest_count = helper_count = 0
    summary = {
        "valid": not errors,
        "manifest_files_checked": manifest_count,
        "helper_files_checked": helper_count,
        "warnings": warnings,
        "errors": errors,
    }
    print(json.dumps(summary, indent=2, sort_keys=True))
    return 0 if summary["valid"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
