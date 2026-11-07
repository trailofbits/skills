"""Persistent native-run artifacts and process execution."""

from __future__ import annotations

import hashlib
import json
import subprocess
from pathlib import Path


def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def artifact(path: Path) -> dict:
    return {"path": str(path.resolve()), "sha256": digest(path)}


def write_json(path: Path, data: dict) -> None:
    path.write_text(json.dumps(data, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")


def reserve(path: Path) -> Path:
    path = path.resolve()
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("x", encoding="utf-8") as stream:
        stream.write('{"status":"running"}\n')
    return path


def execute(argv: list[str], cwd: Path, timeout: int) -> tuple[int | None, str, str, list[str]]:
    if not argv or not all(isinstance(arg, str) and arg for arg in argv):
        return None, "", "", ["Command must be a nonempty argument array"]
    try:
        result = subprocess.run(
            argv,
            cwd=cwd,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=timeout,
            check=False,
        )
        return result.returncode, result.stdout, result.stderr, []
    except (OSError, subprocess.TimeoutExpired) as exc:
        stdout = getattr(exc, "stdout", "") or ""
        stderr = getattr(exc, "stderr", "") or ""
        if isinstance(stdout, bytes):
            stdout = stdout.decode("utf-8", errors="replace")
        if isinstance(stderr, bytes):
            stderr = stderr.decode("utf-8", errors="replace")
        return None, stdout, stderr, [f"Command could not complete: {exc}"]


def check_artifact(item: dict, label: str) -> list[str]:
    try:
        if digest(Path(item["path"])) != item["sha256"]:
            return [f"{label} artifact hash mismatch"]
    except (OSError, KeyError, TypeError):
        return [f"{label} artifact missing or invalid"]
    return []
