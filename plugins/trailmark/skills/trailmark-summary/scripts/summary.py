#!/usr/bin/env -S uv run --script
# /// script
# requires-python = ">=3.11"
# dependencies = []
# ///
"""Return complete summary evidence using an existing Trailmark installation."""

from __future__ import annotations

import argparse
import json
import shutil
import subprocess
import sys
from pathlib import Path


def run(command: list[str]) -> subprocess.CompletedProcess[str]:
    try:
        return subprocess.run(command, text=True, capture_output=True, check=False)
    except FileNotFoundError as exc:
        return subprocess.CompletedProcess(command, 127, "", str(exc))


def collect(target: str) -> dict[str, object]:
    try:
        from trailmark.parse import detect_languages
    except ModuleNotFoundError:
        from trailmark.query.api import detect_languages
    from trailmark.query.api import QueryEngine

    languages = detect_languages(target)
    if not languages:
        return {"languages": [], "error": "Trailmark found no supported languages under target"}
    engine = QueryEngine.from_directory(target, language="auto")
    return {"languages": languages, "summary": engine.summary()}


def python_commands() -> list[list[str]]:
    """Find existing environments without resolving or installing packages."""
    commands = [[sys.executable]]
    executable = shutil.which("trailmark")
    if executable:
        directory = Path(executable).resolve().parent
        for name in ("python", "python3", "python.exe"):
            interpreter = directory / name
            if interpreter.is_file():
                commands.append([str(interpreter)])
    commands.append(["uv", "run", "--no-sync", "python"])
    return commands


def build_summary(target: str) -> dict[str, object]:
    available = [
        command
        for command in (["trailmark"], ["uv", "run", "--no-sync", "trailmark"])
        if run([*command, "analyze", "--help"]).returncode == 0
    ]
    if not available:
        raise RuntimeError("trailmark is not installed")

    result = None
    for command in python_commands():
        result = run([*command, str(Path(__file__).resolve()), "--collect", target])
        if result.returncode == 0:
            break
        if result.returncode not in (3, 127):
            raise RuntimeError(result.stderr.strip() or "Trailmark language detection failed")
    if result is None or result.returncode:
        raise RuntimeError("Trailmark's Python API is unavailable in the existing environments")
    payload = json.loads(result.stdout)
    if not payload["languages"]:
        return payload

    for command in available:
        result = subprocess.run(
            [*command, "analyze", "--language", "auto", "--summary", target],
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            check=False,
        )
        if result.returncode == 0:
            break
    if result.returncode:
        raise RuntimeError(result.stdout.strip() or "Trailmark summary failed")
    if "Entrypoints:" not in result.stdout or "Dependencies:" not in result.stdout:
        raise RuntimeError("Trailmark summary is missing Entrypoints or Dependencies")
    payload["summary_text"] = result.stdout
    for command in available:
        version = run([*command, "--version"])
        if version.returncode == 0 and version.stdout.strip():
            payload["version"] = version.stdout.strip()
            break
    return payload


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("target")
    parser.add_argument("--out", type=Path)
    parser.add_argument("--collect", action="store_true", help=argparse.SUPPRESS)
    args = parser.parse_args()
    try:
        payload = collect(args.target) if args.collect else build_summary(args.target)
        text = json.dumps(payload, indent=2) + "\n"
        if args.out:
            args.out.parent.mkdir(parents=True, exist_ok=True)
            args.out.write_text(text)
        print(text, end="")
    except ImportError as exc:
        print(str(exc), file=sys.stderr)
        return 3
    except (OSError, RuntimeError, ValueError) as exc:
        print(str(exc), file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
