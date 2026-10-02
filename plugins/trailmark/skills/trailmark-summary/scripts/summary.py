#!/usr/bin/env -S uv run --script
# /// script
# requires-python = ">=3.11"
# dependencies = []
# ///
"""Return complete summary evidence using an existing Trailmark installation."""

from __future__ import annotations

import argparse
import contextlib
import importlib
import io
import json
import shlex
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path


def run(command: list[str]) -> subprocess.CompletedProcess[str]:
    try:
        with tempfile.TemporaryDirectory(prefix="trailmark-summary-") as cwd:
            return subprocess.run(command, cwd=cwd, text=True, capture_output=True, check=False)
    except FileNotFoundError as exc:
        return subprocess.CompletedProcess(command, 127, "", str(exc))


def collect(target: str) -> dict[str, object]:
    import trailmark
    from trailmark.cli import _print_summary

    try:
        parse = importlib.import_module("trailmark.parse")
    except ModuleNotFoundError as exc:
        if exc.name != "trailmark.parse":
            raise
        parse = None
    detect_languages = getattr(parse, "detect_languages", None)
    if detect_languages is None:
        from trailmark.query.api import detect_languages
    from trailmark.query.api import QueryEngine

    languages = detect_languages(target)
    if not languages:
        return {"languages": [], "error": "Trailmark found no supported languages under target"}
    # The native renderer and API share the same graph and installed version.
    with contextlib.redirect_stdout(sys.stderr):
        engine = QueryEngine.from_directory(target, language="auto")
        summary = engine.summary()
    output = io.StringIO()
    with contextlib.redirect_stdout(output):
        _print_summary(engine)
    text = output.getvalue()
    if "Entrypoints:" not in text or "Dependencies:" not in text:
        raise RuntimeError("Trailmark summary is missing Entrypoints or Dependencies")
    payload = {"languages": languages, "summary": summary, "summary_text": text}
    if version := getattr(trailmark, "__version__", None):
        payload["version"] = f"trailmark {version}"
    return payload


def python_commands(target: Path, explicit: Path | None = None) -> list[list[str]]:
    """Read global executable metadata; never probe a project environment or CLI."""
    if explicit:
        return [[str(explicit.expanduser().absolute()), "-E", "-P"]]
    roots = (target.resolve(), Path.cwd().resolve())

    def trusted(path: Path) -> bool:
        # Check both the launcher and symlink destination, not just the destination.
        return path.is_file() and not any(
            p.is_relative_to(root) for p in (path.absolute(), path.resolve()) for root in roots
        )

    candidates = [Path(sys.executable)]
    executable = shutil.which("trailmark")
    if executable and trusted(Path(executable)):
        launcher = Path(executable).resolve()
        try:
            with launcher.open("rb") as stream:
                first = stream.readline(4096).decode("utf-8", errors="replace").strip()
        except OSError:
            first = ""  # Executable-only launchers can still have an adjacent interpreter.
        if first.startswith("#!"):
            words = shlex.split(first[2:])
            if (
                words
                and Path(words[0]).is_absolute()
                and Path(words[0]).name.startswith(("python", "pypy"))
            ):
                candidates.insert(0, Path(words[0]))
            elif words and Path(words[0]).name == "env":
                names = [w for w in words[1:] if not w.startswith("-")]
                if (
                    len(names) == 1
                    and names[0].startswith("python")
                    and (interpreter := shutil.which(names[0]))
                ):
                    candidates.insert(0, Path(interpreter))
        for name in ("python", "python3", "python.exe"):
            candidates.append(launcher.parent / name)
    for name in ("python3", "python"):
        if interpreter := shutil.which(name):
            candidates.append(Path(interpreter))
    commands = []
    seen = set()
    for interpreter in candidates:
        # Keep the venv path: resolving a venv's Python symlink loses its site-packages.
        value = str(interpreter.absolute())
        if trusted(interpreter) and value not in seen:
            # Ignore PYTHONPATH/startup overrides and unsafe cwd/script paths, but
            # keep the user's installed site-packages (unlike -I).
            commands.append([value, "-E", "-P"])
            seen.add(value)
    return commands


def build_summary(target: str, interpreter: Path | None = None) -> dict[str, object]:
    root = Path(target).expanduser().resolve()
    if not root.is_dir():
        raise ValueError(f"target is not a directory: {root}")
    errors = []
    for command in python_commands(root, interpreter):
        result = run([*command, str(Path(__file__).resolve()), "--collect", str(root)])
        if result.returncode in (0, 2):
            payload = json.loads(result.stdout)
            if result.returncode == 2 and not (
                isinstance(payload, dict)
                and payload.get("error")
                and payload.get("languages") == []
            ):
                raise RuntimeError(
                    "Trailmark collector failed without a no-supported-languages diagnostic"
                )
            if result.stderr:
                print(result.stderr, file=sys.stderr, end="")
            return payload
        errors.append(result.stderr.strip() or f"{command[0]} exited {result.returncode}")
        if result.returncode not in (3, 127):
            raise RuntimeError(errors[-1])
    raise RuntimeError(
        "Trailmark's Python API is unavailable in trusted existing environments; "
        "use --python=PATH with an absolute trusted interpreter path. " + "; ".join(errors)
    )


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("target")
    parser.add_argument("--out", type=Path)
    parser.add_argument(
        "--python", type=Path, help="explicit trusted Python with Trailmark installed"
    )
    parser.add_argument("--collect", action="store_true", help=argparse.SUPPRESS)
    args = parser.parse_args()
    try:
        with contextlib.redirect_stdout(sys.stderr):
            payload = (
                collect(args.target) if args.collect else build_summary(args.target, args.python)
            )
        text = json.dumps(payload, indent=2) + "\n"
        print(text, end="")
        if args.out:
            args.out.parent.mkdir(parents=True, exist_ok=True)
            args.out.write_text(text)
    except ModuleNotFoundError as exc:
        print(str(exc), file=sys.stderr)
        return 3 if exc.name == "trailmark" else 1
    except (ImportError, OSError, RuntimeError, ValueError) as exc:
        print(str(exc), file=sys.stderr)
        return 1
    return 2 if payload.get("error") else 0


if __name__ == "__main__":
    raise SystemExit(main())
