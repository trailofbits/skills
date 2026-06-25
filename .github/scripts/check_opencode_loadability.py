#!/usr/bin/env python3
# /// script
# requires-python = ">=3.11"
# dependencies = []
# ///
"""Check that this marketplace's skills load through OpenCode.

Runs `opencode debug skill` from the repo root and verifies that every
expected skill is present and has valid frontmatter.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Any


def discover_expected_skills(repo: Path) -> dict[str, Path]:
    """Walk plugins/*/skills/*/SKILL.md and return {skill_name: path}."""
    skills: dict[str, Path] = {}
    plugins_dir = repo / "plugins"

    if not plugins_dir.is_dir():
        return skills

    for plugin_dir in sorted(plugins_dir.iterdir()):
        if not plugin_dir.is_dir():
            continue

        skills_dir = plugin_dir / "skills"
        if not skills_dir.is_dir():
            continue

        for skill_dir in sorted(skills_dir.iterdir()):
            skill_md = skill_dir / "SKILL.md"
            if not skill_md.is_file():
                continue

            # Validate frontmatter
            content = skill_md.read_text(encoding="utf-8")
            if not content.startswith("---"):
                continue

            match = re.match(r"^---\n(.*?)\n---", content, re.DOTALL)
            if not match:
                continue

            frontmatter_text = match.group(1)
            name = None
            description = None

            for line in frontmatter_text.split("\n"):
                if ":" not in line:
                    continue
                key, _, value = line.partition(":")
                key = key.strip()
                value = value.strip().strip('"').strip("'")

                if key == "name":
                    name = value
                elif key == "description":
                    description = value

            if name and description:
                skills[name] = skill_md

    return skills


def validate_skill_names(skills: dict[str, Path], errors: list[str]) -> None:
    """Validate that skill names match OpenCode naming rules."""
    name_pattern = re.compile(r"^[a-z0-9]+(-[a-z0-9]+)*$")

    for name, path in skills.items():
        if len(name) > 64:
            errors.append(f"{path}: name exceeds 64 characters ({len(name)})")
        if not name_pattern.match(name):
            errors.append(
                f"{path}: name '{name}' must be lowercase alphanumeric "
                "with single hyphen separators"
            )

        # Verify name matches parent directory
        expected_name = path.parent.name
        if name != expected_name:
            errors.append(
                f"{path}: frontmatter name '{name}' does not match directory name '{expected_name}'"
            )


def run_opencode_debug_skill(repo: Path, timeout: float) -> list[dict[str, Any]]:
    """Run `opencode debug skill` and parse JSON output."""
    import tempfile

    # Write directly to file to avoid pipe buffer limits (64KB on Linux)
    with tempfile.NamedTemporaryFile(
        mode="w", suffix=".json", delete=False, encoding="utf-8"
    ) as tmp:
        tmp_path = tmp.name

    stderr_path = tmp_path + ".stderr"

    try:
        with (
            open(tmp_path, "w", encoding="utf-8") as stdout,
            open(stderr_path, "w", encoding="utf-8") as stderr,
        ):
            result = subprocess.run(
                ["opencode", "debug", "skill"],
                cwd=str(repo),
                stdout=stdout,
                stderr=stderr,
                timeout=int(timeout),
            )

        if result.returncode != 0:
            with open(stderr_path, encoding="utf-8") as fh:
                stderr_text = fh.read()
            print(
                f"ERROR: opencode debug skill exited with code {result.returncode}",
                file=sys.stderr,
            )
            if stderr_text:
                print(stderr_text, file=sys.stderr)
            sys.exit(1)

        with open(tmp_path, encoding="utf-8") as fh:
            return json.load(fh)

    except json.JSONDecodeError as exc:
        print(f"ERROR: failed to parse opencode debug skill output: {exc}", file=sys.stderr)
        sys.exit(1)
    finally:
        if os.path.exists(tmp_path):
            os.unlink(tmp_path)
        if os.path.exists(stderr_path):
            os.unlink(stderr_path)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("repo", nargs="?", type=Path, default=Path(__file__).resolve().parents[2])
    parser.add_argument("--timeout", type=float, default=30.0)
    parser.add_argument(
        "--skip-cli",
        action="store_true",
        help="Skip `opencode debug skill` and only validate file structure",
    )
    args = parser.parse_args()

    repo = args.repo.resolve()
    errors: list[str] = []

    expected = discover_expected_skills(repo)
    if not expected:
        print("ERROR: no skills found in plugins/", file=sys.stderr)
        return 1

    validate_skill_names(expected, errors)

    if args.skip_cli:
        print(f"found {len(expected)} skills with valid frontmatter (CLI check skipped)")
        if errors:
            print(f"\nFound {len(errors)} error(s):", file=sys.stderr)
            for error in errors:
                print(f"  - {error}", file=sys.stderr)
            return 1
        print("All OpenCode loadability checks passed (static)")
        return 0

    # Check that opencode is available
    opencode_bin = shutil.which("opencode")
    if opencode_bin is None:
        print("ERROR: opencode binary not found in PATH", file=sys.stderr)
        return 1

    loaded = run_opencode_debug_skill(repo, args.timeout)
    loaded_names = {skill["name"] for skill in loaded if "name" in skill}

    missing = sorted(set(expected.keys()) - loaded_names)
    if missing:
        errors.append(f"{len(missing)} skills not discovered by OpenCode: " + ", ".join(missing))

    extra = sorted(loaded_names - set(expected.keys()))
    if extra:
        print(f"note: OpenCode discovered {len(extra)} additional built-in skills")

    print(f"loaded {len(expected)} Trail of Bits skills through OpenCode")

    if errors:
        print(f"\nFound {len(errors)} OpenCode loadability error(s):", file=sys.stderr)
        for error in errors:
            print(f"  - {error}", file=sys.stderr)
        return 1

    print("All OpenCode loadability checks passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
