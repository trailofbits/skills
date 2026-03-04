#!/usr/bin/env python3
# /// script
# requires-python = ">=3.11"
# dependencies = []
# ///
"""Validate OpenCode compatibility assumptions for repository skills."""

from __future__ import annotations

import re
import sys
from dataclasses import dataclass
from pathlib import Path

FRONTMATTER_RE = re.compile(r"^---\r?\n(.*?)\r?\n---(?:\r?\n|$)", re.DOTALL)
NAME_RE = re.compile(r"^[a-z0-9]+(-[a-z0-9]+)*$")

CLAUDE_ONLY_COMMAND_FIELDS = {"allowed-tools", "argument-hint"}


@dataclass(frozen=True)
class SkillRecord:
    """Parsed metadata for one SKILL.md file."""

    name: str
    description: str
    path: Path


def unquote(value: str) -> str:
    """Remove matching single or double quotes around a scalar."""
    if len(value) >= 2 and value[0] == value[-1] and value[0] in {'"', "'"}:
        return value[1:-1]
    return value


def parse_frontmatter(text: str, path: Path) -> dict[str, str]:
    """Parse simple YAML frontmatter scalar key/value pairs.

    Does not handle YAML lists (e.g. allowed-tools entries). List keys
    will have an empty string value.
    """
    match = FRONTMATTER_RE.match(text)
    if not match:
        raise ValueError(f"{path}: missing or malformed YAML frontmatter")

    parsed: dict[str, str] = {}
    for raw_line in match.group(1).splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#") or ":" not in raw_line:
            continue
        key, value = raw_line.split(":", 1)
        parsed[key.strip()] = unquote(value.strip())

    return parsed


def collect_skill_records(
    repo_root: Path,
) -> tuple[list[SkillRecord], list[str], list[str]]:
    """Collect skill metadata and compatibility warnings/errors."""
    records: list[SkillRecord] = []
    errors: list[str] = []
    warnings: list[str] = []

    for skill_path in sorted(repo_root.glob("plugins/**/SKILL.md")):
        relative = skill_path.relative_to(repo_root)
        parts = relative.parts
        if len(parts) < 4 or parts[0] != "plugins" or parts[2] != "skills":
            errors.append(f"{relative}: expected plugins/<plugin>/skills/.../SKILL.md path layout")
            continue

        try:
            text = skill_path.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError) as exc:
            errors.append(f"{relative}: cannot read file ({exc})")
            continue

        if "{baseDir}" in text:
            warnings.append(
                f"{relative}: contains '{{baseDir}}' (Claude-specific variable, "
                "not substituted by OpenCode)"
            )

        try:
            metadata = parse_frontmatter(text, skill_path)
        except ValueError as parse_error:
            errors.append(str(parse_error))
            continue

        name = metadata.get("name", "").strip()
        description = metadata.get("description", "").strip()

        if not name:
            errors.append(f"{relative}: frontmatter missing required 'name'")
            continue
        if not description:
            errors.append(f"{relative}: frontmatter missing required 'description'")
            continue

        if len(name) > 64:
            errors.append(f"{relative}: name '{name}' exceeds OpenCode max length (64)")
        if not NAME_RE.fullmatch(name):
            errors.append(
                f"{relative}: name '{name}' is invalid for OpenCode "
                "(must match ^[a-z0-9]+(-[a-z0-9]+)*$)"
            )

        # OpenCode requires skill directory name to match frontmatter name
        skill_dir_name = skill_path.parent.name
        if skill_dir_name != name:
            errors.append(
                f"{relative}: directory name '{skill_dir_name}' does not match "
                f"frontmatter name '{name}' (OpenCode requires these to match)"
            )

        records.append(SkillRecord(name=name, description=description, path=relative))

    return records, errors, warnings


def check_duplicate_names(records: list[SkillRecord]) -> list[str]:
    """Return duplicate skill name errors."""
    by_name: dict[str, list[Path]] = {}
    for record in records:
        by_name.setdefault(record.name, []).append(record.path)

    errors: list[str] = []
    for name, paths in sorted(by_name.items()):
        if len(paths) <= 1:
            continue
        formatted_paths = ", ".join(str(path) for path in paths)
        errors.append(f"duplicate skill name '{name}' found in: {formatted_paths}")

    return errors


def validate_command_files(
    repo_root: Path,
) -> tuple[list[str], list[str]]:
    """Check command files for OpenCode compatibility issues."""
    errors: list[str] = []
    warnings: list[str] = []
    command_count = 0

    for cmd_path in sorted(repo_root.glob("plugins/*/commands/*.md")):
        relative = cmd_path.relative_to(repo_root)
        command_count += 1

        try:
            text = cmd_path.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError) as exc:
            errors.append(f"{relative}: cannot read file ({exc})")
            continue

        if "${CLAUDE_PLUGIN_ROOT}" in text:
            warnings.append(
                f"{relative}: uses ${{CLAUDE_PLUGIN_ROOT}} (incompatible with OpenCode)"
            )

        try:
            metadata = parse_frontmatter(text, cmd_path)
        except ValueError:
            continue

        found = CLAUDE_ONLY_COMMAND_FIELDS & set(metadata)
        if found:
            warnings.append(
                f"{relative}: uses Claude-specific frontmatter "
                f"fields {found} (silently ignored by OpenCode)"
            )

    return errors, warnings


def main() -> int:
    """Run validation and print a concise report."""
    repo_root = Path(__file__).resolve().parents[1]
    plugins_dir = repo_root / "plugins"
    if not plugins_dir.is_dir():
        print(
            f"Error: {plugins_dir} not found. Is this script in the right location?",
            file=sys.stderr,
        )
        return 1

    records, errors, warnings = collect_skill_records(repo_root)
    errors.extend(check_duplicate_names(records))

    cmd_errors, cmd_warnings = validate_command_files(repo_root)
    errors.extend(cmd_errors)
    warnings.extend(cmd_warnings)

    print(f"Checked {len(records)} skills for OpenCode compatibility.")

    if warnings:
        print(f"\nWarnings ({len(warnings)}):")
        for warning in warnings:
            print(f"  - {warning}")

    if errors:
        print(f"\nErrors ({len(errors)}):", file=sys.stderr)
        for error in errors:
            print(f"  - {error}", file=sys.stderr)
        return 1

    print("\nOpenCode compatibility checks passed.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
