#!/usr/bin/env python3
# /// script
# requires-python = ">=3.11"
# dependencies = []
# ///
"""Validate plugin metadata consistency across all configuration files.

Checks that plugins have:
1. A valid .claude-plugin/plugin.json
2. An entry in .claude-plugin/marketplace.json
3. An entry in README.md
4. An entry in CODEOWNERS
"""

from __future__ import annotations

import json
import os
import re
import sys
from dataclasses import dataclass
from pathlib import Path

PLUGIN_PATH_PATTERN = re.compile(r"^plugins/([^/]+)/")


@dataclass
class ValidationError:
    """A single validation error."""

    plugin: str
    message: str

    def __str__(self) -> str:
        return f"{self.plugin}: {self.message}"


def scan_plugins_directory(plugins_dir: Path) -> set[str]:
    """Scan plugins/ directory and return all plugin directory names."""
    if not plugins_dir.is_dir():
        return set()

    return {
        p.name
        for p in plugins_dir.iterdir()
        if p.is_dir() and not p.name.startswith(".")
    }


def extract_plugins_from_changed_files(
    changed_files: list[str],
    repo_root: Path,
) -> set[str]:
    """Extract plugin names from changed file paths.

    If marketplace.json changed, includes all plugins from marketplace AND
    all directories in plugins/ (to catch unregistered plugins).
    """
    plugins = set()
    marketplace_changed = False

    for path in changed_files:
        if match := PLUGIN_PATH_PATTERN.match(path):
            plugins.add(match.group(1))
        elif path == ".claude-plugin/marketplace.json":
            marketplace_changed = True

    if marketplace_changed:
        marketplace_path = repo_root / ".claude-plugin" / "marketplace.json"
        plugins.update(parse_marketplace(marketplace_path).keys())
        plugins.update(scan_plugins_directory(repo_root / "plugins"))

    return plugins


def parse_marketplace(marketplace_path: Path) -> dict[str, dict]:
    """Parse marketplace.json and return plugin_name -> plugin_data mapping."""
    if not marketplace_path.exists():
        return {}

    data = json.loads(marketplace_path.read_text())
    return {p["name"]: p for p in data.get("plugins", []) if p.get("name")}


def parse_codeowners(codeowners_path: Path) -> set[str]:
    """Parse CODEOWNERS and return set of plugin names with entries."""
    if not codeowners_path.exists():
        return set()

    plugins = set()
    pattern = re.compile(r"^/plugins/([^/]+)/")

    for line in codeowners_path.read_text().splitlines():
        line = line.strip()
        if line and not line.startswith("#") and (match := pattern.match(line)):
            plugins.add(match.group(1))

    return plugins


def parse_readme(readme_path: Path) -> set[str]:
    """Parse README.md and return set of plugin names mentioned in tables."""
    if not readme_path.exists():
        return set()

    plugins = set()
    # Matches [text](plugins/name) or [text](./plugins/name)
    pattern = re.compile(r"\[[^\]]+\]\(\.?/?plugins/([^/)]+)")

    for line in readme_path.read_text().splitlines():
        for match in pattern.finditer(line):
            plugins.add(match.group(1))

    return plugins


def validate_plugin_json(plugin_path: Path, plugin_name: str) -> list[str]:
    """Validate plugin.json exists and has required fields."""
    errors = []
    json_path = plugin_path / ".claude-plugin" / "plugin.json"

    if not json_path.exists():
        return ["missing .claude-plugin/plugin.json"]

    try:
        data = json.loads(json_path.read_text())
    except json.JSONDecodeError as e:
        return [f".claude-plugin/plugin.json is invalid JSON: {e}"]

    if "name" not in data:
        errors.append(".claude-plugin/plugin.json missing 'name' field")
    elif data["name"] != plugin_name:
        errors.append(
            f".claude-plugin/plugin.json name '{data['name']}' "
            f"doesn't match directory name '{plugin_name}'"
        )

    if "description" not in data:
        errors.append(".claude-plugin/plugin.json missing 'description' field")

    if "version" not in data:
        errors.append(".claude-plugin/plugin.json missing 'version' field")

    return errors


def validate_marketplace_entry(
    marketplace_plugins: dict[str, dict],
    plugin_path: Path,
    plugin_name: str,
) -> list[str]:
    """Validate plugin has matching entry in marketplace.json."""
    if plugin_name not in marketplace_plugins:
        return ["not found in .claude-plugin/marketplace.json"]

    errors = []
    marketplace_entry = marketplace_plugins[plugin_name]
    json_path = plugin_path / ".claude-plugin" / "plugin.json"

    if not json_path.exists():
        return errors

    try:
        plugin_data = json.loads(json_path.read_text())
    except json.JSONDecodeError:
        return errors

    if plugin_data.get("name") != marketplace_entry.get("name"):
        errors.append(
            f"name mismatch: plugin.json has '{plugin_data.get('name')}', "
            f"marketplace.json has '{marketplace_entry.get('name')}'"
        )

    expected_source = f"./plugins/{plugin_name}"
    actual_source = marketplace_entry.get("source", "")
    if actual_source != expected_source:
        errors.append(
            f"marketplace.json source '{actual_source}' should be '{expected_source}'"
        )

    return errors


def validate_plugins(
    plugins_to_check: set[str],
    repo_root: Path,
) -> list[ValidationError]:
    """Validate all specified plugins and return errors."""
    errors = []

    plugins_dir = repo_root / "plugins"
    marketplace_plugins = parse_marketplace(
        repo_root / ".claude-plugin" / "marketplace.json"
    )
    codeowners_plugins = parse_codeowners(repo_root / "CODEOWNERS")
    readme_plugins = parse_readme(repo_root / "README.md")

    for plugin_name in sorted(plugins_to_check):
        plugin_path = plugins_dir / plugin_name
        plugin_exists = plugin_path.is_dir()

        if plugin_exists:
            for msg in validate_plugin_json(plugin_path, plugin_name):
                errors.append(ValidationError(plugin_name, msg))

            for msg in validate_marketplace_entry(
                marketplace_plugins, plugin_path, plugin_name
            ):
                errors.append(ValidationError(plugin_name, msg))

            if plugin_name not in codeowners_plugins:
                errors.append(ValidationError(plugin_name, "not found in CODEOWNERS"))

            if plugin_name not in readme_plugins:
                errors.append(ValidationError(plugin_name, "not found in README.md"))
        else:
            if plugin_name in marketplace_plugins:
                errors.append(
                    ValidationError(
                        plugin_name,
                        "deleted but still in .claude-plugin/marketplace.json",
                    )
                )
            if plugin_name in codeowners_plugins:
                errors.append(
                    ValidationError(plugin_name, "deleted but still in CODEOWNERS")
                )
            if plugin_name in readme_plugins:
                errors.append(
                    ValidationError(plugin_name, "deleted but still in README.md")
                )

    return errors


def main() -> int:
    """Validate plugin metadata consistency."""
    repo_root = (
        Path(sys.argv[1]) if len(sys.argv) > 1 else Path(__file__).parent.parent.parent
    )

    changed_files = os.environ.get("CHANGED_FILES", "").splitlines()
    if changed_files:
        plugins_to_check = extract_plugins_from_changed_files(changed_files, repo_root)
        if not plugins_to_check:
            print("No plugins affected by changed files")
            return 0
    else:
        plugins_to_check = scan_plugins_directory(repo_root / "plugins")
        if not plugins_to_check:
            print(f"No plugins found in {repo_root / 'plugins'}")
            return 0

    print(
        f"Checking {len(plugins_to_check)} plugin(s): {', '.join(sorted(plugins_to_check))}"
    )

    errors = validate_plugins(plugins_to_check, repo_root)

    if not errors:
        print("✓ All plugin metadata is in sync")
        return 0

    print(f"\n✗ Found {len(errors)} error(s):\n")
    for error in errors:
        print(f"  • {error}")

    return 1


if __name__ == "__main__":
    sys.exit(main())
