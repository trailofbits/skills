#!/usr/bin/env python3
# /// script
# requires-python = ">=3.11"
# dependencies = ["pyyaml>=6.0"]
# ///
"""Check required ChatGPT skill listing fields in agents/openai.yaml.

These snake_case fields are distinct from a plugin manifest's camelCase
interface. A skill may omit openai.yaml; if present, it must supply both fields.
https://developers.openai.com/plugins/deploy/submission-errors#skill-agent-metadata-errors
"""

from __future__ import annotations

import argparse
import tempfile
import unittest
from pathlib import Path

import yaml


def validate_interface(path: Path) -> list[str]:
    """Parse YAML before checking fields so comments or wrong nesting cannot pass."""
    if path.is_symlink() or not path.is_file():
        return [f"{path}: must be a regular file"]
    try:
        data = yaml.safe_load(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, yaml.YAMLError) as exc:
        return [f"{path}: cannot read YAML: {exc}"]
    if not isinstance(data, dict):
        return [f"{path}: must contain a YAML mapping"]
    interface = data.get("interface")
    if not isinstance(interface, dict):
        return [f"{path}: interface must be a YAML mapping"]
    errors = []
    for field in ("display_name", "short_description"):
        value = interface.get(field)
        if not isinstance(value, str) or not value.strip():
            errors.append(f"{path}: interface.{field} must be a non-empty string")
    return errors


def scan(repo: Path) -> tuple[int, list[str]]:
    # Only shipped skill interfaces, not agents at the plugin root or test fixtures.
    paths = sorted((repo / "plugins").glob("*/skills/*/agents/openai.yaml"))
    if not paths:
        return 0, ["No skill interfaces found; refusing to pass an empty scan"]
    errors = [error for path in paths for error in validate_interface(path)]
    return len(paths), errors


class InterfaceTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.repo = Path(temp.name)
        self.path = self.repo / "plugins/demo/skills/example/agents/openai.yaml"
        self.path.parent.mkdir(parents=True)
        self.valid = {
            "interface": {"display_name": "Example", "short_description": "Example skill"},
            "policy": {"allow_implicit_invocation": False},
        }

    def write(self, data):
        self.path.write_text(yaml.safe_dump(data), encoding="utf-8")

    def test_valid_interface_and_policy(self):
        self.write(self.valid)
        self.assertEqual(scan(self.repo), (1, []))

    def test_original_icon_only_file_is_rejected(self):
        self.write({"interface": {"icon_small": "assets/logo.svg", "brand_color": "#D83A34"}})
        count, errors = scan(self.repo)
        self.assertEqual(count, 1)
        self.assertEqual(len(errors), 2)
        self.assertIn("interface.display_name", errors[0])
        self.assertIn("interface.short_description", errors[1])

    def test_required_fields_reject_missing_and_invalid_values(self):
        for key in ("display_name", "short_description"):
            for value in (None, "", " \t\n", True, 7, [], {}):
                with self.subTest(key=key, value=value):
                    data = {"interface": dict(self.valid["interface"])}
                    data["interface"][key] = value
                    self.write(data)
                    self.assertTrue(validate_interface(self.path))
            data = {"interface": dict(self.valid["interface"])}
            del data["interface"][key]
            self.write(data)
            self.assertTrue(validate_interface(self.path))

    def test_camelcase_and_wrong_nesting_do_not_satisfy_fields(self):
        self.write({"interface": {"displayName": "Example", "shortDescription": "Example"}})
        self.assertEqual(len(validate_interface(self.path)), 2)
        self.write({"display_name": "Example", "short_description": "Example", "interface": {}})
        self.assertEqual(len(validate_interface(self.path)), 2)

    def test_malformed_yaml_and_wrong_mapping_types(self):
        for text in ("interface: [", "", "[]", "null", "interface: []", "interface: null"):
            with self.subTest(text=text):
                self.path.write_text(text)
                self.assertTrue(validate_interface(self.path))

    def test_comments_are_not_fields(self):
        self.path.write_text(
            "interface:\n  # display_name: Example\n  # short_description: Example\n"
        )
        self.assertTrue(validate_interface(self.path))

    def test_invalid_utf8(self):
        self.path.write_bytes(b"\xff")
        self.assertTrue(validate_interface(self.path))

    def test_empty_scan_fails_but_skills_without_interfaces_are_allowed(self):
        self.assertTrue(scan(self.repo)[1])
        self.write(self.valid)
        other = self.repo / "plugins/demo/skills/without-interface/SKILL.md"
        other.parent.mkdir()
        other.write_text("---\nname: without-interface\ndescription: Example\n---\n")
        self.assertEqual(scan(self.repo), (1, []))


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("repo", nargs="?", type=Path, default=Path(__file__).resolve().parents[2])
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args()
    if args.self_test:
        suite = unittest.defaultTestLoader.loadTestsFromTestCase(InterfaceTests)
        if suite.countTestCases() < 8:
            parser.error("Self-test discovered fewer than 8 cases")
        return 0 if unittest.TextTestRunner().run(suite).wasSuccessful() else 1
    count, errors = scan(args.repo)
    print(f"Checked {count} skill interface(s)")
    for error in errors:
        print(f"ERROR: {error}")
    return 1 if errors else 0


if __name__ == "__main__":
    raise SystemExit(main())
