#!/usr/bin/env python3
# /// script
# requires-python = ">=3.11"
# dependencies = []
# ///
"""Regressions for the shared-manifest warning exception; no CLI required."""

import unittest

from check_claude_loadability import validation_issues


class ValidationIssuesTests(unittest.TestCase):
    def setUp(self):
        self.warning = {
            "path": "interface",
            "message": "Unknown field 'interface'. Claude Code ignores it at load time.",
        }
        self.report = {
            "success": True,
            "manifest": {"type": "plugin", "errors": [], "warnings": [self.warning]},
            "contents": [],
        }

    def test_accepts_only_intentional_interface_warning(self):
        self.assertEqual(validation_issues(self.report), [])
        self.report["manifest"]["warnings"] = []
        self.assertEqual(validation_issues(self.report), [])

    def test_other_warnings_still_fail(self):
        self.report["manifest"]["warnings"].append(
            {"path": "author", "message": "No author information provided"}
        )
        self.assertEqual(len(validation_issues(self.report)), 1)

    def test_interface_errors_still_fail(self):
        self.report["manifest"]["errors"] = [{"path": "interface", "message": "invalid"}]
        self.assertTrue(validation_issues(self.report))

    def test_different_interface_warning_still_fails(self):
        self.warning["message"] = "interface must be an object"
        self.assertTrue(validation_issues(self.report))

    def test_misspelled_field_still_fails(self):
        self.warning["path"] = "interfce"
        self.assertTrue(validation_issues(self.report))

    def test_exception_does_not_apply_to_marketplace_or_contents(self):
        self.report["manifest"]["type"] = "marketplace"
        self.assertTrue(validation_issues(self.report))
        self.report["manifest"]["type"] = "plugin"
        self.report["contents"] = [{"warnings": [self.warning], "errors": []}]
        self.assertTrue(validation_issues(self.report))

    def test_failed_or_empty_report_still_fails(self):
        self.report["success"] = False
        self.assertTrue(validation_issues(self.report))
        self.assertTrue(validation_issues({}))
        self.assertTrue(validation_issues({"success": True, "manifest": {}}))

    def test_accepts_nested_plugin_interface_warning_in_marketplace(self):
        self.report["manifest"]["type"] = "marketplace"
        self.warning["path"] = "plugins[12] plugin.json → interface"
        self.assertEqual(validation_issues(self.report), [])
        self.warning["path"] = "plugins[12] plugin.json → interfce"
        self.assertTrue(validation_issues(self.report))


if __name__ == "__main__":
    unittest.main()
