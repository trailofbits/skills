"""The confidence gate accepts producer evidence lists without rewriting them."""

import copy
import importlib.util
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

TOOLS = Path(__file__).resolve().parents[1] / "skills/zeroize-audit/tools"
spec = importlib.util.spec_from_file_location("gates", TOOLS / "mcp/apply_confidence_gates.py")
gates = importlib.util.module_from_spec(spec)
spec.loader.exec_module(gates)


class ConfidenceEvidence(unittest.TestCase):
    def test_real_mir_output_survives_cli(self):
        fixtures = Path(__file__).parent / "rust-regression/fixtures"
        with tempfile.TemporaryDirectory() as d:
            raw, inp, out = [Path(d) / name for name in ["raw.json", "in.json", "out.json"]]
            subprocess.run(
                [
                    sys.executable,
                    str(TOOLS / "scripts/check_mir_patterns.py"),
                    "--mir",
                    str(fixtures / "sample.mir"),
                    "--secrets",
                    str(fixtures / "secrets.json"),
                    "--out",
                    str(raw),
                ],
                check=True,
            )
            findings = json.loads(raw.read_text())
            self.assertGreater(len(findings), 0)
            inp.write_text(json.dumps({"findings": findings}))
            p = subprocess.run(
                [
                    sys.executable,
                    str(TOOLS / "mcp/apply_confidence_gates.py"),
                    "--input",
                    str(inp),
                    "--out",
                    str(out),
                    "--require-mcp-for-advanced",
                ],
                capture_output=True,
                text=True,
            )
            self.assertEqual(p.returncode, 0, p.stderr)
            updated = json.loads(out.read_text())["findings"]
            self.assertEqual(len(updated), len(findings))
            for before, after in zip(findings, updated, strict=True):
                self.assertEqual(after["evidence"][: len(before["evidence"])], before["evidence"])

    def test_notes_preserve_evidence_and_gate_conditions(self):
        for category, note in [
            ("OPTIMIZED_AWAY_ZEROIZE", "missing IR/ASM"),
            ("REGISTER_SPILL", "missing assembly"),
            ("SECRET_COPY", "MCP unavailable"),
        ]:
            for evidence in [["detail"], [{"kind": "mir", "detail": "raw"}], "detail", None]:
                with self.subTest(category=category, evidence=evidence):
                    before = copy.deepcopy(evidence)
                    result = gates.apply_gates(
                        {"findings": [{"category": category, "evidence": evidence}]}, False, True
                    )["findings"][0]
                    self.assertTrue(result["needs_review"])
                    self.assertIn(note, str(result["evidence"]))
                    if isinstance(before, list):
                        self.assertEqual(result["evidence"][:-1], before)
                        if before and isinstance(before[0], dict):
                            self.assertIsInstance(result["evidence"][-1], dict)
                            self.assertEqual(result["evidence"][-1]["source"], "confidence_gate")
                            self.assertIn(note, result["evidence"][-1]["detail"])
        for evidence in ["ASM dump", ["ASM dump"], [{"kind": "asm", "detail": "dump"}]]:
            result = gates.apply_gates(
                {"findings": [{"category": "REGISTER_SPILL", "evidence": evidence}]}, True, True
            )["findings"][0]
            self.assertNotIn("needs_review", result)


if __name__ == "__main__":
    unittest.main()
