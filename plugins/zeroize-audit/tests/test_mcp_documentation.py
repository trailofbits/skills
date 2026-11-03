"""Execute documented MCP command blocks against synthetic local inputs."""

import json
import re
import shlex
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

PLUGIN = Path(__file__).resolve().parents[1]
SKILL = PLUGIN / "skills/zeroize-audit"


class McpDocumentation(unittest.TestCase):
    def test_documented_commands_execute(self):
        cases = [
            (PLUGIN / "agents/1-mcp-resolver.md", "normalize_mcp_evidence.py"),
            (PLUGIN / "agents/4-report-assembler.md", "apply_confidence_gates.py"),
            (SKILL / "references/mcp-analysis.md", "apply_confidence_gates.py"),
        ]
        for doc, script in cases:
            with self.subTest(doc=doc), tempfile.TemporaryDirectory() as d:
                work = Path(d)
                raw = work / "raw.json"
                report = work / "raw-report.json"
                raw.write_text(
                    json.dumps(
                        {
                            "results": [
                                {
                                    "file": "sample.c",
                                    "line": 1,
                                    "symbol": "wipe",
                                    "kind": "function",
                                }
                            ]
                        }
                    )
                )
                report.write_text(json.dumps({"findings": []}))
                blocks = re.findall(r"```bash\n(.*?)```", doc.read_text(), re.S)
                block = next(b for b in blocks if script in b)
                command = block.replace("\\\n", " ").strip()
                for token, value in {
                    "{baseDir}": str(SKILL),
                    "<raw_results>": str(raw),
                    "<workdir>": d,
                    "<raw_report_json>": str(report),
                    "<raw_findings_json>": str(report),
                    "<gated_report_json>": str(work / "gated.json"),
                    "<mcp_available>": "true",
                    "<mcp_required_for_advanced>": "true",
                    "/tmp/raw-report.json": str(report),
                    "/tmp/final-report.json": str(work / "gated.json"),
                }.items():
                    command = command.replace(token, value)
                args = shlex.split(command)
                self.assertEqual(args[:3], ["uv", "run", "--no-project"])
                p = subprocess.run([sys.executable, *args[3:]], capture_output=True, text=True)
                self.assertEqual(p.returncode, 0, p.stderr)
                output = Path(args[args.index("--out") + 1])
                data = json.loads(output.read_text())
                if script == "normalize_mcp_evidence.py":
                    self.assertEqual(
                        set(data), {"mcp_available", "evidence_count", "evidence", "coverage"}
                    )
                    self.assertEqual(data["evidence"][0]["symbol"], "wipe")
                    self.assertIn("metadata", data["evidence"][0])


if __name__ == "__main__":
    unittest.main()
