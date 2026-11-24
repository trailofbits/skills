"""Absent/unreadable sources must use the existing object-link placeholder."""

import importlib.util
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

TOOLS = Path(__file__).resolve().parents[1] / "skills/zeroize-audit/tools"
spec = importlib.util.spec_from_file_location("poc", TOOLS / "generate_poc.py")
assert spec is not None and spec.loader is not None
poc = importlib.util.module_from_spec(spec)
spec.loader.exec_module(poc)


class SourceInclusion(unittest.TestCase):
    def test_missing_source_gets_link_placeholder_not_include(self):
        with tempfile.TemporaryDirectory() as d:
            src = Path(d) / "missing.c"
            gen = poc.MissingSourceZeroizePoC(
                {"id": "ZA-1", "file": str(src), "line": 1}, "unused.json", d, {}
            )
            self.assertFalse(gen._use_source_inclusion())
            self.assertIn("Link against object file", gen._include_directive())

    def test_empty_file_is_includable_but_unreadable_file_is_not(self):
        with tempfile.TemporaryDirectory() as d:
            src = Path(d) / "empty.c"
            src.touch()
            gen = poc.MissingSourceZeroizePoC({"file": str(src)}, "unused.json", d, {})
            self.assertTrue(gen._use_source_inclusion())
            # Deterministic even under root: simulate only the actual file read.
            with patch("builtins.open", side_effect=PermissionError("synthetic unreadable file")):
                self.assertFalse(gen._use_source_inclusion())


if __name__ == "__main__":
    unittest.main()
