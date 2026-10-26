"""Regression tests for compiler-produced Mach-O labels."""

import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from analyzer import AssemblyParser


class MachOLabels(unittest.TestCase):
    def test_annotated_labels_preserve_function_and_filter_attribution(self):
        asm = (
            "_divide: ; @divide\n sdiv w0, w0, w1\n ret\n"
            "Legitimate:\n udiv w0, w0, w1\n ret\n"
            ".globl LBB0_9\nLBB0_9:\n ret\n"
        )
        functions, violations = AssemblyParser("arm64", "clang").parse(asm)
        self.assertEqual([f["name"] for f in functions], ["_divide", "Legitimate", "LBB0_9"])
        self.assertEqual([v.function for v in violations], ["_divide", "Legitimate"])

    @unittest.skipUnless(sys.platform == "darwin" and shutil.which("clang"), "Apple clang needed")
    def test_real_apple_clang_loop_keeps_function_attribution(self):
        with tempfile.TemporaryDirectory() as d:
            src = Path(d) / "sample.c"
            out = Path(d) / "sample.s"
            src.write_text(
                "int Legitimate(int a, int b) { int r = 0; "
                "for (int i = 0; i < b; i++) { r += a / (b - i); "
                '__asm__ volatile(""); } return r; }\n'
            )
            subprocess.run(
                ["clang", "-target", "arm64-apple-macos11", "-O1", "-S", str(src), "-o", str(out)],
                check=True,
            )
            functions, violations = AssemblyParser("arm64", "clang").parse(out.read_text())
            self.assertTrue(violations)
            self.assertEqual([f["name"] for f in functions], ["_Legitimate"])
            self.assertTrue(all(v.function == "_Legitimate" for v in violations))

    @unittest.skipUnless(sys.platform == "darwin" and shutil.which("clang"), "Apple clang needed")
    def test_real_apple_clang_assembly(self):
        with tempfile.TemporaryDirectory() as d:
            src = Path(d) / "sample.c"
            out = Path(d) / "sample.s"
            src.write_text("int Legitimate(int a, int b) { return a / b; }\n")
            subprocess.run(
                ["clang", "-target", "arm64-apple-macos11", "-O2", "-S", str(src), "-o", str(out)],
                check=True,
            )
            functions, violations = AssemblyParser("arm64", "clang").parse(out.read_text())
            self.assertEqual([f["name"] for f in functions], ["_Legitimate"])
            self.assertEqual([v.function for v in violations], ["_Legitimate"])


if __name__ == "__main__":
    unittest.main()
