"""Uppercase .C is C++, including the generated build rule."""

import importlib.util
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

TOOLS = Path(__file__).resolve().parents[1] / "skills/zeroize-audit/tools"
spec = importlib.util.spec_from_file_location("poc", TOOLS / "generate_poc.py")
assert spec is not None and spec.loader is not None
poc = importlib.util.module_from_spec(spec)
spec.loader.exec_module(poc)


class CppPoC(unittest.TestCase):
    def test_uppercase_c_gets_cpp_extension_compiler_and_compilable_source(self):
        with tempfile.TemporaryDirectory() as d:
            src = Path(d) / "input.C"
            out = Path(d) / "out"
            out.mkdir()
            src.write_text("namespace example { int value = 1; }\n")
            gen = poc.MissingSourceZeroizePoC(
                {"id": "ZA-1", "file": str(src), "line": 1}, "unused.json", str(out), {}
            )
            filename, text = gen.generate()
            self.assertTrue(filename.endswith(".cpp"), filename)
            self.assertEqual(gen._compiler_var(), "$(CXX)")
            self.assertFalse(poc._is_cpp_file("input.c"))
            for suffix in [".cpp", ".cc", ".cxx", ".hpp", ".hxx", ".CPP"]:
                self.assertTrue(poc._is_cpp_file("input" + suffix))
            (out / filename).write_text(text)
            (out / "poc_common.h").write_text(poc._generate_common_header())
            if shutil.which("clang++"):
                p = subprocess.run(
                    ["clang++", "-fsyntax-only", str(out / filename)],
                    capture_output=True,
                    text=True,
                )
                self.assertEqual(p.returncode, 0, p.stderr)


if __name__ == "__main__":
    unittest.main()
