"""Use real dis output: source locations must not become byte offsets."""

import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from script_analyzers import PythonAnalyzer


class PythonSourceLines(unittest.TestCase):
    def test_real_dis_multiline_single_line_lambda_and_jump(self):
        source = "\n" * 10 + (
            "f = lambda a, b: a / b\n"
            "def single(a, b): return a // b\n"
            "def multiple(a, b):\n"
            "    x = a + 1\n"
            "    return x / b\n"
            "def branch(a, b):\n"
            "    if a:\n"
            "        return a % b\n"
            "    return a / b\n"
        )
        with tempfile.TemporaryDirectory() as d:
            src = Path(d) / "sample.py"
            src.write_text(source)
            analyzer = PythonAnalyzer()
            ok, output = analyzer._get_dis_output(str(src))
            self.assertTrue(ok, output)
            _, violations = analyzer._parse_dis_output(output, str(src))
            self.assertEqual(
                [(v.function, v.line) for v in violations],
                [("<lambda", 11), ("single", 12), ("multiple", 15), ("branch", 18), ("branch", 19)],
            )


if __name__ == "__main__":
    unittest.main()
