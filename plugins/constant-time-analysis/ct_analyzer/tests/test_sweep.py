"""Tests for sweep.py: one call per arch x level matrix, full payloads identical to direct runs."""

import json
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
SWEEP = HERE.parent / "sweep.py"
ANALYZER = HERE.parent / "analyzer.py"
SAMPLE = HERE / "test_samples" / "decompose_vulnerable.c"  # compiler headers only
JS_SAMPLE = HERE / "triage_samples" / "triage_js.js"


def run(*args, cwd=None):
    return subprocess.run(
        [sys.executable, str(SWEEP), *map(str, args)], capture_output=True, text=True, cwd=cwd
    )


def direct(*args):
    proc = subprocess.run(
        [sys.executable, str(ANALYZER), "--json", *map(str, args)], capture_output=True, text=True
    )
    return json.loads(proc.stdout)


@unittest.skipUnless(shutil.which("clang"), "clang required")
class TestNativeSweep(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="ct sweep "))  # a path with a space
        self.addCleanup(shutil.rmtree, self.tmp)

    def test_every_payload_equals_a_direct_run(self):
        out = self.tmp / "out"
        proc = run(
            "--warnings", "--archs", "x86_64,arm64", "--levels", "O0,O2", "--out", out, SAMPLE
        )
        self.assertEqual(proc.returncode, 1, proc.stderr)  # the sample divides secrets
        for arch in ("x86_64", "arm64"):
            for level in ("O0", "O2"):
                saved = json.loads((out / f"{SAMPLE.name}.{arch}.{level}.json").read_text())
                want = direct("--warnings", "--arch", arch, "--opt-level", level, SAMPLE)
                self.assertEqual(saved, want, f"{arch}/{level}")
                self.assertIn(f"{arch}/{level}", proc.stdout)
        summary = json.loads((out / f"{SAMPLE.name}.sweep.json").read_text())
        self.assertEqual(len(summary["configurations"]), 4)
        merged = sum(e["count"] for e in summary["worklist"])
        direct_total = sum(
            len(json.loads((out / f"{SAMPLE.name}.{a}.{lv}.json").read_text())["violations"])
            for a in ("x86_64", "arm64")
            for lv in ("O0", "O2")
        )
        self.assertEqual(merged, direct_total)  # nothing dropped by the merge

    def test_json_mode_and_function_filter(self):
        proc = run(
            "--warnings",
            "--archs",
            "arm64",
            "--levels",
            "O2",
            "--func",
            "^$",
            "--json",
            "--out",
            self.tmp / "o",
            SAMPLE,
        )
        summary = json.loads(proc.stdout)
        self.assertEqual(summary["worklist"], [])
        self.assertEqual(summary["configurations"][0]["status"], "PASSED")
        self.assertEqual(proc.returncode, 0)

    def test_a_configuration_that_cannot_run_is_an_error_not_clean(self):
        proc = run(
            "--warnings",
            "--archs",
            "arm64,notanarch",
            "--levels",
            "O0",
            "--out",
            self.tmp / "o",
            SAMPLE,
        )
        self.assertEqual(proc.returncode, 2)
        self.assertRegex(proc.stdout, r"notanarch/O0\s+ERROR")
        self.assertRegex(proc.stdout, r"arm64/O0\s+FAILED")

    def test_without_warnings_says_so(self):
        proc = run("--archs", "arm64", "--levels", "O0", "--out", self.tmp / "o", SAMPLE)
        self.assertIn("run without --warnings", proc.stdout)


class TestArguments(unittest.TestCase):
    def test_missing_file(self):
        proc = run("--warnings", "/nonexistent/x.c")
        self.assertEqual(proc.returncode, 2)
        self.assertIn("source file not found", proc.stderr)

    def test_empty_matrix_is_rejected(self):
        proc = run("--warnings", "--archs", "", "--levels", "O0", SAMPLE)
        self.assertEqual(proc.returncode, 2)

    @unittest.skipUnless(shutil.which("node"), "node required")
    def test_bytecode_language_runs_once(self):
        with tempfile.TemporaryDirectory() as t:
            proc = run("--warnings", "--out", Path(t), JS_SAMPLE)
            self.assertIn("configurations (1)", proc.stdout)
            self.assertTrue((Path(t) / f"{JS_SAMPLE.name}.default.json").is_file())


if __name__ == "__main__":
    unittest.main()
