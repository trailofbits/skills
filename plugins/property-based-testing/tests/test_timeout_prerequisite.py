"""Fail before a sweep if GNU timeout is absent; accept Homebrew's name."""

import os
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

EVALS = Path(__file__).resolve().parents[1] / "evals-extra"


class TimeoutPrerequisite(unittest.TestCase):
    def test_grader_selftest_does_not_require_session_timeout(self):
        p = subprocess.run(
            ["/bin/bash", str(EVALS / "effectiveness.sh"), "--self-test"],
            capture_output=True,
            text=True,
        )
        self.assertEqual(p.returncode, 0, p.stdout + p.stderr)
        self.assertIn("grader self-test passed", p.stdout)

    def test_missing_timeout_is_explicit_harness_error(self):
        with tempfile.TemporaryDirectory() as d:
            bindir = Path(d)
            # Deliberately omit timeout/gtimeout and claude; no model invocation.
            for tool in ["dirname", "uv", "mktemp", "mkdir", "cp", "rm"]:
                real = shutil.which(tool)
                self.assertIsNotNone(real)
                (bindir / tool).symlink_to(real)
            for script in ["run.sh", "effectiveness.sh"]:
                p = subprocess.run(
                    ["/bin/bash", str(EVALS / script)],
                    env=os.environ | {"PATH": d},
                    capture_output=True,
                    text=True,
                )
                self.assertEqual(p.returncode, 2, p.stdout + p.stderr)
                self.assertIn("GNU timeout", p.stderr)

    def test_gtimeout_name_is_resolved_before_a_session(self):
        with tempfile.TemporaryDirectory() as d:
            bindir = Path(d)
            for tool in ["dirname", "uv", "mktemp", "mkdir", "cp", "rm"]:
                (bindir / tool).symlink_to(shutil.which(tool))
            # No execution of a session. Probe only the prerequisite prefix of
            # each real script; the remainder includes costly model sweeps.
            for script in ["run.sh", "effectiveness.sh"]:
                (bindir / "timeout").unlink(missing_ok=True)
                source = (EVALS / script).read_text()
                boundary = "\nworkdir=" if script == "run.sh" else "\n# Sorted list"
                end = source.index(boundary)
                for name in ["gtimeout", "timeout"]:
                    (bindir / name).write_text("#!/bin/sh\nexit 0\n")
                    (bindir / name).chmod(0o755)
                    p = subprocess.run(
                        ["/bin/bash", "-c", source[:end] + '\nprintf "%s" "$timeout_bin"'],
                        env=os.environ | {"PATH": d},
                        capture_output=True,
                        text=True,
                    )
                    self.assertEqual(p.returncode, 0, p.stderr)
                    self.assertEqual(p.stdout, str(bindir / name))


if __name__ == "__main__":
    unittest.main()
