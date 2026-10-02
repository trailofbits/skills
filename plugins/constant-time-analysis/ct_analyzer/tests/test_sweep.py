"""Tests for sweep.py: one call per arch x level matrix, full payloads identical to direct runs."""

import importlib
import json
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

HERE = Path(__file__).resolve().parent
SWEEP = HERE.parent / "sweep.py"
ANALYZER = HERE.parent / "analyzer.py"
SAMPLE = HERE / "test_samples" / "sweep_portable.c"  # no cross-target libc dependency
JS_SAMPLE = HERE / "triage_samples" / "triage_js.js"
sys.path.insert(0, str(HERE.parent.parent))
sweep = importlib.import_module("ct_analyzer.sweep")


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
        self.assertEqual(summary["configurations"][0]["status"], "INCOMPLETE")
        self.assertEqual(summary["configurations"][0]["total_functions"], 0)
        self.assertEqual(proc.returncode, 2)

    def test_actual_compiler_flag_forwarding_matches_direct(self):
        out = self.tmp / "flags"
        proc = run(
            "--warnings",
            "--archs",
            "arm64",
            "--levels",
            "O0",
            "--out",
            out,
            "--extra-flags=-DNDEBUG",
            "--extra-flags=-fno-inline",
            SAMPLE,
        )
        self.assertEqual(proc.returncode, 1, proc.stderr)
        payload = json.loads((out / f"{SAMPLE.name}.arm64.O0.json").read_text())
        self.assertEqual(
            payload,
            direct(
                "--warnings",
                "--arch",
                "arm64",
                "--opt-level",
                "O0",
                "--extra-flags=-DNDEBUG",
                "--extra-flags=-fno-inline",
                SAMPLE,
            ),
        )

    def test_failed_rerun_cannot_overwrite_previous_reports(self):
        out = self.tmp / "reuse"
        first = run("--archs", "arm64", "--levels", "O0", "--out", out, SAMPLE)
        self.assertEqual(first.returncode, 1)
        before = {path.name: path.read_bytes() for path in out.iterdir()}
        second = run(
            "--archs", "arm64", "--levels", "O0", "--compiler", "missing-tool", "--out", out, SAMPLE
        )
        self.assertEqual(second.returncode, 2)
        self.assertIn("not empty", second.stderr)
        self.assertEqual(before, {path.name: path.read_bytes() for path in out.iterdir()})

    def test_optimized_away_function_is_incomplete(self):
        source = self.tmp / "private.c"
        source.write_text("static int hidden(int x) { return x / 3; }\n")
        result = run(
            "--archs", "arm64", "--levels", "O2", "--out", self.tmp / "empty", "--json", source
        )
        self.assertEqual(result.returncode, 2)
        self.assertEqual(json.loads(result.stdout)["configurations"][0]["status"], "INCOMPLETE")

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
            self.assertIn(proc.returncode, (0, 1), proc.stderr + proc.stdout)
            payload = json.loads((Path(t) / f"{JS_SAMPLE.name}.default.json").read_text())
            self.assertGreater(payload["total_functions"], 0)
            self.assertGreater(payload["total_instructions"], 0)
            self.assertTrue(payload["violations"])
            self.assertEqual(payload, direct("--warnings", JS_SAMPLE))

    def test_invalid_matrix_regex_and_unknown_extension(self):
        with tempfile.TemporaryDirectory() as t:
            root = Path(t)
            for args in [
                ("--levels", "O9"),
                ("--archs", "../escape"),
                ("--func", "["),
                ("--jobs", "0"),
            ]:
                proc = run(*args, "--out", root / "out", SAMPLE)
                self.assertEqual(proc.returncode, 2)
                self.assertNotIn("Traceback", proc.stderr)
            unknown = root / "source.hh"
            unknown.write_text("int f(int x) { return x; }\n")
            proc = run(unknown, "--out", root / "out")
            self.assertEqual(proc.returncode, 2)
            self.assertIn("unsupported source extension", proc.stderr)

    def test_output_file_instead_of_directory_is_a_clean_error(self):
        with tempfile.TemporaryDirectory() as t:
            output = Path(t) / "report"
            output.write_text("keep me")
            proc = run("--out", output, SAMPLE)
            self.assertEqual(proc.returncode, 2)
            self.assertNotIn("Traceback", proc.stderr)
            self.assertEqual(output.read_text(), "keep me")


class TestNativeAliases(unittest.TestCase):
    def compare_aliases(self, extension, contents, compiler):
        with tempfile.TemporaryDirectory() as t:
            root = Path(t)
            source = root / f"example.{extension}"
            source.write_text(contents)
            out = root / "out"
            proc = run(
                "--warnings",
                "--archs",
                "arm64",
                "--levels",
                "O1,O2",
                "--compiler",
                compiler,
                "--out",
                out,
                "--json",
                source,
            )
            self.assertIn(proc.returncode, (0, 1), proc.stdout + proc.stderr)
            summary = json.loads(proc.stdout)
            self.assertEqual(summary["executions"], 1)
            for level in ("O1", "O2"):
                actual = json.loads((out / f"{source.name}.arm64.{level}.json").read_text())
                expected = direct(
                    "--warnings",
                    "--arch",
                    "arm64",
                    "--opt-level",
                    level,
                    "--compiler",
                    compiler,
                    source,
                )
                self.assertGreater(actual["total_functions"], 0)
                self.assertEqual(actual, expected)

    @unittest.skipUnless(shutil.which("go"), "go required")
    def test_go_alias_payloads_equal_direct_runs(self):
        self.compare_aliases(
            "go",
            """package main
//go:noinline
func divide(a, b int) int { return a / b }
func main() { println(divide(5, 2)) }
""",
            "go",
        )

    @unittest.skipUnless(
        shutil.which("swiftc") and sys.platform == "darwin", "Apple Swift arm64 toolchain required"
    )
    def test_swift_alias_payloads_equal_direct_runs(self):
        self.compare_aliases(
            "swift", "public func divide(_ a: Int, _ b: Int) -> Int { a / b }\n", "swiftc"
        )


def clean_payload(**changes):
    return dict(
        {
            "total_functions": 1,
            "total_instructions": 4,
            "error_count": 0,
            "warning_count": 0,
            "passed": True,
            "violations": [],
            "optimization": "O0",
        },
        **changes,
    )


class TestProcessContract(unittest.TestCase):
    def args(self, **changes):
        from argparse import Namespace

        return Namespace(
            **dict(
                {
                    "source_file": SAMPLE,
                    "warnings": True,
                    "compiler": None,
                    "func": None,
                    "extra_flags": [],
                },
                **changes,
            )
        )

    def fake_run(self, payload, stderr="", code=0, **changes):
        fake = subprocess.CompletedProcess([], code, json.dumps(payload), stderr)
        with patch.object(sweep.subprocess, "run", return_value=fake) as call:
            result = sweep.run_one(self.args(**changes), "arm64", "O0")
        return result, call

    def test_degradation_and_nonzero_exit_are_retained(self):
        warning = "Note: C# compilation failed, using source analysis only"
        result, _ = self.fake_run(clean_payload(), warning)
        self.assertEqual(sweep.status(result), "INCOMPLETE")
        self.assertEqual(result["stderr"], warning)
        self.assertEqual(json.loads(result["stdout"]), clean_payload())
        result, _ = self.fake_run(clean_payload(), "compiler failure\nactual cause", code=7)
        self.assertEqual(sweep.status(result), "ERROR")
        self.assertEqual(result["exit_code"], 7)

    def test_benign_diagnostic_is_retained_without_false_incompleteness(self):
        result, _ = self.fake_run(clean_payload(), "Note: using OPcache debug output")
        self.assertEqual(sweep.status(result), "PASSED")
        self.assertTrue(result["stderr"])

    def test_zero_functions_or_instructions_are_incomplete(self):
        for field in ("total_functions", "total_instructions"):
            result, _ = self.fake_run(clean_payload(**{field: 0}))
            self.assertEqual(sweep.status(result), "INCOMPLETE")

    def test_invalid_json_keeps_the_full_error_not_just_usage(self):
        fake = subprocess.CompletedProcess([], 2, "", "usage: analyzer\nactual cause at end")
        with patch.object(sweep.subprocess, "run", return_value=fake):
            result = sweep.run_one(self.args(), "arm64", "O0")
        self.assertEqual(sweep.status(result), "ERROR")
        self.assertIn("actual cause at end", result["payload"]["error"])

    def test_repeated_and_space_containing_flags_are_single_values(self):
        flags = ["-DNDEBUG", '-DNAME="two words"', "-I/path with spaces"]
        _, call = self.fake_run(clean_payload(), extra_flags=flags)
        command = call.call_args.args[0]
        for flag in flags:
            self.assertIn("--extra-flags=" + flag, command)

    def test_malformed_payloads_never_pass(self):
        for payload in [
            [],
            {},
            {"passed": True},
            clean_payload(total_functions="1"),
            clean_payload(violations=[{}]),
            clean_payload(error_count=1),
        ]:
            result, _ = self.fake_run(payload)
            self.assertEqual(sweep.status(result), "ERROR", payload)

    def test_subprocess_launch_failure_is_reported(self):
        with patch.object(sweep.subprocess, "run", side_effect=OSError("cannot launch")):
            result = sweep.run_one(self.args(), "arm64", "O0")
        self.assertEqual(sweep.status(result), "ERROR")
        self.assertIn("cannot launch", result["stderr"])

    def test_distinct_architecture_reasons_are_not_merged(self):
        results = []
        for arch, reason in [("x86_64", "reason x86"), ("arm64", "reason arm")]:
            finding = {
                "function": "f",
                "mnemonic": "DIV",
                "severity": "error",
                "line": 4,
                "reason": reason,
            }
            results.append({"arch": arch, "level": "O0", "payload": {"violations": [finding]}})
        merged = sweep.merge(results)
        self.assertEqual({item["reason"] for item in merged}, {"reason x86", "reason arm"})
        self.assertEqual(len(merged), 2)

    def test_language_aliases_keep_every_requested_configuration(self):
        for language, expected in [("go", 2), ("swift", 3), ("c", 6)]:
            with tempfile.TemporaryDirectory() as t:
                source = Path(t) / f"source.{language}"
                source.touch()
                output = Path(t) / "out"

                def fake(args, arch, level):
                    return {
                        "arch": arch,
                        "level": level,
                        "payload": clean_payload(optimization=level),
                        "exit_code": 0,
                        "stdout": "{}",
                        "stderr": "",
                    }

                with (
                    patch.object(sweep, "run_one", side_effect=fake) as call,
                    patch.object(
                        sys,
                        "argv",
                        ["sweep", str(source), "--archs", "arm64", "--out", str(output)],
                    ),
                ):
                    self.assertEqual(sweep.main(), 0)
                summary = json.loads((output / f"{source.name}.sweep.json").read_text())
                self.assertEqual(call.call_count, expected)
                self.assertEqual(summary["executions"], expected)
                self.assertEqual(len(summary["configurations"]), 6)
                for config in summary["configurations"]:
                    payload = json.loads(Path(config["payload"]).read_text())
                    self.assertEqual(payload["optimization"], config["config"].split("/")[1])

    def test_unknown_extension_matches_shared_detector(self):
        self.assertEqual(sweep.detect_language("x.mjs"), "javascript")
        self.assertEqual(sweep.detect_language("x.hh"), "unknown")

    def test_payload_write_failure_returns_nonzero_not_traceback(self):
        with tempfile.TemporaryDirectory() as t:
            source = Path(t) / "x.c"
            source.touch()
            output = Path(t) / "out"
            original_open = Path.open

            def failing(path, *args, **kwargs):
                if path.suffix == ".json":
                    raise OSError("disk full")
                return original_open(path, *args, **kwargs)

            result = {
                "arch": "arm64",
                "level": "O0",
                "payload": clean_payload(),
                "exit_code": 0,
                "stdout": "{}",
                "stderr": "",
            }
            with (
                patch.object(Path, "open", failing),
                patch.object(sweep, "run_one", return_value=result),
                patch.object(
                    sys,
                    "argv",
                    [
                        "sweep",
                        str(source),
                        "--archs",
                        "arm64",
                        "--levels",
                        "O0",
                        "--out",
                        str(output),
                    ],
                ),
            ):
                self.assertEqual(sweep.main(), 2)


if __name__ == "__main__":
    unittest.main()
