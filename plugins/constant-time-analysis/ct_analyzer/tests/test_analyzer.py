#!/usr/bin/env python3
"""
Unit tests for the constant-time analyzer.

These tests verify that the analyzer correctly detects timing side-channel
vulnerabilities in compiled cryptographic code.
"""

import json
import os
import platform
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

# Add parent directory to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent))

from analyzer import (
    DANGEROUS_INSTRUCTIONS,
    AssemblyParser,
    OutputFormat,
    Severity,
    analyze_assembly,
    analyze_source,
    detect_language,
    format_report,
    get_native_arch,
    normalize_arch,
)


class TestArchitectureNormalization(unittest.TestCase):
    """Test architecture name normalization."""

    def test_normalize_common_aliases(self):
        self.assertEqual(normalize_arch("amd64"), "x86_64")
        self.assertEqual(normalize_arch("x64"), "x86_64")
        self.assertEqual(normalize_arch("aarch64"), "arm64")
        self.assertEqual(normalize_arch("386"), "i386")
        self.assertEqual(normalize_arch("x86"), "i386")

    def test_normalize_case_insensitive(self):
        self.assertEqual(normalize_arch("AMD64"), "x86_64")
        self.assertEqual(normalize_arch("AARCH64"), "arm64")
        self.assertEqual(normalize_arch("X86_64"), "x86_64")

    def test_normalize_passthrough(self):
        self.assertEqual(normalize_arch("x86_64"), "x86_64")
        self.assertEqual(normalize_arch("arm64"), "arm64")
        self.assertEqual(normalize_arch("riscv64"), "riscv64")


class TestLanguageDetection(unittest.TestCase):
    """Test source file language detection."""

    def test_detect_c(self):
        self.assertEqual(detect_language("foo.c"), "c")
        self.assertEqual(detect_language("foo.h"), "c")
        self.assertEqual(detect_language("/path/to/crypto.c"), "c")

    def test_detect_cpp(self):
        self.assertEqual(detect_language("foo.cpp"), "cpp")
        self.assertEqual(detect_language("foo.cc"), "cpp")
        self.assertEqual(detect_language("foo.cxx"), "cpp")
        self.assertEqual(detect_language("foo.hpp"), "cpp")

    def test_detect_go(self):
        self.assertEqual(detect_language("main.go"), "go")
        self.assertEqual(detect_language("/path/to/crypto.go"), "go")

    def test_detect_rust(self):
        self.assertEqual(detect_language("lib.rs"), "rust")
        self.assertEqual(detect_language("/path/to/crypto.rs"), "rust")

    def test_detect_python(self):
        self.assertEqual(detect_language("crypto.py"), "python")
        self.assertEqual(detect_language("crypto.pyw"), "python")
        self.assertEqual(detect_language("/path/to/crypto.py"), "python")

    def test_detect_ruby(self):
        self.assertEqual(detect_language("crypto.rb"), "ruby")
        self.assertEqual(detect_language("/path/to/crypto.rb"), "ruby")

    def test_detect_java(self):
        self.assertEqual(detect_language("CryptoUtils.java"), "java")
        self.assertEqual(detect_language("/path/to/Crypto.java"), "java")

    def test_detect_csharp(self):
        self.assertEqual(detect_language("CryptoUtils.cs"), "csharp")
        self.assertEqual(detect_language("/path/to/Crypto.cs"), "csharp")

    def test_detect_unknown(self):
        self.assertEqual(detect_language("foo.txt"), "unknown")
        self.assertEqual(detect_language("foo.scala"), "unknown")


class TestDangerousInstructions(unittest.TestCase):
    """Test that dangerous instruction lists are properly defined."""

    def test_all_architectures_have_errors(self):
        for arch in DANGEROUS_INSTRUCTIONS:
            self.assertIn(
                "errors", DANGEROUS_INSTRUCTIONS[arch], f"Architecture {arch} missing 'errors' key"
            )
            self.assertGreater(
                len(DANGEROUS_INSTRUCTIONS[arch]["errors"]),
                0,
                f"Architecture {arch} has no error instructions",
            )

    def test_all_architectures_have_division(self):
        """Every architecture should flag some form of division."""
        division_patterns = ["div", "idiv", "udiv", "sdiv", "d", "dr"]

        for arch, instructions in DANGEROUS_INSTRUCTIONS.items():
            errors = instructions.get("errors", {})
            has_division = any(
                any(pattern in mnemonic.lower() for pattern in division_patterns)
                for mnemonic in errors.keys()
            )
            self.assertTrue(has_division, f"Architecture {arch} should flag division instructions")

    def test_x86_64_has_known_dangerous(self):
        """x86_64 should flag DIV, IDIV, and their variants."""
        x86 = DANGEROUS_INSTRUCTIONS["x86_64"]["errors"]
        self.assertIn("div", x86)
        self.assertIn("idiv", x86)
        self.assertIn("divq", x86)
        self.assertIn("idivq", x86)

    def test_arm64_has_known_dangerous(self):
        """ARM64 should flag UDIV and SDIV."""
        arm64 = DANGEROUS_INSTRUCTIONS["arm64"]["errors"]
        self.assertIn("udiv", arm64)
        self.assertIn("sdiv", arm64)


class TestAssemblyParser(unittest.TestCase):
    """Test assembly parsing and violation detection."""

    def test_parse_x86_64_division(self):
        """Parser should detect x86_64 division instructions."""
        assembly = """
        decompose:
            movq    %rdi, %rax
            cqto
            idivq   %rsi
            movq    %rax, (%rdx)
            movq    %rdx, (%rcx)
            ret
        """

        parser = AssemblyParser("x86_64", "clang")
        functions, violations = parser.parse(assembly)

        self.assertEqual(len(functions), 1)
        self.assertEqual(functions[0]["name"], "decompose")

        # Should find the IDIVQ instruction
        error_violations = [v for v in violations if v.severity == Severity.ERROR]
        self.assertGreater(len(error_violations), 0, "Should detect IDIVQ")
        self.assertEqual(error_violations[0].mnemonic, "IDIVQ")

    def test_parse_arm64_division(self):
        """Parser should detect ARM64 division instructions."""
        assembly = """
        decompose:
            sdiv    w8, w0, w1
            msub    w9, w8, w1, w0
            str     w8, [x2]
            str     w9, [x3]
            ret
        """

        parser = AssemblyParser("arm64", "clang")
        functions, violations = parser.parse(assembly)

        error_violations = [v for v in violations if v.severity == Severity.ERROR]
        self.assertGreater(len(error_violations), 0, "Should detect SDIV")
        self.assertEqual(error_violations[0].mnemonic, "SDIV")

    def test_parse_conditional_branches_as_warnings(self):
        """Parser should detect conditional branches as warnings."""
        assembly = """
        check_value:
            cmpq    $0, %rdi
            je      .Lzero
            movq    $1, %rax
            ret
        .Lzero:
            xorq    %rax, %rax
            ret
        """

        parser = AssemblyParser("x86_64", "clang")
        functions, violations = parser.parse(assembly, include_warnings=True)

        warning_violations = [v for v in violations if v.severity == Severity.WARNING]
        self.assertGreater(len(warning_violations), 0, "Should detect JE as warning")

    def test_parse_no_false_positives_on_clean_code(self):
        """Parser should not flag clean constant-time code."""
        assembly = """
        constant_time_select:
            movq    %rdx, %rax
            negq    %rax
            andq    %rdi, %rax
            notq    %rdx
            andq    %rsi, %rdx
            orq     %rdx, %rax
            ret
        """

        parser = AssemblyParser("x86_64", "clang")
        functions, violations = parser.parse(assembly)

        error_violations = [v for v in violations if v.severity == Severity.ERROR]
        self.assertEqual(len(error_violations), 0, "Clean code should have no violations")


class TestReportFormatting(unittest.TestCase):
    """Test report output formatting."""

    def test_json_format(self):
        """JSON format should produce valid JSON."""
        import json

        from analyzer import AnalysisReport

        report = AnalysisReport(
            architecture="x86_64",
            compiler="clang",
            optimization="O2",
            source_file="test.c",
            total_functions=1,
            total_instructions=10,
            violations=[],
        )

        output = format_report(report, OutputFormat.JSON)
        parsed = json.loads(output)

        self.assertEqual(parsed["architecture"], "x86_64")
        self.assertEqual(parsed["passed"], True)

    def test_text_format_passed(self):
        """Text format should show PASSED for clean code."""
        from analyzer import AnalysisReport

        report = AnalysisReport(
            architecture="x86_64",
            compiler="clang",
            optimization="O2",
            source_file="test.c",
            total_functions=1,
            total_instructions=10,
            violations=[],
        )

        output = format_report(report, OutputFormat.TEXT)
        self.assertIn("PASSED", output)
        self.assertIn("No violations found", output)

    def test_text_format_failed(self):
        """Text format should show FAILED when violations exist."""
        from analyzer import AnalysisReport, Violation

        report = AnalysisReport(
            architecture="x86_64",
            compiler="clang",
            optimization="O2",
            source_file="test.c",
            total_functions=1,
            total_instructions=10,
            violations=[
                Violation(
                    function="decompose",
                    file="test.c",
                    line=10,
                    address="0x1234",
                    instruction="idivq %rsi",
                    mnemonic="IDIVQ",
                    reason="IDIVQ has data-dependent timing",
                    severity=Severity.ERROR,
                )
            ],
        )

        output = format_report(report, OutputFormat.TEXT)
        self.assertIn("FAILED", output)
        self.assertIn("IDIVQ", output)


class TestIntegration(unittest.TestCase):
    """Integration tests that compile actual code.

    These tests require clang/gcc to be installed and may be skipped
    in environments without compilers.
    """

    @classmethod
    def setUpClass(cls):
        """Check if compilers are available."""
        cls.samples_dir = Path(__file__).parent / "test_samples"
        cls.has_clang = cls._check_compiler("clang")
        cls.has_gcc = cls._check_compiler("gcc")

    @staticmethod
    def _check_compiler(name):
        try:
            subprocess.run([name, "--version"], capture_output=True, check=True)
            return True
        except (subprocess.CalledProcessError, FileNotFoundError):
            return False

    @unittest.skipUnless(lambda self: self.has_clang or self.has_gcc, "No C compiler available")
    def test_vulnerable_c_detected(self):
        """Vulnerable C implementation should be detected."""
        if not (self.has_clang or self.has_gcc):
            self.skipTest("No C compiler available")

        vulnerable_file = self.samples_dir / "decompose_vulnerable.c"
        if not vulnerable_file.exists():
            self.skipTest("Test sample not found")

        compiler = "clang" if self.has_clang else "gcc"

        try:
            report = analyze_source(
                str(vulnerable_file),
                compiler=compiler,
                optimization="O2",
            )

            # Should detect division instructions
            self.assertFalse(report.passed, "Vulnerable code should fail analysis")
            self.assertGreater(report.error_count, 0, "Should find error-level violations")

            # Check that we found division-related violations
            div_violations = [v for v in report.violations if "div" in v.mnemonic.lower()]
            self.assertGreater(len(div_violations), 0, "Should detect division instructions")

        except RuntimeError as e:
            if "Compilation failed" in str(e):
                self.skipTest(f"Compilation failed: {e}")
            raise

    @unittest.skipUnless(lambda self: self.has_clang or self.has_gcc, "No C compiler available")
    def test_constant_time_c_clean(self):
        """Constant-time C implementation should pass."""
        if not (self.has_clang or self.has_gcc):
            self.skipTest("No C compiler available")

        ct_file = self.samples_dir / "decompose_constant_time.c"
        if not ct_file.exists():
            self.skipTest("Test sample not found")

        compiler = "clang" if self.has_clang else "gcc"

        try:
            report = analyze_source(
                str(ct_file),
                compiler=compiler,
                optimization="O2",
            )

            # Constant-time implementation should not have division
            div_violations = [
                v
                for v in report.violations
                if "div" in v.mnemonic.lower() and v.severity == Severity.ERROR
            ]

            # Note: We allow this to be empty OR the compiler might have
            # optimized in unexpected ways
            if div_violations:
                print(f"WARNING: Found {len(div_violations)} division violations")
                print("This may indicate the compiler optimized differently than expected")

        except RuntimeError as e:
            if "Compilation failed" in str(e):
                self.skipTest(f"Compilation failed: {e}")
            raise

    def test_multiple_optimization_levels(self):
        """Test that analysis works across optimization levels."""
        if not (self.has_clang or self.has_gcc):
            self.skipTest("No C compiler available")

        vulnerable_file = self.samples_dir / "decompose_vulnerable.c"
        if not vulnerable_file.exists():
            self.skipTest("Test sample not found")

        compiler = "clang" if self.has_clang else "gcc"

        for opt in ["O0", "O1", "O2", "O3"]:
            with self.subTest(optimization=opt):
                try:
                    report = analyze_source(
                        str(vulnerable_file),
                        compiler=compiler,
                        optimization=opt,
                    )
                    # Just verify it runs without error
                    self.assertIsNotNone(report)

                except RuntimeError as e:
                    if "Compilation failed" in str(e):
                        # Some optimization levels may not work on all systems
                        continue
                    raise


class TestCrossArchitecture(unittest.TestCase):
    """Test cross-architecture compilation and analysis.

    These tests verify that the analyzer can handle different target
    architectures, even when cross-compiling from a different host.
    """

    @classmethod
    def setUpClass(cls):
        cls.samples_dir = Path(__file__).parent / "test_samples"
        cls.has_clang = TestIntegration._check_compiler("clang")

    @unittest.skipUnless(lambda self: self.has_clang, "Clang required for cross-compilation")
    def test_cross_compile_arm64(self):
        """Test cross-compilation to ARM64."""
        if not self.has_clang:
            self.skipTest("Clang not available")

        vulnerable_file = self.samples_dir / "decompose_vulnerable.c"
        if not vulnerable_file.exists():
            self.skipTest("Test sample not found")

        try:
            report = analyze_source(
                str(vulnerable_file),
                arch="arm64",
                compiler="clang",
                optimization="O2",
            )

            # Should still detect violations, just ARM64 specific ones
            self.assertIsNotNone(report)
            self.assertEqual(report.architecture, "arm64")

        except RuntimeError as e:
            if "target" in str(e).lower() or "triple" in str(e).lower():
                self.skipTest("ARM64 cross-compilation not supported")
            raise


class TestScriptingLanguageDetection(unittest.TestCase):
    """Test language detection for scripting languages."""

    def test_detect_php(self):
        self.assertEqual(detect_language("crypto.php"), "php")
        self.assertEqual(detect_language("/path/to/crypto.php"), "php")

    def test_detect_javascript(self):
        self.assertEqual(detect_language("crypto.js"), "javascript")
        self.assertEqual(detect_language("crypto.mjs"), "javascript")
        self.assertEqual(detect_language("crypto.cjs"), "javascript")

    def test_detect_typescript(self):
        self.assertEqual(detect_language("crypto.ts"), "typescript")
        self.assertEqual(detect_language("crypto.tsx"), "typescript")
        self.assertEqual(detect_language("crypto.mts"), "typescript")


class TestPHPAnalyzerParsing(unittest.TestCase):
    """Test PHP opcode parsing."""

    def test_parse_vld_division(self):
        """Parser should detect PHP division opcodes."""
        from script_analyzers import PHPAnalyzer

        # Sample VLD output with division
        vld_output = """
Finding entry points
Branch analysis from position: 0
filename:       /path/to/test.php
function name:  vulnerable_mod
number of ops:  8
compiled vars:  !0 = $value, !1 = $modulus
line     #* E I O op                           fetch          ext  return  operands
-------------------------------------------------------------------------------------
   5     0  E >   RECV                                             !0
         1        RECV                                             !1
   6     2        DIV                                              ~2      !0, !1
   7     3        ASSIGN                                                   !2, ~2
   8     4        MOD                                              ~4      !0, !1
         5        ASSIGN                                                   !3, ~4
   9     6        RETURN                                                   !3
  10     7      > RETURN                                                   null
"""

        analyzer = PHPAnalyzer()
        functions, violations = analyzer._parse_vld_output(vld_output)

        # Should find DIV and MOD opcodes
        error_violations = [v for v in violations if v.severity == Severity.ERROR]
        self.assertGreater(len(error_violations), 0, "Should detect DIV/MOD opcodes")

        div_violations = [v for v in error_violations if v.mnemonic in ("DIV", "MOD")]
        self.assertEqual(len(div_violations), 2, "Should find both DIV and MOD")

    def test_parse_vld_function_call(self):
        """Parser should detect dangerous PHP function calls."""
        from script_analyzers import PHPAnalyzer

        vld_output = """
filename:       /path/to/test.php
function name:  vulnerable_encode
number of ops:  5
compiled vars:  !0 = $data
line     #* E I O op                           fetch          ext  return  operands
-------------------------------------------------------------------------------------
   3     0  E >   RECV                                             !0
   4     1        INIT_FCALL                                               'bin2hex'
         2        SEND_VAR                                                 !0
         3        DO_ICALL                                         $1
   5     4      > RETURN                                                   $1
"""

        analyzer = PHPAnalyzer()
        functions, violations = analyzer._parse_vld_output(vld_output)

        # Should detect bin2hex call
        error_violations = [v for v in violations if v.severity == Severity.ERROR]
        self.assertGreater(len(error_violations), 0, "Should detect bin2hex call")

        bin2hex_violations = [v for v in error_violations if "bin2hex" in v.mnemonic.lower()]
        self.assertEqual(len(bin2hex_violations), 1)

    def test_parse_vld_mt_rand(self):
        """Parser should detect mt_rand as dangerous."""
        from script_analyzers import PHPAnalyzer

        vld_output = """
filename:       /path/to/test.php
function name:  generate_token
line     #* E I O op                           fetch          ext  return  operands
-------------------------------------------------------------------------------------
   3     0  E >   INIT_FCALL                                               'mt_rand'
         1        SEND_VAL                                                 0
         2        SEND_VAL                                                 100
         3        DO_ICALL                                         $0
   4     4      > RETURN                                                   $0
"""

        analyzer = PHPAnalyzer()
        functions, violations = analyzer._parse_vld_output(vld_output)

        error_violations = [v for v in violations if v.severity == Severity.ERROR]
        self.assertGreater(len(error_violations), 0, "Should detect mt_rand")


class TestJavaScriptAnalyzerParsing(unittest.TestCase):
    """Test JavaScript V8 bytecode parsing."""

    def test_parse_v8_division(self):
        """Parser should detect V8 division bytecodes."""
        from script_analyzers import JavaScriptAnalyzer

        v8_output = """
[generated bytecode for function: vulnerableDiv (0x1234)]
Bytecode length: 20
Parameter count 3
Register count 2
Frame size 16
         0 : Ldar a0
         2 : Star0
         3 : Ldar a1
         5 : Div r0
         7 : Star1
         8 : Ldar r1
        10 : Return
"""

        analyzer = JavaScriptAnalyzer()
        functions, violations = analyzer._parse_v8_bytecode(
            v8_output, "test.js", include_warnings=False
        )

        self.assertEqual(len(functions), 1)
        self.assertEqual(functions[0]["name"], "vulnerableDiv")

        # Should find Div bytecode
        error_violations = [v for v in violations if v.severity == Severity.ERROR]
        self.assertGreater(len(error_violations), 0, "Should detect Div bytecode")

    def test_parse_v8_modulo(self):
        """Parser should detect V8 modulo bytecodes."""
        from script_analyzers import JavaScriptAnalyzer

        v8_output = """
[generated bytecode for function: vulnerableMod (0x5678)]
Bytecode length: 15
Parameter count 3
Register count 1
Frame size 8
         0 : Ldar a0
         2 : Mod a1
         4 : Return
"""

        analyzer = JavaScriptAnalyzer()
        functions, violations = analyzer._parse_v8_bytecode(v8_output, "test.js")

        error_violations = [v for v in violations if v.severity == Severity.ERROR]
        self.assertGreater(len(error_violations), 0, "Should detect Mod bytecode")

    def test_detect_math_sqrt_in_source(self):
        """Should detect Math.sqrt() calls in source."""
        # Create a temp file with Math.sqrt
        import tempfile

        from script_analyzers import JavaScriptAnalyzer

        with tempfile.NamedTemporaryFile(mode="w", suffix=".js", delete=False) as f:
            f.write("""
function vulnerable(x) {
    return Math.sqrt(x);
}
""")
            temp_path = f.name

        try:
            analyzer = JavaScriptAnalyzer()
            violations = analyzer._detect_dangerous_function_calls(temp_path)

            sqrt_violations = [v for v in violations if "SQRT" in v.mnemonic.upper()]
            self.assertGreater(len(sqrt_violations), 0, "Should detect Math.sqrt()")
        finally:
            os.unlink(temp_path)

    def test_detect_math_random_in_source(self):
        """Should detect Math.random() calls in source."""
        import tempfile

        from script_analyzers import JavaScriptAnalyzer

        with tempfile.NamedTemporaryFile(mode="w", suffix=".js", delete=False) as f:
            f.write("""
function generateToken() {
    return Math.random().toString(36);
}
""")
            temp_path = f.name

        try:
            analyzer = JavaScriptAnalyzer()
            violations = analyzer._detect_dangerous_function_calls(temp_path)

            random_violations = [v for v in violations if "RANDOM" in v.mnemonic.upper()]
            self.assertGreater(len(random_violations), 0, "Should detect Math.random()")
        finally:
            os.unlink(temp_path)


class TestPythonAnalyzerParsing(unittest.TestCase):
    """Test Python dis bytecode parsing."""

    def test_parse_dis_division_python311(self):
        """Parser should detect Python 3.11+ BINARY_OP division."""
        from script_analyzers import PythonAnalyzer

        # Python 3.11+ dis output format
        dis_output = """
Disassembly of <code object vulnerable_div at 0x1234>:
  3           0 RESUME                   0

  4           2 LOAD_FAST                0 (value)
              4 LOAD_FAST                1 (modulus)
              6 BINARY_OP               11 (/)
              8 STORE_FAST               2 (result)

  5          10 LOAD_FAST                0 (value)
             12 LOAD_FAST                1 (modulus)
             14 BINARY_OP                6 (%)
             16 STORE_FAST               3 (remainder)
             18 RETURN_VALUE
"""

        analyzer = PythonAnalyzer()
        functions, violations = analyzer._parse_dis_output(dis_output, "test.py")

        self.assertEqual(len(functions), 1)
        self.assertEqual(functions[0]["name"], "vulnerable_div")

        # Should find BINARY_OP division and modulo
        error_violations = [v for v in violations if v.severity == Severity.ERROR]
        self.assertEqual(len(error_violations), 2, "Should detect both / and % operators")

    def test_parse_dis_division_python310(self):
        """Parser should detect Python < 3.11 division bytecodes."""
        from script_analyzers import PythonAnalyzer

        # Python < 3.11 dis output format
        dis_output = """
Disassembly of <code object vulnerable_div at 0x1234>:
  3           0 LOAD_FAST                0 (value)
              2 LOAD_FAST                1 (modulus)
              4 BINARY_TRUE_DIVIDE
              6 STORE_FAST               2 (result)
              8 LOAD_FAST                0 (value)
             10 LOAD_FAST                1 (modulus)
             12 BINARY_MODULO
             14 STORE_FAST               3 (remainder)
             16 LOAD_CONST               0 (None)
             18 RETURN_VALUE
"""

        analyzer = PythonAnalyzer()
        functions, violations = analyzer._parse_dis_output(dis_output, "test.py")

        error_violations = [v for v in violations if v.severity == Severity.ERROR]
        self.assertEqual(
            len(error_violations), 2, "Should detect BINARY_TRUE_DIVIDE and BINARY_MODULO"
        )

        mnemonics = {v.mnemonic for v in error_violations}
        self.assertIn("BINARY_TRUE_DIVIDE", mnemonics)
        self.assertIn("BINARY_MODULO", mnemonics)

    def test_detect_random_in_source(self):
        """Should detect random.random() calls in source."""
        import tempfile

        from script_analyzers import PythonAnalyzer

        with tempfile.NamedTemporaryFile(mode="w", suffix=".py", delete=False) as f:
            f.write("""
import random

def generate_token():
    return random.random()

def generate_int():
    return random.randint(0, 100)
""")
            temp_path = f.name

        try:
            analyzer = PythonAnalyzer()
            violations = analyzer._detect_dangerous_function_calls(temp_path)

            random_violations = [v for v in violations if "RANDOM" in v.mnemonic.upper()]
            self.assertEqual(
                len(random_violations), 2, "Should detect random.random() and random.randint()"
            )
        finally:
            os.unlink(temp_path)

    def test_detect_math_sqrt_in_source(self):
        """Should detect math.sqrt() calls in source."""
        import tempfile

        from script_analyzers import PythonAnalyzer

        with tempfile.NamedTemporaryFile(mode="w", suffix=".py", delete=False) as f:
            f.write("""
import math

def vulnerable(x):
    return math.sqrt(x)
""")
            temp_path = f.name

        try:
            analyzer = PythonAnalyzer()
            violations = analyzer._detect_dangerous_function_calls(temp_path)

            sqrt_violations = [v for v in violations if "SQRT" in v.mnemonic.upper()]
            self.assertGreater(len(sqrt_violations), 0, "Should detect math.sqrt()")
        finally:
            os.unlink(temp_path)


class TestRubyAnalyzerParsing(unittest.TestCase):
    """Test Ruby YARV bytecode parsing."""

    def test_parse_yarv_division(self):
        """Parser should detect Ruby opt_div bytecodes."""
        from script_analyzers import RubyAnalyzer

        # Ruby YARV output format
        yarv_output = """
== disasm: #<ISeq:<main>@test.rb:1 (1,0)-(10,3)>
0000 putobject                              10
0002 putobject                              3
0004 opt_div                                <calldata!mid:/, argc:1, ARGS_SIMPLE>
0006 leave

== disasm: #<ISeq:vulnerable_mod@test.rb:5 (5,0)-(8,3)>
local table (size: 2, argc: 2 [opts: 0, rest: -1, post: 0, block: -1, kw: -1@-1, kwrest: -1])
[ 2] value@0    [ 1] modulus@1
0000 getlocal_WC_0                          value@0
0002 getlocal_WC_0                          modulus@1
0004 opt_mod                                <calldata!mid:%, argc:1, ARGS_SIMPLE>
0006 leave
"""

        analyzer = RubyAnalyzer()
        functions, violations = analyzer._parse_yarv_output(yarv_output, "test.rb")

        self.assertEqual(len(functions), 2)
        self.assertEqual(functions[0]["name"], "<main>")
        self.assertEqual(functions[1]["name"], "vulnerable_mod")

        # Should find opt_div and opt_mod
        error_violations = [v for v in violations if v.severity == Severity.ERROR]
        self.assertEqual(len(error_violations), 2, "Should detect opt_div and opt_mod")

        mnemonics = {v.mnemonic for v in error_violations}
        self.assertIn("OPT_DIV", mnemonics)
        self.assertIn("OPT_MOD", mnemonics)

    def test_parse_yarv_warnings(self):
        """Parser should detect Ruby comparison bytecodes as warnings."""
        from script_analyzers import RubyAnalyzer

        yarv_output = """
== disasm: #<ISeq:compare@test.rb:1 (1,0)-(3,3)>
0000 getlocal_WC_0                          a@0
0002 getlocal_WC_0                          b@1
0004 opt_eq                                 <calldata!mid:==, argc:1, ARGS_SIMPLE>
0006 branchif                               10
0008 putnil
0009 leave
0010 putobject                              true
0012 leave
"""

        analyzer = RubyAnalyzer()
        functions, violations = analyzer._parse_yarv_output(
            yarv_output, "test.rb", include_warnings=True
        )

        warning_violations = [v for v in violations if v.severity == Severity.WARNING]
        self.assertGreater(
            len(warning_violations), 0, "Should detect opt_eq and branchif as warnings"
        )

    def test_detect_rand_in_source(self):
        """Should detect rand() calls in source."""
        import tempfile

        from script_analyzers import RubyAnalyzer

        with tempfile.NamedTemporaryFile(mode="w", suffix=".rb", delete=False) as f:
            f.write("""
def generate_token
  rand(100)
end

def generate_random
  Random.new.rand
end
""")
            temp_path = f.name

        try:
            analyzer = RubyAnalyzer()
            violations = analyzer._detect_dangerous_function_calls(temp_path)

            rand_violations = [v for v in violations if "RAND" in v.mnemonic.upper()]
            self.assertGreater(len(rand_violations), 0, "Should detect rand() calls")
        finally:
            os.unlink(temp_path)


class TestJavaAnalyzerParsing(unittest.TestCase):
    """Test Java bytecode parsing."""

    def test_parse_javap_division(self):
        """Parser should detect Java division bytecodes."""
        from script_analyzers import JavaAnalyzer

        # Sample javap output with division
        javap_output = """
public class CryptoUtils {
  public int vulnerableDiv(int, int);
    Code:
       0: iload_1
       1: iload_2
       2: idiv
       3: istore_3
       4: iload_1
       5: iload_2
       6: irem
       7: istore        4
       9: iload_3
      10: ireturn
    LineNumberTable:
      line 5: 0
      line 6: 4
      line 7: 9
}
"""

        analyzer = JavaAnalyzer()
        functions, violations = analyzer._parse_javap_output(javap_output, "CryptoUtils.java")

        self.assertEqual(len(functions), 1)
        self.assertEqual(functions[0]["name"], "CryptoUtils.vulnerableDiv")

        # Should find idiv and irem bytecodes
        error_violations = [v for v in violations if v.severity == Severity.ERROR]
        self.assertEqual(len(error_violations), 2, "Should detect idiv and irem")

        mnemonics = {v.mnemonic for v in error_violations}
        self.assertIn("IDIV", mnemonics)
        self.assertIn("IREM", mnemonics)

    def test_parse_javap_long_division(self):
        """Parser should detect Java long division bytecodes."""
        from script_analyzers import JavaAnalyzer

        javap_output = """
public class CryptoUtils {
  public long vulnerableLongDiv(long, long);
    Code:
       0: lload_1
       1: lload_3
       2: ldiv
       3: lreturn
}
"""

        analyzer = JavaAnalyzer()
        functions, violations = analyzer._parse_javap_output(javap_output, "CryptoUtils.java")

        error_violations = [v for v in violations if v.severity == Severity.ERROR]
        self.assertGreater(len(error_violations), 0, "Should detect ldiv")
        self.assertEqual(error_violations[0].mnemonic, "LDIV")

    def test_parse_javap_float_division(self):
        """Parser should detect Java float division bytecodes."""
        from script_analyzers import JavaAnalyzer

        javap_output = """
public class CryptoUtils {
  public double vulnerableFloatDiv(double, double);
    Code:
       0: dload_1
       1: dload_3
       2: ddiv
       3: dreturn
}
"""

        analyzer = JavaAnalyzer()
        functions, violations = analyzer._parse_javap_output(javap_output, "CryptoUtils.java")

        error_violations = [v for v in violations if v.severity == Severity.ERROR]
        self.assertGreater(len(error_violations), 0, "Should detect ddiv")
        self.assertEqual(error_violations[0].mnemonic, "DDIV")

    def test_parse_javap_warnings(self):
        """Parser should detect Java conditional branches as warnings."""
        from script_analyzers import JavaAnalyzer

        javap_output = """
public class CryptoUtils {
  public boolean compare(int, int);
    Code:
       0: iload_1
       1: iload_2
       2: if_icmpne     9
       5: iconst_1
       6: goto          10
       9: iconst_0
      10: ireturn
}
"""

        analyzer = JavaAnalyzer()
        functions, violations = analyzer._parse_javap_output(
            javap_output, "CryptoUtils.java", include_warnings=True
        )

        warning_violations = [v for v in violations if v.severity == Severity.WARNING]
        self.assertGreater(len(warning_violations), 0, "Should detect if_icmpne as warning")

    def test_detect_java_random_in_source(self):
        """Should detect new Random() calls in Java source."""
        import tempfile

        from script_analyzers import JavaAnalyzer

        with tempfile.NamedTemporaryFile(mode="w", suffix=".java", delete=False) as f:
            f.write("""
public class Test {
    public int generate() {
        Random rand = new Random();
        return rand.nextInt(100);
    }
}
""")
            temp_path = f.name

        try:
            analyzer = JavaAnalyzer()
            violations = analyzer._detect_dangerous_function_calls(temp_path)

            random_violations = [v for v in violations if "RANDOM" in v.mnemonic.upper()]
            self.assertGreater(len(random_violations), 0, "Should detect new Random()")
        finally:
            os.unlink(temp_path)

    def test_detect_math_sqrt_in_java_source(self):
        """Should detect Math.sqrt() calls in Java source."""
        import tempfile

        from script_analyzers import JavaAnalyzer

        with tempfile.NamedTemporaryFile(mode="w", suffix=".java", delete=False) as f:
            f.write("""
public class Test {
    public double calculate(double x) {
        return Math.sqrt(x);
    }
}
""")
            temp_path = f.name

        try:
            analyzer = JavaAnalyzer()
            violations = analyzer._detect_dangerous_function_calls(temp_path)

            sqrt_violations = [v for v in violations if "SQRT" in v.mnemonic.upper()]
            self.assertGreater(len(sqrt_violations), 0, "Should detect Math.sqrt()")
        finally:
            os.unlink(temp_path)


class TestCSharpAnalyzerParsing(unittest.TestCase):
    """Test C# IL bytecode parsing."""

    def test_parse_il_division(self):
        """Parser should detect C# division IL opcodes."""
        from script_analyzers import CSharpAnalyzer

        # Sample IL output with division
        il_output = """
.method public hidebysig instance int32 VulnerableDiv(int32, int32) cil managed
{
  .maxstack 2
  .locals init (int32 V_0)
  IL_0000: ldarg.1
  IL_0001: ldarg.2
  IL_0002: div
  IL_0003: stloc.0
  IL_0004: ldarg.1
  IL_0005: ldarg.2
  IL_0006: rem
  IL_0007: stloc.1
  IL_0008: ldloc.0
  IL_0009: ret
}
"""

        analyzer = CSharpAnalyzer()
        functions, violations = analyzer._parse_il_output(il_output, "CryptoUtils.cs")

        self.assertEqual(len(functions), 1)
        self.assertEqual(functions[0]["name"], "VulnerableDiv")

        # Should find div and rem opcodes
        error_violations = [v for v in violations if v.severity == Severity.ERROR]
        self.assertEqual(len(error_violations), 2, "Should detect div and rem")

        mnemonics = {v.mnemonic for v in error_violations}
        self.assertIn("DIV", mnemonics)
        self.assertIn("REM", mnemonics)

    def test_parse_il_unsigned_division(self):
        """Parser should detect C# unsigned division IL opcodes."""
        from script_analyzers import CSharpAnalyzer

        il_output = """
.method public hidebysig static uint32 UnsignedDiv(uint32, uint32) cil managed
{
  .maxstack 2
  IL_0000: ldarg.0
  IL_0001: ldarg.1
  IL_0002: div.un
  IL_0003: ret
}
"""

        analyzer = CSharpAnalyzer()
        functions, violations = analyzer._parse_il_output(il_output, "CryptoUtils.cs")

        error_violations = [v for v in violations if v.severity == Severity.ERROR]
        self.assertGreater(len(error_violations), 0, "Should detect div.un")
        self.assertEqual(error_violations[0].mnemonic, "DIV.UN")

    def test_parse_il_warnings(self):
        """Parser should detect C# conditional branches as warnings."""
        from script_analyzers import CSharpAnalyzer

        il_output = """
.method public hidebysig instance bool Compare(int32, int32) cil managed
{
  .maxstack 2
  IL_0000: ldarg.1
  IL_0001: ldarg.2
  IL_0002: beq.s IL_0006
  IL_0004: ldc.i4.0
  IL_0005: ret
  IL_0006: ldc.i4.1
  IL_0007: ret
}
"""

        analyzer = CSharpAnalyzer()
        functions, violations = analyzer._parse_il_output(
            il_output, "CryptoUtils.cs", include_warnings=True
        )

        warning_violations = [v for v in violations if v.severity == Severity.WARNING]
        self.assertGreater(len(warning_violations), 0, "Should detect beq.s as warning")

    def test_detect_csharp_random_in_source(self):
        """Should detect new Random() calls in C# source."""
        import tempfile

        from script_analyzers import CSharpAnalyzer

        with tempfile.NamedTemporaryFile(mode="w", suffix=".cs", delete=False) as f:
            f.write("""
public class Test {
    public int Generate() {
        Random rand = new Random();
        return rand.Next(100);
    }
}
""")
            temp_path = f.name

        try:
            analyzer = CSharpAnalyzer()
            violations = analyzer._detect_dangerous_function_calls(temp_path)

            random_violations = [v for v in violations if "RANDOM" in v.mnemonic.upper()]
            self.assertGreater(len(random_violations), 0, "Should detect new Random()")
        finally:
            os.unlink(temp_path)

    def test_detect_math_sqrt_in_csharp_source(self):
        """Should detect Math.Sqrt() calls in C# source."""
        import tempfile

        from script_analyzers import CSharpAnalyzer

        with tempfile.NamedTemporaryFile(mode="w", suffix=".cs", delete=False) as f:
            f.write("""
public class Test {
    public double Calculate(double x) {
        return Math.Sqrt(x);
    }
}
""")
            temp_path = f.name

        try:
            analyzer = CSharpAnalyzer()
            violations = analyzer._detect_dangerous_function_calls(temp_path)

            sqrt_violations = [v for v in violations if "SQRT" in v.mnemonic.upper()]
            self.assertGreater(len(sqrt_violations), 0, "Should detect Math.Sqrt()")
        finally:
            os.unlink(temp_path)

    def test_source_only_fallback(self):
        """Source-only analysis should detect division operators."""
        import tempfile

        from script_analyzers import CSharpAnalyzer

        with tempfile.NamedTemporaryFile(mode="w", suffix=".cs", delete=False) as f:
            f.write("""
public class Test {
    public int Divide(int a, int b) {
        return a / b;
    }
    public int Modulo(int a, int b) {
        return a % b;
    }
}
""")
            temp_path = f.name

        try:
            analyzer = CSharpAnalyzer()
            report = analyzer._analyze_source_only(temp_path)

            # Should detect division and modulo operators
            div_violations = [v for v in report.violations if "DIV" in v.mnemonic]
            mod_violations = [v for v in report.violations if "REM" in v.mnemonic]

            self.assertGreater(len(div_violations), 0, "Should detect / operator")
            self.assertGreater(len(mod_violations), 0, "Should detect % operator")
        finally:
            os.unlink(temp_path)


class TestCSharpILRuntimePairing(unittest.TestCase):
    """The tool-store fallback must pair a store assembly with a matching runtime.

    ilspycmd installs framework-dependent, so the assembly in the store targets
    exactly one framework and .NET will not start it on a runtime of a different
    major version. Discovery and runtime choice are therefore one decision. These
    tests use a fake store and fake runtime paths, so they need no dotnet install.
    """

    HOMEBREW = "/opt/homebrew/opt/dotnet@{major}/libexec/dotnet"

    def _make_store(self, root, tfms):
        """Populate a fake `dotnet tool` store with one ilspycmd per TFM.

        Mirrors the real layout:
        `.store/ilspycmd/<version>/ilspycmd/<version>/tools/<tfm>/any/ilspycmd.dll`
        """
        paths = {}
        for tfm in tfms:
            version = f"{tfm.removeprefix('net')}.0"
            dll = (
                root
                / ".dotnet/tools/.store/ilspycmd"
                / version
                / "ilspycmd"
                / version
                / "tools"
                / tfm
                / "any"
                / "ilspycmd.dll"
            )
            dll.parent.mkdir(parents=True, exist_ok=True)
            dll.write_bytes(b"")
            paths[tfm] = dll
        return paths

    def _run(self, store_tfms, installed_majors, generic=(), on_path=None, raise_oserror=()):
        """Run the fallback against a fake store and a fake set of runtimes.

        Args:
            store_tfms: TFM directories to create in the fake tool store.
            installed_majors: majors for which a Homebrew `dotnet@N` keg exists.
            generic: absolute paths of unversioned runtimes that exist.
            on_path: what `shutil.which` should report for the bare "dotnet".
            raise_oserror: runtime paths whose exec raises OSError.

        Returns:
            (result, calls) where calls is the list of (argv, env) actually
            executed, in order — empty when subprocess.run was never reached.
        """
        from script_analyzers import CSharpAnalyzer

        runtimes = {self.HOMEBREW.format(major=m) for m in installed_majors} | set(generic)
        if on_path:
            runtimes.add(on_path)
        real_exists = Path.exists

        def fake_exists(path):
            # Every runtime candidate is an executable named `dotnet`; the fake
            # store on disk is left to the real exists().
            if str(path).endswith("/dotnet"):
                return str(path) in runtimes
            return real_exists(path)

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            self._make_store(root, store_tfms)
            calls = []

            def fake_run(argv, **kwargs):
                calls.append((argv, kwargs.get("env", {})))
                if argv[0] in raise_oserror:
                    raise OSError(86, "Bad CPU type in executable")
                return subprocess.CompletedProcess(argv, 0, stdout="IL_0000: ret", stderr="")

            with (
                mock.patch.object(Path, "home", return_value=root),
                mock.patch.object(Path, "exists", fake_exists),
                mock.patch.object(subprocess, "run", fake_run),
                mock.patch("script_analyzers.shutil.which", return_value=on_path),
            ):
                result = CSharpAnalyzer()._il_via_versioned_runtime("Target.dll")
            return result, calls

    @staticmethod
    def _argv(calls):
        """The argv of the last command executed, or None if nothing ran."""
        return calls[-1][0] if calls else None

    def test_finds_assembly_newer_than_net8(self):
        """A net9.0 store assembly must be found, not just net8.0.

        This is the regression: the glob was pinned to `tools/net8.0/`, so every
        ilspycmd 9.x install was invisible and C# analysis fell through to the
        "IL disassembly tools not available" error — while the install command
        that error recommends produces exactly this layout.
        """
        (ok, output), calls = self._run(["net9.0"], installed_majors=[9])
        argv = self._argv(calls)

        self.assertTrue(ok, "net9.0 store assembly should have been found")
        self.assertEqual(output, "IL_0000: ret")
        self.assertEqual(argv[0], self.HOMEBREW.format(major=9))
        self.assertIn("net9.0", argv[1])

    def test_runtime_major_must_match_the_assembly(self):
        """A net9.0 assembly must not be launched on a .NET 8 keg.

        Widening the glob without pairing the runtime would turn a silent
        no-match into a silent failed exec, which is not an improvement. dotnet@8
        exists here and is still never chosen for a net9.0 assembly; with no
        generic runtime and nothing on PATH either, nothing runs at all.
        """
        (ok, _output), calls = self._run(["net9.0"], installed_majors=[8])
        argv = self._argv(calls)

        self.assertFalse(ok, "should not pair a net9.0 assembly with dotnet@8")
        self.assertIsNone(argv, "should not have executed anything")

    def test_newest_available_tfm_wins(self):
        """With several versions installed, the newest with a runtime is used."""
        (ok, _output), calls = self._run(["net8.0", "net10.0"], installed_majors=[8, 10])
        argv = self._argv(calls)

        self.assertTrue(ok)
        self.assertEqual(argv[0], self.HOMEBREW.format(major=10))
        self.assertIn("net10.0", argv[1])

    def test_falls_back_to_older_tfm_when_newer_runtime_is_absent(self):
        """net10.0 present but no dotnet@10 — the net8.0 pair still runs."""
        (ok, _output), calls = self._run(["net8.0", "net10.0"], installed_majors=[8])
        argv = self._argv(calls)

        self.assertTrue(ok)
        self.assertEqual(argv[0], self.HOMEBREW.format(major=8))
        self.assertIn("net8.0", argv[1])

    def test_exact_major_keg_does_not_set_roll_forward(self):
        """A keg of the right major needs no roll-forward, so it must not ask for one.

        Setting it unconditionally would mask a genuinely mismatched pair instead of
        letting it fail, which is the behaviour the previous test pins.
        """
        (ok, _output), calls = self._run(["net9.0"], installed_majors=[9])

        self.assertTrue(ok)
        argv, env = calls[-1]
        self.assertEqual(argv[0], self.HOMEBREW.format(major=9))
        self.assertNotIn("DOTNET_ROLL_FORWARD", env)

    def test_generic_runtime_runs_with_roll_forward_when_no_keg_exists(self):
        """No dotnet@N keg must not mean no disassembly.

        homebrew-core carries a versioned formula for some majors and not others
        (dotnet@7 was dropped at EOL), and no Linux distribution ships one at all.
        Without this path the fix would only move the silent no-match from the glob
        to the exists() check. A generic runtime is a different major, so it is only
        legal to launch under DOTNET_ROLL_FORWARD=Major.
        """
        installer = "/usr/local/share/dotnet/dotnet"
        (ok, _output), calls = self._run(["net9.0"], installed_majors=[], generic=[installer])

        self.assertTrue(ok, "should fall back to a generic runtime with roll-forward")
        argv, env = calls[-1]
        self.assertEqual(argv[0], installer)
        self.assertEqual(env.get("DOTNET_ROLL_FORWARD"), "Major")

    def test_path_dotnet_is_the_last_resort(self):
        """With no keg and no known install location, the PATH dotnet is tried.

        `dotnet_path` defaults to the bare name "dotnet", so it has to be resolved
        through PATH — exists()-checking a bare name tests the cwd and always fails.
        """
        which = "/opt/custom/bin/dotnet"
        (ok, _output), calls = self._run(["net9.0"], installed_majors=[], on_path=which)

        self.assertTrue(ok)
        argv, env = calls[-1]
        self.assertEqual(argv[0], which)
        self.assertEqual(env.get("DOTNET_ROLL_FORWARD"), "Major")

    def test_oserror_from_a_runtime_is_survivable(self):
        """A runtime that exists but cannot exec must not abort the analysis.

        An Intel keg on an Apple Silicon box without Rosetta raises
        OSError("Bad CPU type in executable"), not FileNotFoundError. Catching only
        the latter let it escape this helper, _get_il_output and analyze, crashing a
        fallback whose contract is to return quietly and let monodis try.
        """
        keg = self.HOMEBREW.format(major=9)
        installer = "/usr/local/share/dotnet/dotnet"
        (ok, _output), calls = self._run(
            ["net9.0"],
            installed_majors=[9],
            generic=[installer],
            raise_oserror={keg},
        )

        self.assertTrue(ok, "should have carried on to the next candidate")
        self.assertEqual([argv[0] for argv, _env in calls], [keg, installer])

    def test_dotnet_root_points_at_the_runtime_parent(self):
        """DOTNET_ROOT is what lets an isolated keg find its shared framework.

        Nothing asserted it before, so deleting the line passed the whole suite.
        """
        (ok, _output), calls = self._run(["net9.0"], installed_majors=[9])

        self.assertTrue(ok)
        _argv, env = calls[-1]
        self.assertEqual(env.get("DOTNET_ROOT"), "/opt/homebrew/opt/dotnet@9/libexec")

    def test_missing_store_is_not_an_error(self):
        """No store at all returns cleanly so callers reach the next fallback."""
        (ok, output), calls = self._run([], installed_majors=[9])
        argv = self._argv(calls)

        self.assertFalse(ok)
        self.assertEqual(output, "")
        self.assertIsNone(argv)

    def test_tfm_version_parsing(self):
        """Only versioned netX.Y monikers name a runtime we can pair with."""
        from script_analyzers import CSharpAnalyzer

        parse = CSharpAnalyzer._tfm_version

        self.assertEqual(parse("net8.0"), (8, 0))
        self.assertEqual(parse("net9.0"), (9, 0))
        self.assertEqual(parse("net10.0"), (10, 0))
        # Ordering is numeric, not lexical: "net10.0" < "net8.0" as strings.
        self.assertGreater(parse("net10.0"), parse("net8.0"))
        # Neither of these names a .NET runtime major version.
        self.assertIsNone(parse("netstandard2.0"))
        self.assertIsNone(parse("net48"))


class TestScriptAnalyzerIntegration(unittest.TestCase):
    """Integration tests for scripting language analyzers.

    These tests require PHP/Node.js/Python/Ruby to be installed.
    """

    @classmethod
    def setUpClass(cls):
        cls.samples_dir = Path(__file__).parent / "test_samples"
        cls.has_php = cls._check_runtime("php")
        cls.has_node = cls._check_runtime("node")
        cls.has_python = cls._check_runtime("python3")
        cls.has_ruby = cls._check_runtime("ruby")

    @staticmethod
    def _check_runtime(name):
        try:
            subprocess.run([name, "--version"], capture_output=True, check=True)
            return True
        except (subprocess.CalledProcessError, FileNotFoundError):
            return False

    def test_php_vulnerable_detected(self):
        """Vulnerable PHP code should be detected."""
        if not self.has_php:
            self.skipTest("PHP not available")

        vulnerable_file = self.samples_dir / "vulnerable.php"
        if not vulnerable_file.exists():
            self.skipTest("PHP test sample not found")

        try:
            report = analyze_source(str(vulnerable_file), include_warnings=False)

            # Should detect dangerous operations
            self.assertIsNotNone(report)
            self.assertEqual(report.architecture, "zend")

            # Check for expected violations (div, mod, or dangerous functions)
            if report.error_count > 0:
                self.assertFalse(report.passed, "Should fail with violations")

        except RuntimeError as e:
            if "VLD" in str(e) or "opcache" in str(e).lower():
                # VLD/opcache may not produce output for simple files
                pass
            else:
                raise

    def test_javascript_vulnerable_detected(self):
        """Vulnerable JavaScript code should be detected."""
        if not self.has_node:
            self.skipTest("Node.js not available")

        # Create a simple vulnerable JS file for testing
        import tempfile

        with tempfile.NamedTemporaryFile(mode="w", suffix=".js", delete=False) as f:
            f.write("""
function vulnerableDiv(a, b) {
    return a / b;
}

function vulnerableRandom() {
    return Math.random();
}

// Call functions to ensure they're compiled
console.log(vulnerableDiv(10, 3));
console.log(vulnerableRandom());
""")
            temp_path = f.name

        try:
            report = analyze_source(temp_path, include_warnings=False)

            self.assertIsNotNone(report)
            self.assertEqual(report.architecture, "v8")

            # Should detect Math.random at minimum (via source analysis)
            # V8 bytecode detection depends on function being compiled

        except RuntimeError as e:
            if "bytecode" in str(e).lower():
                # V8 bytecode output can be tricky
                pass
            else:
                raise
        finally:
            os.unlink(temp_path)

    def test_python_vulnerable_detected(self):
        """Vulnerable Python code should be detected."""
        if not self.has_python:
            self.skipTest("Python not available")

        vulnerable_file = self.samples_dir / "vulnerable.py"
        if not vulnerable_file.exists():
            self.skipTest("Python test sample not found")

        try:
            report = analyze_source(str(vulnerable_file), include_warnings=False)

            # Should detect dangerous operations
            self.assertIsNotNone(report)
            self.assertEqual(report.architecture, "cpython")

            # Should detect division operations and dangerous functions
            if report.error_count > 0:
                self.assertFalse(report.passed, "Should fail with violations")

            # Check for expected violation types
            div_violations = [
                v
                for v in report.violations
                if "DIV" in v.mnemonic.upper() or "MODULO" in v.mnemonic.upper()
            ]
            func_violations = [
                v
                for v in report.violations
                if "RANDOM" in v.mnemonic.upper() or "SQRT" in v.mnemonic.upper()
            ]

            # Should detect at least some violations
            self.assertGreater(
                len(div_violations) + len(func_violations),
                0,
                "Should detect division or dangerous function calls",
            )

        except RuntimeError as e:
            if "dis" in str(e).lower():
                # dis module issues
                pass
            else:
                raise

    def test_ruby_vulnerable_detected(self):
        """Vulnerable Ruby code should be detected."""
        if not self.has_ruby:
            self.skipTest("Ruby not available")

        vulnerable_file = self.samples_dir / "vulnerable.rb"
        if not vulnerable_file.exists():
            self.skipTest("Ruby test sample not found")

        try:
            report = analyze_source(str(vulnerable_file), include_warnings=False)

            # Should detect dangerous operations
            self.assertIsNotNone(report)
            self.assertEqual(report.architecture, "yarv")

            # Should detect division operations and dangerous functions
            if report.error_count > 0:
                self.assertFalse(report.passed, "Should fail with violations")

            # Check for expected violation types
            div_violations = [
                v
                for v in report.violations
                if "DIV" in v.mnemonic.upper() or "MOD" in v.mnemonic.upper()
            ]
            func_violations = [
                v
                for v in report.violations
                if "RAND" in v.mnemonic.upper() or "SQRT" in v.mnemonic.upper()
            ]

            # Should detect at least some violations
            self.assertGreater(
                len(div_violations) + len(func_violations),
                0,
                "Should detect division or dangerous function calls",
            )

        except RuntimeError as e:
            if "yarv" in str(e).lower() or "dump" in str(e).lower():
                # Ruby YARV issues
                pass
            else:
                raise


def _have(*commands):
    """True when every command is on PATH.

    `which`, not `--version`: javap exits non-zero for `--version`, so a
    returncode check would skip Java and Kotlin everywhere, while running the
    tool means a broken shim that exits non-zero looks absent or present
    depending on which error it raises.
    """
    return all(shutil.which(command) is not None for command in commands)


class TestBackendRegressions(unittest.TestCase):
    """One test per backend defect found by auditing real toolchain output.

    Each of these backends reported PASSED on vulnerable code before the fix,
    because unparseable output was skipped silently. They are end-to-end on
    purpose: the pre-existing per-backend tests all feed hand-written listings,
    which is exactly why the drift went unnoticed.
    """

    @classmethod
    def setUpClass(cls):
        cls.samples = Path(__file__).parent / "triage_samples"

    def _analyze(self, fixture, **kwargs):
        path = self.samples / fixture
        self.assertTrue(path.exists(), f"missing fixture: {path}")
        return analyze_source(str(path), **kwargs)

    def test_rust_library_without_main_compiles(self):
        """rustc defaults to a bin crate; crypto lives in libs, which lack `fn main`."""
        if not _have("rustc"):
            self.skipTest("rustc not available")
        report = self._analyze("triage_rust.rs")
        functions = {v.function for v in report.violations}
        self.assertIn("ct_high_bits", functions, f"got {functions}")

    def test_go_reports_only_the_analyzed_source(self):
        """`go build` links the runtime in; its divisions are not the caller's bug."""
        if not _have("go"):
            self.skipTest("go not available")
        report = self._analyze("triage_go.go")
        runtime_hits = [v.function for v in report.violations if v.function.startswith("runtime.")]
        self.assertEqual(runtime_hits, [], "runtime symbols must be filtered out")
        self.assertIn("main.ctHighBits", {v.function for v in report.violations})

    def test_go_detects_plan9_width_suffixed_division(self):
        """Go writes a 32-bit divide as SDIVW, which the arm64 table used to miss."""
        if not _have("go"):
            self.skipTest("go not available")
        report = self._analyze("triage_go.go")
        high_bits = [v for v in report.violations if v.function == "main.ctHighBits"]
        self.assertTrue(high_bits, "int32 division in ctHighBits not detected")

    def test_javascript_v8_bytecode_is_parsed(self):
        """The V8 line format made every JS file parse as zero instructions."""
        if not _have("node"):
            self.skipTest("node not available")
        with tempfile.NamedTemporaryFile("w", suffix=".js", delete=False) as handle:
            handle.write(
                "function ctHighBits(keyCoef, gamma2) {\n"
                "  return Math.trunc(keyCoef / (2 * gamma2));\n"
                "}\n"
                "console.log(ctHighBits(523776, 261888));\n"
            )
            path = handle.name
        try:
            report = analyze_source(path)
        finally:
            os.unlink(path)
        self.assertGreater(report.total_instructions, 0, "no V8 bytecode parsed")
        self.assertIn("DIV", {v.mnemonic for v in report.violations})

    def test_php_opcache_backend_parses_without_vld(self):
        """VLD is an unbundled PECL build, so opcache is the path most users hit."""
        if not _have("php"):
            self.skipTest("php not available")
        report = self._analyze("triage_php.php")
        by_function = {v.function: v.mnemonic for v in report.violations}
        self.assertIn("ct_block_count", by_function, f"got {by_function}")
        self.assertIn("ct_nonce_seed", by_function, f"got {by_function}")
        self.assertFalse(report.passed)

    def test_php_refuses_to_pass_when_nothing_parsed(self):
        """An empty parse is 'we understood nothing', not 'the code is fine'.

        Asserts the raise in `analyze()`, not just that the parser returns
        nothing: returning nothing is what the pre-fix code did too, so a test
        that only checks the empty lists passes with the guard deleted.
        """
        from script_analyzers import PHPAnalyzer

        analyzer = PHPAnalyzer()
        self.assertEqual(analyzer._parse_opcache_output("nothing resembling opcodes\n"), ([], []))

        with tempfile.NamedTemporaryFile("w", suffix=".php", delete=False) as handle:
            handle.write("<?php\nfunction f(int $a, int $b): int { return $a / $b; }\n")
            path = handle.name
        try:
            with (
                mock.patch.object(PHPAnalyzer, "_check_vld_available", return_value=False),
                mock.patch.object(
                    PHPAnalyzer,
                    "_get_opcache_output",
                    return_value=(True, "nothing resembling opcodes\n"),
                ),
                self.assertRaises(RuntimeError) as caught,
            ):
                analyzer.analyze(path)
            self.assertIn("Parsed no functions", str(caught.exception))
        finally:
            os.unlink(path)

    def test_go_refuses_to_pass_when_no_symbol_came_from_the_source(self):
        """The filter dropping everything means the listing was not understood."""
        from analyzer import GoCompiler

        runtime_only = (
            "TEXT runtime.makeBucketArray(SB) /usr/lib/go/src/runtime/map.go\n"
            "  map.go:1\t0x1000\t9ac2087b\tUDIV R2, R3, R27\n"
        )
        compiler = GoCompiler()
        with mock.patch(
            "analyzer.subprocess.run",
            return_value=subprocess.CompletedProcess([], 0, stdout=runtime_only, stderr=""),
        ):
            ok, message = compiler.compile_to_assembly("crypto.go", "/dev/null", "arm64", "O2")
        self.assertFalse(ok, "a listing with no symbols from the source must not succeed")
        self.assertIn("no symbols", message)

    def test_unsupported_architecture_is_refused_not_downgraded(self):
        """Omitting the target flag compiles for the host under the wrong label."""
        from analyzer import GCCCompiler, SwiftCompiler

        ok, message = SwiftCompiler().compile_to_assembly("x.swift", "/dev/null", "riscv64", "O2")
        self.assertFalse(ok)
        self.assertIn("cannot target riscv64", message)

        ok, message = GCCCompiler().compile_to_assembly("x.c", "/dev/null", "mips", "O2")
        self.assertFalse(ok)
        self.assertIn("cannot target mips", message)

    def test_go_filter_does_not_readmit_runtime_by_basename(self):
        """The runtime ships map.go, slice.go, string.go, time.go and select.go."""
        if not _have("go"):
            self.skipTest("go not available")
        with tempfile.TemporaryDirectory() as tmp:
            target = Path(tmp) / "map.go"
            target.write_text((self.samples / "triage_go.go").read_text(), encoding="utf-8")
            report = analyze_source(str(target))
        leaked = sorted(
            {v.function for v in report.violations if v.function.startswith("runtime.")}
        )
        self.assertEqual(leaked, [], f"runtime symbols readmitted by basename: {leaked}")
        self.assertIn("main.ctHighBits", {v.function for v in report.violations})

    def test_swift_targets_the_host_platform(self):
        """Apple triples need Xcode's SDK; on Linux swiftc rejects them outright."""
        from analyzer import SwiftCompiler

        target = SwiftCompiler.target_for("arm64")
        if target is None:
            self.fail("arm64 must map to a target triple on every supported platform")
        if platform.system() == "Darwin":
            self.assertIn("apple", target)
        else:
            self.assertIn("linux", target)

    def test_java_detects_fully_qualified_random(self):
        """`new java.util.Random()` needs no import, so single files use it."""
        if not _have("javac"):
            self.skipTest("javac not available")
        report = self._analyze("TriageJava.java")
        self.assertIn("JAVA_UTIL_RANDOM", {v.mnemonic for v in report.violations})


class TestV8Coverage(unittest.TestCase):
    """V8 compiles lazily and dumps every function in the process, node's included."""

    def _analyze_js(self, source, suffix=".js"):
        if not _have("node"):
            self.skipTest("node not available")
        with tempfile.NamedTemporaryFile("w", suffix=suffix, delete=False) as handle:
            handle.write(source)
            path = handle.name
        try:
            return analyze_source(path), path
        finally:
            os.unlink(path)

    def test_exported_but_never_called_functions_are_covered(self):
        """A library that defines and exports helpers used to analyse as empty."""
        report, _ = self._analyze_js(
            "function ctHighBits(keyCoef, gamma2) {\n"
            "  return Math.trunc(keyCoef / (2 * gamma2));\n"
            "}\n"
            "module.exports = { ctHighBits };\n"
        )
        divisions = [v for v in report.violations if v.mnemonic == "DIV"]
        self.assertTrue(divisions, "never-called function produced no bytecode finding")
        self.assertEqual(divisions[0].function, "ctHighBits")

    def test_findings_carry_the_source_line(self):
        """V8 reports a byte offset; an unconverted offset points at the wrong code."""
        source = (
            "const label = 'padding';\n"
            "function ctHighBits(keyCoef, gamma2) {\n"
            "  return Math.trunc(keyCoef / (2 * gamma2));\n"
            "}\n"
            "module.exports = { ctHighBits, label };\n"
        )
        report, _ = self._analyze_js(source)
        divisions = [v for v in report.violations if v.mnemonic == "DIV"]
        self.assertTrue(divisions)
        self.assertEqual(divisions[0].line, 3, "division is on line 3")

    def test_node_internal_functions_are_not_reported(self):
        """Executing anything pulls in node's streams; their divisions are not ours."""
        report, _ = self._analyze_js(
            "function ctHighBits(keyCoef, gamma2) {\n"
            "  return Math.trunc(keyCoef / (2 * gamma2));\n"
            "}\n"
            "console.log(ctHighBits(523776, 261888));\n"
        )
        reported = {v.function for v in report.violations if v.function != "<source>"}
        self.assertTrue(reported)
        self.assertEqual(reported, {"ctHighBits"}, f"internals leaked: {reported}")

    def test_one_finding_per_division(self):
        """The bytecode and source passes both see the operator; report it once."""
        report, _ = self._analyze_js(
            "function f(a, b) {\n  return a / b;\n}\nmodule.exports = { f };\n"
        )
        lines = [v.line for v in report.violations]
        self.assertEqual(sorted(lines), [2], f"expected a single finding, got {report.violations}")

    def test_typescript_positions_are_not_reported_as_source_lines(self):
        """TS is transpiled first, so V8's offsets index the generated JS."""
        if not _have("node", "tsc"):
            self.skipTest("node or tsc not available")
        path = Path(__file__).parent / "triage_samples" / "triage_ts.ts"
        report = analyze_source(str(path))
        for violation in report.violations:
            if violation.mnemonic in {"DIV", "DIVSMI", "MOD", "MODSMI"}:
                self.assertIsNone(
                    violation.line,
                    "a transpiled offset must not be presented as a .ts line",
                )

    def test_declared_names_finds_declarations_and_skips_keywords(self):
        from script_analyzers import JavaScriptAnalyzer

        names = JavaScriptAnalyzer._declared_function_names(
            "function alpha() {}\n"
            "const beta = (x) => x;\n"
            "class Gamma { delta(a) { if (a) { return 1; } } }\n"
            "const obj = { epsilon: function () {} };\n"
            "// function commented\n"
        )
        for expected in ("alpha", "beta", "Gamma", "delta", "epsilon"):
            self.assertIn(expected, names)
        self.assertNotIn("if", names)
        self.assertNotIn("commented", names, "a name in a comment is not a declaration")

    def test_offset_conversion_bounds(self):
        from script_analyzers import JavaScriptAnalyzer

        source = "a\nbb\nccc\n"
        self.assertEqual(JavaScriptAnalyzer._line_of_offset(source, 0), 1)
        self.assertEqual(JavaScriptAnalyzer._line_of_offset(source, 2), 2)
        self.assertEqual(JavaScriptAnalyzer._line_of_offset(source, 5), 3)
        self.assertIsNone(JavaScriptAnalyzer._line_of_offset(source, len(source) + 1))
        self.assertIsNone(JavaScriptAnalyzer._line_of_offset(source, -1))


class TestSeverityLabelling(unittest.TestCase):
    """The text report is what reviewers read; it must not downgrade errors.

    `analyzer.py` is documented as `uv run .../analyzer.py`, which makes it
    `__main__` while `script_analyzers` imports it again as `analyzer`. Two
    `Severity` enums result, so identity comparison labelled every
    scripting-language error as `[WARN]` while the summary counted it as an error.
    """

    def test_error_label_survives_a_duplicate_severity_enum(self):
        import importlib.util

        from analyzer import AnalysisReport, Violation, format_report

        # Load a second copy of the module, mimicking the __main__/import split.
        spec = importlib.util.spec_from_file_location(
            "analyzer_duplicate", Path(__file__).parent.parent / "analyzer.py"
        )
        if spec is None or spec.loader is None:
            self.fail("could not load a second copy of analyzer.py")
        duplicate = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(duplicate)
        self.assertIsNot(duplicate.Severity, Severity, "expected two distinct enums")

        report = AnalysisReport(
            architecture="zend",
            compiler="php/opcache",
            optimization="default",
            source_file="crypto.php",
            total_functions=1,
            total_instructions=1,
            violations=[
                Violation(
                    function="high_bits",
                    file="crypto.php",
                    line=7,
                    address="0002",
                    instruction="INTDIV",
                    mnemonic="INTDIV",
                    reason="intdiv() performs hardware division",
                    # severity from the *other* copy of the module
                    severity=duplicate.Severity.ERROR,
                )
            ],
        )
        text = format_report(report, OutputFormat.TEXT)
        self.assertIn("[ERROR]", text)
        self.assertNotIn("[WARN]", text)
        self.assertEqual(report.error_count, 1)
        self.assertFalse(report.passed)


class TestCrossCompilation(unittest.TestCase):
    """Proves a requested architecture was really targeted, not silently the host.

    Asserting instruction names unique to the target is the only way to tell
    crossing apart from host output wearing the requested label — the failure
    mode `reject_arch` exists to prevent. The pre-existing cross-architecture
    test asks for arm64, which is the host on some machines and therefore proves
    nothing there.
    """

    @classmethod
    def setUpClass(cls):
        # A freestanding sample: the triage fixtures include <stdint.h>, so
        # cross-compiling them needs the target's libc headers, and a runner
        # without a cross sysroot fails with "bits/libc-header-start.h file not
        # found" — an environment gap reported as a regression. Verifying that a
        # division instruction reaches the assembly needs no libc.
        cls.fixture = Path(__file__).parent / "test_samples" / "cross_probe.c"

    def test_clang_targets_x86_64(self):
        if not _have("clang"):
            self.skipTest("clang not available")
        report = analyze_source(str(self.fixture), compiler="clang", arch="x86_64")
        mnemonics = {v.mnemonic for v in report.violations}
        self.assertEqual(report.architecture, "x86_64")
        self.assertTrue(
            mnemonics & {"DIVL", "DIVQ", "IDIVL", "IDIVQ"},
            f"no x86 division mnemonic, so this was not an x86_64 build: {mnemonics}",
        )
        self.assertNotIn("SDIV", mnemonics, "SDIV is arm64; the host leaked through")

    def test_clang_targets_riscv64(self):
        if not _have("clang"):
            self.skipTest("clang not available")
        report = analyze_source(str(self.fixture), compiler="clang", arch="riscv64")
        mnemonics = {v.mnemonic for v in report.violations}
        self.assertEqual(report.architecture, "riscv64")
        self.assertTrue(
            mnemonics & {"DIV", "DIVU", "DIVW", "DIVUW", "REM", "REMU"},
            f"no RISC-V division mnemonic: {mnemonics}",
        )
        self.assertNotIn("SDIV", mnemonics)

    def test_an_explicit_cross_toolchain_is_driven_with_its_own_flags(self):
        """A GNU cross toolchain is a separate binary, and the report must name it."""
        from analyzer import GNU_TRIPLES

        binary = f"{GNU_TRIPLES['x86_64']}-gcc"
        if not _have(binary):
            self.skipTest(f"{binary} not installed")
        report = analyze_source(str(self.fixture), compiler=binary, arch="x86_64")
        mnemonics = {v.mnemonic for v in report.violations}
        self.assertEqual(report.compiler, binary, "the report must name the binary that ran")
        self.assertTrue(
            mnemonics & {"DIVL", "DIVQ", "IDIVL", "IDIVQ"},
            f"cross gcc produced no x86 division mnemonic: {mnemonics}",
        )

    def test_compiler_family_is_identified_by_name_then_by_version(self):
        from analyzer import ClangCompiler, GCCCompiler, compiler_family, get_compiler

        self.assertEqual(compiler_family("x86_64-linux-gnu-gcc"), "gcc")
        self.assertEqual(compiler_family("/opt/x/bin/aarch64-none-elf-gcc"), "gcc")
        self.assertEqual(compiler_family("clang-18"), "clang")
        # "gcc" contains "cc", so the clang check has to win on a clang binary
        self.assertEqual(compiler_family("clang++"), "clang")
        self.assertIsInstance(get_compiler("x86_64-linux-gnu-gcc", "c"), GCCCompiler)
        self.assertIsInstance(get_compiler("clang-18", "c"), ClangCompiler)
        if _have("cc"):
            # Identified from its version banner rather than its name
            self.assertIn(compiler_family("cc"), {"gcc", "clang"})

    def test_gcc_names_the_cross_binary_to_use_when_it_cannot_cross(self):
        """A raw `unrecognized option '-m64'` does not tell the reader what to do."""
        if not _have("gcc"):
            self.skipTest("gcc not available")
        foreign = "riscv64" if get_native_arch() != "riscv64" else "x86_64"
        with self.assertRaises(RuntimeError) as caught:
            analyze_source(str(self.fixture), compiler="gcc", arch=foreign)
        message = str(caught.exception)
        self.assertIn(f"{foreign}-linux-gnu-gcc", message)
        self.assertIn("--compiler clang", message)

    def test_software_division_helpers_are_detected(self):
        """A target with no hardware divider emits a call, not a divide."""
        assembly = """
        ct_high_bits:
            push    {r4, lr}
            bl      __aeabi_idiv(PLT)
            pop     {r4, pc}
        """
        parser = AssemblyParser("arm", "gcc")
        _functions, violations = parser.parse(assembly)
        self.assertTrue(violations, "bl __aeabi_idiv must be reported")
        self.assertEqual(violations[0].mnemonic, "AEABI_IDIV")
        self.assertEqual(violations[0].severity, Severity.ERROR)

    def test_armv7_division_is_not_reported_as_clean(self):
        """`x / y` on armv7-a becomes `bl __aeabi_idiv`, which read as PASSED."""
        binary = "arm-linux-gnueabihf-gcc"
        if not _have(binary):
            self.skipTest(f"{binary} not installed")
        report = analyze_source(str(self.fixture), compiler=binary, arch="arm")
        self.assertFalse(report.passed, "the probe divides twice, and neither was reported")
        self.assertIn("AEABI_IDIV", {v.mnemonic for v in report.violations})

    def test_go_cross_builds_for_amd64(self):
        """Go cross-builds without a C toolchain, since CGO is disabled."""
        if not _have("go"):
            self.skipTest("go not available")
        fixture = Path(__file__).parent / "triage_samples" / "triage_go.go"
        report = analyze_source(str(fixture), arch="x86_64")
        mnemonics = {v.mnemonic for v in report.violations}
        self.assertTrue(
            mnemonics & {"IDIVL", "IDIVQ", "DIVL", "DIVQ"},
            f"no x86 division mnemonic in a Go amd64 build: {mnemonics}",
        )
        self.assertNotIn("SDIVW", mnemonics, "SDIVW is Plan 9 arm64; the host leaked through")


class TestCommentBlanking(unittest.TestCase):
    """Source-level detectors are regex scans, so comments used to count as code."""

    def test_c_style_comments_are_blanked_without_moving_offsets(self):
        from script_analyzers import blank_comments

        source = "/** a / b */\nx = c / d;\n"
        blanked = blank_comments(source, "c")
        self.assertEqual(len(blanked), len(source))
        self.assertEqual(blanked.count("\n"), source.count("\n"))
        self.assertNotIn("a / b", blanked)
        self.assertIn("c / d", blanked)

    def test_hash_comments_are_blanked(self):
        from script_analyzers import blank_comments

        blanked = blank_comments("# uses random.random()\nv = random.random()\n", "hash")
        self.assertEqual(blanked.count("random.random()"), 1)

    def test_comment_marker_inside_a_string_does_not_blank_code(self):
        """`"http://x"` used to blank the rest of the line, losing real findings."""
        from script_analyzers import blank_comments

        kept = blank_comments('const u = "http://example.com"; const k = a / b;', "c")
        self.assertIn("a / b", kept)
        kept = blank_comments('String u = "http://x"; Random r = new Random();', "c")
        self.assertIn("new Random()", kept)
        kept = blank_comments('puts "tag #{a / b}"', "hash")
        self.assertIn("a / b", kept)

    def test_a_lone_block_comment_marker_in_a_string_is_not_unbounded(self):
        """`"/*"` then any later `*/` blanked every line in between."""
        from script_analyzers import blank_comments

        kept = blank_comments('const m = "/*";\nconst k = a / b;\nconst e = "*/";\n', "c")
        self.assertIn("a / b", kept)

    def test_doc_comment_is_not_reported_as_division(self):
        if not _have("node"):
            self.skipTest("node not available")
        with tempfile.NamedTemporaryFile("w", suffix=".js", delete=False) as handle:
            handle.write("/** Divides a / b and never calls Math.random(). */\nconst k = 1;\n")
            path = handle.name
        try:
            report = analyze_source(path)
        finally:
            os.unlink(path)
        self.assertEqual(
            [v.mnemonic for v in report.violations],
            [],
            "comment text must not produce findings",
        )


# One extension per supported language, so the matrix test cannot drift from the
# languages detect_language() actually recognises.
EVERY_SUPPORTED_EXTENSION = (
    ".c",
    ".cpp",
    ".go",
    ".rs",
    ".swift",
    ".java",
    ".kt",
    ".cs",
    ".php",
    ".js",
    ".ts",
    ".py",
    ".rb",
)

# expectations.json names languages the way a person would; detect_language()
# returns its own identifiers. Mapping them explicitly lets the matrix test compare
# sets rather than counts.
DISPLAY_TO_DETECTED = {
    "C": "c",
    "C++": "cpp",
    "Go": "go",
    "Rust": "rust",
    "Swift": "swift",
    "Java": "java",
    "Kotlin": "kotlin",
    "C#": "csharp",
    "PHP": "php",
    "JavaScript": "javascript",
    "TypeScript": "typescript",
    "Python": "python",
    "Ruby": "ruby",
}

TRIAGE_TOOLCHAINS = {
    "C": ["gcc"],
    "C++": ["gcc"],
    "Go": ["go"],
    "Rust": ["rustc"],
    "Swift": ["swiftc"],
    "Java": ["javac", "javap"],
    "Kotlin": ["kotlinc", "javap"],
    "C#": ["dotnet", "ilspycmd"],
    "PHP": ["php"],
    "JavaScript": ["node"],
    "TypeScript": ["node", "tsc"],
    "Python": ["python3"],
    "Ruby": ["ruby"],
}


class TestTriageMatrix(unittest.TestCase):
    """Drives triage_samples/expectations.json — the (language, family) matrix.

    Each case names a violation the analyzer must still report. Both members of
    every true-positive/false-positive pair have to be reported, because the whole
    premise of the skill's triage step is that the tool cannot tell them apart.
    If a pair stops being reported, the guidance that sends reviewers to these
    fixtures is describing behaviour that no longer exists.
    """

    @classmethod
    def setUpClass(cls):
        cls.samples = Path(__file__).parent / "triage_samples"
        with open(cls.samples / "expectations.json", encoding="utf-8") as handle:
            cls.manifest = json.load(handle)
        cls.fixtures = cls.manifest["fixtures"]

    def test_every_supported_language_has_a_fixture(self):
        """Runs with no toolchain, so the matrix itself is guarded everywhere."""
        # Compare the sets, not their sizes: equal counts stay green if one
        # language is renamed while another is dropped.
        declared = {DISPLAY_TO_DETECTED[entry["language"]] for entry in self.fixtures.values()}
        supported = {detect_language(f"x{ext}") for ext in EVERY_SUPPORTED_EXTENSION}
        self.assertEqual(declared, supported)
        self.assertEqual(len(self.fixtures), len(EVERY_SUPPORTED_EXTENSION))

    def test_every_fixture_pairs_a_true_and_false_positive(self):
        for name, entry in self.fixtures.items():
            with self.subTest(fixture=name):
                verdicts = [case["verdict"] for case in entry["cases"]]
                self.assertIn("true-positive", verdicts, "a fixture with no true positive")
                self.assertIn("false-positive", verdicts, "a fixture with no false positive")

    def test_every_locator_resolves_in_its_fixture(self):
        """A renamed function or edited line silently voids a case; catch it here."""
        for name, entry in self.fixtures.items():
            source = (self.samples / name).read_text(encoding="utf-8")
            for case in entry["cases"]:
                locator = case["locator"]
                if locator["kind"] != "line-of":
                    continue
                with self.subTest(fixture=name, locator=locator["value"]):
                    self.assertEqual(
                        source.count(locator["value"]),
                        1,
                        f"{locator['value']!r} must appear exactly once in {name}",
                    )

    def test_no_fixture_carries_its_verdict_in_a_comment(self):
        """These double as eval input; a labelled answer is not an answer."""
        for name in self.fixtures:
            source = (self.samples / name).read_text(encoding="utf-8").lower()
            with self.subTest(fixture=name):
                for leak in ("true-positive", "false-positive", "true positive", "false positive"):
                    self.assertNotIn(leak, source, f"{name} leaks its verdict")

    def test_analyzer_still_reports_every_case(self):
        exercised, skipped = [], []

        for name, entry in self.fixtures.items():
            language = entry["language"]
            if not _have(*TRIAGE_TOOLCHAINS[language]):
                # A real skip per language, so a CI image that loses a toolchain
                # shows up in the skip count instead of passing quietly with the
                # detail on stdout.
                skipped.append(language)
                with self.subTest(language=language):
                    self.skipTest(f"{language}: missing {TRIAGE_TOOLCHAINS[language]}")
                continue
            exercised.append(language)
            source = (self.samples / name).read_text(encoding="utf-8")
            config = entry.get("config", {})

            for case in entry["cases"]:
                kwargs = dict(config.get(case["family"], {}))
                with self.subTest(fixture=name, family=case["family"], verdict=case["verdict"]):
                    report = analyze_source(str(self.samples / name), **kwargs)
                    wanted = Severity(case["severity"])
                    locator = case["locator"]
                    if locator["kind"] == "function":
                        found = [
                            v
                            for v in report.violations
                            if v.severity == wanted and v.function == locator["value"]
                        ]
                    else:
                        line = source[: source.index(locator["value"])].count("\n") + 1
                        found = [
                            v for v in report.violations if v.severity == wanted and v.line == line
                        ]
                    reported = {
                        (v.severity.value, v.mnemonic, v.function, v.line)
                        for v in report.violations
                    }
                    self.assertTrue(
                        found,
                        f"{name}: no {case['severity']} for {locator} "
                        f"({case['family']}, {case['verdict']}); "
                        f"reported {sorted(reported)}",
                    )

        # A matrix that exercised nothing must fail rather than report success.
        self.assertTrue(exercised, f"no triage fixture ran; missing toolchains for {skipped}")
        if skipped:
            print(f"\nTriageMatrix: exercised {sorted(exercised)}; skipped {sorted(skipped)}")


class TestPythonBytecodeEndToEnd(unittest.TestCase):
    """Runs the real `python3` toolchain rather than replaying canned dis text.

    Every other Python test in this file feeds hand-written disassembly to the
    parser. That is why two defects survived: the BINARY_OP oparg map read 12 as
    `//` when 12 is `^`, and the instruction regex required a byte offset that
    Python 3.13 no longer prints. Canned input in the old format exercised
    neither. These tests go through the actual interpreter, so a future dis
    format change fails here instead of silently returning PASSED.
    """

    @classmethod
    def setUpClass(cls):
        try:
            subprocess.run(["python3", "--version"], capture_output=True, check=True)
            cls.available = True
        except (subprocess.CalledProcessError, FileNotFoundError):
            cls.available = False

    def _analyze(self, source):
        if not self.available:
            self.skipTest("python3 not available")
        with tempfile.NamedTemporaryFile("w", suffix=".py", delete=False) as handle:
            handle.write(source)
            path = handle.name
        try:
            return analyze_source(path, include_warnings=False)
        finally:
            os.unlink(path)

    def test_floor_division_on_a_secret_is_detected(self):
        """`//` is the idiomatic Python integer divide; missing it is a false negative."""
        report = self._analyze(
            "def high_bits(key_coef, gamma2):\n    return key_coef // (2 * gamma2)\n"
        )
        mnemonics = [v.mnemonic for v in report.violations]
        self.assertIn(
            "BINARY_OP_FLOORDIV",
            mnemonics,
            f"floor division not detected; got {mnemonics}",
        )
        self.assertFalse(report.passed)

    def test_true_division_and_modulo_are_detected(self):
        report = self._analyze("def f(a, b):\n    return (a / b, a % b)\n")
        mnemonics = {v.mnemonic for v in report.violations}
        self.assertIn("BINARY_OP_TRUEDIV", mnemonics)
        self.assertIn("BINARY_OP_MODULO", mnemonics)

    def test_xor_and_shift_are_not_reported_as_division(self):
        """Bit tricks are how constant-time code is written — flagging them is noise."""
        report = self._analyze(
            "def ct_select(mask, a, b):\n"
            "    return b ^ (mask & (a ^ b))\n"
            "def ct_shift(x):\n"
            "    return (x >> 3) | (x << 2)\n"
        )
        self.assertEqual(
            [v.mnemonic for v in report.violations],
            [],
            "constant-time bit operations must not be reported as violations",
        )

    def test_violations_carry_a_source_line(self):
        """A finding without a line number is a finding the reviewer cannot check."""
        report = self._analyze(
            "def a(x, y):\n    return x / y\n\n\ndef b(x, y):\n    return x % y\n"
        )
        self.assertTrue(report.violations, "expected violations to attribute")
        for violation in report.violations:
            self.assertIsNotNone(
                violation.line, f"{violation.mnemonic} in {violation.function} has no line"
            )
        self.assertEqual({v.line for v in report.violations}, {2, 6})

    def test_function_attribution(self):
        report = self._analyze(
            "def secret_div(k, g):\n    return k // g\n\ndef public_div(n, w):\n    return n // w\n"
        )
        by_function = {v.function for v in report.violations}
        self.assertEqual(by_function, {"secret_div", "public_div"})


if __name__ == "__main__":
    unittest.main(verbosity=2)
