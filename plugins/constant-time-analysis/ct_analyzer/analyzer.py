#!/usr/bin/env python3
# /// script
# requires-python = ">=3.10"
# ///
"""
ct_analyzer - Constant-Time Assembly Analyzer

A portable tool for detecting timing side-channel vulnerabilities in compiled
cryptographic code by analyzing assembly output for variable-time instructions.

This tool analyzes assembly from multiple compilers (gcc, clang, go, rustc)
across multiple architectures (x86_64, arm64, arm, riscv64, etc.) to detect
instructions that could leak timing information about secret data.

Usage:
    python ct_analyzer/analyzer.py [options] <source_file>

Examples:
    # Analyze a C file with default settings (clang, native arch)
    python ct_analyzer/analyzer.py crypto.c

    # Analyze with specific compiler and optimization level
    python ct_analyzer/analyzer.py --compiler gcc --opt-level O2 crypto.c

    # Analyze a Go file for arm64
    python ct_analyzer/analyzer.py --arch arm64 crypto.go

    # Analyze with warnings enabled (shows conditional branches)
    python ct_analyzer/analyzer.py --warnings crypto.c
"""

import argparse
import json
import os
import re
import subprocess
import sys
import tempfile
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path


class Severity(Enum):
    ERROR = "error"
    WARNING = "warning"


class OutputFormat(Enum):
    TEXT = "text"
    JSON = "json"
    GITHUB = "github"


@dataclass
class Violation:
    """A detected constant-time violation."""

    function: str
    file: str
    line: int | None
    address: str
    instruction: str
    mnemonic: str
    reason: str
    severity: Severity
    # The 6 instructions preceding this one in the same function. Used by
    # operand-source heuristics (e.g. "was the DIV's divisor just loaded
    # from an immediate?").  Empty list when not captured.
    context_before: list[str] = field(default_factory=list)
    # The 4 instructions after, plus the current one's full text. Used for
    # branch-target / loop-backedge analysis.
    context_after: list[str] = field(default_factory=list)
    # Pre-applied triage classification (see classify_violation()). Lets a
    # downstream agent process violations mechanically without re-reading
    # the source file and asm. None when not yet classified.
    triage_hint: str | None = None
    # Three-line source snippet centered on `line`. Populated only when
    # the file is readable and `--explain`/JSON output requests it.
    source_snippet: list[str] | None = None


@dataclass
class AnalysisReport:
    """Report from analyzing a compiled binary."""

    architecture: str
    compiler: str
    optimization: str
    source_file: str
    total_functions: int
    total_instructions: int
    violations: list[Violation] = field(default_factory=list)

    @property
    def error_count(self) -> int:
        return sum(1 for v in self.violations if v.severity == Severity.ERROR)

    @property
    def warning_count(self) -> int:
        return sum(1 for v in self.violations if v.severity == Severity.WARNING)

    @property
    def passed(self) -> bool:
        return self.error_count == 0


# Architecture-specific dangerous instructions
# Based on research from Trail of Bits and the cryptocoding guidelines

DANGEROUS_INSTRUCTIONS = {
    # x86_64 / amd64
    "x86_64": {
        "errors": {
            # Integer division - variable time based on operand values (KyberSlash attack vector)
            "div": "DIV has data-dependent timing; execution time varies based on operand values",
            "idiv": "IDIV has data-dependent timing; execution time varies based on operand values",
            "divb": "DIVB has data-dependent timing; execution time varies based on operand values",
            "divw": "DIVW has data-dependent timing; execution time varies based on operand values",
            "divl": "DIVL has data-dependent timing; execution time varies based on operand values",
            "divq": "DIVQ has data-dependent timing; execution time varies based on operand values",
            "idivb": "IDIVB has data-dependent timing; execution time varies based on operand values",
            "idivw": "IDIVW has data-dependent timing; execution time varies based on operand values",
            "idivl": "IDIVL has data-dependent timing; execution time varies based on operand values",
            "idivq": "IDIVQ has data-dependent timing; execution time varies based on operand values",
            # Floating-point division - variable latency
            "divss": "DIVSS (scalar single FP division) has variable latency",
            "divsd": "DIVSD (scalar double FP division) has variable latency",
            "divps": "DIVPS (packed single FP division) has variable latency",
            "divpd": "DIVPD (packed double FP division) has variable latency",
            "vdivss": "VDIVSS (AVX scalar single FP division) has variable latency",
            "vdivsd": "VDIVSD (AVX scalar double FP division) has variable latency",
            "vdivps": "VDIVPS (AVX packed single FP division) has variable latency",
            "vdivpd": "VDIVPD (AVX packed double FP division) has variable latency",
            # Square root - variable latency
            "sqrtss": "SQRTSS has variable latency based on operand values",
            "sqrtsd": "SQRTSD has variable latency based on operand values",
            "sqrtps": "SQRTPS has variable latency based on operand values",
            "sqrtpd": "SQRTPD has variable latency based on operand values",
            "vsqrtss": "VSQRTSS has variable latency based on operand values",
            "vsqrtsd": "VSQRTSD has variable latency based on operand values",
            "vsqrtps": "VSQRTPS has variable latency based on operand values",
            "vsqrtpd": "VSQRTPD has variable latency based on operand values",
        },
        "warnings": {
            # Conditional branches - may leak timing if condition depends on secret data
            "je": "conditional branch may leak timing information if condition depends on secret data",
            "jne": "conditional branch may leak timing information if condition depends on secret data",
            "jz": "conditional branch may leak timing information if condition depends on secret data",
            "jnz": "conditional branch may leak timing information if condition depends on secret data",
            "ja": "conditional branch may leak timing information if condition depends on secret data",
            "jae": "conditional branch may leak timing information if condition depends on secret data",
            "jb": "conditional branch may leak timing information if condition depends on secret data",
            "jbe": "conditional branch may leak timing information if condition depends on secret data",
            "jg": "conditional branch may leak timing information if condition depends on secret data",
            "jge": "conditional branch may leak timing information if condition depends on secret data",
            "jl": "conditional branch may leak timing information if condition depends on secret data",
            "jle": "conditional branch may leak timing information if condition depends on secret data",
            "jo": "conditional branch may leak timing information if condition depends on secret data",
            "jno": "conditional branch may leak timing information if condition depends on secret data",
            "js": "conditional branch may leak timing information if condition depends on secret data",
            "jns": "conditional branch may leak timing information if condition depends on secret data",
            "jp": "conditional branch may leak timing information if condition depends on secret data",
            "jnp": "conditional branch may leak timing information if condition depends on secret data",
            "jc": "conditional branch may leak timing information if condition depends on secret data",
            "jnc": "conditional branch may leak timing information if condition depends on secret data",
            # Go's Plan 9 amd64 assembler aliases (different mnemonics for the
            # same hardware ops). Without these, every conditional branch
            # emitted by the Go compiler escapes the warning set entirely.
            "jeq": "conditional branch may leak timing information if condition depends on secret data",
            "jlt": "conditional branch may leak timing information if condition depends on secret data",
            "jgt": "conditional branch may leak timing information if condition depends on secret data",
            "jhi": "conditional branch may leak timing information if condition depends on secret data",
            "jls": "conditional branch may leak timing information if condition depends on secret data",
            "jmi": "conditional branch may leak timing information if condition depends on secret data",
            "jpl": "conditional branch may leak timing information if condition depends on secret data",
            "jcs": "conditional branch may leak timing information if condition depends on secret data",
            "jcc": "conditional branch may leak timing information if condition depends on secret data",
            "jos": "conditional branch may leak timing information if condition depends on secret data",
            "joc": "conditional branch may leak timing information if condition depends on secret data",
            "jps": "conditional branch may leak timing information if condition depends on secret data",
            "jpc": "conditional branch may leak timing information if condition depends on secret data",
        },
    },
    # ARM64 / AArch64
    "arm64": {
        "errors": {
            # Division - early termination optimization makes these variable-time
            # Note: Even with DIT (Data Independent Timing) enabled, division is NOT constant-time
            "udiv": "UDIV has early termination optimization; execution time depends on operand values",
            "sdiv": "SDIV has early termination optimization; execution time depends on operand values",
            # Go's ARM64 assembler emits the 32-bit-suffixed forms and uses
            # REM* for modulo. Same hardware ops, same data-dependent timing.
            "udivw": "UDIV (32-bit) has early termination optimization",
            "sdivw": "SDIV (32-bit) has early termination optimization",
            "rem": "REM via SDIV+MSUB; data-dependent timing",
            "remw": "REM (32-bit) via SDIV+MSUB; data-dependent timing",
            "urem": "UREM via UDIV+MSUB; data-dependent timing",
            "uremw": "UREM (32-bit) via UDIV+MSUB; data-dependent timing",
            # Floating-point division
            "fdiv": "FDIV (FP division) has variable latency based on operand values",
            "fdivd": "FDIV (FP double) has variable latency",
            "fdivs": "FDIV (FP single) has variable latency",
            # Square root
            "fsqrt": "FSQRT has variable latency based on operand values",
            "fsqrtd": "FSQRT (double) has variable latency",
            "fsqrts": "FSQRT (single) has variable latency",
        },
        "warnings": {
            # Conditional branches
            "b.eq": "conditional branch may leak timing information if condition depends on secret data",
            "b.ne": "conditional branch may leak timing information if condition depends on secret data",
            "b.cs": "conditional branch may leak timing information if condition depends on secret data",
            "b.cc": "conditional branch may leak timing information if condition depends on secret data",
            "b.mi": "conditional branch may leak timing information if condition depends on secret data",
            "b.pl": "conditional branch may leak timing information if condition depends on secret data",
            "b.vs": "conditional branch may leak timing information if condition depends on secret data",
            "b.vc": "conditional branch may leak timing information if condition depends on secret data",
            "b.hi": "conditional branch may leak timing information if condition depends on secret data",
            "b.ls": "conditional branch may leak timing information if condition depends on secret data",
            "b.ge": "conditional branch may leak timing information if condition depends on secret data",
            "b.lt": "conditional branch may leak timing information if condition depends on secret data",
            "b.gt": "conditional branch may leak timing information if condition depends on secret data",
            "b.le": "conditional branch may leak timing information if condition depends on secret data",
            "beq": "conditional branch may leak timing information if condition depends on secret data",
            "bne": "conditional branch may leak timing information if condition depends on secret data",
            "bcs": "conditional branch may leak timing information if condition depends on secret data",
            "bcc": "conditional branch may leak timing information if condition depends on secret data",
            "bmi": "conditional branch may leak timing information if condition depends on secret data",
            "bpl": "conditional branch may leak timing information if condition depends on secret data",
            "bvs": "conditional branch may leak timing information if condition depends on secret data",
            "bvc": "conditional branch may leak timing information if condition depends on secret data",
            "bhi": "conditional branch may leak timing information if condition depends on secret data",
            "bls": "conditional branch may leak timing information if condition depends on secret data",
            "bge": "conditional branch may leak timing information if condition depends on secret data",
            "blt": "conditional branch may leak timing information if condition depends on secret data",
            "bgt": "conditional branch may leak timing information if condition depends on secret data",
            "ble": "conditional branch may leak timing information if condition depends on secret data",
            # Compare and branch
            "cbz": "compare-and-branch may leak timing information if value depends on secret data",
            "cbnz": "compare-and-branch may leak timing information if value depends on secret data",
            "tbz": "test-bit-and-branch may leak timing information if value depends on secret data",
            "tbnz": "test-bit-and-branch may leak timing information if value depends on secret data",
        },
    },
    # ARM 32-bit
    "arm": {
        "errors": {
            "udiv": "UDIV has early termination optimization; execution time depends on operand values",
            "sdiv": "SDIV has early termination optimization; execution time depends on operand values",
            "vdiv.f32": "VDIV.F32 has variable latency",
            "vdiv.f64": "VDIV.F64 has variable latency",
            "vsqrt.f32": "VSQRT.F32 has variable latency",
            "vsqrt.f64": "VSQRT.F64 has variable latency",
        },
        "warnings": {
            "beq": "conditional branch may leak timing information if condition depends on secret data",
            "bne": "conditional branch may leak timing information if condition depends on secret data",
            "bcs": "conditional branch may leak timing information if condition depends on secret data",
            "bcc": "conditional branch may leak timing information if condition depends on secret data",
            "bmi": "conditional branch may leak timing information if condition depends on secret data",
            "bpl": "conditional branch may leak timing information if condition depends on secret data",
            "bvs": "conditional branch may leak timing information if condition depends on secret data",
            "bvc": "conditional branch may leak timing information if condition depends on secret data",
            "bhi": "conditional branch may leak timing information if condition depends on secret data",
            "bls": "conditional branch may leak timing information if condition depends on secret data",
            "bge": "conditional branch may leak timing information if condition depends on secret data",
            "blt": "conditional branch may leak timing information if condition depends on secret data",
            "bgt": "conditional branch may leak timing information if condition depends on secret data",
            "ble": "conditional branch may leak timing information if condition depends on secret data",
        },
    },
    # RISC-V 64-bit
    "riscv64": {
        "errors": {
            "div": "DIV has variable-time execution based on operand values",
            "divu": "DIVU has variable-time execution based on operand values",
            "divw": "DIVW has variable-time execution based on operand values",
            "divuw": "DIVUW has variable-time execution based on operand values",
            "rem": "REM has variable-time execution based on operand values",
            "remu": "REMU has variable-time execution based on operand values",
            "remw": "REMW has variable-time execution based on operand values",
            "remuw": "REMUW has variable-time execution based on operand values",
            "fdiv.s": "FDIV.S has variable latency",
            "fdiv.d": "FDIV.D has variable latency",
            "fsqrt.s": "FSQRT.S has variable latency",
            "fsqrt.d": "FSQRT.D has variable latency",
        },
        "warnings": {
            "beq": "conditional branch may leak timing information if condition depends on secret data",
            "bne": "conditional branch may leak timing information if condition depends on secret data",
            "blt": "conditional branch may leak timing information if condition depends on secret data",
            "bge": "conditional branch may leak timing information if condition depends on secret data",
            "bltu": "conditional branch may leak timing information if condition depends on secret data",
            "bgeu": "conditional branch may leak timing information if condition depends on secret data",
        },
    },
    # PowerPC 64-bit Little Endian
    "ppc64le": {
        "errors": {
            "divw": "DIVW has variable-time execution",
            "divwu": "DIVWU has variable-time execution",
            "divd": "DIVD has variable-time execution",
            "divdu": "DIVDU has variable-time execution",
            "divwe": "DIVWE has variable-time execution",
            "divweu": "DIVWEU has variable-time execution",
            "divde": "DIVDE has variable-time execution",
            "divdeu": "DIVDEU has variable-time execution",
            "fdiv": "FDIV has variable latency",
            "fdivs": "FDIVS has variable latency",
            "fsqrt": "FSQRT has variable latency",
            "fsqrts": "FSQRTS has variable latency",
        },
        "warnings": {
            "beq": "conditional branch may leak timing information if condition depends on secret data",
            "bne": "conditional branch may leak timing information if condition depends on secret data",
            "blt": "conditional branch may leak timing information if condition depends on secret data",
            "bge": "conditional branch may leak timing information if condition depends on secret data",
            "bgt": "conditional branch may leak timing information if condition depends on secret data",
            "ble": "conditional branch may leak timing information if condition depends on secret data",
        },
    },
    # IBM z/Architecture (s390x)
    "s390x": {
        "errors": {
            "d": "D (divide) has variable-time execution",
            "dr": "DR (divide register) has variable-time execution",
            "dl": "DL (divide logical) has variable-time execution",
            "dlr": "DLR (divide logical register) has variable-time execution",
            "dlg": "DLG (divide logical 64-bit) has variable-time execution",
            "dlgr": "DLGR (divide logical register 64-bit) has variable-time execution",
            "dsg": "DSG (divide single 64-bit) has variable-time execution",
            "dsgr": "DSGR (divide single register 64-bit) has variable-time execution",
            "dsgf": "DSGF (divide single 64x32) has variable-time execution",
            "dsgfr": "DSGFR (divide single register 64x32) has variable-time execution",
            "ddb": "DDB (divide FP) has variable latency",
            "ddbr": "DDBR (divide FP register) has variable latency",
            "sqdb": "SQDB (square root FP) has variable latency",
            "sqdbr": "SQDBR (square root FP register) has variable latency",
        },
        "warnings": {
            "je": "conditional branch may leak timing information if condition depends on secret data",
            "jne": "conditional branch may leak timing information if condition depends on secret data",
            "jh": "conditional branch may leak timing information if condition depends on secret data",
            "jl": "conditional branch may leak timing information if condition depends on secret data",
            "jhe": "conditional branch may leak timing information if condition depends on secret data",
            "jle": "conditional branch may leak timing information if condition depends on secret data",
            "jo": "conditional branch may leak timing information if condition depends on secret data",
            "jno": "conditional branch may leak timing information if condition depends on secret data",
            "jp": "conditional branch may leak timing information if condition depends on secret data",
            "jnp": "conditional branch may leak timing information if condition depends on secret data",
            "jm": "conditional branch may leak timing information if condition depends on secret data",
            "jnm": "conditional branch may leak timing information if condition depends on secret data",
            "jz": "conditional branch may leak timing information if condition depends on secret data",
            "jnz": "conditional branch may leak timing information if condition depends on secret data",
        },
    },
    # i386 / x86 32-bit
    "i386": {
        "errors": {
            "div": "DIV has data-dependent timing; execution time varies based on operand values",
            "idiv": "IDIV has data-dependent timing; execution time varies based on operand values",
            "divb": "DIVB has data-dependent timing",
            "divw": "DIVW has data-dependent timing",
            "divl": "DIVL has data-dependent timing",
            "idivb": "IDIVB has data-dependent timing",
            "idivw": "IDIVW has data-dependent timing",
            "idivl": "IDIVL has data-dependent timing",
            "fdiv": "FDIV has variable latency",
            "fdivp": "FDIVP has variable latency",
            "fidiv": "FIDIV has variable latency",
            "fdivr": "FDIVR has variable latency",
            "fdivrp": "FDIVRP has variable latency",
            "fidivr": "FIDIVR has variable latency",
            "fsqrt": "FSQRT has variable latency",
        },
        "warnings": {
            "je": "conditional branch may leak timing information if condition depends on secret data",
            "jne": "conditional branch may leak timing information if condition depends on secret data",
            "jz": "conditional branch may leak timing information if condition depends on secret data",
            "jnz": "conditional branch may leak timing information if condition depends on secret data",
            "ja": "conditional branch may leak timing information if condition depends on secret data",
            "jae": "conditional branch may leak timing information if condition depends on secret data",
            "jb": "conditional branch may leak timing information if condition depends on secret data",
            "jbe": "conditional branch may leak timing information if condition depends on secret data",
            "jg": "conditional branch may leak timing information if condition depends on secret data",
            "jge": "conditional branch may leak timing information if condition depends on secret data",
            "jl": "conditional branch may leak timing information if condition depends on secret data",
            "jle": "conditional branch may leak timing information if condition depends on secret data",
        },
    },
}

# Architecture aliases
ARCH_ALIASES = {
    "amd64": "x86_64",
    "x64": "x86_64",
    "aarch64": "arm64",
    "armv7": "arm",
    "armhf": "arm",
    "386": "i386",
    "x86": "i386",
    "ppc64": "ppc64le",
    "riscv": "riscv64",
}


def normalize_arch(arch: str) -> str:
    """Normalize architecture name to canonical form."""
    arch = arch.lower()
    return ARCH_ALIASES.get(arch, arch)


def get_native_arch() -> str:
    """Get the native architecture of the current system."""
    import platform

    machine = platform.machine().lower()
    return normalize_arch(machine)


def detect_language(source_file: str) -> str:
    """Detect the programming language from file extension."""
    ext = Path(source_file).suffix.lower()
    language_map = {
        ".c": "c",
        ".h": "c",
        ".cc": "cpp",
        ".cpp": "cpp",
        ".cxx": "cpp",
        ".hpp": "cpp",
        ".hxx": "cpp",
        ".go": "go",
        ".rs": "rust",
        # VM-compiled languages (bytecode analysis)
        ".java": "java",
        ".cs": "csharp",
        # Scripting languages
        ".php": "php",
        ".js": "javascript",
        ".mjs": "javascript",
        ".cjs": "javascript",
        ".ts": "typescript",
        ".tsx": "typescript",
        ".mts": "typescript",
        ".py": "python",
        ".pyw": "python",
        ".rb": "ruby",
        # Kotlin (JVM bytecode)
        ".kt": "kotlin",
        ".kts": "kotlin",
        # Swift (native compiled)
        ".swift": "swift",
    }
    return language_map.get(ext, "unknown")


def is_bytecode_language(language: str) -> bool:
    """Check if the language is analyzed via bytecode (scripting and VM-compiled)."""
    return language in (
        "php",
        "javascript",
        "typescript",
        "python",
        "ruby",  # Scripting
        "java",
        "csharp",
        "kotlin",  # VM-compiled (JVM/CIL)
    )


# Backward compatibility alias
is_scripting_language = is_bytecode_language


class Compiler:
    """Base class for compiler interfaces."""

    def __init__(self, name: str, path: str | None = None):
        self.name = name
        self.path = path or name

    def compile_to_assembly(
        self,
        source_file: str,
        output_file: str,
        arch: str,
        optimization: str,
        extra_flags: list[str] = None,
    ) -> tuple[bool, str]:
        """Compile source to assembly. Returns (success, error_message)."""
        raise NotImplementedError

    def is_available(self) -> bool:
        """Check if the compiler is available on the system."""
        try:
            subprocess.run(
                [self.path, "--version"],
                capture_output=True,
                check=True,
            )
            return True
        except (subprocess.CalledProcessError, FileNotFoundError):
            return False


class GCCCompiler(Compiler):
    """GCC compiler interface."""

    ARCH_FLAGS = {
        "x86_64": ["-m64"],
        "i386": ["-m32"],
        "arm64": ["-march=armv8-a"],
        "arm": ["-march=armv7-a", "-mfloat-abi=hard"],
        "riscv64": ["-march=rv64gc", "-mabi=lp64d"],
        "ppc64le": ["-mcpu=power8", "-mlittle-endian"],
        "s390x": ["-march=z13"],
    }

    def __init__(self, path: str | None = None):
        super().__init__("gcc", path or "gcc")

    def compile_to_assembly(
        self,
        source_file: str,
        output_file: str,
        arch: str,
        optimization: str,
        extra_flags: list[str] = None,
    ) -> tuple[bool, str]:
        arch = normalize_arch(arch)
        arch_flags = self.ARCH_FLAGS.get(arch, [])

        cmd = [
            self.path,
            f"-{optimization}",
            "-S",  # Generate assembly
            "-fno-asynchronous-unwind-tables",  # Cleaner output
            "-fno-dwarf2-cfi-asm",  # Cleaner output
            *arch_flags,
            *(extra_flags or []),
            source_file,
            "-o",
            output_file,
        ]

        try:
            result = subprocess.run(cmd, capture_output=True, text=True)
            if result.returncode != 0:
                return False, result.stderr
            return True, ""
        except FileNotFoundError:
            return False, f"Compiler not found: {self.path}"


class ClangCompiler(Compiler):
    """Clang compiler interface."""

    ARCH_TARGETS = {
        "x86_64": "x86_64-unknown-linux-gnu",
        "i386": "i386-unknown-linux-gnu",
        "arm64": "aarch64-unknown-linux-gnu",
        "arm": "armv7-unknown-linux-gnueabihf",
        "riscv64": "riscv64-unknown-linux-gnu",
        "ppc64le": "powerpc64le-unknown-linux-gnu",
        "s390x": "s390x-unknown-linux-gnu",
    }

    def __init__(self, path: str | None = None):
        super().__init__("clang", path or "clang")

    def compile_to_assembly(
        self,
        source_file: str,
        output_file: str,
        arch: str,
        optimization: str,
        extra_flags: list[str] = None,
    ) -> tuple[bool, str]:
        arch = normalize_arch(arch)
        target = self.ARCH_TARGETS.get(arch)

        cmd = [
            self.path,
            f"-{optimization}",
            "-S",  # Generate assembly
            "-fno-asynchronous-unwind-tables",
            *(["--target=" + target] if target else []),
            *(extra_flags or []),
            source_file,
            "-o",
            output_file,
        ]

        try:
            result = subprocess.run(cmd, capture_output=True, text=True)
            if result.returncode != 0:
                return False, result.stderr
            return True, ""
        except FileNotFoundError:
            return False, f"Compiler not found: {self.path}"


class GoCompiler(Compiler):
    """Go compiler interface.

    We emit assembly with ``go build -gcflags=-S`` from the source file's
    package directory, falling back to ``go tool compile -S`` for stand-
    alone files with no go.mod. Both paths produce ONLY the user package's
    assembly: no Go runtime, no scheduler, no GC. The previous
    ``go build`` + ``go tool objdump`` approach pulled in ~1k functions
    and 100k instructions of runtime code per analysis, drowning the
    user findings.

    Notes for the C-aligned harness:
     - The output is in Plan-9 / gc-S format, distinct from objdump's
       output. ``AssemblyParser.parse`` detects the format on-the-fly.
     - Source attribution is embedded as ``(/abs/path.go:NN)`` per line,
       not via ``objdump -l``. The Go branch of the parser handles this.
    """

    ARCH_MAP = {
        "x86_64": "amd64",
        "i386": "386",
        "arm64": "arm64",
        "arm": "arm",
        "riscv64": "riscv64",
        "ppc64le": "ppc64le",
        "s390x": "s390x",
    }

    def __init__(self, path: str | None = None):
        super().__init__("go", path or "go")

    def is_available(self) -> bool:
        try:
            subprocess.run(
                [self.path, "version"],
                capture_output=True,
                check=True,
            )
            return True
        except (subprocess.CalledProcessError, FileNotFoundError):
            return False

    @staticmethod
    def _find_module_root(start: Path) -> Path | None:
        cur = start.resolve()
        if cur.is_file():
            cur = cur.parent
        while True:
            if (cur / "go.mod").exists():
                return cur
            if cur.parent == cur:
                return None
            cur = cur.parent

    def compile_to_assembly(
        self,
        source_file: str,
        output_file: str,
        arch: str,
        optimization: str,
        extra_flags: list[str] = None,
    ) -> tuple[bool, str]:
        arch = normalize_arch(arch)
        goarch = self.ARCH_MAP.get(arch, arch)

        env = os.environ.copy()
        env["GOOS"] = env.get("GOOS", "linux")
        env["GOARCH"] = goarch
        env["CGO_ENABLED"] = "0"

        gcflag_parts = ["-S"]
        if optimization == "O0":
            gcflag_parts.extend(["-N", "-l"])
        gcflags = " ".join(gcflag_parts)

        src_path = Path(source_file).resolve()
        pkg_dir = src_path.parent
        module_root = self._find_module_root(src_path)

        if module_root is not None:
            try:
                with tempfile.TemporaryDirectory() as tmpdir:
                    bin_path = os.path.join(tmpdir, "discard")
                    cmd = [
                        self.path, "build",
                        "-o", bin_path,
                        "-gcflags", gcflags,
                        *(extra_flags or []),
                        ".",
                    ]
                    result = subprocess.run(
                        cmd, capture_output=True, text=True,
                        env=env, cwd=str(pkg_dir),
                    )
            except FileNotFoundError:
                return False, f"Go not found: {self.path}"
            asm_text = result.stderr  # `go build -gcflags=-S` emits to stderr
            if "TEXT\t" not in asm_text and "STEXT" not in asm_text:
                if result.returncode != 0:
                    return False, asm_text or result.stdout
                return False, "go build produced no assembly (empty package?)"
        else:
            cmd = [self.path, "tool", "compile", "-S"]
            if optimization == "O0":
                cmd.extend(["-N", "-l"])
            cmd.extend(extra_flags or [])
            cmd.append(str(src_path))
            try:
                with tempfile.TemporaryDirectory() as tmpdir:
                    result = subprocess.run(
                        cmd, capture_output=True, text=True,
                        env=env, cwd=tmpdir,
                    )
            except FileNotFoundError:
                return False, f"Go not found: {self.path}"
            asm_text = result.stdout  # `go tool compile -S` emits to stdout
            if "TEXT\t" not in asm_text and "STEXT" not in asm_text:
                msg = result.stderr or result.stdout
                if "could not import" in msg or "file not found" in msg:
                    msg += (
                        "\n\nHint: this file imports a package but is not part "
                        "of a Go module. Place it under a directory containing "
                        "go.mod (run `go mod init <name>`) and re-run."
                    )
                return False, msg

        with open(output_file, "w") as f:
            # Sentinel comment so AssemblyParser routes to the Go branch
            f.write("# ct_analyzer:format=go-gcflags-S\n")
            f.write(f"# ct_analyzer:source={src_path}\n")
            f.write(asm_text)
        return True, ""


class RustCompiler(Compiler):
    """Rust compiler interface.

    Compiles single .rs files as `--crate-type=rlib` (library) instead of
    a binary. This is critical for correctness: when a `.rs` file is built
    as a binary (`--crate-type=bin`), only `main` is a kept symbol. The
    optimizer aggressively dead-code-eliminates non-main functions, and
    when `main` calls them with compile-time-constant arguments, every
    operation gets constant-folded away. The result is that obviously
    vulnerable code (e.g. `r / two_gamma2` from KyberSlash patterns)
    leaves zero IDIV instructions in the asm and the analyzer reports
    PASSED on truly broken crypto -- a critical false negative.

    Compiling as `rlib` keeps every `pub fn` (and any `fn` reachable from
    a public item) as a real exported symbol that the optimizer cannot
    remove or fully constant-fold across.

    For Cargo projects (Cargo.toml adjacent to the source file), the
    compiler shells out to `cargo rustc --release -- --emit=asm` so that
    workspace dependencies are resolved and only the target crate's
    assembly is emitted.
    """

    ARCH_TARGETS = {
        "x86_64": "x86_64-unknown-linux-gnu",
        "i386": "i686-unknown-linux-gnu",
        "arm64": "aarch64-unknown-linux-gnu",
        "arm": "armv7-unknown-linux-gnueabihf",
        "riscv64": "riscv64gc-unknown-linux-gnu",
        "ppc64le": "powerpc64le-unknown-linux-gnu",
        "s390x": "s390x-unknown-linux-gnu",
    }

    def __init__(self, path: str | None = None):
        super().__init__("rustc", path or "rustc")

    @staticmethod
    def _find_cargo_root(source_file: str) -> str | None:
        """Walk up from source_file to find a Cargo.toml. None if standalone."""
        path = Path(source_file).resolve()
        for parent in [path.parent, *path.parents]:
            if (parent / "Cargo.toml").is_file():
                return str(parent)
        return None

    @staticmethod
    def crate_name_for(source_file: str) -> str:
        """Compute the rustc crate name for a standalone .rs file.

        rustc replaces hyphens with underscores in default crate names,
        so we normalize for stable symbol filtering.
        """
        stem = Path(source_file).stem
        return re.sub(r"[^A-Za-z0-9_]", "_", stem)

    def compile_to_assembly(
        self,
        source_file: str,
        output_file: str,
        arch: str,
        optimization: str,
        extra_flags: list[str] = None,
    ) -> tuple[bool, str]:
        arch = normalize_arch(arch)
        target = self.ARCH_TARGETS.get(arch)

        opt_level = {
            "O0": "0",
            "O1": "1",
            "O2": "2",
            "O3": "3",
            "Os": "s",
            "Oz": "z",
        }.get(optimization, "2")

        cargo_root = self._find_cargo_root(source_file)
        if cargo_root is not None:
            return self._compile_via_cargo(
                cargo_root, source_file, output_file, arch, target, opt_level, extra_flags
            )
        return self._compile_standalone(
            source_file, output_file, arch, target, opt_level, extra_flags
        )

    def _compile_standalone(
        self,
        source_file: str,
        output_file: str,
        arch: str,
        target: str | None,
        opt_level: str,
        extra_flags: list[str] | None,
    ) -> tuple[bool, str]:
        crate_name = self.crate_name_for(source_file)

        # The flag soup below is critical for correctness; see notes:
        #
        #  * `--crate-type=rlib`: don't build a binary. A binary
        #    aggressively DCEs everything except `main`, so any `pub fn`
        #    called only from `main` with constant arguments gets folded
        #    away and the analyzer reports PASSED on actually-broken
        #    crypto. With rlib, every function is a candidate for export.
        #
        #  * `-C link-dead-code=on`: rlib alone is NOT enough at
        #    `opt-level >= 1`. LLVM marks unused `pub fn` as
        #    `available_externally` linkage, which means "another CU
        #    will provide this body, don't emit it here." For our
        #    purposes that's a false negative: the user's source clearly
        #    contains the function and we need to see its asm. This
        #    flag forces every function to be emitted.
        #
        #  * `-C codegen-units=1`: ensures we get all functions in one
        #    asm file, not split across CUs we'd then have to stitch.
        #
        #  * `-C panic=abort`: removes unwinding metadata noise; the
        #    panic landing pads otherwise add ~30% noise to the asm.
        #
        #  * `-C debuginfo=1`: emit `.file` / `.loc` directives so the
        #    parser can resolve violations to source `file:line`.
        cmd = [
            self.path,
            "--emit=asm",
            "--crate-type=rlib",
            "--crate-name",
            crate_name,
            "-C",
            f"opt-level={opt_level}",
            "-C",
            "codegen-units=1",
            "-C",
            "panic=abort",
            "-C",
            "debuginfo=1",
            "-C",
            "link-dead-code=on",
            "--edition=2021",
            *(["--target", target] if target else []),
            *(extra_flags or []),
            source_file,
            "-o",
            output_file,
        ]

        try:
            result = subprocess.run(cmd, capture_output=True, text=True)
            if result.returncode != 0:
                return False, result.stderr
            return True, ""
        except FileNotFoundError:
            return False, f"Rustc not found: {self.path}"

    def _compile_via_cargo(
        self,
        cargo_root: str,
        source_file: str,
        output_file: str,
        arch: str,
        target: str | None,
        opt_level: str,
        extra_flags: list[str] | None,
    ) -> tuple[bool, str]:
        cargo = "cargo"
        env = os.environ.copy()
        # Force codegen-units=1 and panic=abort via RUSTFLAGS for clean asm.
        rustflags = env.get("RUSTFLAGS", "").split()
        # See `_compile_standalone` for why each flag is needed.
        # `link-dead-code=on` is the critical one for `pub fn` retention
        # at any opt-level >= 1.
        rustflags += [
            "--emit=asm",
            "-C",
            "codegen-units=1",
            "-C",
            "debuginfo=1",
            "-C",
            "link-dead-code=on",
        ]
        env["RUSTFLAGS"] = " ".join(rustflags)

        # Resolve the authoritative `target_directory` via `cargo metadata`
        # rather than guessing `<cargo_root>/target`. Workspaces put their
        # build output at the workspace root, not under the member crate
        # that owns the source file -- so a naive `cargo_root/target` path
        # misses the asm we just emitted.
        target_directory = self._cargo_target_directory(cargo_root, env)
        if target_directory is None:
            target_directory = Path(cargo_root) / "target"

        # Determine which member crate owns the source file so we can run
        # `cargo rustc -p <member>` and get a focused build.
        package_name = self._package_for_source(cargo_root, source_file, env)

        profile = "release" if opt_level in ("2", "3", "s", "z") else "dev"
        cmd = [cargo, "rustc"]
        if profile == "release":
            cmd.append("--release")
        if package_name:
            cmd.extend(["-p", package_name])
        if target:
            cmd.extend(["--target", target])
        cmd.extend(["--", "-C", f"opt-level={opt_level}", *(extra_flags or [])])

        try:
            result = subprocess.run(cmd, capture_output=True, text=True, cwd=cargo_root, env=env)
            if result.returncode != 0:
                return False, result.stderr
        except FileNotFoundError:
            return False, "cargo not found in PATH (required for Cargo projects)"

        # Locate the emitted .s files and concatenate into output_file.
        deps_dir = target_directory
        if target:
            deps_dir = deps_dir / target
        deps_dir = deps_dir / ("release" if profile == "release" else "debug") / "deps"

        if not deps_dir.is_dir():
            return False, f"cargo rustc did not produce expected output dir: {deps_dir}"

        # Filter to asm files belonging to the package we built (when
        # known). Without this filter a workspace build with many members
        # can dump megabytes of unrelated asm.
        glob = "*.s"
        asm_files = sorted(deps_dir.glob(glob))
        if package_name:
            normalized = package_name.replace("-", "_")
            focused = [
                a for a in asm_files if a.name.startswith(f"{normalized}-")
            ]
            if focused:
                asm_files = focused

        if not asm_files:
            return False, f"no .s files emitted in {deps_dir}"

        with open(output_file, "w") as out:
            for asm in asm_files:
                out.write(f"# === {asm.name} ===\n")
                out.write(asm.read_text())
                out.write("\n")
        return True, ""

    @staticmethod
    def _cargo_target_directory(cargo_root: str, env: dict) -> Path | None:
        """Return the authoritative target_directory from `cargo metadata`.

        Workspaces put output at the workspace root, not under the member
        crate that the source belongs to.
        """
        try:
            result = subprocess.run(
                ["cargo", "metadata", "--format-version=1", "--no-deps"],
                capture_output=True,
                text=True,
                cwd=cargo_root,
                env=env,
            )
            if result.returncode != 0:
                return None
            meta = json.loads(result.stdout)
            target = meta.get("target_directory")
            return Path(target) if target else None
        except (FileNotFoundError, json.JSONDecodeError):
            return None

    @staticmethod
    def _package_for_source(
        cargo_root: str, source_file: str, env: dict
    ) -> str | None:
        """Find the cargo package whose `src/` contains the source file."""
        try:
            result = subprocess.run(
                ["cargo", "metadata", "--format-version=1", "--no-deps"],
                capture_output=True,
                text=True,
                cwd=cargo_root,
                env=env,
            )
            if result.returncode != 0:
                return None
            meta = json.loads(result.stdout)
        except (FileNotFoundError, json.JSONDecodeError):
            return None

        src = Path(source_file).resolve()
        best_match: tuple[int, str] | None = None
        for pkg in meta.get("packages", []):
            manifest = Path(pkg["manifest_path"]).resolve().parent
            try:
                rel = src.relative_to(manifest)
            except ValueError:
                continue
            depth = len(manifest.parts)
            name = pkg["name"]
            if best_match is None or depth > best_match[0]:
                best_match = (depth, name)
        return best_match[1] if best_match else None


class SwiftCompiler(Compiler):
    """Swift compiler interface for iOS/macOS development."""

    ARCH_TARGETS = {
        "x86_64": "x86_64-apple-macosx10.15",
        "arm64": "arm64-apple-macosx11.0",
        # iOS targets
        "arm64-ios": "arm64-apple-ios13.0",
        "arm64-ios-sim": "arm64-apple-ios13.0-simulator",
        "x86_64-ios-sim": "x86_64-apple-ios13.0-simulator",
    }

    def __init__(self, path: str | None = None):
        super().__init__("swiftc", path or "swiftc")

    def compile_to_assembly(
        self,
        source_file: str,
        output_file: str,
        arch: str,
        optimization: str,
        extra_flags: list[str] = None,
    ) -> tuple[bool, str]:
        arch = normalize_arch(arch)
        target = self.ARCH_TARGETS.get(arch)

        opt_level = {
            "O0": "-Onone",
            "O1": "-O",
            "O2": "-O",
            "O3": "-O",
            "Os": "-Osize",
            "Oz": "-Osize",
        }.get(optimization, "-O")

        cmd = [
            self.path,
            "-emit-assembly",
            opt_level,
            *(["-target", target] if target else []),
            *(extra_flags or []),
            source_file,
            "-o",
            output_file,
        ]

        try:
            result = subprocess.run(cmd, capture_output=True, text=True)
            if result.returncode != 0:
                return False, result.stderr
            return True, ""
        except FileNotFoundError:
            return False, f"Swift compiler not found: {self.path}"


def get_compiler(name: str, language: str) -> Compiler:
    """Get a compiler instance by name or detect from language."""
    compilers = {
        "gcc": GCCCompiler,
        "clang": ClangCompiler,
        "go": GoCompiler,
        "rustc": RustCompiler,
        "swiftc": SwiftCompiler,
    }

    if name:
        if name in compilers:
            return compilers[name]()
        # Assume it's a path to a compiler
        return ClangCompiler(name)

    # Auto-detect based on language
    if language == "go":
        return GoCompiler()
    elif language == "rust":
        return RustCompiler()
    elif language == "swift":
        return SwiftCompiler()
    else:
        # Default to clang for C/C++
        return ClangCompiler()


def _decimal_pc_to_addr(instrs: list[dict], pc: int) -> int:
    """Map a Go gc-S decimal pc (the second column, e.g. ``00024``) to the
    hex byte-offset (``addr_int``) of the matching instruction. Go's
    branch operands use the decimal pc form; the panic-block address set
    is built from addr_int. We look up by linear scan -- O(n) but n is
    typically small per function."""
    for ins in instrs:
        # The second column is exactly the decimal int of addr_int
        if ins["addr_int"] == pc:
            return ins["addr_int"]
    return -1


# Rust legacy mangling escape sequences. The new `v0` mangling (`_R...`) is
# also handled below where we strip its `::h<hex>` hash suffix.
_RUST_LEGACY_ESCAPES = {
    "$SP$": "@",
    "$BP$": "*",
    "$RF$": "&",
    "$LT$": "<",
    "$GT$": ">",
    "$LP$": "(",
    "$RP$": ")",
    "$C$": ",",
    "$u20$": " ",
    "$u22$": '"',
    "$u23$": "#",
    "$u27$": "'",
    "$u2b$": "+",
    "$u3b$": ";",
    "$u5b$": "[",
    "$u5d$": "]",
    "$u7b$": "{",
    "$u7d$": "}",
    "$u7e$": "~",
    ".": "-",
    "..": "::",
}


def demangle_rust(symbol: str) -> str | None:
    """Demangle a Rust mangled symbol (legacy `_ZN...E` form).

    Returns the demangled `crate::module::function` form, or None if the
    symbol is not a Rust mangled name. The trailing `17h<hash>E`
    disambiguator is stripped.

    The newer v0 format (`_R...`) is partially handled by stripping the
    common hash suffix; full v0 demangling requires the rustc-demangle
    crate. For our purposes the asm symbols are still recognizable.
    """
    if not symbol:
        return None

    # v0: just strip the leading _R and any trailing hash; we don't fully
    # decode, but the symbol is still usable for filtering.
    if symbol.startswith("_R"):
        return symbol  # caller filters using the raw form

    if not symbol.startswith("_ZN") or not symbol.endswith("E"):
        return None

    body = symbol[3:-1]
    components: list[str] = []
    i = 0
    while i < len(body):
        j = i
        while j < len(body) and body[j].isdigit():
            j += 1
        if j == i:
            return None  # malformed
        try:
            length = int(body[i:j])
        except ValueError:
            return None
        end = j + length
        if end > len(body):
            return None
        component = body[j:end]
        # Apply Rust legacy escape sequences (longest match first).
        for esc, repl in sorted(
            _RUST_LEGACY_ESCAPES.items(), key=lambda kv: -len(kv[0])
        ):
            component = component.replace(esc, repl)
        components.append(component)
        i = end

    # Strip the disambiguator `h<16-hex>` if present.
    if components and re.match(r"^h[0-9a-f]{16}$", components[-1]):
        components = components[:-1]

    if not components:
        return None
    return "::".join(components)


def rust_crate_of(symbol_or_demangled: str) -> str | None:
    """Return the crate name (first path component) of a demangled Rust path.

    For a raw mangled symbol, demangles first. Returns None if unknown.

    Handles `<impl Trait for Type>::method` style names, which legacy
    mangling produces as `_<crate::...>::method` after applying the `$LT$`
    / `$GT$` escapes.

    For `<Type as TraitPath>::method` form (e.g. `<i64 as core::ops::Div>::div`),
    the leading "crate" is actually a type name (`i64`, `usize`, `bool`).
    The actual implementation crate is the trait's defining crate, which
    appears as a path component later. We scan all path components and
    prefer a match against `RUST_STDLIB_CRATES` so that stdlib trait
    impls monomorphized into the user's binary are correctly classified.
    """
    s = symbol_or_demangled
    if s.startswith("_ZN") or s.startswith("_R"):
        d = demangle_rust(s)
        if d is None:
            return None
        s = d

    # Strip leading `_<` / `<` from impl-block demangling: the crate is the
    # first path component inside the angle brackets.
    while s.startswith(("_<", "<")):
        s = s[2:] if s.startswith("_<") else s[1:]

    if not s:
        return None

    # Scan all path-component tokens. If any is a known stdlib crate,
    # prefer that. Required for `<i64 as core::ops::Div>::div`-style
    # symbols where the leading `i64` is a primitive type, not a crate.
    tokens = re.findall(r"[A-Za-z_][A-Za-z0-9_]*", s)
    for t in tokens:
        if t in RUST_STDLIB_CRATES:
            return t

    # Otherwise, the first identifier is the crate name.
    head = re.match(r"^([A-Za-z_][A-Za-z0-9_]*)", s)
    return head.group(1) if head else None


# Standard-library / language-runtime crates whose monomorphizations are
# pulled into user crates by inlining. We never report violations in these
# unless the user passes --include-stdlib (e.g. for forensic review).
RUST_STDLIB_CRATES = frozenset(
    {
        "core",
        "alloc",
        "std",
        "panic_abort",
        "panic_unwind",
        "compiler_builtins",
        "rustc_std_workspace_core",
        "rustc_std_workspace_alloc",
        "rustc_std_workspace_std",
        "proc_macro",
        "test",
        "unwind",
        "backtrace",
        "addr2line",
        "object",
        "miniz_oxide",
        "adler",
        "hashbrown",
        "rustc_demangle",
        "gimli",
    }
)


# Triage hint values. The convention: a `*_likely_fp` hint says a
# downstream agent can confidently file as a false positive; a
# `*_review` hint demands per-line review. The full taxonomy is
# documented in references/rust.md.
TRIAGE_STDLIB_ITER_END = "stdlib_iter_end_likely_fp"
TRIAGE_STDLIB_BOUNDS = "stdlib_bounds_check_likely_fp"
TRIAGE_STDLIB_OTHER = "stdlib_other_likely_fp"
TRIAGE_DEPENDENCY = "dependency_source_review"
TRIAGE_FN_DECL = "fn_declaration_dispatch_likely_fp"
TRIAGE_LOOP_BOUND = "user_loop_bound_likely_fp"
TRIAGE_REJECTION_LOOP = "rejection_sample_loop_likely_fp"
TRIAGE_ITER_LOOP = "iterator_loop_likely_fp"
TRIAGE_LEN_COMPARE = "public_length_compare_likely_fp"
# `vartime_*` is a Rust crypto convention for explicitly-variable-time
# code paths whose operands are public (signature verification,
# public-key-only operations, batch verification). The convention is
# enforced in audited crypto crates: curve25519-dalek, ed25519-dalek,
# k256/p256/p384, rsa, ring. A branch in a `vartime_*` function is
# almost always a false positive at the crypto level.
TRIAGE_VARTIME = "vartime_function_likely_fp"
TRIAGE_RODATA_COMPARE = "compare_to_constant_likely_fp"
TRIAGE_EARLY_RETURN_CMP = "early_return_compare_review"
TRIAGE_USER_REVIEW = "user_code_review"
TRIAGE_NEEDS_REVIEW = "needs_review"


def _read_source_snippet(file_path: str, line: int, ctx: int = 2) -> list[str] | None:
    """Read a (2*ctx+1)-line window of `file_path` centered on `line`.

    Returns None if the file is unreadable (e.g. /rustc/<commit>/...
    paths from rustc's debug info, which are virtual unless rust-src
    is installed). Lines are returned without trailing newlines.
    """
    if not file_path or not line or line < 1:
        return None
    try:
        with open(file_path, encoding="utf-8", errors="replace") as f:
            lines = f.readlines()
    except (OSError, UnicodeDecodeError):
        return None
    start = max(0, line - 1 - ctx)
    end = min(len(lines), line + ctx)
    return [lines[i].rstrip("\n") for i in range(start, end)]


# Stdlib path markers. Order matters: most specific first; the bare
# `/rustc/` fallback is the last resort.
_STDLIB_PATH_MARKERS = (
    ("/library/core/src/iter/",                TRIAGE_STDLIB_ITER_END),
    ("/library/core/src/slice/iter/",          TRIAGE_STDLIB_ITER_END),
    ("/library/core/src/ops/index_range",      TRIAGE_STDLIB_ITER_END),
    ("/library/core/src/slice/",               TRIAGE_STDLIB_BOUNDS),
    ("/rustc/",                                TRIAGE_STDLIB_OTHER),
)
_DEPENDENCY_MARKERS = (
    "/.cargo/registry/",
    "/.cargo/git/",
    "\\.cargo\\registry\\",
    "/cargo/registry/",
)
_FN_DECL_RE = re.compile(
    r"^\s*(?:#\[[^\]]+\]\s*)*"             # optional attributes
    r"(?:pub(?:\s*\(\s*[\w:]+\s*\))?\s+)?"  # pub / pub(crate)
    r"(?:async\s+)?(?:unsafe\s+)?"
    r"(?:const\s+)?fn\s+\w"
)
_FOR_RANGE_LITERAL_RE = re.compile(r"^\s*for\s+\w+\s+in\s+0\.\.\s*[A-Z_][A-Z0-9_]*")
_FOR_RANGE_NUMBER_RE = re.compile(r"^\s*for\s+\w+\s+in\s+0\.\.\s*[0-9]")
# `for x in buf.iter()`, `for x in buf.iter_mut()`, `for x in buf.into_iter()`,
# `for x in &buf`, etc. The loop bound is the container's length, which is
# typically public (slice length, fixed-size array, message length).
_FOR_ITER_RE = re.compile(
    r"^\s*for\s+\w+\s+in\s+(?:&\s*)?\w+"
    r"(?:\s*\.\s*(?:iter|iter_mut|into_iter|chunks|chunks_mut|chunks_exact|"
    r"chunks_exact_mut|windows|enumerate|zip)\([^)]*\))?\s*\{?"
)
_REJECTION_LOOP_RE = re.compile(r"^\s*while\s+!?\s*done\b|^\s*while\s+\w+\s*<\s*[A-Z_][A-Z0-9_]*\b")
_CMP_TO_UPPER_CONST_RE = re.compile(r"<\s*[A-Z_][A-Z0-9_]+\b|>\s*[A-Z_][A-Z0-9_]+\b|==\s*[A-Z_][A-Z0-9_]+\b")
# `if a.len() != b.len()`, `if x.is_empty()`, `if buf.len() < 16`, etc.
# Length / emptiness checks are on metadata that is virtually always
# public (slice length is structural, not content-derived).
_LEN_COMPARE_RE = re.compile(
    r"^\s*if\s+"
    r"(?:[\w.]+\.\s*(?:len|is_empty|is_zero)\s*\(\s*\)|[\w.]+\.\s*len\s*\(\s*\))"
    r"\s*(?:[!<>=]+|&&|\|\|)"
)
_EARLY_RETURN_RE = re.compile(
    r"^\s*if\s+.+\s*(?:!=|==)\s*\w+(?:\[.+\])?\s*\{\s*$|"  # if a != b {
    r"return\s+\w+\s*[!=]=\s*"                              # return a == b ...
)


def classify_violation(
    violation: "Violation", source_snippet: list[str] | None = None
) -> str:
    """Apply rules A-F to assign a triage hint.

    The classifier is intentionally simple and conservative: when a rule
    doesn't fire cleanly, we return TRIAGE_NEEDS_REVIEW so the case
    surfaces to the reviewer. False positives in the classifier (saying
    "FP" when it's actually a TP) are far worse than false negatives
    (saying "review" when it's actually FP), so all `*_likely_fp` rules
    require a positive match against a path or pattern, never a
    negative one.
    """
    file_path = violation.file or ""
    line = violation.line
    function = (violation.function or "")

    # Rule V (function naming): the Rust crypto convention for
    # variable-time code paths uses `vartime` as part of the function
    # name. Two common forms in audited crates:
    #   - prefix:  `vartime_double_base_mul` (dalek)
    #   - suffix:  `pow_vartime`, `sqn_vartime` (k256/p256, bls12_381)
    # Both forms denote "this function is variable-time on PUBLIC
    # operands by design" -- callers pass signatures, public keys,
    # public scalars, public exponents. High-confidence FP.
    import re as _re
    if _re.search(
        r"(?:^|::|<|\b)vartime_|"      # `vartime_foo` (prefix)
        r"_vartime(?:$|::|>|\b)",       # `foo_vartime` (suffix)
        function,
    ):
        return TRIAGE_VARTIME

    # Rules A & B: stdlib path, most specific marker wins.
    for marker, hint in _STDLIB_PATH_MARKERS:
        if marker in file_path:
            return hint

    # Rule C: cargo dependency.
    if any(m in file_path for m in _DEPENDENCY_MARKERS):
        return TRIAGE_DEPENDENCY

    # Source-snippet-driven rules require the file to be readable.
    if not source_snippet:
        return TRIAGE_NEEDS_REVIEW

    # The middle line of the snippet is the cited source line.
    mid = len(source_snippet) // 2
    cited = source_snippet[mid] if 0 <= mid < len(source_snippet) else ""

    # Rule D: warning attributed to a `fn ... <...>` declaration line.
    # rustc points the .loc directive at the function header for
    # const-generic instantiation dispatch code that has no real source
    # location of its own.
    if _FN_DECL_RE.match(cited):
        return TRIAGE_FN_DECL

    # Rule E: rejection-sampling-style loop (while !done, while x < N).
    # Kyber/Dilithium use these and the loop bound depends on a hash of
    # PUBLIC randomness (the seed sent in the public ciphertext).
    if _REJECTION_LOOP_RE.match(cited):
        return TRIAGE_REJECTION_LOOP

    # Rule F1: `for i in 0..PUBLIC_CONST` loop -- iteration count is a
    # compile-time constant or an UPPER_SNAKE_CASE module constant.
    if _FOR_RANGE_LITERAL_RE.match(cited) or _FOR_RANGE_NUMBER_RE.match(cited):
        return TRIAGE_LOOP_BOUND

    # Rule F1b: `for x in container.iter()` / `for x in &container` --
    # iteration count is the container length, which is metadata, not
    # contents. The textbook example: `for b in buf.iter_mut() { b ^= 0; }`
    # is constant-time despite emitting a JE/JNE for the iterator end.
    if _FOR_ITER_RE.match(cited):
        return TRIAGE_ITER_LOOP

    # Rule F2: comparison against an UPPER_SNAKE_CASE constant. Captures
    # the libcrux `if sampled_coefficients[i] < COEFFICIENTS_IN_RING_ELEMENT`
    # pattern that the asm-level cmp-imm filter misses because the
    # constant is loaded into a register before the cmp.
    if _CMP_TO_UPPER_CONST_RE.search(cited):
        return TRIAGE_RODATA_COMPARE

    # Rule F3: length / emptiness check at the head of a function.
    # `if a.len() != b.len() { return ... }` is the canonical Rust idiom
    # for length-mismatch handling; `len()` is metadata, not content.
    if _LEN_COMPARE_RE.match(cited):
        return TRIAGE_LEN_COMPARE

    # Rule G: textbook early-exit-compare pattern. This is the textbook
    # MAC-tag-mismatch / padding-oracle bug. We mark for review, NOT as
    # FP, because this is the most likely place for a real finding.
    if _EARLY_RETURN_RE.search(cited):
        return TRIAGE_EARLY_RETURN_CMP

    return TRIAGE_USER_REVIEW


class AssemblyParser:
    """Parser for assembly output from various compilers."""

    # Functions whose name implies the developer claimed constant-time
    # behavior. In `strict` mode, any conditional-branch warning inside
    # one of these is promoted to ERROR -- a branch in a function named
    # `verify_tag` or `ct_eq` is a regression on its stated contract.
    _STRICT_PROMOTE_FUNC_RE = re.compile(
        r"(?:^|::)(?:"
        r"verify\w*|"
        r"compare\w*|"
        r"equals?\w*|"
        r"ct_\w+|"
        r"constant_time_\w*|"
        r"in_constant_time|"
        r"select_\w*_in_constant_time"
        r")(?:::|$)"
    )

    # Heuristic: if a branch follows `cmp <reg>, $<imm>` (AT&T) or
    # `cmp <reg>, #<imm>` (ARM) or `test <reg>, <reg>` (zero-test idiom),
    # the test is on a literal -- secrets are rarely compared to small
    # constants. Almost all `for i in 0..len` loop-control warnings
    # collapse via this rule.
    _CMP_IMM_RE = re.compile(
        r"^(?:cmp[bwlq]?\s+\$-?[0-9]|"  # AT&T x86: cmp $0, %r
        r"cmp\s+\w+,\s*#-?[0-9]|"        # ARM: cmp r, #imm
        r"cmp[bwlq]?\s+\$-?[0-9]+,)"     # AT&T x86 with explicit second op
    )
    _TEST_SELF_RE = re.compile(r"^test[bwlq]?\s+(%\w+),\s*\1\s*$")

    # Stdlib panic functions: a `call` to any of these from a branch
    # target marks that label as a panic block.
    _PANIC_CALL_RE = re.compile(
        r"_ZN(?:[0-9]+core[0-9]+panicking|"
        r"[0-9]+std[0-9]+panicking|"
        r"[0-9]+core5slice[0-9]+index)|"
        r"__rust_panic|"
        r"panic_bounds_check|"
        r"_ZN4core5slice5index"
    )

    def __init__(
        self,
        arch: str,
        compiler: str,
        rust_user_crate: str | None = None,
        include_stdlib: bool = False,
        strict: bool = False,
        precise_warnings: bool = True,
    ):
        self.arch = normalize_arch(arch)
        self.compiler = compiler
        self.rust_user_crate = rust_user_crate
        self.include_stdlib = include_stdlib
        self.strict = strict
        self.precise_warnings = precise_warnings

        # Get dangerous instructions for this architecture
        if self.arch not in DANGEROUS_INSTRUCTIONS:
            print(
                f"Warning: Architecture '{self.arch}' is not supported. "
                f"Supported architectures: {', '.join(DANGEROUS_INSTRUCTIONS.keys())}. "
                "No timing violations will be detected.",
                file=sys.stderr,
            )
            self.errors = {}
            self.warnings = {}
        else:
            arch_instructions = DANGEROUS_INSTRUCTIONS[self.arch]
            self.errors = arch_instructions.get("errors", {})
            self.warnings = arch_instructions.get("warnings", {})

    # Go-specific format detection (the gc compiler's `-S` output is
    # syntactically different from objdump or gcc/clang -S). The parser
    # routes to a dedicated branch below when it sees the sentinel comment
    # we emit in GoCompiler or the characteristic STEXT-family directive.
    _GO_INSTR_RE = re.compile(
        r"^\s*0x[0-9a-fA-F]+\s+\d+\s+\(([^)]+):(\d+)\)\s+([A-Za-z][\w.]*)\b(.*)$"
    )
    _GO_FUNC_HEADER_RE = re.compile(
        r"^([\w./<>$\-]*\.[\w<>$]+)\s+S\w*TEXT\w*\b"
    )

    def _should_skip_function(self, raw_symbol: str | None) -> bool:
        """Decide whether to ignore violations in this function.

        For Rust, monomorphized stdlib code (`core::*`, `alloc::*`,
        `std::*`, plus a few support crates) gets pulled into the user
        crate's asm by inlining. Reporting `DIVQ` or `DIVSD` in
        `core::fmt::Formatter::pad` is just noise -- the user can't fix
        it. We drop those by default; `--include-stdlib` brings them
        back for forensic review.

        We also filter to the user's crate when known, so any non-stdlib
        third-party crate that gets monomorphized is reported only when
        explicitly opted into.
        """
        if self.include_stdlib or self.compiler != "rustc" or not raw_symbol:
            return False
        crate = rust_crate_of(raw_symbol)
        if crate is None:
            return False
        if crate in RUST_STDLIB_CRATES:
            return True
        if self.rust_user_crate and crate != self.rust_user_crate:
            return True
        return False

    @classmethod
    def _is_cmp_to_literal(cls, prev_line: str) -> bool:
        """True if the previous asm line is `cmp <reg>, $<imm>` style.

        Branches that follow a compare-to-literal almost always test
        public iteration state (`for i in 0..len`) or argument
        validation (`if x.is_empty()`). Secrets are rarely compared
        against compile-time constants. The libcrux ML-KEM validation
        showed this filter eliminates ~80% of warning noise without
        suppressing any of the four CVE-derived vulnerable patterns.
        """
        if not prev_line:
            return False
        s = prev_line.strip()
        return bool(cls._CMP_IMM_RE.match(s) or cls._TEST_SELF_RE.match(s))

    @classmethod
    def _branches_to_panic(cls, instruction: str, panic_labels: set[str]) -> bool:
        """True if a conditional branch's target label is a panic block.

        Bounds checks, divide-by-zero checks, and unwrap-on-None all
        compile to `cmp; jcc <panic-label>`. The `<panic-label>` block
        does nothing but call `core::panicking::*` and abort. Such
        branches are not exploitable as timing oracles -- the panic
        path is taken at most once before the program dies.
        """
        if not panic_labels:
            return False
        # Branch targets are the last whitespace-delimited token, often
        # `.LBB0_5` or similar. We allow trailing punctuation.
        parts = instruction.split()
        if not parts:
            return False
        target = parts[-1].rstrip(",;")
        # Strip any leading `*` (indirect branches don't have a static target).
        if target.startswith("*"):
            return False
        return target in panic_labels

    @classmethod
    def _is_strict_promote_function(cls, function_name: str) -> bool:
        """True if the function's demangled name claims constant-time."""
        return bool(cls._STRICT_PROMOTE_FUNC_RE.search(function_name))

    @staticmethod
    def _is_third_party_source(file_path: str) -> bool:
        """True if the source path lives in stdlib or a cargo dependency.

        Used to gate `--strict` promotion: a JNE at
        `~/.cargo/registry/.../subtle/src/lib.rs:318` is a contract
        of the upstream crate, not a regression of the user's code.
        """
        if not file_path:
            return False
        third_party_markers = (
            "/rustc/",                 # std/core/alloc
            "/.cargo/registry/",       # cargo deps (linux/mac home)
            "\\.cargo\\registry\\",    # cargo deps (windows)
            "/.cargo/git/",            # cargo git deps
            "/cargo/registry/",        # CI without leading dot
        )
        return any(marker in file_path for marker in third_party_markers)

    @classmethod
    def _scan_panic_labels(cls, assembly_text: str) -> set[str]:
        """Find labels whose body calls a stdlib panic function.

        The scanner is intentionally simple: it walks the asm tracking
        the most-recent local label (`.L*:`); whenever it sees a
        line containing a stdlib-panic call symbol, it marks that
        label as a panic block. Cross-block flow (a panic block
        whose first line is `jmp <other_label>` reaching the panic
        only transitively) is not handled, but in practice rustc emits
        the panic call inline in the same block as the entry label.
        """
        panic = set()
        current_label: str | None = None
        for raw in assembly_text.split("\n"):
            line = raw.strip()
            if not line:
                continue
            # Local label: `.L<...>:`
            m = re.match(r"^(\.L[\w$.]+):\s*$", line)
            if m:
                current_label = m.group(1)
                continue
            # New function (top-level mangled symbol followed by `:`):
            # reset so panic labels from one fn don't bleed to the next.
            if re.match(r"^[A-Za-z_][\w$.:]*:\s*$", line) and not line.startswith(".L"):
                current_label = None
                continue
            # Skip directives.
            if line.startswith("."):
                continue
            # Detect a call to a stdlib panic function.
            if current_label and ("call" in line.split()[0] if line.split() else False):
                if cls._PANIC_CALL_RE.search(line):
                    panic.add(current_label)
        return panic

    def parse(
        self, assembly_text: str, include_warnings: bool = False
    ) -> tuple[list[dict], list[Violation]]:
        """
        Parse assembly text and detect violations.
        Returns (functions, violations).
        """
        head = assembly_text[:8192]
        if (
            "ct_analyzer:format=go-gcflags-S" in head
            or re.search(r"\bS\w*TEXT\w*\b", head)
        ):
            return self._parse_go_format(assembly_text, include_warnings)

        functions = []
        violations = []

        # Pre-scan local labels that are panic landing pads. Branches
        # whose destination lives in one of these blocks are unreachable
        # on the happy path and not exploitable as a timing oracle, so
        # we drop their warnings under `precise_warnings`.
        panic_labels: set[str] = set()
        if include_warnings and self.precise_warnings:
            panic_labels = self._scan_panic_labels(assembly_text)

        current_function = None  # display name (demangled for Rust)
        current_raw_symbol = None  # mangled symbol (for crate filtering)
        current_file = None
        prev_instruction_line = ""  # for cmp-imm-then-branch filter
        current_line = None
        instruction_count = 0
        recent: list[str] = []          # last N instructions in current function
        pending_after: list[tuple[Violation, int]] = []  # (violation, remaining)

        # `.file <id> "path"` mapping for resolving `.loc <id>` directives.
        file_table: dict[int, str] = {}

        all_lines = assembly_text.split("\n")
        for line in all_lines:
            line = line.strip()

            # objdump -l emits source attributions as bare lines:
            #   /abs/path/to/file.c:1593 (discriminator 1)
            # before the next instruction.  Pick those up *before* the
            # empty/comment skip, so the parser tracks current_file/line
            # for every following instruction in the function body.
            objdump_src = re.match(
                r"^(/[^:]+\.(c|cc|cpp|cxx|h|hpp|S|s)):(\d+)(?:\s*\(.*\))?$",
                line,
            )
            if objdump_src:
                current_file = objdump_src.group(1)
                current_line = int(objdump_src.group(3))
                continue

            # Skip empty lines and comments
            if not line or line.startswith("#") or line.startswith("//") or line.startswith(";"):
                # Check for file/line info in inline comments (gcc/clang -S style)
                file_match = re.search(r"#\s*([^:]+):(\d+)", line)
                if file_match:
                    current_file = file_match.group(1)
                    current_line = int(file_match.group(2))
                continue

            # `.file 1 "/abs/path/source.rs"` -- registers a debug file.
            file_dir = re.match(r'^\.file\s+(\d+)\s+(?:"([^"]+)"\s+)?"([^"]+)"', line)
            if file_dir:
                fid = int(file_dir.group(1))
                # Form 1: .file <id> "path" -> group(2)=None, group(3)=path
                # Form 2: .file <id> "dir" "name" -> group(2)=dir, group(3)=name
                if file_dir.group(2):
                    file_table[fid] = file_dir.group(2).rstrip("/") + "/" + file_dir.group(3)
                else:
                    file_table[fid] = file_dir.group(3)
                continue

            # `.loc <file_id> <line> <column>` -- rustc/clang debug info.
            loc_dir = re.match(r"^\.loc\s+(\d+)\s+(\d+)", line)
            if loc_dir:
                fid = int(loc_dir.group(1))
                current_file = file_table.get(fid, current_file)
                current_line = int(loc_dir.group(2))
                continue

            # Detect function start (various formats).
            func_match = (
                # GCC/Clang/rustc: optionally-mangled `symbol:`
                # Mangled Rust names contain `$`, `.`, `:` -- broaden the charset.
                re.match(r"^([A-Za-z_][\w$.:]*):$", line)
                or
                # Go objdump: TEXT symbol_name(SB) file
                re.match(r"^TEXT\s+([^\s(]+)\(SB\)", line)
                or
                # With .type directive (mangled symbols allowed)
                re.match(r"\.type\s+([A-Za-z_][\w$.:]*),\s*[@%]function", line)
                or
                # objdump -d:  0000000000000000 <function_name>:
                re.match(r"^[0-9a-fA-F]+\s+<([a-zA-Z_][\w.]*)>:", line)
            )

            if func_match:
                if current_function:
                    functions.append(
                        {
                            "name": current_function,
                            "instructions": instruction_count,
                        }
                    )
                raw = func_match.group(1)
                current_raw_symbol = raw
                # Demangle Rust symbols for human-readable display.
                if self.compiler == "rustc":
                    demangled = demangle_rust(raw)
                    current_function = demangled or raw
                else:
                    current_function = raw
                instruction_count = 0
                recent = []
                pending_after = []
                continue

            # Skip directives
            if line.startswith("."):
                continue

            # Parse instruction
            # Handle various formats:
            # - "   mov    %rax, %rbx"
            # - "   0x1234   mov %rax, %rbx"
            # - "   file:10   0x1234   aabbccdd   mov %rax, %rbx"

            instruction = line
            address = ""

            # Extract address if present
            addr_match = re.search(r"0x([0-9a-fA-F]+)", line)
            if addr_match:
                address = "0x" + addr_match.group(1)

            # Extract mnemonic (first word-like token that's not an address or file ref)
            parts = line.split()
            mnemonic = ""
            for part in parts:
                # Skip addresses, hex bytes, file references
                if part.startswith("0x") or re.match(r"^[0-9a-fA-F]{2,}$", part):
                    continue
                if ":" in part and not part.endswith(":"):  # file:line reference
                    continue
                # objdump address prefixes look like "123:" or "ffff:" - all-hex with trailing colon.
                # Skip them: a real mnemonic is alphanumeric (with optional . for AT&T suffixes / ARM).
                if part.endswith(":") and re.match(r"^[0-9a-fA-F]+:$", part):
                    continue
                # This should be the mnemonic
                mnemonic = part.lower().rstrip(":")
                break

            if not mnemonic:
                continue

            instruction_count += 1

            # Filter out monomorphized stdlib code (Rust) so the user
            # sees vulnerabilities in their own crate, not in `core::fmt`.
            if self._should_skip_function(current_raw_symbol):
                prev_instruction_line = instruction
                continue

            # Feed any open "after" windows
            for v, _ in pending_after:
                v.context_after.append(instruction)
            pending_after = [(v, n - 1) for v, n in pending_after if n > 1]

            # Check for violations
            new_v = None
            if mnemonic in self.errors:
                new_v = Violation(
                    function=current_function or "<unknown>",
                    file=current_file or "",
                    line=current_line,
                    address=address,
                    instruction=instruction,
                    mnemonic=mnemonic.upper(),
                    reason=self.errors[mnemonic],
                    severity=Severity.ERROR,
                    context_before=list(recent[-6:]),
                )
            elif include_warnings and mnemonic in self.warnings:
                # Apply warning-precision filters. These exist because
                # treating every JE/JNE as suspect drowns the real
                # signal under loop-control noise. Each filter has been
                # vetted against the libcrux ML-KEM corpus to ensure it
                # doesn't suppress real findings.
                if self.precise_warnings:
                    if self._is_cmp_to_literal(prev_instruction_line):
                        prev_instruction_line = instruction
                        continue
                    if self._branches_to_panic(instruction, panic_labels):
                        prev_instruction_line = instruction
                        continue

                # `--strict`: a branch inside a function whose name
                # claims constant-time behavior is a contract regression.
                # We only promote when the source location is in user
                # code (not stdlib at `/rustc/...` or a cargo dependency
                # at `~/.cargo/registry/...`), because vetted CT crates
                # like `subtle` legitimately have JNE on public-length
                # checks that are part of their public API contract.
                severity = Severity.WARNING
                if (
                    self.strict
                    and self._is_strict_promote_function(current_function or "")
                    and not self._is_third_party_source(current_file or "")
                ):
                    severity = Severity.ERROR

                new_v = Violation(
                    function=current_function or "<unknown>",
                    file=current_file or "",
                    line=current_line,
                    address=address,
                    instruction=instruction,
                    mnemonic=mnemonic.upper(),
                    reason=self.warnings[mnemonic],
                    severity=severity,
                    context_before=list(recent[-6:]),
                )
            if new_v is not None:
                violations.append(new_v)
                pending_after.append((new_v, 4))

            recent.append(instruction)
            if len(recent) > 8:
                recent.pop(0)

            prev_instruction_line = instruction

        # Don't forget the last function
        if current_function:
            functions.append(
                {
                    "name": current_function,
                    "instructions": instruction_count,
                }
            )

        if self.precise_warnings and include_warnings:
            violations = self._aggregate_warnings(violations)

        # Attach source snippet + triage hint to every violation. This
        # is the data a downstream agent needs to mechanically classify
        # findings without re-reading the source. We do it as a single
        # post-pass so we read each source file at most once.
        self._attach_triage_metadata(violations)

        return functions, violations

    def _parse_go_format(
        self, assembly_text: str, include_warnings: bool
    ) -> tuple[list[dict], list[Violation]]:
        """Parse Go's gc-S output. Two-pass: pass 1 collects per-function
        instruction tuples; pass 2 emits violations with cross-instruction
        context (most importantly, recognizing branches whose target is a
        Go panic helper so the bounds-check filter can suppress them)."""
        per_func: list[tuple[str, list[dict]]] = []
        cur_fn: str | None = None
        cur: list[dict] = []
        for line in assembly_text.split("\n"):
            header = self._GO_FUNC_HEADER_RE.match(line)
            if header:
                if cur_fn is not None:
                    per_func.append((cur_fn, cur))
                cur_fn = header.group(1)
                cur = []
                continue
            instr = self._GO_INSTR_RE.match(line)
            if not instr:
                continue
            mnemonic = instr.group(3).lower()
            if mnemonic in ("text", "funcdata", "pcdata", "rel", "type"):
                continue
            addr_match = re.search(r"0x([0-9a-fA-F]+)", line)
            cur.append({
                "file": instr.group(1),
                "line": int(instr.group(2)),
                "mnemonic": mnemonic,
                "operands": instr.group(4).strip(),
                "addr_int": int(addr_match.group(1), 16) if addr_match else -1,
                "addr_str": f"0x{addr_match.group(1)}" if addr_match else "",
                "raw": line.strip(),
            })
        if cur_fn is not None:
            per_func.append((cur_fn, cur))

        functions: list[dict] = []
        violations: list[Violation] = []
        for fn_name, instrs in per_func:
            functions.append({"name": fn_name, "instructions": len(instrs)})

            # Build set of "panic block" addresses: the address of each CALL
            # to a Go panic helper plus the 1-4 setup instructions
            # immediately before it.
            panic_addrs: set[int] = set()
            for i, ins in enumerate(instrs):
                if ins["mnemonic"] != "call":
                    continue
                callee = ins["operands"].split("(", 1)[0].strip()
                if not callee.startswith("runtime.panic"):
                    continue
                panic_addrs.add(ins["addr_int"])
                for k in range(1, 5):
                    j = i - k
                    if j < 0:
                        break
                    panic_addrs.add(instrs[j]["addr_int"])

            # Emit violations and tag bounds-check candidates inline.
            recent: list[str] = []
            pending_after: list[tuple[Violation, int]] = []
            for i, ins in enumerate(instrs):
                # Feed the after-window first
                for v, _ in pending_after:
                    v.context_after.append(ins["raw"])
                pending_after = [(v, n - 1) for v, n in pending_after if n > 1]

                m = ins["mnemonic"]
                new_v = None
                if m in self.errors:
                    new_v = Violation(
                        function=fn_name, file=ins["file"], line=ins["line"],
                        address=ins["addr_str"], instruction=ins["raw"],
                        mnemonic=m.upper(), reason=self.errors[m],
                        severity=Severity.ERROR,
                        context_before=list(recent[-6:]),
                    )
                elif include_warnings and m in self.warnings:
                    new_v = Violation(
                        function=fn_name, file=ins["file"], line=ins["line"],
                        address=ins["addr_str"], instruction=ins["raw"],
                        mnemonic=m.upper(), reason=self.warnings[m],
                        severity=Severity.WARNING,
                        context_before=list(recent[-6:]),
                    )
                if new_v is not None:
                    # Bounds-check tag: if this branch's explicit target OR
                    # its fall-through within 2 instructions reaches a panic
                    # block, mark it. The reason text is appended with a
                    # sentinel string so filter_go_bounds_checks can detect
                    # without re-running the cross-instruction logic.
                    if new_v.severity == Severity.WARNING:
                        if self._go_branch_is_bounds_check(
                            i, instrs, panic_addrs, ins["operands"],
                        ):
                            new_v.reason = (
                                new_v.reason + " [BOUNDS_CHECK]"
                            )
                    violations.append(new_v)
                    pending_after.append((new_v, 4))

                recent.append(ins["raw"])
                if len(recent) > 8:
                    recent.pop(0)
        return functions, violations

    @staticmethod
    def _go_branch_is_bounds_check(
        idx: int, instrs: list[dict], panic_addrs: set[int], operands: str,
    ) -> bool:
        """A Go conditional branch is a bounds check if its taken target OR
        its fall-through (within ~3 instructions, possibly via one
        unconditional JMP) reaches a panic-block address."""
        # Parse explicit target: the last numeric token in operands.
        op_tail = operands.strip().split(",")[-1].strip().split()[0] if operands.strip() else ""
        try:
            tgt: int | None = int(op_tail)
        except (ValueError, TypeError):
            tgt = None
        if tgt is not None:
            # The Go assembler's branch operand is a *byte offset* (the
            # second column of each instruction). Find the instruction
            # whose decimal pc equals tgt.
            for k in range(idx + 1, len(instrs)):
                if instrs[k]["addr_int"] in panic_addrs:
                    if instrs[k]["addr_int"] == _decimal_pc_to_addr(instrs, tgt):
                        return True
        # Fall-through window: either a panic-block address directly, or a
        # JMP to one.
        for k in range(idx + 1, min(idx + 4, len(instrs))):
            if instrs[k]["addr_int"] in panic_addrs:
                return True
            if instrs[k]["mnemonic"] == "jmp":
                jt_tail = instrs[k]["operands"].strip().split()[0]
                try:
                    jt = int(jt_tail)
                except ValueError:
                    continue
                jt_addr = _decimal_pc_to_addr(instrs, jt)
                if jt_addr in panic_addrs:
                    return True
        return False

    @staticmethod
    def _attach_triage_metadata(violations: list[Violation]) -> None:
        """Populate `source_snippet` + `triage_hint` on each violation.

        Files are cached by path so each source file is read at most
        once even if it has dozens of violations.
        """
        cache: dict[str, list[str] | None] = {}
        for v in violations:
            if not v.file or not v.line:
                v.triage_hint = classify_violation(v, None)
                continue
            full = cache.get(v.file)
            if v.file not in cache:
                full = _read_source_snippet(v.file, v.line, ctx=2)
                cache[v.file] = full
            v.source_snippet = full
            v.triage_hint = classify_violation(v, full)

    @staticmethod
    def _aggregate_warnings(violations: list[Violation]) -> list[Violation]:
        """Collapse warnings sharing `(file, line)` into one entry.

        Implementation lives in `filters.aggregate_warnings_per_source_line`
        and is also exposed as the named post-filter `rust-aggregate-warnings`
        so the same operation is available via `--filter`.  This method
        is kept as a thin wrapper because the parser invokes it inline
        when `precise_warnings` is on -- the filter version is only run
        when the user explicitly requests it through `--filter`.
        """
        try:
            from .filters import aggregate_warnings_per_source_line
        except ImportError:
            from filters import aggregate_warnings_per_source_line
        return aggregate_warnings_per_source_line(violations)


def analyze_source(
    source_file: str,
    arch: str = None,
    compiler: str = None,
    optimization: str = "O2",
    include_warnings: bool = False,
    function_filter: str = None,
    extra_flags: list[str] = None,
    post_filters: list[str] | None = None,
    include_stdlib: bool = False,
    rust_user_crate: str | None = None,
    strict: bool = False,
    precise_warnings: bool = True,
) -> AnalysisReport:
    """
    Analyze a source file for constant-time violations.

    Args:
        source_file: Path to the source file to analyze
        arch: Target architecture (default: native, ignored for scripting languages)
        compiler: Compiler to use (default: auto-detect from language)
        optimization: Optimization level (default: O2, ignored for scripting languages)
        include_warnings: Include warning-level violations
        function_filter: Regex pattern to filter functions
        extra_flags: Extra flags to pass to the compiler (ignored for scripting languages)
        include_stdlib: For Rust, do not skip violations in stdlib
            monomorphizations (`core::*`, `alloc::*`, ...). Off by default
            because stdlib timing leaks are usually not the user's bug.
        rust_user_crate: Override the user crate name for Rust filtering.
            By default we infer it from the source file stem for standalone
            files, or accept any non-stdlib crate for Cargo projects.

    Returns:
        AnalysisReport with results
    """
    source_path = Path(source_file)
    if not source_path.exists():
        raise FileNotFoundError(f"Source file not found: {source_file}")

    language = detect_language(source_file)

    # Route scripting/bytecode languages to specialized analyzers
    if is_bytecode_language(language):
        try:
            from .script_analyzers import get_script_analyzer
        except ImportError:
            from script_analyzers import get_script_analyzer

        analyzer = get_script_analyzer(language)
        if analyzer is None:
            raise RuntimeError(f"No analyzer available for language: {language}")

        if not analyzer.is_available():
            runtime_map = {
                "php": "PHP",
                "javascript": "Node.js",
                "typescript": "Node.js",
                "python": "Python",
                "ruby": "Ruby",
                "java": "Java (javac/javap)",
                "csharp": ".NET SDK",
                "kotlin": "Kotlin (kotlinc)",
            }
            runtime = runtime_map.get(language, language)
            raise RuntimeError(
                f"{runtime} is not available. Please install it to analyze {language} files."
            )

        return analyzer.analyze(
            str(source_path.absolute()),
            include_warnings=include_warnings,
            function_filter=function_filter,
        )

    # Compiled languages use assembly analysis
    arch = normalize_arch(arch or get_native_arch())

    compiler_obj = get_compiler(compiler, language)
    if not compiler_obj.is_available():
        raise RuntimeError(f"Compiler not available: {compiler_obj.name}")

    # Compile to assembly
    with tempfile.NamedTemporaryFile(mode="w", suffix=".s", delete=False) as asm_file:
        asm_path = asm_file.name

    try:
        success, error = compiler_obj.compile_to_assembly(
            str(source_path.absolute()),
            asm_path,
            arch,
            optimization,
            extra_flags,
        )

        if not success:
            raise RuntimeError(f"Compilation failed: {error}")

        with open(asm_path) as f:
            assembly_text = f.read()

        # For Rust, infer the user's crate name from the source file when
        # not given explicitly so the parser can filter out monomorphized
        # stdlib code.
        user_crate = rust_user_crate
        if language == "rust" and user_crate is None:
            cargo_root = RustCompiler._find_cargo_root(str(source_path.absolute()))
            if cargo_root is None:
                # Standalone file: rustc derives crate name from file stem.
                user_crate = RustCompiler.crate_name_for(str(source_path.absolute()))
            # For Cargo projects we leave user_crate=None so any non-stdlib
            # crate is reported (workspace builds may emit several crates).

        # Parse and analyze
        parser = AssemblyParser(
            arch,
            compiler_obj.name,
            rust_user_crate=user_crate,
            include_stdlib=include_stdlib,
            strict=strict,
            precise_warnings=precise_warnings,
        )
        functions, violations = parser.parse(assembly_text, include_warnings)

        # Filter functions if requested
        if function_filter:
            pattern = re.compile(function_filter)
            violations = [v for v in violations if pattern.search(v.function)]
            functions = [f for f in functions if pattern.search(f["name"])]

        if post_filters:
            try:
                from .filters import apply_filters
            except ImportError:
                from filters import apply_filters
            kept, _ = apply_filters(violations, post_filters, source_path=str(source_path.absolute()))
            violations = kept

        return AnalysisReport(
            architecture=arch,
            compiler=compiler_obj.name,
            optimization=optimization,
            source_file=str(source_file),
            total_functions=len(functions),
            total_instructions=sum(f["instructions"] for f in functions),
            violations=violations,
        )

    finally:
        if os.path.exists(asm_path):
            os.unlink(asm_path)


def analyze_assembly(
    assembly_file: str,
    arch: str,
    include_warnings: bool = False,
    function_filter: str = None,
    strict: bool = False,
    precise_warnings: bool = True,
) -> AnalysisReport:
    """
    Analyze pre-compiled assembly for constant-time violations.

    Args:
        assembly_file: Path to the assembly file
        arch: Target architecture
        include_warnings: Include warning-level violations
        function_filter: Regex pattern to filter functions
        strict: Promote warnings in CT-named functions to ERRORs
        precise_warnings: Apply heuristic filters that drop loop-control
            and panic-target branches (default True)

    Returns:
        AnalysisReport with results
    """
    arch = normalize_arch(arch)

    with open(assembly_file) as f:
        assembly_text = f.read()

    parser = AssemblyParser(
        arch, "unknown", strict=strict, precise_warnings=precise_warnings
    )
    functions, violations = parser.parse(assembly_text, include_warnings)

    if function_filter:
        pattern = re.compile(function_filter)
        violations = [v for v in violations if pattern.search(v.function)]
        functions = [f for f in functions if pattern.search(f["name"])]

    return AnalysisReport(
        architecture=arch,
        compiler="unknown",
        optimization="unknown",
        source_file=assembly_file,
        total_functions=len(functions),
        total_instructions=sum(f["instructions"] for f in functions),
        violations=violations,
    )


def format_report(
    report: AnalysisReport,
    format_type: OutputFormat,
    explain: bool = False,
) -> str:
    """Format an analysis report for output.

    `explain=True` adds a `triage_hint` and a 5-line source snippet to
    every violation in TEXT mode (it's always included in JSON mode for
    machine consumption).
    """

    if format_type == OutputFormat.JSON:
        return json.dumps(
            {
                "architecture": report.architecture,
                "compiler": report.compiler,
                "optimization": report.optimization,
                "source_file": report.source_file,
                "total_functions": report.total_functions,
                "total_instructions": report.total_instructions,
                "error_count": report.error_count,
                "warning_count": report.warning_count,
                "passed": report.passed,
                "violations": [
                    {
                        "function": v.function,
                        "file": v.file,
                        "line": v.line,
                        "address": v.address,
                        "instruction": v.instruction,
                        "mnemonic": v.mnemonic,
                        "reason": v.reason,
                        "severity": v.severity.value,
                        "triage_hint": v.triage_hint,
                        "source_snippet": v.source_snippet,
                    }
                    for v in report.violations
                ],
            },
            indent=2,
        )

    elif format_type == OutputFormat.GITHUB:
        lines = []
        for v in report.violations:
            level = "error" if v.severity == Severity.ERROR else "warning"
            file_ref = f"file={v.file}" if v.file else ""
            line_ref = f",line={v.line}" if v.line else ""
            hint = f" [{v.triage_hint}]" if v.triage_hint else ""
            lines.append(
                f"::{level} {file_ref}{line_ref}::{v.mnemonic} in {v.function}: {v.reason}{hint}"
            )
        return "\n".join(lines)

    else:  # TEXT
        lines = []
        lines.append("=" * 60)
        lines.append("Constant-Time Analysis Report")
        lines.append("=" * 60)
        lines.append(f"Source: {report.source_file}")
        lines.append(f"Architecture: {report.architecture}")
        lines.append(f"Compiler: {report.compiler}")
        lines.append(f"Optimization: {report.optimization}")
        lines.append(f"Functions analyzed: {report.total_functions}")
        lines.append(f"Instructions analyzed: {report.total_instructions}")
        lines.append("")

        if report.violations:
            lines.append("VIOLATIONS FOUND:")
            lines.append("-" * 40)
            for v in report.violations:
                severity_marker = "ERROR" if v.severity == Severity.ERROR else "WARN"
                lines.append(f"[{severity_marker}] {v.mnemonic}")
                lines.append(f"  Function: {v.function}")
                if v.file:
                    file_info = f"  File: {v.file}"
                    if v.line:
                        file_info += f":{v.line}"
                    lines.append(file_info)
                if v.address:
                    lines.append(f"  Address: {v.address}")
                lines.append(f"  Reason: {v.reason}")
                if explain and v.triage_hint:
                    lines.append(f"  Triage: {v.triage_hint}")
                if explain and v.source_snippet and v.line:
                    ctx = len(v.source_snippet) // 2
                    start_line = max(1, v.line - ctx)
                    lines.append("  Source:")
                    for i, src in enumerate(v.source_snippet):
                        ln = start_line + i
                        marker = ">" if ln == v.line else " "
                        lines.append(f"    {marker} {ln:>5}: {src}")
                lines.append("")
        else:
            lines.append("No violations found.")

        lines.append("-" * 40)
        status = "PASSED" if report.passed else "FAILED"
        lines.append(f"Result: {status}")
        lines.append(f"Errors: {report.error_count}, Warnings: {report.warning_count}")

        return "\n".join(lines)


def main():
    parser = argparse.ArgumentParser(
        description="Analyze code for constant-time violations",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s crypto.c                          # Analyze C file with defaults
  %(prog)s --compiler gcc --opt O3 crypto.c  # Use GCC with -O3
  %(prog)s --arch arm64 crypto.go            # Analyze Go for ARM64
  %(prog)s --warnings crypto.c               # Include branch warnings
  %(prog)s --json crypto.c                   # Output as JSON
  %(prog)s CryptoUtils.java                  # Analyze Java (JVM bytecode)
  %(prog)s CryptoUtils.kt                    # Analyze Kotlin (JVM bytecode)
  %(prog)s CryptoUtils.cs                    # Analyze C# (CIL bytecode)
  %(prog)s crypto.swift                      # Analyze Swift (native code)
  %(prog)s crypto.php                        # Analyze PHP (uses VLD/opcache)
  %(prog)s crypto.ts                         # Analyze TypeScript (transpiles first)
  %(prog)s crypto.js                         # Analyze JavaScript (V8 bytecode)

Supported languages:
  Native compiled: C, C++, Go, Rust, Swift
  VM-compiled: Java, Kotlin, C#
  Scripting: PHP, JavaScript, TypeScript, Python, Ruby

Supported architectures (native compiled languages only):
  x86_64, arm64, arm, riscv64, ppc64le, s390x, i386

Note: VM-compiled and scripting languages analyze bytecode and don't use --arch or --opt-level.
""",
    )

    parser.add_argument("source_file", help="Source file to analyze")
    parser.add_argument("--arch", "-a", help="Target architecture (default: native)")
    parser.add_argument("--compiler", "-c", help="Compiler to use (gcc, clang, go, rustc)")
    parser.add_argument(
        "--opt-level", "-O", default="O2", help="Optimization level (O0, O1, O2, O3, Os, Oz)"
    )
    parser.add_argument(
        "--warnings",
        "-w",
        action="store_true",
        help="Include warning-level violations (conditional branches)",
    )
    parser.add_argument("--func", "-f", help="Regex pattern to filter functions")
    parser.add_argument("--json", action="store_true", help="Output in JSON format")
    parser.add_argument("--github", action="store_true", help="Output GitHub Actions annotations")
    parser.add_argument(
        "--assembly", action="store_true", help="Input is already assembly (requires --arch)"
    )
    parser.add_argument(
        "--list-arch", action="store_true", help="List supported architectures and exit"
    )
    parser.add_argument(
        "--extra-flags",
        "-X",
        action="append",
        default=[],
        help="Extra flags to pass to the compiler",
    )
    parser.add_argument(
        "--filter",
        action="append",
        default=[],
        help=(
            "Comma-separated post-analysis filters that prune false positives. "
            "Available: ct-funcs, aggregate, compiler-helpers, non-secret, memcmp-source. "
            "Use 'all' for the recommended default set."
        ),
    )
    parser.add_argument(
        "--include-stdlib",
        action="store_true",
        help="(Rust) include violations in stdlib monomorphizations "
        "(core::*, alloc::*, std::*). Off by default to keep reports "
        "actionable for crypto authors.",
    )
    parser.add_argument(
        "--rust-crate",
        help="(Rust) override the user-crate name for symbol filtering. "
        "Default: source file stem with `-` -> `_`.",
    )
    parser.add_argument(
        "--no-precise-warnings",
        dest="precise_warnings",
        action="store_false",
        default=True,
        help="Disable warning-precision filters: report every conditional "
        "branch, including loop-control and panic-target branches. "
        "Useful only for forensic review of the raw asm.",
    )
    parser.add_argument(
        "--strict",
        action="store_true",
        help="Promote conditional-branch warnings to ERRORs when found "
        "in functions whose name implies constant-time behavior "
        "(verify*, ct_*, constant_time_*, compare*, equals*). A branch "
        "in `verify_tag` is a regression on its stated contract.",
    )
    parser.add_argument(
        "--explain",
        action="store_true",
        help="With each violation, emit a triage hint and a 5-line "
        "source snippet centered on the cited line, and when "
        "post-analysis filters drop a finding, print the suppression "
        "reason to stderr. Lets a downstream agent (or human) classify "
        "findings without re-reading the file.",
    )

    args = parser.parse_args()

    if args.list_arch:
        print("Supported Architectures:")
        print("=" * 40)
        for arch, instructions in DANGEROUS_INSTRUCTIONS.items():
            print(f"\n{arch}:")
            print(f"  Errors: {len(instructions.get('errors', {}))}")
            print(f"  Warnings: {len(instructions.get('warnings', {}))}")
        return 0

    # Determine output format
    if args.json:
        output_format = OutputFormat.JSON
    elif args.github:
        output_format = OutputFormat.GITHUB
    else:
        output_format = OutputFormat.TEXT

    try:
        if args.assembly:
            if not args.arch:
                print("Error: --arch is required when analyzing assembly files", file=sys.stderr)
                return 1
            report = analyze_assembly(
                args.source_file,
                args.arch,
                include_warnings=args.warnings,
                function_filter=args.func,
                strict=args.strict,
                precise_warnings=args.precise_warnings,
            )
        else:
            report = analyze_source(
                args.source_file,
                arch=args.arch,
                compiler=args.compiler,
                optimization=args.opt_level,
                include_warnings=args.warnings,
                function_filter=args.func,
                extra_flags=args.extra_flags,
                include_stdlib=args.include_stdlib,
                rust_user_crate=args.rust_crate,
                strict=args.strict,
                precise_warnings=args.precise_warnings,
            )

        # Apply post-analysis filters
        filter_list: list[str] = []
        for f in args.filter:
            filter_list.extend(s.strip() for s in f.split(",") if s.strip())
        if "all" in filter_list:
            filter_list = ["compiler-helpers", "memcmp-source", "ct-funcs",
                           "non-secret", "div-public", "loop-backedge",
                           "aggregate"]
        if filter_list:
            try:
                from .filters import apply_filters
            except ImportError:
                from filters import apply_filters
            src = args.source_file if not args.assembly else None
            kept, suppressed = apply_filters(report.violations, filter_list, source_path=src)
            report.violations = kept
            if args.explain:
                for v, why in suppressed:
                    print(f"  [suppressed] {v.mnemonic} in {v.function}: {why}", file=sys.stderr)

        print(format_report(report, output_format, explain=args.explain))
        return 0 if report.passed else 1

    except (FileNotFoundError, RuntimeError, subprocess.CalledProcessError) as e:
        if output_format == OutputFormat.JSON:
            print(json.dumps({"error": str(e)}))
        else:
            print(f"Error: {e}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
