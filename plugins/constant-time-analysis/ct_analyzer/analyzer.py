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
import platform
import re
import subprocess
import sys
import tempfile
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import TypedDict


class Severity(Enum):
    ERROR = "error"
    WARNING = "warning"


class OutputFormat(Enum):
    TEXT = "text"
    JSON = "json"
    GITHUB = "github"


class ParsedFunction(TypedDict):
    """A function or method seen while parsing, with its instruction count.

    Previously a bare `dict`, which typed the values as `str | int` and made the
    `functions[-1]["instructions"] += 1` counter in every parser look like string
    addition to a type checker.
    """

    name: str
    instructions: int


def is_error(violation: "Violation") -> bool:
    """True when `violation` is error severity, compared by value.

    `analyzer.py` is documented to be run as a script, which makes this module
    `__main__` while `script_analyzers` imports it again as `analyzer`. Each copy
    defines its own `Severity` enum, so `severity is Severity.ERROR` is False for
    every finding produced by a scripting-language backend. That printed all six
    PHP errors as `[WARN]` while the summary line counted them as errors —
    downgrading real findings in the output a reviewer actually reads.
    """
    return violation.severity.value == Severity.ERROR.value


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
        return sum(1 for v in self.violations if is_error(v))

    @property
    def warning_count(self) -> int:
        return sum(1 for v in self.violations if not is_error(v))

    @property
    def passed(self) -> bool:
        return self.error_count == 0


# Compiler-provided division routines. A target without a hardware divider does
# not emit a division instruction at all: gcc calls a libgcc helper, so the
# mnemonic is an ordinary `bl`/`call` and the instruction tables never match.
# armv7-a is the common case — `key_coef / (2 * gamma2)` becomes
# `bl __aeabi_idiv` — and __divti3 appears on x86_64 for __int128 division, which
# crypto code does use. These routines loop over the operands, so they are more
# operand-dependent than the hardware instruction they replace, and reporting
# PASSED for them is the worst kind of false negative.
DIVISION_HELPERS = {
    # Arm EABI
    "__aeabi_idiv",
    "__aeabi_uidiv",
    "__aeabi_idivmod",
    "__aeabi_uidivmod",
    "__aeabi_ldivmod",
    "__aeabi_uldivmod",
    # libgcc / compiler-rt, by operand width
    "__divsi3",
    "__udivsi3",
    "__modsi3",
    "__umodsi3",
    "__divdi3",
    "__udivdi3",
    "__moddi3",
    "__umoddi3",
    "__divti3",
    "__udivti3",
    "__modti3",
    "__umodti3",
}


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
        },
    },
    # ARM64 / AArch64
    "arm64": {
        "errors": {
            # Division - early termination optimization makes these variable-time
            # Note: Even with DIT (Data Independent Timing) enabled, division is NOT constant-time
            "udiv": "UDIV has early termination optimization; execution time depends on operand values",
            "sdiv": "SDIV has early termination optimization; execution time depends on operand values",
            # Go's assembler writes arm64 in Plan 9 syntax, which puts the operand
            # width in the mnemonic instead of the register name: a 32-bit divide
            # is SDIVW, not `sdiv w0, w0, w1`. Without these, `int32 / int32` — the
            # shape of every polynomial coefficient divide — read as clean on Go.
            "udivw": "UDIVW has early termination optimization; execution time depends on operand values",
            "sdivw": "SDIVW has early termination optimization; execution time depends on operand values",
            # Floating-point division
            "fdiv": "FDIV (FP division) has variable latency based on operand values",
            "fdivs": "FDIVS (FP division) has variable latency based on operand values",
            "fdivd": "FDIVD (FP division) has variable latency based on operand values",
            # Square root
            "fsqrt": "FSQRT has variable latency based on operand values",
            "fsqrts": "FSQRTS has variable latency based on operand values",
            "fsqrtd": "FSQRTD has variable latency based on operand values",
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
        extra_flags: list[str] | None = None,
    ) -> tuple[bool, str]:
        """Compile source to assembly. Returns (success, error_message)."""
        raise NotImplementedError

    def reject_arch(self, arch: str, supported) -> tuple[bool, str]:
        """Refuse an architecture this compiler cannot target.

        Omitting the target flag instead would compile for the host while
        `analyze_source` still labels the report with the architecture that was
        asked for and applies that architecture's instruction table. A reviewer
        then records "PASSED for riscv64" from a run that never targeted riscv64,
        which is worse than an error.
        """
        return False, (
            f"{self.name} cannot target {arch} here; supported: {', '.join(sorted(supported))}"
        )

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
        # -mfpu is required: armv7-a alone has no FPU, so hard float was
        # rejected with "selected architecture lacks an FPU". vfpv3-d16 is
        # Debian's armhf baseline.
        "arm": ["-march=armv7-a", "-mfpu=vfpv3-d16", "-mfloat-abi=hard"],
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
        extra_flags: list[str] | None = None,
    ) -> tuple[bool, str]:
        arch = normalize_arch(arch)
        if arch not in self.ARCH_FLAGS:
            return self.reject_arch(arch, self.ARCH_FLAGS)
        arch_flags = self.ARCH_FLAGS[arch]

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
        extra_flags: list[str] | None = None,
    ) -> tuple[bool, str]:
        arch = normalize_arch(arch)
        if arch not in self.ARCH_TARGETS:
            return self.reject_arch(arch, self.ARCH_TARGETS)
        target = self.ARCH_TARGETS[arch]

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
    """Go compiler interface."""

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

    def compile_to_assembly(
        self,
        source_file: str,
        output_file: str,
        arch: str,
        optimization: str,
        extra_flags: list[str] | None = None,
    ) -> tuple[bool, str]:
        arch = normalize_arch(arch)
        if arch not in self.ARCH_MAP:
            return self.reject_arch(arch, self.ARCH_MAP)
        goarch = self.ARCH_MAP[arch]

        # For Go, we need to build a binary and then disassemble it
        with tempfile.TemporaryDirectory() as tmpdir:
            binary_path = os.path.join(tmpdir, "binary")

            env = os.environ.copy()
            env["GOOS"] = "linux"
            env["GOARCH"] = goarch
            env["CGO_ENABLED"] = "0"

            # Build command - use gcflags to control optimization
            gcflags = ""
            if optimization == "O0":
                gcflags = "-N -l"  # Disable optimizations and inlining

            cmd = [
                self.path,
                "build",
                "-o",
                binary_path,
            ]
            if gcflags:
                cmd.extend(["-gcflags", gcflags])
            cmd.append(source_file)

            try:
                result = subprocess.run(cmd, capture_output=True, text=True, env=env)
                if result.returncode != 0:
                    return False, result.stderr

                # Now disassemble
                disasm_cmd = [self.path, "tool", "objdump", binary_path]
                result = subprocess.run(disasm_cmd, capture_output=True, text=True)
                if result.returncode != 0:
                    return False, result.stderr

                disassembly, kept = self._keep_only_source_symbols(result.stdout, source_file)
                if not kept:
                    return False, (
                        f"Disassembly contained no symbols from {source_file}. Go links the "
                        "whole runtime into the binary, so reporting the unfiltered listing "
                        "would attribute the runtime's divisions to your code."
                    )

                with open(output_file, "w") as f:
                    f.write(disassembly)

                return True, ""
            except FileNotFoundError:
                return False, f"Go not found: {self.path}"

    @staticmethod
    def _keep_only_source_symbols(disassembly: str, source_file: str) -> tuple[str, int]:
        """Drop objdump blocks that did not come from `source_file`.

        `go build` links the runtime into every binary, so an unfiltered objdump
        of a 30-line file yields ~900 functions and reports the allocator's and
        garbage collector's divisions — all on public data — while the caller's
        own code is a rounding error in the output. Each block starts with
        `TEXT main.fn(SB) /path/to/file.go`, so the originating file is known
        exactly and no heuristic is needed.

        Returns the filtered listing and the number of blocks kept.
        """
        wanted = os.path.realpath(source_file)
        kept_lines: list[str] = []
        kept = 0
        in_wanted_block = False

        for line in disassembly.splitlines(keepends=True):
            header = re.match(r"^TEXT\s+[^\s(]+\(SB\)\s+(.*)$", line.strip())
            if header:
                block_file = header.group(1).strip()
                if os.path.isabs(block_file):
                    # objdump printed a full path, so compare exactly. Falling back
                    # to basenames here readmitted the runtime: it ships map.go,
                    # slice.go, string.go, time.go and select.go, so analyzing a
                    # user file with any of those names matched
                    # `/usr/lib/go/src/runtime/map.go` and reported the
                    # allocator's divisions as the caller's.
                    in_wanted_block = os.path.realpath(block_file) == wanted
                else:
                    in_wanted_block = os.path.basename(block_file) == os.path.basename(wanted)
                if in_wanted_block:
                    kept += 1
            if in_wanted_block:
                kept_lines.append(line)

        return "".join(kept_lines), kept


class RustCompiler(Compiler):
    """Rust compiler interface."""

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
    def _declares_main(source_file: str) -> bool:
        """True when the file defines a top-level `fn main`."""
        try:
            with open(source_file, encoding="utf-8", errors="replace") as handle:
                return (
                    re.search(r"^\s*(pub\s+)?fn\s+main\s*\(", handle.read(), re.MULTILINE)
                    is not None
                )
        except OSError:
            return False

    def compile_to_assembly(
        self,
        source_file: str,
        output_file: str,
        arch: str,
        optimization: str,
        extra_flags: list[str] | None = None,
    ) -> tuple[bool, str]:
        arch = normalize_arch(arch)
        if arch not in self.ARCH_TARGETS:
            return self.reject_arch(arch, self.ARCH_TARGETS)
        target = self.ARCH_TARGETS[arch]

        opt_level = {
            "O0": "0",
            "O1": "1",
            "O2": "2",
            "O3": "3",
            "Os": "s",
            "Oz": "z",
        }.get(optimization, "2")

        # rustc defaults to a bin crate, which rejects any file without `fn main`
        # (E0601). Crypto code lives in libraries, so a bare module was previously
        # unanalyzable. Compile as a lib unless the file really is a binary.
        crate_type = "bin" if self._declares_main(source_file) else "lib"

        cmd = [
            self.path,
            "--emit=asm",
            f"--crate-type={crate_type}",
            "-C",
            f"opt-level={opt_level}",
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

    # The Apple triples above need Xcode's SDK. On Linux swiftc rejects them with
    # "unable to load standard library for target 'arm64-apple-macosx11.0'", which
    # made every Swift analysis fail on Linux and in CI.
    LINUX_ARCH_TARGETS = {
        "x86_64": "x86_64-unknown-linux-gnu",
        "arm64": "aarch64-unknown-linux-gnu",
    }

    def __init__(self, path: str | None = None):
        super().__init__("swiftc", path or "swiftc")

    @classmethod
    def target_for(cls, arch: str) -> str | None:
        """Return the triple for `arch` on the host platform, or None if unmapped."""
        if platform.system() == "Darwin":
            return cls.ARCH_TARGETS.get(arch)
        return cls.LINUX_ARCH_TARGETS.get(arch)

    def compile_to_assembly(
        self,
        source_file: str,
        output_file: str,
        arch: str,
        optimization: str,
        extra_flags: list[str] | None = None,
    ) -> tuple[bool, str]:
        arch = normalize_arch(arch)
        target = self.target_for(arch)
        if target is None:
            supported = (
                self.ARCH_TARGETS if platform.system() == "Darwin" else self.LINUX_ARCH_TARGETS
            )
            return self.reject_arch(arch, supported)

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


# GNU cross-toolchain prefixes, for naming the binary to install or pass. The
# analyzer's architecture names are not the triple prefixes: arm64 is aarch64,
# i386 is i686, ppc64le is powerpc64le, and arm carries an ABI suffix.
# Debian/Ubuntu cross libc packages are named by Debian architecture, which is
# neither the analyzer's name nor the GNU triple: x86_64 is amd64, ppc64le is
# ppc64el, arm is armhf.
DEBIAN_CROSS_LIBC = {
    "x86_64": "libc6-dev-amd64-cross",
    "i386": "libc6-dev-i386-cross",
    "arm64": "libc6-dev-arm64-cross",
    "arm": "libc6-dev-armhf-cross",
    "riscv64": "libc6-dev-riscv64-cross",
    "ppc64le": "libc6-dev-ppc64el-cross",
    "s390x": "libc6-dev-s390x-cross",
}

GNU_TRIPLES = {
    "x86_64": "x86_64-linux-gnu",
    "i386": "i686-linux-gnu",
    "arm64": "aarch64-linux-gnu",
    "arm": "arm-linux-gnueabihf",
    "riscv64": "riscv64-linux-gnu",
    "ppc64le": "powerpc64le-linux-gnu",
    "s390x": "s390x-linux-gnu",
}


def compiler_family(name: str) -> str | None:
    """Identify which compiler `name` is, by filename then by `--version`.

    A GNU cross toolchain *is* a separate binary — `x86_64-linux-gnu-gcc` — so
    handing the analyzer an explicit compiler is how cross-compilation works for
    gcc. Every unrecognized `--compiler` value used to be driven as clang, which
    passed `--target=` to gcc and failed with "unrecognized command-line option",
    making the one escape hatch that should have worked unusable.

    Args:
        name: The `--compiler` value: a bare name or a path.

    Returns:
        One of `clang`, `gcc`, `rustc`, `swiftc`, `go`, or None when neither the
        filename nor the version banner identifies it.
    """
    stem = Path(name).name.lower()
    # clang before gcc: "gcc" contains "cc", and a clang binary may be named
    # anything, so the more specific token wins.
    if "clang" in stem:
        return "clang"
    if "gcc" in stem or "g++" in stem:
        return "gcc"
    if "rustc" in stem:
        return "rustc"
    if "swiftc" in stem:
        return "swiftc"
    if stem == "go":
        return "go"

    try:
        probe = subprocess.run([name, "--version"], capture_output=True, text=True)
    except OSError:
        return None
    banner = f"{probe.stdout}\n{probe.stderr}".lower()
    if "clang version" in banner:
        return "clang"
    if "free software foundation" in banner or "gcc" in banner:
        return "gcc"
    if "rustc" in banner:
        return "rustc"
    if "swift version" in banner:
        return "swiftc"
    return None


def get_compiler(name: str | None, language: str) -> Compiler:
    """Get a compiler instance by name, or detect one from the language.

    `name` is optional: callers pass the `--compiler` value through unchanged, and
    the auto-detection below is what runs when it was not supplied. An explicit
    value is dispatched on which compiler it actually is, so a cross toolchain
    such as `x86_64-linux-gnu-gcc` is driven with gcc's flags. Nothing is
    substituted on the caller's behalf: the binary asked for is the binary run,
    and the report names it.
    """
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
        family = compiler_family(name)
        if family is None:
            print(
                f"Note: could not tell which compiler {name} is from its name or "
                "version banner; driving it with clang's flags",
                file=sys.stderr,
            )
            return ClangCompiler(name)
        return compilers[family](name)

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


class AssemblyParser:
    """Parser for assembly output from various compilers."""

    def __init__(self, arch: str, compiler: str):
        self.arch = normalize_arch(arch)
        self.compiler = compiler

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

    def parse(
        self, assembly_text: str, include_warnings: bool = False
    ) -> tuple[list[ParsedFunction], list[Violation]]:
        """
        Parse assembly text and detect violations.
        Returns (functions, violations).
        """
        functions: list[ParsedFunction] = []
        violations = []

        current_function = None
        current_file = None
        current_line = None
        instruction_count = 0

        for line in assembly_text.split("\n"):
            line = line.strip()

            # Skip empty lines and comments
            if not line or line.startswith("#") or line.startswith("//") or line.startswith(";"):
                # Check for file/line info in comments
                file_match = re.search(r"#\s*([^:]+):(\d+)", line)
                if file_match:
                    current_file = file_match.group(1)
                    current_line = int(file_match.group(2))
                continue

            # Detect function start (various formats)
            func_match = (
                # GCC/Clang: function_name:
                re.match(r"^([a-zA-Z_][a-zA-Z0-9_]*):$", line)
                or
                # Go objdump: TEXT symbol_name(SB) file
                re.match(r"^TEXT\s+([^\s(]+)\(SB\)", line)
                or
                # With .type directive
                re.match(r"\.type\s+([a-zA-Z_][a-zA-Z0-9_]*),\s*@function", line)
            )

            if func_match:
                if current_function:
                    functions.append(
                        {
                            "name": current_function,
                            "instructions": instruction_count,
                        }
                    )
                current_function = func_match.group(1)
                instruction_count = 0
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
                # This should be the mnemonic
                mnemonic = part.lower().rstrip(":")
                break

            if not mnemonic:
                continue

            instruction_count += 1

            called_helper = next(
                (helper for helper in DIVISION_HELPERS if helper in instruction), None
            )

            # Check for violations
            if called_helper:
                violations.append(
                    Violation(
                        function=current_function or "<unknown>",
                        file=current_file or "",
                        line=current_line,
                        address=address,
                        instruction=instruction,
                        mnemonic=called_helper.upper().lstrip("_"),
                        reason=(
                            f"{called_helper} performs division in software; it loops over "
                            "the operands, so its execution time depends on their values"
                        ),
                        severity=Severity.ERROR,
                    )
                )
            elif mnemonic in self.errors:
                violations.append(
                    Violation(
                        function=current_function or "<unknown>",
                        file=current_file or "",
                        line=current_line,
                        address=address,
                        instruction=instruction,
                        mnemonic=mnemonic.upper(),
                        reason=self.errors[mnemonic],
                        severity=Severity.ERROR,
                    )
                )
            elif include_warnings and mnemonic in self.warnings:
                violations.append(
                    Violation(
                        function=current_function or "<unknown>",
                        file=current_file or "",
                        line=current_line,
                        address=address,
                        instruction=instruction,
                        mnemonic=mnemonic.upper(),
                        reason=self.warnings[mnemonic],
                        severity=Severity.WARNING,
                    )
                )

        # Don't forget the last function
        if current_function:
            functions.append(
                {
                    "name": current_function,
                    "instructions": instruction_count,
                }
            )

        return functions, violations


def analyze_source(
    source_file: str,
    arch: str | None = None,
    compiler: str | None = None,
    optimization: str = "O2",
    include_warnings: bool = False,
    function_filter: str | None = None,
    extra_flags: list[str] | None = None,
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
            from .script_analyzers import get_script_analyzer  # ty: ignore[unresolved-import]
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
            if arch != get_native_arch() and "file not found" in error:
                package = DEBIAN_CROSS_LIBC.get(arch)
                remedy = f"install {package}" if package else "install the target's libc headers"
                error = (
                    f"{error.rstrip()}\n"
                    f"Cross-compiling for {arch} needs that target's C library headers, which "
                    f"are separate from the compiler: {remedy}, or analyze a source file that "
                    "includes no libc headers."
                )

            already_cross = "-linux-gnu" in Path(compiler_obj.path).name
            if (
                arch != get_native_arch()
                and compiler_family(compiler_obj.path) == "gcc"
                and not already_cross
            ):
                triple = GNU_TRIPLES.get(arch)
                suggestion = f"--compiler {triple}-gcc" if triple else "an explicit cross build"
                error = (
                    f"{error.rstrip()}\n"
                    f"The gcc on PATH targets its own ISA family, so it cannot build for "
                    f"{arch}. Pass a cross build explicitly ({suggestion}), or use "
                    f"--compiler clang, which cross-compiles through --target."
                )
            raise RuntimeError(f"Compilation failed: {error}")

        with open(asm_path) as f:
            assembly_text = f.read()

        # Parse and analyze
        parser = AssemblyParser(arch, compiler_obj.name)
        functions, violations = parser.parse(assembly_text, include_warnings)

        # Filter functions if requested
        if function_filter:
            pattern = re.compile(function_filter)
            violations = [v for v in violations if pattern.search(v.function)]
            functions = [f for f in functions if pattern.search(f["name"])]

        return AnalysisReport(
            architecture=arch,
            # The binary that ran, not the family: with an explicit cross toolchain
            # `--compiler x86_64-linux-gnu-gcc`, reporting "gcc" would name a
            # different compiler — often a different major version — than the one
            # whose codegen is in this report.
            compiler=compiler_obj.path,
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
    function_filter: str | None = None,
) -> AnalysisReport:
    """
    Analyze pre-compiled assembly for constant-time violations.

    Args:
        assembly_file: Path to the assembly file
        arch: Target architecture
        include_warnings: Include warning-level violations
        function_filter: Regex pattern to filter functions

    Returns:
        AnalysisReport with results
    """
    arch = normalize_arch(arch)

    with open(assembly_file) as f:
        assembly_text = f.read()

    parser = AssemblyParser(arch, "unknown")
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


def format_report(report: AnalysisReport, format_type: OutputFormat) -> str:
    """Format an analysis report for output."""

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
                    }
                    for v in report.violations
                ],
            },
            indent=2,
        )

    elif format_type == OutputFormat.GITHUB:
        lines = []
        for v in report.violations:
            level = "error" if is_error(v) else "warning"
            file_ref = f"file={v.file}" if v.file else ""
            line_ref = f",line={v.line}" if v.line else ""
            lines.append(
                f"::{level} {file_ref}{line_ref}::{v.mnemonic} in {v.function}: {v.reason}"
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
                severity_marker = "ERROR" if is_error(v) else "WARN"
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
            )

        print(format_report(report, output_format))
        return 0 if report.passed else 1

    except (FileNotFoundError, RuntimeError, subprocess.CalledProcessError) as e:
        if output_format == OutputFormat.JSON:
            print(json.dumps({"error": str(e)}))
        else:
            print(f"Error: {e}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
