#!/usr/bin/env python3
# /// script
# requires-python = ">=3.10"
# ///
"""
Script language analyzers for constant-time analysis.

This module provides analyzers for scripting languages (PHP, JavaScript/TypeScript)
that work at the bytecode/opcode level rather than native assembly.
"""

import os
import re
import subprocess
import sys
import tempfile
import xml.sax.saxutils as _saxutils
from abc import ABC, abstractmethod
from pathlib import Path

# Import shared types from the main analyzer. Both spellings are needed because
# analyzer.py is documented to run as a script (`uv run .../analyzer.py`) as well as
# import as a package. ty resolves the top-level spelling via `tool.ty.environment
# extra-paths`, so the package-relative branch is unresolvable for it by
# construction; the ignore covers that branch only.
try:
    from .analyzer import (  # ty: ignore[unresolved-import]
        AnalysisReport,
        ParsedFunction,
        Severity,
        Violation,
    )
except ImportError:
    from analyzer import AnalysisReport, ParsedFunction, Severity, Violation


# =============================================================================
# PHP Dangerous Operations
# =============================================================================

DANGEROUS_PHP_OPCODES = {
    "errors": {
        # Variable-time arithmetic
        "zend_div": "DIV opcode has variable-time execution based on operand values",
        "div": "DIV opcode has variable-time execution based on operand values",
        "zend_mod": "MOD opcode has variable-time execution based on operand values",
        "mod": "MOD opcode has variable-time execution based on operand values",
        "zend_pow": "POW opcode has variable-time execution",
        "pow": "POW opcode has variable-time execution",
    },
    "warnings": {
        # Comparisons that may early-terminate
        "zend_is_equal": "Equality comparison may early-terminate on secret data",
        "is_equal": "Equality comparison may early-terminate on secret data",
        "zend_is_identical": "Identity comparison may early-terminate on secret data",
        "is_identical": "Identity comparison may early-terminate on secret data",
        "zend_is_not_equal": "Inequality comparison may early-terminate on secret data",
        "is_not_equal": "Inequality comparison may early-terminate on secret data",
        "zend_is_not_identical": "Non-identity comparison may early-terminate on secret data",
        "is_not_identical": "Non-identity comparison may early-terminate on secret data",
        # Table lookups (cache timing via secret-indexed array access)
        "fetch_dim_r": "Array access may leak timing via cache if index depends on secrets",
        "zend_fetch_dim_r": "Array access may leak timing via cache if index depends on secrets",
        "fetch_dim_w": "Array access may leak timing via cache if index depends on secrets",
        "zend_fetch_dim_w": "Array access may leak timing via cache if index depends on secrets",
        # Bit shift operations (may leak via timing if shift amount is secret)
        "zend_sl": "Left shift may leak timing if shift amount depends on secrets",
        "sl": "Left shift may leak timing if shift amount depends on secrets",
        "zend_sr": "Right shift may leak timing if shift amount depends on secrets",
        "sr": "Right shift may leak timing if shift amount depends on secrets",
    },
}

# Functions with timing side-channels (based on Paragonie research)
DANGEROUS_PHP_FUNCTIONS = {
    "errors": {
        # Division reached through a function rather than an operator, so no DIV
        # opcode is emitted and the opcode table above never sees it
        "intdiv": "intdiv() performs hardware division; execution time depends on operand values",
        "fdiv": "fdiv() performs floating-point division with operand-dependent latency",
        # Cache-timing side-channels via table lookups
        "chr": "chr() uses table lookup indexed by secret data; use pack('C', $int) instead",
        "ord": "ord() uses table lookup indexed by secret data; use unpack('C', $char)[1] instead",
        "bin2hex": "bin2hex() uses table lookups indexed on secret data",
        "hex2bin": "hex2bin() uses table lookups indexed on secret data",
        "base64_encode": "base64_encode() uses table lookups indexed on secret data",
        "base64_decode": "base64_decode() uses table lookups indexed on secret data",
        # Predictable randomness (not cryptographically secure)
        "rand": "rand() is predictable; use random_int() for cryptographic purposes",
        "mt_rand": "mt_rand() is predictable; use random_int() for cryptographic purposes",
        "array_rand": "array_rand() uses mt_rand internally; use random_int() instead",
        "uniqid": "uniqid() is predictable; use random_bytes() for cryptographic purposes",
        "lcg_value": "lcg_value() is predictable; use random_int() for cryptographic purposes",
        "str_shuffle": "str_shuffle() uses mt_rand internally",
        "shuffle": "shuffle() uses mt_rand internally; use a Fisher-Yates with random_int()",
    },
    "warnings": {
        # Variable-time string comparisons
        "strcmp": "strcmp() has variable-time execution; use hash_equals() for secrets",
        "strcasecmp": "strcasecmp() has variable-time execution; use hash_equals() for secrets",
        "strncmp": "strncmp() has variable-time execution; use hash_equals() for secrets",
        "strncasecmp": "strncasecmp() has variable-time execution; use hash_equals() for secrets",
        "substr_compare": "substr_compare() has variable-time execution; use hash_equals()",
        # String operations that may indicate unsafe comparison patterns
        "substr": "substr() in comparisons may indicate timing-unsafe pattern",
        # Variable-length encoding (may leak data length via timing)
        "pack": "pack() may leak data length via timing; ensure fixed-length output",
        "unpack": "unpack() may leak data length via timing; ensure fixed-length input",
        "serialize": "serialize() produces variable-length output that may leak information",
        "json_encode": "json_encode() produces variable-length output that may leak information",
    },
}


# =============================================================================
# JavaScript/TypeScript Dangerous Operations
# =============================================================================

DANGEROUS_JS_BYTECODES = {
    "errors": {
        # Variable-time arithmetic
        "div": "Div bytecode has variable-time execution based on operand values",
        "mod": "Mod bytecode has variable-time execution based on operand values",
        "divsmi": "DivSmi (division by small integer) has variable-time execution",
        "modsmi": "ModSmi (modulo by small integer) has variable-time execution",
    },
    "warnings": {
        # Conditional jumps (may leak timing if condition depends on secrets)
        "jumpiftrue": "Conditional jump may leak timing if condition depends on secret data",
        "jumpiffalse": "Conditional jump may leak timing if condition depends on secret data",
        "jumpiftobooleanfalse": "Conditional jump may leak timing if condition depends on secret data",
        "jumpiftobooleantrue": "Conditional jump may leak timing if condition depends on secret data",
        "jumpifundefined": "Conditional jump may leak timing if condition depends on secret data",
        "jumpifnull": "Conditional jump may leak timing if condition depends on secret data",
        # Comparison operations
        "testequal": "Equality test may early-terminate on secret data",
        "testequalstrict": "Strict equality test may early-terminate on secret data",
        # Table lookups (cache timing via secret-indexed array access)
        # Keyed access only: `obj[secret]` can be indexed by a secret, while a
        # named access has a constant property name and never can, so flagging
        # named access reports every `Math.trunc` call as a finding.
        "getkeyedproperty": "Array/property access may leak timing via cache if index depends on secrets",
        "setkeyedproperty": "Array/property access may leak timing via cache if index depends on secrets",
        "ldakeyedproperty": "Array/property access may leak timing via cache if index depends on secrets",
        "stakeyedproperty": "Array/property access may leak timing via cache if index depends on secrets",
        "getkeyed": "Array access may leak timing via cache if index depends on secrets",
        "setkeyed": "Array access may leak timing via cache if index depends on secrets",
        # Bit shift operations (may leak via timing if shift amount is secret)
        "shiftleft": "Left shift may leak timing if shift amount depends on secrets",
        "shiftright": "Right shift may leak timing if shift amount depends on secrets",
        "shiftrightsmi": "Right shift by constant may still leak timing in some contexts",
        "shiftleftsmi": "Left shift by constant may still leak timing in some contexts",
        "bitwiseand": "Bitwise AND timing may vary based on operands",
        "bitwiseor": "Bitwise OR timing may vary based on operands",
        "bitwisexor": "Bitwise XOR timing may vary based on operands",
    },
}

DANGEROUS_JS_FUNCTIONS = {
    "errors": {
        # Variable latency math operations
        "math.sqrt": "Math.sqrt() has variable latency based on operand values",
        "math.pow": "Math.pow() has variable latency based on operand values",
        # Unpredictable timing
        "eval": "eval() has unpredictable timing characteristics",
        # Predictable randomness
        "math.random": "Math.random() is predictable; use crypto.getRandomValues() instead",
    },
    "warnings": {
        # Variable-time string operations
        "localecompare": "localeCompare() has variable-time execution",
        "indexof": "indexOf() has early-terminating behavior",
        "includes": "includes() has early-terminating behavior",
        "startswith": "startsWith() has early-terminating behavior",
        "endswith": "endsWith() has early-terminating behavior",
        "search": "search() has variable-time execution",
        "match": "match() has variable-time execution",
        # Variable-length encoding (may leak data length via timing)
        "textencoder": "TextEncoder may leak data length via timing; ensure fixed-length output",
        "textdecoder": "TextDecoder may leak data length via timing; ensure fixed-length input",
        "json.stringify": "JSON.stringify() produces variable-length output that may leak information",
        "json.parse": "JSON.parse() timing may vary based on input length/structure",
        "btoa": "btoa() produces variable-length output based on input",
        "atob": "atob() timing may vary based on input length",
        "encodeuricomponent": "encodeURIComponent() produces variable-length output",
        "decodeuricomponent": "decodeURIComponent() timing may vary based on input",
    },
}


# =============================================================================
# Python Dangerous Operations
# =============================================================================

DANGEROUS_PYTHON_BYTECODES = {
    "errors": {
        # Python < 3.11 division/modulo operations
        "binary_true_divide": "BINARY_TRUE_DIVIDE has variable-time execution",
        "binary_floor_divide": "BINARY_FLOOR_DIVIDE has variable-time execution",
        "binary_modulo": "BINARY_MODULO has variable-time execution",
        "inplace_true_divide": "INPLACE_TRUE_DIVIDE has variable-time execution",
        "inplace_floor_divide": "INPLACE_FLOOR_DIVIDE has variable-time execution",
        "inplace_modulo": "INPLACE_MODULO has variable-time execution",
        # Python 3.11+ uses BINARY_OP with oparg for these
        # We detect these specially in the parser
    },
    "warnings": {
        # Comparison operations
        "compare_op": "COMPARE_OP may early-terminate on secret data",
        "contains_op": "CONTAINS_OP has early-terminating behavior",
        # Table lookups (cache timing via secret-indexed access)
        "binary_subscr": "Subscript access may leak timing via cache if index depends on secrets",
        "store_subscr": "Subscript store may leak timing via cache if index depends on secrets",
        # Bit shift operations (may leak via timing if shift amount is secret)
        "binary_lshift": "Left shift may leak timing if shift amount depends on secrets",
        "binary_rshift": "Right shift may leak timing if shift amount depends on secrets",
        "inplace_lshift": "Inplace left shift may leak timing if shift amount depends on secrets",
        "inplace_rshift": "Inplace right shift may leak timing if shift amount depends on secrets",
    },
}

DANGEROUS_PYTHON_FUNCTIONS = {
    "errors": {
        # Predictable randomness (not cryptographically secure)
        "random.random": "random.random() is predictable; use secrets.token_bytes() instead",
        "random.randint": "random.randint() is predictable; use secrets.randbelow() instead",
        "random.randrange": "random.randrange() is predictable; use secrets.randbelow() instead",
        "random.choice": "random.choice() is predictable; use secrets.choice() instead",
        "random.shuffle": "random.shuffle() is predictable; use secrets module instead",
        "random.sample": "random.sample() is predictable; use secrets module instead",
        # Variable latency math operations
        "math.sqrt": "math.sqrt() has variable latency based on operand values",
        "math.pow": "math.pow() has variable latency based on operand values",
        # Dangerous eval
        "eval": "eval() has unpredictable timing characteristics",
        "exec": "exec() has unpredictable timing characteristics",
    },
    "warnings": {
        # Variable-time string operations
        "str.find": "str.find() has early-terminating behavior",
        "str.index": "str.index() has early-terminating behavior",
        "str.startswith": "str.startswith() has early-terminating behavior",
        "str.endswith": "str.endswith() has early-terminating behavior",
        # in operator on strings (detected via CONTAINS_OP)
        # Variable-length encoding (may leak data length via timing)
        "int.to_bytes": "int.to_bytes() output length may leak information about the integer",
        "int.from_bytes": "int.from_bytes() timing may vary based on input length",
        "struct.pack": "struct.pack() may leak data length via timing; ensure fixed-length output",
        "struct.unpack": "struct.unpack() may leak data length via timing; ensure fixed-length input",
        "json.dumps": "json.dumps() produces variable-length output that may leak information",
        "json.loads": "json.loads() timing may vary based on input length/structure",
        "pickle.dumps": "pickle.dumps() produces variable-length output that may leak information",
        "pickle.loads": "pickle.loads() timing varies based on input; also a security risk",
        "base64.b64encode": "base64.b64encode() produces variable-length output",
        "base64.b64decode": "base64.b64decode() timing may vary based on input length",
    },
}


# =============================================================================
# Ruby Dangerous Operations
# =============================================================================

DANGEROUS_RUBY_BYTECODES = {
    "errors": {
        # Division and modulo operations
        "opt_div": "opt_div has variable-time execution based on operand values",
        "opt_mod": "opt_mod has variable-time execution based on operand values",
    },
    "warnings": {
        # Comparison and equality operations
        "opt_eq": "opt_eq may early-terminate on secret data",
        "opt_neq": "opt_neq may early-terminate on secret data",
        "opt_lt": "opt_lt comparison may leak timing information",
        "opt_le": "opt_le comparison may leak timing information",
        "opt_gt": "opt_gt comparison may leak timing information",
        "opt_ge": "opt_ge comparison may leak timing information",
        "branchif": "Conditional branch may leak timing if condition depends on secrets",
        "branchunless": "Conditional branch may leak timing if condition depends on secrets",
        # Table lookups (cache timing via secret-indexed access)
        "opt_aref": "Array access may leak timing via cache if index depends on secrets",
        "opt_aset": "Array store may leak timing via cache if index depends on secrets",
        # Bit shift operations (may leak via timing if shift amount is secret)
        "opt_lshift": "Left shift may leak timing if shift amount depends on secrets",
        "opt_rshift": "Right shift may leak timing if shift amount depends on secrets",
        "opt_and": "Bitwise AND timing may vary based on operands",
        "opt_or": "Bitwise OR timing may vary based on operands",
    },
}

DANGEROUS_RUBY_FUNCTIONS = {
    "errors": {
        # Predictable randomness
        "rand": "rand() is predictable; use SecureRandom instead",
        "random": "Random is predictable; use SecureRandom instead",
        "srand": "srand() sets predictable seed; use SecureRandom instead",
        # Variable latency math operations
        "math.sqrt": "Math.sqrt() has variable latency based on operand values",
    },
    "warnings": {
        # Variable-time string operations
        "include?": "include?() has early-terminating behavior",
        "index": "index() has early-terminating behavior",
        "start_with?": "start_with?() has early-terminating behavior",
        "end_with?": "end_with?() has early-terminating behavior",
        "match": "match() has variable-time execution",
        "=~": "=~ regex match has variable-time execution",
        # Variable-length encoding (may leak data length via timing)
        "pack": "Array#pack() may leak data length via timing; ensure fixed-length output",
        "unpack": "String#unpack() may leak data length via timing; ensure fixed-length input",
        "to_json": "to_json() produces variable-length output that may leak information",
        "json.parse": "JSON.parse() timing may vary based on input length/structure",
        "marshal.dump": "Marshal.dump() produces variable-length output that may leak information",
        "marshal.load": "Marshal.load() timing varies based on input; also a security risk",
        "base64.encode64": "Base64.encode64() produces variable-length output",
        "base64.decode64": "Base64.decode64() timing may vary based on input length",
    },
}


# =============================================================================
# Java (JVM) Dangerous Operations
# =============================================================================

DANGEROUS_JAVA_BYTECODES = {
    "errors": {
        # Integer division - variable time based on operand values
        "idiv": "IDIV has variable-time execution based on operand values",
        "ldiv": "LDIV has variable-time execution based on operand values",
        "irem": "IREM has variable-time execution based on operand values",
        "lrem": "LREM has variable-time execution based on operand values",
        # Floating-point division - variable latency
        "fdiv": "FDIV has variable latency based on operand values",
        "ddiv": "DDIV has variable latency based on operand values",
        "frem": "FREM has variable latency based on operand values",
        "drem": "DREM has variable latency based on operand values",
    },
    "warnings": {
        # Conditional branches - may leak timing if condition depends on secrets
        "ifeq": "conditional branch may leak timing if condition depends on secret data",
        "ifne": "conditional branch may leak timing if condition depends on secret data",
        "iflt": "conditional branch may leak timing if condition depends on secret data",
        "ifge": "conditional branch may leak timing if condition depends on secret data",
        "ifgt": "conditional branch may leak timing if condition depends on secret data",
        "ifle": "conditional branch may leak timing if condition depends on secret data",
        "if_icmpeq": "conditional branch may leak timing if condition depends on secret data",
        "if_icmpne": "conditional branch may leak timing if condition depends on secret data",
        "if_icmplt": "conditional branch may leak timing if condition depends on secret data",
        "if_icmpge": "conditional branch may leak timing if condition depends on secret data",
        "if_icmpgt": "conditional branch may leak timing if condition depends on secret data",
        "if_icmple": "conditional branch may leak timing if condition depends on secret data",
        "if_acmpeq": "conditional branch may leak timing if condition depends on secret data",
        "if_acmpne": "conditional branch may leak timing if condition depends on secret data",
        "ifnull": "conditional branch may leak timing if condition depends on secret data",
        "ifnonnull": "conditional branch may leak timing if condition depends on secret data",
        # Table lookups - cache timing if index depends on secrets
        "iaload": "array access may leak timing via cache if index depends on secrets",
        "laload": "array access may leak timing via cache if index depends on secrets",
        "faload": "array access may leak timing via cache if index depends on secrets",
        "daload": "array access may leak timing via cache if index depends on secrets",
        "aaload": "array access may leak timing via cache if index depends on secrets",
        "baload": "array access may leak timing via cache if index depends on secrets",
        "caload": "array access may leak timing via cache if index depends on secrets",
        "saload": "array access may leak timing via cache if index depends on secrets",
        "iastore": "array store may leak timing via cache if index depends on secrets",
        "lastore": "array store may leak timing via cache if index depends on secrets",
        "fastore": "array store may leak timing via cache if index depends on secrets",
        "dastore": "array store may leak timing via cache if index depends on secrets",
        "aastore": "array store may leak timing via cache if index depends on secrets",
        "bastore": "array store may leak timing via cache if index depends on secrets",
        "castore": "array store may leak timing via cache if index depends on secrets",
        "sastore": "array store may leak timing via cache if index depends on secrets",
        "tableswitch": "switch statement may leak timing based on case value",
        "lookupswitch": "switch statement may leak timing based on case value",
    },
}

DANGEROUS_JAVA_FUNCTIONS = {
    "errors": {
        # Predictable randomness
        "java.util.random": "java.util.Random is predictable; use SecureRandom instead",
        "math.random": "Math.random() is predictable; use SecureRandom instead",
        # Variable latency math
        "math.sqrt": "Math.sqrt() has variable latency based on operand values",
        "math.pow": "Math.pow() has variable latency based on operand values",
    },
    "warnings": {
        # Variable-time comparisons
        "arrays.equals": "Arrays.equals() may early-terminate; use MessageDigest.isEqual()",
        "string.equals": "String.equals() may early-terminate on secret data",
        "string.compareto": "String.compareTo() has variable-time execution",
        "string.contentequals": "String.contentEquals() may early-terminate",
        # Variable-length encoding
        "base64.getencoder": "Base64 encoding produces variable-length output",
        "base64.getdecoder": "Base64 decoding timing may vary based on input",
    },
}


# =============================================================================
# Kotlin (JVM) Dangerous Operations
# =============================================================================

# Kotlin compiles to JVM bytecode, so it uses the same dangerous bytecodes as Java
DANGEROUS_KOTLIN_BYTECODES = DANGEROUS_JAVA_BYTECODES

DANGEROUS_KOTLIN_FUNCTIONS = {
    "errors": {
        # Predictable randomness (Kotlin stdlib)
        "random.nextint": "Random.nextInt() is predictable; use SecureRandom instead",
        "random.nextlong": "Random.nextLong() is predictable; use SecureRandom instead",
        "random.nextdouble": "Random.nextDouble() is predictable; use SecureRandom instead",
        "random.nextfloat": "Random.nextFloat() is predictable; use SecureRandom instead",
        "random.nextbytes": "Random.nextBytes() is predictable; use SecureRandom instead",
        "random.default": "Random.Default is predictable; use SecureRandom instead",
        # Java interop (same as Java)
        "java.util.random": "java.util.Random is predictable; use SecureRandom instead",
        "math.random": "Math.random() is predictable; use SecureRandom instead",
        # Variable latency math
        "kotlin.math.sqrt": "sqrt() has variable latency based on operand values",
        "kotlin.math.pow": "pow() has variable latency based on operand values",
        "math.sqrt": "Math.sqrt() has variable latency based on operand values",
        "math.pow": "Math.pow() has variable latency based on operand values",
    },
    "warnings": {
        # Variable-time comparisons (Kotlin-specific)
        "contentequals": "contentEquals() may early-terminate on secret data",
        "equals": "equals() may early-terminate on secret data",
        "compareto": "compareTo() has variable-time execution",
        # Arrays
        "arrays.equals": "Arrays.equals() may early-terminate; use MessageDigest.isEqual()",
        "arrays.contentequals": "contentEquals() may early-terminate on array comparison",
        # String operations
        "string.equals": "String.equals() may early-terminate on secret data",
        "string.compareto": "String.compareTo() has variable-time execution",
        # Variable-length encoding
        "base64.getencoder": "Base64 encoding produces variable-length output",
        "base64.getdecoder": "Base64 decoding timing may vary based on input",
        "encodetobytearray": "encodeToByteArray() produces variable-length output",
        "decodetostring": "decodeToString() timing may vary based on input",
    },
}


# =============================================================================
# C# (CIL/.NET) Dangerous Operations
# =============================================================================

DANGEROUS_CSHARP_BYTECODES = {
    "errors": {
        # Integer division - variable time based on operand values
        "div": "DIV has variable-time execution based on operand values",
        "div.un": "DIV.UN has variable-time execution based on operand values",
        "rem": "REM has variable-time execution based on operand values",
        "rem.un": "REM.UN has variable-time execution based on operand values",
    },
    "warnings": {
        # Conditional branches - may leak timing if condition depends on secrets
        "beq": "conditional branch may leak timing if condition depends on secret data",
        "beq.s": "conditional branch may leak timing if condition depends on secret data",
        "bne": "conditional branch may leak timing if condition depends on secret data",
        "bne.un": "conditional branch may leak timing if condition depends on secret data",
        "bne.un.s": "conditional branch may leak timing if condition depends on secret data",
        "blt": "conditional branch may leak timing if condition depends on secret data",
        "blt.s": "conditional branch may leak timing if condition depends on secret data",
        "blt.un": "conditional branch may leak timing if condition depends on secret data",
        "blt.un.s": "conditional branch may leak timing if condition depends on secret data",
        "bgt": "conditional branch may leak timing if condition depends on secret data",
        "bgt.s": "conditional branch may leak timing if condition depends on secret data",
        "bgt.un": "conditional branch may leak timing if condition depends on secret data",
        "bgt.un.s": "conditional branch may leak timing if condition depends on secret data",
        "ble": "conditional branch may leak timing if condition depends on secret data",
        "ble.s": "conditional branch may leak timing if condition depends on secret data",
        "ble.un": "conditional branch may leak timing if condition depends on secret data",
        "ble.un.s": "conditional branch may leak timing if condition depends on secret data",
        "bge": "conditional branch may leak timing if condition depends on secret data",
        "bge.s": "conditional branch may leak timing if condition depends on secret data",
        "bge.un": "conditional branch may leak timing if condition depends on secret data",
        "bge.un.s": "conditional branch may leak timing if condition depends on secret data",
        "brfalse": "conditional branch may leak timing if condition depends on secret data",
        "brfalse.s": "conditional branch may leak timing if condition depends on secret data",
        "brtrue": "conditional branch may leak timing if condition depends on secret data",
        "brtrue.s": "conditional branch may leak timing if condition depends on secret data",
        # Table lookups - cache timing if index depends on secrets
        "ldelem": "array access may leak timing via cache if index depends on secrets",
        "ldelem.i": "array access may leak timing via cache if index depends on secrets",
        "ldelem.i1": "array access may leak timing via cache if index depends on secrets",
        "ldelem.i2": "array access may leak timing via cache if index depends on secrets",
        "ldelem.i4": "array access may leak timing via cache if index depends on secrets",
        "ldelem.i8": "array access may leak timing via cache if index depends on secrets",
        "ldelem.u1": "array access may leak timing via cache if index depends on secrets",
        "ldelem.u2": "array access may leak timing via cache if index depends on secrets",
        "ldelem.u4": "array access may leak timing via cache if index depends on secrets",
        "ldelem.r4": "array access may leak timing via cache if index depends on secrets",
        "ldelem.r8": "array access may leak timing via cache if index depends on secrets",
        "ldelem.ref": "array access may leak timing via cache if index depends on secrets",
        "stelem": "array store may leak timing via cache if index depends on secrets",
        "stelem.i": "array store may leak timing via cache if index depends on secrets",
        "stelem.i1": "array store may leak timing via cache if index depends on secrets",
        "stelem.i2": "array store may leak timing via cache if index depends on secrets",
        "stelem.i4": "array store may leak timing via cache if index depends on secrets",
        "stelem.i8": "array store may leak timing via cache if index depends on secrets",
        "stelem.r4": "array store may leak timing via cache if index depends on secrets",
        "stelem.r8": "array store may leak timing via cache if index depends on secrets",
        "stelem.ref": "array store may leak timing via cache if index depends on secrets",
        "switch": "switch statement may leak timing based on case value",
    },
}

DANGEROUS_CSHARP_FUNCTIONS = {
    "errors": {
        # Predictable randomness
        "system.random": "System.Random is predictable; use RandomNumberGenerator instead",
        # Variable latency math
        "math.sqrt": "Math.Sqrt() has variable latency based on operand values",
        "math.pow": "Math.Pow() has variable latency based on operand values",
    },
    "warnings": {
        # Variable-time comparisons
        "sequenceequal": "SequenceEqual() may early-terminate; use FixedTimeEquals()",
        "string.equals": "String.Equals() may early-terminate on secret data",
        "string.compare": "String.Compare() has variable-time execution",
        "array.equals": "Array comparison may early-terminate",
        # Variable-length encoding
        "convert.tobase64string": "Base64 encoding produces variable-length output",
        "convert.frombase64string": "Base64 decoding timing may vary based on input",
    },
}


# =============================================================================
# ScriptAnalyzer Base Class
# =============================================================================


def qualified_call_pattern(func_name: str) -> str:
    """Regex matching `func_name` as written in source, case-insensitively.

    Table keys mix two shapes and they cannot be treated alike:

    - `string.equals` names a method on any receiver, so it must match
      `.equals(` regardless of what precedes the dot.
    - `arrays.equals`, `base64.getencoder` and `convert.tobase64string` name a
      member of a specific type, so they must match the qualified form only.
      Matching these as bare methods would report every `.equals(` call as
      `Arrays.equals`.

    The per-backend if/elif chains spelled out only a few keys and skipped the
    rest, which left the base64 and convert entries unreachable: the tables
    listed them and no source could ever match. Case-insensitivity is embedded
    with `(?i)` so callers that compile without flags still get it — the keys are
    lowercase while the source spells them `Base64.getEncoder` and `.Equals`.
    """
    if "." in func_name:
        qualifier, method = func_name.rsplit(".", 1)
        if qualifier == "string":
            return rf"(?i)\.{re.escape(method)}\s*\("
        return rf"(?i)\b{re.escape(func_name)}\s*\("
    return rf"(?i)\.{re.escape(func_name)}\s*\("


def blank_comments(source: str, style: str = "c") -> str:
    """Replace comment bodies with spaces, preserving offsets and line breaks.

    The source-level detectors are regex scans, so without this a `/** ... */`
    doc comment counted as a division and prose mentioning `Math.random()`
    counted as a call. Blanking rather than deleting keeps every subsequent match
    offset and line number correct.

    String literals are matched first and left intact, because a comment marker
    inside one is not a comment. Without that, `const u = "http://x"` blanked the
    rest of the line — losing any real finding on it — and a lone `"/*"` blanked
    every line up to the next `*/` anywhere in the file.

    This is still a regex, not a lexer. Unterminated literals, JavaScript regex
    literals like `/=/`, Ruby heredocs and `%w[]` literals are not modelled; the
    failure mode is a blanked or unblanked span, never a crash.

    Args:
        source: The file contents to scrub.
        style: `"c"` for `//` and `/* */` (C, C++, Java, Kotlin, C#, JS, TS),
            `"hash"` for `#` (Python, Ruby). PHP is absent deliberately: its
            detection is opcode-based and never scans source text.

    Returns:
        The source with comment bodies replaced by spaces.
    """
    literals = [
        r'"""(?:\\.|[^\\])*?"""',  # Python triple-quoted, before the single form
        r"'''(?:\\.|[^\\])*?'''",
        r'"(?:\\.|[^"\\\n])*"',
        r"'(?:\\.|[^'\\\n])*'",
        r"`(?:\\.|[^`\\])*`",  # JS template literal
    ]
    comments = [r"#[^\n]*"] if style == "hash" else [r"//[^\n]*", r"/\*.*?\*/"]
    pattern = "|".join(literals + comments)

    def scrub(match: re.Match) -> str:
        text = match.group(0)
        if text[0] in "\"'`":
            return text
        return "".join("\n" if char == "\n" else " " for char in text)

    return re.sub(pattern, scrub, source, flags=re.DOTALL)


class ScriptAnalyzer(ABC):
    """Base class for scripting language analyzers."""

    name: str = "unknown"

    @abstractmethod
    def is_available(self) -> bool:
        """Check if the analyzer's runtime is available."""
        raise NotImplementedError

    @abstractmethod
    def analyze(
        self,
        source_file: str,
        include_warnings: bool = False,
        function_filter: str | None = None,
    ) -> AnalysisReport:
        """
        Analyze source for timing violations.

        Args:
            source_file: Path to the source file to analyze
            include_warnings: Include warning-level violations
            function_filter: Regex pattern to filter functions

        Returns:
            AnalysisReport with results
        """
        raise NotImplementedError


# =============================================================================
# PHP Analyzer
# =============================================================================


class PHPAnalyzer(ScriptAnalyzer):
    """
    Analyzer for PHP scripts using VLD extension or OPcache debug output.

    Detects timing-unsafe opcodes and function calls in PHP code.
    """

    name = "php"

    def __init__(self, php_path: str | None = None):
        self.php_path = php_path or "php"
        self._vld_available: bool | None = None

    def is_available(self) -> bool:
        """Check if PHP is available."""
        try:
            result = subprocess.run(
                [self.php_path, "--version"],
                capture_output=True,
                text=True,
            )
            return result.returncode == 0
        except FileNotFoundError:
            return False

    def _check_vld_available(self) -> bool:
        """Check if VLD extension is available."""
        if self._vld_available is not None:
            return self._vld_available

        try:
            result = subprocess.run(
                [self.php_path, "-m"],
                capture_output=True,
                text=True,
            )
            self._vld_available = "vld" in result.stdout.lower()
        except FileNotFoundError:
            self._vld_available = False

        return self._vld_available

    def _get_vld_output(self, source_file: str) -> tuple[bool, str]:
        """Get VLD opcode dump for a PHP file."""
        cmd = [
            self.php_path,
            "-d",
            "vld.active=1",
            "-d",
            "vld.execute=0",
            "-d",
            "vld.verbosity=1",
            source_file,
        ]

        try:
            result = subprocess.run(cmd, capture_output=True, text=True)
            # VLD outputs to stderr
            return True, result.stderr
        except FileNotFoundError:
            return False, f"PHP not found: {self.php_path}"

    def _get_opcache_output(self, source_file: str) -> tuple[bool, str]:
        """Get OPcache debug output for a PHP file (fallback)."""
        cmd = [
            self.php_path,
            "-d",
            "opcache.enable_cli=1",
            "-d",
            "opcache.opt_debug_level=0x10000",
            source_file,
        ]

        try:
            result = subprocess.run(cmd, capture_output=True, text=True)
            # OPcache debug outputs to stderr
            return True, result.stderr
        except FileNotFoundError:
            return False, f"PHP not found: {self.php_path}"

    def _parse_vld_output(
        self,
        output: str,
        include_warnings: bool = False,
        function_filter: str | None = None,
    ) -> tuple[list[ParsedFunction], list[Violation]]:
        """
        Parse VLD output for dangerous opcodes and function calls.

        VLD output format example:
        Finding entry points
        Branch analysis from position: 0
        ...
        filename:       /path/to/file.php
        function name:  vulnerable_function
        ...
        line     #* E I O op                           fetch          ext  return  operands
        -------------------------------------------------------------------------------------
           5     0  E >   ASSIGN                                                   !0, 10
           6     1        ASSIGN                                                   !1, 3
           7     2        DIV                                              ~4      !0, !1
        """
        functions: list[ParsedFunction] = []
        violations = []

        current_function = None
        current_file = None
        in_opcode_section = False
        filter_pattern = re.compile(function_filter) if function_filter else None

        # Track function calls for detection
        pending_fcall: str | None = None

        for line in output.split("\n"):
            line_stripped = line.strip()

            # Detect function name
            func_match = re.match(r"function name:\s*(.+)", line_stripped, re.IGNORECASE)
            if func_match:
                func_name = func_match.group(1).strip()
                if func_name and func_name != "(null)":
                    current_function = func_name
                    functions.append({"name": current_function, "instructions": 0})
                continue

            # Detect filename
            file_match = re.match(r"filename:\s*(.+)", line_stripped, re.IGNORECASE)
            if file_match:
                current_file = file_match.group(1).strip()
                continue

            # Detect start of opcode listing
            # VLD format has header line with "line" and "op", then "---" separator
            if "---" in line_stripped:
                in_opcode_section = True
                continue

            # Also detect header line format
            if line_stripped.startswith("line") and "op" in line_stripped.lower():
                continue  # Skip header line, section starts after ---

            if not in_opcode_section:
                continue

            # Parse opcode line
            # Format: line# index flags opcode [fetch] [ext] [return] operands
            # Line number is optional (continuation lines don't have it)
            # Examples:
            #    5     0  E >   RECV    !0
            #          1        RECV    !1      (no line number)
            opcode_match = re.match(r"(?:(\d+)\s+)?(\d+)\s+[E>*\s]*([A-Z_]+)\s*(.*)", line_stripped)

            if not opcode_match:
                # Check for end of section
                if line_stripped.startswith("---") or not line_stripped:
                    in_opcode_section = False
                continue

            line_num = int(opcode_match.group(1)) if opcode_match.group(1) else None
            # group(2) is the index, group(3) is the opcode, group(4) is operands
            opcode = opcode_match.group(3).strip()
            operands = opcode_match.group(4).strip() if opcode_match.group(4) else ""

            # Update instruction count
            if functions:
                functions[-1]["instructions"] += 1

            # Check if we should skip this function
            if filter_pattern and current_function:
                if not filter_pattern.search(current_function):
                    continue

            opcode_lower = opcode.lower()

            # Track function calls (INIT_FCALL followed by DO_FCALL)
            if opcode in ("INIT_FCALL", "INIT_FCALL_BY_NAME", "INIT_NS_FCALL_BY_NAME"):
                # Extract function name from operands
                # Format varies: 'function_name' or "function_name"
                fname_match = re.search(r"['\"]([^'\"]+)['\"]", operands)
                if fname_match:
                    pending_fcall = fname_match.group(1).lower()

            elif opcode in ("DO_FCALL", "DO_ICALL", "DO_FCALL_BY_NAME"):
                if pending_fcall:
                    # Check if this function is dangerous
                    if pending_fcall in DANGEROUS_PHP_FUNCTIONS["errors"]:
                        violations.append(
                            Violation(
                                function=current_function or "<main>",
                                file=current_file or "",
                                line=line_num,
                                address="",
                                instruction=f"{opcode} {pending_fcall}",
                                mnemonic=pending_fcall.upper(),
                                reason=DANGEROUS_PHP_FUNCTIONS["errors"][pending_fcall],
                                severity=Severity.ERROR,
                            )
                        )
                    elif include_warnings and pending_fcall in DANGEROUS_PHP_FUNCTIONS["warnings"]:
                        violations.append(
                            Violation(
                                function=current_function or "<main>",
                                file=current_file or "",
                                line=line_num,
                                address="",
                                instruction=f"{opcode} {pending_fcall}",
                                mnemonic=pending_fcall.upper(),
                                reason=DANGEROUS_PHP_FUNCTIONS["warnings"][pending_fcall],
                                severity=Severity.WARNING,
                            )
                        )
                    pending_fcall = None

            # Check for dangerous opcodes
            if opcode_lower in DANGEROUS_PHP_OPCODES["errors"]:
                violations.append(
                    Violation(
                        function=current_function or "<main>",
                        file=current_file or "",
                        line=line_num,
                        address="",
                        instruction=f"{opcode} {operands}".strip(),
                        mnemonic=opcode.upper(),
                        reason=DANGEROUS_PHP_OPCODES["errors"][opcode_lower],
                        severity=Severity.ERROR,
                    )
                )
            elif include_warnings and opcode_lower in DANGEROUS_PHP_OPCODES["warnings"]:
                violations.append(
                    Violation(
                        function=current_function or "<main>",
                        file=current_file or "",
                        line=line_num,
                        address="",
                        instruction=f"{opcode} {operands}".strip(),
                        mnemonic=opcode.upper(),
                        reason=DANGEROUS_PHP_OPCODES["warnings"][opcode_lower],
                        severity=Severity.WARNING,
                    )
                )

        return functions, violations

    def _parse_opcache_output(
        self,
        output: str,
        include_warnings: bool = False,
        function_filter: str | None = None,
    ) -> tuple[list[ParsedFunction], list[Violation]]:
        """Parse `opcache.opt_debug_level` output.

        This used to delegate to the VLD parser on the claim that the formats
        were "similar enough". They share nothing structural: VLD prints a
        `function name:` header and a `---` ruled table, OPcache prints

            ct_high_bits:
                 ; (lines=11, args=2, vars=2, tmps=2)
                 ; /path/to/file.php:7-10
            0000 CV0($key_coef) = RECV 1
            0004 T2 = MUL CV1($gamma2) int(2)

        so the VLD parser never entered its opcode section and every PHP file
        analysed without the VLD extension — which is the common case, since VLD
        is an unbundled PECL build — reported zero findings and PASSED.

        Args:
            output: Raw OPcache debug output.
            include_warnings: Also report warning-severity findings.
            function_filter: Regex; when given, only matching functions report.

        Returns:
            The functions seen and the violations found.
        """
        functions: list[ParsedFunction] = []
        violations: list[Violation] = []

        current_function: str | None = None
        current_line: int | None = None
        filter_pattern = re.compile(function_filter) if function_filter else None

        # `ct_high_bits:` or `$_main:` at the start of a line opens a block.
        header_re = re.compile(r"^([A-Za-z_$][\w$\\:]*)\s*:\s*$")
        # `; /path/file.php:7-10` gives the block's source range.
        location_re = re.compile(r"^;\s*(.+?):(\d+)(?:-\d+)?\s*$")
        # `0004 T2 = MUL CV1($gamma2) int(2)` / `0000 RETURN int(1)`
        # `\d{4,}`, not `\d{4}`: op_arrays past 9999 opcodes exist in generated code,
        # and a fixed width made `10000 T2 = MUL …` unparseable, silently dropping
        # every opcode from that point on while `functions` stayed non-empty — so the
        # "nothing parsed" guard would not fire and the report looked like a partial pass.
        opcode_re = re.compile(r"^(\d{4,})\s+(?:\S+\s*=\s*)?([A-Z][A-Z0-9_]*)\s*(.*)$")

        def report(mnemonic: str, reason: str, severity: Severity, offset: str, text: str) -> None:
            if filter_pattern and current_function and not filter_pattern.search(current_function):
                return
            violations.append(
                Violation(
                    function=current_function or "<main>",
                    file="",
                    line=current_line,
                    address=offset,
                    instruction=text,
                    mnemonic=mnemonic,
                    reason=reason,
                    severity=severity,
                )
            )

        for line in output.split("\n"):
            stripped = line.strip()
            if not stripped:
                continue

            header = header_re.match(stripped)
            if header:
                name = header.group(1)
                current_function = "<main>" if name == "$_main" else name
                current_line = None
                functions.append({"name": current_function, "instructions": 0})
                continue

            if stripped.startswith(";"):
                location = location_re.match(stripped)
                if location and location.group(1).endswith(".php"):
                    current_line = int(location.group(2))
                continue

            opcode_match = opcode_re.match(stripped)
            if not opcode_match:
                continue

            offset, opcode, operands = opcode_match.groups()
            if functions:
                functions[-1]["instructions"] += 1
            opcode_lower = opcode.lower()

            if opcode_lower in DANGEROUS_PHP_OPCODES["errors"]:
                report(
                    opcode,
                    DANGEROUS_PHP_OPCODES["errors"][opcode_lower],
                    Severity.ERROR,
                    offset,
                    stripped,
                )
            elif include_warnings and opcode_lower in DANGEROUS_PHP_OPCODES["warnings"]:
                report(
                    opcode,
                    DANGEROUS_PHP_OPCODES["warnings"][opcode_lower],
                    Severity.WARNING,
                    offset,
                    stripped,
                )

            # Calls name their target in the init opcode: INIT_FCALL 2 112 string("mt_rand")
            if opcode.startswith("INIT_"):
                called = re.search(r'string\("([^"]+)"\)', operands)
                if not called:
                    continue
                name = called.group(1).lower().lstrip("\\")
                if name in DANGEROUS_PHP_FUNCTIONS["errors"]:
                    report(
                        name.upper(),
                        DANGEROUS_PHP_FUNCTIONS["errors"][name],
                        Severity.ERROR,
                        offset,
                        stripped,
                    )
                elif include_warnings and name in DANGEROUS_PHP_FUNCTIONS["warnings"]:
                    report(
                        name.upper(),
                        DANGEROUS_PHP_FUNCTIONS["warnings"][name],
                        Severity.WARNING,
                        offset,
                        stripped,
                    )

        return functions, violations

    def analyze(
        self,
        source_file: str,
        include_warnings: bool = False,
        function_filter: str | None = None,
    ) -> AnalysisReport:
        """Analyze a PHP file for constant-time violations."""
        source_path = Path(source_file)
        if not source_path.exists():
            raise FileNotFoundError(f"Source file not found: {source_file}")

        # Try VLD first, fall back to OPcache
        use_vld = self._check_vld_available()

        if use_vld:
            success, output = self._get_vld_output(str(source_path.absolute()))
            backend = "vld"
        else:
            success, output = self._get_opcache_output(str(source_path.absolute()))
            backend = "opcache"
            print("Note: VLD extension not available, using OPcache debug output", file=sys.stderr)

        if not success:
            raise RuntimeError(f"Failed to get opcodes: {output}")

        # Each backend gets its own parser: the formats are unrelated, and calling
        # the VLD parser on OPcache output is why this path found nothing.
        parse = self._parse_vld_output if use_vld else self._parse_opcache_output
        functions, violations = parse(
            output,
            include_warnings,
            function_filter,
        )

        if not functions:
            raise RuntimeError(
                f"Parsed no functions from {backend} output for {source_file}. Reporting "
                "PASSED here would mean 'the parser understood nothing', not 'the code is "
                "constant-time'."
            )

        return AnalysisReport(
            architecture="zend",  # PHP's Zend Engine
            compiler=f"php/{backend}",
            optimization="default",
            source_file=str(source_file),
            total_functions=len(functions),
            total_instructions=sum(f["instructions"] for f in functions),
            violations=violations,
        )


# =============================================================================
# JavaScript/TypeScript Analyzer
# =============================================================================


class JavaScriptAnalyzer(ScriptAnalyzer):
    """
    Analyzer for JavaScript/TypeScript using V8 bytecode output.

    For TypeScript files, transpiles to JavaScript first using tsc.
    """

    name = "javascript"

    def __init__(self, node_path: str | None = None, tsc_path: str | None = None):
        self.node_path = node_path or "node"
        self.tsc_path = tsc_path or "tsc"

    def is_available(self) -> bool:
        """Check if Node.js is available."""
        try:
            result = subprocess.run(
                [self.node_path, "--version"],
                capture_output=True,
                text=True,
            )
            return result.returncode == 0
        except FileNotFoundError:
            return False

    def _is_tsc_available(self) -> bool:
        """Check if TypeScript compiler is available."""
        try:
            result = subprocess.run(
                [self.tsc_path, "--version"],
                capture_output=True,
                text=True,
            )
            return result.returncode == 0
        except FileNotFoundError:
            # Try npx tsc
            try:
                result = subprocess.run(
                    ["npx", "tsc", "--version"],
                    capture_output=True,
                    text=True,
                )
                if result.returncode == 0:
                    self.tsc_path = "npx tsc"
                    return True
            except FileNotFoundError:
                pass
            return False

    def _transpile_typescript(self, source_file: str, output_dir: str) -> tuple[bool, str]:
        """Transpile TypeScript to JavaScript."""
        source_path = Path(source_file)

        # Check for tsconfig.json in the same directory or parent directories
        tsconfig = None
        check_dir = source_path.parent
        for _ in range(5):  # Check up to 5 parent directories
            possible_config = check_dir / "tsconfig.json"
            if possible_config.exists():
                tsconfig = str(possible_config)
                break
            if check_dir.parent == check_dir:
                break
            check_dir = check_dir.parent

        output_file = Path(output_dir) / source_path.with_suffix(".js").name

        if self.tsc_path.startswith("npx"):
            cmd = ["npx", "tsc"]
        else:
            cmd = [self.tsc_path]

        cmd.extend(
            [
                "--outDir",
                output_dir,
                "--target",
                "ES2020",
                "--module",
                "commonjs",
                "--skipLibCheck",
                "--noEmit",
                "false",
            ]
        )

        if tsconfig:
            cmd.extend(["--project", tsconfig])

        cmd.append(str(source_path.absolute()))

        try:
            result = subprocess.run(cmd, capture_output=True, text=True)
            if result.returncode != 0:
                return False, result.stderr or result.stdout
            return True, str(output_file)
        except FileNotFoundError:
            return False, "TypeScript compiler not found"

    def _get_v8_bytecode(
        self, source_file: str, function_filter: str | None = None
    ) -> tuple[bool, str]:
        """Get V8 bytecode output for a JavaScript file.

        `--no-lazy` compiles function bodies V8 would otherwise skip. Without it
        only executed code has bytecode, so a module that defines crypto helpers
        and exports them — the normal shape for a library — was analysed as if it
        contained nothing. It also pulls in hundreds of node-internal functions,
        which `_declared_function_names` filters back out.
        """
        cmd = [self.node_path, "--no-lazy", "--print-bytecode"]

        if function_filter:
            cmd.extend(["--print-bytecode-filter", function_filter])

        cmd.append(source_file)

        try:
            result = subprocess.run(cmd, capture_output=True, text=True)
            # V8 bytecode goes to stdout
            return True, result.stdout
        except FileNotFoundError:
            return False, f"Node.js not found: {self.node_path}"

    # Words that look like a call site but open a block, so they must never be
    # mistaken for a declared function name.
    _JS_KEYWORDS = frozenset(
        {
            "if",
            "for",
            "while",
            "switch",
            "catch",
            "do",
            "else",
            "return",
            "typeof",
            "function",
            "class",
            "new",
            "await",
            "yield",
        }
    )

    @classmethod
    def _declared_function_names(cls, source: str) -> set[str]:
        """Names declared in `source`, used to drop node's own functions.

        Unlike Go, V8's bytecode dump carries no file attribution — every
        function in the process appears the same way — so the only available
        discriminator is the name. That makes this a heuristic, with two known
        consequences: a user function sharing a name with a node internal lets
        that internal through, and anonymous callbacks in user code are dropped.
        Both are visible in the report rather than silent, because the
        source-level scan still covers division and RNG calls textually.
        """
        blanked = blank_comments(source, "c")
        names: set[str] = set()
        patterns = (
            r"\bfunction\s*\*?\s*([A-Za-z_$][\w$]*)",  # function decls and generators
            r"\bclass\s+([A-Za-z_$][\w$]*)",  # class decls
            r"\b(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=",  # arrow/function assignment
            r"([A-Za-z_$][\w$]*)\s*[:=]\s*(?:async\s*)?(?:function|\()",  # props and arrows
            # Method shorthand, anywhere on a line — `class C { m(a) { … } }` is
            # legal on one line. Erring toward over-capture is deliberate: an
            # extra name only risks admitting a same-named node internal, while a
            # missed name drops the user's own function from the analysis.
            r"(?:static\s+|async\s+|get\s+|set\s+)*([A-Za-z_$][\w$]*)\s*\([^)]*\)\s*\{",
        )
        for pattern in patterns:
            for match in re.finditer(pattern, blanked, re.MULTILINE):
                name = match.group(1)
                if name not in cls._JS_KEYWORDS:
                    names.add(name)
        return names

    @staticmethod
    def _line_of_offset(source: str, offset: int) -> int | None:
        """Convert a V8 source position (a byte offset) to a 1-based line number."""
        if offset < 0 or offset > len(source):
            return None
        return source[:offset].count("\n") + 1

    def _parse_v8_bytecode(
        self,
        output: str,
        source_file: str,
        include_warnings: bool = False,
        function_filter: str | None = None,
        compiled_source: str | None = None,
        map_positions: bool = False,
    ) -> tuple[list[ParsedFunction], list[Violation]]:
        """
        Parse V8 bytecode output for dangerous operations.

        V8 bytecode format example:
        [generated bytecode for function: vulnerableFunction (0x...)]
        Bytecode length: 42
        Parameter count 2
        Register count 3
        Frame size 24
                0 : LdaSmi [10]
                2 : Star0
                3 : LdaSmi [3]
                5 : Star1
                6 : Ldar r0
                8 : Div r1
               10 : Return
        """
        functions: list[ParsedFunction] = []
        violations = []

        current_function = None
        current_file = source_file
        in_bytecode_section = False
        filter_pattern = re.compile(function_filter) if function_filter else None

        # V8 dumps every function the process compiles, node's own included, and
        # names are the only discriminator available. Restrict to what the file
        # under analysis declares; `declared` is empty only when the source could
        # not be read, in which case nothing is filtered.
        # None means "could not read the compiled file", which must not be
        # confused with "no declarations found". Treating an empty set as
        # "filtering off" let an unreadable file report hundreds of node-internal
        # functions as findings, indistinguishable from a genuinely noisy file.
        if compiled_source is None:
            declared = None
            print(
                "Note: could not read the compiled JavaScript, so node-internal "
                "functions cannot be filtered out of the bytecode findings",
                file=sys.stderr,
            )
        else:
            declared = self._declared_function_names(compiled_source)

        # Track function calls
        pending_call: str | None = None

        for line in output.split("\n"):
            line_stripped = line.strip()

            # Detect function start
            # Format: [generated bytecode for function: functionName (0x...)]
            func_match = re.match(r"\[generated bytecode for function:\s*([^\s(]+)", line_stripped)
            if func_match:
                func_name = func_match.group(1).strip()
                # Skip internal Node.js functions
                if func_name and not func_name.startswith("__"):
                    if declared is not None and func_name not in declared:
                        current_function = None
                        in_bytecode_section = False
                        continue
                    current_function = func_name
                    functions.append({"name": current_function, "instructions": 0})
                    in_bytecode_section = True
                continue

            # Detect end of bytecode section
            if line_stripped.startswith("[") and "bytecode" in line_stripped.lower():
                in_bytecode_section = False
                continue

            if not in_bytecode_section:
                continue

            # Skip metadata lines
            if any(
                line_stripped.startswith(x)
                for x in [
                    "Bytecode length:",
                    "Parameter count",
                    "Register count",
                    "Frame size",
                    "Constant pool",
                    "Handler Table",
                ]
            ):
                continue

            # Parse a bytecode instruction. Real `node --print-bytecode` output
            # carries a source position, the bytecode address and the raw opcode
            # bytes ahead of the mnemonic:
            #    67 E> 0x17461d981ece @   14 : 3e 03 04          Div a0, [4]
            #          0x17461d981ed1 @   17 : c7                Star2
            # Matching only `offset : Mnemonic` parsed none of it, so every V8
            # file came back with zero instructions and no division findings.
            # The leading segments stay optional so the bare form still parses.
            bytecode_match = re.match(
                r"(?:(\d+)\s+[SE]>\s*)?"  # source position, e.g. `67 E>`
                r"(?:0x[0-9a-fA-F]+\s*@\s*)?"  # bytecode address
                r"(\d+)\s*:\s*"  # offset within the function
                r"(?:(?:[0-9a-f]{2}\s+)+)?"  # raw opcode bytes
                r"([A-Za-z][A-Za-z0-9]*)\s*(.*)",  # mnemonic and operands
                line_stripped,
            )

            if not bytecode_match:
                continue

            # group(1) is V8's source *position*: a byte offset into the compiled
            # file, not a line number. Convert it so findings are navigable; when
            # the compiled file is transpiled output the offsets refer to that
            # output, so `compiled_source` is only passed for plain JavaScript.
            source_line = (
                self._line_of_offset(compiled_source, int(bytecode_match.group(1)))
                if map_positions and compiled_source and bytecode_match.group(1)
                else None
            )
            offset = bytecode_match.group(2)
            instruction = bytecode_match.group(3)
            operands = bytecode_match.group(4).strip()

            # Update instruction count
            if functions:
                functions[-1]["instructions"] += 1

            # Check if we should skip this function
            if filter_pattern and current_function:
                if not filter_pattern.search(current_function):
                    continue

            instruction_lower = instruction.lower()

            # Track function calls
            if instruction in (
                "CallRuntime",
                "CallUndefinedReceiver0",
                "CallUndefinedReceiver1",
                "CallUndefinedReceiver2",
                "CallProperty0",
                "CallProperty1",
                "CallProperty2",
            ):
                # Try to extract function name from operands
                # This is approximate since V8 bytecode uses indices
                pending_call = operands.lower()

            # Check for dangerous bytecodes
            if instruction_lower in DANGEROUS_JS_BYTECODES["errors"]:
                violations.append(
                    Violation(
                        function=current_function or "<anonymous>",
                        file=current_file,
                        line=source_line,
                        address=offset,
                        instruction=f"{instruction} {operands}".strip(),
                        mnemonic=instruction.upper(),
                        reason=DANGEROUS_JS_BYTECODES["errors"][instruction_lower],
                        severity=Severity.ERROR,
                    )
                )
            elif include_warnings and instruction_lower in DANGEROUS_JS_BYTECODES["warnings"]:
                violations.append(
                    Violation(
                        function=current_function or "<anonymous>",
                        file=current_file,
                        line=source_line,
                        address=offset,
                        instruction=f"{instruction} {operands}".strip(),
                        mnemonic=instruction.upper(),
                        reason=DANGEROUS_JS_BYTECODES["warnings"][instruction_lower],
                        severity=Severity.WARNING,
                    )
                )

        return functions, violations

    def _detect_dangerous_function_calls(
        self,
        source_file: str,
        include_warnings: bool = False,
    ) -> list[Violation]:
        """
        Detect dangerous function calls and operators via static analysis of source.

        This complements bytecode analysis since function names aren't
        always clear in V8 bytecode output.
        """
        violations = []

        try:
            with open(source_file) as f:
                source = blank_comments(f.read(), "c")
        except OSError:
            return violations

        # Simple regex-based detection for common patterns
        for func_name, reason in DANGEROUS_JS_FUNCTIONS["errors"].items():
            # Match function calls like Math.sqrt() or standalone sqrt()
            pattern = rf"\b{re.escape(func_name)}\s*\("
            for match in re.finditer(pattern, source, re.IGNORECASE):
                # Get line number
                line_num = source[: match.start()].count("\n") + 1
                violations.append(
                    Violation(
                        function="<source>",
                        file=source_file,
                        line=line_num,
                        address="",
                        instruction=match.group(0),
                        mnemonic=func_name.upper().replace(".", "_"),
                        reason=reason,
                        severity=Severity.ERROR,
                    )
                )

        # Detect division and modulo operators in source
        # Pattern matches: a / b, a % b (but not // comments or /= assignment)
        div_pattern = r"[^/]\s*/\s*[^/=*]"
        for match in re.finditer(div_pattern, source):
            # Skip if inside a comment or regex
            line_start = source.rfind("\n", 0, match.start()) + 1
            line_end = source.find("\n", match.start())
            if line_end == -1:
                line_end = len(source)
            line = source[line_start:line_end]
            # Skip comment lines
            if line.strip().startswith("//") or line.strip().startswith("*"):
                continue
            line_num = source[: match.start()].count("\n") + 1
            violations.append(
                Violation(
                    function="<source>",
                    file=source_file,
                    line=line_num,
                    address="",
                    instruction="/",
                    mnemonic="DIV_OP",
                    reason="Division operator has variable-time execution",
                    severity=Severity.ERROR,
                )
            )

        mod_pattern = r"\s%\s*[^=]"
        for match in re.finditer(mod_pattern, source):
            line_start = source.rfind("\n", 0, match.start()) + 1
            line_end = source.find("\n", match.start())
            if line_end == -1:
                line_end = len(source)
            line = source[line_start:line_end]
            if line.strip().startswith("//") or line.strip().startswith("*"):
                continue
            line_num = source[: match.start()].count("\n") + 1
            violations.append(
                Violation(
                    function="<source>",
                    file=source_file,
                    line=line_num,
                    address="",
                    instruction="%",
                    mnemonic="MOD_OP",
                    reason="Modulo operator has variable-time execution",
                    severity=Severity.ERROR,
                )
            )

        if include_warnings:
            for func_name, reason in DANGEROUS_JS_FUNCTIONS["warnings"].items():
                # `(?:\.|\b)` so both method calls and globals match: requiring the
                # leading dot made `btoa(`, `atob(`, `JSON.parse(` and the other
                # non-method entries unreachable.
                pattern = rf"(?:\.|\b){re.escape(func_name)}\s*\("
                for match in re.finditer(pattern, source, re.IGNORECASE):
                    line_num = source[: match.start()].count("\n") + 1
                    violations.append(
                        Violation(
                            function="<source>",
                            file=source_file,
                            line=line_num,
                            address="",
                            instruction=match.group(0),
                            mnemonic=func_name.upper(),
                            reason=reason,
                            severity=Severity.WARNING,
                        )
                    )

        return violations

    def analyze(
        self,
        source_file: str,
        include_warnings: bool = False,
        function_filter: str | None = None,
    ) -> AnalysisReport:
        """Analyze a JavaScript or TypeScript file for constant-time violations."""
        source_path = Path(source_file)
        if not source_path.exists():
            raise FileNotFoundError(f"Source file not found: {source_file}")

        js_file = source_file
        is_typescript = source_path.suffix.lower() in (".ts", ".tsx")

        # Handle TypeScript
        if is_typescript:
            if not self._is_tsc_available():
                raise RuntimeError(
                    "TypeScript compiler not found. Install with: npm install -g typescript"
                )

            with tempfile.TemporaryDirectory() as tmpdir:
                success, result = self._transpile_typescript(source_file, tmpdir)
                if not success:
                    raise RuntimeError(f"TypeScript compilation failed: {result}")
                js_file = result

                # Analyze the transpiled JS
                return self._analyze_js(
                    js_file,
                    source_file,  # Report against original TS file
                    include_warnings,
                    function_filter,
                )
        else:
            return self._analyze_js(
                js_file,
                source_file,
                include_warnings,
                function_filter,
            )

    def _analyze_js(
        self,
        js_file: str,
        report_file: str,
        include_warnings: bool = False,
        function_filter: str | None = None,
    ) -> AnalysisReport:
        """Analyze a JavaScript file."""
        success, output = self._get_v8_bytecode(js_file, function_filter)
        if not success:
            raise RuntimeError(f"Failed to get V8 bytecode: {output}")

        try:
            with open(js_file, encoding="utf-8", errors="replace") as handle:
                compiled_source = handle.read()
        except OSError:
            compiled_source = None

        # TypeScript is transpiled first, so V8's positions index the generated
        # JavaScript. Reporting those as line numbers in the .ts would point at
        # the wrong code, so mapping is enabled only when no transpile happened.
        map_positions = os.path.realpath(js_file) == os.path.realpath(report_file)

        functions, violations = self._parse_v8_bytecode(
            output,
            report_file,
            include_warnings,
            function_filter,
            compiled_source=compiled_source,
            map_positions=map_positions,
        )

        # Also check for dangerous function calls in source
        source_violations = self._detect_dangerous_function_calls(
            report_file if Path(report_file).exists() else js_file,
            include_warnings,
        )

        # Merge violations, avoiding duplicates. The two passes name the same
        # operator differently — bytecode reports DIV, the source scan DIV_OP — so
        # also drop a source-scan operator finding when the bytecode pass already
        # reported one on that line. Keep the bytecode one: it names the enclosing
        # function. The source scan still contributes on lines the bytecode pass
        # cannot reach, such as anonymous callbacks.
        operator_equivalents = {"DIV_OP": {"DIV", "DIVSMI"}, "MOD_OP": {"MOD", "MODSMI"}}
        existing = {(v.line, v.mnemonic) for v in violations}
        lines_by_mnemonic: dict[str, set[int | None]] = {}
        for v in violations:
            lines_by_mnemonic.setdefault(v.mnemonic, set()).add(v.line)

        for v in source_violations:
            if (v.line, v.mnemonic) in existing:
                continue
            covered = operator_equivalents.get(v.mnemonic, set())
            if v.line is not None and any(
                v.line in lines_by_mnemonic.get(mnemonic, set()) for mnemonic in covered
            ):
                continue
            violations.append(v)

        return AnalysisReport(
            architecture="v8",
            compiler="node",
            optimization="default",
            source_file=report_file,
            total_functions=len(functions),
            total_instructions=sum(f["instructions"] for f in functions),
            violations=violations,
        )


# =============================================================================
# Python Analyzer
# =============================================================================


class PythonAnalyzer(ScriptAnalyzer):
    """
    Analyzer for Python scripts using the dis module for bytecode disassembly.

    Detects timing-unsafe bytecodes and function calls in Python code.
    """

    name = "python"

    # Python 3.11+ collapses arithmetic into BINARY_OP, disambiguated by an oparg
    # that dis renders as the operator symbol: `BINARY_OP  2 (//)`. Key off the
    # symbol, not the number. The numbers come from CPython's `_nb_ops` table and
    # are renumbered whenever an operator is added — an earlier version of this
    # map read oparg 12 as `//` when 12 is `^`, so every constant-time XOR was
    # reported as a division and every floor division was missed.
    BINARY_OP_DIV_SYMBOLS = {
        "/": "BINARY_OP_TRUEDIV",
        "//": "BINARY_OP_FLOORDIV",
        "%": "BINARY_OP_MODULO",
        "/=": "BINARY_OP_INPLACE_TRUEDIV",
        "//=": "BINARY_OP_INPLACE_FLOORDIV",
        "%=": "BINARY_OP_INPLACE_MODULO",
    }

    def __init__(self, python_path: str | None = None):
        # sys.executable, not "python3": the analyzer already runs under uv, and the
        # modern-python shims refuse a bare `python3 --version` probe.
        self.python_path = python_path or sys.executable or "python3"

    def is_available(self) -> bool:
        """Check if Python is available."""
        try:
            result = subprocess.run(
                [self.python_path, "--version"],
                capture_output=True,
                text=True,
            )
            return result.returncode == 0
        except FileNotFoundError:
            return False

    def _get_dis_output(self, source_file: str) -> tuple[bool, str]:
        """Get Python dis module output for bytecode disassembly."""
        cmd = [
            self.python_path,
            "-m",
            "dis",
            source_file,
        ]

        try:
            result = subprocess.run(cmd, capture_output=True, text=True)
            # dis outputs to stdout
            if result.returncode != 0:
                return False, result.stderr or result.stdout
            return True, result.stdout
        except FileNotFoundError:
            return False, f"Python not found: {self.python_path}"

    def _parse_dis_output(
        self,
        output: str,
        source_file: str,
        include_warnings: bool = False,
        function_filter: str | None = None,
    ) -> tuple[list[ParsedFunction], list[Violation]]:
        """
        Parse Python dis output for dangerous bytecodes.

        dis output format example:
        Disassembly of <code object vulnerable_function at 0x...>:
          3           0 LOAD_FAST                0 (value)
                      2 LOAD_FAST                1 (modulus)
                      4 BINARY_TRUE_DIVIDE
                      6 STORE_FAST               2 (result)
        ...

        Python 3.11+ format:
        Disassembly of <code object vulnerable_function at 0x...>:
          3           0 RESUME                   0

          4           2 LOAD_FAST                0 (value)
                      4 LOAD_FAST                1 (modulus)
                      6 BINARY_OP               11 (/)
                      8 STORE_FAST               2 (result)
        """
        functions: list[ParsedFunction] = []
        violations = []

        current_function = None
        last_line_num = None
        filter_pattern = re.compile(function_filter) if function_filter else None

        for line in output.split("\n"):
            line_stripped = line.strip()

            # Detect function/code object start
            # Format: Disassembly of <code object functionName at 0x...>:
            func_match = re.match(r"Disassembly of <code object\s+([^\s>]+)", line_stripped)
            if func_match:
                func_name = func_match.group(1).strip()
                current_function = func_name
                # Reset, or the first instructions of this code object inherit the
                # previous function's line number when dis omits one.
                last_line_num = None
                functions.append({"name": current_function, "instructions": 0})
                continue

            # Also detect module-level code
            if line_stripped.startswith("Disassembly of") and "<module>" in line_stripped:
                current_function = "<module>"
                last_line_num = None
                functions.append({"name": current_function, "instructions": 0})
                continue

            # Parse bytecode instruction. Every column ahead of the opcode is
            # optional, because dis has dropped and added them across versions:
            # 3.13 prints no byte offsets at all, and 3.13+ prints jump labels
            # (`L1:`) where older versions printed `>>`. Requiring the offset made
            # this skip every line except the first of each source line, which is
            # how `x // secret` came back clean on 3.13.
            #   3.10:   3     >>   12 BINARY_TRUE_DIVIDE
            #   3.11:   3           6 BINARY_OP               11 (/)
            #   3.13:   3             BINARY_OP                2 (//)
            #   3.13:         L1:     FOR_ITER                15 (to L3)
            bytecode_match = re.match(
                r"(?:(\d+)\s+)?(?:L\d+:\s*)?(?:>>\s*)?(?:(\d+)\s+)?([A-Z][A-Z0-9_]*)\s*(.*)",
                line_stripped,
            )

            if not bytecode_match:
                continue

            # dis prints the source line only on the first instruction of that
            # line, so carry it forward: otherwise every violation after the first
            # reports no line and the reviewer cannot navigate to it.
            if bytecode_match.group(1):
                last_line_num = int(bytecode_match.group(1))
            line_num = last_line_num
            offset = bytecode_match.group(2)
            instruction = bytecode_match.group(3).strip()
            operands = bytecode_match.group(4).strip() if bytecode_match.group(4) else ""

            # Update instruction count
            if functions:
                functions[-1]["instructions"] += 1

            # Check if we should skip this function
            if filter_pattern and current_function:
                if not filter_pattern.search(current_function):
                    continue

            instruction_lower = instruction.lower()

            # Handle Python 3.11+ BINARY_OP, e.g. `BINARY_OP  2 (//)`
            if instruction == "BINARY_OP":
                symbol_match = re.search(r"\(([^)]+)\)", operands)
                if symbol_match:
                    symbol = symbol_match.group(1).strip()
                    if symbol in self.BINARY_OP_DIV_SYMBOLS:
                        op_name = self.BINARY_OP_DIV_SYMBOLS[symbol]
                        violations.append(
                            Violation(
                                function=current_function or "<module>",
                                file=source_file,
                                line=line_num,
                                address=offset,
                                instruction=f"{instruction} {operands}".strip(),
                                mnemonic=op_name,
                                reason=f"{op_name} has variable-time execution",
                                severity=Severity.ERROR,
                            )
                        )
                continue

            # Check for dangerous bytecodes (Python < 3.11)
            if instruction_lower in DANGEROUS_PYTHON_BYTECODES["errors"]:
                violations.append(
                    Violation(
                        function=current_function or "<module>",
                        file=source_file,
                        line=line_num,
                        address=offset,
                        instruction=f"{instruction} {operands}".strip(),
                        mnemonic=instruction.upper(),
                        reason=DANGEROUS_PYTHON_BYTECODES["errors"][instruction_lower],
                        severity=Severity.ERROR,
                    )
                )
            elif include_warnings and instruction_lower in DANGEROUS_PYTHON_BYTECODES["warnings"]:
                violations.append(
                    Violation(
                        function=current_function or "<module>",
                        file=source_file,
                        line=line_num,
                        address=offset,
                        instruction=f"{instruction} {operands}".strip(),
                        mnemonic=instruction.upper(),
                        reason=DANGEROUS_PYTHON_BYTECODES["warnings"][instruction_lower],
                        severity=Severity.WARNING,
                    )
                )

        return functions, violations

    def _detect_dangerous_function_calls(
        self,
        source_file: str,
        include_warnings: bool = False,
    ) -> list[Violation]:
        """
        Detect dangerous function calls via static analysis of source.
        """
        violations = []

        try:
            with open(source_file) as f:
                source = blank_comments(f.read(), "hash")
        except OSError:
            return violations

        # Detect dangerous function calls
        for func_name, reason in DANGEROUS_PYTHON_FUNCTIONS["errors"].items():
            # Match function calls like random.random() or math.sqrt()
            pattern = rf"\b{re.escape(func_name)}\s*\("
            for match in re.finditer(pattern, source, re.IGNORECASE):
                line_num = source[: match.start()].count("\n") + 1
                violations.append(
                    Violation(
                        function="<source>",
                        file=source_file,
                        line=line_num,
                        address="",
                        instruction=match.group(0),
                        mnemonic=func_name.upper().replace(".", "_"),
                        reason=reason,
                        severity=Severity.ERROR,
                    )
                )

        if include_warnings:
            for func_name, reason in DANGEROUS_PYTHON_FUNCTIONS["warnings"].items():
                # Match method calls like .find(), .startswith()
                method_name = func_name.split(".")[-1] if "." in func_name else func_name
                pattern = rf"\.{re.escape(method_name)}\s*\("
                for match in re.finditer(pattern, source, re.IGNORECASE):
                    line_num = source[: match.start()].count("\n") + 1
                    violations.append(
                        Violation(
                            function="<source>",
                            file=source_file,
                            line=line_num,
                            address="",
                            instruction=match.group(0),
                            mnemonic=method_name.upper(),
                            reason=reason,
                            severity=Severity.WARNING,
                        )
                    )

        return violations

    def analyze(
        self,
        source_file: str,
        include_warnings: bool = False,
        function_filter: str | None = None,
    ) -> AnalysisReport:
        """Analyze a Python file for constant-time violations."""
        source_path = Path(source_file)
        if not source_path.exists():
            raise FileNotFoundError(f"Source file not found: {source_file}")

        success, output = self._get_dis_output(str(source_path.absolute()))
        if not success:
            raise RuntimeError(f"Failed to get Python bytecode: {output}")

        functions, violations = self._parse_dis_output(
            output,
            source_file,
            include_warnings,
            function_filter,
        )

        # Also check for dangerous function calls in source
        source_violations = self._detect_dangerous_function_calls(
            source_file,
            include_warnings,
        )

        # Merge violations, avoiding duplicates
        existing = {(v.line, v.mnemonic) for v in violations}
        for v in source_violations:
            if (v.line, v.mnemonic) not in existing:
                violations.append(v)

        return AnalysisReport(
            architecture="cpython",
            compiler="python3",
            optimization="default",
            source_file=str(source_file),
            total_functions=len(functions),
            total_instructions=sum(f["instructions"] for f in functions),
            violations=violations,
        )


# =============================================================================
# Ruby Analyzer
# =============================================================================


class RubyAnalyzer(ScriptAnalyzer):
    """
    Analyzer for Ruby scripts using YARV instruction sequence dump.

    Detects timing-unsafe bytecodes and function calls in Ruby code.
    """

    name = "ruby"

    def __init__(self, ruby_path: str | None = None):
        self.ruby_path = ruby_path or "ruby"

    def is_available(self) -> bool:
        """Check if Ruby is available."""
        try:
            result = subprocess.run(
                [self.ruby_path, "--version"],
                capture_output=True,
                text=True,
            )
            return result.returncode == 0
        except FileNotFoundError:
            return False

    def _get_yarv_output(self, source_file: str) -> tuple[bool, str]:
        """Get Ruby YARV instruction sequence dump."""
        # Use --dump=insns to get instruction sequence
        cmd = [
            self.ruby_path,
            "--dump=insns",
            source_file,
        ]

        try:
            result = subprocess.run(cmd, capture_output=True, text=True)
            # Ruby dumps to stdout
            if result.returncode != 0:
                return False, result.stderr or result.stdout
            return True, result.stdout
        except FileNotFoundError:
            return False, f"Ruby not found: {self.ruby_path}"

    def _parse_yarv_output(
        self,
        output: str,
        source_file: str,
        include_warnings: bool = False,
        function_filter: str | None = None,
    ) -> tuple[list[ParsedFunction], list[Violation]]:
        """
        Parse Ruby YARV instruction sequence output.

        YARV output format example:
        == disasm: #<ISeq:<main>@test.rb:1 (1,0)-(10,3)>
        0000 putobject                              10
        0002 putobject                              3
        0004 opt_div                                <calldata!...>
        0006 leave

        == disasm: #<ISeq:vulnerable_function@test.rb:1 (1,0)-(5,3)>
        local table (size: 2, argc: 2 [opts: 0, rest: -1, post: 0, block: -1, kw: -1@-1, kwrest: -1])
        [ 2] value@0    [ 1] modulus@1
        0000 getlocal_WC_0                          value@0
        0002 getlocal_WC_0                          modulus@1
        0004 opt_div                                <calldata!mid:/, argc:1, ARGS_SIMPLE>
        0006 leave
        """
        functions: list[ParsedFunction] = []
        violations = []

        current_function = None
        current_line = None
        filter_pattern = re.compile(function_filter) if function_filter else None

        for line in output.split("\n"):
            line_stripped = line.strip()

            # Detect function/instruction sequence start
            # Format: == disasm: #<ISeq:functionName@file.rb:line ...>
            func_match = re.match(r"==\s*disasm:\s*#<ISeq:([^@]+)@([^:]+):(\d+)", line_stripped)
            if func_match:
                func_name = func_match.group(1).strip()
                # file_name = func_match.group(2)
                start_line = int(func_match.group(3))
                current_function = func_name
                current_line = start_line
                functions.append({"name": current_function, "instructions": 0})
                continue

            # Skip local table and other metadata lines
            if line_stripped.startswith("local table") or line_stripped.startswith("["):
                continue

            # Parse YARV instruction
            # Format: offset instruction operands
            # Examples:
            #   0000 putobject        10
            #   0004 opt_div          <calldata!...>
            yarv_match = re.match(r"(\d{4})\s+([a-z_]+[a-z0-9_]*)\s*(.*)", line_stripped)

            if not yarv_match:
                continue

            offset = yarv_match.group(1)
            instruction = yarv_match.group(2).strip()
            operands = yarv_match.group(3).strip() if yarv_match.group(3) else ""

            # Update instruction count
            if functions:
                functions[-1]["instructions"] += 1

            # Check if we should skip this function
            if filter_pattern and current_function:
                if not filter_pattern.search(current_function):
                    continue

            instruction_lower = instruction.lower()

            # Check for dangerous bytecodes
            if instruction_lower in DANGEROUS_RUBY_BYTECODES["errors"]:
                violations.append(
                    Violation(
                        function=current_function or "<main>",
                        file=source_file,
                        line=current_line,
                        address=offset,
                        instruction=f"{instruction} {operands}".strip(),
                        mnemonic=instruction.upper(),
                        reason=DANGEROUS_RUBY_BYTECODES["errors"][instruction_lower],
                        severity=Severity.ERROR,
                    )
                )
            elif include_warnings and instruction_lower in DANGEROUS_RUBY_BYTECODES["warnings"]:
                violations.append(
                    Violation(
                        function=current_function or "<main>",
                        file=source_file,
                        line=current_line,
                        address=offset,
                        instruction=f"{instruction} {operands}".strip(),
                        mnemonic=instruction.upper(),
                        reason=DANGEROUS_RUBY_BYTECODES["warnings"][instruction_lower],
                        severity=Severity.WARNING,
                    )
                )

        return functions, violations

    def _detect_dangerous_function_calls(
        self,
        source_file: str,
        include_warnings: bool = False,
    ) -> list[Violation]:
        """
        Detect dangerous function calls via static analysis of source.
        """
        violations = []

        try:
            with open(source_file) as f:
                source = blank_comments(f.read(), "hash")
        except OSError:
            return violations

        # Detect dangerous function calls
        for func_name, reason in DANGEROUS_RUBY_FUNCTIONS["errors"].items():
            # Match function calls like rand() or Random.new
            if func_name == "random":
                # Match Random.new or Random.rand
                pattern = r"\bRandom\.(new|rand|bytes)\s*[(\[]?"
            elif func_name == "math.sqrt":
                pattern = r"\bMath\.sqrt\s*\("
            else:
                pattern = rf"\b{re.escape(func_name)}\s*[(\[]?"
            for match in re.finditer(pattern, source, re.IGNORECASE):
                line_num = source[: match.start()].count("\n") + 1
                violations.append(
                    Violation(
                        function="<source>",
                        file=source_file,
                        line=line_num,
                        address="",
                        instruction=match.group(0),
                        mnemonic=func_name.upper().replace(".", "_").replace("?", ""),
                        reason=reason,
                        severity=Severity.ERROR,
                    )
                )

        if include_warnings:
            for func_name, reason in DANGEROUS_RUBY_FUNCTIONS["warnings"].items():
                # Match method calls like .include?(), .start_with?()
                if func_name == "=~":
                    pattern = r"\s=~\s"
                elif "." in func_name:
                    # Module-qualified names such as `base64.encode64` are written
                    # `Base64.encode64(...)`, so the leading dot used for method
                    # calls must not be required — prefixing it produced
                    # `\.base64\.encode64`, which no Ruby source can match. That
                    # made five of these warning entries unreachable.
                    pattern = rf"\b{re.escape(func_name)}\s*[(\[]?"
                else:
                    pattern = rf"\.{re.escape(func_name)}\s*[(\[]?"
                for match in re.finditer(pattern, source, re.IGNORECASE):
                    line_num = source[: match.start()].count("\n") + 1
                    violations.append(
                        Violation(
                            function="<source>",
                            file=source_file,
                            line=line_num,
                            address="",
                            instruction=match.group(0),
                            mnemonic=func_name.upper().replace(".", "_").replace("?", ""),
                            reason=reason,
                            severity=Severity.WARNING,
                        )
                    )

        return violations

    def analyze(
        self,
        source_file: str,
        include_warnings: bool = False,
        function_filter: str | None = None,
    ) -> AnalysisReport:
        """Analyze a Ruby file for constant-time violations."""
        source_path = Path(source_file)
        if not source_path.exists():
            raise FileNotFoundError(f"Source file not found: {source_file}")

        success, output = self._get_yarv_output(str(source_path.absolute()))
        if not success:
            raise RuntimeError(f"Failed to get Ruby bytecode: {output}")

        functions, violations = self._parse_yarv_output(
            output,
            source_file,
            include_warnings,
            function_filter,
        )

        # Also check for dangerous function calls in source
        source_violations = self._detect_dangerous_function_calls(
            source_file,
            include_warnings,
        )

        # Merge violations, avoiding duplicates
        existing = {(v.line, v.mnemonic) for v in violations}
        for v in source_violations:
            if (v.line, v.mnemonic) not in existing:
                violations.append(v)

        return AnalysisReport(
            architecture="yarv",
            compiler="ruby",
            optimization="default",
            source_file=str(source_file),
            total_functions=len(functions),
            total_instructions=sum(f["instructions"] for f in functions),
            violations=violations,
        )


# =============================================================================
# Java Analyzer
# =============================================================================


class JavaAnalyzer(ScriptAnalyzer):
    """
    Analyzer for Java source files using javap for bytecode disassembly.

    Compiles Java source to bytecode and analyzes for timing-unsafe operations.
    """

    name = "java"

    def __init__(self, javac_path: str | None = None, javap_path: str | None = None):
        self.javac_path = javac_path or "javac"
        self.javap_path = javap_path or "javap"

    def is_available(self) -> bool:
        """Check if Java compiler and disassembler are available."""
        try:
            result = subprocess.run(
                [self.javac_path, "-version"],
                capture_output=True,
                text=True,
            )
            if result.returncode != 0:
                return False
            result = subprocess.run(
                [self.javap_path, "-version"],
                capture_output=True,
                text=True,
            )
            return result.returncode == 0
        except FileNotFoundError:
            return False

    def _compile_java(self, source_file: str, output_dir: str) -> tuple[bool, str]:
        """Compile Java source to class files."""
        cmd = [
            self.javac_path,
            "-d",
            output_dir,
            source_file,
        ]

        try:
            result = subprocess.run(cmd, capture_output=True, text=True)
            if result.returncode != 0:
                return False, result.stderr or result.stdout
            return True, output_dir
        except FileNotFoundError:
            return False, f"Java compiler not found: {self.javac_path}"

    def _get_bytecode_output(self, class_file: str) -> tuple[bool, str]:
        """Get javap bytecode disassembly for a class file."""
        cmd = [
            self.javap_path,
            "-c",  # Disassemble code
            "-p",  # Show private members
            "-v",  # Verbose (includes line numbers)
            class_file,
        ]

        try:
            result = subprocess.run(cmd, capture_output=True, text=True)
            if result.returncode != 0:
                return False, result.stderr or result.stdout
            return True, result.stdout
        except FileNotFoundError:
            return False, f"Java disassembler not found: {self.javap_path}"

    def _parse_javap_output(
        self,
        output: str,
        source_file: str,
        include_warnings: bool = False,
        function_filter: str | None = None,
    ) -> tuple[list[ParsedFunction], list[Violation]]:
        """
        Parse javap bytecode output for dangerous operations.

        javap output format example:
        public class CryptoUtils {
          public int vulnerable(int, int);
            Code:
               0: iload_1
               1: iload_2
               2: idiv
               3: ireturn
            LineNumberTable:
              line 5: 0
        """
        functions: list[ParsedFunction] = []
        violations = []

        current_method = None
        current_class = None
        current_line = None
        in_code_section = False
        filter_pattern = re.compile(function_filter) if function_filter else None

        # Line number table mapping: bytecode offset -> source line
        line_number_table: dict[int, int] = {}
        in_line_number_table = False

        for line in output.split("\n"):
            line_stripped = line.strip()

            # Detect class declaration
            class_match = re.match(
                r"(?:public\s+|private\s+|protected\s+)?(?:final\s+)?class\s+(\S+)", line_stripped
            )
            if class_match:
                current_class = class_match.group(1)
                continue

            # Detect method declaration
            method_match = re.match(
                r"(?:public|private|protected|static|\s)+\S+\s+(\w+)\s*\(", line_stripped
            )
            if method_match and not line_stripped.startswith("//"):
                method_name = method_match.group(1)
                if current_class:
                    current_method = f"{current_class}.{method_name}"
                else:
                    current_method = method_name
                functions.append({"name": current_method, "instructions": 0})
                in_code_section = False
                in_line_number_table = False
                line_number_table = {}
                continue

            # Detect Code section start
            if line_stripped == "Code:":
                in_code_section = True
                in_line_number_table = False
                continue

            # Detect LineNumberTable start
            if line_stripped == "LineNumberTable:":
                in_line_number_table = True
                in_code_section = False
                continue

            # Parse line number table entries
            if in_line_number_table:
                lnt_match = re.match(r"line\s+(\d+):\s+(\d+)", line_stripped)
                if lnt_match:
                    source_line = int(lnt_match.group(1))
                    bytecode_offset = int(lnt_match.group(2))
                    line_number_table[bytecode_offset] = source_line
                elif line_stripped and not line_stripped.startswith("line"):
                    in_line_number_table = False
                continue

            if not in_code_section:
                continue

            # Parse bytecode instruction
            # Format: offset: instruction [operands]
            bytecode_match = re.match(r"(\d+):\s+(\w+)\s*(.*)", line_stripped)

            if not bytecode_match:
                # End of code section - look for markers that indicate we've left the code
                # Skip metadata lines like "stack=3, locals=4, args_size=2"
                if line_stripped.startswith(("stack=", "locals", "args_size")):
                    continue
                # Other non-digit lines end the code section
                if line_stripped and not line_stripped[0].isdigit():
                    in_code_section = False
                continue

            offset = int(bytecode_match.group(1))
            instruction = bytecode_match.group(2).strip()
            operands = bytecode_match.group(3).strip() if bytecode_match.group(3) else ""

            # Look up source line from line number table
            current_line = line_number_table.get(offset)

            # Update instruction count
            if functions:
                functions[-1]["instructions"] += 1

            # Check if we should skip this method
            if filter_pattern and current_method:
                if not filter_pattern.search(current_method):
                    continue

            instruction_lower = instruction.lower()

            # Check for dangerous bytecodes
            if instruction_lower in DANGEROUS_JAVA_BYTECODES["errors"]:
                violations.append(
                    Violation(
                        function=current_method or "<unknown>",
                        file=source_file,
                        line=current_line,
                        address=str(offset),
                        instruction=f"{instruction} {operands}".strip(),
                        mnemonic=instruction.upper(),
                        reason=DANGEROUS_JAVA_BYTECODES["errors"][instruction_lower],
                        severity=Severity.ERROR,
                    )
                )
            elif include_warnings and instruction_lower in DANGEROUS_JAVA_BYTECODES["warnings"]:
                violations.append(
                    Violation(
                        function=current_method or "<unknown>",
                        file=source_file,
                        line=current_line,
                        address=str(offset),
                        instruction=f"{instruction} {operands}".strip(),
                        mnemonic=instruction.upper(),
                        reason=DANGEROUS_JAVA_BYTECODES["warnings"][instruction_lower],
                        severity=Severity.WARNING,
                    )
                )

        return functions, violations

    def _detect_dangerous_function_calls(
        self,
        source_file: str,
        include_warnings: bool = False,
    ) -> list[Violation]:
        """Detect dangerous function calls via static analysis of source."""
        violations = []

        try:
            with open(source_file) as f:
                source = blank_comments(f.read(), "c")
        except OSError:
            return violations

        # Detect dangerous function calls
        for func_name, reason in DANGEROUS_JAVA_FUNCTIONS["errors"].items():
            if func_name == "java.util.random":
                # Both the imported short form and the fully-qualified one. Only
                # `new Random(` was matched before, so `new java.util.Random()`
                # — which needs no import and so is common in single files — was
                # reported as clean.
                pattern = r"\bnew\s+(?:java\.util\.)?Random\s*\("
            elif func_name == "math.random":
                pattern = r"\bMath\.random\s*\("
            elif func_name == "math.sqrt":
                pattern = r"\bMath\.sqrt\s*\("
            elif func_name == "math.pow":
                pattern = r"\bMath\.pow\s*\("
            else:
                continue
            for match in re.finditer(pattern, source):
                line_num = source[: match.start()].count("\n") + 1
                violations.append(
                    Violation(
                        function="<source>",
                        file=source_file,
                        line=line_num,
                        address="",
                        instruction=match.group(0),
                        mnemonic=func_name.upper().replace(".", "_"),
                        reason=reason,
                        severity=Severity.ERROR,
                    )
                )

        if include_warnings:
            for func_name, reason in DANGEROUS_JAVA_FUNCTIONS["warnings"].items():
                pattern = qualified_call_pattern(func_name)
                for match in re.finditer(pattern, source):
                    line_num = source[: match.start()].count("\n") + 1
                    violations.append(
                        Violation(
                            function="<source>",
                            file=source_file,
                            line=line_num,
                            address="",
                            instruction=match.group(0),
                            mnemonic=func_name.upper().replace(".", "_"),
                            reason=reason,
                            severity=Severity.WARNING,
                        )
                    )

        return violations

    def analyze(
        self,
        source_file: str,
        include_warnings: bool = False,
        function_filter: str | None = None,
    ) -> AnalysisReport:
        """Analyze a Java file for constant-time violations."""
        source_path = Path(source_file)
        if not source_path.exists():
            raise FileNotFoundError(f"Source file not found: {source_file}")

        with tempfile.TemporaryDirectory() as tmpdir:
            # Compile Java source
            success, result = self._compile_java(str(source_path.absolute()), tmpdir)
            if not success:
                raise RuntimeError(f"Java compilation failed: {result}")

            # Find compiled class files
            class_files = list(Path(tmpdir).glob("**/*.class"))
            if not class_files:
                raise RuntimeError("No class files generated from compilation")

            all_functions: list[ParsedFunction] = []
            all_violations = []

            # Analyze each class file
            for class_file in class_files:
                success, output = self._get_bytecode_output(str(class_file))
                if not success:
                    continue

                functions, violations = self._parse_javap_output(
                    output,
                    source_file,
                    include_warnings,
                    function_filter,
                )
                all_functions.extend(functions)
                all_violations.extend(violations)

        # Also check for dangerous function calls in source
        source_violations = self._detect_dangerous_function_calls(
            source_file,
            include_warnings,
        )

        # Merge violations, avoiding duplicates
        existing = {(v.line, v.mnemonic) for v in all_violations}
        for v in source_violations:
            if (v.line, v.mnemonic) not in existing:
                all_violations.append(v)

        return AnalysisReport(
            architecture="jvm",
            compiler="javac",
            optimization="default",
            source_file=str(source_file),
            total_functions=len(all_functions),
            total_instructions=sum(f["instructions"] for f in all_functions),
            violations=all_violations,
        )


# =============================================================================
# Kotlin Analyzer
# =============================================================================


class KotlinAnalyzer(ScriptAnalyzer):
    """
    Analyzer for Kotlin source files using kotlinc and javap for bytecode disassembly.

    Compiles Kotlin source to JVM bytecode and analyzes for timing-unsafe operations.
    Kotlin targets Android and JVM platforms, compiling to the same bytecode as Java.
    """

    name = "kotlin"

    def __init__(self, kotlinc_path: str | None = None, javap_path: str | None = None):
        self.kotlinc_path = kotlinc_path or "kotlinc"
        self.javap_path = javap_path or "javap"

    def is_available(self) -> bool:
        """Check if Kotlin compiler and Java disassembler are available."""
        try:
            result = subprocess.run(
                [self.kotlinc_path, "-version"],
                capture_output=True,
                text=True,
            )
            if result.returncode != 0:
                return False
            result = subprocess.run(
                [self.javap_path, "-version"],
                capture_output=True,
                text=True,
            )
            return result.returncode == 0
        except FileNotFoundError:
            return False

    def _compile_kotlin(self, source_file: str, output_dir: str) -> tuple[bool, str]:
        """Compile Kotlin source to class files."""
        cmd = [
            self.kotlinc_path,
            "-d",
            output_dir,
            source_file,
        ]

        try:
            result = subprocess.run(cmd, capture_output=True, text=True)
            if result.returncode != 0:
                return False, result.stderr or result.stdout
            return True, output_dir
        except FileNotFoundError:
            return False, f"Kotlin compiler not found: {self.kotlinc_path}"

    def _get_bytecode_output(self, class_file: str) -> tuple[bool, str]:
        """Get javap bytecode disassembly for a class file."""
        cmd = [
            self.javap_path,
            "-c",  # Disassemble code
            "-p",  # Show private members
            "-v",  # Verbose (includes line numbers)
            class_file,
        ]

        try:
            result = subprocess.run(cmd, capture_output=True, text=True)
            if result.returncode != 0:
                return False, result.stderr or result.stdout
            return True, result.stdout
        except FileNotFoundError:
            return False, f"Java disassembler not found: {self.javap_path}"

    def _parse_javap_output(
        self,
        output: str,
        source_file: str,
        include_warnings: bool = False,
        function_filter: str | None = None,
    ) -> tuple[list[ParsedFunction], list[Violation]]:
        """Parse javap bytecode output for dangerous operations (same as Java)."""
        functions: list[ParsedFunction] = []
        violations = []

        current_method = None
        current_class = None
        current_line = None
        in_code_section = False
        filter_pattern = re.compile(function_filter) if function_filter else None

        line_number_table: dict[int, int] = {}
        in_line_number_table = False

        for line in output.split("\n"):
            line_stripped = line.strip()

            # Detect class declaration (including Kotlin's Kt suffix for file classes)
            class_match = re.match(
                r"(?:public\s+|private\s+|protected\s+)?(?:final\s+)?class\s+(\S+)", line_stripped
            )
            if class_match:
                current_class = class_match.group(1)
                continue

            # Detect method declaration
            method_match = re.match(
                r"(?:public|private|protected|static|final|\s)+\S+\s+(\w+)\s*\(", line_stripped
            )
            if method_match and not line_stripped.startswith("//"):
                method_name = method_match.group(1)
                if current_class:
                    current_method = f"{current_class}.{method_name}"
                else:
                    current_method = method_name
                functions.append({"name": current_method, "instructions": 0})
                in_code_section = False
                in_line_number_table = False
                line_number_table = {}
                continue

            # Detect Code section start
            if line_stripped == "Code:":
                in_code_section = True
                in_line_number_table = False
                continue

            # Detect LineNumberTable start
            if line_stripped == "LineNumberTable:":
                in_line_number_table = True
                in_code_section = False
                continue

            # Parse line number table entries
            if in_line_number_table:
                lnt_match = re.match(r"line\s+(\d+):\s+(\d+)", line_stripped)
                if lnt_match:
                    source_line = int(lnt_match.group(1))
                    bytecode_offset = int(lnt_match.group(2))
                    line_number_table[bytecode_offset] = source_line
                elif line_stripped and not line_stripped.startswith("line"):
                    in_line_number_table = False
                continue

            if not in_code_section:
                continue

            # Parse bytecode instruction
            bytecode_match = re.match(r"(\d+):\s+(\w+)\s*(.*)", line_stripped)

            if not bytecode_match:
                if line_stripped.startswith(("stack=", "locals", "args_size")):
                    continue
                if line_stripped and not line_stripped[0].isdigit():
                    in_code_section = False
                continue

            offset = int(bytecode_match.group(1))
            instruction = bytecode_match.group(2).strip()
            operands = bytecode_match.group(3).strip() if bytecode_match.group(3) else ""

            current_line = line_number_table.get(offset)

            if functions:
                functions[-1]["instructions"] += 1

            if filter_pattern and current_method:
                if not filter_pattern.search(current_method):
                    continue

            instruction_lower = instruction.lower()

            # Check for dangerous bytecodes (same as Java since Kotlin compiles to JVM)
            if instruction_lower in DANGEROUS_KOTLIN_BYTECODES["errors"]:
                violations.append(
                    Violation(
                        function=current_method or "<unknown>",
                        file=source_file,
                        line=current_line,
                        address=str(offset),
                        instruction=f"{instruction} {operands}".strip(),
                        mnemonic=instruction.upper(),
                        reason=DANGEROUS_KOTLIN_BYTECODES["errors"][instruction_lower],
                        severity=Severity.ERROR,
                    )
                )
            elif include_warnings and instruction_lower in DANGEROUS_KOTLIN_BYTECODES["warnings"]:
                violations.append(
                    Violation(
                        function=current_method or "<unknown>",
                        file=source_file,
                        line=current_line,
                        address=str(offset),
                        instruction=f"{instruction} {operands}".strip(),
                        mnemonic=instruction.upper(),
                        reason=DANGEROUS_KOTLIN_BYTECODES["warnings"][instruction_lower],
                        severity=Severity.WARNING,
                    )
                )

        return functions, violations

    def _detect_dangerous_function_calls(
        self,
        source_file: str,
        include_warnings: bool = False,
    ) -> list[Violation]:
        """Detect dangerous function calls via static analysis of Kotlin source."""
        violations = []

        try:
            with open(source_file) as f:
                source = blank_comments(f.read(), "c")
        except OSError:
            return violations

        # Detect dangerous function calls (Kotlin-specific patterns)
        for func_name, reason in DANGEROUS_KOTLIN_FUNCTIONS["errors"].items():
            pattern = None
            if func_name == "random.nextint":
                pattern = r"\bRandom\.nextInt\s*\("
            elif func_name == "random.nextlong":
                pattern = r"\bRandom\.nextLong\s*\("
            elif func_name == "random.nextdouble":
                pattern = r"\bRandom\.nextDouble\s*\("
            elif func_name == "random.nextfloat":
                pattern = r"\bRandom\.nextFloat\s*\("
            elif func_name == "random.nextbytes":
                pattern = r"\bRandom\.nextBytes\s*\("
            elif func_name == "random.default":
                pattern = r"\bRandom\.Default\b"
            elif func_name == "java.util.random":
                pattern = r"\bjava\.util\.Random\s*\("
            elif func_name == "math.random":
                pattern = r"\bMath\.random\s*\("
            elif func_name in ("kotlin.math.sqrt", "math.sqrt"):
                pattern = r"\b(?:kotlin\.math\.)?sqrt\s*\(|\bMath\.sqrt\s*\("
            elif func_name in ("kotlin.math.pow", "math.pow"):
                pattern = r"\b(?:kotlin\.math\.)?pow\s*\(|\bMath\.pow\s*\("

            if pattern:
                for match in re.finditer(pattern, source, re.IGNORECASE):
                    line_num = source[: match.start()].count("\n") + 1
                    violations.append(
                        Violation(
                            function="<source>",
                            file=source_file,
                            line=line_num,
                            address="",
                            instruction=match.group(0),
                            mnemonic=func_name.upper().replace(".", "_"),
                            reason=reason,
                            severity=Severity.ERROR,
                        )
                    )

        if include_warnings:
            for func_name, reason in DANGEROUS_KOTLIN_FUNCTIONS["warnings"].items():
                pattern = qualified_call_pattern(func_name)

                if pattern:
                    for match in re.finditer(pattern, source):
                        line_num = source[: match.start()].count("\n") + 1
                        violations.append(
                            Violation(
                                function="<source>",
                                file=source_file,
                                line=line_num,
                                address="",
                                instruction=match.group(0),
                                mnemonic=func_name.upper().replace(".", "_"),
                                reason=reason,
                                severity=Severity.WARNING,
                            )
                        )

        return violations

    def analyze(
        self,
        source_file: str,
        include_warnings: bool = False,
        function_filter: str | None = None,
    ) -> AnalysisReport:
        """Analyze a Kotlin file for constant-time violations."""
        source_path = Path(source_file)
        if not source_path.exists():
            raise FileNotFoundError(f"Source file not found: {source_file}")

        with tempfile.TemporaryDirectory() as tmpdir:
            # Compile Kotlin source
            success, result = self._compile_kotlin(str(source_path.absolute()), tmpdir)
            if not success:
                raise RuntimeError(f"Kotlin compilation failed: {result}")

            # Find compiled class files
            class_files = list(Path(tmpdir).glob("**/*.class"))
            if not class_files:
                raise RuntimeError("No class files generated from compilation")

            all_functions: list[ParsedFunction] = []
            all_violations = []

            # Analyze each class file
            for class_file in class_files:
                success, output = self._get_bytecode_output(str(class_file))
                if not success:
                    continue

                functions, violations = self._parse_javap_output(
                    output,
                    source_file,
                    include_warnings,
                    function_filter,
                )
                all_functions.extend(functions)
                all_violations.extend(violations)

        # Also check for dangerous function calls in source
        source_violations = self._detect_dangerous_function_calls(
            source_file,
            include_warnings,
        )

        # Merge violations, avoiding duplicates
        existing = {(v.line, v.mnemonic) for v in all_violations}
        for v in source_violations:
            if (v.line, v.mnemonic) not in existing:
                all_violations.append(v)

        return AnalysisReport(
            architecture="jvm",
            compiler="kotlinc",
            optimization="default",
            source_file=str(source_file),
            total_functions=len(all_functions),
            total_instructions=sum(f["instructions"] for f in all_functions),
            violations=all_violations,
        )


# =============================================================================
# C# Analyzer
# =============================================================================


class CSharpAnalyzer(ScriptAnalyzer):
    """
    Analyzer for C# source files using .NET SDK for compilation and IL disassembly.

    Compiles C# source to IL and analyzes for timing-unsafe operations.
    """

    name = "csharp"

    def __init__(self, dotnet_path: str | None = None):
        self.dotnet_path = dotnet_path or "dotnet"

    def is_available(self) -> bool:
        """Check if .NET SDK is available."""
        try:
            result = subprocess.run(
                [self.dotnet_path, "--version"],
                capture_output=True,
                text=True,
            )
            return result.returncode == 0
        except FileNotFoundError:
            return False

    def _compile_csharp(self, source_file: str, output_dir: str) -> tuple[bool, str]:
        """Compile C# source to DLL using dotnet build."""
        source_path = Path(source_file)
        output_dll = Path(output_dir) / f"{source_path.stem}.dll"

        # Create a minimal project file for compilation
        proj_content = f"""<Project Sdk="Microsoft.NET.Sdk">
  <PropertyGroup>
    <TargetFramework>net8.0</TargetFramework>
    <OutputType>Library</OutputType>
    <OutputPath>{_saxutils.escape(str(output_dir))}</OutputPath>
    <EnableDefaultCompileItems>false</EnableDefaultCompileItems>
  </PropertyGroup>
  <ItemGroup>
    <Compile Include="{_saxutils.escape(str(source_path.absolute()), {chr(34): "&quot;"})}" />
  </ItemGroup>
</Project>
"""
        proj_file = Path(output_dir) / "temp.csproj"
        proj_file.write_text(proj_content)

        cmd = [
            self.dotnet_path,
            "build",
            str(proj_file),
            "-c",
            "Release",
            "--nologo",
            "-v",
            "q",
        ]

        try:
            result = subprocess.run(cmd, capture_output=True, text=True, cwd=output_dir)
            if result.returncode != 0:
                return False, result.stderr or result.stdout

            # Find the output DLL
            dll_files = list(Path(output_dir).glob("**/*.dll"))
            if not dll_files:
                return False, "No DLL files generated"

            return True, str(dll_files[0])
        except FileNotFoundError:
            return False, f".NET SDK not found: {self.dotnet_path}"

    def _get_il_output(self, dll_file: str) -> tuple[bool, str]:
        """Get IL disassembly for a .NET assembly."""
        # First try ilspycmd directly (globally installed and in PATH)
        try:
            result = subprocess.run(
                ["ilspycmd", "-il", dll_file],
                capture_output=True,
                text=True,
            )
            if result.returncode == 0:
                return True, result.stdout
        except FileNotFoundError:
            pass  # ilspycmd not in PATH, try other methods

        # Try as local tool
        try:
            result = subprocess.run(
                [self.dotnet_path, "tool", "run", "ilspycmd", "-il", dll_file],
                capture_output=True,
                text=True,
            )
            if result.returncode == 0:
                return True, result.stdout
        except FileNotFoundError:
            pass  # dotnet not found or local tool not installed

        # Try running ilspycmd via .NET 8.0 from Homebrew (macOS)
        # This handles the case where ilspycmd targets .NET 8.0 but the system
        # has a newer .NET version installed
        dotnet8_paths = [
            "/opt/homebrew/opt/dotnet@8/libexec/dotnet",  # Apple Silicon
            "/usr/local/opt/dotnet@8/libexec/dotnet",  # Intel Mac
        ]
        ilspycmd_dll = Path.home() / ".dotnet/tools/.store/ilspycmd"
        if ilspycmd_dll.exists():
            # Find the ilspycmd.dll in the store
            for dll_path in ilspycmd_dll.glob("*/ilspycmd/*/tools/net8.0/any/ilspycmd.dll"):
                for dotnet8 in dotnet8_paths:
                    if Path(dotnet8).exists():
                        try:
                            env = os.environ.copy()
                            env["DOTNET_ROOT"] = str(Path(dotnet8).parent)
                            result = subprocess.run(
                                [dotnet8, str(dll_path), "-il", dll_file],
                                capture_output=True,
                                text=True,
                                env=env,
                            )
                            if result.returncode == 0:
                                return True, result.stdout
                        except FileNotFoundError:
                            pass
                break  # Only try the first matching dll

        # Try monodis (available on Linux/macOS with Mono)
        try:
            result = subprocess.run(
                ["monodis", "--method", dll_file],
                capture_output=True,
                text=True,
            )
            if result.returncode == 0:
                return True, result.stdout
        except FileNotFoundError:
            pass  # monodis not available

        # If nothing works, return helpful error
        return False, (
            "IL disassembly tools not available. Install ILSpy CLI: "
            "`dotnet tool install -g ilspycmd`"
        )

    def _parse_il_output(
        self,
        output: str,
        source_file: str,
        include_warnings: bool = False,
        function_filter: str | None = None,
    ) -> tuple[list[ParsedFunction], list[Violation]]:
        """
        Parse CIL/IL output for dangerous operations.

        IL output format from ILSpy spans multiple lines:
        .method public hidebysig static
            int32 VulnerableModReduce (
                int32 'value',
                int32 modulus
            ) cil managed
        {
          .maxstack 2
          IL_0000: ldarg.1
          IL_0001: ldarg.2
          IL_0002: div
          IL_0003: ret
        }
        """
        functions: list[ParsedFunction] = []
        violations = []

        current_method = None
        in_method = False
        in_method_decl = False  # Between .method and {
        filter_pattern = re.compile(function_filter) if function_filter else None

        for line in output.split("\n"):
            line_stripped = line.strip()

            # Detect start of method declaration
            if line_stripped.startswith(".method "):
                in_method_decl = True
                current_method = None
                # Try to extract method name from this line (single-line format)
                name_match = re.search(r"(\w+)\s*\(", line_stripped)
                if name_match:
                    current_method = name_match.group(1)
                # Check if brace is on same line (rare but possible)
                if "{" in line_stripped:
                    in_method_decl = False
                    in_method = True
                    if current_method:
                        functions.append({"name": current_method, "instructions": 0})
                continue

            # During method declaration, look for method name (before opening paren)
            if in_method_decl and not in_method:
                # Look for pattern: name ( - the method name is right before (
                name_match = re.search(r"(\w+)\s*\(", line_stripped)
                if name_match and current_method is None:
                    current_method = name_match.group(1)

                # Opening brace starts method body
                if "{" in line_stripped:
                    in_method_decl = False
                    in_method = True
                    if current_method:
                        functions.append({"name": current_method, "instructions": 0})
                continue

            # Detect end of method
            if line_stripped.startswith("}") and in_method:
                in_method = False
                continue

            if not in_method:
                continue

            # Parse IL instruction
            # Format: IL_xxxx: instruction [operands]
            il_match = re.match(r"IL_([0-9a-fA-F]+):\s+(\S+)\s*(.*)", line_stripped)

            if not il_match:
                continue

            offset = il_match.group(1)
            instruction = il_match.group(2).strip()
            operands = il_match.group(3).strip() if il_match.group(3) else ""

            # Update instruction count
            if functions:
                functions[-1]["instructions"] += 1

            # Check if we should skip this method
            if filter_pattern and current_method:
                if not filter_pattern.search(current_method):
                    continue

            instruction_lower = instruction.lower()

            # Check for dangerous bytecodes
            if instruction_lower in DANGEROUS_CSHARP_BYTECODES["errors"]:
                violations.append(
                    Violation(
                        function=current_method or "<unknown>",
                        file=source_file,
                        line=None,
                        address=f"IL_{offset}",
                        instruction=f"{instruction} {operands}".strip(),
                        mnemonic=instruction.upper(),
                        reason=DANGEROUS_CSHARP_BYTECODES["errors"][instruction_lower],
                        severity=Severity.ERROR,
                    )
                )
            elif include_warnings and instruction_lower in DANGEROUS_CSHARP_BYTECODES["warnings"]:
                violations.append(
                    Violation(
                        function=current_method or "<unknown>",
                        file=source_file,
                        line=None,
                        address=f"IL_{offset}",
                        instruction=f"{instruction} {operands}".strip(),
                        mnemonic=instruction.upper(),
                        reason=DANGEROUS_CSHARP_BYTECODES["warnings"][instruction_lower],
                        severity=Severity.WARNING,
                    )
                )

        return functions, violations

    def _detect_dangerous_function_calls(
        self,
        source_file: str,
        include_warnings: bool = False,
    ) -> list[Violation]:
        """Detect dangerous function calls via static analysis of source."""
        violations = []

        try:
            with open(source_file) as f:
                source = blank_comments(f.read(), "c")
        except OSError:
            return violations

        # Detect dangerous function calls
        for func_name, reason in DANGEROUS_CSHARP_FUNCTIONS["errors"].items():
            if func_name == "system.random":
                pattern = r"\bnew\s+Random\s*\("
            elif func_name == "math.sqrt":
                pattern = r"\bMath\.Sqrt\s*\("
            elif func_name == "math.pow":
                pattern = r"\bMath\.Pow\s*\("
            else:
                continue
            for match in re.finditer(pattern, source):
                line_num = source[: match.start()].count("\n") + 1
                violations.append(
                    Violation(
                        function="<source>",
                        file=source_file,
                        line=line_num,
                        address="",
                        instruction=match.group(0),
                        mnemonic=func_name.upper().replace(".", "_"),
                        reason=reason,
                        severity=Severity.ERROR,
                    )
                )

        if include_warnings:
            for func_name, reason in DANGEROUS_CSHARP_FUNCTIONS["warnings"].items():
                pattern = qualified_call_pattern(func_name)
                for match in re.finditer(pattern, source):
                    line_num = source[: match.start()].count("\n") + 1
                    violations.append(
                        Violation(
                            function="<source>",
                            file=source_file,
                            line=line_num,
                            address="",
                            instruction=match.group(0),
                            mnemonic=func_name.upper().replace(".", "_"),
                            reason=reason,
                            severity=Severity.WARNING,
                        )
                    )

        return violations

    def _analyze_source_only(
        self,
        source_file: str,
        include_warnings: bool = False,
    ) -> AnalysisReport:
        """Fallback analysis using source-level pattern matching only."""
        violations = self._detect_dangerous_function_calls(source_file, include_warnings)

        # Also detect division/modulo operators in source
        try:
            with open(source_file) as f:
                source = blank_comments(f.read(), "c")
        except OSError:
            source = ""

        # Detect division operator
        div_pattern = r"[^/]\s*/\s*[^/=*]"
        for match in re.finditer(div_pattern, source):
            line_start = source.rfind("\n", 0, match.start()) + 1
            line_end = source.find("\n", match.start())
            if line_end == -1:
                line_end = len(source)
            line = source[line_start:line_end]
            if line.strip().startswith("//"):
                continue
            line_num = source[: match.start()].count("\n") + 1
            violations.append(
                Violation(
                    function="<source>",
                    file=source_file,
                    line=line_num,
                    address="",
                    instruction="/",
                    mnemonic="DIV_OP",
                    reason="Division operator may have variable-time execution",
                    severity=Severity.ERROR,
                )
            )

        # Detect modulo operator
        mod_pattern = r"\s%\s*[^=]"
        for match in re.finditer(mod_pattern, source):
            line_start = source.rfind("\n", 0, match.start()) + 1
            line_end = source.find("\n", match.start())
            if line_end == -1:
                line_end = len(source)
            line = source[line_start:line_end]
            if line.strip().startswith("//"):
                continue
            line_num = source[: match.start()].count("\n") + 1
            violations.append(
                Violation(
                    function="<source>",
                    file=source_file,
                    line=line_num,
                    address="",
                    instruction="%",
                    mnemonic="REM_OP",
                    reason="Modulo operator may have variable-time execution",
                    severity=Severity.ERROR,
                )
            )

        return AnalysisReport(
            architecture="cil",
            compiler="source-analysis",
            optimization="default",
            source_file=str(source_file),
            total_functions=0,
            total_instructions=0,
            violations=violations,
        )

    def analyze(
        self,
        source_file: str,
        include_warnings: bool = False,
        function_filter: str | None = None,
    ) -> AnalysisReport:
        """Analyze a C# file for constant-time violations."""
        source_path = Path(source_file)
        if not source_path.exists():
            raise FileNotFoundError(f"Source file not found: {source_file}")

        with tempfile.TemporaryDirectory() as tmpdir:
            # Try to compile C# source
            success, result = self._compile_csharp(str(source_path.absolute()), tmpdir)
            if not success:
                # Fall back to source-only analysis
                print(
                    f"Note: C# compilation failed ({result}), using source analysis only",
                    file=sys.stderr,
                )
                return self._analyze_source_only(source_file, include_warnings)

            # Get IL disassembly
            success, output = self._get_il_output(result)
            if not success:
                # Fall back to source-only analysis
                print(
                    f"Note: IL disassembly failed ({output}), using source analysis only",
                    file=sys.stderr,
                )
                return self._analyze_source_only(source_file, include_warnings)

            functions, violations = self._parse_il_output(
                output,
                source_file,
                include_warnings,
                function_filter,
            )

        # Also check for dangerous function calls in source
        source_violations = self._detect_dangerous_function_calls(
            source_file,
            include_warnings,
        )

        # Merge violations, avoiding duplicates
        existing = {(v.line, v.mnemonic) for v in violations}
        for v in source_violations:
            if (v.line, v.mnemonic) not in existing:
                violations.append(v)

        return AnalysisReport(
            architecture="cil",
            compiler="dotnet",
            optimization="Release",
            source_file=str(source_file),
            total_functions=len(functions),
            total_instructions=sum(f["instructions"] for f in functions),
            violations=violations,
        )


# =============================================================================
# Helper Functions
# =============================================================================


def get_script_analyzer(language: str) -> ScriptAnalyzer | None:
    """
    Get the appropriate analyzer for a bytecode-analyzed language.

    Args:
        language: The language identifier

    Returns:
        ScriptAnalyzer instance or None if not supported
    """
    analyzers = {
        "php": PHPAnalyzer,
        "javascript": JavaScriptAnalyzer,
        "typescript": JavaScriptAnalyzer,
        "python": PythonAnalyzer,
        "ruby": RubyAnalyzer,
        "java": JavaAnalyzer,
        "kotlin": KotlinAnalyzer,
        "csharp": CSharpAnalyzer,
    }

    analyzer_class = analyzers.get(language.lower())
    if analyzer_class:
        return analyzer_class()
    return None


def is_script_language(language: str) -> bool:
    """Check if a language is handled by bytecode analysis in this module."""
    return language.lower() in (
        "php",
        "javascript",
        "typescript",
        "python",
        "ruby",
        "java",
        "kotlin",
        "csharp",
    )
