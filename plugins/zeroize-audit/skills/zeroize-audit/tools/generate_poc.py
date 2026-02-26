#!/usr/bin/env python3
# /// script
# requires-python = ">=3.9"
# dependencies = ["pyyaml>=6.0"]
# ///
"""
Generate proof-of-concept C programs from zeroize-audit findings.

Each PoC demonstrates that a finding is exploitable by reading sensitive
data that should have been zeroized. PoCs exit 0 when the secret persists
(exploitable) and exit 1 when the data has been wiped (not exploitable).

Usage:
  python generate_poc.py \\
    --findings <findings.json> \\
    --compile-db <compile_commands.json> \\
    --out <output_dir> \\
    [--categories CAT1,CAT2,...] \\
    [--config <config.yaml>]

Exit codes:
  0  PoCs generated successfully
  1  Invalid input (bad JSON, missing required fields)
  2  No exploitable findings in the selected categories
  3  Output directory error
"""

import argparse
import json
import os
import re
import subprocess
import sys
import textwrap
from pathlib import Path
from typing import Any

try:
    import yaml
except ImportError:
    yaml = None  # type: ignore[assignment]

# ---------------------------------------------------------------------------
# Categories that support PoC generation
# ---------------------------------------------------------------------------
EXPLOITABLE_CATEGORIES = frozenset(
    [
        "MISSING_SOURCE_ZEROIZE",
        "OPTIMIZED_AWAY_ZEROIZE",
        "STACK_RETENTION",
        "REGISTER_SPILL",
        "SECRET_COPY",
        "MISSING_ON_ERROR_PATH",
        "PARTIAL_WIPE",
        "NOT_ON_ALL_PATHS",
        "INSECURE_HEAP_ALLOC",
        "LOOP_UNROLLED_INCOMPLETE",
        "NOT_DOMINATING_EXITS",
    ]
)

# ---------------------------------------------------------------------------
# Defaults
# ---------------------------------------------------------------------------
_DEFAULT_SECRET_FILL: int = 0xAA
_DEFAULT_SOURCE_INCLUSION_THRESHOLD: int = 5000
_DEFAULT_STACK_PROBE_MAX: int = 4096
_DEFAULT_MIN_CONFIDENCE: str = "likely"

_CONFIDENCE_ORDER = {"confirmed": 0, "likely": 1, "needs_review": 2}

_TOOLS_DIR = Path(__file__).resolve().parent


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _load_config(config_path: str | None) -> dict[str, Any]:
    """Load a YAML config file and return the poc_generation section."""
    if not config_path:
        return {}
    path = Path(config_path)
    if yaml is None:
        sys.stderr.write("Error: --config requires pyyaml. Install with: pip install pyyaml\n")
        sys.exit(1)
    if not path.exists():
        sys.stderr.write(f"Error: config file not found: {path}\n")
        sys.exit(1)
    with open(path) as f:
        data = yaml.safe_load(f) or {}
    return data.get("poc_generation", {})


def _get_compile_flags(compile_db: str, src_file: str) -> list[str] | None:
    """Call extract_compile_flags.py and return flags as a list, or None on failure."""
    script = _TOOLS_DIR / "extract_compile_flags.py"
    if not script.exists():
        sys.stderr.write(f"Warning: compile flag extractor not found: {script}\n")
        return None
    try:
        result = subprocess.run(
            [
                sys.executable,
                str(script),
                "--compile-db",
                compile_db,
                "--src",
                src_file,
                "--format",
                "json",
            ],
            capture_output=True,
            text=True,
            timeout=30,
        )
        if result.returncode != 0:
            sys.stderr.write(
                f"Warning: extract_compile_flags.py exited with code {result.returncode}"
                f" for {src_file}\n"
            )
            return None
        return json.loads(result.stdout)
    except subprocess.TimeoutExpired:
        sys.stderr.write(f"Warning: extract_compile_flags.py timed out for {src_file}\n")
        return None
    except json.JSONDecodeError as exc:
        sys.stderr.write(
            f"Warning: extract_compile_flags.py returned invalid JSON for {src_file}: {exc}\n"
        )
        return None
    except OSError as exc:
        sys.stderr.write(f"Warning: failed to run extract_compile_flags.py for {src_file}: {exc}\n")
        return None


def _count_lines(path: str) -> int:
    """Return the number of lines in a file, or 0 if unreadable."""
    try:
        with open(path) as f:
            return sum(1 for _ in f)
    except OSError:
        return 0


def _extract_function_signature(src_file: str, line: int) -> str | None:
    """
    Attempt to extract the function signature surrounding the given line number.
    Returns the function name if found, or None.
    """
    try:
        with open(src_file) as f:
            lines = f.readlines()
    except OSError:
        return None

    # Search backwards from the finding line to find a function definition
    start = max(0, line - 30)
    end = min(len(lines), line + 5)
    region = "".join(lines[start:end])

    # Match C/C++ function definitions: return_type func_name(params) {
    pattern = re.compile(
        r"(?:^|\n)\s*"
        r"(?:static\s+|inline\s+|extern\s+|__attribute__\s*\([^)]*\)\s+)*"
        r"(?:(?:const\s+|unsigned\s+|signed\s+|volatile\s+)*\w[\w\s*&]*?)\s+"
        r"(\w+)\s*\([^)]*\)\s*(?:\{|$)",
        re.MULTILINE,
    )
    matches = list(pattern.finditer(region))
    if matches:
        return matches[-1].group(1)
    return None


def _is_cpp_file(src_file: str) -> bool:
    """Return True if the source file appears to be C++."""
    ext = Path(src_file).suffix.lower()
    return ext in (".cpp", ".cxx", ".cc", ".C", ".hpp", ".hxx")


def _is_rust_file(src_file: str) -> bool:
    """Return True if the source file appears to be Rust."""
    return Path(src_file).suffix.lower() == ".rs"


def _relative_source_path(src_file: str, out_dir: str) -> str:
    """Compute a relative path from out_dir to src_file."""
    try:
        return os.path.relpath(src_file, out_dir)
    except ValueError:
        return src_file


# ---------------------------------------------------------------------------
# poc_common.h generation
# ---------------------------------------------------------------------------


def _generate_common_header(
    secret_fill: int = _DEFAULT_SECRET_FILL, stack_probe_max: int = _DEFAULT_STACK_PROBE_MAX
) -> str:
    return textwrap.dedent(f"""\
        #ifndef POC_COMMON_H
        #define POC_COMMON_H

        #include <stdio.h>
        #include <stdlib.h>
        #include <string.h>
        #include <stdint.h>

        #define SECRET_FILL_BYTE 0x{secret_fill:02X}
        #define STACK_PROBE_MAX  {stack_probe_max}

        #define POC_PASS() do {{ \\
            fprintf(stderr, "POC PASS: secret persists (exploitable)\\n"); \\
            exit(0); \\
        }} while (0)

        #define POC_FAIL() do {{ \\
            fprintf(stderr, "POC FAIL: secret was wiped (not exploitable)\\n"); \\
            exit(1); \\
        }} while (0)

        /* Read through a volatile pointer to prevent the compiler from
           optimizing away the verification read. Returns non-zero if any
           byte in [ptr, ptr+len) is non-zero. */
        static int volatile_read_nonzero(const void *ptr, size_t len) {{
            const volatile unsigned char *p = (const volatile unsigned char *)ptr;
            int found = 0;
            for (size_t i = 0; i < len; i++) {{
                if (p[i] != 0) {{
                    found = 1;
                }}
            }}
            return found;
        }}

        /* Read through volatile pointer checking for the secret fill pattern. */
        static int volatile_read_has_secret(const void *ptr, size_t len) {{
            const volatile unsigned char *p = (const volatile unsigned char *)ptr;
            int count = 0;
            for (size_t i = 0; i < len; i++) {{
                if (p[i] == SECRET_FILL_BYTE) {{
                    count++;
                }}
            }}
            /* Consider it a match if >= 50% of bytes are the fill pattern */
            return count >= (int)(len / 2);
        }}

        /* Dump hex to stderr for diagnostics. */
        static void hex_dump(const char *label, const void *ptr, size_t len) {{
            const unsigned char *p = (const unsigned char *)ptr;
            fprintf(stderr, "%s (%zu bytes):", label, len);
            for (size_t i = 0; i < len && i < 64; i++) {{
                if (i % 16 == 0) fprintf(stderr, "\\n  ");
                fprintf(stderr, "%02x ", p[i]);
            }}
            if (len > 64) fprintf(stderr, "\\n  ... (%zu more bytes)", len - 64);
            fprintf(stderr, "\\n");
        }}

        /* Probe the stack for residual secret data from a prior call frame.
           Must be __attribute__((noinline, noclone)) so the compiler cannot
           merge this frame with the caller. */
        __attribute__((noinline))
        #if defined(__GNUC__) && !defined(__clang__)
        __attribute__((noclone))
        #endif
        static int stack_probe(size_t frame_size) {{
            if (frame_size > STACK_PROBE_MAX) frame_size = STACK_PROBE_MAX;
            volatile unsigned char probe[STACK_PROBE_MAX];
            /* Do NOT initialize — we want to read whatever is on the stack */
            int count = 0;
            for (size_t i = 0; i < frame_size; i++) {{
                if (probe[i] == SECRET_FILL_BYTE) {{
                    count++;
                }}
            }}
            return count >= (int)(frame_size / 4);  /* 25% threshold */
        }}

        /* Fill a buffer with the secret marker pattern. */
        static void fill_secret(void *buf, size_t len) {{
            memset(buf, SECRET_FILL_BYTE, len);
        }}

        /* Check whether heap memory retains secret data after free+realloc.
           Do NOT compile with ASan — it poisons freed memory and hides the bug. */
        static int heap_residue_check(size_t alloc_size) {{
            void *ptr = malloc(alloc_size);
            if (!ptr) return 0;
            fill_secret(ptr, alloc_size);
            free(ptr);
            void *ptr2 = malloc(alloc_size);
            if (!ptr2) return 0;
            int found = volatile_read_has_secret(ptr2, alloc_size);
            hex_dump("Heap residue after free+realloc", ptr2,
                     alloc_size > 64 ? 64 : alloc_size);
            free(ptr2);
            return found;
        }}

        #endif /* POC_COMMON_H */
    """)


# ---------------------------------------------------------------------------
# Per-category PoC generators
# ---------------------------------------------------------------------------


class PoCGenerator:
    """Base class for per-category PoC generators."""

    category: str = ""
    opt_level: str = "-O0"

    def __init__(
        self, finding: dict[str, Any], compile_db: str, out_dir: str, config: dict[str, Any]
    ):
        self.finding = finding
        self.compile_db = compile_db
        self.out_dir = out_dir
        self.config = config
        self.finding_id = finding.get("id", "unknown")
        self.src_file = finding.get("file", "")
        self.line = finding.get("line", 0)
        self.symbol = finding.get("symbol")
        self.requires_manual = False
        self.adjustment_notes: str | None = None

    def _func_name(self) -> str | None:
        if self.symbol:
            return self.symbol
        return _extract_function_signature(self.src_file, self.line)

    def _source_include_path(self) -> str:
        return _relative_source_path(self.src_file, self.out_dir)

    def _use_source_inclusion(self) -> bool:
        threshold = self.config.get(
            "source_inclusion_threshold", _DEFAULT_SOURCE_INCLUSION_THRESHOLD
        )
        return _count_lines(self.src_file) <= threshold

    def _flags_str(self) -> str:
        flags = _get_compile_flags(self.compile_db, self.src_file)
        if flags is None:
            return ""
        # Filter out optimization flags — we set our own
        return " ".join(f for f in flags if not re.match(r"^-O[0-3sg]$", f))

    def _poc_filename(self) -> str:
        safe_id = re.sub(r"[^a-zA-Z0-9_-]", "_", self.finding_id)
        ext = ".cpp" if _is_cpp_file(self.src_file) else ".c"
        return f"poc_{safe_id}_{self.category.lower()}{ext}"

    def _compiler_var(self) -> str:
        return "$(CXX)" if _is_cpp_file(self.src_file) else "$(CC)"

    def _include_directive(self) -> str:
        func = self._func_name()
        if self._use_source_inclusion():
            return f'#include "{self._source_include_path()}"'
        return f"/* Link against object file containing {func or 'target function'} */"

    def _build_poc_source(self, comment_lines: list[str], body_lines: list[str]) -> str:
        """Assemble a PoC C source file with correct indentation."""
        parts: list[str] = []
        parts.append("/* " + comment_lines[0])
        for cl in comment_lines[1:]:
            parts.append(" * " + cl)
        parts.append(" */")
        parts.append('#include "poc_common.h"')
        parts.append(self._include_directive())
        parts.append("")
        parts.append("int main(void) {")
        for bl in body_lines:
            if bl == "":
                parts.append("")
            else:
                parts.append("    " + bl)
        parts.append("}")
        parts.append("")
        return "\n".join(parts)

    def generate(self) -> tuple[str, str]:
        """Generate PoC source code. Returns (filename, source_code)."""
        raise NotImplementedError

    def makefile_target(self, filename: str) -> str:
        """Return a Makefile target string for this PoC."""
        binary = Path(filename).stem
        flags = self._flags_str()
        compiler = self._compiler_var()
        return (
            f"{binary}: {filename} poc_common.h\n\t{compiler} {self.opt_level} {flags} -o $@ $<\n"
        )

    def manifest_entry(self, filename: str) -> dict[str, Any]:
        """Return a manifest entry for this PoC."""
        entry: dict[str, Any] = {
            "finding_id": self.finding_id,
            "category": self.category,
            "file": filename,
            "makefile_target": Path(filename).stem,
            "compile_opt": self.opt_level,
            "requires_manual_adjustment": self.requires_manual,
        }
        if self.adjustment_notes:
            entry["adjustment_notes"] = self.adjustment_notes
        return entry


class MissingSourceZeroizePoC(PoCGenerator):
    category = "MISSING_SOURCE_ZEROIZE"
    opt_level = "-O0"

    def generate(self) -> tuple[str, str]:
        func = self._func_name()
        filename = self._poc_filename()
        comment = [
            f"PoC for finding {self.finding_id}: {self.category}",
            f"Source: {self.src_file}:{self.line}",
            "Strategy: Call function at -O0, volatile-read buffer after return,",
            "          verify secret persists.",
        ]

        if func:
            body = [
                "unsigned char secret_buf[256];",
                "fill_secret(secret_buf, sizeof(secret_buf));",
                "",
                "/* Call the function that handles the secret */",
                f"{func}(/* TODO: fill in arguments */);",
                "",
                "/* Check if the secret buffer still contains data */",
                "if (volatile_read_nonzero(secret_buf, sizeof(secret_buf)))",
                "    POC_PASS();",
                "else",
                "    POC_FAIL();",
            ]
            self.requires_manual = True
            self.adjustment_notes = (
                f"Fill in arguments for {func}() call and adjust "
                "secret_buf to point to the actual sensitive variable."
            )
        else:
            body = [
                "/* TODO: call the function that handles the secret */",
                "/* TODO: volatile-read the secret buffer after return */",
                "/* if (volatile_read_nonzero(ptr, len)) POC_PASS(); else POC_FAIL(); */",
                'fprintf(stderr, "PoC requires manual adjustment\\n");',
                "exit(1);",
            ]
            self.requires_manual = True
            self.adjustment_notes = (
                "Could not determine function signature. "
                "Fill in function call and secret buffer check."
            )

        return filename, self._build_poc_source(comment, body)


class OptimizedAwayZeroizePoC(PoCGenerator):
    category = "OPTIMIZED_AWAY_ZEROIZE"

    def __init__(self, *args: Any, **kwargs: Any):
        super().__init__(*args, **kwargs)
        compiler_ev = self.finding.get("compiler_evidence", {}) or {}
        diff_summary = compiler_ev.get("diff_summary", "")
        match = re.search(r"O([1-3s])", diff_summary)
        if match:
            self.opt_level = f"-O{match.group(1)}"
        else:
            self.opt_level = "-O2"

    def generate(self) -> tuple[str, str]:
        func = self._func_name()
        filename = self._poc_filename()
        comment = [
            f"PoC for finding {self.finding_id}: {self.category}",
            f"Source: {self.src_file}:{self.line}",
            f"Strategy: Compile at {self.opt_level} where the wipe vanishes,",
            "          call function, volatile-read buffer.",
        ]

        if func:
            body = [
                "unsigned char secret_buf[256];",
                "fill_secret(secret_buf, sizeof(secret_buf));",
                "",
                "/* Call function that contains the wipe the compiler removes */",
                f"{func}(/* TODO: fill in arguments */);",
                "",
                "/* At this opt level the compiler has removed the wipe.",
                "   Volatile-read the buffer to see if secret persists. */",
                "if (volatile_read_nonzero(secret_buf, sizeof(secret_buf)))",
                "    POC_PASS();",
                "else",
                "    POC_FAIL();",
            ]
            self.requires_manual = True
            self.adjustment_notes = (
                f"Fill in arguments for {func}(). "
                f"Compile at {self.opt_level} where the wipe disappears."
            )
        else:
            body = [
                "/* TODO: call function whose wipe is optimized away */",
                'fprintf(stderr, "PoC requires manual adjustment\\n");',
                "exit(1);",
            ]
            self.requires_manual = True
            self.adjustment_notes = "Could not determine function signature."

        return filename, self._build_poc_source(comment, body)


class StackRetentionPoC(PoCGenerator):
    category = "STACK_RETENTION"
    opt_level = "-O2"

    def generate(self) -> tuple[str, str]:
        func = self._func_name()
        filename = self._poc_filename()
        evidence = self.finding.get("evidence", "")
        frame_match = re.search(r"(\d+)\s*bytes?\s*(?:frame|stack|alloc)", evidence)
        frame_size = frame_match.group(1) if frame_match else "256"

        comment = [
            f"PoC for finding {self.finding_id}: {self.category}",
            f"Source: {self.src_file}:{self.line}",
            "Strategy: Call function, immediately call stack_probe() with",
            "          matching frame size to detect residual secrets.",
        ]

        if func:
            body = [
                "/* Call the function that leaves secrets on the stack */",
                f"{func}(/* TODO: fill in arguments */);",
                "",
                "/* Immediately probe the stack for residual secret data */",
                f"if (stack_probe({frame_size}))",
                "    POC_PASS();",
                "else",
                "    POC_FAIL();",
            ]
            self.requires_manual = True
            self.adjustment_notes = (
                f"Fill in arguments for {func}(). "
                f"Frame size {frame_size} is estimated from evidence; adjust if needed."
            )
        else:
            body = [
                "/* TODO: call the function that retains secrets on stack */",
                f"if (stack_probe({frame_size}))",
                "    POC_PASS();",
                "else",
                "    POC_FAIL();",
            ]
            self.requires_manual = True
            self.adjustment_notes = "Could not determine function signature."

        return filename, self._build_poc_source(comment, body)


class RegisterSpillPoC(PoCGenerator):
    category = "REGISTER_SPILL"
    opt_level = "-O2"

    def generate(self) -> tuple[str, str]:
        func = self._func_name()
        filename = self._poc_filename()
        evidence = self.finding.get("evidence", "")
        offset_match = re.search(r"-(\d+)\(%[re][sb]p\)", evidence)
        spill_offset = offset_match.group(1) if offset_match else "64"

        comment = [
            f"PoC for finding {self.finding_id}: {self.category}",
            f"Source: {self.src_file}:{self.line}",
            "Strategy: Like stack retention but probe the specific spill",
            "          offset region from ASM evidence.",
        ]

        if func:
            body = [
                "/* Call the function that spills secrets to stack */",
                f"{func}(/* TODO: fill in arguments */);",
                "",
                "/* Probe the specific spill offset region */",
                f"if (stack_probe({spill_offset}))",
                "    POC_PASS();",
                "else",
                "    POC_FAIL();",
            ]
            self.requires_manual = True
            self.adjustment_notes = (
                f"Fill in arguments for {func}(). "
                f"Spill offset {spill_offset} from ASM evidence; adjust if needed."
            )
        else:
            body = [
                "/* TODO: call the function that spills registers to stack */",
                f"if (stack_probe({spill_offset}))",
                "    POC_PASS();",
                "else",
                "    POC_FAIL();",
            ]
            self.requires_manual = True
            self.adjustment_notes = "Could not determine function signature."

        return filename, self._build_poc_source(comment, body)


class SecretCopyPoC(PoCGenerator):
    category = "SECRET_COPY"
    opt_level = "-O0"

    def generate(self) -> tuple[str, str]:
        func = self._func_name()
        filename = self._poc_filename()
        comment = [
            f"PoC for finding {self.finding_id}: {self.category}",
            f"Source: {self.src_file}:{self.line}",
            "Strategy: Call function at -O0, verify original may be wiped,",
            "          volatile-read the copy destination.",
        ]

        if func:
            body = [
                "/* Call function; it copies the secret internally */",
                f"{func}(/* TODO: fill in arguments */);",
                "",
                "/* The original may be wiped, but the copy destination persists.",
                "   TODO: point this at the actual copy destination buffer. */",
                "unsigned char *copy_dest = NULL; /* TODO: set to copy destination */",
                "if (copy_dest && volatile_read_has_secret(copy_dest, 256))",
                "    POC_PASS();",
                "else",
                "    POC_FAIL();",
            ]
            self.requires_manual = True
            self.adjustment_notes = (
                f"Fill in arguments for {func}() and set copy_dest to "
                "point to the buffer where the secret is copied."
            )
        else:
            body = [
                "/* TODO: call the function that copies the secret */",
                "/* TODO: volatile-read the copy destination after return */",
                'fprintf(stderr, "PoC requires manual adjustment\\n");',
                "exit(1);",
            ]
            self.requires_manual = True
            self.adjustment_notes = "Could not determine function signature or copy destination."

        return filename, self._build_poc_source(comment, body)


class MissingOnErrorPathPoC(PoCGenerator):
    category = "MISSING_ON_ERROR_PATH"
    opt_level = "-O0"

    def generate(self) -> tuple[str, str]:
        func = self._func_name()
        filename = self._poc_filename()
        comment = [
            f"PoC for finding {self.finding_id}: {self.category}",
            f"Source: {self.src_file}:{self.line}",
            "Strategy: Force the error path via controlled input,",
            "          volatile-read buffer after error return.",
        ]

        if func:
            body = [
                "unsigned char secret_buf[256];",
                "fill_secret(secret_buf, sizeof(secret_buf));",
                "",
                "/* Force the error path via controlled input.",
                "   TODO: set up inputs that trigger the error return. */",
                f"int ret = {func}(/* TODO: error-triggering arguments */);",
                "",
                'fprintf(stderr, "Function returned: %d\\n", ret);',
                'hex_dump("Secret buffer after error return", secret_buf,',
                "         sizeof(secret_buf));",
                "",
                "/* After error return the secret should have been wiped */",
                "if (volatile_read_has_secret(secret_buf, sizeof(secret_buf)))",
                "    POC_PASS();",
                "else",
                "    POC_FAIL();",
            ]
            self.requires_manual = True
            self.adjustment_notes = (
                f"Fill in error-triggering arguments for {func}(). "
                "The error path must be taken to demonstrate missing cleanup."
            )
        else:
            body = [
                "/* TODO: call function with error-triggering inputs */",
                "/* TODO: volatile-read buffer after error return */",
                'fprintf(stderr, "PoC requires manual adjustment\\n");',
                "exit(1);",
            ]
            self.requires_manual = True
            self.adjustment_notes = "Could not determine function signature."

        return filename, self._build_poc_source(comment, body)


class PartialWipePoC(PoCGenerator):
    category = "PARTIAL_WIPE"
    opt_level = "-O0"

    def generate(self) -> tuple[str, str]:
        func = self._func_name()
        filename = self._poc_filename()
        evidence = self.finding.get("evidence", "")

        # Try to extract wiped vs full sizes from evidence
        size_matches = re.findall(r"(\d+)\s*bytes?", evidence)
        if len(size_matches) >= 2:
            wiped_size = size_matches[0]
            full_size = size_matches[1]
        else:
            wiped_size = "8"
            full_size = "256"

        comment = [
            f"PoC for finding {self.finding_id}: {self.category}",
            f"Source: {self.src_file}:{self.line}",
            "Strategy: Fill full buffer with secret, call function, volatile-read",
            "          the tail beyond the incorrectly-sized wipe.",
        ]

        if func:
            body = [
                f"unsigned char buf[{full_size}];",
                f"fill_secret(buf, {full_size});",
                "",
                "/* Call function that partially wipes the buffer */",
                f"{func}(/* TODO: fill in arguments */);",
                "",
                f"/* The wipe covers only {wiped_size} bytes of {full_size}.",
                "   Check the tail beyond the wiped region. */",
                f"if (volatile_read_has_secret(buf + {wiped_size}, {full_size} - {wiped_size}))",
                "    POC_PASS();",
                "else",
                "    POC_FAIL();",
            ]
            self.requires_manual = True
            self.adjustment_notes = (
                f"Fill in arguments for {func}(). "
                f"Wiped size {wiped_size} and full size {full_size} are estimated "
                "from evidence; adjust if needed."
            )
        else:
            body = [
                f"unsigned char buf[{full_size}];",
                f"fill_secret(buf, {full_size});",
                "",
                "/* TODO: call the function that partially wipes the buffer */",
                "",
                f"/* Check tail beyond the {wiped_size}-byte wipe */",
                f"if (volatile_read_has_secret(buf + {wiped_size}, {full_size} - {wiped_size}))",
                "    POC_PASS();",
                "else",
                "    POC_FAIL();",
            ]
            self.requires_manual = True
            self.adjustment_notes = (
                "Could not determine function signature. "
                f"Wiped size {wiped_size} and full size {full_size} are estimated; "
                "adjust if needed."
            )

        return filename, self._build_poc_source(comment, body)


class NotOnAllPathsPoC(PoCGenerator):
    category = "NOT_ON_ALL_PATHS"
    opt_level = "-O0"

    def generate(self) -> tuple[str, str]:
        func = self._func_name()
        filename = self._poc_filename()
        evidence = self.finding.get("evidence", "")

        # Try to extract uncovered path line from evidence
        line_match = re.search(r"line (\d+)", evidence)
        uncovered_line = line_match.group(1) if line_match else "unknown"

        comment = [
            f"PoC for finding {self.finding_id}: {self.category}",
            f"Source: {self.src_file}:{self.line}",
            "Strategy: Force execution down the uncovered path that lacks the wipe,",
            "          then volatile-read the secret buffer.",
        ]

        if func:
            body = [
                "unsigned char secret_buf[256];",
                "fill_secret(secret_buf, sizeof(secret_buf));",
                "",
                "/* Force the uncovered path (no wipe).",
                f"   TODO: set up inputs that take the path at line {uncovered_line}. */",
                f"{func}(/* TODO: path-forcing arguments */);",
                "",
                "/* After taking the uncovered path the secret should persist */",
                "if (volatile_read_has_secret(secret_buf, sizeof(secret_buf)))",
                "    POC_PASS();",
                "else",
                "    POC_FAIL();",
            ]
            self.requires_manual = True
            self.adjustment_notes = (
                f"Fill in arguments for {func}() that force execution through "
                f"the uncovered path (line {uncovered_line}). "
                "Identify which inputs bypass the wipe."
            )
        else:
            body = [
                "/* TODO: call function with inputs that take the uncovered path */",
                "/* TODO: volatile-read buffer after return */",
                'fprintf(stderr, "PoC requires manual adjustment\\n");',
                "exit(1);",
            ]
            self.requires_manual = True
            self.adjustment_notes = (
                "Could not determine function signature. "
                "Identify inputs that force the uncovered path."
            )

        return filename, self._build_poc_source(comment, body)


class InsecureHeapAllocPoC(PoCGenerator):
    category = "INSECURE_HEAP_ALLOC"
    opt_level = "-O0"

    def generate(self) -> tuple[str, str]:
        func = self._func_name()
        filename = self._poc_filename()
        evidence = self.finding.get("evidence", "")

        # Extract allocation size and allocator from evidence
        size_match = re.search(r"(\d+)", evidence)
        alloc_size = size_match.group(1) if size_match else "256"
        alloc_match = re.search(r"(malloc|calloc|realloc)", evidence)
        allocator = alloc_match.group(1) if alloc_match else "malloc"

        comment = [
            f"PoC for finding {self.finding_id}: {self.category}",
            f"Source: {self.src_file}:{self.line}",
            "Strategy: Demonstrate heap residue — allocate, fill with secret, free,",
            "          re-allocate same size, check if secret persists.",
            "NOTE: Do NOT compile with ASan (it poisons freed memory).",
        ]

        body = [
            f"/* Demonstrate that {allocator}() leaves secret residue after free */",
            f"if (heap_residue_check({alloc_size}))",
            "    POC_PASS();",
            "else",
            "    POC_FAIL();",
        ]

        if func:
            body.extend(
                [
                    "",
                    "/* Additionally, call the function that uses the insecure allocator",
                    "   and verify residue after it returns. */",
                    f"/* {func}(/ * TODO: fill in arguments * /); */",
                ]
            )
            self.requires_manual = False  # Self-contained heap check works
            self.adjustment_notes = (
                f"The self-contained heap_residue_check() demonstrates the "
                f"vulnerability. Optionally uncomment and fill in {func}() "
                "for a function-specific test."
            )
        else:
            self.requires_manual = False
            self.adjustment_notes = (
                f"Self-contained PoC using heap_residue_check({alloc_size}). "
                "Optionally add a call to the target function for specificity."
            )

        return filename, self._build_poc_source(comment, body)


class LoopUnrolledIncompletePoC(PoCGenerator):
    category = "LOOP_UNROLLED_INCOMPLETE"
    opt_level = "-O2"

    def generate(self) -> tuple[str, str]:
        func = self._func_name()
        filename = self._poc_filename()
        evidence = self.finding.get("evidence", "")

        # Extract covered bytes and object size from evidence
        covered_match = re.search(r"(\d+)\s*consecutive", evidence)
        covered_bytes = covered_match.group(1) if covered_match else "16"
        size_match = re.search(r"object size is (\d+)", evidence)
        full_size = size_match.group(1) if size_match else "256"

        comment = [
            f"PoC for finding {self.finding_id}: {self.category}",
            f"Source: {self.src_file}:{self.line}",
            "Strategy: Compile at -O2 where incomplete loop unrolling occurs.",
            f"          Fill buffer, call function, check tail beyond {covered_bytes}",
            f"          unrolled bytes (object size: {full_size}).",
        ]

        if func:
            body = [
                f"unsigned char buf[{full_size}];",
                f"fill_secret(buf, {full_size});",
                "",
                "/* Call function whose wipe loop is incompletely unrolled at -O2 */",
                f"{func}(/* TODO: fill in arguments */);",
                "",
                f"/* The compiler unrolled {covered_bytes} bytes of the wipe loop",
                f"   but the object is {full_size} bytes. Check the tail. */",
                (
                    f"if (volatile_read_has_secret(buf + {covered_bytes},"
                    f" {full_size} - {covered_bytes}))"
                ),
                "    POC_PASS();",
                "else",
                "    POC_FAIL();",
            ]
            self.requires_manual = True
            self.adjustment_notes = (
                f"Fill in arguments for {func}(). "
                f"Covered bytes {covered_bytes} and object size {full_size} are "
                "estimated from IR evidence; adjust if needed. "
                "Must compile at -O2 for unrolling to occur."
            )
        else:
            body = [
                f"unsigned char buf[{full_size}];",
                f"fill_secret(buf, {full_size});",
                "",
                "/* TODO: call function with incompletely unrolled wipe loop */",
                "",
                f"/* Check tail beyond the {covered_bytes}-byte unrolled region */",
                (
                    f"if (volatile_read_has_secret(buf + {covered_bytes},"
                    f" {full_size} - {covered_bytes}))"
                ),
                "    POC_PASS();",
                "else",
                "    POC_FAIL();",
            ]
            self.requires_manual = True
            self.adjustment_notes = (
                "Could not determine function signature. "
                f"Covered bytes {covered_bytes} and object size {full_size} are "
                "estimated; adjust if needed."
            )

        return filename, self._build_poc_source(comment, body)


class NotDominatingExitsPoC(PoCGenerator):
    category = "NOT_DOMINATING_EXITS"
    opt_level = "-O0"

    def generate(self) -> tuple[str, str]:
        func = self._func_name()
        filename = self._poc_filename()
        evidence = self.finding.get("evidence", "")

        # Extract exit line or path count from CFG evidence
        exit_match = re.search(r"exit at line (\d+)", evidence)
        path_match = re.search(r"(\d+) of (\d+) exit paths", evidence)
        if exit_match:
            exit_info = f"line {exit_match.group(1)}"
        elif path_match:
            exit_info = f"{path_match.group(1)} of {path_match.group(2)} exit paths"
        else:
            exit_info = "an exit path that bypasses the wipe"

        comment = [
            f"PoC for finding {self.finding_id}: {self.category}",
            f"Source: {self.src_file}:{self.line}",
            "Strategy: Force execution through an exit path that bypasses the wipe",
            f"          (CFG evidence: {exit_info}), then volatile-read the secret.",
        ]

        if func:
            body = [
                "unsigned char secret_buf[256];",
                "fill_secret(secret_buf, sizeof(secret_buf));",
                "",
                "/* Force execution through the exit path that bypasses the wipe.",
                f"   CFG shows the wipe does not dominate {exit_info}.",
                "   TODO: set up inputs that reach this exit path. */",
                f"{func}(/* TODO: exit-path-forcing arguments */);",
                "",
                "/* After taking the non-dominated exit the secret should persist */",
                "if (volatile_read_has_secret(secret_buf, sizeof(secret_buf)))",
                "    POC_PASS();",
                "else",
                "    POC_FAIL();",
            ]
            self.requires_manual = True
            self.adjustment_notes = (
                f"Fill in arguments for {func}() that force execution through "
                f"{exit_info} (the exit not dominated by the wipe). "
                "Requires understanding of the function's control flow."
            )
        else:
            body = [
                "/* TODO: call function with inputs that reach the non-dominated exit */",
                "/* TODO: volatile-read buffer after return */",
                'fprintf(stderr, "PoC requires manual adjustment\\n");',
                "exit(1);",
            ]
            self.requires_manual = True
            self.adjustment_notes = (
                "Could not determine function signature. "
                "Identify inputs that reach the exit path bypassing the wipe."
            )

        return filename, self._build_poc_source(comment, body)


# ---------------------------------------------------------------------------
# Category -> generator mapping
# ---------------------------------------------------------------------------
_GENERATORS: dict[str, type] = {
    "MISSING_SOURCE_ZEROIZE": MissingSourceZeroizePoC,
    "OPTIMIZED_AWAY_ZEROIZE": OptimizedAwayZeroizePoC,
    "STACK_RETENTION": StackRetentionPoC,
    "REGISTER_SPILL": RegisterSpillPoC,
    "SECRET_COPY": SecretCopyPoC,
    "MISSING_ON_ERROR_PATH": MissingOnErrorPathPoC,
    "PARTIAL_WIPE": PartialWipePoC,
    "NOT_ON_ALL_PATHS": NotOnAllPathsPoC,
    "INSECURE_HEAP_ALLOC": InsecureHeapAllocPoC,
    "LOOP_UNROLLED_INCOMPLETE": LoopUnrolledIncompletePoC,
    "NOT_DOMINATING_EXITS": NotDominatingExitsPoC,
}


# ---------------------------------------------------------------------------
# Makefile generation
# ---------------------------------------------------------------------------


def _generate_makefile(targets: list[dict[str, str]]) -> str:
    """Generate a Makefile for all PoC targets."""
    lines = [
        "# Auto-generated by generate_poc.py",
        "# Build: make all",
        "# Run:   make run",
        "",
        "CC ?= cc",
        "CXX ?= c++",
        "CFLAGS ?= -Wall -Wextra",
        "CXXFLAGS ?= -Wall -Wextra",
        "",
        "BINARIES =",
    ]

    binary_names = []
    target_blocks = []

    for t in targets:
        binary = t["binary"]
        binary_names.append(binary)
        target_blocks.append(t["rule"])

    lines[9] = "BINARIES = " + " ".join(binary_names)
    lines.append("")
    lines.append(".PHONY: all run clean")
    lines.append("")
    lines.append("all: $(BINARIES)")
    lines.append("")

    # Run target
    lines.append("run: all")
    for name in binary_names:
        lines.append(f"\t@echo '--- Running {name} ---'")
        lines.append(f"\t@./{name} && echo 'RESULT: EXPLOITABLE' || echo 'RESULT: NOT EXPLOITABLE'")
    lines.append("")

    # Per-target rules
    for block in target_blocks:
        lines.append(block)
        lines.append("")

    lines.append("clean:")
    lines.append("\trm -f $(BINARIES)")
    lines.append("")

    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Main logic
# ---------------------------------------------------------------------------


def _filter_findings(
    findings: list[dict[str, Any]], categories: frozenset, min_confidence: str | None
) -> list[dict[str, Any]]:
    """Filter findings to only exploitable categories above confidence threshold.

    When min_confidence is None, all findings in the selected categories are
    returned regardless of confidence level.
    """
    result = []
    for f in findings:
        cat = f.get("category", "")
        if cat not in categories:
            continue
        if min_confidence is None:
            result.append(f)
            continue
        threshold = _CONFIDENCE_ORDER.get(min_confidence, 2)
        # Map needs_review boolean to confidence string
        conf = "needs_review" if f.get("needs_review", False) else "likely"
        # Check evidence/compiler_evidence for confirmed signals
        if f.get("compiler_evidence"):
            conf = "confirmed"
        # CFG-backed findings use evidence_source instead of compiler_evidence
        evidence_sources = f.get("evidence_source", [])
        if isinstance(evidence_sources, list) and "cfg" in evidence_sources:
            conf = "confirmed"
        if _CONFIDENCE_ORDER.get(conf, 2) <= threshold:
            result.append(f)
    return result


def run(
    findings_path: str,
    compile_db: str,
    out_dir: str,
    categories: list[str] | None = None,
    config_path: str | None = None,
    no_confidence_filter: bool = False,
) -> int:
    """Main entry point. Returns exit code.

    Args:
        no_confidence_filter: When True, generate PoCs for all findings
            regardless of confidence level.
    """

    # Load findings
    try:
        with open(findings_path) as f:
            data = json.load(f)
    except (OSError, json.JSONDecodeError) as exc:
        sys.stderr.write(f"Error: cannot read findings: {exc}\n")
        return 1

    # Support both top-level array and {findings: [...]} format
    if isinstance(data, list):
        findings = data
    elif isinstance(data, dict):
        findings = data.get("findings", [])
    else:
        sys.stderr.write("Error: findings must be a JSON array or object with 'findings' key\n")
        return 1

    # Load config
    config = _load_config(config_path)
    min_confidence: str | None = (
        None if no_confidence_filter else config.get("min_confidence", _DEFAULT_MIN_CONFIDENCE)
    )
    secret_fill = config.get("secret_fill_byte", _DEFAULT_SECRET_FILL)
    stack_probe_max = config.get("stack_probe_max_size", _DEFAULT_STACK_PROBE_MAX)

    # Determine categories
    if categories:
        selected = frozenset(categories) & EXPLOITABLE_CATEGORIES
    else:
        selected = EXPLOITABLE_CATEGORIES

    # Filter findings
    exploitable = _filter_findings(findings, selected, min_confidence)
    if not exploitable:
        sys.stderr.write("No exploitable findings found in selected categories.\n")
        return 2

    # Create output directory
    try:
        os.makedirs(out_dir, exist_ok=True)
    except OSError as exc:
        sys.stderr.write(f"Error: cannot create output directory: {exc}\n")
        return 3

    # Write poc_common.h
    common_h = _generate_common_header(secret_fill, stack_probe_max)
    with open(os.path.join(out_dir, "poc_common.h"), "w") as f:
        f.write(common_h)

    # Generate PoCs
    makefile_targets: list[dict[str, str]] = []
    manifest_entries: list[dict[str, Any]] = []
    generated_count = 0
    manual_count = 0

    for finding in exploitable:
        cat = finding.get("category", "")
        gen_cls = _GENERATORS.get(cat)
        if gen_cls is None:
            continue

        gen = gen_cls(finding, compile_db, out_dir, config)
        filename, source = gen.generate()

        # Write PoC source
        poc_path = os.path.join(out_dir, filename)
        with open(poc_path, "w") as f:
            f.write(source)

        # Collect Makefile target
        binary = Path(filename).stem
        makefile_targets.append(
            {
                "binary": binary,
                "rule": gen.makefile_target(filename),
            }
        )

        # Collect manifest entry
        manifest_entries.append(gen.manifest_entry(filename))

        generated_count += 1
        if gen.requires_manual:
            manual_count += 1

    # Write Makefile
    makefile_content = _generate_makefile(makefile_targets)
    with open(os.path.join(out_dir, "Makefile"), "w") as f:
        f.write(makefile_content)

    # Write manifest
    manifest = {
        "pocs_generated": generated_count,
        "pocs_requiring_adjustment": manual_count,
        "output_dir": out_dir,
        "categories_covered": sorted(set(e["category"] for e in manifest_entries)),
        "entries": manifest_entries,
    }
    with open(os.path.join(out_dir, "poc_manifest.json"), "w") as f:
        json.dump(manifest, f, indent=2)
        f.write("\n")

    # Summary
    sys.stderr.write(
        f"Generated {generated_count} PoC(s) in {out_dir}/ "
        f"({manual_count} requiring manual adjustment)\n"
    )
    return 0


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Generate proof-of-concept programs from zeroize-audit findings.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    parser.add_argument(
        "--findings",
        required=True,
        metavar="PATH",
        help="Path to findings JSON (array or {findings: [...]})",
    )
    parser.add_argument(
        "--compile-db",
        required=True,
        metavar="PATH",
        help="Path to compile_commands.json",
    )
    parser.add_argument(
        "--out",
        required=True,
        metavar="DIR",
        help="Output directory for generated PoCs",
    )
    parser.add_argument(
        "--categories",
        metavar="CAT1,CAT2,...",
        default=None,
        help="Comma-separated list of finding categories (default: all exploitable)",
    )
    parser.add_argument(
        "--config",
        metavar="PATH",
        default=None,
        help="Path to config YAML with poc_generation section",
    )
    parser.add_argument(
        "--no-confidence-filter",
        action="store_true",
        default=False,
        help="Generate PoCs for all findings regardless of confidence level",
    )
    args = parser.parse_args()

    categories = None
    if args.categories:
        categories = [c.strip() for c in args.categories.split(",")]

    sys.exit(
        run(
            args.findings,
            args.compile_db,
            args.out,
            categories=categories,
            config_path=args.config,
            no_confidence_filter=args.no_confidence_filter,
        )
    )


if __name__ == "__main__":
    main()
