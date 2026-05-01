#!/usr/bin/env python3
# /// script
# requires-python = ">=3.11"
# dependencies = []
# ///
"""
Extract per-TU compilation flags from compile_commands.json.

Reads the compile database for a given source file and emits the compilation
flags suitable for single-file LLVM IR or assembly emission via clang. Output
and dependency-generation flags are stripped.

Usage:
  python extract_compile_flags.py \\
    --compile-db compile_commands.json \\
    --src path/to/file.c \\
    [--format shell|json|lines] \\
    [--working-dir /override/cwd]

  # Recommended: capture as a bash array (works in both bash and zsh):
  FLAGS=()
  while IFS= read -r flag; do FLAGS+=("$flag"); done < <(
    python {baseDir}/tools/extract_compile_flags.py \\
      --compile-db build/compile_commands.json \\
      --src src/crypto.c --format lines)
  {baseDir}/tools/emit_ir.sh --src src/crypto.c --out /tmp/out.ll --opt O2 -- "${FLAGS[@]}"

  # Get as JSON list:
  python {baseDir}/tools/extract_compile_flags.py \\
    --compile-db build/compile_commands.json \\
    --src src/crypto.c \\
    --format json

Exit codes:
  0  flags written to stdout
  1  compile_commands.json not found or contains invalid JSON
  2  source file not found in the compile database
"""

import argparse
import contextlib
import json
import re
import shlex
import sys
from pathlib import Path

# ---------------------------------------------------------------------------
# Flags to strip: irrelevant or harmful for single-file IR/ASM emission.
# Ordering matters for the "takes an argument" set — we must skip the next
# token too.
# ---------------------------------------------------------------------------

# Flags that consume the next token as their argument and should be stripped.
_STRIP_WITH_ARG = frozenset(["-o", "-MF", "-MT", "-MQ"])

# Single-token flags to strip (no argument consumed).
_STRIP_STANDALONE = frozenset(
    [
        "-c",
        "-MD",
        "-MMD",
        "-MP",
        "-MG",
        "-pipe",
        "-save-temps",
        "-gsplit-dwarf",
    ]
)

# Prefix patterns: strip any flag whose string starts with one of these.
_STRIP_PREFIXES = (
    "-fcrash-diagnostics-dir",
    "-fmodule-file=",
    "-fmodules-cache-path=",
    "-fpch-preprocess",
    "--serialize-diagnostics",
    "-fdebug-prefix-map=",
    "--debug-prefix-map=",
    "-iprefix",
    "-iwithprefix",
    "-iwithprefixbefore",
    "-fprofile-generate",
    "-fprofile-use=",
    "-fprofile-instr-generate",
    "-fprofile-instr-use=",
    "-fcoverage-mapping",
)

# Regex for "attached" forms of strip-with-arg flags, e.g. "-MFdepfile" or "-MF=depfile".
# These are single tokens that begin with one of the strip-with-arg prefixes.
_STRIP_ATTACHED_RE = re.compile(r"^(?:-o|-MF|-MT|-MQ)(?:=?.+)$")


def _should_strip(flag: str) -> bool:
    """Return True if this flag token should be removed from the output."""
    if flag in _STRIP_STANDALONE:
        return True
    if _STRIP_ATTACHED_RE.match(flag):
        return True
    return any(flag.startswith(prefix) for prefix in _STRIP_PREFIXES)


def _extract_flags(raw_flags: list[str]) -> list[str]:
    """
    Filter a list of raw flag tokens (excluding the compiler executable at index 0
    and the source file argument) down to the build-relevant subset.
    """
    result: list[str] = []
    skip_next = False

    for token in raw_flags:
        if skip_next:
            skip_next = False
            continue

        # Strip-with-arg: consume this token and the next.
        if token in _STRIP_WITH_ARG:
            skip_next = True
            continue

        # Other strip conditions (standalone and prefixed).
        if _should_strip(token):
            continue

        result.append(token)

    return result


def _parse_command_string(command: str) -> list[str]:
    """Split a shell command string into tokens using POSIX shlex rules."""
    try:
        return shlex.split(command)
    except ValueError as exc:
        # Malformed quoting — best-effort split on whitespace.
        sys.stderr.write(f"Warning: shlex.split failed ({exc}), falling back to whitespace split\n")
        return command.split()


def _normalize_path(path_str: str, directory: str) -> Path:
    """Resolve a (possibly relative) path against a directory to an absolute Path."""
    p = Path(path_str)
    if not p.is_absolute():
        p = Path(directory) / p
    return p.resolve()


def find_entry(db: list, src: str, working_dir: str | None = None) -> dict | None:
    """
    Find the compile_commands.json entry for the given source file.

    Matching is done by resolving both the entry's 'file' field and the
    requested 'src' to absolute paths and comparing them.  The first match
    is returned (some projects emit duplicates for different configurations).
    """
    src_path = Path(src)
    if working_dir and not src_path.is_absolute():
        src_path = Path(working_dir) / src_path
    with contextlib.suppress(OSError):
        src_path = src_path.resolve()  # file may not exist on disk; compare string form

    for entry in db:
        entry_dir = entry.get("directory", "")
        entry_file = entry.get("file", "")
        try:
            entry_path = _normalize_path(entry_file, entry_dir)
        except OSError:
            entry_path = Path(entry_file)

        if entry_path == src_path:
            return entry

    # Second pass: basename comparison (handles minor path discrepancies).
    src_basename = src_path.name
    for entry in db:
        entry_file = entry.get("file", "")
        if Path(entry_file).name == src_basename:
            return entry

    return None


def get_raw_flags(entry: dict) -> list[str]:
    """
    Extract the raw flag tokens from a compile_commands.json entry.

    Returns all tokens except the compiler executable (index 0) and the
    source file argument.  The caller is responsible for further filtering.
    """
    arguments: list[str] | None = entry.get("arguments")
    if arguments is None:
        command = entry.get("command", "")
        arguments = _parse_command_string(command)

    if not arguments:
        return []

    # Drop compiler executable (index 0) and the source file token.
    src_file = entry.get("file", "")
    raw: list[str] = []
    for token in arguments[1:]:
        # Skip the source file itself (it will be specified via --src to emit_ir.sh).
        if token == src_file or (src_file and Path(token).name == Path(src_file).name):
            continue
        raw.append(token)

    return raw


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Extract per-TU compile flags from compile_commands.json.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    parser.add_argument(
        "--compile-db",
        required=True,
        metavar="PATH",
        help="Path to compile_commands.json",
    )
    parser.add_argument(
        "--src",
        required=True,
        metavar="FILE",
        help="Source file to look up in the compile database",
    )
    parser.add_argument(
        "--format",
        choices=["shell", "json", "lines"],
        default="shell",
        help=(
            "Output format: 'shell' (space-separated, shell-quoted), 'json' list, "
            "or 'lines' (one flag per line, for array consumption) (default: shell)"
        ),
    )
    parser.add_argument(
        "--working-dir",
        metavar="DIR",
        default=None,
        help="Working directory for resolving relative --src paths (default: cwd)",
    )
    args = parser.parse_args()

    # Load compile database.
    db_path = Path(args.compile_db)
    if not db_path.exists():
        sys.stderr.write(f"Error: compile database not found: {db_path}\n")
        sys.exit(1)

    try:
        db = json.loads(db_path.read_text())
    except json.JSONDecodeError as exc:
        sys.stderr.write(f"Error: invalid JSON in {db_path}: {exc}\n")
        sys.exit(1)

    if not isinstance(db, list):
        sys.stderr.write(f"Error: expected a JSON array in {db_path}\n")
        sys.exit(1)

    # Find the entry for the requested source file.
    entry = find_entry(db, args.src, args.working_dir)
    if entry is None:
        sys.stderr.write(f"Error: '{args.src}' not found in {db_path} ({len(db)} entries)\n")
        sys.exit(2)

    # Extract and filter flags.
    raw = get_raw_flags(entry)
    flags = _extract_flags(raw)

    # Output.
    if args.format == "json":
        print(json.dumps(flags))
    elif args.format == "lines":
        for f in flags:
            print(f)
    else:
        # Shell format: space-join of individually shell-quoted tokens.
        print(" ".join(shlex.quote(f) for f in flags))


if __name__ == "__main__":
    main()
