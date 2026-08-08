#!/usr/bin/env python3
# /// script
# requires-python = ">=3.11"
# dependencies = ["tree-sitter>=0.23", "tree-sitter-c>=0.23", "tree-sitter-cpp>=0.23"]
# ///
"""Enumerate review units and their countable site populations for c-review.

This is the spine of the location partition. Measurement (see
tools/c-review-bench/MEASUREMENTS.md) found that partitioning review work by source
location beat partitioning it by bug class at ~40% of the cost, and that the two
axes find different bugs. Location wins on coverage you can *prove*: every line is
owned by exactly one agent, and that ownership is generated here, from a parse, not
from an agent's own account of what it read.

Two constraints are load-bearing and both come from measured failures:

1. **Units are capped at `--max-unit-lines`.** One 628-line function held four bugs
   and no configuration ever found all four in eight attempts. A function larger
   than the cap is split at syntactic seams (switch cases, loop and branch bodies),
   because as one atomic unit it reproduces exactly the saturation problem the
   location partition exists to solve.

2. **Every line is owned.** Chunks tile their function's line range contiguously and
   every file contributes a `file-scope` unit for the regions outside any function.
   Reachability weighting is for depth, never for coverage: three of the four bugs
   only a class sweep found lived in cold error-handling paths, which an
   attacker-reachability prior would have deprioritised.

The site populations are what make a `clean` ledger verdict falsifiable downstream:
`check_ledger.py` requires a clean row to account for every site line counted here.
An agent cannot clear "bounds" on a unit with twelve write sites by saying it looked.

Exits non-zero when it finds no source files or no units. A partitioner that
partitions nothing must fail loudly rather than certify an empty review.
"""

from __future__ import annotations

import argparse
import json
import math
import re
import sys
from pathlib import Path
from typing import Any

C_EXTS = frozenset({".c", ".h"})
CPP_EXTS = frozenset({".cc", ".cpp", ".cxx", ".c++", ".hpp", ".hh", ".hxx", ".h++", ".ipp", ".tcc"})
SOURCE_EXTS = C_EXTS | CPP_EXTS

# Directories that hold build output or vendored VCS metadata rather than code under
# review. Deliberately short: skipping `tests/` or `third_party/` by default would be a
# silent coverage hole, and the caller can pass --exclude for those.
SKIP_DIRS = frozenset({".git", ".svn", ".hg", "node_modules", "__pycache__"})

MEM_WRITE_FNS = frozenset(
    {
        "memcpy",
        "memmove",
        "memset",
        "memccpy",
        "mempcpy",
        "bcopy",
        "bzero",
        "strcpy",
        "strncpy",
        "strcat",
        "strncat",
        "stpcpy",
        "stpncpy",
        "sprintf",
        "snprintf",
        "vsprintf",
        "vsnprintf",
        "swprintf",
        "wmemcpy",
        "wmemmove",
        "wmemset",
        "wcscpy",
        "wcsncpy",
        "wcscat",
        "read",
        "pread",
        "recv",
        "recvfrom",
        "recvmsg",
        "fread",
        "gets",
        "fgets",
        "memcpy_s",
        "memmove_s",
        "strcpy_s",
        "strcat_s",
        "sprintf_s",
    }
)
ALLOC_FNS = frozenset(
    {
        "malloc",
        "calloc",
        "realloc",
        "reallocarray",
        "aligned_alloc",
        "valloc",
        "memalign",
        "posix_memalign",
        "strdup",
        "strndup",
        "wcsdup",
        "asprintf",
        "vasprintf",
        "open",
        "openat",
        "fopen",
        "fdopen",
        "freopen",
        "socket",
        "accept",
        "mmap",
        "dup",
        "dup2",
        "opendir",
        "tmpfile",
        "HeapAlloc",
        "LocalAlloc",
        "GlobalAlloc",
        "VirtualAlloc",
        "CoTaskMemAlloc",
    }
)
RELEASE_FNS = frozenset(
    {
        "free",
        "cfree",
        "close",
        "fclose",
        "closedir",
        "munmap",
        "shutdown",
        "HeapFree",
        "LocalFree",
        "GlobalFree",
        "VirtualFree",
        "CoTaskMemFree",
    }
)
STRING_FNS = frozenset(
    {
        "strcpy",
        "strncpy",
        "strcat",
        "strncat",
        "strlen",
        "strnlen",
        "strdup",
        "strndup",
        "stpcpy",
        "stpncpy",
        "strtok",
        "strtok_r",
        "strchr",
        "strrchr",
        "strstr",
        "strcmp",
        "strncmp",
        "strcasecmp",
        "strncasecmp",
        "sprintf",
        "snprintf",
        "vsnprintf",
        "asprintf",
        "wcslen",
        "wcscpy",
        "wcsncpy",
    }
)
# Functions whose return value is conventionally discarded — memcpy returns its own
# destination, printf's count is noise. Counting these as unchecked calls would pad the
# return-values population with lines that cannot be bugs, and the ledger gate makes an
# agent account for every line in a population, so the padding is not free.
RETURN_IGNORABLE_FNS = frozenset(
    {
        "memcpy",
        "memmove",
        "memset",
        "bcopy",
        "bzero",
        "mempcpy",
        "wmemcpy",
        "wmemset",
        "strcpy",
        "strncpy",
        "strcat",
        "strncat",
        "stpcpy",
        "printf",
        "fprintf",
        "vprintf",
        "vfprintf",
        "puts",
        "fputs",
        "putchar",
        "perror",
        "syslog",
        "vsyslog",
        "abort",
        "exit",
        "_exit",
        "assert",
        "va_start",
        "va_end",
        "va_copy",
        "qsort",
        "srand",
        "srandom",
    }
)

# Report a call to one of these as a vulnerability only with a traced source and sink.
# The bare presence is a hardening observation; see the class brief in the workflow.
BANNED_FNS = frozenset(
    {
        "gets",
        "strcpy",
        "strcat",
        "sprintf",
        "vsprintf",
        "tmpnam",
        "tempnam",
        "mktemp",
        "mktemps",
        "strtok",
        "alloca",
        "putenv",
        "rand",
        "srand",
        "random",
        "scanf",
        "sscanf",
        "fscanf",
        "atoi",
        "atol",
        "atof",
        "realpath",
        "getwd",
        "getpass",
        "cuserid",
    }
)

# question id -> (title, site kinds that make up its countable population)
QUESTIONS: dict[str, tuple[str, tuple[str, ...]]] = {
    "bounds": (
        "Spatial safety at every write: what bounds each destination, and can the "
        "index or length reach past it?",
        ("write",),
    ),
    "integer": (
        "Width, signedness and wrap at every conversion and at every arithmetic "
        "expression that becomes a size or an index.",
        ("conversion",),
    ),
    "alloc-lifetime": (
        "Allocation and release pairing: single owner, freed once, never used after, "
        "and no copy of a reallocated pointer left behind.",
        ("alloc", "release"),
    ),
    "sizeof-arith": (
        "Every sizeof in a size computation: is it the pointee rather than the "
        "pointer, and can the surrounding arithmetic overflow?",
        ("sizeof",),
    ),
    "nul-termination": (
        "Every string produced or consumed here: is it NUL-terminated on every path, "
        "and is byte length being confused with character length?",
        ("strop",),
    ),
    "return-values": (
        "Every call whose failure matters: is the result checked, and against the "
        "convention that function actually uses?",
        ("unchecked_call",),
    ),
    "caller-contract": (
        "What this unit assumes its caller guarantees about each parameter, and "
        "whether every caller actually guarantees it.",
        ("param",),
    ),
    "banned-api": (
        "Each banned or deprecated API here: name the source of the data and the "
        "size that reaches it, and what validates between them.",
        ("banned",),
    ),
    "initialisation": (
        "Every field of every caller-provided out-parameter, and every local this unit "
        "returns through: is it written on every path before anything reads it? "
        "`malloc` does not zero and neither does the stack.",
        ("outparam",),
    ),
    "macro-contract": (
        "Each function-like macro: what it assumes of its arguments, and whether "
        "that is enforced at every expansion site. A macro is textual, unscoped and "
        "untypechecked, so the invariant is invisible where it is used.",
        ("macro",),
    ),
}

SITE_KINDS = tuple(sorted({k for _, kinds in QUESTIONS.values() for k in kinds}))


class EnumerateError(Exception):
    """Nothing usable to partition. Callers exit non-zero."""


# ------------------------------------------------------------------ parse layer


def _language_for(path: Path, forced: str) -> str:
    if forced in ("c", "cpp"):
        return forced
    return "cpp" if path.suffix.lower() in CPP_EXTS else "c"


def _parsers() -> dict[str, Any]:
    """Import tree-sitter lazily so the pure logic below stays importable without it."""
    try:
        import tree_sitter_c
        import tree_sitter_cpp
        from tree_sitter import Language, Parser
    except ImportError as exc:  # pragma: no cover - exercised by the subprocess test
        raise EnumerateError(
            f"tree-sitter is required to enumerate units ({exc}). Run this script with "
            f"`uv run`, which installs the PEP 723 dependencies in its header."
        ) from exc
    return {
        "c": Parser(Language(tree_sitter_c.language())),
        "cpp": Parser(Language(tree_sitter_cpp.language())),
    }


IDENT_TOKEN = re.compile(rb"\b[A-Za-z_][A-Za-z0-9_]*\b")
# `#define NAME body` with no parameter list. The negative lookahead on `(` is what
# keeps function-like macros out: those cannot be resolved by textual substitution
# without an argument parser, and they are not what breaks the grammar anyway.
OBJECT_MACRO = re.compile(
    rb"^[ \t]*#[ \t]*define[ \t]+([A-Za-z_][A-Za-z0-9_]*)(?!\()[ \t]*([^\n\\]*)$", re.MULTILINE
)
# Bodies safe to substitute textually. A storage class, a qualifier, a calling
# convention or nothing at all — the decorations that sit between the return type and
# the function name and that a parser with no preprocessor cannot know about.
SAFE_MACRO_BODIES = frozenset(
    {
        b"",
        b"static",
        b"extern",
        b"const",
        b"inline",
        b"__inline",
        b"__inline__",
        b"register",
        b"volatile",
        b"restrict",
        b"__restrict",
        b"__restrict__",
        b"unsigned",
        b"signed",
        b"void",
        b"__cdecl",
        b"__stdcall",
        b"__fastcall",
        b"__declspec",
        b"__attribute__",
        b"_Noreturn",
    }
)
C_KEYWORDS = frozenset(
    x.encode()
    for x in (
        "auto break case char const continue default do double else enum extern float "
        "for goto if inline int long register restrict return short signed sizeof static "
        "struct switch typedef union unsigned void volatile while _Bool _Complex "
        "_Noreturn _Static_assert bool class namespace template typename"
    ).split()
)
MAX_MACRO_PASSES = 8


def _error_count(node: Any) -> int:
    if not node.has_error:
        return 0
    total = 1 if node.type == "ERROR" or node.is_missing else 0
    for child in node.children:
        total += _error_count(child)
    return total


def collect_object_macros(sources: list[bytes]) -> dict[bytes, bytes]:
    """Object-like macros whose body is a decoration a parser can safely be given.

    Collected across the whole tree, not per file, because the definition and the use
    are usually in different files: the benchmark corpus defines `quaesk` as `static`
    in one header and uses it on almost every function in every .c file.
    """
    out: dict[bytes, bytes] = {}
    for source in sources:
        for match in OBJECT_MACRO.finditer(source):
            name, body = match.group(1), match.group(2).strip()
            # Never rewrite a keyword. Pre-ANSI headers carry `#define const` under an
            # `#ifndef STDC` guard, and honouring it deleted every `const` in the file —
            # a substitution that cannot help the parse and can only lose information.
            if name in C_KEYWORDS:
                continue
            if body in SAFE_MACRO_BODIES:
                out[name] = body
    return out


def _substitute_outside_directives(source: bytes, macros: dict[bytes, bytes]) -> bytes:
    """Replace macro uses in code, leaving preprocessor lines untouched.

    Rewriting `#  define quaesk static` into `#  define static static` is worse than
    the disease: the first version of this did exactly that, the error count went up,
    and the repair silently backed off and achieved nothing. Line count is preserved,
    which is all that downstream line numbering requires.
    """
    if not macros:
        return source
    pattern = re.compile(
        rb"\b(" + rb"|".join(re.escape(n) for n in sorted(macros, key=len, reverse=True)) + rb")\b"
    )

    def one(match: re.Match[bytes]) -> bytes:
        body = macros[match.group(1)]
        return body if body else b" " * len(match.group(1))

    out = []
    for line in source.split(b"\n"):
        out.append(line if line.lstrip().startswith(b"#") else pattern.sub(one, line))
    return b"\n".join(out)


def _idents_in_errors(node: Any, source: bytes, out: set[bytes]) -> None:
    """Identifiers sitting inside a parse error — the macro suspects."""
    if not node.has_error:
        return
    if node.type == "ERROR":
        for match in IDENT_TOKEN.finditer(source[node.start_byte : node.end_byte]):
            out.add(match.group(0))
    for child in node.children:
        _idents_in_errors(child, source, out)


def parse_tolerant(parser: Any, source: bytes, macros: dict[bytes, bytes]) -> tuple[Any, list[str]]:
    """Parse C, resolving decoration macros that defeat the grammar. Returns (tree, applied).

    `quaesk int foo(...)` is not valid C to a parser that has never seen
    `#define quaesk static`, and tree-sitter's recovery from it is not local: on the
    benchmark corpus it flattened a 628-line function body into top-level statements, so
    the function vanished from the unit list and its lines fell into one 963-line
    file-scope unit. 24 of 27 files were affected, which would have quietly reduced a
    function-aware partition to arbitrary line ranges — a different design from the one
    being measured.

    Self-correcting rather than a hardcoded list: parse, look at which identifiers the
    parser actually choked on, substitute only those that the tree's own `#define`s say
    are decorations, reparse, and keep the result only while the error count is falling.
    Substitution never adds or removes a newline, and only line numbers are used
    downstream, so the site lines the ledger gate diffs against stay exact.
    """
    tree = parser.parse(source)
    if not tree.root_node.has_error or not macros:
        return tree, []

    applied: list[str] = []
    best = tree
    best_errors = _error_count(tree.root_node)
    current = source
    tried: set[bytes] = set()

    for _ in range(MAX_MACRO_PASSES):
        suspects: set[bytes] = set()
        _idents_in_errors(best.root_node, current, suspects)
        suspects = {s for s in suspects if s in macros} - tried
        if not suspects:
            break
        tried |= suspects
        patched = _substitute_outside_directives(current, {n: macros[n] for n in suspects})
        candidate = parser.parse(patched)
        errors = _error_count(candidate.root_node)
        if errors >= best_errors:
            break
        best, best_errors, current = candidate, errors, patched
        applied.extend(sorted(n.decode("ascii", "replace") for n in suspects))
        if not best.root_node.has_error:
            break

    return best, applied


def _callee_name(node: Any) -> str:
    fn = node.child_by_field_name("function")
    while fn is not None and fn.type in ("parenthesized_expression",):
        fn = fn.named_children[0] if fn.named_children else None
    if fn is None:
        return ""
    if fn.type == "identifier":
        return fn.text.decode("utf-8", "replace")
    if fn.type in ("field_expression", "qualified_identifier"):
        last = fn.children[-1] if fn.children else None
        if last is not None and last.type in ("field_identifier", "identifier"):
            return last.text.decode("utf-8", "replace")
    return ""


def _is_write_target(node: Any) -> bool:
    """LHS shapes that write through memory rather than to a named local.

    Field writes (`p->f = x`) are deliberately excluded: they are the invariant
    audit's population, not the bounds question's, and including them would swamp
    the bounds row on any state-machine code.
    """
    return node is not None and node.type in ("subscript_expression", "pointer_expression")


def _collect_sites(node: Any, sites: dict[str, set[int]], in_size_ctx: bool = False) -> None:
    """Walk a subtree, recording the 1-based line of every countable site."""
    kind = node.type
    line = node.start_point[0] + 1

    if kind == "assignment_expression":
        if _is_write_target(node.child_by_field_name("left")):
            sites["write"].add(line)
    elif kind == "update_expression":
        if _is_write_target(node.child_by_field_name("argument")):
            sites["write"].add(line)
    elif kind == "cast_expression":
        sites["conversion"].add(line)
    elif kind == "sizeof_expression":
        sites["sizeof"].add(line)
    elif kind == "binary_expression" and in_size_ctx:
        op = node.child_by_field_name("operator")
        text = op.text.decode("utf-8", "replace") if op is not None else ""
        if text in ("+", "-", "*", "<<"):
            sites["conversion"].add(line)
    elif kind == "call_expression":
        name = _callee_name(node)
        if name in MEM_WRITE_FNS:
            sites["write"].add(line)
        if name in ALLOC_FNS:
            sites["alloc"].add(line)
        if name in RELEASE_FNS:
            sites["release"].add(line)
        if name in STRING_FNS:
            sites["strop"].add(line)
        if name in BANNED_FNS:
            sites["banned"].add(line)
        args = node.child_by_field_name("arguments")
        size_ctx = name in ALLOC_FNS or name in MEM_WRITE_FNS
        for child in node.children:
            _collect_sites(child, sites, in_size_ctx=(size_ctx and child is args))
        return
    elif kind == "expression_statement":
        # A call whose value is dropped on the floor, including the `(void)` idiom.
        inner = node.named_children[0] if node.named_children else None
        if inner is not None and inner.type == "cast_expression":
            inner = inner.child_by_field_name("value")
        if (
            inner is not None
            and inner.type == "call_expression"
            and _callee_name(inner) not in RETURN_IGNORABLE_FNS
        ):
            sites["unchecked_call"].add(line)
    elif kind == "subscript_expression":
        index = node.child_by_field_name("index")
        for child in node.children:
            _collect_sites(child, sites, in_size_ctx=(child is index))
        return

    for child in node.children:
        _collect_sites(child, sites, in_size_ctx=in_size_ctx)


def _empty_sites() -> dict[str, set[int]]:
    return {kind: set() for kind in SITE_KINDS}


def _function_nodes(root: Any) -> list[Any]:
    """Every function_definition, including ones nested in namespaces or classes."""
    found: list[Any] = []

    def walk(node: Any) -> None:
        if node.type == "function_definition":
            found.append(node)
            return  # a nested lambda body stays part of its enclosing function unit
        for child in node.children:
            walk(child)

    walk(root)
    return found


def _function_name(node: Any) -> str:
    declarator = node.child_by_field_name("declarator")
    while declarator is not None:
        if declarator.type in (
            "identifier",
            "field_identifier",
            "qualified_identifier",
            "operator_name",
        ):
            return declarator.text.decode("utf-8", "replace")
        nxt = declarator.child_by_field_name("declarator")
        if nxt is None:
            break
        declarator = nxt
    return "(anonymous)"


def _parameters(node: Any) -> list[str]:
    declarator = node.child_by_field_name("declarator")
    params: list[str] = []

    def find_list(n: Any) -> Any:
        if n is None:
            return None
        if n.type == "parameter_list":
            return n
        for child in n.children:
            got = find_list(child)
            if got is not None:
                return got
        return None

    plist = find_list(declarator)
    if plist is None:
        return params
    for child in plist.named_children:
        if child.type in ("parameter_declaration", "optional_parameter_declaration"):
            text = " ".join(child.text.decode("utf-8", "replace").split())
            if text and text != "void":
                params.append(text)
    return params


# ------------------------------------------------------- splitting (pure logic)


def seam_lines(node: Any, max_lines: int) -> list[int]:
    """Candidate chunk-start lines inside a construct, descending into oversized ones.

    Descending is the whole point and was once missing. A C function body is always a
    `compound_statement`, so a single level of seams over `{ switch (x) { case ...: } }`
    yields exactly one candidate — the `switch` line — and the split then falls back to
    cutting on raw line count, straight through the middle of a case body. That is the
    failure the seam logic exists to prevent, so any child still larger than the cap
    contributes its own seams too.
    """
    out: list[int] = []
    for child in _direct_seams(node):
        out.append(child.start_point[0] + 1)
        if child.end_point[0] - child.start_point[0] + 1 > max_lines:
            out.extend(seam_lines(child, max_lines))
    return sorted(set(out))


def _direct_seams(node: Any) -> list[Any]:
    """One level of syntactic seams inside a construct. [] when there is none."""
    if node is None:
        return []
    if node.type == "compound_statement":
        return [c for c in node.named_children]
    if node.type == "switch_statement":
        body = node.child_by_field_name("body")
        cases = [c for c in body.named_children] if body is not None else []
        return cases or _direct_seams(body)
    if node.type in (
        "for_statement",
        "while_statement",
        "do_statement",
        "if_statement",
        "for_range_loop",
    ):
        body = node.child_by_field_name("body")
        return _direct_seams(body)
    if node.type in ("case_statement", "labeled_statement"):
        return [c for c in node.named_children]
    return []


def split_span(
    start: int, end: int, seam_starts: list[int], max_lines: int
) -> list[tuple[int, int]]:
    """Tile [start, end] into contiguous chunks no larger than max_lines where possible.

    `seam_starts` are candidate first-lines of chunks, in order. Chunks always tile
    the whole span with no gap and no overlap — a line that fell through a gap would
    be a line no agent owns, which is the one thing the location partition must not
    allow. A seam-free span longer than the cap is hard-split on line count, and the
    caller marks it so the ledger can say the cut was arbitrary.
    """
    if end - start + 1 <= max_lines:
        return [(start, end)]

    usable = sorted({s for s in seam_starts if start < s <= end})
    if not usable:
        chunks: list[tuple[int, int]] = []
        cursor = start
        while cursor <= end:
            stop = min(cursor + max_lines - 1, end)
            chunks.append((cursor, stop))
            cursor = stop + 1
        return chunks

    # Walk forward taking the LAST seam that still fits under the cap, not the first
    # seam that is a full cap away. Taking the first one skipped every nearer seam and
    # then hard-split the oversized remainder, so a function whose cases are 12 lines
    # apart under a 20-line cap got cut through the middle of a case anyway.
    boundaries = [start]
    while end - boundaries[-1] + 1 > max_lines:
        ahead = [s for s in usable if s > boundaries[-1]]
        if not ahead:
            break
        within = [s for s in ahead if s - boundaries[-1] <= max_lines]
        # No seam within reach: cut at the nearest one and let the hard-split pass
        # below deal with the oversized chunk it leaves behind.
        boundaries.append(within[-1] if within else ahead[0])
    chunks = []
    for i, first in enumerate(boundaries):
        last = (boundaries[i + 1] - 1) if i + 1 < len(boundaries) else end
        if last < first:
            continue
        chunks.append((first, last))

    # A single seam-delimited chunk can still exceed the cap (one huge case body).
    # Hard-split those rather than shipping a unit the cap was meant to prevent.
    final: list[tuple[int, int]] = []
    for first, last in chunks:
        if last - first + 1 <= max_lines:
            final.append((first, last))
            continue
        cursor = first
        while cursor <= last:
            stop = min(cursor + max_lines - 1, last)
            final.append((cursor, stop))
            cursor = stop + 1
    return final


def contiguous_ranges(lines: list[int]) -> list[list[int]]:
    """Collapse a sorted line list into [start, end] pairs."""
    out: list[list[int]] = []
    for line in lines:
        if out and line == out[-1][1] + 1:
            out[-1][1] = line
        else:
            out.append([line, line])
    return out


def out_parameter_lines(params: list[str], signature_line: int) -> list[int]:
    """The signature line, when this unit writes through a caller-supplied pointer.

    Derived from the unit's SHAPE, not from sites found in its body, and that is the
    whole point. A bug of omission has no site: `sgl_record_load` in the benchmark
    corpus fails to zero one field of the struct its caller passes in, and because the
    parser counts no write, no cast and no allocation there, the unit was asked exactly
    one question and answered it correctly. The gate then reported 105/105 and 100%
    coverage over a unit whose only bug it had never asked about. A site-driven question
    allocator cannot see something that is missing; this one asks anyway.
    """
    for text in params:
        stripped = text.strip()
        if "*" not in stripped:
            continue
        # `const char *in` is an input. Anything else pointer-shaped can be written through.
        before_star = stripped.split("*", 1)[0]
        if "const" in before_star:
            continue
        return [signature_line]
    return []


def required_questions(sites: dict[str, list[int]], is_function: bool) -> list[str]:
    """Which ledger rows this unit owes.

    A question with an empty population is not asked: a unit with no allocations owes
    no alloc-lifetime row, and demanding one would fill the ledger with rows whose
    only honest answer is "nothing here". `caller-contract` is the exception — every
    function has a contract with its callers even when it takes no parameters.
    """
    out = []
    for qid, (_, kinds) in QUESTIONS.items():
        if qid == "caller-contract":
            if is_function:
                out.append(qid)
            continue
        if any(sites.get(kind) for kind in kinds):
            out.append(qid)
    return out


def pack_assignments(units: list[dict[str, Any]], agents: int) -> list[dict[str, Any]]:
    """Split units into `agents` contiguous buckets balanced on line count.

    Contiguous, not round-robin: neighbouring units share callers, types and buffers,
    so a bucket that is a run of one file reads as code rather than as a sample. The
    measured `fanout` arm partitioned exactly this way.
    """
    if agents < 1:
        agents = 1
    total = sum(u["lines"] for u in units) or len(units)
    target = total / agents
    buckets: list[list[dict[str, Any]]] = [[]]
    running = 0.0
    for i, unit in enumerate(units):
        remaining_units = len(units) - i
        remaining_buckets = agents - len(buckets) + 1
        must_close = running > 0 and running >= target and remaining_buckets > 1
        # Never strand a bucket with nothing in it: if every remaining unit is needed
        # to give the remaining buckets one each, close now.
        forced = remaining_units <= remaining_buckets - 1 and running > 0
        if (must_close or forced) and len(buckets) < agents:
            buckets.append([])
            running = 0.0
        buckets[-1].append(unit)
        running += unit["lines"]

    # A trailing runt is a whole agent spent on a handful of lines while its neighbour
    # carries a full share. Fold anything under a quarter of target back in.
    if len(buckets) > 1 and sum(u["lines"] for u in buckets[-1]) < target / 4:
        buckets[-2].extend(buckets.pop())

    out = []
    for i, members in enumerate(buckets):
        if not members:
            continue
        out.append(
            {
                "id": f"unit-{i + 1:02d}",
                "unit_ids": [u["id"] for u in members],
                "files": sorted({u["file"] for u in members}),
                "total_lines": sum(u["lines"] for u in members),
                "unit_count": len(members),
            }
        )
    return out


def default_agent_count(total_lines: int, lines_per_agent: int, lo: int, hi: int) -> int:
    if total_lines <= 0:
        return lo
    return max(lo, min(hi, math.ceil(total_lines / lines_per_agent)))


# ------------------------------------------------------------------ discovery


def discover_sources(root: Path, exclude: list[str]) -> list[Path]:
    found = []
    for path in sorted(root.rglob("*")):
        if not path.is_file() or path.suffix.lower() not in SOURCE_EXTS:
            continue
        rel = path.relative_to(root)
        if any(part in SKIP_DIRS for part in rel.parts):
            continue
        if any(rel.match(pattern) or pattern in str(rel) for pattern in exclude):
            continue
        found.append(path)
    return found


def units_for_file(rel: str, source: bytes, tree: Any, max_lines: int) -> list[dict[str, Any]]:
    """Function units (split at seams when oversized) plus one file-scope unit."""
    # A trailing newline terminates the last line; it does not start another one.
    # Counting one extra gave every file-scope unit ownership of a line that does not
    # exist, which is harmless for coverage and quietly wrong in the line totals.
    total_lines = source.count(b"\n") + (0 if not source or source.endswith(b"\n") else 1)
    out: list[dict[str, Any]] = []
    covered: set[int] = set()

    for node in _function_nodes(tree.root_node):
        start = node.start_point[0] + 1
        end = node.end_point[0] + 1
        covered.update(range(start, end + 1))
        name = _function_name(node)
        params = _parameters(node)

        body = node.child_by_field_name("body")
        seams = seam_lines(body, max_lines)
        seam_set = set(seams)
        chunks = split_span(start, end, seams, max_lines)

        for idx, (cstart, cend) in enumerate(chunks):
            # Per chunk, not per function. "This function had some seam somewhere" said
            # `seam` over four cuts of which three were raw line-count cuts, so the
            # ledger could not tell an arbitrary cut from a syntactic one. The first
            # chunk starts at the signature, which is a real boundary by construction.
            at_seam = idx == 0 or cstart in seam_set
            sites = _empty_sites()
            _collect_sites(node, sites)
            scoped = {
                kind: sorted(line for line in lines if cstart <= line <= cend)
                for kind, lines in sites.items()
            }
            # The parameter *site* is the signature line, so only the first chunk owes
            # a counted row for it. Every chunk still gets the parameter list: a chunk
            # cut out of the middle of a function reasons about the same arguments.
            scoped["param"] = sorted({start}) if (idx == 0 and params) else []
            scoped["outparam"] = out_parameter_lines(params, start) if idx == 0 else []
            label = name if len(chunks) == 1 else f"{name} [part {idx + 1}/{len(chunks)}]"
            out.append(
                {
                    "id": f"{rel}:{cstart}-{cend}",
                    "file": rel,
                    "name": label,
                    "function": name,
                    "kind": "function",
                    "start_line": cstart,
                    "end_line": cend,
                    "lines": cend - cstart + 1,
                    "split": "none" if len(chunks) == 1 else ("seam" if at_seam else "hard"),
                    "parameters": params,
                    "sites": scoped,
                    "required_questions": required_questions(scoped, is_function=True),
                }
            )

    outside = [n for n in range(1, total_lines + 1) if n not in covered]
    if outside:
        sites = _empty_sites()
        for child in tree.root_node.children:
            cstart = child.start_point[0] + 1
            if child.type == "function_definition":
                continue
            if child.type in ("preproc_function_def",):
                sites["macro"].add(cstart)
                continue
            _collect_sites(child, sites)

        # File scope must obey the cap too. On real C it is not a thin margin of
        # includes: an attribute macro (`int ZEXPORT foo(...)`) defeats tree-sitter's
        # error recovery, which then flattens whole function bodies into top-level
        # statements, and every one of those lines lands here. Measured on the
        # measured corpus, one file-scope unit was 963 lines holding a 628-line
        # function the parser never recognised — precisely the saturation the cap
        # exists to prevent, arriving through the one unit that was exempt from it.
        top_seams = [c.start_point[0] + 1 for c in tree.root_node.children]
        for chunk_index, (rstart, rend) in enumerate(_split_ranges(outside, top_seams, max_lines)):
            span = [n for n in outside if rstart <= n <= rend]
            if not span:
                continue
            scoped = {
                kind: sorted(line for line in lines if rstart <= line <= rend)
                for kind, lines in sites.items()
            }
            scoped["param"] = []
            scoped["outparam"] = []
            out.append(
                {
                    "id": f"{rel}:file-scope-{chunk_index + 1}",
                    "file": rel,
                    "name": "(file-scope)"
                    if chunk_index == 0
                    else f"(file-scope {chunk_index + 1})",
                    "function": "(file-level)",
                    "kind": "file-scope",
                    "start_line": rstart,
                    "end_line": rend,
                    # The gaps between the functions, not the span that encloses them.
                    # Without the explicit list an agent reads "1-812" and either
                    # re-reviews every function or gives up.
                    "ranges": contiguous_ranges(span),
                    "lines": len(span),
                    "split": "none",
                    "parameters": [],
                    "sites": scoped,
                    "required_questions": required_questions(scoped, is_function=False),
                }
            )

    out.sort(key=lambda u: (u["file"], u["start_line"]))
    return out


def _split_ranges(lines: list[int], seams: list[int], max_lines: int) -> list[tuple[int, int]]:
    """Cap-respecting chunks over a discontiguous set of owned lines.

    Chunks are keyed on *owned* line count, not on the span they cover, so the gaps
    where the functions sit do not count against the cap, and every owned line lands
    in exactly one chunk.

    Ranges are ACCUMULATED rather than emitted one per range. File scope between two
    functions is usually a single blank line, so emitting a unit per contiguous range
    turned one file into 199 units of one line each — a ledger row apiece, and an
    assignment list that reads as noise.
    """
    out: list[tuple[int, int]] = []
    pending: list[tuple[int, int]] = []
    owned = 0

    def flush() -> None:
        nonlocal pending, owned
        if pending:
            out.append((pending[0][0], pending[-1][1]))
            pending = []
            owned = 0

    for rstart, rend in contiguous_ranges(lines):
        size = rend - rstart + 1
        if size > max_lines:
            flush()
            out.extend(split_span(rstart, rend, seams, max_lines))
            continue
        if owned + size > max_lines:
            flush()
        pending.append((rstart, rend))
        owned += size
    flush()
    return out


# ----------------------------------------------------------------------- main


def build(
    root: Path,
    exclude: list[str],
    language: str,
    max_lines: int,
    agents: int | None,
    lines_per_agent: int,
    agent_min: int,
    agent_max: int,
) -> dict[str, Any]:
    if not root.is_dir():
        raise EnumerateError(f"scope root is not a directory: {root}")
    sources = discover_sources(root, exclude)
    if not sources:
        raise EnumerateError(
            f"no C/C++ source files under {root}. Nothing to partition — check the "
            f"finding scope root and --exclude."
        )

    parsers = _parsers()
    units: list[dict[str, Any]] = []
    unreadable: list[str] = []
    degraded: list[str] = []
    repaired: dict[str, list[str]] = {}

    # Read every file up front so the macro table is built from the whole tree: the
    # `#define` that makes a file parseable is usually in a different file.
    texts: list[tuple[Path, str, bytes]] = []
    for path in sources:
        rel = str(path.relative_to(root))
        try:
            texts.append((path, rel, path.read_bytes()))
        except OSError as exc:
            unreadable.append(f"{rel}: {exc}")
    macros = collect_object_macros([src for _, _, src in texts])

    for path, rel, source in texts:
        parser = parsers[_language_for(path, language)]
        tree, blanked = parse_tolerant(parser, source, macros)
        if blanked:
            repaired[rel] = blanked
        if tree.root_node.has_error:
            degraded.append(rel)
        units.extend(units_for_file(rel, source, tree, max_lines))

    if not units:
        raise EnumerateError(
            f"parsed {len(sources)} file(s) under {root} and produced no units. That is a "
            f"parser failure, not an empty codebase; do not treat it as a clean review."
        )

    units.sort(key=lambda u: (u["file"], u["start_line"]))
    total_lines = sum(u["lines"] for u in units)
    n_agents = agents or default_agent_count(total_lines, lines_per_agent, agent_min, agent_max)
    assignments = pack_assignments(units, n_agents)

    checks_required = sum(len(u["required_questions"]) for u in units)
    sites_total = {kind: sum(len(u["sites"].get(kind, [])) for u in units) for kind in SITE_KINDS}

    return {
        "root": str(root),
        "max_unit_lines": max_lines,
        "files": [str(p.relative_to(root)) for p in sources],
        "unreadable": unreadable,
        "parse_degraded": degraded,
        "macros_resolved": repaired,
        "units": units,
        "assignments": assignments,
        "questions": {qid: text for qid, (text, _) in QUESTIONS.items()},
        "totals": {
            "files": len(sources),
            "units": len(units),
            "lines": total_lines,
            "oversized_split": sum(1 for u in units if u["split"] != "none"),
            "hard_split": sum(1 for u in units if u["split"] == "hard"),
            "parse_degraded_files": len(degraded),
            "macro_repaired_files": len(repaired),
            "checks_required": checks_required,
            "sites": sites_total,
        },
    }


def write_outputs(doc: dict[str, Any], out_dir: Path) -> dict[str, Any]:
    out_dir.mkdir(parents=True, exist_ok=True)
    (out_dir / "units.json").write_text(json.dumps(doc, indent=2), encoding="utf-8")

    by_id = {u["id"]: u for u in doc["units"]}
    assign_dir = out_dir / "assignments"
    assign_dir.mkdir(parents=True, exist_ok=True)
    for assignment in doc["assignments"]:
        payload = {
            "assignment_id": assignment["id"],
            "questions": doc["questions"],
            "max_unit_lines": doc["max_unit_lines"],
            "units": [by_id[uid] for uid in assignment["unit_ids"]],
        }
        (assign_dir / f"{assignment['id']}.json").write_text(
            json.dumps(payload, indent=2), encoding="utf-8"
        )

    return {
        "units_json": str(out_dir / "units.json"),
        "assignment_dir": str(assign_dir),
        "assignments": [
            {
                "id": a["id"],
                "path": str(assign_dir / f"{a['id']}.json"),
                "unit_count": a["unit_count"],
                "total_lines": a["total_lines"],
                "files": a["files"][:8],
            }
            for a in doc["assignments"]
        ],
        "totals": doc["totals"],
        "unreadable": doc["unreadable"],
        "parse_degraded": doc["parse_degraded"],
        "macros_resolved": sorted({m for v in doc["macros_resolved"].values() for m in v}),
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", required=True, type=Path, help="finding scope root to partition")
    parser.add_argument("--out-dir", required=True, type=Path, help="run directory for units.json")
    parser.add_argument("--exclude", action="append", default=[], help="glob or substring to skip")
    parser.add_argument("--language", choices=["auto", "c", "cpp"], default="auto")
    parser.add_argument("--max-unit-lines", type=int, default=150)
    parser.add_argument("--agents", type=int, default=None, help="override the derived agent count")
    parser.add_argument("--lines-per-agent", type=int, default=800)
    parser.add_argument("--agent-min", type=int, default=4)
    parser.add_argument("--agent-max", type=int, default=14)
    ns = parser.parse_args(argv)

    if ns.max_unit_lines < 20:
        print("enumerate_units: --max-unit-lines below 20 is not a review unit", file=sys.stderr)
        return 2
    try:
        doc = build(
            root=ns.root,
            exclude=ns.exclude,
            language=ns.language,
            max_lines=ns.max_unit_lines,
            agents=ns.agents,
            lines_per_agent=ns.lines_per_agent,
            agent_min=ns.agent_min,
            agent_max=ns.agent_max,
        )
    except EnumerateError as exc:
        print(f"enumerate_units: {exc}", file=sys.stderr)
        return 2

    summary = write_outputs(doc, ns.out_dir)
    print(json.dumps(summary, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
