#!/usr/bin/env python3
# /// script
# requires-python = ">=3.11"
# # Exact pins, not ranges: the coverage gate's site populations are counted by these
# # grammars, and a grammar release that renames a node type silently shrinks the
# # denominator — the gate recomputes through the same parser, so it agrees with itself.
# # Dependabot has no PEP 723 ecosystem (.github/dependabot.yml); bump all four headers
# # (three scripts + test_enumerate_units.py's ATTACH_SCRIPT) together, by hand.
# dependencies = ["tree-sitter==0.26.0", "tree-sitter-c==0.24.2", "tree-sitter-cpp==0.23.4"]
# ///
"""Enumerate review units and their countable site populations for c-review.

This is the spine of the location partition: every line is owned by exactly one agent, and
that ownership is generated here from a parse, never from an agent's own account of what it
read. Bug-class sweeps layer on top, because the two axes find different bugs.

Two constraints are load-bearing:

1. **Units are capped at `--max-unit-lines`.** One oversized unit saturates the reader — the
   exact problem the location partition exists to solve — so a function over the cap is split
   at syntactic seams (switch cases, loop and branch bodies).

2. **Every line is owned.** Chunks tile their function's line range contiguously and every
   file contributes a `file-scope` unit for the regions outside any function. Reachability
   weighting is for depth, never for coverage: cold error-handling paths hold real bugs that
   an attacker-reachability prior would deprioritise.

The site populations are what make a `clean` ledger verdict falsifiable downstream:
`check_ledger.py` requires a clean row to account for every site line counted here.
An agent cannot clear "bounds" on a unit with twelve write sites by saying it looked.

Exits non-zero when it finds no source files or no units. A partitioner that
partitions nothing must fail loudly rather than certify an empty review.
"""

from __future__ import annotations

import argparse
import heapq
import json
import math
import re
import sys
from pathlib import Path
from typing import Any

C_EXTS = frozenset({".c", ".h"})
# A missing extension is a file enumerated by nobody, at exit 0 and with no warning, so the
# less obvious spellings are here explicitly: `.inl` is the usual name for a C++
# inline-implementation header, and `.ixx`/`.cppm` are module interface units.
CPP_EXTS = frozenset(
    {
        ".cc",
        ".cpp",
        ".cxx",
        ".c++",
        ".hpp",
        ".hh",
        ".hxx",
        ".h++",
        ".ipp",
        ".tcc",
        ".inl",
        ".ixx",
        ".cppm",
    }
)
SOURCE_EXTS = C_EXTS | CPP_EXTS

# Directories that hold build output or vendored VCS metadata rather than code under
# review. Deliberately short: skipping `tests/` or `third_party/` by default would be a
# silent coverage hole, and the caller can pass --exclude for those.
SKIP_DIRS = frozenset({".git", ".svn", ".hg", "node_modules", "__pycache__"})

# Below this a "unit" is not a thing a reviewer reads. Enforced on the CLI flag AND on the
# value `sites_by_id` reads back out of units.json, which is the same number arriving from a
# file every worker agent can write.
MIN_UNIT_LINES = 20

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
# destination, printf's count is noise, and the second group returns `void` so there is
# nothing to check at all. Counting these as unchecked calls would pad the return-values
# population with lines that cannot be bugs, and the ledger gate makes an agent account for
# every line in a population, so the padding is not free: on the measured corpus `free`
# alone was 27 of 291 `unchecked_call` sites. A C++ member call (`v.clear()`,
# `v.push_back(x)`) is the same waste and is NOT fixable by name — the return type is not in
# the parse — so a C++ unit's return-values population is still padded.
RETURN_IGNORABLE_FNS = frozenset(
    {
        "free",
        "rewind",
        "clearerr",
        "setbuf",
        "longjmp",
        "siglongjmp",
        "pthread_exit",
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
CAST_FNS = frozenset({"static_cast", "reinterpret_cast", "const_cast", "dynamic_cast"})

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
    # `.C` (uppercase) is conventionally C++. Lowercasing first sends it to the C grammar,
    # which degrades on every class, template and reference in the file.
    if path.suffix == ".C":
        return "cpp"
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
    """Iterative: a generated expression a few thousand terms deep overflows the stack."""
    total = 0
    stack = [node]
    while stack:
        current = stack.pop()
        if not current.has_error:
            continue
        if current.type == "ERROR" or current.is_missing:
            total += 1
        stack.extend(current.children)
    return total


def collect_object_macros(sources: list[bytes]) -> dict[bytes, bytes]:
    """Object-like macros whose body is a decoration a parser can safely be given.

    Collected across the whole tree, not per file: a `#define` and its uses are commonly
    split across a header and its consumers.
    """
    out: dict[bytes, bytes] = {}
    for source in sources:
        for match in OBJECT_MACRO.finditer(source):
            name, body = match.group(1), match.group(2).strip()
            # Never rewrite a keyword. Pre-ANSI headers carry `#define const` under an
            # `#ifndef STDC` guard, and honouring it deletes every `const` in the file — a
            # substitution that cannot help the parse and can only lose information.
            if name in C_KEYWORDS:
                continue
            if body in SAFE_MACRO_BODIES:
                out[name] = body
    return out


def _substitute_outside_directives(source: bytes, macros: dict[bytes, bytes]) -> bytes:
    """Replace macro uses in code, leaving preprocessor lines untouched.

    Substituting inside a `#define` rewrites the macro's own definition — `#define X
    static` becomes `#define static static` — which raises the parser error count instead
    of lowering it. Line count is preserved, which is all downstream numbering requires.
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
    """Identifiers sitting inside a parse error — the macro suspects. Iterative."""
    stack = [node]
    while stack:
        current = stack.pop()
        if not current.has_error:
            continue
        if current.type == "ERROR":
            for match in IDENT_TOKEN.finditer(source[current.start_byte : current.end_byte]):
                out.add(match.group(0))
        stack.extend(current.children)


def parse_tolerant(parser: Any, source: bytes, macros: dict[bytes, bytes]) -> tuple[Any, list[str]]:
    """Parse C, resolving decoration macros that defeat the grammar. Returns (tree, applied).

    A decoration macro (`DECOR int foo(...)`) is not valid C to a parser that has never
    seen its `#define`, and tree-sitter's recovery from it is not local: it can flatten a
    whole function body into top-level statements, so the function drops out of the unit
    list and its lines fall into the file-scope unit. That silently reduces a
    function-aware partition to arbitrary line ranges.

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
    if fn.type == "template_function":
        # `static_cast<int>(x)` and any `f<T>(x)`: the callee is under the template head.
        fn = fn.child_by_field_name("name") or (fn.named_children[0] if fn.named_children else None)
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


def _collect_sites(
    node: Any,
    sites: dict[str, set[int]],
    in_size_ctx: bool = False,
    skip_functions: bool = False,
) -> None:
    """Walk a subtree, recording the 1-based line of every countable site.

    `skip_functions` prunes nested `function_definition` subtrees. That is how the
    file-scope unit avoids being charged for lines another unit owns: a function inside
    `#ifdef`, `extern "C" { }` or a C++ `namespace` is not a direct child of the root, so
    filtering the root's own children leaves it in, and its writes and allocations land on
    a unit whose `ranges` do not contain them.

    Iterative, with the size context carried on the stack: recursion dies with a
    `RecursionError` on a generated table (`int t = 1 + 1 + …;`, a few thousand terms), which
    the caller can only report as a file nobody reviews.
    """
    stack: list[tuple[Any, bool]] = [(node, in_size_ctx)]
    while stack:
        current, size_ctx = stack.pop()
        kind = current.type
        line = current.start_point[0] + 1

        if kind == "function_definition" and skip_functions:
            continue
        if kind == "preproc_function_def":
            # Matched here rather than among the root's children, because a header's macros
            # sit inside its include guard — one `preproc_ifdef` — and a scan of top-level
            # children alone never asks `macro-contract` about any of them. The replacement
            # list is a single unparsed token, so there is nothing below to descend into.
            sites["macro"].add(line)
            continue
        if kind == "assignment_expression":
            if _is_write_target(current.child_by_field_name("left")):
                sites["write"].add(line)
        elif kind == "update_expression":
            if _is_write_target(current.child_by_field_name("argument")):
                sites["write"].add(line)
        elif kind == "cast_expression":
            # `(void)x;` is a cast to nothing — the idiom for discarding a value or marking
            # a parameter unused. Counting it puts every such line in the `integer`
            # population, and set equality then makes the reviewer account for lines that
            # cannot hold a conversion bug.
            target = current.child_by_field_name("type")
            if target is None or target.text.decode("utf-8", "replace").strip() != "void":
                sites["conversion"].add(line)
        elif kind == "new_expression":
            # C++ allocation and release are their own node types, not calls, so without
            # these two an idiomatic C++ tree counts no alloc/release site anywhere and is
            # never asked the use-after-free or double-free question at all.
            sites["alloc"].add(line)
        elif kind == "delete_expression":
            sites["release"].add(line)
        elif kind == "sizeof_expression":
            sites["sizeof"].add(line)
        elif kind == "binary_expression" and size_ctx:
            op = current.child_by_field_name("operator")
            text = op.text.decode("utf-8", "replace") if op is not None else ""
            if text in ("+", "-", "*", "<<"):
                sites["conversion"].add(line)
        elif kind == "call_expression":
            name = _callee_name(current)
            callee = current.child_by_field_name("function")
            # The C++ spellings of a cast. `static_cast<T>(x)` parses as a call through a
            # `template_function`, and the functional cast `int(n)` as a call whose callee
            # IS a type — neither is a `cast_expression`, so neither counts as a conversion
            # without being matched here.
            if name in CAST_FNS or (
                callee is not None and callee.type in ("primitive_type", "sized_type_specifier")
            ):
                sites["conversion"].add(line)
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
            args = current.child_by_field_name("arguments")
            inner_ctx = name in ALLOC_FNS or name in MEM_WRITE_FNS
            for child in current.children:
                stack.append((child, inner_ctx and child is args))
            continue
        elif kind == "expression_statement":
            # A call whose value is dropped on the floor, including the `(void)` idiom.
            inner = current.named_children[0] if current.named_children else None
            if inner is not None and inner.type == "cast_expression":
                inner = inner.child_by_field_name("value")
            if (
                inner is not None
                and inner.type == "call_expression"
                and _callee_name(inner) not in RETURN_IGNORABLE_FNS
            ):
                sites["unchecked_call"].add(line)
        elif kind == "subscript_expression":
            index = current.child_by_field_name("index")
            for child in current.children:
                stack.append((child, child is index))
            continue

        for child in current.children:
            stack.append((child, size_ctx))


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


def _declared_name(node: Any) -> str:
    """The identifier a declarator declares. "" for an unnamed parameter."""
    if node is None:
        return ""
    if node.type == "identifier":
        return node.text.decode("utf-8", "replace")
    for child in node.children:
        got = _declared_name(child)
        if got:
            return got
    return ""


def _parameters(node: Any) -> list[tuple[str, str]]:
    """(source text, declared name) per parameter. The name is "" when there is none.

    The name is read off the `declarator` field rather than the whole parameter, so a
    namespaced or templated TYPE cannot be mistaken for the parameter's own identifier.
    """
    declarator = node.child_by_field_name("declarator")
    params: list[tuple[str, str]] = []

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
                params.append((text, _declared_name(child.child_by_field_name("declarator"))))
    if params:
        return params

    # K&R: `int kr(a, b) int a; char *b; { … }`. The parameter list holds bare identifiers
    # and the TYPES are `declaration` siblings between `)` and `{`. Without this the
    # parameter list is empty, so neither `caller-contract` nor `initialisation` is ever
    # asked about a written-through out-parameter and the gate reports the unit 100% clean.
    types: dict[str, str] = {}
    for decl in node.children:
        if decl.type != "declaration":
            continue
        text = " ".join(decl.text.decode("utf-8", "replace").split())
        for sub in decl.named_children:
            name = _declared_name(sub)
            if name:
                types[name] = text
    for child in plist.named_children:
        if child.type == "identifier":
            name = child.text.decode("utf-8", "replace")
            params.append((types.get(name, name), name))
    return params


def _reference_lines(node: Any, names: set[str], out: set[int]) -> None:
    """Every line inside `node` where one of `names` is referenced. Iterative on purpose.

    A recursive walk over a generated expression (a table of ~4000 `+` terms) exhausts the
    Python stack, and a `RecursionError` here is a file nobody reviews.
    """
    if node is None or not names:
        return
    stack = [node]
    while stack:
        current = stack.pop()
        if current.type == "identifier" and current.text.decode("utf-8", "replace") in names:
            out.add(current.start_point[0] + 1)
        stack.extend(current.children)


def _parameter_scopes(node: Any) -> list[Any]:
    """Where a parameter may be USED: the body, plus a C++ member-initializer list.

    `Buf(char *p, unsigned n) : p_(p), n_(n) {}` stores a caller-supplied pointer and
    length into members and has an empty body, so a body-only scan counts no reference, the
    unit owes no question at all, and a constructor doing exactly what `caller-contract`
    exists to ask about is invisible to the coverage gate.
    """
    body = node.child_by_field_name("body")
    scopes = [c for c in node.children if c.type == "field_initializer_list"]
    return ([body] if body is not None else []) + scopes


# ------------------------------------------------------- splitting (pure logic)


def seam_lines(node: Any, max_lines: int) -> tuple[list[int], list[int]]:
    """(every candidate chunk-start line, the STRONG ones), descending into oversized children.

    Descending is the whole point: a C function body is always a `compound_statement`, so a
    single level of seams over `{ switch (x) { case ...: } }` yields exactly one candidate —
    the `switch` line — and the split then falls back to cutting on raw line count, straight
    through the middle of a case body. That is the failure the seam logic exists to prevent,
    so any child still larger than the cap contributes its own seams too.

    A STRONG seam is an arm boundary — a `case`/`default` label, or the `} else {` of an
    if/else chain. Every ordinary statement is also a candidate, and because `split_span`
    takes the LAST candidate that fits, on ordinary code the cap boundary always wins: with
    one undifferentiated list the `} else {` seam is never selected on any arm holding more
    than one statement, and every chunk of a 250-arm dispatcher starts at an exact multiple
    of the cap while `split: seam` claims a structural cut. The two lists let `split_span`
    prefer an arm boundary that fits over a mid-arm statement that fits.
    """
    out: list[int] = []
    strong: list[int] = []
    for child, is_strong in _direct_seams(node):
        line = child.start_point[0] + 1
        out.append(line)
        if is_strong:
            strong.append(line)
        if child.end_point[0] - child.start_point[0] + 1 > max_lines:
            deep_all, deep_strong = seam_lines(child, max_lines)
            out.extend(deep_all)
            strong.extend(deep_strong)
    return sorted(set(out)), sorted(set(strong))


def _direct_seams(node: Any) -> list[tuple[Any, bool]]:
    """One level of syntactic seams inside a construct, each paired with `is_strong`.

    [] when there is none. `is_strong` marks an arm boundary — a switch case or an `else`
    clause — which is a cut a reader needs the partition to make; an ordinary statement is
    merely a cut it is allowed to make.
    """
    if node is None:
        return []
    if node.type == "compound_statement":
        return [(c, False) for c in node.named_children]
    if node.type == "switch_statement":
        body = node.child_by_field_name("body")
        cases = [(c, True) for c in body.named_children] if body is not None else []
        return cases or _direct_seams(body)
    if node.type == "if_statement":
        # tree-sitter names these `consequence`/`alternative`, not `body`, so asking for
        # `body` returns None and an `if` contributes no seam at all: a function with a
        # 60-line then-branch and a 60-line else-branch is cut on raw line count straight
        # through both. The `else` arm arrives wrapped in an `else_clause`.
        #
        # The `else_clause` NODE is a seam in its own right, not only its contents: without
        # it `} else {` is not a candidate chunk start and one unit straddles both arms,
        # which is the single cut a reader most needs the partition not to make.
        #
        # The whole `else if` chain is flattened HERE, iteratively, and `else_clause` is
        # deliberately not a case below. Recursing into the arm instead is quadratic in the
        # chain length and makes `seam_lines` exponential in it — each `else_clause` spans
        # the rest of the chain, so it is always over the cap, `seam_lines` descends into it
        # and re-expands the remainder: T(n) = ΣT(n−i). 45 arms take 0.05 s, 55 take 7.3 s,
        # 60 do not finish in 300 s, and a 1200-arm chain raises RecursionError — in the
        # detect phase and again in the gate, which re-runs this parse. Flattening once is
        # linear and yields the same seam set.
        out: list[tuple[Any, bool]] = []
        current: Any = node
        while current is not None and current.type == "if_statement":
            out += _direct_seams(current.child_by_field_name("consequence"))
            alternative = current.child_by_field_name("alternative")
            if alternative is None:
                return out
            out.append((alternative, True))
            current = alternative.named_children[-1] if alternative.named_children else None
        return out + _direct_seams(current)
    if node.type == "try_statement":
        # The same shape as `else_clause`, one node type over. Unhandled, a 62-line
        # `try { … } catch (…) { … }` at a 20-line cap produces a 2-line runt and then cuts
        # straight through `} catch`, hard-splitting both arms. A `catch_clause` is an ARM
        # boundary — the strongest cut a reader needs the partition to make — so it is a
        # seam in its own right, not only its contents.
        out = _direct_seams(node.child_by_field_name("body"))
        for child in node.named_children:
            if child.type == "catch_clause":
                # The clause AND its contents, exactly as the `else` arm above: without its
                # contents an arm longer than the cap hard-splits on line count.
                out.append((child, True))
                out += _direct_seams(child.child_by_field_name("body"))
        return out
    if node.type in ("for_statement", "while_statement", "do_statement", "for_range_loop"):
        return _direct_seams(node.child_by_field_name("body"))
    if node.type in ("case_statement", "labeled_statement"):
        return [(c, False) for c in node.named_children]
    return []


def split_span(
    start: int,
    end: int,
    seam_starts: list[int],
    max_lines: int,
    strong_starts: list[int] | None = None,
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

    # Walk forward taking the LAST seam that still fits under the cap, not the first seam
    # that is a full cap away: taking the first skips every nearer seam and then hard-splits
    # the oversized remainder, so a function whose cases are 12 lines apart under a 20-line
    # cap gets cut through the middle of a case anyway.
    #
    # An ARM boundary that fits beats an ordinary statement that fits, even a later one —
    # see `seam_lines` for why the strong list exists at all.
    strong = {s for s in (strong_starts or []) if start < s <= end}
    boundaries = [start]
    while end - boundaries[-1] + 1 > max_lines:
        ahead = [s for s in usable if s > boundaries[-1]]
        if not ahead:
            break
        within = [s for s in ahead if s - boundaries[-1] <= max_lines]
        strong_within = [s for s in within if s in strong]
        # No seam within reach: cut at the nearest one and let the hard-split pass
        # below deal with the oversized chunk it leaves behind.
        if within:
            boundaries.append((strong_within or within)[-1])
        else:
            boundaries.append(ahead[0])
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


# `const` as a WORD. `"const" in prefix` is a substring test, so `int constants[16]` and
# `unsigned char const_table[256]` read as const-qualified and are skipped — a false
# negative on exactly the array parameters the question is about.
CONST_WORD = re.compile(r"\bconst\b")
# `int (*cb)(void)`, `void (*h)(int)`: a parenthesised pointer declarator FOLLOWED BY a
# parameter list. A looser `"(" in s and "*" in s` test also eats `int (*out)[10]`, which is
# a pointer to an array and is written through. Brackets are excluded from the inner run so
# `int (*tab[4])(void)` — an ARRAY of function pointers, which is written through — is not
# mistaken for one function pointer.
FUNCTION_POINTER = re.compile(r"\(\s*\*+[^()\[\]]*\)\s*\(")
# A callable spelled as a template argument: `std::function<void(int)>`, `Fn<int(char*)>`.
# Template arguments are erased below before any sigil is looked for, so this has to be
# recognised on the un-erased text or every `std::function<…> &cb` reads as an out-param.
CALLABLE_TEMPLATE = re.compile(r"<[^<>]*\([^()]*\)[^<>]*>")
# Everything that is NOT part of the declarator, and that `is_out_parameter` must not read
# as if it were. See `_declarator_text`.
TEMPLATE_ARGS = re.compile(r"<[^<>]*>")
ATTRIBUTE = re.compile(r"__attribute__\s*\(\(.*?\)\)|\[\[[^\]]*\]\]", re.DOTALL)
LITERAL = re.compile(r"\"(?:[^\"\\]|\\.)*\"|'(?:[^'\\]|\\.)*'")
DEFAULT_ARG = re.compile(r"(?<![=!<>])=(?!=)")


def _declarator_text(text: str) -> str:
    """The parameter with everything that is not its declarator removed.

    `is_out_parameter` reasons about the first `*`/`&` and the words left of it, and three
    things put those characters somewhere they mean nothing: template arguments
    (`std::vector<const char*> &v` — that `const` binds the vector's element, not the
    reference, and that `*` is not the parameter's own sigil), string and character
    literals in a default argument (`std::string s = "a*b"`), and the default argument
    itself (`int n = MAXN * 2`). Each is a measured misfire in both directions.
    """
    cleaned = ATTRIBUTE.sub(" ", text.strip())
    cleaned = LITERAL.sub('""', cleaned)
    while True:
        collapsed = TEMPLATE_ARGS.sub("<>", cleaned)
        if collapsed == cleaned:
            break
        cleaned = collapsed
    cut = DEFAULT_ARG.search(cleaned)
    return (cleaned[: cut.start()] if cut else cleaned).strip()


def is_out_parameter(text: str) -> bool:
    """Can this unit write THROUGH this parameter?

    - `char buf[64]` / `char buf[]` — an array parameter is a writable pointer.
    - `const char *argv[]` — the ELEMENT is `const char *`, which is assignable; only a
      `const` with no pointer between it and the bracket qualifies the element itself.
    - `const char **out` — `const` binds the POINTEE; the outer pointer is written through.
    - `void *const *out` — the const binds the pointee POINTER, so it is not.
    - `int &out`, `std::string &s` — the normal C++ out-parameter.
    - `int (*cb)(void)`, `std::function<void(int)> &cb` — a callable is an INPUT.
    - `T &&x` — an rvalue reference is a source to move FROM, not a destination.
    """
    raw = text.strip()
    if not raw or raw in ("void", "..."):
        return False
    if CALLABLE_TEMPLATE.search(raw):
        return False
    stripped = _declarator_text(raw)
    if not stripped or stripped in ("void", "..."):
        return False
    if "&&" in stripped or FUNCTION_POINTER.search(stripped):
        return False
    if "[" in stripped:
        head = stripped.split("[", 1)[0]
        return "*" in head or not CONST_WORD.search(head)
    first = min((i for i in (stripped.find("*"), stripped.find("&")) if i >= 0), default=-1)
    if first < 0:
        return False
    if stripped[first] == "*":
        second = stripped.find("*", first + 1)
        if second >= 0:
            # `T *q *x`: `*x` has type `T *q`, so it is the qualifier BETWEEN the two stars
            # that decides, not the one left of both.
            return not CONST_WORD.search(stripped[first + 1 : second])
    prefix = stripped[:first]
    if CONST_WORD.search(prefix):
        return False
    # A callable type carries a balanced parameter list of its own; `int (*out)[10]` does not.
    return not ("(" in prefix and ")" in prefix)


def required_questions(sites: dict[str, list[int]]) -> list[str]:
    """Which ledger rows this unit owes: one per question with a non-empty population.

    A question with an empty population is not asked. A unit with no allocations owes no
    alloc-lifetime row, and demanding one would fill the ledger with rows whose only
    honest answer is "nothing here" — rows the gate then has to accept on evidence text
    alone, which is free coverage over a population nobody had to read anything to clear. No
    question is exempt from that rule, `caller-contract` included: exempting it makes every
    zero-parameter function owe a row with an empty population — 5% of all required checks on
    a real corpus, closable with a verdict and nothing else.
    """
    return [qid for qid, (_, kinds) in QUESTIONS.items() if any(sites.get(kind) for kind in kinds)]


def pack_assignments(units: list[dict[str, Any]], agents: int) -> list[dict[str, Any]]:
    """Split units into `agents` contiguous buckets balanced on line count.

    Contiguous, not round-robin: neighbouring units share callers, types and buffers, so
    a bucket that is a run of one file reads as code rather than as a sample.
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


def _walk(root: Path) -> tuple[list[Path], list[tuple[str, str]]]:
    """(every SOURCE file under `root`, every path the walk refused and why).

    Symlinks are followed, with cycles cut on the resolved path. `Path.rglob` does not follow
    directory symlinks at all, so a subtree linked in under the root enumerates as nothing:
    exit 0, no warning, and a run that reads as complete.

    Following stops at the scope root. A link whose target resolves OUTSIDE it is refused and
    named, which the caller turns into an exit-2 naming `--exclude` as the remedy, because
    reviewing code the root does not contain files findings at paths that exist only through
    the link. Vendoring by symlink from outside the tree is therefore a deliberate decision
    the caller makes with `--exclude` or a second `--root`, not one this makes by following.
    ONE containment rule covers files and directories: judging directories against the root's
    ancestors and files against the directory they sit in refuses
    `src/shared.c -> ../common/shared.c`, in scope by both spellings, while following
    `vendor -> /elsewhere`.

    FILES are deduplicated on the resolved path too, because cutting cycles on directories
    alone lets `top/link -> ../real` and `top/alias.c -> ../real/r.c` both reach one inode:
    the file is billed twice against the ledger, and a finding filed at the canonical path
    matches no unit id at all because the alias won.

    The source-extension filter runs HERE, before that dedup, and a real path beats a symlink
    at both levels. Filtered afterwards, a non-source spelling wins the tie-break and is then
    dropped, taking the real file with it: `src/a.txt -> z.c` removes `src/z.c` from the
    review entirely — in no unit, in no artifact, exit 0 — and `src/OLD-parse.bak -> parse.c`
    kills the run with "no C/C++ source files". Preferring the real path is the same rule one
    level up: `proj/alink -> src` sorts before `proj/src`, so every unit in it is keyed at
    the alias and a finding filed at the path the compiler uses matches no unit id. Ties
    among two real paths go to the smallest, so which spelling of a doubly-reachable file
    survives is fixed rather than a consequence of stack order.

    A directory this cannot walk is RETURNED, never dropped. Dropped, `chmod 000 secret`
    gives `totals.files: 1`, `unreadable: []`, `excluded: []`, exit 0 and a whole subtree
    named in no field of any artifact — while the same condition on a single FILE aborts the
    run. The caller decides; this stops deciding by omission.
    """
    files: dict[str, Path] = {}
    seen: set[str] = set()
    refused: list[tuple[str, str]] = []
    root_key = str(root.resolve())
    # (is a symlink, path). A real directory is popped before any alias of it, so the
    # alias is the one `seen` skips whichever way the two names sort.
    queue = [(0, str(root))]
    heapq.heapify(queue)
    while queue:
        current = Path(heapq.heappop(queue)[1])
        rel = _rel_text(current, root)
        try:
            key = str(current.resolve())
        except OSError as exc:
            refused.append((rel, str(exc)))
            continue
        if key in seen:
            continue
        seen.add(key)
        # The containment rule: what this reviews resolves under the scope root.
        # `inner/up -> ../..` enumerates `up/proj/vendor/secret.c` and a link to `/` reads a
        # whole parent tree into memory; `proj/vendor -> /elsewhere` parses out-of-tree code,
        # bills it to an agent and files its findings at `vendor/…`, a path that exists only
        # through the link.
        if not _within(key, root_key):
            refused.append((rel, f"resolves to {key}, outside the scope root {root_key}"))
            continue
        try:
            entries = sorted(current.iterdir())
        except OSError as exc:
            refused.append((rel, str(exc)))
            continue
        for entry in entries:
            if entry.is_dir():
                if entry.name not in SKIP_DIRS:
                    heapq.heappush(queue, (1 if entry.is_symlink() else 0, str(entry)))
            elif entry.is_file():
                if entry.suffix.lower() not in SOURCE_EXTS:
                    continue
                try:
                    target = str(entry.resolve())
                except OSError:
                    continue
                if not _within(target, root_key):
                    refused.append(
                        (
                            _rel_text(entry, root),
                            f"symlink to {target}, outside the scope root {root_key}",
                        )
                    )
                    continue
                if target not in files or _spelling(entry) < _spelling(files[target]):
                    files[target] = entry
    return sorted(files.values()), refused


def _within(target: str, root_key: str) -> bool:
    """Does a resolved path lie inside the resolved scope root?"""
    return target == root_key or target.startswith(root_key.rstrip("/") + "/")


def _spelling(path: Path) -> tuple[int, str]:
    """Rank two names for one inode: a real path first, then the smallest string."""
    return (1 if path.is_symlink() else 0, str(path))


def _rel_text(path: Path, root: Path) -> str:
    try:
        return str(path.relative_to(root))
    except ValueError:  # pragma: no cover - the queue only ever holds paths under root
        return str(path)


def _is_excluded(rel: Path, exclude: list[str]) -> bool:
    """Glob against the relative path, or an exact path component — never a substring.

    A bare substring also drops `src/latest.c` and `src/protest.c` for `--exclude test`. An
    empty pattern raises `ValueError: empty pattern` out of `rel.match`, which reaches the
    coverage gate as an uncaught traceback because `units.json` carries the patterns; it
    matches nothing instead.
    """
    return any(
        pattern and (rel.match(pattern) or pattern in rel.parts or Path(pattern) == rel)
        for pattern in exclude
    )


def discover_sources(root: Path, exclude: list[str]) -> tuple[list[Path], list[str], list[str]]:
    """(source files, the paths `--exclude` dropped, the paths the walk refused).

    The dropped list is returned so over-exclusion is visible in the output document
    rather than only in the totals. A refused directory that `--exclude` covers is a
    deliberate omission and is reported as excluded; the rest reach the caller, which
    fails the run over them rather than reviewing a tree with a hole in it.
    """
    walked, refused = _walk(root)
    found: list[Path] = []
    excluded: list[str] = []
    problems: list[str] = []
    for rel_text, reason in refused:
        if _is_excluded(Path(rel_text), exclude):
            excluded.append(rel_text)
        else:
            problems.append(f"{rel_text}: {reason}")
    for path in walked:
        if path.suffix.lower() not in SOURCE_EXTS:
            continue
        rel = path.relative_to(root)
        if any(part in SKIP_DIRS for part in rel.parts):
            continue
        if _is_excluded(rel, exclude):
            excluded.append(str(rel))
            continue
        found.append(path)
    return found, sorted(excluded), problems


def units_for_file(rel: str, source: bytes, tree: Any, max_lines: int) -> list[dict[str, Any]]:
    """Function units (split at seams when oversized) plus one file-scope unit."""
    # A trailing newline terminates the last line; it does not start another one.
    # Counting one extra would give every file-scope unit a line that does not exist:
    # harmless for coverage, quietly wrong in the line totals.
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
        seams, strong_seams = seam_lines(body, max_lines)
        seam_set = set(seams)
        chunks = split_span(start, end, seams, max_lines, strong_seams)

        sites = _empty_sites()
        _collect_sites(node, sites)
        # Where the parameters are USED, not the signature line they are declared on. The
        # declaration line is `start_line`, which every assignment file prints as a display
        # field, so a population of `{start_line}` is transcribable: on a real corpus 45% of
        # all required checks owe exactly that one line and clear without opening a source
        # file. A use site has to be found by reading.
        named = {n for _, n in params if n}
        out_named = {n for text, n in params if n and is_out_parameter(text)}
        for scope in _parameter_scopes(node):
            _reference_lines(scope, named, sites["param"])
            _reference_lines(scope, out_named, sites["outparam"])

        for idx, (cstart, cend) in enumerate(chunks):
            # Per chunk, not per function: labelling at the function level calls a chunk
            # `seam` even when its own cut was an arbitrary line-count one, and the ledger
            # then cannot tell the two apart. The first chunk starts at the signature,
            # which is a real boundary by construction.
            at_seam = idx == 0 or cstart in seam_set
            scoped = {
                kind: sorted(line for line in lines if cstart <= line <= cend)
                for kind, lines in sites.items()
            }
            label = name if len(chunks) == 1 else f"{name} [part {idx + 1}/{len(chunks)}]"
            out.append(
                {
                    "id": f"{rel}:{cstart}-{cend}",
                    "file": rel,
                    "name": label,
                    # `_uniquify_ids` below may append a suffix: two sibling functions that
                    # start and end on the same physical line would otherwise share an id.
                    "function": name,
                    "kind": "function",
                    "start_line": cstart,
                    "end_line": cend,
                    "lines": cend - cstart + 1,
                    "split": "none" if len(chunks) == 1 else ("seam" if at_seam else "hard"),
                    "parameters": [text for text, _ in params],
                    "sites": scoped,
                    "required_questions": required_questions(scoped),
                }
            )

    outside = [n for n in range(1, total_lines + 1) if n not in covered]
    if outside:
        sites = _empty_sites()
        _collect_sites(tree.root_node, sites, skip_functions=True)

        # File scope must obey the cap too. On real C it is not a thin margin of
        # includes: an attribute macro (`int ZEXPORT foo(...)`) defeats tree-sitter's
        # error recovery, which flattens whole function bodies into top-level statements,
        # and every one of those lines lands here — the exact saturation the cap exists to
        # prevent, arriving through the one unit that would otherwise be exempt.
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
                    "required_questions": required_questions(scoped),
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
    yields hundreds of one-line units — a ledger row apiece, and an assignment list that
    reads as noise.
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
    sources, excluded, refused = discover_sources(root, exclude)
    if refused:
        # Before "no sources": an unwalkable directory is why there are none, and the
        # generic message hides the name of the thing to fix. Same rule as the unreadable
        # FILE guard below — a path nobody can enumerate is code nobody reviews, and the
        # rest of the tree still producing units makes the run look complete.
        raise EnumerateError(
            f"{len(refused)} path(s) under {root} could not be enumerated, so the code "
            f"they hold is in no unit and would be reviewed by nobody: "
            + "; ".join(refused[:10])
            + ("" if len(refused) <= 10 else f" … and {len(refused) - 10} more")
            + ". Pass --exclude for a path that is deliberately out of scope."
        )
    if not sources:
        raise EnumerateError(
            f"no C/C++ source files under {root}. Nothing to partition — check the "
            f"finding scope root and --exclude."
            + (f" {len(excluded)} file(s) were dropped by --exclude." if excluded else "")
        )

    parsers = _parsers()
    units: list[dict[str, Any]] = []
    unreadable: list[str] = []
    unparseable: list[str] = []
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
        try:
            tree, blanked = parse_tolerant(parser, source, macros)
            file_units = units_for_file(rel, source, tree, max_lines)
        except RecursionError:
            # The site and reference walks are iterative, so this is reachable only through
            # the shallow helpers on a pathologically nested file. It is still a file nobody
            # can review, so it still stops the run — but it is not an I/O failure, and
            # saying so is what tells the caller what to do about it.
            unparseable.append(rel)
            continue
        if blanked:
            repaired[rel] = blanked
        if tree.root_node.has_error:
            degraded.append(rel)
        units.extend(file_units)

    # Unreadable first: when every file is unreadable there are also no units, and
    # reporting "that is a parser failure" hides the names of the files that actually
    # failed — which is the only thing that says what to fix.
    if unreadable:
        # Coverage is reported over the units that exist, so an unreadable file shows up as
        # a gap nowhere downstream: the rest of the tree still producing units makes the run
        # look complete.
        raise EnumerateError(
            f"{len(unreadable)} file(s) could not be read, so they are in no unit and will "
            f"be reviewed by nobody: "
            + "; ".join(unreadable[:10])
            + ("" if len(unreadable) <= 10 else f" … and {len(unreadable) - 10} more")
        )
    if unparseable:
        raise EnumerateError(
            f"{len(unparseable)} file(s) are nested too deeply to analyse without exhausting "
            f"the interpreter stack, so they are in no unit and would be reviewed by nobody: "
            + ", ".join(unparseable[:10])
            + ("" if len(unparseable) <= 10 else f" … and {len(unparseable) - 10} more")
            + ". This is a generated-code shape (a table of a few thousand terms, or deeply "
            "nested parentheses), not an I/O failure. Pass --exclude for the generated file "
            "if a human has confirmed it is not review material."
        )
    if not units:
        raise EnumerateError(
            f"parsed {len(sources)} file(s) under {root} and produced no units. That is a "
            f"parser failure, not an empty codebase; do not treat it as a clean review."
        )

    units.sort(key=lambda u: (u["file"], u["start_line"]))
    id_collisions = _uniquify_ids(units)
    total_lines = sum(u["lines"] for u in units)
    # An explicit `--agents` is clamped too. `agents or default_agent_count(...)` lets it
    # bypass `--agent-max` entirely, so README and SKILL.md would describe a fan-out of 4-14
    # while any number at all is reachable.
    n_agents = max(
        agent_min,
        min(
            agent_max,
            agents or default_agent_count(total_lines, lines_per_agent, agent_min, agent_max),
        ),
    )
    assignments = pack_assignments(units, n_agents)

    checks_required = sum(len(u["required_questions"]) for u in units)
    sites_total = {kind: sum(len(u["sites"].get(kind, [])) for u in units) for kind in SITE_KINDS}

    return {
        # Resolved, and with the `--exclude` patterns and language beside it, because
        # `sites_by_id` re-derives the gate's site populations from exactly this input and
        # runs from a different working directory than the enumeration did.
        "root": str(root.resolve()),
        "language": language,
        "exclude": list(exclude),
        "max_unit_lines": max_lines,
        "files": [str(p.relative_to(root)) for p in sources],
        "unreadable": unreadable,
        "excluded": excluded,
        "id_collisions": id_collisions,
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


def _uniquify_ids(units: list[dict[str, Any]]) -> int:
    """Make every unit id unique in place. Returns how many had to be suffixed.

    A unit id is `<file>:<start>-<end>`, which collides when two sibling definitions begin
    and end on the same physical line (`int a(void){...} int b(void){...}`). The collision
    is silent and expensive: `write_outputs` keys assignments by id, so one function's data
    overwrites the other's and the loser never appears in ANY assignment file — unreviewed,
    while the ledger still shows its lines as owned. `check_ledger` collapses the same way.
    """
    seen: dict[str, int] = {}
    collided = 0
    for unit in units:
        base = unit["id"]
        if base not in seen:
            seen[base] = 1
            continue
        seen[base] += 1
        unit["id"] = f"{base}#{seen[base]}"
        collided += 1
    return collided


def assignment_unit(unit: dict[str, Any]) -> dict[str, Any]:
    """One unit as the REVIEWER sees it: everything except the site line numbers.

    This is what makes the coverage gate falsifiable by the source. `check_ledger.py` accepts
    a row when `sites_accounted` equals the population the parse counted, so an assignment
    file carrying that population verbatim lets a ledger fabricated mechanically from
    `assignments/*.json` score 100% coverage with zero violations without a source file ever
    being opened: the diff is against code-generated line numbers, but the agent was handed
    them, so it proves transcription.

    The reviewer still gets the count per question, which is what it needs to know when it
    has found them all; the lines themselves it has to go and read.

    No per-(unit, question) DIGEST of the population ships here either, tempting as it is —
    it would let the gate tell a count-preserving source edit from a reviewer that
    miscounted. An unsalted SHA-256 over a line list whose two bounding parameters,
    `site_counts` (k) and `start_line`..`end_line` (n), sit in the same JSON object has a
    preimage search of C(n, k): a reviewer with `Read` and the standard library recovered
    68.5% of a 154-unit corpus's site lines in 37 seconds of one core, and 100% of a small
    fixture in 508 hashes. Salting does not help — any salt this can write, the reviewer can
    read. It publishes far more than it protects.
    """
    out = {key: value for key, value in unit.items() if key != "sites"}
    sites = unit.get("sites") or {}
    populations = {
        question: {n for kind in QUESTIONS[question][1] for n in sites.get(kind, [])}
        for question in unit.get("required_questions") or []
        if question in QUESTIONS
    }
    out["site_counts"] = {q: len(lines) for q, lines in populations.items()}
    return out


def sites_by_id(units_doc: dict[str, Any]) -> dict[str, dict[str, list[int]]]:
    """`{unit id: site populations}`, RECOMPUTED from the source `units_doc` describes.

    The site line numbers are the answer key `check_ledger.py` diffs `sites_accounted`
    against, and nothing writes them to disk. Relocating them cannot help — any file holding
    these numbers is one `grep -rn` away whether or not a prompt names it, so a ledger
    fabricated from wherever they live scores 100%. Not persisting them can: this enumeration
    is deterministic over the source tree (byte-identical output across interpreter hash
    seeds), so the gate re-derives the populations here at the moment it needs them, from the
    same parse, and the review phase runs with no file on disk that answers its questions.

    THIS FUNCTION IS THE OTHER HALF OF THAT ARGUMENT, AND IT IS PUBLIC. It is pure, it
    ships in the run's own `scripts/` directory, and its only argument is the `units.json`
    every worker can read — so one shell command reproduces the entire answer key with no
    source file opened, and a ledger built from it scores 100% coverage, zero violations,
    exit 0. Nothing that can be done to this file closes that, because the gate has to be
    able to recompute what the agent must not. What closes it is that the producing agents
    have no shell: see `agents/c-review-worker.md` and `WORKER_AGENT` in the workflow. If
    that scoping is ever removed, this function is the bypass.
    """
    root_text = str(units_doc.get("root") or "").strip()
    # `Path("")` is `PosixPath('.')`, whose `is_dir()` is True, so `"root": ""` or `null`
    # walks straight past the guard below and enumerates the CURRENT WORKING DIRECTORY —
    # 20 unit ids from wherever the gate happens to run instead of 154 from the corpus.
    if not root_text:
        raise EnumerateError(
            "units.json records no scope root, so there is no tree to recompute the "
            "gate's site populations from. Re-run enumerate_units.py."
        )
    root = Path(root_text)
    if not root.is_dir():
        raise EnumerateError(
            f"units.json records its scope root as {root_text!r}, which is not a directory. "
            f"The gate's site populations are recomputed from the source rather than read "
            f"back, so the tree that was enumerated has to still be there."
        )
    # Every one of these is read back out of a file in the run directory. Unguarded,
    # `max_unit_lines: -5` is an INFINITE LOOP in `split_span`'s hard split, `"forty"` an
    # uncaught ValueError that escapes the gate and destroys a completed review's artifacts,
    # and `5` (below the CLI's own floor) silently repartitions the tree into 858 units none
    # of which any ledger row can match.
    max_lines = units_doc.get("max_unit_lines")
    if not isinstance(max_lines, int) or isinstance(max_lines, bool) or max_lines < MIN_UNIT_LINES:
        raise EnumerateError(
            f"units.json records max_unit_lines as {max_lines!r}; the enumerator accepts an "
            f"integer of at least {MIN_UNIT_LINES}. Re-run enumerate_units.py."
        )
    raw_exclude = units_doc.get("exclude") or []
    if not isinstance(raw_exclude, list) or not all(isinstance(p, str) for p in raw_exclude):
        raise EnumerateError(
            f"units.json records exclude as {raw_exclude!r}; the enumerator accepts a list "
            f"of patterns. Re-run enumerate_units.py."
        )
    fresh = build(
        root=root,
        exclude=list(raw_exclude),
        language=str(units_doc.get("language") or "auto"),
        max_lines=max_lines,
        agents=1,
        lines_per_agent=800,
        agent_min=1,
        agent_max=1,
    )
    return {u["id"]: u["sites"] for u in fresh["units"]}


def write_outputs(doc: dict[str, Any], out_dir: Path) -> dict[str, Any]:
    """Write the run directory: units.json plus one assignment file per reviewer.

    Neither carries the site LINE NUMBERS — see `sites_by_id`. Both carry the per-question
    counts, which is what a reviewer needs to know when it has found them all.
    """
    out_dir.mkdir(parents=True, exist_ok=True)
    public = dict(doc, units=[assignment_unit(u) for u in doc["units"]])
    (out_dir / "units.json").write_text(json.dumps(public, indent=2), encoding="utf-8")

    # The PREVIOUS run's artifacts, for the same reason the part files below are cleared.
    # `assemble_findings.py` exits 2 without writing anything when a part file is unreadable,
    # and the four artifacts of the last run into this directory survive it — so the assemble
    # agent, which is told to answer `artifacts_written` from the DIRECTORY rather than from
    # the exit code, honestly reports true, and SKILL.md then tells the reader "the artifacts
    # are complete and on disk; do not re-run the assembler". The previous run's findings and
    # coverage get reported as this run's.
    for name in ("findings.json", "REPORT.md", "REPORT.sarif", "ledger-gate.json"):
        (out_dir / name).unlink(missing_ok=True)

    # Every agent writes into parts/, and a leftover `review-unit-07.json` from a previous
    # 9-agent run into the same directory is assembled as this run's output and its ledger
    # rows counted as this run's coverage. Done here rather than in the detect agent's
    # prompt: a cleanup an LLM is asked to perform is a cleanup that can be summarised
    # instead of run, and nothing downstream could tell.
    parts_dir = out_dir / "parts"
    parts_dir.mkdir(parents=True, exist_ok=True)
    for path in parts_dir.glob("*.json"):
        path.unlink()

    by_id = {u["id"]: u for u in doc["units"]}
    assign_dir = out_dir / "assignments"
    assign_dir.mkdir(parents=True, exist_ok=True)
    # A rerun into the same output directory partitions the tree differently whenever the
    # agent count or the tree changed, and the leftovers from the previous partition are
    # indistinguishable from this run's: `unit-07.json` from a 9-agent run survives a
    # 6-agent one and reads as a live slice. This directory is generated, so it is owned.
    stale = [p for p in assign_dir.glob("*.json")]
    for path in stale:
        path.unlink()
    for assignment in doc["assignments"]:
        payload = {
            "assignment_id": assignment["id"],
            "questions": doc["questions"],
            "max_unit_lines": doc["max_unit_lines"],
            "units": [assignment_unit(by_id[uid]) for uid in assignment["unit_ids"]],
        }
        (assign_dir / f"{assignment['id']}.json").write_text(
            json.dumps(payload, indent=2), encoding="utf-8"
        )

    return {
        "units_json": str(out_dir / "units.json"),
        "parts_dir": str(parts_dir),
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
        "excluded": doc["excluded"],
        # Two sibling definitions that begin and end on the same physical line share an
        # id. `_uniquify_ids` makes the id unique, but the LINE is then owned by two
        # units and billed twice against the ledger, so the count has to be visible.
        "id_collisions": doc["id_collisions"],
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

    if ns.max_unit_lines < MIN_UNIT_LINES:
        print(
            f"enumerate_units: --max-unit-lines below {MIN_UNIT_LINES} is not a review unit",
            file=sys.stderr,
        )
        return 2
    # Each of these escapes the exit-2 contract unchecked: `--lines-per-agent 0` comes out as
    # an uncaught ZeroDivisionError with no units.json, and `--agents 0` reads as "not
    # supplied", so a caller pinning the fan-out for a measurement silently gets the derived
    # count instead.
    if ns.lines_per_agent < 1:
        print("enumerate_units: --lines-per-agent must be at least 1", file=sys.stderr)
        return 2
    if ns.agents is not None and ns.agents < 1:
        print("enumerate_units: --agents must be at least 1", file=sys.stderr)
        return 2
    if ns.agent_min < 1 or ns.agent_max < ns.agent_min:
        print(
            "enumerate_units: need 1 <= --agent-min <= --agent-max; the clamp silently "
            "returned --agent-min and violated --agent-max",
            file=sys.stderr,
        )
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
