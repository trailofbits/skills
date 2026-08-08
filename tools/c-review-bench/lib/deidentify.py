"""De-identify a C source tree so a reviewer cannot diff it against upstream.

Why this exists: the first attempt to benchmark c-review was invalidated three
times over by reviewers who looked the answer up. One of them defeated a version
scrub outright and reported the corpus as "byte-identical to real expat release
R_2_4_3". Telling an agent not to cheat does not work; the only durable defence is
that there is nothing to find. So the corpus is renamed until an upstream file
cannot be matched to it, and the bugs are ours, injected at sites we chose, so no
advisory or commit log contains them.

What is transformed, in order, line by line:

1. **Comments and banners are removed.** Copyright headers, `@brief` blocks and
   the one-line version banners are the strongest identity signal in C source.
2. **Identifiers are renamed** through one deterministic seeded mapping shared by
   every file in the corpus, so the tree still compiles and still cross-references.
   Occurrences inside string literals are renamed too — an error message like
   "invalid stored block lengths" identifies the project as loudly as a symbol.
3. **Whitespace is normalised**: leading tabs to spaces, trailing whitespace gone,
   runs of blank lines collapsed.

Deliberately *not* done: token-level reflow (rewrapping lines, moving braces).
It would break `\\`-continued macros and multi-line string literals for a cosmetic
gain, and cosmetics are not what makes a diff hard — the renaming is. This is
stated plainly rather than pretended away.

Every transformation is line-wise, and `Deidentified.line_map` records which source
line each output line came from. That is what lets an injected bug's ground-truth
line number survive de-identification: the injector computes the line in the
pre-de-identified text and maps it forward, instead of guessing.

**No defence here is airtight against training-data recall of code *patterns*.** A
model that has read the upstream project may still recognise the shape of an
inflate loop. What it cannot do is recover *where we put the bugs*, because that
information exists only in this harness.
"""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass, field
from pathlib import Path

from .creserved import RESERVED

# The lookbehind is load-bearing: without it the regex matches `x7ff00000` inside the
# hex literal `0x7ff00000` and renames it, so `0x7ff00000` becomes `0nexirn` and the
# corpus stops compiling. Two corpora passed the gate before a third one — with hex
# constants carrying letters — caught it.
IDENT_RE = re.compile(r"(?<![A-Za-z0-9_])[A-Za-z_][A-Za-z0-9_]*")
SEGMENT_RE = re.compile(r"[A-Z]+(?![a-z])|[A-Z][a-z]+|[a-z]+|\d+")
MIN_SEGMENT_LENGTH = 5
MIN_SEGMENT_USES = 2
INCLUDE_LOCAL_RE = re.compile(r'^(\s*#\s*include\s*")([^"]+)(".*)$')
INCLUDE_SYSTEM_RE = re.compile(r"^\s*#\s*include\s*<")
# The word after a `#` is a preprocessor directive, not a project identifier. Renaming
# it produces `#lornfen "header.h"`, which does not compile — and the compile gate is
# the only reason that was ever caught, so it is fixed here rather than left to a
# reserved-word list that would also refuse to rename a variable named `line`.
DIRECTIVE_RE = re.compile(r"^\s*#\s*([A-Za-z_][A-Za-z0-9_]*)")

# Syllables chosen to read like plausible C project names without evoking any real
# project. Two or three of them plus a deterministic suffix gives a namespace big
# enough that collisions are rare and handled when they happen.
SYLLABLES = (
    "ar",
    "bel",
    "cal",
    "dor",
    "eth",
    "fen",
    "gal",
    "hem",
    "ith",
    "jor",
    "kel",
    "lum",
    "mar",
    "nex",
    "oth",
    "pel",
    "qua",
    "ren",
    "sil",
    "tor",
    "urn",
    "vel",
    "wyn",
    "xen",
    "yar",
    "zon",
    "bra",
    "cro",
    "dun",
    "esk",
    "fyr",
    "glim",
    "hox",
    "irn",
    "jud",
    "kip",
    "lorn",
    "mox",
    "nub",
    "orv",
    "prin",
    "quil",
    "rast",
    "sev",
    "trin",
    "umb",
    "varn",
    "wold",
    "xis",
    "yorn",
    "zeph",
)

MIN_RENAME_LENGTH = 3


class DeidError(Exception):
    """The de-identifier cannot proceed. Callers exit non-zero."""


@dataclass
class Deidentified:
    """One file after de-identification."""

    text: str
    line_map: list[int]  # 0-based output index -> 1-based source line number

    def map_line(self, source_line: int) -> int:
        """Where source line `source_line` ended up, 1-based.

        Raises when the line was removed (a pure comment line). An injected bug
        whose site line vanished is a broken recipe, not something to paper over
        with a nearby line.
        """
        for index, origin in enumerate(self.line_map):
            if origin == source_line:
                return index + 1
        raise DeidError(
            f"source line {source_line} does not survive de-identification (it was a "
            f"comment-only or blank line). Anchor the injection on a line of code."
        )


def _regions(
    line: str, in_block: bool, in_string: bool
) -> tuple[list[tuple[str, str]], bool, bool]:
    """Split one line into (kind, text) runs. Kinds: code, string, char, comment.

    Carries two bits of state across lines: inside a `/* */` block, and inside a
    string literal continued with a trailing backslash.
    """
    out: list[tuple[str, str]] = []
    buf: list[str] = []
    kind = "code"
    i = 0
    n = len(line)

    def flush(next_kind: str) -> None:
        nonlocal kind, buf
        if buf:
            out.append((kind, "".join(buf)))
            buf = []
        kind = next_kind

    if in_block:
        kind = "comment"
    elif in_string:
        kind = "string"

    while i < n:
        ch = line[i]
        if kind == "comment":
            if line.startswith("*/", i):
                buf.append("*/")
                i += 2
                in_block = False
                flush("code")
                continue
            buf.append(ch)
            i += 1
            continue
        if kind == "string":
            buf.append(ch)
            if ch == "\\":
                if i + 1 < n:
                    buf.append(line[i + 1])
                    i += 2
                    continue
                i += 1  # backslash at end of line: the literal continues
                in_string = True
                break
            if ch == '"':
                i += 1
                in_string = False
                flush("code")
                continue
            i += 1
            continue
        if kind == "char":
            buf.append(ch)
            if ch == "\\" and i + 1 < n:
                buf.append(line[i + 1])
                i += 2
                continue
            if ch == "'":
                i += 1
                flush("code")
                continue
            i += 1
            continue
        # kind == "code"
        if line.startswith("//", i):
            flush("comment")
            buf.append(line[i:])
            i = n
            continue
        if line.startswith("/*", i):
            flush("comment")
            buf.append("/*")
            i += 2
            in_block = True
            continue
        if ch == '"':
            flush("string")
            buf.append(ch)
            i += 1
            in_string = True
            continue
        if ch == "'":
            flush("char")
            buf.append(ch)
            i += 1
            continue
        buf.append(ch)
        i += 1

    if buf:
        out.append((kind, "".join(buf)))
    # `in_block` is maintained precisely where `/*` and `*/` are seen. An earlier version
    # inferred it here — "the line ended in a comment and does not end with */, so we must
    # be inside a block" — which promoted every `//` line comment to an unterminated block
    # comment and swallowed the rest of the file. It survived two corpora that happen to
    # use only /* */ and was caught by the first one with // comments in it.
    return out, in_block, in_string


def _directive(line: str) -> str | None:
    match = DIRECTIVE_RE.match(line)
    return match.group(1) if match else None


def collect_identifiers(texts: dict[str, str], min_length: int = MIN_RENAME_LENGTH) -> set[str]:
    """Every identifier in code regions that is a candidate for renaming.

    Skips reserved names, implementation-reserved shapes (`_foo`, `foo__bar`) and
    anything shorter than `min_length` — a loop counter named `i` carries no
    identity and renaming it only risks a collision.
    """
    found: set[str] = set()
    for text in texts.values():
        in_block = in_string = False
        for line in text.splitlines():
            if INCLUDE_SYSTEM_RE.match(line):
                continue
            directive = _directive(line)
            runs, in_block, in_string = _regions(line, in_block, in_string)
            for kind, run in runs:
                if kind != "code":
                    continue
                for match in IDENT_RE.finditer(run):
                    name = match.group(0)
                    if len(name) < min_length or name == directive:
                        continue
                    if name in RESERVED or name.startswith("_") or "__" in name:
                        continue
                    found.add(name)
    return found


def _pseudonym(name: str, seed: str, salt: int) -> str:
    digest = hashlib.sha256(f"{seed}\x00{name}\x00{salt}".encode()).digest()
    count = 2 + (digest[0] % 2)
    parts = [SYLLABLES[digest[1 + i] % len(SYLLABLES)] for i in range(count)]
    base = "".join(parts)
    if name.isupper():
        return base.upper() if "_" not in name else "_".join(p.upper() for p in parts)
    if name.endswith("_t"):
        return base + "_t"
    if name[0].isupper():
        return base.capitalize()
    if "_" in name:
        return "_".join(parts)
    return base


def build_segment_map(names: set[str], mapping: dict[str, str], seed: str) -> dict[str, str]:
    """Project-wide *word* renames, for identity that hides inside string literals.

    Whole-identifier renaming misses the case that actually gives a project away: an
    error message like "widgetlib: slot count out of range", where `widgetlib` is never
    an identifier on its own. The word is a *segment* of many identifiers, though, so
    segments that appear in at least `MIN_SEGMENT_USES` distinct identifiers and are at
    least `MIN_SEGMENT_LENGTH` characters get their own stable pseudonym, applied
    case-insensitively inside strings.

    The two thresholds are what keeps this conservative. A one-off word in one
    identifier is not a project name and is left alone, so ordinary English in an error
    message survives; a word threaded through the whole namespace is exactly the thing
    worth renaming. `forbidden_strings` in the recipe remains the enforcement — this
    reduces how often an author has to reach for it, and the gate still fails if a
    declared tell survives.
    """
    counts: dict[str, int] = {}
    for name in names:
        for segment in {s.lower() for s in SEGMENT_RE.findall(name)}:
            counts[segment] = counts.get(segment, 0) + 1
    segments = {
        segment
        for segment, count in counts.items()
        if count >= MIN_SEGMENT_USES
        and len(segment) >= MIN_SEGMENT_LENGTH
        and segment not in {r.lower() for r in RESERVED}
    }
    taken = {v.lower() for v in mapping.values()}
    out: dict[str, str] = {}
    for segment in sorted(segments):
        for salt in range(64):
            candidate = _pseudonym(segment, seed + "\x00segment", salt)
            if candidate.lower() not in taken:
                out[segment] = candidate
                taken.add(candidate.lower())
                break
    return out


def apply_segment_map(text: str, segment_map: dict[str, str]) -> str:
    """Replace segment words inside a string literal, preserving the original case."""
    if not segment_map:
        return text
    for segment, replacement in sorted(segment_map.items(), key=lambda kv: -len(kv[0])):
        pattern = re.compile(re.escape(segment), re.IGNORECASE)

        def substitute(match: re.Match[str], replacement: str = replacement) -> str:
            found = match.group(0)
            if found.isupper():
                return replacement.upper()
            if found[0].isupper():
                return replacement.capitalize()
            return replacement.lower()

        text = pattern.sub(substitute, text)
    return text


def build_mapping(
    names: set[str], seed: str, extra_reserved: set[str] | None = None
) -> dict[str, str]:
    """Deterministic original -> pseudonym map. Same seed, same corpus, same map."""
    if not names:
        raise DeidError(
            "collected zero identifiers to rename, so de-identification would be a no-op. "
            "Either the file selection is empty or the source is not C."
        )
    blocked = set(RESERVED) | set(extra_reserved or ()) | set(names)
    mapping: dict[str, str] = {}
    used: set[str] = set()
    for name in sorted(names):
        for salt in range(64):
            candidate = _pseudonym(name, seed, salt)
            if candidate not in blocked and candidate not in used:
                mapping[name] = candidate
                used.add(candidate)
                break
        else:  # pragma: no cover - 64 salted attempts colliding is not reachable in practice
            raise DeidError(f"could not find a free pseudonym for {name!r}")
    return mapping


def map_file_name(path: str, mapping: dict[str, str], seed: str) -> str:
    """Rename a path's basename stem through the identifier mapping.

    `inflate.c` staying `inflate.c` after every symbol inside it is renamed would
    hand the project's identity straight back.
    """
    p = Path(path)
    stem = p.stem
    new = mapping.get(stem) or _pseudonym(stem, seed + "\x00file", 0)
    return str(p.with_name(new + p.suffix))


def rename_words(text: str, mapping: dict[str, str], protect: str | None = None) -> str:
    def one(match: re.Match[str]) -> str:
        name = match.group(0)
        if name == protect:
            return name
        return mapping.get(name, name)

    return IDENT_RE.sub(one, text)


def deidentify_text(
    text: str,
    mapping: dict[str, str],
    file_map: dict[str, str] | None = None,
    string_scrub: list[tuple[re.Pattern[str], str]] | None = None,
    segment_map: dict[str, str] | None = None,
) -> Deidentified:
    """Strip comments, rename identifiers, normalise whitespace. Keeps a line map."""
    out: list[str] = []
    line_map: list[int] = []
    in_block = in_string = False
    blank_run = 0

    for number, raw in enumerate(text.splitlines(), 1):
        had_code = bool(raw.strip())
        directive = _directive(raw)
        if INCLUDE_SYSTEM_RE.match(raw):
            pieces = [raw]
            in_block_next, in_string_next = in_block, in_string
        else:
            local = INCLUDE_LOCAL_RE.match(raw)
            if local and file_map is not None:
                head, target, tail = local.groups()
                pieces = [head + file_map.get(target, target) + tail]
                in_block_next, in_string_next = in_block, in_string
            else:
                runs, in_block_next, in_string_next = _regions(raw, in_block, in_string)
                pieces = []
                for kind, run in runs:
                    if kind == "comment":
                        continue
                    if kind == "string":
                        piece = rename_words(run, mapping)
                        piece = apply_segment_map(piece, segment_map or {})
                        for pattern, replacement in string_scrub or ():
                            piece = pattern.sub(replacement, piece)
                        pieces.append(piece)
                    elif kind == "char":
                        pieces.append(run)
                    else:
                        pieces.append(rename_words(run, mapping, protect=directive))
        in_block, in_string = in_block_next, in_string_next

        line = "".join(pieces)
        stripped_tabs = re.sub(r"^\t+", lambda m: "    " * len(m.group(0)), line)
        line = stripped_tabs.rstrip()

        if not line.strip():
            if had_code:  # a comment-only line: drop it entirely
                continue
            blank_run += 1
            if blank_run > 1:
                continue
        else:
            blank_run = 0
        out.append(line)
        line_map.append(number)

    return Deidentified(text="\n".join(out) + "\n", line_map=line_map)


@dataclass
class Corpus:
    """A whole tree of de-identified files plus the maps needed to score it."""

    files: dict[str, Deidentified] = field(default_factory=dict)
    identifier_map: dict[str, str] = field(default_factory=dict)
    file_map: dict[str, str] = field(default_factory=dict)
    segment_map: dict[str, str] = field(default_factory=dict)


def deidentify_tree(
    texts: dict[str, str],
    seed: str,
    rename_files: bool = True,
    reserved_extra: set[str] | None = None,
    string_scrub: list[tuple[str, str]] | None = None,
    min_length: int = MIN_RENAME_LENGTH,
) -> Corpus:
    """De-identify every file with one shared mapping, so the tree still links."""
    if not texts:
        raise DeidError("no files to de-identify — the corpus file selection matched nothing")
    names = collect_identifiers(texts, min_length=min_length)
    names -= set(reserved_extra or ())
    mapping = build_mapping(names, seed, extra_reserved=reserved_extra)
    file_map = (
        {path: map_file_name(path, mapping, seed) for path in texts}
        if rename_files
        else dict.fromkeys(texts, "")
    )
    if rename_files:
        # `#include "x.h"` is written relative to the includer, so index by basename too.
        base_map = {Path(k).name: Path(v).name for k, v in file_map.items()}
        include_map = dict(file_map)
        include_map.update(base_map)
    else:
        file_map = {path: path for path in texts}
        include_map = {}
    compiled = [(re.compile(pattern), replacement) for pattern, replacement in string_scrub or ()]
    segment_map = build_segment_map(names, mapping, seed)

    corpus = Corpus(identifier_map=mapping, file_map=file_map, segment_map=segment_map)
    for path, text in texts.items():
        corpus.files[file_map[path]] = deidentify_text(
            text,
            mapping,
            file_map=include_map,
            string_scrub=compiled,
            segment_map=segment_map,
        )
    return corpus
