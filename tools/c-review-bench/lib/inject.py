"""Apply a recipe's bug and decoy patches to a base tree, and locate them afterwards.

Patches are anchored on exact source text that must occur **exactly once** in the
file. Not a line number, not a fuzzy context: a unique substring. A recipe whose
anchor matches zero or two places fails the build rather than silently patching the
wrong function, which is the failure mode that makes a benchmark quietly wrong.

Every patch for a file is applied against the *original* text and spliced in one
pass, so the recipe's order does not matter and one patch cannot move another's
anchor out from under it. Overlapping patches are rejected.

The site line of each bug is computed from the text after splicing — that is the
number the ground truth records (mapped forward once more through
de-identification). Nothing in the corpus marks a bug site: a sentinel comment
would be the answer key sitting in the code.

This module also holds the reachability check, because "the bug is reachable" is
the claim a benchmark most needs to be true and most easily fakes. What is checked
is a **syntactic call chain**: for each declared edge from -> to, the callee's name
must appear as a call inside the caller's function body in the base source. That is
weaker than a proof of dynamic reachability and stronger than a recorded assertion,
and the difference is stated rather than glossed over. An edge through a function
pointer is declared `indirect` and must cite a file where the callee's address is
taken.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from .deidentify import _regions


class InjectError(Exception):
    """A recipe that cannot be applied. Callers exit non-zero."""


@dataclass
class Site:
    """Where an applied patch ended up in the post-injection text."""

    id: str
    line: int
    marker: str


@dataclass
class Patched:
    text: str
    sites: list[Site]


def apply_patches(path: str, text: str, patches: list[dict]) -> Patched:
    """Splice every patch for one file, then report each one's site line.

    `anchor` must appear exactly once. `replacement` replaces it. `site_marker`,
    which defaults to the first non-blank line of the replacement, identifies which
    line inside the replacement is *the* bug line for grading.
    """
    if not patches:
        return Patched(text=text, sites=[])

    spans: list[tuple[int, int, dict]] = []
    for patch in patches:
        anchor = patch["anchor"]
        count = text.count(anchor)
        if count != 1:
            raise InjectError(
                f"{path}: patch {patch['id']} anchor occurs {count} time(s), needs exactly 1.\n"
                f"anchor was:\n{anchor}"
            )
        start = text.index(anchor)
        spans.append((start, start + len(anchor), patch))

    spans.sort(key=lambda s: s[0])
    for index in range(len(spans) - 1):
        _, first_end, first = spans[index]
        second_start, _, second = spans[index + 1]
        if second_start < first_end:
            raise InjectError(
                f"{path}: patches {first['id']} and {second['id']} overlap; split the anchors so "
                f"each patch owns its own text"
            )

    out: list[str] = []
    cursor = 0
    placements: list[tuple[int, dict]] = []  # offset in new text -> patch
    for start, end, patch in spans:
        out.append(text[cursor:start])
        placements.append((sum(len(chunk) for chunk in out), patch))
        out.append(patch["replacement"])
        cursor = end
    out.append(text[cursor:])
    new_text = "".join(out)

    sites: list[Site] = []
    for offset, patch in placements:
        replacement = patch["replacement"]
        marker = patch.get("site_marker") or _first_code_line(replacement)
        if not marker:
            raise InjectError(f"{path}: patch {patch['id']} has an empty replacement and no marker")
        local = replacement.find(marker)
        if local < 0:
            raise InjectError(
                f"{path}: patch {patch['id']} site_marker is not inside its own replacement:\n"
                f"{marker!r}"
            )
        absolute = offset + local
        sites.append(
            Site(id=patch["id"], line=new_text.count("\n", 0, absolute) + 1, marker=marker)
        )
    return Patched(text=new_text, sites=sites)


def _first_code_line(text: str) -> str:
    for line in text.splitlines():
        if line.strip():
            return line.strip()
    return ""


# ----------------------------------------------------------------- reachability

# What may sit between a parameter list and the opening brace of a definition:
# whitespace and attribute-ish tokens. Written as a single character class on purpose.
# The first version was `\A\s*(?:[A-Za-z_][A-Za-z0-9_]*\s*)*\{` — nested quantifiers
# over the same characters, which backtracks exponentially on any call site whose tail
# has no brace. That one regex was 9 minutes of CPU on a 9.5 KLOC corpus.
_DEF_TAIL = re.compile(r"\A[\sA-Za-z0-9_]*\{")


DEF_NAME_RE = re.compile(r"\b([A-Za-z_][A-Za-z0-9_]*)\s*\(")


def _skip_balanced(text: str, start: int, opener: str, closer: str) -> int:
    """Index just past the balanced pair opening at `start`, or -1."""
    depth = 0
    i = start
    n = len(text)
    while i < n:
        char = text[i]
        if char == opener:
            depth += 1
        elif char == closer:
            depth -= 1
            if depth == 0:
                return i
        i += 1
    return -1


def code_only(text: str) -> str:
    """The same text with comments removed and literal contents blanked.

    Indexing raw C source means a `(` inside a string literal — `"("`, and a JS engine
    has plenty — never balances. The first version abandoned the whole file at that
    point and reported that half the project's functions did not exist. Blanking
    literals first is cheaper than teaching the scanner to skip them twice.

    Line structure is preserved so any line number derived from the result still lines
    up with the original.
    """
    out: list[str] = []
    in_block = in_string = False
    for line in text.splitlines():
        runs, in_block, in_string = _regions(line, in_block, in_string)
        pieces = []
        for kind, run in runs:
            if kind == "comment":
                pieces.append(" " * len(run))
            elif kind in ("string", "char"):
                quote = run[0] if run and run[0] in "\"'" else '"'
                pieces.append(
                    quote + " " * max(0, len(run) - 2) + quote if len(run) >= 2 else " " * len(run)
                )
            else:
                pieces.append(run)
        out.append("".join(pieces))
    return "\n".join(out)


def index_functions(text: str) -> dict[str, str]:
    """Every function definition in one translation unit, as {name: body}.

    Built in a single pass that skips over each body once it is found, so the cost is
    linear in file size. The previous form re-scanned the whole file for every call
    edge being checked, which took over nine minutes of CPU on a 9.5 KLOC corpus and
    would have made the gate unusable on the large one — and a gate too slow to run is
    a gate nobody runs.

    Crude by design: a name followed by a balanced paren group and then `{` (allowing
    attribute-ish tokens between) is a definition. It returns what it is sure of and
    lets the caller turn a miss into a hard failure rather than guessing.
    """
    text = code_only(text)
    found: dict[str, str] = {}
    cursor = 0
    length = len(text)
    while cursor < length:
        match = DEF_NAME_RE.search(text, cursor)
        if match is None:
            break
        # Every failure below advances past this match rather than abandoning the file:
        # one unbalanced construct must not hide every function after it.
        close = _skip_balanced(text, match.end() - 1, "(", ")")
        if close < 0:
            cursor = match.end()
            continue
        if _DEF_TAIL.match(text[close + 1 : close + 200]):
            brace = text.find("{", close + 1)
            end = _skip_balanced(text, brace, "{", "}") if brace >= 0 else -1
            if end < 0:
                cursor = match.end()
                continue
            found.setdefault(match.group(1), text[brace : end + 1])
            cursor = end + 1
            continue
        cursor = match.end()
    return found


def function_body(text: str, name: str) -> str | None:
    """The brace-balanced body of `name`'s definition, or None if there is none."""
    return index_functions(text).get(name)


def calls(body: str, callee: str) -> bool:
    return re.search(r"\b" + re.escape(callee) + r"\s*\(", body) is not None


def mentions(text: str, name: str) -> bool:
    return re.search(r"\b" + re.escape(name) + r"\b", text) is not None


def check_edges(
    texts: dict[str, str], edges: list[dict], entry_points: set[str], target: str
) -> list[str]:
    """Verify a declared call chain. Returns a list of problems; empty means verified.

    `texts` is the *base* tree keyed by original relative path. The chain must start
    at a declared entry point and end at the function holding the bug.
    """
    problems: list[str] = []
    if not edges:
        return [f"no call_path declared for {target}, so reachability was never established"]

    # A bug inside an entry point needs no chain: the entry point *is* the reachable
    # point. Written as a self-edge so every bug still carries an explicit claim
    # rather than an absent one, and so the entry point is still checked against the
    # declared list.
    if len(edges) == 1 and edges[0]["from"] == edges[0]["to"] == target:
        if target in entry_points:
            return []
        return [
            f"{target} is claimed as its own entry point but is not in the declared entry_points"
        ]

    if edges[0]["from"] not in entry_points:
        problems.append(
            f"call_path starts at {edges[0]['from']!r}, which is not a declared entry point"
        )
    if edges[-1]["to"] != target:
        problems.append(
            f"call_path ends at {edges[-1]['to']!r}, not at the bug's function {target!r}"
        )
    for a, b in zip(edges, edges[1:], strict=False):
        if a["to"] != b["from"]:
            problems.append(f"call_path is not contiguous: {a['to']!r} then {b['from']!r}")

    joined = "\n".join(texts.values())
    indexed: dict[str, str] = {}
    for text in texts.values():
        for name, body in index_functions(text).items():
            indexed.setdefault(name, body)
    for edge in edges:
        caller, callee = edge["from"], edge["to"]
        kind = edge.get("kind", "direct")
        if kind == "indirect":
            evidence = edge.get("evidence_file")
            if not evidence or evidence not in texts:
                problems.append(
                    f"indirect edge {caller} -> {callee} cites evidence_file "
                    f"{evidence!r}, which is not in the corpus"
                )
            elif not mentions(texts[evidence], callee):
                problems.append(
                    f"indirect edge {caller} -> {callee}: {callee} never appears in {evidence}, "
                    f"so nothing shows its address being taken"
                )
            continue
        body = indexed.get(caller)
        if body is None:
            problems.append(f"cannot find a definition of {caller!r} in the corpus")
            continue
        if not calls(body, callee):
            if calls(joined, callee):
                problems.append(f"{caller} does not call {callee} (it is called elsewhere)")
            else:
                problems.append(f"{caller} does not call {callee}, and nothing else does either")
    return problems
