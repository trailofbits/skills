#!/usr/bin/env python3
# /// script
# requires-python = ">=3.11"
# # Exact pins — see enumerate_units.py's header for why; keep the four headers in step.
# dependencies = ["tree-sitter==0.26.0", "tree-sitter-c==0.24.2", "tree-sitter-cpp==0.23.4"]
# ///
"""Assemble findings.json, REPORT.md and REPORT.sarif from the per-agent part files.

Each producing agent writes only its own small result to `<run-dir>/parts/`, and this
script joins them. No agent ever retypes the corpus, so no volume of findings can degrade
the artifact.

Everything here is deterministic — parts are read in sorted filename order, ids are derived
from sorted content, and nothing consults the clock or a random source. Re-running over the
same directory must produce byte-identical output, because the workflow engine replays this
step on resume and a resumed run that renumbers its findings is worse than one that fails.

Exit codes, and NOTHING else may exit non-zero: 0 when the artifacts were written and the
coverage gate accepted the ledger, 1 when all three artifacts were written but the gate
could not run or rejected the ledger (the review is assembled but unverified, and every
artifact says so), 2 when no artifact was written at all. An unexpected exception is
caught and reported as 2, because a traceback exits 1 and the caller cannot tell that
apart from "assembled but unverified" — it is told the report is complete and not to
re-run, over an empty directory.

All four artifacts — findings.json, REPORT.md, REPORT.sarif and ledger-gate.json — are
rendered in memory, then staged and renamed into place together, so neither a generator
that raises nor a write that fails can leave a fresh findings.json beside a previous run's
REPORT.sarif.

Usage:
    uv run assemble_findings.py --run-dir RUNDIR --threat-model REMOTE --severity-filter all
"""

from __future__ import annotations

import argparse
import json
import math
import re
import sys
from collections import Counter
from collections.abc import Sequence
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parent))

import check_ledger  # noqa: E402
import findings_model  # noqa: E402
import generate_sarif  # noqa: E402
import render_report  # noqa: E402

# Part-file naming is the dispatch. A stem that matches none of these is not read, which is
# why an unrecognised stem is counted and warned about rather than skipped in silence: a
# misnamed part is one agent's entire output dropped, and it looks exactly like a clean run.
# No `second-`: the second review pass is gone from the workflow, so a `second-*.json` in a
# run directory is a leftover from an earlier run and is counted as an unrecognised part —
# reported — rather than read as this run's output.
PRODUCING_PREFIXES = ("review-", "invariant-", "sweep-")
DEDUP_PREFIX = "dedup-"
VERDICT_PREFIX = "verdict-"

CONFIDENCE_RANK = {"High": 3, "Medium": 2, "Low": 1}
SURVIVOR_VERDICTS = frozenset({"TRUE_POSITIVE", "LIKELY_TP"})
REJECTION_VERDICTS = frozenset({"FALSE_POSITIVE", "LIKELY_FP"})
# Anything else is neither, and is ignored rather than silently read as a rejection.
KNOWN_VERDICTS = SURVIVOR_VERDICTS | REJECTION_VERDICTS
SEVERITY_LEVELS = frozenset({"CRITICAL", "HIGH", "MEDIUM", "LOW"})
UNJUDGED_RATIONALE = "JUDGE DID NOT RUN — verdict and severity are unvalidated"
REVIEWER_RATIONALE = (
    "reviewer-reported; no independent false-positive review ran in this configuration"
)
MARKDOWN_LINK = re.compile(r"\[([^\]]+)\]\([^)]*\)")

# Fields a finding is useless without. The workflow's schema requires them of the value an
# agent *returns*, but the part file is written separately and the two can diverge: a field
# the return carried can still be missing from the file. The count check (`--expect
# ID=COUNT`) cannot see that, because the count is unaffected. Silence here would ship
# findings that state a location and no defect.
REQUIRED_FINDING_FIELDS = ("title", "file", "line", "description", "impact", "recommendation")

# Tier 1.5: two findings in one function, within this many lines of each other, are the same
# bug described twice — including when they were filed under different bug classes, which is
# the case tier 1's exact `(file, line, bug_class)` match cannot see. The window is short on
# purpose: it is a deterministic substitute for a dedup agent, not a replacement for one, and
# a wide window merges two genuinely distinct bugs that happen to share a few lines.
NEARBY_LINES = 3

# How far apart two findings of DIFFERENT `bug_class` may sit and still be merged
# deterministically. Zero means "the same line, or not at all": a correct cross-class merge —
# one defect filed twice under two labels — lands on the SAME line, both reviewers pointing at
# the same statement, and at any greater distance a cross-class pair has only ever turned out
# to be two different bugs. Same-class pairs keep the full NEARBY_LINES window. A cross-class
# pair one to three lines apart is not refused, only left unmerged for the dedup agent, which
# reads both write-ups instead of guessing from a line distance.
CROSS_CLASS_NEARBY_LINES = 0

FUNCTION_SEPARATORS = re.compile(r"[-_\s]+")
# Ported verbatim from the JS workflow's NO_FUNCTION. A file-level finding has no enclosing
# function to share, so it never merges on the tier-1.5 rule — "both are file-level" says
# nothing about whether they are the same bug.
NO_FUNCTION = frozenset(
    {"", "-", "none", "n/a", "na", "file-level", "(file-level)", "filelevel", "file level"}
)

# The workflow's collision rule, ported from `collisionBuckets` / `flowsIntersect`. The dedup
# agent only ever sees findings that collided, and the workflow discards a merge whose members
# came from two different buckets — but the agent writes the part file this script reads, and
# this script owns the artifacts, so a merge rejected only there is rejected only in the log,
# and a reviewer's finding 900 lines away is dropped from REPORT.md. Held to the JS by
# test_assemble_findings.py's drift tests; change both together.
COLLISION_LINES = 8
FLOW_SPLIT = re.compile(r"[^A-Za-z0-9_]+")
FLOW_STOPWORDS = frozenset(
    """the and from into with this that then than when where which value values data input
    source sink size length len buffer buf pointer ptr user attacker controlled validation
    validated check checked none null call caller function via passed reaches reach between
    them for not are its it chain flow unchecked bound bounds bounded field struct line lines
    code file path unit review here there both each reachable reachability entry point write
    read copy copied""".split()
)

# The consolidated 56-class catalogue (66 -> 56, per the internal benchmark harness). It is
# duplicated from the JS workflow's CLASSES object rather than parsed out of it: this script
# must run with no dependencies and no JS runtime, and a parser that half-matches a foreign
# file is this repository's most expensive recurring bug. The duplication is held honest by
# test_assemble_findings.py's drift test, which fails when the two key sets diverge.
CLASS_PREFIXES: dict[str, str] = {
    "buffer-overflow": "BOF",
    "memcpy-size": "MEMCPYSZ",
    "overlapping-buffers": "OVERLAP",
    "flexible-array": "FLEX",
    "oob-read": "OOBREAD",
    "string-bounds-and-termination": "STRBOUND",
    "string-issues": "STR",
    "format-string": "FMT",
    "snprintf-retval": "SNPRINTF",
    "scanf-uninit": "SCANFUNINIT",
    "banned-api-with-attacker-data": "BANNEDAPI",
    "uninitialized-data": "UNINIT",
    "null-deref": "NULL",
    "use-after-free": "UAF",
    "memory-leak": "LEAK",
    "state-field-invariant": "STATEINV",
    "integer-overflow": "INT",
    "oob-comparison": "OOBCMP",
    "operator-precedence": "PREC",
    "type-confusion": "TYPE",
    "undefined-behavior": "UB",
    "error-handling": "ERR",
    "open-issues": "FILEOP",
    "filesystem-issues": "FS",
    "socket-state": "SOCKSTATE",
    "race-condition": "RACE",
    "thread-safety": "THREAD",
    "signal-handler": "SIGNAL",
    "access-control": "ACCESS",
    "privilege-drop": "PRIVDROP",
    "envvar": "ENVVAR",
    "time-issues": "TIME",
    "dos": "DOS",
    "exploit-mitigations": "MITIGATION",
    "qsort": "QSORT",
    "regex-issues": "REGEX",
    "va-start-end": "VAARG",
    "logic-flaw": "LOGIC",
    "crypto-misuse": "CRYPTO",
    "smart-pointer": "SPTR",
    "move-semantics": "MOVE",
    "lambda-capture": "LAMBDA",
    "iterator-invalidation": "ITER",
    "init-order": "INIT",
    "virtual-function": "VIRT",
    "exception-safety": "EXCEPT",
    "createprocess": "CREATEPROC",
    "cross-process": "CROSSPROC",
    "token-privilege": "TOKPRIV",
    "service-security": "WINSVC",
    "dll-planting": "DLLPLANT",
    "windows-path": "WINPATH",
    "installer-race": "INSTRACE",
    "named-pipe": "NAMEDPIPE",
    "windows-crypto": "WINCRYPTO",
    "windows-alloc": "WINALLOC",
}
FALLBACK_CLASS = "logic-flaw"


def _precision_rank(finding: dict[str, Any]) -> int:
    """How precisely a finding states where the bug is. Higher is better.

    Location precision comes FIRST in primary election, ahead of confidence. A merge
    keeps one member's site and discards the others', so electing a vaguely located
    member throws away the only thing the grader — and a human opening the file — can
    act on. A file-level member winning election drags the merged finding tens of lines
    from the defect.
    """
    return 0 if not norm_function(finding.get("function")) else 1


def _election_key(findings: dict[str, Any], key: str) -> tuple[int, int, str]:
    f = findings[key]
    return (-_precision_rank(f), -CONFIDENCE_RANK.get(f["confidence"], 2), key)


POINTER_WINDOW = 12


def promote_unclaimed_pointers(
    findings: dict[str, dict[str, Any]], pointers: list[dict[str, Any]]
) -> list[dict[str, Any]]:
    """Turn an out-of-slice pointer into a finding only where nobody filed one.

    Reviewers are told not to write up bugs outside their own units, because under a
    location partition those lines already have an owner who is reading them with more
    context. That avoids duplicated work, but is only safe if a pointer the owner then
    missed still reaches the report.

    So: a pointer within `POINTER_WINDOW` lines of an existing finding in the same file
    is dropped, because the owner did file it and their write-up is the better one. A
    pointer nobody covered becomes a finding, marked `from_pointer`, at Low confidence
    and with the note as its description — deliberately thin, because the reviewer who
    raised it was explicitly told not to spend effort on it.
    """
    claimed: dict[str, list[int]] = {}
    for finding in findings.values():
        claimed.setdefault(finding["file"], []).append(finding["line"])

    promoted = []
    for ptr in pointers:
        near = any(
            abs(ptr["line"] - line) <= POINTER_WINDOW for line in claimed.get(ptr["file"], [])
        )
        # A pointer with no note is a location and no defect — exactly the shape
        # REQUIRED_FINDING_FIELDS exists to reject — and promotion runs after that check, so
        # it reaches the report as `Unreviewed pointer: ` with an empty description and
        # `incomplete_findings: []`.
        if near or not ptr["file"] or not ptr["note"].strip():
            continue
        promoted.append(ptr)
        # Claim it, so two pointers at the same place promote once.
        claimed.setdefault(ptr["file"], []).append(ptr["line"])
    return promoted


def resolve_chains(merged: dict[str, str]) -> None:
    """Point every `merged_into` at a finding that is not itself merged.

    Agent merges arrive in arbitrary order, so one merge can elect a primary that a
    later merge demotes. Guarding only "is this duplicate already merged" misses that
    entirely — the stale pointer is a *value*, not a key. Left uncompressed the report
    shows a primary that is not in the reported set and `also_known_as` does not
    round-trip.
    """
    for key in list(merged):
        seen = {key}
        target = merged[key]
        while target in merged:
            if target in seen:  # a cycle: break it rather than spin
                break
            seen.add(target)
            target = merged[target]
        if target == key:
            # A cycle back to this key. Left pointing at ITSELF it writes
            # `merged_into == own id`, which `findings_model.primaries()` resolves to the
            # finding itself, sees survive, and skips: the finding vanishes from REPORT.md
            # and from SARIF while findings.json still holds it, with nothing counting or
            # warning. Unmerge it instead — it becomes the group's primary and the rest of
            # the cycle resolves onto it on the next iterations.
            del merged[key]
            continue
        merged[key] = target


class AssembleError(Exception):
    """The run directory is not assemblable. Callers exit 2 and write nothing."""


# ------------------------------------------------------------------ normalisation


def _text(value: Any) -> str:
    """JS `String(x || '')`. Falsy becomes empty; a container is re-serialised, not repr'd.

    Python's repr of a dict would put single quotes into REPORT.md, so a structured value an
    agent put in a prose field at least stays valid JSON on the way through.
    """
    if not value:
        return ""
    if value is True:
        return "true"
    if isinstance(value, (list, dict)):
        return json.dumps(value, ensure_ascii=False, sort_keys=True)
    return str(value)


def normalize_path(value: Any, scope_root: str | Sequence[str] = "") -> str:
    """Port of the workflow's `normalizePath`, plus containment against the scope root.

    Agents hand back `[src/parse.c](src/parse.c)`, `./src/parse.c` and `src//parse.c` for the
    same file. Collapsing them here is what makes the tier-1 `(file, line, bug_class)` merge
    and the SARIF URIs agree; without it the same bug filed twice reads as two locations.

    `/build/proj/src/a.c` and `../src/a.c` are the same third and fourth spelling of it, and
    they merge with neither: the same bug is reported three times, and a code-scanning UI
    cannot resolve an absolute `uri` under a `%SRCROOT%` base id. So an absolute path inside
    the scope root is relativised against it, and `.`/`..` segments are folded away.

    `scope_root` is a SEQUENCE because the scope root has two spellings and findings arrive
    in both. `enumerate_units.py --root src` names units relative to `src`, so a reviewer
    cites `parse.c`; the same reviewer reading through `context_roots: .` cites
    `src/parse.c`; a tool-emitted path is `/repo/src/parse.c`. Stripping only the absolute
    form — which is what `Path(ns.scope).resolve()` alone gives when `--scope` is the
    relative `src` — leaves the middle spelling unmerged HERE while the workflow's
    `normalizePath`, which is handed the same two roots, merges it: the workflow log then
    reports one primary over a findings.json holding two.
    """
    text = str("" if value is None else value).replace("\\", "/").strip()
    link = MARKDOWN_LINK.fullmatch(text)
    if link:
        text = link.group(1)
    while "//" in text:
        text = text.replace("//", "/", 1)
    text = _fold_segments(text)
    roots = [scope_root] if isinstance(scope_root, str) else list(scope_root)
    for candidate in roots:
        # The root is folded too, so a caller passing `./src` strips the same as `src`.
        root = _fold_segments(str(candidate or "").replace("\\", "/").rstrip("/"))
        if root and text.startswith(root + "/"):
            text = text[len(root) + 1 :]
            break
    return text


def _fold_segments(text: str) -> str:
    """Resolve `.` and `..` segments, keeping any leading `/`.

    Run BEFORE the scope root is stripped, not after. Stripping first leaves `./src/parse.c`
    unmatched against a root of `src` — the `./` is still on the front — so it folds to
    `src/parse.c` while its siblings fold to `parse.c`, and the one file is two findings. The
    docstring above names `./src/parse.c` as a spelling this collapses, so the order is the
    whole of that promise. `normalizePath` in the workflow does the same two steps in the
    same order.
    """
    parts: list[str] = []
    for segment in text.split("/"):
        if segment == "." or (segment == "" and parts):
            continue
        if segment == ".." and parts and parts[-1] not in ("", ".."):
            parts.pop()
            continue
        parts.append(segment)
    return "/".join(parts)


def pad3(value: Any) -> str:
    text = str(value)
    return text if len(text) >= 3 else "0" * (3 - len(text)) + text


def _line(value: Any) -> int:
    """A missing, non-numeric or non-positive line becomes 1, as the workflow does.

    Line 1 is wrong but locatable; dropping the finding, or emitting `null`, is not. SARIF
    consumers reject a zero or negative `startLine` outright.

    A decimal STRING is a number, not junk: `"line": "142"` collapsing to 1 fires no marker
    either, because 1 is a valid int. Two unrelated findings quoted that way in one file then
    share `(file, line, bug_class)` and tier 1 merges one of them out of the report entirely
    — a real bug deleted by a quoting mistake.
    """
    return _line_or_none(value) or 1


def _line_or_none(value: Any) -> int | None:
    """The usable line in `value`, or None when there was none to read.

    Split out so the caller can record that the 1 was INVENTED. `_line` has to return a valid
    positive int — SARIF rejects anything else and the tier-1 dedup bucket is keyed on it — so
    after coercion nothing downstream can distinguish an invented line 1 from a real one, and
    `[LINE NUMBER INVENTED]` could never fire on an assembled finding.
    """
    if isinstance(value, str):
        try:
            value = int(value.strip())
        except ValueError:
            return None
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return None
    # `isfinite` is asked only about FLOATS. `math.isfinite(10**400)` raises OverflowError —
    # it converts to float first — so a `line` of `10**400`, which `json.loads` accepts,
    # escapes as an exit 2 that deletes the previous run's artifacts over a display field. An
    # int too large for a SARIF region is still a line number here; it fails
    # `findings_model.line_usable` and carries `[LINE NUMBER INVENTED]` instead.
    if isinstance(value, float) and not math.isfinite(value):
        return None
    if value <= 0:
        return None
    return int(math.floor(value))


def norm_function(name: Any) -> str:
    """Port of the workflow's `normFunction`. Returns "" for anything meaning "no function".

    Same order as the JS — lowercase, drop parentheses, collapse `-`/`_`/whitespace runs to a
    single space — so `(file-level)` and `file_level` both land on the same sentinel and the
    two implementations bucket the same pairs.
    """
    text = _text(name).lower().replace("(", "").replace(")", "")
    text = FUNCTION_SEPARATORS.sub(" ", text).strip()
    return "" if text in NO_FUNCTION else text


def _flow_tokens(text: Any) -> set[str]:
    """Identifier-ish tokens out of a `data_flow` description. Port of `flowTokens`."""
    return {
        token
        for token in (word.lower() for word in FLOW_SPLIT.split(_text(text)))
        if len(token) >= 3 and token not in FLOW_STOPWORDS and not token.isdigit()
    }


def _flows_intersect(a: dict[str, Any], b: dict[str, Any]) -> bool:
    """Two write-ups of one data-flow chain name the same identifiers. Port of `flowsIntersect`.

    Deliberately hard to trigger: a loose threshold measures prose similarity rather than
    shared identifiers, and lets two short unrelated descriptions collide by chance.
    """
    left, right = _flow_tokens(a.get("data_flow")), _flow_tokens(b.get("data_flow"))
    if len(left) < 4 or len(right) < 4:
        return False
    shared = len(left & right)
    return shared >= 3 and shared / min(len(left), len(right)) >= 0.5


def collides(a: dict[str, Any], b: dict[str, Any]) -> bool:
    """Do these two point at one construct? The pairwise half of `collisionBuckets`.

    Same file, and pointing at one construct: the same enclosing function, lines within
    `COLLISION_LINES`, or two descriptions of one data-flow chain. This is the predicate the
    workflow unions with; the bucket a merge is judged against is the transitive closure —
    see `collision_buckets`.
    """
    if a["file"] != b["file"]:
        return False
    function = norm_function(a["function"])
    if function and function == norm_function(b["function"]):
        return True
    if abs(a["line"] - b["line"]) <= COLLISION_LINES:
        return True
    return _flows_intersect(a, b)


def collision_buckets(
    findings: dict[str, dict[str, Any]], merged: dict[str, str]
) -> dict[str, str]:
    """Bucket root per live key, for keys in a bucket of two or more. Port of `collisionBuckets`.

    The workflow unions colliding pairs with union-find and then judges a merge on *bucket
    membership*, so the relation it enforces is transitive: three findings at lines 10, 18 and
    26 are one bucket, and the agent may merge 26 into 10 even though those two never collided
    directly. Testing `collides(10, 26)` here instead refuses exactly those merges, so the
    workflow's reported `stats.primaries` and this script's findings.json disagree about the
    same run and a duplicate the run log says was merged comes back as a second primary in
    REPORT.md.

    A key in no bucket maps to nothing, and the workflow requires membership to match this:
    comparing two absent bucket ids gives `undefined !== undefined` and accepts a merge
    between two findings that are each alone.
    """
    live = [key for key in findings if key not in merged]
    parent = {key: key for key in live}
    for index, left in enumerate(live):
        for right in live[index + 1 :]:
            if collides(findings[left], findings[right]):
                root_left, root_right = _find(parent, left), _find(parent, right)
                if root_left != root_right:
                    parent[root_left] = root_right
    roots = Counter(_find(parent, key) for key in live)
    return {key: _find(parent, key) for key in live if roots[_find(parent, key)] > 1}


def reviewer_severity(value: Any) -> str:
    """The reviewer's own severity, upper-cased; "" when absent or not one of the four.

    An unrecognised label is dropped rather than carried, because `findings_model` scores an
    unknown severity as 0: a finding whose reviewer typed `Critical!!` would then be filtered
    out by `--severity-filter high`. The MEDIUM default that replaces it is visible instead.
    """
    text = _text(value).strip().upper()
    return text if text in SEVERITY_LEVELS else ""


def _seq(value: Any) -> list[Any]:
    """A list-valued part field, or empty.

    `x or []` accepts any non-empty non-iterable, so `"ledger": 5` or `"merges": 5` raises
    `TypeError: 'int' object is not iterable` before a single artifact is written and takes a
    completed review with it. `findings` is checked explicitly; its six siblings come through
    here.
    """
    return value if isinstance(value, list) else []


def _dropped(value: Any) -> bool:
    """True when `_seq` had to throw a present-but-wrong-typed field away.

    Dropping in silence is a worse failure than the crash it replaces: a `dedup-01.json`
    whose `merges` is a merge OBJECT rather than an array gives `merged_agent: 0`,
    `ignored_merges: 0`, no stderr line and exit 0 — indistinguishable from a dedup agent
    that found nothing. Same for `verdicts`, `pointers` and `ledger`, the last of which is a
    whole agent's coverage account. Every caller counts the loss.
    """
    return value is not None and not isinstance(value, list)


def normalize_finding(
    raw: dict[str, Any], part_id: str, key: str, scope_root: str | Sequence[str] = ""
) -> dict[str, Any]:
    """One part-file finding as it appears in findings.json.

    An unrecognised `bug_class` becomes `logic-flaw` and the original is preserved in
    `reported_bug_class`: a class the catalogue does not know has no id prefix and no SARIF
    rule, and silently dropping the finding to avoid that would lose a real bug over a typo.

    `severity`, `attack_vector`, `exploitability` and `severity_rationale` are the reviewer's
    own assessment and are only set when the reviewer supplied one. Absence is meaningful
    downstream: a finding a judge rejects must carry no severity at all, and a key that is
    always present could not say that.
    """
    # `in` on a dict hashes the key, so an unguarded list or dict `bug_class`/`confidence`
    # raises `TypeError: unhashable type` and destroys every artifact. The JS side coerces to
    # a string and falls back, so this is a port divergence as well as a crash.
    reported_class = raw.get("bug_class")
    bug_class = (
        reported_class
        if isinstance(reported_class, str) and reported_class in CLASS_PREFIXES
        else FALLBACK_CLASS
    )
    confidence = raw.get("confidence")
    line = _line_or_none(raw.get("line"))
    reviewer_fields = {
        "severity": reviewer_severity(raw.get("severity")),
        "attack_vector": _text(raw.get("attack_vector")).strip(),
        "exploitability": _text(raw.get("exploitability")).strip(),
        "severity_rationale": _text(raw.get("severity_rationale")).strip(),
    }
    return {
        "key": key,
        "bug_class": bug_class,
        "reported_bug_class": _text(reported_class),
        "title": _text(raw.get("title")) or "untitled",
        "file": normalize_path(raw.get("file"), scope_root),
        "line": line or 1,
        # Both artifacts print `[LINE NUMBER INVENTED]` off this. It has to be a separate
        # field: the line itself is coerced to a usable int before anything reads it.
        "line_invented": line is None,
        "function": _text(raw.get("function") or "(file-level)").strip(),
        "unit_id": _text(raw.get("unit_id")),
        "confidence": (
            confidence
            if isinstance(confidence, str) and confidence in CONFIDENCE_RANK
            else "Medium"
        ),
        "description": _text(raw.get("description")),
        "code": _text(raw.get("code")),
        "data_flow": _text(raw.get("data_flow")),
        "reachability": _text(raw.get("reachability")),
        "impact": _text(raw.get("impact")),
        "mitigations_checked": _text(raw.get("mitigations_checked")),
        "recommendation": _text(raw.get("recommendation")),
        "outside_assigned_classes": raw.get("outside_assigned_classes") is True,
        "found_by": part_id,
        **{name: value for name, value in reviewer_fields.items() if value},
    }


# ------------------------------------------------------------------ inputs


def _load_json(path: Path, label: str) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        # `UnicodeDecodeError` is a ValueError, not an OSError, so one 0xFF byte in a part
        # file escapes an OSError-only handler and exits 2 with no artifacts.
        raise AssembleError(f"{label} {path} is not valid UTF-8 JSON ({exc})") from exc
    except OSError as exc:
        raise AssembleError(f"{label} {path} cannot be read ({exc})") from exc


def _optional_json(path: Path, label: str) -> Any | None:
    """Absent is allowed; corrupt is not.

    Treating an unreadable optional input as absent is how a run reports "no ledger" when
    what it means is "the ledger did not parse".
    """
    if not path.is_file():
        return None
    return _load_json(path, label)


def load_parts(run_dir: Path) -> list[tuple[str, dict[str, Any]]]:
    """Every `<run-dir>/parts/*.json`, in sorted filename order, as (stem, document).

    Zero part files is a hard failure, not an empty assembly. An assembler that inspects
    nothing and reports success is the exact shape of bug AGENTS.md forbids: it would emit a
    clean report for a run in which every agent crashed. Zero *findings* across parts that
    are present is a different thing entirely, and succeeds.
    """
    parts_dir = run_dir / "parts"
    if not run_dir.is_dir():
        raise AssembleError(f"run directory does not exist: {run_dir}")
    if not parts_dir.is_dir():
        raise AssembleError(f"no parts directory at {parts_dir}; no agent wrote its results")
    paths = sorted(parts_dir.glob("*.json"))
    if not paths:
        raise AssembleError(
            f"{parts_dir} holds no part files. Nothing was assembled, which is not the same "
            f"as a review that found nothing — refusing to write a clean report."
        )
    out: list[tuple[str, dict[str, Any]]] = []
    for path in paths:
        doc = _load_json(path, "part file")
        if not isinstance(doc, dict):
            raise AssembleError(
                f"part file {path}: expected a JSON object, got {type(doc).__name__}"
            )
        out.append((path.stem, doc))
    return out


def dispatched_stems(expected: list[str]) -> set[str] | None:
    """The producing part stems the workflow actually dispatched, or None if it said nothing.

    `check_expectations` asserts every dispatched part ARRIVED and arrived whole; this is the
    converse. Without it any file under `parts/` whose stem starts with a producing prefix is
    read, its findings assembled and its ledger rows counted — so with
    `--expect review-unit-01=0` as the only expectation, a `parts/sweep-ghost.json` nobody
    dispatched contributes a CRITICAL that renders in REPORT.md as `BOF-001`, with
    `unrecognised_parts: 0`, `ok: true` and exit 0. `ID=COUNT` alone does not close it:
    an agent wanting to exceed its count writes the surplus to a second file. The workflow
    knows the exact set of stems it dispatched.

    None when no `--expect` was given at all — the hand-assembly path, which is not a silent
    pass: `main` turns an empty expectation set into `ok: false` and exit 1, because an
    allowlist handed zero items admits everything and certifies it with exit 0.
    """
    stems = {item.partition("=")[0].removesuffix(".json") for item in expected}
    return stems or None


def require_producing_part(
    parts: list[tuple[str, dict[str, Any]]], ghosts: list[str], parts_dir: Path
) -> None:
    """At least one DISPATCHED producing part, or there is nothing to assemble.

    Counting *files* passes when every review and sweep agent died and only `detect` wrote
    one: the run assembles to `producing_parts: 0`, zero findings, zero coverage rows, exit 0
    and a clean REPORT.md that says the review found nothing. A reader cannot tell that apart
    from a clean codebase, and a benchmark collector records it as a zero-recall result for
    the tool rather than a failed run.

    Run AFTER the allowlist, not before it: before it, a `parts/sweep-classes.json` nobody
    dispatched satisfies the guard and is then filtered out, so a real CRITICAL is dropped
    and REPORT.md says "No findings passed" over a run with no producing part at all, at exit
    1 with `artifacts_written: true`.
    """
    if any(stem.startswith(PRODUCING_PREFIXES) for stem, _ in parts):
        return
    found = sorted([stem for stem, _ in parts] + ghosts)
    raise AssembleError(
        f"{parts_dir} holds {len(found)} part file(s) but none of them is a dispatched "
        f"producing part ({', '.join(PRODUCING_PREFIXES)}) — no agent reviewed any code. "
        f"Found: {', '.join(found) or 'nothing'}"
        + (f" (undispatched: {', '.join(sorted(ghosts))})" if ghosts else "")
        + ". Refusing to write a report that would read as 'no findings'."
    )


# The one part the workflow dispatches and deliberately never names in `--expect`:
# DEDUP_SCHEMA has no `part_written` field, so an expectation for it fails the whole assembly
# whenever the dedup agent returns merges without writing, and that phase must not be able to
# cost the run. Allowlisted by EXACT STEM, never by prefix: as a prefix carve-out any
# `parts/dedup-ghost.json` is read whatever `--expect` says, and a ghost dedup part merges a
# CRITICAL out of REPORT.md with `unrecognised_parts: 0`, no Run warning, and its own name
# printed nowhere.
ALWAYS_ALLOWED_STEMS = frozenset({"dedup-agent"})


def split_undispatched(
    parts: list[tuple[str, dict[str, Any]]], allowed: set[str] | None
) -> tuple[list[tuple[str, dict[str, Any]]], list[str]]:
    """(the parts a rule may read, the stems nobody dispatched)."""
    if allowed is None:
        return parts, []
    kept = []
    ghosts = []
    for stem, doc in parts:
        if stem in allowed or stem in ALWAYS_ALLOWED_STEMS:
            kept.append((stem, doc))
        else:
            ghosts.append(stem)
    return kept, ghosts


def _external_declarations(items: list[str]) -> dict[str, bool]:
    """`--external-source ID=0|1` into `{stem: answered_yes}`. A malformed item is fatal."""
    out: dict[str, bool] = {}
    for item in items:
        name, sep, value = item.partition("=")
        if not sep or value not in {"0", "1"}:
            raise AssembleError(f"--external-source {item!r}: expected ID=0 or ID=1")
        out[name.removesuffix(".json")] = value == "1"
    return out


def check_expectations(
    expected: list[str],
    parts: list[tuple[str, dict[str, Any]]],
    run_dir: Path,
    declared_failures: list[str] | None = None,
) -> None:
    """Assert every part the workflow dispatched arrived, and arrived whole.

    `ID` alone catches an agent that never wrote. `ID=COUNT` catches the failure this
    whole design exists to remove: an agent that wrote a file but summarised its own
    output on the way. The workflow knows the count because it received the same
    findings through the schema, so a part file shorter than its return value is a
    detectable lie rather than a quietly shorter report.
    """
    if not expected:
        # A checker handed zero items must not report success. The workflow always passes one
        # `--expect` per dispatched part, so an empty list means this is a hand assembly —
        # the documented recovery path when the assemble agent dies — and that path silently
        # drops the workflow's bookkeeping: a review agent that never wrote its part file
        # leaves `agent_failures: []` and a full `parts_read`, which reads as a clean
        # 13-slice run rather than a 12-slice one. Nothing here can recover the expectation,
        # so the document must say it was never checked rather than let an empty failure list
        # be read as no failures.
        print(
            "assemble_findings: WARNING: no --expect given, so NOTHING verified that every "
            "dispatched agent wrote its part file. `run.agent_failures` and `run.parts_read` "
            "below describe only what is on disk. If this is a hand assembly after an "
            "assemble-agent failure, read the workflow's own log for the dispatched part "
            "list before trusting coverage.",
            file=sys.stderr,
        )

    # An agent that reported it could not write its part file is already recorded as a
    # failure in both artifacts, so a MISSING file for it is expected rather than fatal. Only
    # the missing-file case is excused: dropping the whole expectation would drop the COUNT
    # check on a file that IS present, turning `part_written: false` into an agent-controlled
    # switch that disables the only cross-check on that part's contents while it is still
    # read in full.
    declared = {str(item).split(":", 1)[0].strip() for item in (declared_failures or ())}
    by_stem = {stem: doc for stem, doc in parts}
    missing: list[str] = []
    short: list[str] = []
    over: list[str] = []
    for item in expected:
        name, _, count_text = item.partition("=")
        stem = name.removesuffix(".json")
        if stem not in by_stem:
            if stem not in declared:
                missing.append(stem)
            continue
        if not count_text:
            continue
        try:
            wanted = int(count_text)
        except ValueError as exc:
            raise AssembleError(f"--expect {item!r}: {count_text!r} is not an integer") from exc
        # `or []`, not the bare get. `collect` rejects a TRUTHY non-list; it reads
        # `doc.get("findings") or []`, so `null`, `0`, `""`, `{}` and an ABSENT `findings`
        # key all become "this agent found nothing" — which is exactly the shape this check
        # exists to catch. Skipped here, an agent that returned 9 findings and wrote a part
        # file with no `findings` key at all produces rc 0, zero findings and no warning.
        raw = by_stem[stem].get("findings") or []
        if not isinstance(raw, list):
            # `len()` on a non-list raises an uncaught TypeError here, one step before
            # `collect` rejects the same part with a precise message.
            continue
        got = len(raw)
        # Directional on purpose. The part FILE is the artifact; the returned count is a
        # cross-check against summarisation on the way to disk, so only `part < returned` is
        # evidence of loss. The symmetric version kills real runs: an invariant-sweep agent
        # that writes nine findings to disk and returns zero — reading `findings` as "what I
        # am returning inline", a defensible reading of an ambiguous contract — loses all
        # nine over a disagreement in the safe direction. Over-delivery is logged, never
        # fatal.
        if got < wanted:
            short.append(f"{stem} holds {got} finding(s), the agent returned {wanted}")
        elif got > wanted:
            over.append(f"{stem} holds {got} finding(s), the agent returned {wanted}")

    if missing:
        raise AssembleError(
            f"expected part file(s) absent from {run_dir / 'parts'}: {', '.join(sorted(missing))}. "
            f"The agent that owed them did not write, so the assembled document would be "
            f"silently short."
        )
    if short:
        raise AssembleError(
            "part file(s) are SHORTER than what their agent returned: "
            + "; ".join(sorted(short))
            + ". A part file shorter than its agent's own output means the file was "
            "summarised on the way to disk, which is the failure this pipeline is built "
            "to prevent."
        )
    if over:
        print(
            "assemble_findings: note: part file(s) hold more findings than their agent "
            "reported returning: " + "; ".join(sorted(over)) + ". The file is the artifact, "
            "so all of them are assembled.",
            file=sys.stderr,
        )


def _coverage_row(part_id: str, row: dict[str, Any]) -> dict[str, Any]:
    """One ledger row rendered into the coverage shape REPORT.md already knows how to print.

    The ledger is per (unit, question) while the coverage table is per (group, bug class), so
    the question takes the bug-class column. `check_ledger.py` is what actually audits these
    rows against the code-generated unit list; this projection is for the human reader.
    """
    sites = [n for n in _seq(row.get("sites_accounted")) if isinstance(n, int)]
    return {
        "group": part_id,
        "bug_class": _text(row.get("question")),
        "outcome": _text(row.get("verdict")),
        "population": f"{len(sites)} site(s): {', '.join(str(n) for n in sites)}",
        "evidence": _text(row.get("evidence")),
        "unit_id": _text(row.get("unit_id")),
    }


class Collected:
    """Everything read out of parts/, before any merging or judging."""

    def __init__(self) -> None:
        self.findings: dict[str, dict[str, Any]] = {}
        self.coverage: list[dict[str, Any]] = []
        self.externals: list[dict[str, Any]] = []
        self.notes: list[str] = []
        self.dedup: list[tuple[str, dict[str, Any]]] = []
        self.verdicts: list[tuple[str, dict[str, Any]]] = []
        self.unrecognised: list[str] = []
        self.incomplete: list[str] = []
        self.pointers: list[dict[str, Any]] = []
        # `<part>.<field>` for every list-valued field that was present with the wrong
        # type and therefore silently dropped. See `_dropped`.
        self.ignored_fields: list[str] = []


def collect(
    parts: list[tuple[str, dict[str, Any]]],
    benchmark_mode: bool = False,
    returned_external: dict[str, bool] | None = None,
    scope_root: str | Sequence[str] = "",
) -> Collected:
    """Split the parts by role and normalise every producing part's findings.

    A finding's stable identity is `<part file stem>#<index>` — derived from the filename,
    never from the `part_id` field inside the file, so a field an agent mistyped cannot break
    the mapping that dedup and judge verdicts reference.

    `returned_external` is the external-source declaration each part gave through the SCHEMA
    (`--external-source`). The part file and the structured return can disagree — a file
    written before a rejected structured answer was retried is the same staleness `--expect`
    exists for — so any `true` from either source wins, exactly as it would if the two agreed.
    """
    returned_external = returned_external or {}
    got = Collected()
    for stem, doc in parts:
        if stem.startswith(PRODUCING_PREFIXES):
            raw_findings = doc.get("findings") or []
            if not isinstance(raw_findings, list):
                raise AssembleError(f"part {stem}: 'findings' must be a list")
            for index, raw in enumerate(raw_findings):
                if not isinstance(raw, dict):
                    raise AssembleError(
                        f"part {stem}: findings[{index}] is {type(raw).__name__}, "
                        f"expected an object"
                    )
                missing = [f for f in REQUIRED_FINDING_FIELDS if not raw.get(f)]
                if missing:
                    got.incomplete.append(f"{stem}#{index} ({', '.join(missing)})")
                key = f"{stem}#{index}"
                got.findings[key] = normalize_finding(raw, stem, key, scope_root)
            if _dropped(doc.get("ledger")):
                got.ignored_fields.append(f"{stem}.ledger")
            for index, row in enumerate(_seq(doc.get("ledger"))):
                if not isinstance(row, dict):
                    # Dropped, not fatal. A wholly wrong-typed `ledger` is already tolerated
                    # one line above (`_dropped` records it and the run continues), so
                    # raising here would make ONE bad row the strictest failure in the file:
                    # exit 2, no artifacts, and the previous run's four deleted, over a field
                    # that feeds only REPORT.md's display table — `check_ledger` re-reads the
                    # parts itself and degrades to `{"error": …}` on the same input.
                    got.ignored_fields.append(f"{stem}.ledger[{index}]")
                    continue
                got.coverage.append(_coverage_row(stem, row))
            got.externals.append(
                {
                    "group": stem,
                    "consulted": doc.get("external_sources_consulted") is True
                    or returned_external.get(stem) is True,
                    "detail": _text(doc.get("external_sources_detail")) or "none",
                    # Whether this part ANSWERED, in either channel. The declaration is
                    # benchmark-only instrumentation (`benchmarkMode`), so with it off every
                    # part reports `consulted: false` whether or not the reviewer looked
                    # anything up — indistinguishable from an honest no. A scored run must be
                    # able to tell "declared nothing" from "was never asked". The
                    # `benchmark_mode and` conjunct keeps a model that volunteers the property
                    # unprompted from making an unasked cell look cleared; the rest is the
                    # answer itself, because `declarations_seen` counts records the check
                    # actually read, and a constant would count silent parts as declarations.
                    "declared": benchmark_mode
                    and ("external_sources_consulted" in doc or stem in returned_external),
                }
            )
            if _dropped(doc.get("pointers")):
                got.ignored_fields.append(f"{stem}.pointers")
            for raw_ptr in _seq(doc.get("pointers")):
                if not isinstance(raw_ptr, dict):
                    continue
                got.pointers.append(
                    {
                        "file": normalize_path(raw_ptr.get("file"), scope_root),
                        "line": _line(raw_ptr.get("line")),
                        "note": _text(raw_ptr.get("note")),
                        "from": stem,
                    }
                )
            if doc.get("notes"):
                got.notes.append(f"{stem}: {_text(doc.get('notes'))}")
        elif stem.startswith(DEDUP_PREFIX):
            got.dedup.append((stem, doc))
        elif stem.startswith(VERDICT_PREFIX):
            got.verdicts.append((stem, doc))
        else:
            got.unrecognised.append(stem)
    return got


# ------------------------------------------------------------------ merge and judge


def tier1(findings: dict[str, dict[str, Any]]) -> dict[str, str]:
    """Identical `(file, line, bug_class)` is a duplicate by construction.

    Primary is the higher confidence, ties broken by the lexicographically smallest key so
    the choice does not depend on which agent happened to finish first.
    """
    buckets: dict[tuple[str, int, str], list[str]] = {}
    for key, finding in findings.items():
        bucket = (finding["file"], finding["line"], finding["bug_class"])
        buckets.setdefault(bucket, []).append(key)
    merged: dict[str, str] = {}
    for members in buckets.values():
        if len(members) < 2:
            continue
        primary = min(members, key=lambda k: _election_key(findings, k))
        for member in members:
            if member != primary:
                merged[member] = primary
    return merged


def _cross_class_too_far(findings: dict[str, dict[str, Any]], component: list[str]) -> bool:
    """Does this component contain a cross-class pair further apart than the cap allows?"""
    for index, left in enumerate(component):
        for right in component[index + 1 :]:
            a, b = findings[left], findings[right]
            if a["bug_class"] == b["bug_class"]:
                continue
            if abs(a["line"] - b["line"]) > CROSS_CLASS_NEARBY_LINES:
                return True
    return False


def _find(parent: dict[str, str], key: str) -> str:
    while parent[key] != key:
        parent[key] = parent[parent[key]]
        key = parent[key]
    return key


def tier1_5(findings: dict[str, dict[str, Any]], merged: dict[str, str]) -> int:
    """Near-duplicates: same file, same enclosing function, lines within `NEARBY_LINES`.

    Runs on top of tier 1 and mutates `merged`. Returns how many new merges it made.

    Unlike tier 1 this ignores `bug_class`, because the duplication it exists to remove is one
    bug filed twice under two names — an unchecked length reported as `integer-overflow` at
    line 141 and as `buffer-overflow` at line 142. Every pair it catches is a pair no dedup
    agent has to be spawned for.

    Grouping is by connected component rather than pairwise, so three findings at lines 100,
    102 and 104 become one group even though the outer two are four lines apart: a pairwise
    rule would want to merge 100 into 102 and 102 into 104, and `merged_into` must never point
    at something that is itself merged.
    """
    groups: dict[tuple[str, str], list[str]] = {}
    for key, finding in findings.items():
        if key in merged:
            continue
        function = norm_function(finding["function"])
        if not function:
            continue
        groups.setdefault((finding["file"], function), []).append(key)

    added = 0
    for bucket in sorted(groups):
        members = groups[bucket]
        if len(members) < 2:
            continue
        members.sort(key=lambda k: (findings[k]["line"], k))
        parent = {key: key for key in members}
        for index, earlier in enumerate(members):
            for later in members[index + 1 :]:
                gap = findings[later]["line"] - findings[earlier]["line"]
                if gap > NEARBY_LINES:
                    break
                if gap > CROSS_CLASS_NEARBY_LINES and (
                    findings[later]["bug_class"] != findings[earlier]["bug_class"]
                ):
                    continue
                root_a, root_b = _find(parent, earlier), _find(parent, later)
                if root_a != root_b:
                    parent[root_a] = root_b

        components: dict[str, list[str]] = {}
        for key in members:
            components.setdefault(_find(parent, key), []).append(key)
        for component in components.values():
            if len(component) < 2:
                continue
            # The cap is pairwise but the merge is by connected component, so
            # A(buffer-overflow,100) + B(integer-overflow,100) + C(buffer-overflow,102)
            # put B and C — cross-class, two lines apart — in one group through A, which
            # is precisely the merge CROSS_CLASS_NEARBY_LINES was measured to prevent.
            # A component holding such a pair is left whole for the dedup agent, which
            # reads both write-ups instead of guessing from a line distance.
            if _cross_class_too_far(findings, component):
                continue
            primary = min(component, key=lambda k: _election_key(findings, k))
            demoted = [key for key in component if key != primary]
            for key in demoted:
                merged[key] = primary
                added += 1
            # A tier-1 primary can lose here — it is live, so tier 1.5 considers it — and
            # everything tier 1 folded into it has to follow it down. Left alone, those
            # entries would point at a finding that is now a duplicate itself, which is the
            # chain `merged_into` must never contain. Not counted: they were merged already.
            for dup, target in list(merged.items()):
                if target in demoted and dup not in demoted:
                    merged[dup] = primary
    return added


def apply_agent_merges(
    findings: dict[str, dict[str, Any]],
    merged: dict[str, str],
    dedup_parts: list[tuple[str, dict[str, Any]]],
) -> int:
    """Fold the dedup agents' merges in on top of tier 1. Returns the ignored count.

    A merge is ignored when either side is a key that does not exist, has already been
    merged, or is not in the stated primary's collision bucket. Chaining is what the second
    rule prevents: if `merged_into` could point at a finding that is itself merged, the
    report would show a primary that is not in the reported set, and `also_known_as` would
    not round-trip. The third is the bucket constraint the agent was given and the workflow
    enforces on the agent's *return* — it has to hold here too, because this script reads
    the agent's part file and owns the artifacts.

    Buckets are computed once, before any agent merge is applied, exactly as the workflow
    computes `bucketOf` once before dispatching the agent.
    """
    buckets = collision_buckets(findings, merged)
    ignored = 0
    for _stem, doc in dedup_parts:
        # A whole dedup return dropped for being an object instead of an array otherwise
        # counts as zero merges and zero ignored merges — a silent no-op with the same
        # signature as an honest one.
        ignored += 1 if _dropped(doc.get("merges")) else 0
        for merge in _seq(doc.get("merges")):
            if not isinstance(merge, dict):
                ignored += 1
                continue
            stated = str(merge.get("primary") or "")
            duplicates = [str(d) for d in _seq(merge.get("duplicates"))]
            if stated not in findings or stated in merged:
                ignored += max(1, len(duplicates))
                continue
            live = [
                d
                for d in duplicates
                if d != stated
                and d in findings
                and d not in merged
                and stated in buckets
                and buckets.get(d) == buckets[stated]
            ]
            ignored += len(duplicates) - len(live)
            if not live:
                continue
            # Re-elect rather than trusting the agent's choice. The agent is asked to
            # prefer the higher-confidence member and knows nothing about how the site
            # will be graded, so it can and does nominate a `(file-level)` report over
            # two that named the function and the exact line.
            group = [stated, *live]
            primary = min(group, key=lambda k: _election_key(findings, k))
            for member in group:
                if member != primary:
                    merged[member] = primary
    resolve_chains(merged)
    return ignored


def apply_verdicts(
    findings: dict[str, dict[str, Any]],
    merged: dict[str, str],
    verdict_parts: list[tuple[str, dict[str, Any]]],
    *,
    no_judge: bool = False,
) -> tuple[list[str], int]:
    """Attach judge verdicts to primaries. Returns (unjudged keys, ignored verdicts).

    Driven by the primary set rather than by what came back, so a judge batch that answered
    for four of its five candidates leaves the fifth labelled unjudged instead of dropping
    it. The fallback is deliberately a *survivor* — an unreviewed finding is shown to the
    user and flagged, never silently suppressed, because the judge tier was measured to
    remove nothing that mattered (`suppressed: 0` in both valid guarded runs).

    A verdict part always wins over the reviewer's own severity, in both modes. Under
    `no_judge` the fallback is not a failure report but the normal path: no judge was
    dispatched, so the reviewer's severity stands and nothing is listed as unjudged.
    Verdict parts are still honoured if any exist, which is what makes the two modes
    comparable on the same run directory.
    """
    ignored = 0
    judged: set[str] = set()
    for _stem, doc in verdict_parts:
        ignored += 1 if _dropped(doc.get("verdicts")) else 0
        for verdict in _seq(doc.get("verdicts")):
            if not isinstance(verdict, dict):
                ignored += 1
                continue
            key = str(verdict.get("key") or "")
            name = _text(verdict.get("fp_verdict"))
            # An unrecognised label is NOT a rejection. Treating anything outside
            # SURVIVOR_VERDICTS as one means a judge that types `TP` instead of
            # `TRUE_POSITIVE` deletes the finding's severity, drops it from the reported set
            # and from SARIF, and counts nothing anywhere.
            if name and name.upper() not in KNOWN_VERDICTS:
                ignored += 1
                continue
            if key not in findings or key in merged or key in judged or not name:
                ignored += 1
                continue
            judged.add(key)
            finding = findings[key]
            finding["fp_verdict"] = name
            finding["fp_rationale"] = _text(verdict.get("fp_rationale"))
            finding["severity_validated"] = True
            if name.upper() in SURVIVOR_VERDICTS:
                # Validated exactly like the reviewer path. An unrecognised level scores 0
                # in SEVERITY_ORDER, which is below every filter including `all`, so a
                # judged TRUE_POSITIVE would silently vanish from every report tier.
                judged_severity = _text(verdict.get("severity")).upper()
                if judged_severity in SEVERITY_LEVELS:
                    finding["severity"] = judged_severity
                else:
                    finding["severity"] = "MEDIUM"
                    finding["severity_validated"] = False
                finding["attack_vector"] = _text(verdict.get("attack_vector"))
                finding["exploitability"] = _text(verdict.get("exploitability"))
                finding["severity_rationale"] = _text(verdict.get("severity_rationale"))
                if not verdict.get("severity"):
                    finding["severity_validated"] = False
            else:
                # A rejected finding carries no severity. Dropping what the reviewer
                # claimed is the point: the "Not reported" table would otherwise print a
                # CRITICAL beside a finding the judge just called a false positive.
                for field in (
                    "severity",
                    "attack_vector",
                    "exploitability",
                    "severity_rationale",
                ):
                    finding.pop(field, None)

    unjudged: list[str] = []
    for key, finding in findings.items():
        if key in judged:
            continue
        if key in merged:
            # A duplicate is represented by its primary and is normally never printed — but
            # `findings_model.primaries()` resurrects one whose primary a judge rejected, and
            # a finding with no `fp_verdict` and no `severity_validated` defaults to
            # "survives, severity deliberately assigned". The reviewer's own guess is then
            # reported as judge-validated, with `unjudged: 0` and the only trace an empty
            # string in `verdict_counts`.
            finding.setdefault("fp_verdict", "LIKELY_TP")
            finding.setdefault("fp_rationale", REVIEWER_RATIONALE)
            finding["severity_validated"] = False
            continue
        if no_judge:
            reviewer_assigned = bool(finding.get("severity"))
            finding["fp_verdict"] = "LIKELY_TP"
            finding["fp_rationale"] = REVIEWER_RATIONALE
            finding["severity"] = finding.get("severity") or "MEDIUM"
            finding["severity_source"] = "reviewer"
            # True on purpose, and load-bearing: findings_model.reported_findings() exempts
            # every *unvalidated* finding from the severity filter, so leaving this False
            # here would make `--severity-filter high` quietly report LOW findings too.
            # "Validated" means "someone assigned this deliberately", not "a judge did" — so
            # it is False when NOBODY did: a reviewer that omitted `severity` got the MEDIUM
            # on the line above from this function, and stamping that validated drops the
            # finding out of `--severity-filter high` with no counter, no warning and no
            # marker. A promoted pointer is the same case: its LOW is a placeholder nobody
            # assessed.
            finding["severity_validated"] = reviewer_assigned and not finding.get("from_pointer")
            continue
        unjudged.append(key)
        finding["fp_verdict"] = "LIKELY_TP"
        finding["fp_rationale"] = UNJUDGED_RATIONALE
        finding["severity"] = "MEDIUM"
        finding["severity_validated"] = False
    return unjudged, ignored


def assign_ids(findings: dict[str, dict[str, Any]]) -> list[dict[str, Any]]:
    """Public ids, assigned here and nowhere else, after merging.

    Sorted by `(file, line, bug_class, title)` and numbered per class prefix, so the same
    inputs always give the same `BOF-001`. Ids are assigned to duplicates too: the report
    cites them in `also_known_as`, and a merged finding with no id could not be referenced
    at all.

    The line is sorted as an INTEGER. `pad3` is an id-suffix formatter and is wrong as a sort
    key: findings at 90, 142 and 1000 in one file number BOF-001@90, BOF-002@1000,
    BOF-003@142, so every C file over 999 lines gets ids and a report ordering that
    contradict the file.
    """
    ordered = sorted(
        findings.values(),
        key=lambda f: (f["file"], f["line"], f["bug_class"], f["title"]),
    )
    counters: dict[str, int] = {}
    for finding in ordered:
        prefix = CLASS_PREFIXES[finding["bug_class"]]
        counters[prefix] = counters.get(prefix, 0) + 1
        finding["id"] = f"{prefix}-{pad3(counters[prefix])}"
    return ordered


def link_merges(findings: dict[str, dict[str, Any]], merged: dict[str, str]) -> None:
    """Write `merged_into` and `also_known_as` in public ids, once those exist."""
    absorbed: dict[str, list[str]] = {}
    for dup_key, primary_key in merged.items():
        findings[dup_key]["merged_into"] = findings[primary_key]["id"]
        absorbed.setdefault(primary_key, []).append(findings[dup_key]["id"])
    for primary_key, ids in absorbed.items():
        findings[primary_key]["also_known_as"] = sorted(ids)


# ------------------------------------------------------------------ document


def _csv(value: str) -> list[str]:
    return [item.strip() for item in value.split(",") if item.strip()]


def run_ledger_gate(
    run_dir: Path, units_doc: dict[str, Any], allowed: set[str] | None = None
) -> tuple[dict[str, Any], Any]:
    """Run `check_ledger` in-process. Returns (summary for `run.ledger`, full gate report).

    In-process rather than as its own agent for the same reason `render_report` and
    `generate_sarif` are called here: it is deterministic code with no third-party
    dependencies, and an agent whose whole job is to shell out to a script is an agent that
    can forget to, summarise the output, or crash and take the report with it.

    NOTHING raises out of here. It still fails the run — `main` exits non-zero and every
    artifact carries "coverage is **unmeasured**" — but the artifacts are WRITTEN first, so
    one malformed unit in the gate's input cannot throw away a completed review. `except
    LedgerError` is not enough on its own: an `AttributeError` from one part file's
    `"ledger": {…}` object, a `ValueError` from a `max_unit_lines` of `"forty"` and a
    tree-sitter ABI mismatch (a `ValueError`, not an `ImportError`) all take the same route
    out, to exit 2 with zero artifacts.

    The full report goes back to the caller rather than to disk here. Written eagerly, a
    fresh `ledger-gate.json` lands beside the PREVIOUS run's findings.json whenever a later
    step fails, and on a gate that could not run at all the previous run's file stays in
    place still claiming 100%.
    """
    try:
        parts, _ = split_undispatched(
            check_ledger.load_parts(run_dir / "parts", PRODUCING_PREFIXES), allowed
        )
        report = check_ledger.check(check_ledger.attach_sites(units_doc), parts)
    except check_ledger.LedgerError as exc:
        return {"error": f"{exc}"}, None
    except Exception as exc:  # noqa: BLE001
        return {"error": f"unexpected {type(exc).__name__} in the coverage gate: {exc}"}, None
    # The module's own projection, not a second one written here: two definitions of the
    # gate summary would drift, and `run.ledger` is what the workflow reads back.
    return check_ledger._summary(report), report  # noqa: SLF001


def _clear_stale_artifacts(run_dir: Path) -> str:
    """Remove a PREVIOUS run's artifacts when this run is about to exit 2 having written none.

    `enumerate_units.write_outputs` clears these at the start of a full workflow run, which
    closes it for the workflow — but not for the path SKILL.md and the assemble prompt both
    send the reader down: re-running this script by hand. A good run, then a corrupt part
    file, then a hand re-assemble gives `rc=2`, "NO artifact was written", and `findings.json`,
    `REPORT.md` and `REPORT.sarif` all still holding run 1 — and the assemble agent, told to
    answer `artifacts_written` from what is actually in the directory, honestly reports `true`
    for a run that wrote nothing.

    Returns a sentence to append to the failure message, or "" — silently deleting a
    reader's files is worse than the state it fixes.
    """
    gone = []
    for name in ("findings.json", "REPORT.md", "REPORT.sarif", "ledger-gate.json"):
        path = run_dir / name
        try:
            if path.is_file():
                path.unlink()
                gone.append(name)
        except OSError:  # noqa: PERF203 - an artifact that cannot be removed is reported below
            gone.append(f"{name} (COULD NOT REMOVE)")
    if not gone:
        return ""
    return (
        f" A PREVIOUS run's artifacts were in {run_dir} and have been removed ("
        + ", ".join(gone)
        + "), because leaving them there reports one run's coverage as another's."
    )


def gate_failure(ledger: Any) -> str:
    """Why this run's coverage gate did not pass, or "" when it did.

    A gate that could not run at all and a gate that ran and rejected every single row are
    the same thing to a reader — nothing verified this review against the parse — so both
    are failures here.

    No `units.json` at all is a gate failure too. This script is also the documented
    hand-assembly path over part files alone, where there is no parse to measure against, but
    exit 0 is defined as "the artifacts were written AND the coverage gate accepted the
    ledger": returning "" there shows a human reading this script's own JSON summary
    unqualified success over a run nothing checked. The workflow is protected separately —
    `checks_required` comes back null and it refuses to report `gateAccepted` on a null.
    """
    if not isinstance(ledger, dict):
        return (
            "no units.json, so no coverage gate ran over this run — the artifacts are "
            "assembled but nothing measured them against a parse of the source"
        )
    if ledger.get("error"):
        return f"the coverage gate could not check this run — {ledger['error']}"
    missing = int(ledger.get("missing_row_count") or 0)
    violations = int(ledger.get("violation_count") or 0)
    # `unknown` and `malformed` belong here for the same reason `generate_sarif.lost_work`
    # already counts them, and their absence was the asymmetry: a ledger of rows over unit
    # ids the parse never produced satisfied every check it did claim, so this returned ""
    # and the run exited 0 — while REPORT.sarif, built from the same report, recorded
    # `executionSuccessful: false`.
    unknown = int(ledger.get("unknown_unit_count") or 0)
    malformed = int(ledger.get("malformed_row_count") or 0)
    if missing or violations or unknown or malformed:
        return (
            f"the coverage gate rejected this run's ledger: {missing} unanswered row(s), "
            f"{violations} violation(s), {unknown} row(s) naming a unit the parse never "
            f"produced, {malformed} unreadable field(s), "
            f"{ledger.get('checks_satisfied')} of {ledger.get('checks_required')} "
            f"required check(s) satisfied"
        )
    return ""


def build_document(
    ns: argparse.Namespace, got: Collected
) -> tuple[dict[str, Any], dict[str, int], Any]:
    """Assemble the whole result document. Returns (document, ignored counts, gate report).

    The gate report is returned rather than written: `main` writes it with the other three
    artifacts so a failure after this point cannot leave a fresh `ledger-gate.json` beside
    the previous run's `findings.json`, and cannot leave the previous run's clean sheet in
    place when this run's gate could not run at all.
    """
    run_dir: Path = ns.run_dir
    # A part the workflow certified complete (every returned finding carried every required
    # field) whose FILE nonetheless has incomplete findings is stale: the agent wrote the
    # file, its structured answer was rejected, it fixed the answer and never rewrote the
    # file. That is a different fault from an agent that genuinely had nothing to say, and
    # only the workflow's copy of the return can tell them apart.
    certified = set(getattr(ns, "expect_complete", None) or [])
    stale_parts = sorted(
        {entry.split("#", 1)[0] for entry in got.incomplete}
        & {stem.removesuffix(".json") for stem in certified}
    )
    detect = _optional_json(run_dir / "detect.json", "detect output")
    if detect is None:
        detect = {}
    if not isinstance(detect, dict):
        raise AssembleError(f"{run_dir / 'detect.json'}: expected a JSON object")
    raw_units = _optional_json(run_dir / "units.json", "unit list")
    units = raw_units if isinstance(raw_units, dict) else None
    # Every slice `enumerate_units.py` generated should have a `review-<id>` part file. The
    # workflow dispatches from the detect agent's TRANSCRIPTION of the assignment ids, so a
    # slice it failed to copy is never dispatched, gets no `--expect`, and its absence shows
    # up only as a drop in `checks_satisfied`. units.json is the code-generated list, so it
    # is the one place the drop can be named.
    dispatched = [
        str(a.get("id") or "")
        for a in ((units or {}).get("assignments") or [])
        if isinstance(a, dict)
    ]
    present = {entry["group"] for entry in got.externals}
    missing_slices = sorted(
        f"review-{aid}" for aid in dispatched if aid and f"review-{aid}" not in present
    )
    gate_report: Any = None
    if units is not None:
        ledger, gate_report = run_ledger_gate(
            run_dir, units, dispatched_stems(getattr(ns, "expect", None) or [])
        )
    elif raw_units is not None:
        # Unreported, a units.json whose root is a JSON array skips the gate silently and
        # exits 0 while `{}` and `{"units": []}` are fatal — the same corruption with
        # opposite outcomes depending on the root type.
        ledger = {"error": f"units.json is a {type(raw_units).__name__}, not an object"}
    else:
        # No unit list at all: the gate measures the ledger against a parse this run never
        # produced, so coverage is UNMEASURED. A `ledger-gate.json` an earlier run left in
        # this directory is NOT read back — nothing compares its unit ids, part list or
        # timestamp against this run, so honouring it reports a previous run's 100% as this
        # one's.
        ledger = None

    # Promote BEFORE any merging, so a promoted pointer is deduplicated on the same terms
    # as everything else and can never end up as a near-duplicate of the finding it was
    # meant to back up.
    promoted = promote_unclaimed_pointers(got.findings, got.pointers)
    for index, ptr in enumerate(promoted):
        key = f"pointer#{index}"
        got.findings[key] = normalize_finding(
            {
                "bug_class": FALLBACK_CLASS,
                "title": f"Unreviewed pointer: {ptr['note'][:80]}",
                "file": ptr["file"],
                "line": ptr["line"],
                "function": "",
                "confidence": "Low",
                "description": ptr["note"],
                "impact": "Not assessed — raised by a reviewer who did not own these lines.",
                "recommendation": "Review this location; no agent owned it and wrote it up.",
                "severity": "LOW",
            },
            ptr["from"],
            key,
        )
        got.findings[key]["from_pointer"] = True

    merged = tier1(got.findings)
    merged_auto = len(merged) + tier1_5(got.findings, merged)
    ignored_merges = apply_agent_merges(got.findings, merged, got.dedup)
    merged_agent = len(merged) - merged_auto
    unjudged_keys, ignored_verdicts = apply_verdicts(
        got.findings, merged, got.verdicts, no_judge=ns.no_judge
    )
    ordered = assign_ids(got.findings)
    link_merges(got.findings, merged)

    # Reported in public ids because that is what both consumers print beside a finding;
    # the keys are kept alongside so the warning can still be traced to a part file.
    unjudged_ids = sorted(got.findings[k]["id"] for k in unjudged_keys)

    doc: dict[str, Any] = {
        "run": {
            "threat_model": ns.threat_model,
            "severity_filter": ns.severity_filter,
            "finding_scope_root": ns.scope,
            "context_roots": ns.context_roots,
            "worker_model": ns.worker_model,
            # Only meaningful when a judge ran. Emitting `judge_mode: "batched"` next to
            # `judge_ran: false` reads as a judge that ran in batched mode and found
            # nothing to reject, which is the opposite of what happened.
            "judge_mode": None if ns.no_judge else ns.judge_mode,
            "judge_batch_size": None if ns.no_judge else ns.judge_batch_size,
            "output_dir": str(run_dir),
            "is_cpp": detect.get("is_cpp"),
            "is_posix": detect.get("is_posix"),
            "is_windows": detect.get("is_windows"),
            "platform_evidence": detect.get("platform_evidence", ""),
            "purpose": detect.get("purpose", ""),
            "entry_points": detect.get("entry_points", []),
            "trust_boundaries": detect.get("trust_boundaries", []),
            "existing_hardening": detect.get("existing_hardening", []),
            "groups_attempted": _csv(ns.groups_attempted),
            "groups_failed": _csv(ns.groups_failed),
            "judge_ran": not ns.no_judge,
            "incomplete_findings": got.incomplete,
            "pointers_seen": len(got.pointers),
            "pointers_promoted": len(promoted),
            "unjudged_findings": unjudged_ids,
            "unjudged_keys": sorted(unjudged_keys),
            "hunter_notes": got.notes,
            "hunter_external_sources": got.externals,
            "agent_failures": list(ns.agent_failure),
            # False when the assembler was run without --expect, i.e. nothing confirmed that
            # every dispatched agent actually wrote its part file. `agent_failures` and
            # `parts_read` then describe the disk, not the run, and an empty failure list
            # means "unchecked", not "none". See check_expectations.
            "expectations_checked": bool(ns.expect),
            # Parts whose file is provably behind the agent's own accepted return. Distinct
            # from `incomplete_findings`, which cannot tell a stale file from a thin one.
            "stale_part_files": stale_parts,
            "parts_read": [e["group"] for e in got.externals],
            # Slices units.json generated that no part file answers: code the partition
            # assigned to somebody and nobody reviewed.
            "missing_review_parts": missing_slices,
            "unrecognised_parts": sorted(got.unrecognised),
            "ledger": ledger,
            "units": units.get("totals") if units else None,
        },
        "stats": {},
        "findings": ordered,
        "coverage": got.coverage,
    }

    primaries = findings_model.primaries(doc)
    survivors = findings_model.survivors(doc)
    reported = findings_model.reported_findings(doc)
    verdict_counts: dict[str, int] = {}
    for finding in primaries:
        name = str(finding.get("fp_verdict", ""))
        verdict_counts[name] = verdict_counts.get(name, 0) + 1
    severity_counts: dict[str, int] = {}
    for finding in reported:
        name = str(finding.get("severity", ""))
        severity_counts[name] = severity_counts.get(name, 0) + 1

    doc["stats"] = {
        "raw_findings": len(ordered),
        "merged": len(merged),
        # Split so a reader can see how much of the dedup phase the agents were needed for.
        # `merged_auto` is what tiers 1 and 1.5 settled deterministically and for free;
        # `merged_agent` is what cost a spawn. If the second stays near zero the phase can go.
        "merged_auto": merged_auto,
        "merged_agent": merged_agent,
        "primaries": len(primaries),
        "survivors": len(survivors),
        "reported": len(reported),
        "producing_parts": len(got.externals),
        "dedup_agents": len(got.dedup),
        "judge_agents": len(got.verdicts),
        "verdict_counts": dict(sorted(verdict_counts.items())),
        "severity_counts": dict(sorted(severity_counts.items())),
    }
    counts = {
        "unjudged": len(unjudged_keys),
        "ignored_merges": ignored_merges,
        "ignored_verdicts": ignored_verdicts,
        "unrecognised_parts": len(got.unrecognised),
        "ignored_fields": len(got.ignored_fields),
    }
    return doc, counts, gate_report


# ------------------------------------------------------------------ cli


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--run-dir", required=True, type=Path)
    # Both are recorded verbatim in findings.json and both are silently normalised
    # downstream, so an unvalidated value put a filter in `run.severity_filter` that never
    # ran and a threat model in the report header that means nothing.
    parser.add_argument(
        "--threat-model", required=True, choices=["REMOTE", "LOCAL_UNPRIVILEGED", "BOTH"]
    )
    parser.add_argument("--severity-filter", required=True, choices=["all", "medium", "high"])
    parser.add_argument("--scope", default=".")
    parser.add_argument(
        "--scope-abs",
        default=None,
        dest="scope_abs",
        help=(
            "the absolute spelling of --scope, resolved by the CALLER. The workflow's "
            "`normalizePath` cannot touch the filesystem, so resolving `src` here instead "
            "would leave the two normalisers stripping different strings and disagreeing "
            "about which findings merge. Pass it empty to say no absolute root is known. "
            "Omitted entirely (hand re-assembly), --scope is resolved against the cwd."
        ),
    )
    parser.add_argument("--context-roots", default=".")
    parser.add_argument("--worker-model", default="inherit")
    parser.add_argument("--judge-mode", default="batched")
    parser.add_argument("--judge-batch-size", type=int, default=5)
    parser.add_argument(
        "--no-judge",
        action="store_true",
        help=(
            "no false-positive/severity judge was dispatched: the reviewer's own severity is "
            "authoritative and nothing is reported as unjudged. Omit it to reproduce the "
            "judged configuration, in which a primary with no verdict is a judge failure."
        ),
    )
    parser.add_argument(
        "--expect",
        action="append",
        default=[],
        help=(
            "part id that must be present, optionally as ID=COUNT to also assert the "
            "number of findings in it (repeatable); a mismatch is a hard failure"
        ),
    )
    parser.add_argument(
        "--benchmark-mode",
        action="store_true",
        help="the run asked every reviewer to declare external sources (the workflow's "
        "`benchmarkMode`). Recorded per part as `declared`, so scoring can tell a clean "
        "declaration from a question that was never posed.",
    )
    parser.add_argument("--groups-attempted", default="")
    parser.add_argument("--groups-failed", default="")
    parser.add_argument("--agent-failure", action="append", default=[])
    parser.add_argument(
        "--expect-complete",
        action="append",
        default=[],
        dest="expect_complete",
        help="part stem whose RETURNED findings all carried every required field. Its file "
        "having incomplete findings therefore means the file is stale — written before a "
        "rejected structured answer was retried — not that the agent had nothing to say.",
    )
    parser.add_argument(
        "--external-source",
        action="append",
        default=[],
        dest="external_source",
        metavar="ID=0|1",
        help="the external-source declaration a part gave through the SCHEMA (repeatable). "
        "The part file can disagree with the accepted return — same staleness `--expect` "
        "exists for — so a `1` from either source counts as consulted.",
    )
    ns = parser.parse_args(argv)

    # Both spellings, absolute first, and never one derived here when the caller named it:
    # the workflow strips exactly this pair and the two sides have to stay identical.
    if ns.scope_abs is None:
        try:
            scope_abs = str(Path(ns.scope).resolve())
        except OSError:
            scope_abs = ns.scope
    else:
        scope_abs = ns.scope_abs
    scope_root = tuple(dict.fromkeys(r for r in (scope_abs, ns.scope) if r))
    try:
        parts = load_parts(ns.run_dir)
        check_expectations(ns.expect, parts, ns.run_dir, ns.agent_failure)
        parts, ghost_parts = split_undispatched(parts, dispatched_stems(ns.expect))
        require_producing_part(parts, ghost_parts, ns.run_dir / "parts")
        # `verdict-` is not in ALWAYS_ALLOWED_STEMS and `--expect` is mandatory for exit 0,
        # so the judged configuration — the one the `--no-judge` help advertises — has
        # exactly one way to allowlist a verdict part: `--expect verdict-NN`. Say so here,
        # because a judge part nobody named is otherwise dropped in silence, its rejections
        # discarded and its findings shipped as survivors.
        dropped_verdicts = sorted(s for s in ghost_parts if s.startswith(VERDICT_PREFIX))
        if dropped_verdicts and not ns.no_judge:
            raise AssembleError(
                f"judge part file(s) {', '.join(dropped_verdicts)} are in "
                f"{ns.run_dir / 'parts'} but were not named in --expect, so every verdict in "
                f"them would be discarded and their findings would ship as survivors. Pass "
                f"--expect for each of them, or --no-judge if no judge ran."
            )
        got = collect(
            parts, ns.benchmark_mode, _external_declarations(ns.external_source), scope_root
        )
        # Reported through the same field a misnamed stem uses: their contents are in no
        # artifact, and a part nobody dispatched is exactly as much of a bookkeeping fault
        # as a part nobody reads.
        got.unrecognised.extend(ghost_parts)
        doc, counts, gate_report = build_document(ns, got)
        # Both artifacts are rendered BEFORE either is written. Written findings.json first,
        # a generator that raises leaves this run's findings on disk beside the PREVIOUS
        # run's REPORT.sarif — two files describing different runs, and an exit code that
        # says nothing about which.
        report_md = render_report.render(doc)
        report_sarif = json.dumps(generate_sarif.build_sarif(doc), indent=2) + "\n"
    except AssembleError as exc:
        print(f"assemble_findings: {exc}{_clear_stale_artifacts(ns.run_dir)}", file=sys.stderr)
        return 2
    except Exception as exc:  # noqa: BLE001
        # Exit 1 means "assembled but unverified — the artifacts are complete, do not
        # re-run". An uncaught traceback also exits 1, and the caller then tells the user
        # exactly that over an empty directory. Nothing has been written here, so this is a
        # 2, and the part files it names are still recoverable.
        print(
            f"assemble_findings: unexpected {type(exc).__name__}: {exc}. NO artifact was "
            f"written; the part files under {ns.run_dir / 'parts'} are intact and this run "
            f"can be re-assembled once the malformed part is fixed."
            + _clear_stale_artifacts(ns.run_dir),
            file=sys.stderr,
        )
        return 2

    if doc["run"].get("stale_part_files"):
        # Louder than the generic incomplete warning below, because this one has a known
        # cause and a known fix: the file on disk is an earlier draft than the answer the
        # agent actually returned.
        print(
            "assemble_findings: WARNING: STALE part file(s) "
            + ", ".join(doc["run"]["stale_part_files"])
            + " — the agent's accepted return carried every required field but the file on "
            "disk does not, so the file was written before a rejected structured answer was "
            "retried and never rewritten. Those findings are degraded on disk only.",
            file=sys.stderr,
        )

    if got.incomplete:
        # Loud, and in the document. An agent that omits `description` while returning it
        # through its schema produces findings that state a location and no defect; the
        # bench collector rejects such a document outright, and a user reading REPORT.md
        # would see an empty finding and assume the tool had nothing to say.
        print(
            f"assemble_findings: WARNING: {len(got.incomplete)} finding(s) are missing "
            f"required field(s) — the agent dropped them when writing its part file: "
            + "; ".join(got.incomplete[:10])
            + (" …" if len(got.incomplete) > 10 else ""),
            file=sys.stderr,
        )

    if got.unrecognised:
        print(
            "assemble_findings: WARNING: no rule reads part file(s) "
            f"{', '.join(got.unrecognised)} — their contents are not in the report",
            file=sys.stderr,
        )

    if got.ignored_fields:
        print(
            "assemble_findings: WARNING: list field(s) "
            + ", ".join(got.ignored_fields)
            + " are present with the wrong type and were dropped — that agent's rows are "
            "in no artifact and the run reads exactly like one where it had nothing to say",
            file=sys.stderr,
        )

    findings_json = ns.run_dir / "findings.json"
    outputs: list[tuple[Path, str]] = [
        (findings_json, json.dumps(doc, indent=2, ensure_ascii=False) + "\n"),
        (ns.run_dir / "REPORT.md", report_md),
        (ns.run_dir / "REPORT.sarif", report_sarif),
        # Written HERE, with the rest, rather than eagerly inside the gate. See
        # `run_ledger_gate`.
        (
            ns.run_dir / "ledger-gate.json",
            json.dumps(
                gate_report
                if gate_report is not None
                else {"error": gate_failure(doc["run"].get("ledger")) or "the gate did not run"},
                indent=2,
            )
            + "\n",
        ),
    ]
    # Staged, then renamed, and inside a `try`: an ENOSPC, a read-only output directory or a
    # run dir removed mid-run otherwise escapes as a traceback and exits 1 — which the
    # workflow prompt and SKILL.md both define as "everything WAS written, do not re-run" —
    # over a findings.json holding this run beside a REPORT.sarif holding the last one.
    # `Path.replace` is atomic within a filesystem, so the window between the four is as
    # small as this can be made without a transaction.
    staged: list[tuple[Path, Path]] = []
    # (backup or None, destination) for every rename already done, so a failure part-way
    # through can be undone. Without the rollback the message below still promises "NO
    # artifact was replaced" while a PermissionError on the third of four renames — a macOS
    # `uchg` flag, an ACL denying delete, an EACCES from an NFS mount — leaves run 2's
    # findings.json and REPORT.md beside run 1's REPORT.sarif and ledger-gate.json at exit 2.
    # Two artifacts describing different runs is precisely the state the staging exists to
    # make impossible.
    replaced: list[tuple[Path | None, Path]] = []
    try:
        # A destination that is a DIRECTORY is refused up front rather than rolled back:
        # the rollback moves the old artifact aside and back, and a directory moved aside
        # is not something this should be doing on a path it does not own.
        #
        # The STAGING paths are checked too. `<artifact>.partial` is a fixed, predictable
        # path inside a directory every producing worker can write to, so a stale
        # `REPORT.sarif.partial` DIRECTORY is agent-plantable: `tmp.write_text` raises
        # IsADirectoryError, the rollback raises PermissionError unlinking it, and that
        # escapes `main()` as exit 1 — "everything WAS written, do not re-run" — over a
        # directory missing artifacts.
        for path, _ in outputs:
            for candidate in (path, path.with_name(path.name + ".partial")):
                if candidate.is_dir():
                    raise IsADirectoryError(
                        f"{candidate} is a directory, so it cannot be written or replaced"
                    )
        for path, text in outputs:
            tmp = path.with_name(path.name + ".partial")
            # Appended BEFORE the write, so a `write_text` that creates and truncates the
            # file and then fails — ENOSPC — still has its staging file cleaned up.
            staged.append((tmp, path))
            tmp.write_text(text, encoding="utf-8")
        for tmp, path in staged:
            backup = path.with_name(path.name + ".prev")
            if path.exists():
                path.replace(backup)
                replaced.append((backup, path))
            else:
                replaced.append((None, path))
            tmp.replace(path)
    except (OSError, ValueError) as exc:
        # `ValueError` as well as `OSError`, for `UnicodeEncodeError`: `json.loads` decodes
        # `\ud800` in a part file into a LONE SURROGATE and `write_text(encoding="utf-8")`
        # then raises a ValueError, which misses an OSError-only handler, escapes `main()`
        # and exits 1 — the code the workflow and SKILL.md define as "everything WAS written,
        # do not re-run" — over a directory still holding the PREVIOUS run's four artifacts.
        #
        # Every step of the rollback below is guarded for the same reason: unguarded file I/O
        # here propagates out of `main()` to that same exit 1, over a directory MISSING
        # artifacts and with no `assemble_findings:` line printed at all. And it restores with
        # `backup.replace(path)` alone — `Path.replace` overwrites atomically, so a preceding
        # `path.unlink()` buys nothing and destroys the artifact it is restoring if it fails
        # between the two.
        undo_failed: list[str] = []
        for backup, path in replaced:
            try:
                if backup is not None:
                    backup.replace(path)
                else:
                    path.unlink(missing_ok=True)
            except OSError as undo:
                undo_failed.append(f"{path.name} ({undo})")
        for tmp, _ in staged:
            try:
                tmp.unlink(missing_ok=True)
            except OSError:  # noqa: PERF203 - a leftover .partial is litter, not a failure
                pass
        print(
            f"assemble_findings: {type(exc).__name__} writing the artifacts ({exc}). "
            + (
                f"THE OUTPUT DIRECTORY IS INCONSISTENT: {len(undo_failed)} artifact(s) could "
                f"not be rolled back — {'; '.join(undo_failed)}. Any `.prev` file left in "
                f"{ns.run_dir} is the previous run's copy of the artifact beside it. "
                if undo_failed
                # Exit 2 means "no artifact was written", and the rollback has just put the
                # PREVIOUS run's four artifacts back — which `c-review.js` then has the
                # assemble agent answer `artifacts_written` from, honestly reporting `true`
                # for a run that wrote nothing. Only when the rollback succeeded: a
                # half-rolled-back directory is inconsistent and its `.prev` files are the
                # only copy left.
                else "NO artifact was replaced." + _clear_stale_artifacts(ns.run_dir) + " "
            )
            + f"The part files under {ns.run_dir / 'parts'} are intact and this run can be "
            f"re-assembled once the output directory is writable.",
            file=sys.stderr,
        )
        return 2
    for backup, _ in replaced:
        if backup is not None:
            backup.unlink(missing_ok=True)

    # Every gate failure (see `gate_failure`) is reported AFTER the artifacts are on disk.
    # Exit 1 is "assembled, but unverified"; exit 2 is still "nothing was assembled".
    failure = gate_failure(doc["run"].get("ledger"))
    if not ns.expect:
        # A checker handed zero items must not report success. With no `--expect` the
        # allowlist admits every file under `parts/`, so a `parts/sweep-ghost.json` nobody
        # dispatched contributes half of a run's certified coverage and a CRITICAL to
        # REPORT.md at `ok: true`, exit 0 — which is what the workflow and any CI wrapper key
        # off. The warning, the `expectations_checked: false` field and the SARIF
        # notification all fire on that run, and not one of them changes an exit code.
        failure = failure or (
            "no --expect was given, so nothing verified which parts this run dispatched: "
            "every file under parts/ was read and no missing part could be detected"
        )
    print(
        json.dumps(
            {
                "ok": not failure,
                "artifacts_written": True,
                "gate_error": failure or None,
                "findings_json": str(findings_json),
                "report_md": str(ns.run_dir / "REPORT.md"),
                "report_sarif": str(ns.run_dir / "REPORT.sarif"),
                "stats": doc["stats"],
                # Lifted out of run.ledger so the workflow can read coverage back without
                # re-parsing the whole document. `checks_satisfied` is the strict number.
                "checks_required": (doc["run"].get("ledger") or {}).get("checks_required"),
                "checks_completed": (doc["run"].get("ledger") or {}).get("checks_completed"),
                "checks_satisfied": (doc["run"].get("ledger") or {}).get("checks_satisfied"),
                **counts,
            },
            indent=2,
        )
    )
    if failure:
        print(
            f"assemble_findings: {failure}. findings.json, REPORT.md and REPORT.sarif WERE "
            f"written and all three say coverage is unverified; do not re-run.",
            file=sys.stderr,
        )
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
