#!/usr/bin/env python3
# /// script
# requires-python = ">=3.11"
# dependencies = []
# ///
"""Assemble findings.json, REPORT.md and REPORT.sarif from the per-agent part files.

This script exists because of one measured defect. The previous last phase embedded the
entire findings payload as JSON in a prompt and asked a single agent to copy it verbatim
into a heredoc. Across four measured cells it was faithful at 15 and 25 findings and
destroyed the document at 75 and 86 — every evidence field (`description`, `code`,
`impact`, `recommendation`, `function`, `found_by`) stripped from 22 and 23 of the 23
findings that survived at all — and one run shipped an **empty** findings array while its
own stats block read `reported: 14`, two CRITICAL. The failure scales with the pipeline's
own success: the more the hunters find, the more certain the user gets nothing.

The fix is structural, not a better prompt. Each producing agent writes only its own small
result to `<run-dir>/parts/`, and this script joins them. No agent ever retypes the corpus,
so no amount of finding volume can degrade the artifact.

Everything here is deterministic — parts are read in sorted filename order, ids are derived
from sorted content, and nothing consults the clock or a random source. Re-running over the
same directory must produce byte-identical output, because the workflow engine replays this
step on resume and a resumed run that renumbers its findings is worse than one that fails.

Usage:
    uv run assemble_findings.py --run-dir RUNDIR --threat-model REMOTE --severity-filter all
"""

from __future__ import annotations

import argparse
import contextlib
import json
import math
import re
import sys
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
PRODUCING_PREFIXES = ("review-", "second-", "invariant-", "sweep-")
DEDUP_PREFIX = "dedup-"
VERDICT_PREFIX = "verdict-"

CONFIDENCE_RANK = {"High": 3, "Medium": 2, "Low": 1}
SURVIVOR_VERDICTS = frozenset({"TRUE_POSITIVE", "LIKELY_TP"})
SEVERITY_LEVELS = frozenset({"CRITICAL", "HIGH", "MEDIUM", "LOW"})
UNJUDGED_RATIONALE = "JUDGE DID NOT RUN — verdict and severity are unvalidated"
REVIEWER_RATIONALE = (
    "reviewer-reported; no independent false-positive review ran in this configuration"
)
MARKDOWN_LINK = re.compile(r"\[([^\]]+)\]\([^)]*\)")

# Fields a finding is useless without. The workflow's schema already requires them of the
# value an agent *returns*, but the part file is written by hand afterwards, and a measured
# run showed one review agent omitting `description` from all nine of its findings while its
# schema return carried it. The count check (`--expect ID=COUNT`) cannot see that: the count
# was right. Silence here would ship nine findings with no statement of what is wrong.
REQUIRED_FINDING_FIELDS = ("title", "file", "line", "description", "impact", "recommendation")

# Tier 1.5: two findings in one function, within this many lines of each other, are the same
# bug described twice — including when they were filed under different bug classes, which is
# the case tier 1's exact `(file, line, bug_class)` match cannot see. The window is short on
# purpose: it is a deterministic substitute for a dedup agent, not a replacement for one, and
# a wide window merges two genuinely distinct bugs that happen to share a few lines.
NEARBY_LINES = 3

# How far apart two findings of DIFFERENT `bug_class` may sit and still be merged
# deterministically. Zero means "the same line, or not at all".
#
# Measured, not tuned (see tools/c-review-bench/MEASUREMENTS.md): correct cross-class merges
# — one defect filed twice under two labels — land on the SAME line, because both reviewers
# point at the same statement. Every cross-class merge at a non-zero distance that could be
# checked joined two different bugs, and two of them cost a ground-truth bug outright.
#
# Same-class pairs keep the full NEARBY_LINES window; no measured same-class merge was wrong.
# A cross-class pair one to three lines apart is not refused, only left unmerged for the dedup
# agent, which reads both write-ups instead of guessing from a line distance.
CROSS_CLASS_NEARBY_LINES = 0

FUNCTION_SEPARATORS = re.compile(r"[-_\s]+")
# Ported verbatim from the JS workflow's NO_FUNCTION. A file-level finding has no enclosing
# function to share, so it never merges on the tier-1.5 rule — "both are file-level" says
# nothing about whether they are the same bug.
NO_FUNCTION = frozenset(
    {"", "-", "none", "n/a", "na", "file-level", "(file-level)", "filelevel", "file level"}
)

# The consolidated 56-class catalogue (66 -> 56, see tools/c-review-bench/MEASUREMENTS.md). It is
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
    act on. This cost a real run a HARD true positive: two agents pinned an
    encoding-invariant bug at `src/path.c:55` in `sgl_scope_set`, a third reported the
    same defect at `src/path.c:9` as `(file-level)`, and because that third had the
    lexicographically smallest key it became the primary. The merged finding then sat
    46 lines from the bug, outside the grader's window, and scored SUPPRESSED — one bug
    lost entirely to plumbing.
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
    context. That saves a great deal of duplicated work — measured, it removed a line being
    written up five times over — but it is only safe if a pointer the owner then missed
    still reaches the report.

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
        if near or not ptr["file"]:
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


def normalize_path(value: Any) -> str:
    """Port of the workflow's `normalizePath`.

    Agents hand back `[src/parse.c](src/parse.c)`, `./src/parse.c` and `src//parse.c` for the
    same file. Collapsing them here is what makes the tier-1 `(file, line, bug_class)` merge
    and the SARIF URIs agree; without it the same bug filed twice reads as two locations.
    """
    text = str("" if value is None else value).replace("\\", "/").strip()
    link = MARKDOWN_LINK.fullmatch(text)
    if link:
        text = link.group(1)
    while text.startswith("./"):
        text = text[2:]
    while "//" in text:
        text = text.replace("//", "/", 1)
    return text


def pad3(value: Any) -> str:
    text = str(value)
    return text if len(text) >= 3 else "0" * (3 - len(text)) + text


def _line(value: Any) -> int:
    """A missing, non-numeric or non-positive line becomes 1, as the workflow does.

    Line 1 is wrong but locatable; dropping the finding, or emitting `null`, is not. SARIF
    consumers reject a zero or negative `startLine` outright.
    """
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return 1
    if not math.isfinite(value) or value <= 0:
        return 1
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


def reviewer_severity(value: Any) -> str:
    """The reviewer's own severity, upper-cased; "" when absent or not one of the four.

    An unrecognised label is dropped rather than carried, because `findings_model` scores an
    unknown severity as 0: a finding whose reviewer typed `Critical!!` would then be filtered
    out by `--severity-filter high`. The MEDIUM default that replaces it is visible instead.
    """
    text = _text(value).strip().upper()
    return text if text in SEVERITY_LEVELS else ""


def normalize_finding(raw: dict[str, Any], part_id: str, key: str) -> dict[str, Any]:
    """One part-file finding as it appears in findings.json.

    An unrecognised `bug_class` becomes `logic-flaw` and the original is preserved in
    `reported_bug_class`: a class the catalogue does not know has no id prefix and no SARIF
    rule, and silently dropping the finding to avoid that would lose a real bug over a typo.

    `severity`, `attack_vector` and `exploitability` are the reviewer's own assessment and are
    only set when the reviewer supplied one. Absence is meaningful downstream: a finding a
    judge rejects must carry no severity at all, and a key that is always present could not
    say that.
    """
    reported_class = raw.get("bug_class")
    bug_class = reported_class if reported_class in CLASS_PREFIXES else FALLBACK_CLASS
    reviewer_fields = {
        "severity": reviewer_severity(raw.get("severity")),
        "attack_vector": _text(raw.get("attack_vector")).strip(),
        "exploitability": _text(raw.get("exploitability")).strip(),
    }
    return {
        "key": key,
        "bug_class": bug_class,
        "reported_bug_class": _text(reported_class),
        "title": _text(raw.get("title")) or "untitled",
        "file": normalize_path(raw.get("file")),
        "line": _line(raw.get("line")),
        "function": _text(raw.get("function") or "(file-level)").strip(),
        "unit_id": _text(raw.get("unit_id")),
        "confidence": (
            raw.get("confidence") if raw.get("confidence") in CONFIDENCE_RANK else "Medium"
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
    except json.JSONDecodeError as exc:
        raise AssembleError(f"{label} {path} is not valid JSON ({exc})") from exc
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
    # Same rule one level down. Counting *files* passes when every review and sweep agent
    # died and only `detect` wrote one: the run then assembles to `producing_parts: 0`,
    # zero findings, zero coverage rows, exit 0 and a clean REPORT.md that says the review
    # found nothing. A reader cannot tell that apart from a clean codebase, and a benchmark
    # collector records it as a zero-recall result for the tool rather than a failed run.
    if not any(path.stem.startswith(PRODUCING_PREFIXES) for path in paths):
        raise AssembleError(
            f"{parts_dir} holds {len(paths)} part file(s) but none of them is a producing "
            f"part ({', '.join(PRODUCING_PREFIXES)}) — no agent reviewed any code. Found: "
            f"{', '.join(sorted(p.stem for p in paths))}. Refusing to write a report that "
            f"would read as 'no findings'."
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


def check_expectations(
    expected: list[str], parts: list[tuple[str, dict[str, Any]]], run_dir: Path
) -> None:
    """Assert every part the workflow dispatched arrived, and arrived whole.

    `ID` alone catches an agent that never wrote. `ID=COUNT` catches the failure this
    whole design exists to remove: an agent that wrote a file but summarised its own
    output on the way. The workflow knows the count because it received the same
    findings through the schema, so a part file shorter than its return value is a
    detectable lie rather than a quietly shorter report.
    """
    if not expected:
        # A checker handed zero items must not report success. The workflow always passes
        # one `--expect` per dispatched part, so an empty list means this is a hand
        # assembly — the documented recovery path when the assemble agent dies. That path
        # silently drops the workflow's bookkeeping: on the 2026-08-07 slice cell one
        # review agent never wrote its part file, the workflow logged the gap, and the
        # hand-assembled document then reported `agent_failures: []` and a full
        # `parts_read`, which reads as a clean 13-slice run rather than a 12-slice one.
        # Nothing here can recover the expectation, so the document must say it was never
        # checked rather than let an empty failure list be read as no failures.
        print(
            "assemble_findings: WARNING: no --expect given, so NOTHING verified that every "
            "dispatched agent wrote its part file. `run.agent_failures` and `run.parts_read` "
            "below describe only what is on disk. If this is a hand assembly after an "
            "assemble-agent failure, read the workflow's own log for the dispatched part "
            "list before trusting coverage.",
            file=sys.stderr,
        )

    by_stem = {stem: doc for stem, doc in parts}
    missing: list[str] = []
    short: list[str] = []
    over: list[str] = []
    for item in expected:
        name, _, count_text = item.partition("=")
        stem = name.removesuffix(".json")
        if stem not in by_stem:
            missing.append(stem)
            continue
        if not count_text:
            continue
        try:
            wanted = int(count_text)
        except ValueError as exc:
            raise AssembleError(f"--expect {item!r}: {count_text!r} is not an integer") from exc
        got = len(by_stem[stem].get("findings") or [])
        # Directional on purpose. The part FILE is the artifact; the returned count is a
        # cross-check against summarisation on the way to disk, so only `part < returned`
        # is evidence of loss. The symmetric version killed a real run: an invariant-sweep
        # agent wrote nine findings to disk and returned zero (reading `findings` as "what
        # I am returning inline", a defensible reading of an ambiguous contract), and the
        # assembler threw away nine good findings over a disagreement in the safe
        # direction. Over-delivery is logged, never fatal.
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
    sites = [n for n in (row.get("sites_accounted") or []) if isinstance(n, int)]
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


def collect(parts: list[tuple[str, dict[str, Any]]]) -> Collected:
    """Split the parts by role and normalise every producing part's findings.

    A finding's stable identity is `<part file stem>#<index>` — derived from the filename,
    never from the `part_id` field inside the file, so a field an agent mistyped cannot break
    the mapping that dedup and judge verdicts reference.
    """
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
                got.findings[key] = normalize_finding(raw, stem, key)
            for index, row in enumerate(doc.get("ledger") or []):
                if not isinstance(row, dict):
                    raise AssembleError(
                        f"part {stem}: ledger[{index}] is {type(row).__name__}, expected an object"
                    )
                got.coverage.append(_coverage_row(stem, row))
            got.externals.append(
                {
                    "group": stem,
                    "consulted": doc.get("external_sources_consulted") is True,
                    "detail": _text(doc.get("external_sources_detail")) or "none",
                }
            )
            for raw_ptr in doc.get("pointers") or []:
                if not isinstance(raw_ptr, dict):
                    continue
                got.pointers.append(
                    {
                        "file": normalize_path(raw_ptr.get("file")),
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

    A merge is ignored when either side is a key that does not exist or has already been
    merged. Chaining is what that second rule prevents: if `merged_into` could point at a
    finding that is itself merged, the report would show a primary that is not in the
    reported set, and `also_known_as` would not round-trip.
    """
    ignored = 0
    for _stem, doc in dedup_parts:
        for merge in doc.get("merges") or []:
            if not isinstance(merge, dict):
                ignored += 1
                continue
            stated = str(merge.get("primary") or "")
            duplicates = [str(d) for d in (merge.get("duplicates") or [])]
            if stated not in findings or stated in merged:
                ignored += max(1, len(duplicates))
                continue
            live = [stated] + [
                d for d in duplicates if d != stated and d in findings and d not in merged
            ]
            ignored += len(duplicates) - (len(live) - 1)
            if len(live) < 2:
                continue
            # Re-elect rather than trusting the agent's choice. The agent is asked to
            # prefer the higher-confidence member and knows nothing about how the site
            # will be graded, so it can and does nominate a `(file-level)` report over
            # two that named the function and the exact line.
            primary = min(live, key=lambda k: _election_key(findings, k))
            for member in live:
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
        for verdict in doc.get("verdicts") or []:
            if not isinstance(verdict, dict):
                ignored += 1
                continue
            key = str(verdict.get("key") or "")
            name = _text(verdict.get("fp_verdict"))
            if key not in findings or key in merged or key in judged or not name:
                ignored += 1
                continue
            judged.add(key)
            finding = findings[key]
            finding["fp_verdict"] = name
            finding["fp_rationale"] = _text(verdict.get("fp_rationale"))
            finding["severity_validated"] = True
            if name.upper() in SURVIVOR_VERDICTS:
                finding["severity"] = _text(verdict.get("severity")) or "MEDIUM"
                finding["attack_vector"] = _text(verdict.get("attack_vector"))
                finding["exploitability"] = _text(verdict.get("exploitability"))
                finding["severity_rationale"] = _text(verdict.get("severity_rationale"))
                if not verdict.get("severity"):
                    finding["severity_validated"] = False
            else:
                # A rejected finding carries no severity. Dropping what the reviewer
                # claimed is the point: the "Not reported" table would otherwise print a
                # CRITICAL beside a finding the judge just called a false positive.
                for field in ("severity", "attack_vector", "exploitability"):
                    finding.pop(field, None)

    unjudged: list[str] = []
    for key, finding in findings.items():
        if key in merged or key in judged:
            continue
        if no_judge:
            finding["fp_verdict"] = "LIKELY_TP"
            finding["fp_rationale"] = REVIEWER_RATIONALE
            finding["severity"] = finding.get("severity") or "MEDIUM"
            finding["severity_source"] = "reviewer"
            # True on purpose, and load-bearing: findings_model.reported_findings() exempts
            # every *unvalidated* finding from the severity filter, so leaving this False
            # here would make `--severity-filter high` quietly report LOW findings too.
            # "Validated" means "someone assigned this deliberately", not "a judge did".
            finding["severity_validated"] = True
            continue
        unjudged.append(key)
        finding["fp_verdict"] = "LIKELY_TP"
        finding["fp_rationale"] = UNJUDGED_RATIONALE
        finding["severity"] = "MEDIUM"
        finding["severity_validated"] = False
    return unjudged, ignored


def assign_ids(findings: dict[str, dict[str, Any]]) -> list[dict[str, Any]]:
    """Public ids, assigned here and nowhere else, after merging.

    Sorted by `(file, padded line, bug_class, title)` and numbered per class prefix, so the
    same inputs always give the same `BOF-001`. Ids are assigned to duplicates too: the
    report cites them in `also_known_as`, and a merged finding with no id could not be
    referenced at all.
    """
    ordered = sorted(
        findings.values(),
        key=lambda f: (f["file"], pad3(f["line"]), f["bug_class"], f["title"]),
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


def run_ledger_gate(run_dir: Path, units_doc: Any) -> Any:
    """Run `check_ledger` in-process and return the compact summary for `run.ledger`.

    In-process rather than as its own agent for the same reason `render_report` and
    `generate_sarif` are called here: it is deterministic code with no third-party
    dependencies, and an agent whose whole job is to shell out to a script is an agent that
    can forget to, summarise the output, or crash and take the report with it.

    A gate that cannot run is *reported*, never fatal. `LedgerError` means there was nothing
    to check — no units, no rows — which says nothing about whether the findings are worth
    shipping. The failure has to be visible in `run.ledger.error` and on stderr, because a
    silently absent gate reads exactly like a gate that passed.
    """
    try:
        parts = check_ledger.load_parts(run_dir / "parts", PRODUCING_PREFIXES)
        report = check_ledger.check(units_doc, parts)
    except check_ledger.LedgerError as exc:
        print(f"assemble_findings: WARNING: ledger gate did not run — {exc}", file=sys.stderr)
        return {"error": str(exc)}
    (run_dir / "ledger-gate.json").write_text(json.dumps(report, indent=2), encoding="utf-8")
    # The module's own projection, not a second one written here: two definitions of the
    # gate summary would drift, and `run.ledger` is what the workflow reads back.
    return check_ledger._summary(report)  # noqa: SLF001


def build_document(ns: argparse.Namespace, got: Collected) -> tuple[dict[str, Any], dict[str, int]]:
    """Assemble the whole result document. Returns (document, ignored counts)."""
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
    units = _optional_json(run_dir / "units.json", "unit list")
    if isinstance(units, dict):
        ledger = run_ledger_gate(run_dir, units)
    else:
        # No unit list is a legitimate configuration, not a failure: the gate measures the
        # ledger against a parse that this run may never have produced. An answer someone
        # else already left on disk is still honoured.
        ledger = _optional_json(run_dir / "ledger-gate.json", "ledger gate")

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
            "unrecognised_parts": sorted(got.unrecognised),
            "ledger": ledger,
            "units": units.get("totals") if isinstance(units, dict) else None,
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
    }
    return doc, counts


# ------------------------------------------------------------------ cli


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--run-dir", required=True, type=Path)
    parser.add_argument("--threat-model", required=True)
    parser.add_argument("--severity-filter", required=True)
    parser.add_argument("--scope", default=".")
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
    ns = parser.parse_args(argv)

    try:
        parts = load_parts(ns.run_dir)
        check_expectations(ns.expect, parts, ns.run_dir)
        got = collect(parts)
        doc, counts = build_document(ns, got)
    except AssembleError as exc:
        print(f"assemble_findings: {exc}", file=sys.stderr)
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

    findings_json = ns.run_dir / "findings.json"
    findings_json.write_text(json.dumps(doc, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")

    # The generators log to stdout; stdout here is a machine-readable summary, so their
    # chatter goes to stderr and the caller can parse what it reads.
    args = ["--findings", str(findings_json), "--output-dir", str(ns.run_dir)]
    with contextlib.redirect_stdout(sys.stderr):
        rc = render_report.main(args)
        if rc == 0:
            rc = generate_sarif.main(args)
    if rc != 0:
        print(f"assemble_findings: artifact generation failed (exit {rc})", file=sys.stderr)
        return rc

    print(
        json.dumps(
            {
                "ok": True,
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
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
