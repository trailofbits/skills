#!/usr/bin/env python3
# /// script
# requires-python = ">=3.11"
# dependencies = []
# ///
"""Write REPORT.md from a c-review workflow result document.

Deterministic rendering, so REPORT.md and REPORT.sarif cannot drift apart and no
model has to retype a finding body to produce a report.

Usage:
    uv run render_report.py --findings findings.json --output-dir /path/to/run
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path
from typing import Any

from findings_model import (
    SEVERITY_ORDER,
    FindingsError,
    as_int,
    display_title,
    is_validated,
    ledger_warnings,
    load,
    location,
    primaries,
    reconciliation_warnings,
    reported_findings,
    severity_filter,
)

SEVERITY_TIERS = ["CRITICAL", "HIGH", "MEDIUM", "LOW"]
EMBED_FULL_BODY = {"CRITICAL", "HIGH"}

# Line-leading Markdown that opens or closes a block: an ATX heading, a fence, a blockquote,
# raw HTML, or a thematic/setext rule. Anything else in a body renders as content.
#
# The setext underlines are `-+`/`=+`, not `-{3,}`/`={3,}`: a CommonMark setext heading needs
# only ONE character under a paragraph, so `CRITICAL (99)\n==` renders a real `<h1>` and
# `FAKE-001 — fabricated\n--` a real `<h2>` — the same forged severity section a
# three-character form lets straight through. A line of only dashes is never content;
# `- item` has content after the dash and does not match.
#
# `<` is in the alternation because GitHub and every other CommonMark renderer pass raw HTML
# through: `<h2>CRITICAL (99)</h2>` is a heading, and an unterminated `<!--` swallows every
# finding after it.
MD_BLOCK_START = re.compile(r"^(\s{0,3})(#|>|<|```|~~~|-+\s*$|=+\s*$|\*{3,}\s*$|_{3,}\s*$)")

# A paragraph that is nothing but bold text. `_finding_block` labels its sections with
# `**Impact**`-style bold paragraphs rather than headings, so they are not block starts and a
# body could forge its own: a `description` ending in `**Impact**\n\nNone; benign.` renders a
# second Impact section ABOVE the real one, and any tool splitting on `**Impact**` reads the
# forged one. A bold RUN inside a sentence (`**Note:** …`) is content and is left alone.
#
# All three spellings, because CommonMark renders `__Impact__`, `**Impact**` and
# `***Impact***` as the same bold-paragraph label: an asterisk-only pattern leaves the
# underscore form open, and `\*\*[^*]+\*\*` cannot match the three-asterisk form at all
# because the inner class excludes the third asterisk. Each spelling on its own is enough to
# forge an Impact label above the genuine one.
MD_BOLD_LABEL = re.compile(r"^(\s{0,3})((?:\*{2,3}[^*]+\*{2,3}|_{2,3}[^_]+_{2,3})\s*$)")

# Mid-line raw HTML. MD_BLOCK_START guards only column 0, but CommonMark INLINE HTML needs
# no column: `ok <h2>CRITICAL (99)</h2>` renders a live heading mid-paragraph, and a
# terminated `<!-- … -->` hides everything between the arrows. Only `<` opening a tag,
# comment, declaration or processing instruction is escaped — `\<` renders as a literal
# `<` — so prose comparisons (`a < b`) are untouched. Inside a backtick span the backslash
# would show, which is why `_code` bypasses this: its callers wrap the value in backticks,
# where HTML is already inert.
MD_INLINE_HTML = re.compile(r"<(?=[A-Za-z/!?])")


def _flag(value: Any) -> str:
    """Render a JSON boolean as JSON writes it, not as Python repr's it.

    `_inline` for the rest: `run.is_cpp` and its two siblings are copied verbatim out of the
    agent-written `detect.json`, which is read as "is it a dict" and nothing more, so a
    string holding `\\n\\n## CRITICAL (99)\\n\\n### FAKE-9 …` rendered a real severity
    section and a real finding block ahead of the Run-warnings block.
    """
    if isinstance(value, bool):
        return "true" if value else "false"
    return "unknown" if value is None else _inline(value)


def _section(title: str, body: Any) -> list[str]:
    """One agent-authored body, with block-level Markdown neutralised.

    `description`, `data_flow`, `reachability`, `impact`, `mitigations_checked` and
    `recommendation` are the six largest free-text fields in the document. Raw, a
    `description` of "ok\\n\\n## CRITICAL (99)\\n\\n### FAKE-001 — …" produces a real
    severity section and a real finding block that no agent filed, and a stray fence
    swallows every section after it. Paragraphs, lists and inline code all still render;
    only a line that would open or close a BLOCK is escaped.
    """
    text = str(body or "").strip()
    if not text:
        return []
    safe = "\n".join(
        # Inline HTML first: a line-leading `<h2>` becomes `\<h2>`, which MD_BLOCK_START's
        # `<` alternation then has nothing left to match — one escape, not two.
        MD_BOLD_LABEL.sub(
            r"\1\\\2", MD_BLOCK_START.sub(r"\1\\\2", MD_INLINE_HTML.sub(r"\\<", line))
        )
        for line in text.splitlines()
    )
    return [f"**{title}**", "", safe, ""]


def _inline(value: Any) -> str:
    """One line of agent-authored text, for anywhere a newline would end the construct.

    A newline in `fp_rationale` or `severity_rationale` breaks out of its bullet and the
    rest renders as document-level Markdown — an injected `## CRITICAL (99)` heading is
    indistinguishable from a real one. Inline HTML is escaped for the same reason: these
    values render bare, where `<h2>` is live.
    """
    return MD_INLINE_HTML.sub(r"\\<", " ".join(str(value).split()))


def _code(value: Any) -> str:
    """One line for a value the caller wraps in backticks.

    Collapses like `_inline` but skips its HTML escape — inside a code span HTML is
    already inert and the backslash would render, turning a C++ `foo<T>` into `foo\\<T>`.
    Backticks are stripped, not escaped: a `file` of ``x` **BOLD** `y`` otherwise closes
    the code span and renders the middle as emphasis. Nothing inside a path, a function
    name or a bug class needs a backtick.
    """
    return " ".join(str(value).split()).replace("`", "")


def _items(value: Any) -> list[str]:
    """A list-valued field as strings. A bare string is ONE item, not its characters.

    `also_known_as: "BOF-002"` would render as `B, O, F, -, 0, 0, 2`, and a `hunter_notes`
    of `"abc"` as three separate reviewer notes in both artifacts.
    """
    if value is None:
        return []
    if isinstance(value, str):
        return [value]
    if isinstance(value, (list, tuple)):
        return [str(item) for item in value]
    return [str(value)]


def _cell(value: Any) -> str:
    """One table cell. A newline ends the row in Markdown, so it cannot survive as one.

    Escaping only `|` lets a `fp_rationale` holding a newline terminate its row early: the
    rest renders as a paragraph and every subsequent row falls outside the table.
    """
    return _inline(value).replace("|", "\\|")


def _fence(code: str) -> str:
    """A fence longer than the longest backtick run inside `code`.

    `code` is agent-authored free text copied out of the source. A three-backtick run in it
    closes a three-backtick block, so the `## …` that follows becomes a real heading in
    REPORT.md and the Impact and Recommendation sections vanish into the orphaned fence.
    """
    longest = 0
    run = 0
    for char in code:
        run = run + 1 if char == "`" else 0
        longest = max(longest, run)
    return "`" * max(3, longest + 1)


def _finding_block(f: dict[str, Any], embed: bool) -> list[str]:
    # `id` is agent-influenced and sits between two headings, so raw, an id carrying a
    # newline and a `### ` produces a finding block nobody filed — beside a `title` that is
    # sanitised for exactly that.
    fid = _inline(f.get("id", "?"))
    path, line = location(f)
    out = [f"### {fid} — {display_title(f)}", ""]
    out.append(
        f"- **Location:** `{_code(path or f.get('file', '?'))}:{line}` "
        f"(`{_code(f.get('function', '?'))}`)"
    )
    out.append(f"- **Bug class:** `{_code(f.get('bug_class', '?'))}`")
    out.append(
        f"- **Verdict:** {_inline(f.get('fp_verdict', 'UNJUDGED'))} — "
        f"{_inline(f.get('fp_rationale', ''))}"
    )
    if f.get("attack_vector") or f.get("exploitability"):
        out.append(
            f"- **Attack vector:** {_inline(f.get('attack_vector', '?'))} · "
            f"**Exploitability:** {_inline(f.get('exploitability', '?'))}"
        )
    if f.get("severity_rationale"):
        out.append(f"- **Severity rationale:** {_inline(f['severity_rationale'])}")
    if f.get("severity_source") == "reviewer":
        # Without this the line above reads as a judge's verdict. It is not one: no
        # independent pass saw this finding, and the severity is the reviewer's own.
        out.append(
            "- **Severity source:** reviewer-assigned and unreviewed — no independent "
            "false-positive or severity review ran in this configuration."
        )
    if f.get("also_known_as"):
        out.append(f"- **Also reported as:** {_inline(', '.join(_items(f['also_known_as'])))}")
    if f.get("outside_assigned_classes"):
        out.append("- **Note:** reported outside the finder's assigned bug classes")
    if not is_validated(f):
        out.append(
            "- **Caveat:** no judge validated this severity; it is an inferred placeholder and the "
            "finding is exempt from the severity filter."
        )
    out.append("")

    if embed:
        out += _section("Description", f.get("description"))
        code = str(f.get("code") or "").strip()
        if code:
            fence = _fence(code)
            out += ["**Code**", "", fence + "c", code, fence, ""]
        out += _section("Data flow", f.get("data_flow"))
        out += _section("Reachability", f.get("reachability"))
        out += _section("Impact", f.get("impact"))
        out += _section("Mitigations checked", f.get("mitigations_checked"))
        out += _section("Recommendation", f.get("recommendation"))
    else:
        out += _section("Description", f.get("description"))
        out += _section("Recommendation", f.get("recommendation"))
    return out


def render(doc: dict[str, Any]) -> str:
    run = doc.get("run", {})
    stats = doc.get("stats", {})
    reported = reported_findings(doc)
    all_primaries = primaries(doc)
    filter_name = severity_filter(doc)

    lines: list[str] = []
    # JSON-quoted, which is also valid YAML for a string. Raw, a newline in `threat_model`
    # injects `severity_filter: high` ABOVE the real key, in a block whose whole purpose is
    # to be machine-read.
    lines += [
        "---",
        "stage: final-report",
        f"threat_model: {json.dumps(str(run.get('threat_model', 'UNKNOWN')))}",
        f"severity_filter: {json.dumps(filter_name)}",
        f"finding_scope_root: {json.dumps(str(run.get('finding_scope_root', '.')))}",
        f"total_primaries: {len(all_primaries)}",
        f"reported_findings: {len(reported)}",
        "---",
        "",
        "# C/C++ Security Review",
        "",
        f"- **Threat model:** {_inline(run.get('threat_model', 'UNKNOWN'))}",
        f"- **Scope:** `{_code(run.get('finding_scope_root', '.'))}`  "
        f"(context read from `{_code(run.get('context_roots', '.'))}`)",
        f"- **Severity filter:** {filter_name}",
        f"- **Platform:** is_cpp={_flag(run.get('is_cpp'))}, "
        f"is_posix={_flag(run.get('is_posix'))}, is_windows={_flag(run.get('is_windows'))}",
        "",
    ]

    if run.get("platform_evidence"):
        # Detect-agent free text, so through `_inline` rather than as a raw paragraph.
        lines += [f"Platform detection evidence: {_inline(run['platform_evidence'])}", ""]

    warnings: list[str] = ledger_warnings(run.get("ledger"))
    if run.get("groups_failed"):
        warnings.append(
            "Bug-class group(s) returned nothing, so their classes are **uncovered**: "
            + ", ".join(f"`{_code(g)}`" for g in _items(run["groups_failed"]))
        )
    # A slice reviewer that died loses lines, not classes, so it is not a `groups_failed`
    # entry and needs a warning of its own: unreported, a run that lost 13 of 16 reviewers
    # renders exactly like a complete one.
    if run.get("agent_failures"):
        warnings.append(
            "Review agent(s) failed, so the code they were assigned is **unreviewed**: "
            + ", ".join(f"`{_code(a)}`" for a in _items(run["agent_failures"]))
        )
    # The assembler's own integrity checks. It records these in findings.json and prints them
    # to stderr, but nothing downstream reads either: a misnamed part file is one agent's
    # entire output dropped on the floor, and the report is otherwise indistinguishable from
    # a clean run.
    #
    # A slice the unit list generated and no agent answered is distinct from an agent that
    # failed: nothing was ever dispatched, so it appears in no failure list at all.
    if run.get("missing_review_parts"):
        warnings.append(
            "The unit list generated slice(s) that no part file answers, so that code was "
            "reviewed by **nobody**: "
            + ", ".join(f"`{_code(p)}`" for p in _items(run["missing_review_parts"]))
        )
    if run.get("unrecognised_parts"):
        warnings.append(
            "No rule reads part file(s), so their findings are **not in this report**: "
            + ", ".join(f"`{_code(p)}`" for p in _items(run["unrecognised_parts"]))
        )
    if run.get("stale_part_files"):
        warnings.append(
            "Part file(s) are an earlier draft than the agent's accepted return, so the "
            "findings read from them are degraded: "
            + ", ".join(f"`{_code(p)}`" for p in _items(run["stale_part_files"]))
        )
    if run.get("incomplete_findings"):
        incomplete = _items(run["incomplete_findings"])
        warnings.append(
            f"{len(incomplete)} finding(s) reached the report missing required field(s): "
            + ", ".join(f"`{_code(i)}`" for i in incomplete[:10])
            + (" …" if len(incomplete) > 10 else "")
        )
    if run.get("expectations_checked") is False:
        warnings.append(
            "Nothing verified that every dispatched agent wrote a part file, so the failure "
            "list above describes the disk rather than the run: an empty one means "
            "**unchecked**, not none, and coverage below may be over-reported."
        )
    if run.get("unjudged_findings"):
        warnings.append(
            "Finding(s) reached no judge and are reported with an unvalidated severity: "
            + ", ".join(f"`{_code(i)}`" for i in _items(run["unjudged_findings"]))
        )
    for note in _items(run.get("hunter_notes")):
        warnings.append(f"Reviewer note — {note}")
    # Shared with the SARIF generator, so both artifacts carry the same verdict.
    warnings += reconciliation_warnings(doc)
    if warnings:
        lines += ["## Run warnings", ""]
        # `_inline` per bullet: every warning above interpolates agent-authored list members.
        lines += [f"- {_inline(w)}" for w in warnings]
        lines += [""]

    counts = {tier: 0 for tier in SEVERITY_TIERS}
    unrated = 0
    unvalidated = 0
    for f in reported:
        tier = str(f.get("severity", "")).strip().upper()
        if tier in counts:
            counts[tier] += 1
        else:
            unrated += 1
        if not is_validated(f):
            unvalidated += 1

    lines += ["## Reported findings", "", "| Severity | Count |", "|---|---|"]
    for tier in SEVERITY_TIERS:
        lines.append(f"| {tier} | {counts[tier]} |")
    # Without this row the four tiers do not sum to the total printed underneath, and a
    # reader reconciling the two concludes a finding was lost — over an `## Unrated` section
    # that is right there below.
    if unrated:
        lines.append(f"| Unrated | {unrated} |")
    lines += [""]
    if run.get("judge_ran") is False:
        gate = (
            f"{len(reported)} reported after the `{filter_name}` severity filter. No "
            f"false-positive pass ran in this configuration: every severity below is the "
            f"reviewer's own and was not independently reviewed."
        )
    else:
        gate = (
            f"{len(reported)} reported after the false-positive pass and the "
            f"`{filter_name}` severity filter."
        )
    lines += [
        f"{len(all_primaries)} primary finding(s) after dedup; "
        f"{as_int(stats.get('merged'))} merged as duplicates; {gate}"
    ]
    if unvalidated:
        lines.append(f"{unvalidated} of these carry an unvalidated severity (see Run warnings).")
    lines += [""]

    if not reported:
        passed = (
            "the severity filter"
            if run.get("judge_ran") is False
            else "the false-positive pass and the severity filter"
        )
        lines += [f"No findings passed {passed}.", ""]

    for tier in SEVERITY_TIERS:
        tier_findings = [f for f in reported if str(f.get("severity", "")).strip().upper() == tier]
        if not tier_findings:
            continue
        lines += [f"## {tier} ({len(tier_findings)})", ""]
        for f in tier_findings:
            lines += _finding_block(f, embed=tier in EMBED_FULL_BODY)
            lines += ["---", ""]

    other = [
        f for f in reported if str(f.get("severity", "")).strip().upper() not in SEVERITY_ORDER
    ]
    if other:
        lines += [f"## Unrated ({len(other)})", ""]
        for f in other:
            # Embedded, like CRITICAL and HIGH. These are findings a judge CONFIRMED and
            # then left with no severity, so the truncated form would drop the code, data
            # flow, reachability, impact and mitigations from exactly the findings nobody
            # could rank.
            lines += _finding_block(f, embed=True)
            lines += ["---", ""]

    rejected = [f for f in all_primaries if f not in reported]
    if rejected:
        lines += [
            "## Not reported",
            "",
            "| ID | Location | Verdict | Severity | Rationale |",
            "|---|---|---|---|---|",
        ]
        for f in sorted(rejected, key=lambda x: str(x.get("id", ""))):
            cells = [
                _cell(f.get("id", "?")),
                "`" + _cell("{}:{}".format(*location(f))) + "`",
                _cell(f.get("fp_verdict", "UNJUDGED")),
                _cell(f.get("severity") or "—"),
                _cell(f.get("fp_rationale", "")),
            ]
            lines.append("| " + " | ".join(cells) + " |")
        lines += [""]

    coverage = doc.get("coverage", [])
    if coverage:
        # Conditional on whether the gate actually ran. As a constant the blurb contradicts
        # the Run warnings above it: a run whose warnings say "the coverage gate did not run,
        # so coverage is **unmeasured**" would head this table with `check_ledger.py` having
        # audited these rows against the unit parse — to the reader most likely to skim
        # straight to the table.
        gate = run.get("ledger")
        audited = isinstance(gate, dict) and not gate.get("error")
        lines += [
            "## Coverage (self-reported)",
            "",
            "These rows are what each reviewer said it did. "
            + (
                "`check_ledger.py` audits them against the unit parse and anything it "
                "rejected is in Run warnings above and in `ledger-gate.json`; the outcome "
                "column itself is unverified, so read the evidence column, not the outcome "
                "column."
                if audited
                else "**The coverage gate did not run over this document**, so nothing "
                "audited them against the unit parse: every column below is self-reported "
                "and none of it is verified coverage."
            ),
            "",
            "| Group | Bug class | Outcome | Population | Evidence |",
            "|---|---|---|---|---|",
        ]
        for row in coverage:
            cells = [
                _cell(row.get("group", "")),
                _cell(row.get("bug_class", "")),
                _cell(row.get("outcome", "")),
                _cell(row.get("population", "")),
                _cell(row.get("evidence", "")),
            ]
            lines.append("| " + " | ".join(cells) + " |")
        lines += [""]

    lines += [
        "## Artifacts",
        "",
        "- `findings.json` — every finding including merged duplicates and rejected candidates",
        "- `REPORT.sarif` — SARIF 2.1.0 export of the same reported set",
        "",
    ]
    return "\n".join(lines).rstrip() + "\n"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--findings", required=True, help="path to findings.json, or - for stdin")
    parser.add_argument("--output-dir", type=Path, default=None, help="writes REPORT.md here")
    parser.add_argument("--output", type=Path, default=None, help="explicit output path")
    parsed = parser.parse_args(argv)

    if not parsed.output and not parsed.output_dir:
        parser.error("one of --output-dir or --output is required")

    try:
        doc = load(parsed.findings)
    except FindingsError as exc:
        print(f"render_report: {exc}", file=sys.stderr)
        return 2

    out = parsed.output or (parsed.output_dir / "REPORT.md")
    out.parent.mkdir(parents=True, exist_ok=True)
    # Staged and renamed, and `ValueError` caught as well as `OSError`. A lone surrogate
    # decoded out of findings.json (`"\ud800"` is valid JSON) makes `write_text` raise
    # `UnicodeEncodeError` — a ValueError — part-way through, which unstaged exits 1 over a
    # TRUNCATED REPORT.md that reads as a completed render.
    tmp = out.with_name(out.name + ".partial")
    try:
        tmp.write_text(render(doc), encoding="utf-8")
        tmp.replace(out)
    except (OSError, ValueError) as exc:
        try:
            tmp.unlink(missing_ok=True)
        except OSError:
            pass
        print(
            f"render_report: {type(exc).__name__} rendering {out} ({exc}). No report was "
            f"written and any previous one is untouched.",
            file=sys.stderr,
        )
        return 2
    print(f"wrote {out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
