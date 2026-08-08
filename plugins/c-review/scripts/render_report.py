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
import sys
from pathlib import Path
from typing import Any

from findings_model import (
    SEVERITY_ORDER,
    FindingsError,
    display_title,
    is_validated,
    load,
    primaries,
    reported_findings,
    severity_filter,
)

SEVERITY_TIERS = ["CRITICAL", "HIGH", "MEDIUM", "LOW"]
EMBED_FULL_BODY = {"CRITICAL", "HIGH"}


def _flag(value: Any) -> str:
    """Render a JSON boolean as JSON writes it, not as Python repr's it."""
    if isinstance(value, bool):
        return "true" if value else "false"
    return "unknown" if value is None else str(value)


def _section(title: str, body: Any) -> list[str]:
    text = str(body or "").strip()
    return [f"**{title}**", "", text, ""] if text else []


def _finding_block(f: dict[str, Any], embed: bool) -> list[str]:
    fid = str(f.get("id", "?"))
    out = [f"### {fid} — {display_title(f)}", ""]
    out.append(
        f"- **Location:** `{f.get('file', '?')}:{f.get('line', '?')}` (`{f.get('function', '?')}`)"
    )
    out.append(f"- **Bug class:** `{f.get('bug_class', '?')}`")
    out.append(f"- **Verdict:** {f.get('fp_verdict', 'UNJUDGED')} — {f.get('fp_rationale', '')}")
    if f.get("attack_vector") or f.get("exploitability"):
        out.append(
            f"- **Attack vector:** {f.get('attack_vector', '?')} · "
            f"**Exploitability:** {f.get('exploitability', '?')}"
        )
    if f.get("severity_rationale"):
        out.append(f"- **Severity rationale:** {f['severity_rationale']}")
    if f.get("severity_source") == "reviewer":
        # Without this the line above reads as a judge's verdict. It is not one: no
        # independent pass saw this finding, and the severity is the reviewer's own.
        out.append(
            "- **Severity source:** reviewer-assigned and unreviewed — no independent "
            "false-positive or severity review ran in this configuration."
        )
    if f.get("also_known_as"):
        out.append(f"- **Also reported as:** {', '.join(f['also_known_as'])}")
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
            out += ["**Code**", "", "```c", code, "```", ""]
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
    lines += [
        "---",
        "stage: final-report",
        f"threat_model: {run.get('threat_model', 'UNKNOWN')}",
        f"severity_filter: {filter_name}",
        f"finding_scope_root: {run.get('finding_scope_root', '.')}",
        f"total_primaries: {len(all_primaries)}",
        f"reported_findings: {len(reported)}",
        "---",
        "",
        "# C/C++ Security Review",
        "",
        f"- **Threat model:** {run.get('threat_model', 'UNKNOWN')}",
        f"- **Scope:** `{run.get('finding_scope_root', '.')}`  (context read from `{run.get('context_roots', '.')}`)",
        f"- **Severity filter:** {filter_name}",
        f"- **Platform:** is_cpp={_flag(run.get('is_cpp'))}, "
        f"is_posix={_flag(run.get('is_posix'))}, is_windows={_flag(run.get('is_windows'))}",
        "",
    ]

    if run.get("platform_evidence"):
        lines += [f"Platform detection evidence: {run['platform_evidence']}", ""]

    warnings: list[str] = []
    if run.get("groups_failed"):
        warnings.append(
            "Bug-class group(s) returned nothing, so their classes are **uncovered**: "
            + ", ".join(f"`{g}`" for g in run["groups_failed"])
        )
    if run.get("unjudged_findings"):
        warnings.append(
            "Finding(s) reached no judge and are reported with an unvalidated severity: "
            + ", ".join(f"`{i}`" for i in run["unjudged_findings"])
        )
    for note in run.get("hunter_notes", []) or []:
        warnings.append(f"Reviewer note — {note}")
    if warnings:
        lines += ["## Run warnings", ""]
        lines += [f"- {w}" for w in warnings]
        lines += [""]

    counts = {tier: 0 for tier in SEVERITY_TIERS}
    unvalidated = 0
    for f in reported:
        tier = str(f.get("severity", "")).upper()
        if tier in counts:
            counts[tier] += 1
        if not is_validated(f):
            unvalidated += 1

    lines += ["## Reported findings", "", "| Severity | Count |", "|---|---|"]
    for tier in SEVERITY_TIERS:
        lines.append(f"| {tier} | {counts[tier]} |")
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
        f"{stats.get('merged', 0)} merged as duplicates; {gate}"
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
        tier_findings = [f for f in reported if str(f.get("severity", "")).upper() == tier]
        if not tier_findings:
            continue
        lines += [f"## {tier} ({len(tier_findings)})", ""]
        for f in tier_findings:
            lines += _finding_block(f, embed=tier in EMBED_FULL_BODY)
            lines += ["---", ""]

    other = [f for f in reported if str(f.get("severity", "")).upper() not in SEVERITY_ORDER]
    if other:
        lines += [f"## Unrated ({len(other)})", ""]
        for f in other:
            lines += _finding_block(f, embed=False)
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
            rationale = str(f.get("fp_rationale", "")).replace("|", "\\|")
            lines.append(
                f"| {f.get('id', '?')} | `{f.get('file', '?')}:{f.get('line', '?')}` | "
                f"{f.get('fp_verdict', 'UNJUDGED')} | {f.get('severity', '—')} | {rationale} |"
            )
        lines += [""]

    coverage = doc.get("coverage", [])
    if coverage:
        lines += [
            "## Coverage (self-reported, unverified)",
            "",
            "These rows are what each reviewer said it did. Nothing downstream validates them and no "
            "gate depends on them — read the evidence column, not the outcome column.",
            "",
            "| Group | Bug class | Outcome | Population | Evidence |",
            "|---|---|---|---|---|",
        ]
        for row in coverage:
            cells = [
                str(row.get("group", "")),
                str(row.get("bug_class", "")),
                str(row.get("outcome", "")),
                str(row.get("population", "")),
                str(row.get("evidence", "")),
            ]
            lines.append(
                "| " + " | ".join(c.replace("|", "\\|").replace("\n", " ") for c in cells) + " |"
            )
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
    out.write_text(render(doc), encoding="utf-8")
    print(f"wrote {out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
