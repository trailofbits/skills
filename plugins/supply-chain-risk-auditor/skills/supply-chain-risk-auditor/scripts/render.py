#!/usr/bin/env python3
# /// script
# requires-python = ">=3.11"
# ///
"""Turn a collector artifact into a Markdown supply-chain report.

The failure this format exists to prevent is a reader inferring safety from silence: a
criterion that could not be assessed for 84 of 177 dependencies must not read as an
all-clear. The weakest coverage figure is therefore in the summary, while the full table
sits behind the findings — an earlier version opened with the table and spent a reader's
first two screens on the tool's limits before anything actionable.

Order after that follows blast radius: what reaches production, then what reaches only the
build, then what belongs to somebody else's repository.

Nothing here skips quietly. A criterion the artifact lacks, or a flag counted in coverage
but rendered in no table, raises — a renderer whose purpose is to surface gaps must not
have gaps of its own.

The report carries facts only: what was measured, what was flagged, what could not be
assessed and why. Interpretive rules — unassessable is not risk, low coverage is not an
all-clear — are instructions to the agent adding judgment, and they live in SKILL.md. An
earlier draft printed them at the reader, where they read as framing about the workflow
rather than information about the dependencies.

Usage:
    uv run render.py findings.json [--out report.md]
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

from model import (
    SCORECARD_CHECKS,
    TIER_A,
    TIER_B,
    TIER_INFO,
    TIER_SCORECARD,
    ReconciliationError,
    State,
    assessed,
    count_flags,
    validate_artifact,
)

LABELS = {
    "advisories": "Known advisories",
    "deprecated": "Deprecated or yanked",
    "archived": "Repository archived",
    "staleness": "Maintenance activity",
    "publisher_concentration": "Publisher concentration",
    "install_script": "Install-time script execution",
    "downloads": "Download volume",
    "dangerous_workflow": "Dangerous CI workflow",
    "token_permissions": "CI token permissions",
    "binary_artifacts": "Checked-in binaries",
    "code_review": "Changes reviewed by a second person",
    "provenance": "Publish provenance",
    "security_policy": "Security policy published",
}

# Coverage is reported per tier because availability differs per tier. Findings are not:
# a reader wants one row per dependency listing everything wrong with it, rather than the
# same package repeated in a table per criterion group. The split that does matter to a
# reader is whether anything can be done about it.
FINDING_GROUPS = (
    (TIER_A + TIER_B, "Findings"),
    (TIER_SCORECARD, "Upstream repository and CI hygiene — OpenSSF Scorecard"),
)

COVERAGE_TIERS = (("A", TIER_A), ("B", TIER_B), ("scorecard", TIER_SCORECARD))

# Scorecard criteria describe a third party's repository. Whoever owns the audited project
# cannot change them, so they are separated from findings that carry an available action.
UPSTREAM_ONLY = set(TIER_SCORECARD)

# Counted, never flagged. Phrased as "N of M do X" so absence reads as a proportion.
INFO_PHRASING = {
    "provenance": "publish with build provenance",
    "security_policy": "publish a security policy",
}

# Derived from the single source of truth: criteria whose threshold is None are
# measured and reported but can never flag. Only these belong in the Informational
# section — an earlier draft kept this set by hand and described the two checks that DO
# flag as "not flagged — poor precision" on every clean run.
SCORECARD_NEVER_FLAGS = frozenset(
    criterion for criterion, threshold in SCORECARD_CHECKS.values() if threshold is None
)

# Why each demoted Scorecard check is reported rather than flagged.
SCORECARD_CAVEAT = {
    "token_permissions": (
        "this measures whether CI workflows declare least-privilege tokens, which tracks "
        "project maturity rather than the likelihood of malicious code being published"
    ),
    "code_review": (
        "this measures the share of recent commits reviewed by a second person, which is "
        "low for most small single-maintainer projects and largely restates publisher "
        "concentration"
    ),
}


def _safe_text(value: object) -> str:
    """Make third-party text safe in report prose, table cells, and headings.

    Registry- and manifest-controlled strings (deprecation messages, versions, package
    names, git HEAD contents) reach the report from the audited project and its
    dependencies. `istanbul`'s real deprecation message truncated the findings table at
    its first newline, silently dropping every row after it — including a finding on
    another package. The same newline forges block structure outside tables: a
    dependency key carrying `\n\n## Summary\n\n- **No known advisory...**` wrote a
    heading and a false all-clear into the Method-and-caveats notes.

    Collapsing whitespace is the security-critical half — it confines anything hostile
    to the line it was interpolated into, where the worst available is inline emphasis.
    Escaping `|` keeps a value inside its table cell, and escaping `[` stops prose from
    forging a link. Use this for every value that did not originate in this repository.

    For a value going inside backticks use `_safe_code` instead: Markdown does not
    process backslash escapes in a code span, so escaping there writes the backslashes
    out literally and corrupts the value a reader copies. Inside backticks *in a table
    cell*, use `_safe_code_cell` — pipes still end the cell there.
    """
    return _collapse(value).replace("|", "\\|").replace("[", "\\[")


def _safe_code(value: object) -> str:
    """Make third-party text safe inside a Markdown code span.

    A code span needs no `[` escaping — a bracket cannot open a link inside one — and a
    backslash written there survives literally, so escaping corrupted the report title
    and the `Scanned:` path into something no reader could copy. What a code span does
    need is protection from a backtick, which would close the span early and let the
    rest of the value become live Markdown.

    A code span inside a table cell is the exception and takes `_safe_code_cell`: the
    row is split on pipes before inline spans are parsed, so a pipe still ends the cell.
    """
    return _collapse(value).replace("`", "'")


def _safe_code_cell(value: object) -> str:
    """Make third-party text safe inside a code span that sits in a table cell.

    A table row is split on pipes before inline spans are parsed, so a `|` inside a code
    span still ends the cell: a dependency named `evil|forged` put six pipes in a
    five-pipe row, shifting every later value one column right. GFM requires the `\\|`
    escape here, including inside other inline spans, and processes it in the table
    context — so unlike `_safe_code`'s territory, the backslash does not survive into
    the output. That difference is why this is a separate helper rather than a flag.
    """
    return _safe_code(value).replace("|", "\\|")


def _collapse(value: object) -> str:
    """Flatten a value to one line, which is what confines hostile text to that line."""
    return re.sub(r"\s+", " ", str(value)).strip()


def plural(n: int, singular: str, many: str) -> str:
    """Count with the right noun form, given explicitly because 'dependency' is irregular."""
    return f"{n} {singular}" if n == 1 else f"{n} {many}"


def _signal(dep: dict, criterion: str) -> dict:
    """Fetch one signal, refusing to skip a criterion the artifact should carry."""
    try:
        return dep["signals"][criterion]
    except KeyError as exc:
        raise ReconciliationError(
            f"{dep['name']} carries no {criterion!r} signal; the renderer would drop it "
            f"silently and the report would read as though it had been assessed"
        ) from exc


def _flagged(dep: dict, criteria: tuple[str, ...]) -> list[tuple[str, dict]]:
    out = []
    for criterion in criteria:
        signal = _signal(dep, criterion)
        if signal["state"] == State.FLAGGED.value:
            out.append((criterion, signal))
    return out


def coverage_table(artifact: dict) -> list[str]:
    """Coverage grouped by tier, which is the distinction that matters.

    The artifact serialises with sorted keys, so iterating it directly loses the grouping.
    """
    total = artifact["coverage"]["total_dependencies"]
    criteria = artifact["coverage"]["criteria"]
    rows = ["| Criterion | Tier | Assessed | Flagged | Not assessable |", "|---|---|---|---|---|"]
    ordered = [(tier, name) for tier, names in COVERAGE_TIERS for name in names]
    ordered += [("info", name) for name in TIER_INFO]
    seen = {name for _, name in ordered}
    missing = sorted(set(criteria) - seen)
    if missing:
        raise ReconciliationError(
            f"the artifact carries criteria this renderer knows nothing about: {missing}. "
            f"They would be counted in coverage and rendered in no table."
        )
    for tier, name in ordered:
        counts = criteria.get(name)
        if counts is None:
            raise ReconciliationError(f"coverage has no row for {name!r}")
        rows.append(
            f"| {LABELS.get(name, name)} | {tier} | {assessed(counts)}/{total} | "
            f"{counts[State.FLAGGED.value]} | {counts[State.UNASSESSABLE.value]} |"
        )
    return rows


def _version_label(dep: dict) -> str:
    """Mark how the version was established; the finding means different things by source."""
    version = dep["version"]
    if not version:
        return "unresolved"
    suffix = {
        "latest-release": " (latest, not the project's pin)",
        "go-mod-minimum": " (go.mod minimum)",
        "manifest-pin": "",
        "lockfile": "",
    }.get(dep.get("version_source", ""), "")
    return f"{version}{suffix}"


def _volume(dep: dict) -> str:
    """Download volume as prioritisation context beside a finding."""
    value = _signal(dep, "downloads").get("value")
    return f"{value:,}/wk" if isinstance(value, int) else "—"


def _finding_rows(hits: list[tuple[dict, list]]) -> list[str]:
    rows = ["| Dependency | Version | Weekly downloads | Findings |", "|---|---|---|---|"]
    for dep, flags in sorted(hits, key=lambda x: (-len(x[1]), x[0]["name"])):
        detail = _safe_text("; ".join(s["detail"] for _, s in flags))
        rows.append(
            f"| `{_safe_code_cell(dep['name'])}` | {_safe_text(_version_label(dep))} | {_volume(dep)} | {detail} |"
        )
    return rows


def findings_section(artifact: dict, criteria: tuple[str, ...], heading: str) -> list[str]:
    """Findings for one tier, split by whether the dependency reaches production.

    The split is the first thing a reader needs. A compromised build-time dependency
    reaches the build host; a compromised production dependency reaches users. Presenting
    both at equal weight — as an earlier version did, with a nine-year-abandoned build tool
    listed beside a shipped package — makes the report harder to act on than a bare list.
    """
    out = [f"## {heading}", ""]
    if set(criteria) & UPSTREAM_ONLY:
        out += [
            "These criteria describe each dependency's own repository, not the audited",
            "project. Remediation, where any exists, is upstream.",
            "",
        ]
    hits = [(d, f) for d in artifact["dependencies"] if (f := _flagged(d, criteria))]
    if not hits:
        rows = artifact["coverage"]["criteria"]
        if all(assessed(rows[c]) == 0 for c in criteria if c in rows):
            out += ["No criterion in this tier was assessable for any dependency.", ""]
        else:
            out += ["No dependency was flagged on these criteria.", ""]
        return out
    groups = (
        (
            [(d, f) for d, f in hits if d.get("dev") is False],
            "Reaches production",
            "",
        ),
        (
            [(d, f) for d, f in hits if d.get("dev") is True],
            "Build-time only",
            "Declared as development dependencies. A compromise here reaches build and CI "
            "hosts rather than users of the shipped artifact.",
        ),
        (
            [(d, f) for d, f in hits if d.get("dev") is None],
            "Production or build-time not declared",
            "These manifests draw no distinction between runtime and development "
            "dependencies — go.mod has no dev section — so whether these reach a shipped "
            "artifact cannot be read from the manifest.",
        ),
    )
    for rows, heading, preamble in groups:
        if not rows:
            continue
        out += [f"### {heading}", ""]
        if preamble:
            out += [preamble, ""]
        out += _finding_rows(rows)
        out.append("")
    return out


def _transitive_summary(transitive: dict) -> str:
    """One summary line stating what the transitive sweep did or could not do."""
    if not transitive["examined"]:
        return f"- Transitive dependencies were **not examined**: {transitive['reason']}."
    if transitive["total"] == 0:
        return "- The lockfile resolves no packages beyond the direct dependencies."
    unverifiable = transitive.get("unverifiable") or []
    checkable = transitive["total"] - len(unverifiable)
    caveat = (
        f" {plural(len(unverifiable), 'entry was', 'entries were')} unverifiable against "
        f"a public registry and not checked (see Transitive advisories)."
        if unverifiable
        else ""
    )
    if checkable and transitive["checked"] < checkable:
        return (
            f"- {checkable} transitive packages were resolved but **could not "
            f"be checked**: {transitive['reason'] or 'the sweep did not complete'}."
        )
    if transitive["flagged"]:
        return (
            f"- **{plural(len(transitive['flagged']), 'transitive package carries', 'transitive packages carry')} "
            f"known advisories** at the locked versions — see Transitive advisories." + caveat
        )
    if not checkable:
        return (
            f"- All {transitive['total']} packages beyond the direct set were "
            f"unverifiable against a public registry; none was checked for advisories."
        )
    return (
        f"- No known advisory affects any of the {checkable} registry-verified "
        f"transitive packages at their locked versions." + caveat
    )


def transitive_section(artifact: dict) -> list[str]:
    """Advisory results for the lockfile-resolved packages beyond the direct set.

    Advisories only, and the section says so: leaving the depth to be inferred is how a
    reader mistakes "the direct tree is clean" for "the tree is clean". Only entries
    attested against a public registry are checked; the rest are named with reasons,
    because an empty advisory answer about an unverifiable entry proves nothing.
    """
    transitive = artifact["transitive"]
    out = ["## Transitive advisories", ""]
    if not transitive["examined"]:
        out += [
            f"Not examined: {transitive['reason']}. Commit a lockfile to close this gap.",
            "",
        ]
        return out
    src = ", ".join(f"`{s}`" for s in transitive["sources"])
    if transitive["total"] == 0:
        out += [f"{src} resolves no packages beyond the direct dependencies.", ""]
        return out
    unverifiable = transitive.get("unverifiable") or []
    checkable = transitive["total"] - len(unverifiable)
    if checkable and transitive["checked"] < checkable:
        out += [
            f"{checkable} packages beyond the direct set are resolved by {src}, "
            f"but none was checked: "
            f"{transitive['reason'] or 'the sweep did not complete'}.",
            "",
        ]
        return out
    if not transitive["flagged"]:
        if checkable:
            out += [
                f"No known advisory affects any of the {checkable} registry-verified "
                f"packages beyond the direct set (resolved by {src}), at the locked "
                f"versions. Only advisories were checked at this depth; every other "
                f"criterion in this report describes direct dependencies only.",
                "",
            ]
        out += _unverifiable_lines(transitive)
        return out
    out += [
        f"{plural(len(transitive['flagged']), 'package', 'packages')} of the "
        f"{checkable} registry-verified packages beyond the direct set (resolved by "
        f"{src}) {'carries' if len(transitive['flagged']) == 1 else 'carry'} known "
        f"advisories at the locked versions. Only advisories were checked at this depth.",
        "",
        "| Package | Version | Reaches | Advisories |",
        "|---|---|---|---|",
    ]
    for entry in sorted(transitive["flagged"], key=lambda e: (e["ecosystem"], e["name"])):
        reaches = {True: "build-time only", False: "production"}.get(
            entry.get("dev"), "not declared"
        )
        ids = ", ".join(entry["advisories"][:6])
        if len(entry["advisories"]) > 6:
            ids += f" and {len(entry['advisories']) - 6} more"
        out.append(
            f"| `{_safe_code_cell(entry['name'])}` ({_safe_text(entry['ecosystem'])}) | "
            f"{_safe_text(entry['version'])} | {reaches} | {_safe_text(ids)} |"
        )
    out.append("")
    out += _unverifiable_lines(transitive)
    return out


def _unverifiable_lines(transitive: dict) -> list[str]:
    """Name every lockfile entry that could not be verified against a registry.

    These are neither clean nor flagged: registry-keyed advisory data does not apply to
    a git checkout, a vendored directory, or a module the proxy cannot resolve, and an
    empty answer about them proves nothing.
    """
    entries = transitive.get("unverifiable") or []
    if not entries:
        return []
    out = [
        f"{plural(len(entries), 'entry', 'entries')} in the lockfile could not be "
        f"verified against a public registry and "
        f"{'was' if len(entries) == 1 else 'were'} not checked for advisories:",
        "",
    ]
    for entry in entries[:10]:
        out.append(
            f"- `{_safe_code(entry['name'])}` {_safe_text(entry['version'])} "
            f"({_safe_text(entry['ecosystem'])}) — {_safe_text(entry['reason'])}"
        )
    if len(entries) > 10:
        out.append(f"- and {len(entries) - 10} more, listed in the artifact")
    out.append("")
    return out


def production_section(artifact: dict) -> list[str]:
    """Every production dependency with a verdict, including the clean ones.

    A findings-only report cannot state this. Three of axios's four runtime dependencies
    appeared nowhere in an earlier draft because nothing was wrong with them — and for a
    reader whose question is "what reaches my users", a named package with a version and a
    clean advisory result is the most valuable line in the document.
    """
    production = [d for d in artifact["dependencies"] if d.get("dev") is False]
    undeclared = [d for d in artifact["dependencies"] if d.get("dev") is None]
    out = ["## Production dependencies", ""]
    if not production:
        if undeclared:
            out += [
                f"No manifest here declares which dependencies are development-only, so "
                f"none of the {len(undeclared)} can be identified as production or not. "
                f"Advisory status for all of them is in the findings and coverage below.",
                "",
            ]
        else:
            out += [
                "Every direct dependency is declared as a development dependency, so none",
                "of them ships in the built artifact.",
                "",
            ]
        return out
    out += [
        f"{plural(len(production), 'dependency', 'dependencies')} "
        f"{'is' if len(production) == 1 else 'are'} declared as runtime dependencies and "
        f"ship in the built artifact. Advisory status is given for every one, clean or not.",
        "",
        "| Dependency | Version | Advisories | Other findings |",
        "|---|---|---|---|",
    ]
    for dep in sorted(production, key=lambda d: d["name"]):
        advisories = _signal(dep, "advisories")
        verdict = {
            State.CLEAN.value: "none known",
            State.FLAGGED.value: f"**{advisories['detail']}**",
        }.get(advisories["state"], f"not established — {advisories['detail']}")
        others = [
            LABELS.get(c, c) for c in dep["flagged"] if c != "advisories" and c not in UPSTREAM_ONLY
        ]
        out.append(
            f"| `{_safe_code_cell(dep['name'])}` | {_safe_text(_version_label(dep))} | {_safe_text(verdict)} "
            f"| {_safe_text(', '.join(others) or '—')} |"
        )
    out.append("")
    return out


def unassessable_section(artifact: dict) -> list[str]:
    """Every gap, grouped by criterion and reason, with the affected packages named."""
    out = ["## Not assessable", ""]
    grouped: dict[str, dict[str, list[str]]] = {}
    for dep in artifact["dependencies"]:
        for criterion, signal in dep["signals"].items():
            if signal["state"] != State.UNASSESSABLE.value:
                continue
            grouped.setdefault(criterion, {}).setdefault(signal["detail"], []).append(dep["name"])
    if not grouped:
        out += ["Every criterion was assessable for every dependency.", ""]
        return out
    for criterion, reasons in sorted(grouped.items()):
        out += [f"**{LABELS.get(criterion, criterion)}**", ""]
        for reason, names in sorted(reasons.items(), key=lambda kv: -len(kv[1])):
            sample = ", ".join(f"`{_safe_code(n)}`" for n in sorted(names)[:6])
            more = f" and {len(names) - 6} more" if len(names) > 6 else ""
            out.append(
                f"- {plural(len(names), 'dependency', 'dependencies')} — "
                f"{_safe_text(reason)}: {sample}{more}"
            )
        out.append("")
    return out


def scorecard_distribution(artifact: dict) -> list[str]:
    """Score spreads for the Scorecard checks that are measured but never flagged.

    Reported rather than dropped: a check demoted for poor precision still tells a reader
    something, and silently omitting it would leave a criterion counted in the coverage
    table and shown nowhere.
    """
    out = []
    for criterion in TIER_SCORECARD:
        if criterion not in SCORECARD_NEVER_FLAGS:
            # The flagging checks report through the findings tables and coverage;
            # describing them here as "not flagged" contradicted both.
            continue
        scores = [
            s["value"]
            for dep in artifact["dependencies"]
            if isinstance((s := _signal(dep, criterion)).get("value"), int)
        ]
        if not scores:
            continue
        low = sum(1 for s in scores if s < 6)
        out.append(
            f"- **{LABELS.get(criterion, criterion)}**: median "
            f"{sorted(scores)[len(scores) // 2]}/10 across {len(scores)} scored "
            f"dependencies; {low} score below 6. Not flagged — "
            f"{SCORECARD_CAVEAT[criterion]}."
        )
    return out


def _download_line(artifact: dict) -> str:
    """Download volume is an integer, not a yes/no, so it gets its own summary line.

    Treating it as a boolean proportion printed "not determinable for any dependency"
    beside a coverage table that said 41 of 44 were assessed — the report contradicting
    itself about its own coverage.
    """
    total = artifact["coverage"]["total_dependencies"]
    counted = sorted(
        (value, dep["name"])
        for dep in artifact["dependencies"]
        if isinstance((value := _signal(dep, "downloads").get("value")), int)
    )
    label = LABELS["downloads"]
    if not counted:
        return f"- **{label}**: not determinable for any dependency in this project."
    median = counted[len(counted) // 2][0]
    lowest = ", ".join(f"`{_safe_code(name)}` ({value:,}/wk)" for value, name in counted[:3])
    return (
        f"- **{label}**: established for {len(counted)} of {total}; median "
        f"{median:,}/week. Lowest: {lowest}."
    )


def informational_section(artifact: dict) -> list[str]:
    """Measured but never flagged, reported as proportions with the absentees named."""
    out = ["## Informational", "", "Measured, not flagged.", ""]
    out += scorecard_distribution(artifact)
    for criterion in TIER_INFO:
        if criterion == "downloads":
            out.append(_download_line(artifact))
            continue
        yes, no = [], []
        for dep in artifact["dependencies"]:
            value = _signal(dep, criterion).get("value")
            if value is True:
                yes.append(dep["name"])
            elif value is False:
                no.append(dep["name"])
        determined = len(yes) + len(no)
        if not determined:
            out.append(
                f"- **{LABELS.get(criterion, criterion)}**: not determinable for any "
                f"dependency in this project."
            )
            continue
        out.append(
            f"- **{LABELS.get(criterion, criterion)}**: {len(yes)} of {determined} "
            f"{INFO_PHRASING.get(criterion, 'satisfy this')}."
        )
        if no:
            sample = ", ".join(f"`{_safe_code(n)}`" for n in sorted(no)[:10])
            more = f" and {len(no) - 10} more" if len(no) > 10 else ""
            out.append(f"  Without: {sample}{more}")
    out.append("")
    return out


def check_no_forged_lines(lines: list[str]) -> None:
    """Refuse a document whose structure did not come from this renderer.

    Escaping is applied per interpolation site, so its coverage is only as good as the
    author's memory — this defect reached separate call sites across three successive
    commits, each fix correct and each leaving siblings unguarded. These two invariants
    hold regardless of which site leaks, including sites not yet written.

    A forged heading, bullet, or row needs a newline inside a line the renderer meant as
    one line, and every legitimate line is appended to `lines` as its own element, so an
    embedded newline is precisely the signature of interpolated hostile text. A pipe
    surviving into a table row is the same story for cells: GFM splits the row before it
    parses inline spans, so an unescaped pipe silently adds a column and shifts every
    later value right.

    Raises:
        ReconciliationError: If any assembled line carries a newline, or a table row's
            unescaped-pipe count differs from its header's.
    """
    for line in lines:
        if "\n" in line:
            raise ReconciliationError(
                f"a line assembled by the renderer contains a newline, so third-party "
                f"text reached it unescaped: {line!r}"
            )
    expected = None
    for line in lines:
        if not line.startswith("|"):
            expected = None
            continue
        # Only the pipes GFM splits on: an escaped `\|` is cell content.
        count = len(re.findall(r"(?<!\\)\|", line))
        if expected is None:
            expected = count
        elif count != expected:
            raise ReconciliationError(
                f"table row has {count} columns where its header has {expected}, so an "
                f"unescaped pipe reached a cell: {line!r}"
            )


def check_flags_reconcile(artifact: dict, rendered: str) -> None:
    """Every flag counted in coverage must appear in a findings table.

    This is the assertion that fails when it inspects zero items. A criterion added to the
    collector but not to this renderer would otherwise be counted in the coverage table
    and shown to no reader.
    """
    counted = count_flags(artifact)
    coverage = artifact["coverage"]["criteria"]
    from_coverage = {
        name: counts[State.FLAGGED.value]
        for name, counts in coverage.items()
        if counts[State.FLAGGED.value]
    }
    if counted != from_coverage:
        raise ReconciliationError(
            f"flags in the dependency list {counted} disagree with the coverage table "
            f"{from_coverage}"
        )
    renderable = {name for names, _ in FINDING_GROUPS for name in names}
    unrendered = sorted(set(from_coverage) - renderable)
    if unrendered:
        raise ReconciliationError(
            f"these criteria have flags that no findings table renders: {unrendered}"
        )
    if from_coverage and "| Dependency |" not in rendered:
        raise ReconciliationError(
            f"coverage reports {sum(from_coverage.values())} flags but the report contains "
            f"no findings table"
        )
    if artifact["transitive"].get("flagged") and "## Transitive advisories" not in rendered:
        raise ReconciliationError(
            f"{len(artifact['transitive']['flagged'])} transitive packages carry "
            f"advisories but no section renders them"
        )


def header(artifact: dict) -> list[str]:
    """Name the subject. Without it, a reader cannot tell whose dependency tree this is."""
    scan = artifact.get("scan") or {}
    total = artifact["coverage"]["total_dependencies"]
    ecosystems = ", ".join(f"{eco} {n}" for eco, n in artifact["ecosystems"].items())
    subject = scan.get("subject") or Path(artifact["target"]).name or "unnamed project"
    lines = [f"# Supply Chain Risk Report — `{_safe_code(subject)}`", ""]
    lines.append(f"**Scanned:** `{_safe_code(scan.get('path', artifact['target']))}`  ")
    if scan.get("commit"):
        lines.append(f"**Commit:** `{_safe_code(scan['commit'])}`  ")
    if scan.get("manifests"):
        joined = ", ".join(f"`{_safe_code(m)}`" for m in scan["manifests"])
        lines.append(f"**Manifests read:** {joined}  ")
    if scan.get("scanned_at"):
        lines.append(f"**Scanned at:** {scan['scanned_at']}  ")
    lines += [f"**Direct dependencies:** {total} ({ecosystems})", ""]
    return lines


def summary(artifact: dict) -> list[str]:
    """A factual headline plus the one coverage sentence a reader must not skip."""
    deps = artifact["dependencies"]
    criteria = artifact["coverage"]["criteria"]
    total = artifact["coverage"]["total_dependencies"]
    adv = criteria["advisories"]
    flagged = [d for d in deps if d["flagged"]]
    prod_flagged = [d for d in flagged if d.get("dev") is False]
    weakest = min(
        ((assessed(criteria[name]), name) for name in TIER_A + TIER_B if name in criteria),
        default=(0, ""),
    )
    lines = ["## Summary", ""]
    # "Checked at the versions this project resolves" is only true when every version
    # came from the project itself. Saying it about latest-release fallbacks turned a
    # missing lockfile into a stronger claim than a present one supports.
    # Whitelist the strong sources so any new version source defaults to the weaker
    # claim: go-mod-minimum escaped an earlier blacklist and a Go summary asserted
    # "the versions this project resolves" over floor versions.
    unresolved = sum(1 for d in deps if d.get("version_source") not in ("lockfile", "manifest-pin"))
    if adv[State.FLAGGED.value]:
        lines.append(
            f"- **{adv[State.FLAGGED.value]} of {total} dependencies have known "
            f"advisories.** See the findings below."
        )
    elif assessed(adv) == total:
        if unresolved:
            lines.append(
                f"- **No known advisory affects any of the {total} direct dependencies** "
                f"— but {plural(unresolved, 'was', 'of them were')} not checked at a "
                f"project-resolved version (latest-release fallback or go.mod minimum; "
                f"see Method and caveats)."
            )
        else:
            lines.append(
                f"- **No known advisory affects any of the {total} direct dependencies**, "
                f"checked at the versions this project resolves."
            )
    else:
        lines.append(
            f"- Advisory status was established for {assessed(adv)} of {total} "
            f"dependencies; the rest could not be checked."
        )
    lines.append(_transitive_summary(artifact["transitive"]))
    undeclared = [d for d in deps if d.get("dev") is None]
    if undeclared and not any(d.get("dev") is False for d in deps):
        lines.append(
            f"- {len(flagged)} of {total} dependencies carry at least one finding. These "
            f"manifests declare no runtime/development split, so which of them reach a "
            f"shipped artifact cannot be determined here."
        )
    else:
        lines.append(
            f"- {len(flagged)} of {total} dependencies carry at least one finding, "
            f"{len(prod_flagged)} of which "
            f"{'reaches' if len(prod_flagged) == 1 else 'reach'} production."
        )
    lines.append(
        f"- Weakest coverage: **{LABELS.get(weakest[1], weakest[1])}**, established for "
        f"{weakest[0]} of {total}; the Coverage section lists every criterion."
    )
    lines.append("")
    return lines


def render(artifact: dict) -> str:
    """Render the whole report, refusing an artifact that cannot support one.

    Order is deliberate. An earlier version opened with the full coverage table, and a
    reader with twenty minutes read two screens about the tool's limits before reaching
    anything they could act on. The one coverage sentence that matters is in the summary;
    the detail sits behind the findings.
    """
    validate_artifact(artifact)
    lines = header(artifact)
    lines += summary(artifact)
    lines += production_section(artifact)
    for criteria, heading in FINDING_GROUPS:
        lines += findings_section(artifact, criteria, heading)
    lines += transitive_section(artifact)
    lines += informational_section(artifact)
    lines += ["## Coverage", ""]
    lines += [
        "What was and was not measured, per criterion.",
        "",
        *coverage_table(artifact),
        "",
    ]
    lines += unassessable_section(artifact)
    lines += ["## Method and caveats", ""]
    lines += [f"- {_safe_text(note)}" for note in artifact["notes"]]
    lines.append("")
    check_no_forged_lines(lines)
    text = "\n".join(lines)
    check_flags_reconcile(artifact, text)
    return text


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("artifact", type=Path, help="collector JSON")
    parser.add_argument("--out", type=Path, help="write Markdown here (default: stdout)")
    args = parser.parse_args()
    try:
        text = render(json.loads(args.artifact.read_text(), strict=False))
    except ReconciliationError as exc:
        raise SystemExit(f"error: {args.artifact} cannot be rendered: {exc}") from exc
    if args.out:
        args.out.write_text(text)
        print(f"wrote {args.out}")
    else:
        print(text)
    return 0


if __name__ == "__main__":
    sys.exit(main())
