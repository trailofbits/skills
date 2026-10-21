"""Audience-specific HTML fragments from validated run records."""

import json
from collections import defaultdict
from pathlib import PurePosixPath

from report_sections import Check, Evidence, evidence_label, safe, state_label


def receipt_link(item: Evidence, label: str | None = None) -> str:
    return f'<a href="#{item.anchor}">{safe(label or item.path)}</a>'


def receipt_for(items: list[Evidence], path: str) -> Evidence | None:
    return next((item for item in items if item.path == path), None)


def receipt_links(items: list[Evidence], paths: list[str]) -> str:
    links = [
        receipt_link(item, PurePosixPath(path).name)
        for path in paths
        if (item := receipt_for(items, path))
    ]
    return ", ".join(links)


def proof_receipts(anchor: str, attempt: int, items: list[Evidence]) -> list[Evidence]:
    prefix = f"prove/attempt-{attempt}/"
    record = receipt_for(items, prefix + "prove.json")
    if not record:
        return []
    proof = json.loads(record.content)
    paths = [record.path]
    entries = proof["cases"] if anchor == "check-cases" else proof["project_checks"]
    for entry in entries:
        runs = (
            entry["runs"].values()
            if anchor == "check-cases"
            else (entry["baseline"], entry["patched"])
        )
        for run in runs:
            if run:
                paths.extend(prefix + run[key] for key in ("stdout", "stderr"))
    return [item for path in dict.fromkeys(paths) if (item := receipt_for(items, path))]


def check_receipts(row: Check, attempt: int, items: list[Evidence]) -> list[Evidence]:
    if row.anchor in {"check-cases", "check-project"}:
        return proof_receipts(row.anchor, attempt, items)
    roots = {
        "check-reproduction": "reproduce/receipts/",
        "check-validation": "validate/receipts/",
        "check-suite": f"patch/attempt-{attempt}/receipts/",
        "check-arms": f"prove/attempt-{attempt}/receipts/arms/",
        "check-build": f"prove/attempt-{attempt}/receipts/source.json",
        "check-regression-outcomes": "regression/receipts/",
    }
    prefix = roots.get(row.anchor)
    found = [item for item in items if prefix and item.path.startswith(prefix)]
    if found:
        if row.anchor == "check-arms":
            record = receipt_for(items, f"prove/attempt-{attempt}/prove.json")
            if record:
                found.insert(0, record)
        return found
    record = {
        "check-reproduction": "reproduce/reproduce.json",
        "check-validation": "validate/validate.json",
        "check-patch": f"patch/attempt-{attempt}/patch.json",
        "check-suite": f"patch/attempt-{attempt}/patch.json",
        "check-arms": f"prove/attempt-{attempt}/prove.json",
        "check-build": f"prove/attempt-{attempt}/prove.json",
        "check-cases": f"prove/attempt-{attempt}/prove.json",
        "check-project": f"prove/attempt-{attempt}/prove.json",
        "check-regression-coverage": "regression/regression.json",
        "check-regression-outcomes": "regression/regression.json",
    }.get(row.anchor)
    item = receipt_for(items, record) if record else None
    return [item] if item else []


def verification_table(rows: list[Check], attempt: int, items: list[Evidence]) -> str:
    body = []
    for row in rows:
        receipts = check_receipts(row, attempt, items)
        links = ", ".join(receipt_link(item, PurePosixPath(item.path).name) for item in receipts)
        body.append(
            f'<tr id="{row.anchor}" class="state-{safe(row.state)}">'
            f'<th scope="row">{safe(row.name)}</th><td>{safe(state_label(row.state))}</td>'
            f"<td>{safe(row.result)}</td><td>{links or 'No retained receipt'}</td></tr>"
        )
    return (
        '<table class="checks"><thead><tr><th>Check</th><th>Result</th>'
        "<th>Recorded finding</th><th>Receipts</th></tr></thead><tbody>"
        + "".join(body)
        + "</tbody></table>"
    )


def decisive_checks(rows: list[Check], attempt: int, items: list[Evidence]) -> str:
    selected = [
        row
        for row in rows
        if row.anchor
        in {
            "check-reproduction",
            "check-validation",
            "check-arms",
            "check-build",
            "check-suite",
            "check-cases",
            "check-project",
            "check-regression-coverage",
            "check-regression-outcomes",
        }
    ]
    if not selected:
        return "<li>No verification checks were recorded.</li>"
    return "".join(
        f'<li><a href="#{row.anchor}">{safe(row.name)}</a>: {safe(state_label(row.state))}'
        + (
            f" ({receipt_link(receipts[0], 'receipt')})"
            if (receipts := check_receipts(row, attempt, items))
            else ""
        )
        + "</li>"
        for row in selected
    )


def receipt_group(item: Evidence) -> str:
    parts = PurePosixPath(item.path).parts
    if len(parts) < 2:
        return "Run records"
    if parts[0] in {"patch", "prove"} and len(parts) > 1:
        prefix = f"Attempt {parts[1].removeprefix('attempt-')} · "
    else:
        prefix = ""
    if parts[0] == "prove" and "receipts" in parts:
        name = parts[-1]
        kind = (
            "Three-arm proof"
            if "arms" in parts or name == "source.json"
            else "Project checks"
            if name.startswith("project-")
            else "Scoped cases"
        )
        return prefix + kind
    return prefix + {
        "reproduce": "Reproduction",
        "validate": "Independent validation",
        "patch": "Patch and focused tests",
        "regression": "Regression review",
    }.get(parts[0], "Run records")


def grouped_evidence(items: list[Evidence]) -> str:
    groups: dict[str, list[Evidence]] = defaultdict(list)
    for item in items:
        groups[receipt_group(item)].append(item)
    blocks = []
    for group, members in groups.items():
        entries = []
        for item in members:
            label = (
                item.redaction_note or "Excerpt: last 20 lines"
                if item.excerpt or item.redaction_note
                else "Full retained content"
            )
            entries.append(
                f'<article class="receipt" id="{item.anchor}"><h3>{safe(item.path)}</h3>'
                f"<p>{safe(evidence_label(item.path))} · {item.size} bytes · "
                f"SHA-256 <code>{item.digest}</code></p>"
                f"<details><summary>{safe(label)}</summary><pre>{safe(item.content)}</pre></details></article>"
            )
        blocks.append(
            f'<details class="receipt-group"><summary>{safe(group)} '
            f"<span>({len(members)})</span></summary>{''.join(entries)}</details>"
        )
    return "".join(blocks)


def supplied_details(finding: dict) -> tuple[str, list[str]]:
    reported = finding.get("reported", {})
    fields = []
    gaps = []
    for key, label in (("severity", "Severity"), ("priority", "Priority")):
        if reported.get(key):
            fields.append(f"<p><strong>{label}:</strong> {safe(reported[key])}</p>")
    for key, label in (
        ("impact", "Impact"),
        ("expected_behavior", "Expected behavior"),
        ("observed_behavior", "Observed behavior"),
    ):
        if reported.get(key):
            fields.append(f"<p><strong>{label}:</strong> {safe(reported[key])}</p>")
        else:
            gaps.append(f"{label} was not supplied")
    steps = reported.get("reproduction_steps", [])
    if steps:
        fields.append(
            "<h3>Supplied reproduction steps</h3><ol>"
            + "".join(f"<li>{safe(step)}</li>" for step in steps)
            + "</ol>"
        )
    else:
        gaps.append("Reproduction steps were not supplied")
    return "".join(fields), gaps


def limits_html(
    proof: dict | None,
    open_risks: list[str],
    scope_detail: str,
    label: str,
    reasons: list[str] | None = None,
) -> str:
    limits = list(proof.get("unproven", [])) if proof else []
    if proof and not limits:
        limits.append("No explicit limits were recorded.")
    limits.extend(open_risks)
    if label == "INCONCLUSIVE" and scope_detail:
        limits.insert(0, scope_detail)
    if label in {"INCONCLUSIVE", "FAILED REPAIR"}:
        limits.extend(reasons or [])
    if not limits:
        return (
            "<p>No explicit limits were recorded. "
            "Behavior outside the stated scope was not assessed.</p>"
        )
    return "<ul>" + "".join(f"<li>{safe(item)}</li>" for item in dict.fromkeys(limits)) + "</ul>"


def variant_summary(patch: dict | None) -> str:
    if not patch:
        return ""
    variants = patch["variants"]
    if not variants:
        return "<p>Variants: No variants recorded.</p>"
    fixed = sum(item["status"] == "fixed" for item in variants)
    remaining = [item for item in variants if item["status"] != "fixed"]
    detail = " ".join(f"{safe(item['location'])}: {safe(item['reason'])}." for item in remaining)
    status = "! Caution. " if remaining else "✓ Pass. "
    return f"<p>Variants: {fixed}/{len(variants)} fixed. {status}{detail}</p>"


def earlier_attempts(run_dir, attempt: int, items: list[Evidence]) -> str:
    from report_sections import optional

    rows = []
    for number in range(1, attempt):
        patch = optional(run_dir, f"patch/attempt-{number}/patch.json")
        proof = optional(run_dir, f"prove/attempt-{number}/prove.json")
        if not patch and not proof:
            continue
        paths = [f"patch/attempt-{number}/patch.json", f"prove/attempt-{number}/prove.json"]
        summary = f"Attempt {number}: " + (
            f"commit {patch['patch_commit'] or 'none recorded'}" if patch else "no patch record"
        )
        if proof:
            summary += f"; revert {proof['reverted']}"
        rows.append(f"<li>{safe(summary)}. {receipt_links(items, paths)}</li>")
    return "<ul>" + "".join(rows) + "</ul>" if rows else "<p>No earlier attempts were recorded.</p>"
