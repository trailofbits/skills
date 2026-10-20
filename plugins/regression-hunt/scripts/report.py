"""Validate saved decisions and render local reports; never dispatch or adjudicate agents."""

import argparse
import html
import json
import os
from collections import Counter
from pathlib import Path
from urllib.parse import quote

from evidence import IntegrityError, digest, local, read
from registry import accepted, check_change, check_scope, verification

LEVEL_LABELS = {"isolated": "isolated", "shared-host": "shared host"}

OUTCOMES = (
    "REPRODUCED_REGRESSION",
    "INCOMPLETE_FIX",
    "LATENT_BUG",
    "PREEXISTING_BUG",
    "REJECTED",
    "UNRESOLVED",
)
CHECKS = (
    "supported_behavior",
    "reachability",
    "introduced_defect",
    "incomplete_fix",
    "latent_bug",
    "preexisting_bug",
    "intentional_change",
    "unsupported_expectation",
    "security_scope",
)

DECISION_FIELDS = (
    "outcome",
    "reason",
    "evidence",
    "category",
    "severity",
    "likelihood",
    "severity_reason",
    "likelihood_reason",
    "duplicate_of",
)


def require(condition: object, message: str) -> None:
    """Reject incomplete or inconsistent evidence with context."""
    if not condition:
        raise ValueError(message)


def stage(root: Path, name: str, expected: str, change: str | None = None) -> dict:
    """Verify a stage's evidence before interpreting its fields."""
    value = accepted(root, name)
    require(value.get("stage") == expected, f"{name}: expected {expected} record")
    require(value.get("status") in ("complete", "blocked"), f"{name}: invalid status")
    require(value.get("security_review"), f"{name}: missing security document review")
    if change is not None:
        check_change(value, change, name)
    return value


def bound(root: Path, record: str, paths: list[str]) -> None:
    """Require each claimed artifact to occur in the sealed package."""
    seal = read(root, record + ".seal.json")
    available = seal["inputs"] | seal["artifacts"]
    require(all(p in available for p in paths), f"{record}: unsealed referenced evidence")


def experiment(root: Path, name: str, expected: str, source: str) -> dict:
    """Check a claimed live before/after experiment against its pinned source states."""
    value = stage(root, name, expected)
    require(value["status"] == "complete", f"{name}: experiment is blocked")
    require(value.get("source") == source, f"{name}: wrong source boundary")
    runs = value.get("runs", [])
    require(
        isinstance(runs, list) and all(isinstance(r, dict) for r in runs),
        f"{name}: runs must be a list of observations",
    )
    require([r.get("state") for r in runs] == ["S0", "S1"], f"{name}: need S0 and S1 runs")
    pinned = read(root, source)
    paths = [source, value["setup"], value["poc"], value["workload"]]
    for run, behavior in zip(runs, ("correct", "failure"), strict=True):
        require(run.get("revision") == pinned[run["state"].lower()], f"{name}: wrong revision")
        require(run.get("behavior") == behavior, f"{name}: differential result not observed")
        require(run.get("deployment") and run.get("command"), f"{name}: missing live command")
        paths.append(run["log"])
    require(runs[0]["log"] != runs[1]["log"], f"{name}: use separate state logs")
    bound(root, name, paths)
    for run in runs:
        require(local(root, run["log"]).stat().st_size, f"{name}: empty execution log")
    return value


def confirmation(root: Path, name: str, value: dict, change: dict) -> None:
    """Enforce structural proof gates without claiming to validate human reasoning."""
    prepare = stage(root, change["prepare"], "prepare")
    require(prepare["status"] == "complete", f"{name}: preparation is blocked")
    source = prepare["source"]
    bound(root, change["prepare"], [source])
    repro_name, replay_name = value["reproduction"], value["replay"]
    repro = experiment(root, repro_name, "reproduce", source)
    replay = experiment(root, replay_name, "replay", source)
    require(
        len({value["agent"], repro["agent"], replay["agent"]}) == 3,
        f"{name}: reproduction, replay and adjudication need distinct agents",
    )
    require(repro_name in replay["inputs"], f"{replay_name}: missing complete reproduction input")
    for record_name, record in ((repro_name, repro), (replay_name, replay)):
        check_change(record, change["id"], record_name)
        require(record["candidate"] == value["candidate"], f"{record_name}: wrong candidate")
        require(
            {change["prepare"], change["hunt"]} <= set(record["inputs"]),
            f"{record_name}: missing preparation/discovery inputs",
        )
    bound(root, name, [repro_name, replay_name])
    for field in ("poc", "workload"):
        require(
            digest(local(root, repro[field])) == digest(local(root, replay[field])),
            f"{name}: {field} changed during replay",
        )
    require(
        {r["log"] for r in repro["runs"]}.isdisjoint(r["log"] for r in replay["runs"]),
        f"{name}: replay must retain its own logs",
    )
    require(
        value.get("category") in ("VULNERABILITY", "FUNCTIONAL_BUG", "PERFORMANCE", "BUILD_TEST"),
        f"{name}: invalid category",
    )
    require(value.get("severity") in ("Low", "Medium", "High", "Critical"), f"{name}: severity")
    require(value.get("likelihood") in ("Low", "Medium", "High"), f"{name}: likelihood")
    require(
        value.get("severity_reason") and value.get("likelihood_reason"), f"{name}: rating reasons"
    )
    check_conclusions(root, name, value)


def check_conclusions(root: Path, name: str, value: dict) -> None:
    """Reject unknown or contradictory assessments before a confirmation is counted."""
    checks = value.get("checks", {})
    require(isinstance(checks, dict), f"{name}: checks must be an object")
    for key in CHECKS:
        expected = "SUPPORTED" if key in CHECKS[:3] else "REFUTED"
        if key == "security_scope":
            expected = "SUPPORTED" if value["category"] == "VULNERABILITY" else "NOT_APPLICABLE"
        check = checks.get(key, {})
        require(isinstance(check, dict), f"{name}: {key} must contain a conclusion and evidence")
        require(check.get("conclusion") == expected, f"{name}: {key} is not established")
        require(check.get("reason"), f"{name}: explain {key}")
        if expected != "NOT_APPLICABLE":
            require(check.get("evidence"), f"{name}: cite evidence for {key}")
            bound(root, name, check["evidence"])


def failure(error: Exception) -> str:
    if isinstance(error, KeyError):
        return f"missing field {error.args[0]!r}"
    return str(error)


def finding(root: Path, item: dict, change: dict) -> dict:
    """Read a candidate and its optional adjudication without dropping unresolved work."""
    candidate = read(root, item["candidate"])
    require(candidate.get("id") == item["id"], f"{item['id']}: wrong candidate file")
    bound(root, change["hunt"], [item["candidate"]])
    row = {
        "id": item["id"],
        "change": change["id"],
        "input": change["input"],
        "title": candidate["title"],
        "outcome": "UNRESOLVED",
        "reason": "Adjudication pending",
        "evidence": [item["candidate"]],
        "verification": None,
        "unresolved_reason": "Adjudication pending",
    }
    if not item.get("decision"):
        return row
    local(root, item["decision"])
    try:
        return decided(root, item, change, row)
    except IntegrityError:
        raise
    except (OSError, ValueError, KeyError, TypeError) as error:
        reason = failure(error)
        return {
            **row,
            "reason": f"Decision not applied: {reason}",
            "unresolved_reason": reason,
            "evidence": list(dict.fromkeys([item["decision"], *row["evidence"]])),
        }


def decided(root: Path, item: dict, change: dict, row: dict) -> dict:
    """Apply one adjudication; any incomplete evidence leaves the finding unresolved."""
    name = item["decision"]
    value = stage(root, name, "adjudicate")
    check_change(value, change["id"], name)
    require(value.get("candidate") == item["id"], f"{name}: wrong candidate")
    require(value.get("outcome") in OUTCOMES, f"{name}: unknown outcome")
    require(
        value.get("reason") and value.get("evidence"), f"{name}: decision lacks evidence/reason"
    )
    require(
        {change["prepare"], change["hunt"], item["candidate"]} <= set(value["inputs"]),
        f"{name}: missing preparation/discovery/candidate inputs",
    )
    bound(root, name, value["evidence"])
    level = None
    if value["outcome"] == "REPRODUCED_REGRESSION":
        require(value["status"] == "complete", f"{name}: blocked decision cannot confirm")
        confirmation(root, name, value, change)
        level = verification(root, [value["reproduction"], value["replay"], name])
        require(level, f"{name}: reproduction, replay or adjudication lacks a verification level")
    result = {**row, **{k: value[k] for k in DECISION_FIELDS if k in value}}
    result["evidence"] = list(dict.fromkeys([name, *result["evidence"]]))
    result["verification"] = level
    result["unresolved_reason"] = value["reason"] if value["outcome"] == "UNRESOLVED" else None
    return result


def collect(root: Path) -> dict:
    """Reconcile indexed candidates with sealed discovery and decisions."""
    campaign = read(root, "campaign.json")
    check_scope(root, campaign)
    rows, coverage, ids, change_ids = [], [], set(), set()
    for change in campaign["changes"]:
        require(change["id"] not in change_ids, f"Duplicate change ID: {change['id']}")
        change_ids.add(change["id"])
        complete = True
        for role in ("prepare", "hunt"):
            record = stage(root, change[role], role, change["id"]) if change.get(role) else None
            complete = complete and bool(record and record["status"] == "complete")
            if role == "hunt" and record:
                listed = [c["id"] for c in change["candidates"]]
                require(
                    sorted(record["candidates"]) == sorted(listed),
                    f"{change['id']}: discovery/index candidate mismatch",
                )
        for item in change["candidates"]:
            require(item["id"] not in ids, f"Duplicate candidate ID: {item['id']}")
            ids.add(item["id"])
            rows.append(finding(root, item, change))
            complete = complete and rows[-1]["outcome"] != "UNRESOLVED"
        coverage.append(
            {
                "id": change["id"],
                "input": change["input"],
                "status": "COMPLETE" if complete else "INCOMPLETE",
                "limitations": change.get("limitations", ""),
            }
        )
    by_id = {r["id"]: r for r in rows}
    for row in rows:
        if canonical := row.get("duplicate_of"):
            target = by_id.get(canonical, {})
            require(
                target and canonical != row["id"] and not target.get("duplicate_of"),
                f"{row['id']}: invalid duplicate mapping",
            )
            if target["outcome"] == "UNRESOLVED" and row["outcome"] != "UNRESOLVED":
                reason = f"canonical finding {canonical} is unresolved"
                row.update(
                    outcome="UNRESOLVED",
                    reason=f"Decision not applied: {reason}",
                    unresolved_reason=reason,
                    verification=None,
                )
            require(target["outcome"] == row["outcome"], f"{row['id']}: invalid duplicate mapping")
    counts = Counter(r["outcome"] for r in rows if not r.get("duplicate_of"))
    return {
        "title": campaign["title"],
        "counts": {k: counts[k] for k in OUTCOMES},
        "changes": coverage,
        "findings": rows,
    }


def input_label(value: str | dict[str, object]) -> str:
    """Display structured commit inputs while retaining the original object in JSON."""
    if isinstance(value, str):
        return value
    if isinstance(value, dict) and all(k in value for k in ("repository", "s0", "s1")):
        return f"{value['repository']} @ {value['s0']}..{value['s1']}"
    return json.dumps(value, ensure_ascii=False)


def render(root: Path, data: dict, output_name: str = "report") -> None:
    """Write evidence-linked HTML, Markdown and JSON without executing embedded content."""
    output = local(root, output_name)
    output.mkdir(parents=True, exist_ok=True)
    lines = [f"# {data['title']}", "", "Agent conclusions; pending human review.", ""]
    for label, count in data["counts"].items():
        lines.append(f"- {label}: {count}")
    lines.extend(["", "## Coverage", ""])
    for change in data["changes"]:
        lines.append(
            f"- {change['id']}: {change['status']} — "
            f"{input_label(change['input'])}; {change['limitations']}"
        )
    summary = "\n".join(lines[4:])
    sections = []
    for row in data["findings"]:
        label = LEVEL_LABELS.get(row.get("verification") or "")
        outcome = f"{row['outcome']} ({label})" if label else row["outcome"]
        text = [
            f"## {row['id']}: {row['title']}",
            "",
            f"{outcome} — {input_label(row['input'])}",
            "",
            row["reason"],
        ]
        for key in (
            "category",
            "severity",
            "severity_reason",
            "likelihood",
            "likelihood_reason",
            "duplicate_of",
            "unresolved_reason",
        ):
            if row.get(key):
                text.append(f"{key}: {row[key]}")
        links = [
            (p, quote(Path(os.path.relpath(local(root, p), output)).as_posix(), safe="/"))
            for p in row["evidence"]
        ]
        lines.extend(["", *text, "", *[f"- [{p}]({url})" for p, url in links]])
        sections.append(
            "<section><h2>"
            + html.escape(text[0].removeprefix("## "))
            + "</h2><pre>"
            + html.escape("\n\n".join(text[2:]))
            + "</pre><ul>"
            + "".join(
                f'<li><a href="{html.escape(url)}">{html.escape(p)}</a></li>' for p, url in links
            )
            + "</ul></section>"
        )
    (output / "report.md").write_text("\n".join(lines) + "\n")
    (output / "report.json").write_text(json.dumps(data, indent=2) + "\n")
    page = (
        '<!doctype html><meta charset="utf-8"><meta name="viewport" '
        'content="width=device-width,initial-scale=1"><title>'
        + html.escape(data["title"])
        + "</title><style>body{font:16px system-ui;max-width:1000px;margin:3rem auto;padding:1rem;"
        "background:#f5f7fb;color:#172033}section{background:white;padding:1.5rem;margin:1rem 0;"
        "border:1px solid #d9e0eb;border-radius:10px}pre{white-space:pre-wrap;font:inherit;"
        "overflow-wrap:anywhere}a{color:#185abc}</style><h1>"
        + html.escape(data["title"])
        + "</h1><p>Agent conclusions; pending human review. Hash checks establish integrity, "
        "not correctness.</p><pre>" + html.escape(summary) + "</pre>" + "".join(sections)
    )
    (output / "index.html").write_text(page)


def main() -> None:
    """Render a campaign; refuse only on integrity or index errors."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("campaign", type=Path)
    parser.add_argument("--output", default="report", help="Campaign-relative report directory")
    args = parser.parse_args()
    try:
        root = args.campaign.resolve(strict=True)
        data = collect(root)
    except IntegrityError as error:
        parser.exit(1, f"Report integrity error: {error}; no report written\n")
    except (OSError, ValueError, TypeError, KeyError) as error:
        parser.exit(1, f"Report error: {error}; no report written\n")
    try:
        render(root, data, args.output)
    except (OSError, ValueError) as error:
        parser.exit(1, f"Report error: {error}\n")
    print(root / args.output / "index.html")


if __name__ == "__main__":
    main()
