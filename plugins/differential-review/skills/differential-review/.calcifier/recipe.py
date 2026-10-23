# /// script
# requires-python = ">=3.13"
# dependencies = ["calcifier==0.2.0"]
# ///

import json
import re
from datetime import date
from pathlib import Path
from time import monotonic
from typing import Any, Literal

from calcifier import (
    Budget,
    agent,
    emit,
    fail,
    output_type,
    prepare_context,
    recipe,
    resource,
    run_command,
    step,
    verify_artifact,
    write_text,
)

Risk = Literal["CRITICAL", "HIGH", "MEDIUM", "LOW"]


@output_type
class FileReview:
    path: str
    risk: Risk
    blast_radius: str
    scope_and_observations: str


@output_type
class Finding:
    severity: Risk
    title: str
    reference: str
    commit: str
    callers: int | None
    blast_radius: Risk | Literal["UNKNOWN"]
    test_coverage: Literal["YES", "NO", "PARTIAL"]
    exploitability: Literal["EASY", "MEDIUM", "HARD"]
    details: str


@output_type
class Review:
    overall_risk: Risk
    recommendation: Literal["APPROVE", "REJECT", "CONDITIONAL"]
    confidence: Literal["HIGH", "MEDIUM", "LOW"]
    summary: str
    files: list[FileReview]
    findings: list[Finding]
    test_gap_count: int
    high_blast_count: int
    regressions_count: int
    test_coverage: str
    blast_radius: str
    historical_context: str
    recommendations: str
    methodology: str
    appendices: str


def git(root: str, *args: str) -> str:
    result = run_command(
        ["git", "--no-pager", "-C", root, *args],
        timeout_seconds=120,
        mutating=False,
    )
    if result.exit_code != 0:
        fail(f"Git evidence collection failed: {result.stderr}")
    return result.stdout


def tree(listing: str) -> dict[str, tuple[str, str, str]]:
    entries = {}
    for record in listing.split("\0"):
        if record:
            metadata, path = record.split("\t", 1)
            mode, kind, oid = metadata.split()
            entries[path] = (mode, kind, oid)
    return entries


def blob(root: str, item: tuple[str, str, str] | None, binary: bool) -> str:
    if item is None:
        return ""
    if item[1] != "blob" or binary:
        return f"Content not decoded; Git object metadata: {item}"
    return git(root, "cat-file", "blob", item[2])


@step
def collect(root: str, base: str, head: str) -> str:
    baseline_tree = git(root, "ls-tree", "-r", "--full-tree", "-z", base)
    head_tree = git(root, "ls-tree", "-r", "--full-tree", "-z", head)
    before, after = tree(baseline_tree), tree(head_tree)
    stats = git(
        root,
        "diff",
        "--no-ext-diff",
        "--no-textconv",
        "--no-renames",
        "--numstat",
        "-z",
        base,
        head,
        "--",
    )
    changes = []
    for record in stats.split("\0"):
        if not record:
            continue
        added, removed, path = record.split("\t", 2)
        old = before.get(path)
        binary = added == "-" or removed == "-"
        blame = ""
        if old and old[0].startswith("100") and not binary and removed != "0":
            blame = git(root, "blame", "--line-porcelain", base, "--", path)
        changes.append(
            {
                "path": path,
                "added": added,
                "removed": removed,
                "before": blob(root, old, binary),
                "after": blob(root, after.get(path), binary),
                "baseline_blame": blame,
            }
        )
    if not changes:
        fail("The selected revisions contain no changed files; inspection scope is empty.")
    return json.dumps(
        {
            "base": base,
            "head": head,
            "baseline_tree": baseline_tree,
            "head_tree": head_tree,
            "codebase_files": len(after),
            "changes": changes,
            "timeline": git(root, "log", "--reverse", "--format=%H %aI %s", f"{base}..{head}"),
            "stat": git(root, "diff", "--no-ext-diff", "--no-renames", "--stat", base, head),
            "patch": git(
                root,
                "diff",
                "--no-ext-diff",
                "--no-textconv",
                "--no-renames",
                "--full-index",
                base,
                head,
                "--",
            ),
        },
        ensure_ascii=False,
    )


def cell(value: str) -> str:
    return value.replace("|", "\\|").replace("\r", "").replace("\n", "<br>")


def render(data: dict[str, Any], review: Review) -> str:
    levels = ("CRITICAL", "HIGH", "MEDIUM", "LOW")
    counts = {level: sum(f.severity == level for f in review.findings) for level in levels}
    parts = ["# Executive Summary", "| Severity | Count |\n|---|---|"]
    parts.extend(f"| {level} | {counts[level]} |" for level in levels)
    severity_table = "\n".join(parts[1:])
    parts = [parts[0], severity_table]
    parts.extend(
        [
            f"**Overall Risk:** {review.overall_risk}\n**Recommendation:** {review.recommendation}",
            review.summary,
            f"**Key Metrics:** {len(review.files)} changed files classified; "
            f"{review.test_gap_count} test gaps; {review.high_blast_count} high blast radius "
            f"changes; {review.regressions_count} security regressions.",
            "## What Changed",
            f"**Commit Range:** `{data['base']}..{data['head']}`",
            "```text\n" + data["timeline"] + data["stat"] + "```",
        ]
    )
    assessments = {item.path: item for item in review.files}
    rows = [
        "| File | +Lines | -Lines | Risk | Blast Radius | Scope and Observations |",
        "|---|---|---|---|---|---|",
    ]
    for change in data["changes"]:
        path = change["path"]
        item = assessments[path]
        rows.append(
            f"| {cell(path)} | {change['added']} | {change['removed']} | {item.risk} | "
            f"{cell(item.blast_radius)} | {cell(item.scope_and_observations)} |"
        )
    parts.extend(("\n".join(rows), "## Critical Findings"))
    if not review.findings:
        parts.append("No vulnerabilities identified within the reported analysis scope.")
    for finding in review.findings:
        callers = "UNKNOWN" if finding.callers is None else str(finding.callers)
        parts.extend(
            [
                f"### [{finding.severity}] {finding.title}",
                f"**File:** {finding.reference}\n**Commit:** {finding.commit}",
                f"**Blast Radius:** {callers} callers ({finding.blast_radius})\n"
                f"**Test Coverage:** {finding.test_coverage}\n"
                f"**Exploitability:** {finding.exploitability}",
                finding.details,
            ]
        )
    for title, text in (
        ("Test Coverage Analysis", review.test_coverage),
        ("Blast Radius Analysis", review.blast_radius),
        ("Historical Context", review.historical_context),
        ("Recommendations", review.recommendations),
        ("Analysis Methodology", review.methodology),
        ("Appendices", review.appendices),
    ):
        parts.extend((f"## {title}", text))
    return "\n\n".join(parts) + "\n"


@recipe(
    version="1",
    agents=("worker",),
    capabilities=("Bash",),
    output_root=".",
    budget=Budget(max_agent_calls=2, max_wall_seconds=3600),
)
def differential_review(
    repository: str,
    baseline: str,
    head: str = "HEAD",
    mode: Literal["full", "quick-triage"] = "full",
) -> str:
    started = monotonic()
    root = git(str(Path(repository).resolve()), "rev-parse", "--show-toplevel").strip()
    base = git(
        root,
        "rev-parse",
        "--verify",
        "--end-of-options",
        baseline + "^{commit}",
    ).strip()
    target = git(
        root,
        "rev-parse",
        "--verify",
        "--end-of-options",
        head + "^{commit}",
    ).strip()
    data = json.loads(collect(root, base, target))
    references = tuple(
        resource(name)
        for name in (
            "methodology.md",
            "adversarial.md",
            "patterns.md",
            "reporting.md",
        )
    )
    task = (
        f"Perform the original skill's {mode} review of {base}..{target}. "
        "Preserve its reasoning workflow and checks in order. Prepared observations "
        "complete no reasoning: first understand the entire relevant baseline project. "
        "Use immutable Git-object views instead of changing the checkout; use read-only "
        "Git/history/search commands, never edit files or execute project code. Interpret "
        "the complete references in your declared filesystem view. Finish historical, "
        "test, caller, transitive-impact, and adversarial analysis as required by source. "
        "Classify every changed file; state actual adaptive scope and limitations. "
        "Handle binary/submodule evidence honestly. Apply source applicability exclusions. "
        "Use available optional integrations only when genuinely available, otherwise the "
        "source's manual analysis path. Keep all connected reasoning in this session. "
        "Return final report fragments and one file row per changed path. Finding.details "
        "must include every original finding field: description, history, attacker model, "
        "accessible attack sequence and proof, exploitability justification, concrete "
        "impact, highlighted PoC, root cause, baseline violation, and specific fix. Include "
        "the required timeline and dependency visuals in suitable report fragments. "
        "Report unperformed checks and unavailable evidence; never invent clean results."
    )
    context = prepare_context(task, prior_results=json.dumps(data, ensure_ascii=False))
    review = agent(
        "worker",
        context.prompt,
        working_directory=root,
        readable_paths=(root, *references),
        required_capabilities=("commands",),
        context=context,
        output=Review,
        timeout=3600,
    )
    expected = {item["path"] for item in data["changes"]}
    if {item.path for item in review.files} != expected or len(review.files) != len(expected):
        fail("Final report must classify every changed file exactly once.")
    sections = (
        review.summary,
        review.test_coverage,
        review.blast_radius,
        review.historical_context,
        review.recommendations,
        review.methodology,
        review.appendices,
    )
    if not all(section.strip() for section in sections):
        fail("The final report omitted a required section.")
    if min(review.test_gap_count, review.high_blast_count, review.regressions_count) < 0:
        fail("Report metrics cannot be negative.")
    report = render(data, review)
    project = re.sub(r"[^A-Za-z0-9_.-]+", "_", Path(root).name) or "PROJECT"
    filename = f"{project}_DIFFERENTIAL_REVIEW_{date.today().isoformat()}.md"
    output_path = write_text(filename, report)
    verify_artifact(output_path)
    notification = (
        f"Report: {output_path}\nSize: {len(report.encode('utf-8'))} bytes\n"
        f"Review time: {(monotonic() - started) / 3600:.2f} hours\n"
        f"Findings: {len(review.findings)}; recommendation: {review.recommendation}; "
        f"confidence: {review.confidence}.\nReview findings and address CRITICAL/HIGH "
        "issues before merge. Consider issue-writer for a stakeholder report."
    )
    emit(notification, name="review-summary")
    return emit(report, name="differential-review")


if __name__ == "__main__":
    raise SystemExit(differential_review.cli())


# --- calcifier metadata (skill provenance + sha256) ---
_CALCIFIER_COMPILATION = "compiled"
_CALCIFIER_SKILL = {
    "path": "../SKILL.md",
    "sha256": ("f9af6a8193fc1a9f8ca3c54bb8d19095a5f20c9472ca6d014488bbde50b67da0"),
}
_CALCIFIER_RESOURCES = [
    {
        "path": "adversarial.md",
        "sha256": ("3cb823f38c6e551cbcf5f72325d2bb219dacdad774072519c31d50d92db19800"),
        "size": 5062,
        "source": None,
    },
    {
        "path": "agents/adversarial-modeler.md",
        "sha256": ("f7be8413601990ceae260f2b1e3557f6d33022e7c4279eaedbed0a7d3bc919e6"),
        "size": 5746,
        "source": "../../agents/adversarial-modeler.md",
    },
    {
        "path": "methodology.md",
        "sha256": ("16b335d24cf2145e3dc4a37f50056550d29db2efa20e6df78fec95ec1e6fb0b4"),
        "size": 6738,
        "source": None,
    },
    {
        "path": "patterns.md",
        "sha256": ("52abb18abbc73502a3d3b2f36a7a035adc1db40fd812d1d5424cf065036a06e9"),
        "size": 6999,
        "source": None,
    },
    {
        "path": "reporting.md",
        "sha256": ("0016876dc6f158e926448bff1b6f634796757c7afe09dff177cfe30250724fc4"),
        "size": 7006,
        "source": None,
    },
]
_CALCIFIER_INTERFACE = {
    "text": (
        "The destination repository uses Ruff rules E, F, I, UP, B,"
        " and SIM, target-version py311, and line-length 100. The g"
        "enerated recipe must satisfy those checks, including B007,"
        " B905, and SIM102. Keep the Python 3.13 minimum required b"
        "y Calcifier in its generated PEP 723 header. This skill is"
        " distributed independently: do not require another unmerge"
        "d skill recipe. Referenced prose and explicitly provided r"
        "esources may be packaged, while the generated recipe belon"
        "gs only to the requested skill. Repository contribution ru"
        "le: a checker that inspects zero items must fail with an e"
        "xplanation rather than return a successful clean report. T"
        "his applies to an empty inspection scope, not to a complet"
        "ed inspection that finds zero issues."
    ),
    "sha256": ("12c73b0662a6bdb615688c499f4e3e22540e4788549e5ad24bb7e01f76c25fcc"),
}
_CALCIFIER_SUBRECIPES = []
