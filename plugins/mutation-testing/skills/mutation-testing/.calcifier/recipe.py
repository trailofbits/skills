# /// script
# requires-python = ">=3.13"
# dependencies = ["calcifier==0.2.0"]
# ///

import csv
import json
import re
from collections import Counter, defaultdict
from datetime import date
from pathlib import Path
from typing import Any, Literal

import calcifier as c

WORKFLOWS = {
    "configure": (
        "workflows/configuration.md",
        "references/optimization-strategies.md",
    ),
    "hunt": ("workflows/bug-hunter.md",),
    "analyze": (
        "workflows/analyzing-results.md",
        "references/equivalent-mutants.md",
        "references/severity-classification.md",
        "references/report-template.md",
    ),
    "assist": (),
}
TIERS = ("", "Critical", "High", "Medium", "Low")
PREFIXES = "CHML"


@c.output_type
class Finding:
    index: int
    kind: Literal["equivalent", "gap", "unresolved"]
    tier: Literal[0, 1, 2, 3, 4]
    title: str
    context: str
    reason: str
    tests: list[str]
    cases: list[str]
    gap: str
    recommendation: str


@c.output_type
class Result:
    state: Literal["completed", "needs_user_input", "blocked"]
    tool_version: str
    overview: str
    equivalent_intro: str
    findings: list[Finding]


def unpack(value: Any) -> list[dict[str, Any]]:
    if isinstance(value, list) and all(isinstance(item, dict) for item in value):
        return value
    if isinstance(value, dict):
        if isinstance(value.get("files"), dict):
            return [
                {**record, "file": name}
                for name, item in value["files"].items()
                for record in unpack(item.get("mutants", []))
            ]
        for key in ("mutants", "results", "mutations"):
            if key in value:
                return unpack(value[key])
    c.fail("Unrecognized result structure; export a record list as JSON or CSV.")


def parse(text: str, suffix: str) -> list[dict[str, Any]]:
    if suffix.lower() == ".csv":
        raw = list(csv.DictReader(text.splitlines()))
    elif re.match(r"\s*(?:\{|\[\s*[\{\]])", text):
        raw = unpack(json.loads(text))
    else:
        raw = []
        for block in re.split(r"(?m)^(?=\[[A-Z]{2,4}\])", text):
            marker = re.match(r"\[([A-Z]{2,4})\]", block)
            if marker:
                pairs = re.findall(r"(?m)^\s*(\w+):[ \t]*(.*)$", block)
                row = {key.lower(): value for key, value in pairs}
                raw.append(row | {"operator": marker.group(1)})
    if not raw:
        c.fail("No result records parsed. Export SQLite or HTML results to JSON or CSV.")
    rows = []
    for entry in raw:
        nested = entry.get("mutant")
        item = nested | entry if isinstance(nested, dict) else entry
        location = item.get("location") or {}
        start = location.get("start") or {}
        status = item.get("status", item.get("outcome", ""))
        if isinstance(status, dict):
            status = status.get("status", status.get("name", ""))
        status = str(status).casefold()
        filename = item.get("file", item.get("path", item.get("filename", "")))
        line = item.get("line", item.get("line_number", start.get("line", 0)))
        if not filename or not str(line).isdigit() or int(line) < 1 or not status:
            c.fail("A record lacks a source path, positive line number, or status.")
        category = "survived" if status in ("uncaught", "survived", "alive") else "other"
        if status in ("caught", "testfail", "killed"):
            category = "killed"
        if status in ("timeout", "skipped"):
            category = status
        rows.append(
            {
                "file": str(filename),
                "line": int(line),
                "status": status,
                "category": category,
                "original": item.get("original", item.get("original_code", "")),
                "mutated": item.get("mutated", item.get("replacement", item.get("mutation", ""))),
                "operator": item.get("operator", item.get("mutatorName", "")),
            }
        )
    return rows


def table(headers: list[str], rows: list[list[Any]]) -> str:
    return "\n".join(
        "| " + " | ".join(str(v).replace("|", r"\|").replace("\n", " ") for v in row) + " |"
        for row in [headers, ["---"] * len(headers), *rows]
    )


def render(
    result: Result,
    rows: list[dict[str, Any]],
    project: Path,
    inputs: list[str],
    scope: str,
) -> str:
    survivors = [row for row in rows if row["category"] == "survived"]
    sites = {row["index"]: row for row in survivors}
    if len(result.findings) != len(sites) or {f.index for f in result.findings} != set(sites):
        c.fail("Every parsed survivor requires exactly one individual analysis.")
    for finding in result.findings:
        if finding.kind == "gap" and (
            finding.tier == 0
            or not all((finding.title, finding.context, finding.gap, finding.recommendation))
        ):
            c.fail("A confirmed testing gap lacks required analysis or a severity tier.")
        if finding.kind != "gap" and (finding.tier != 0 or not finding.reason.strip()):
            c.fail("Equivalent and unresolved cases require reasons and tier zero.")
    counts = Counter(row["category"] for row in rows)
    equivalent = [f for f in result.findings if f.kind == "equivalent"]
    gaps = [f for f in result.findings if f.kind == "gap"]
    unresolved = [f for f in result.findings if f.kind == "unresolved"]
    killed = counts["killed"]
    denominator = killed + len(survivors)
    adjusted_denominator = denominator - len(equivalent)
    raw = f"{100 * killed / denominator:.2f}% ({killed}/{denominator})" if denominator else "N/A"
    adjusted = (
        f"{100 * killed / adjusted_denominator:.2f}% ({killed}/{adjusted_denominator})"
        if adjusted_denominator
        else "N/A"
    )
    metrics = [
        ["Total mutants generated", len(rows) if scope == "all" else "Not established"],
        ["Mutants killed", killed],
        ["Mutants survived", len(survivors)],
        ["Equivalent mutants", len(equivalent)],
        ["Real surviving mutants", len(gaps)],
        ["Unresolved survivors", len(unresolved)],
        ["Skipped", counts["skipped"]],
        ["Timed out", counts["timeout"]],
        ["Other inconclusive outcomes", counts["other"]],
        ["Mutation kill rate (raw)", raw if scope == "all" else "Not established"],
        ["Adjusted kill rate", adjusted if scope == "all" else "Not established"],
    ]
    lines = [
        "# Mutation Testing Analysis Report",
        f"**Project:** {project.name}\n\n**Repository:** `{project}`",
        f"**Analysis Date:** {date.today().isoformat()}",
        f"**Mutation Testing Tool:** {result.tool_version}",
        "**Analyzer:** Configured worker with mutation-testing skill; model unspecified",
        "## Executive Summary",
        table(["Metric", "Value"], metrics),
        f"Campaign scope: {scope}; {len(rows)} supplied records. Rates exclude skipped, "
        "timed-out, and other inconclusive outcomes. Unresolved survivors remain in the "
        "eligible denominator. Rates do not establish overall test adequacy.",
        "### Key Findings",
        result.overview,
        "### Severity Distribution",
        table(
            ["Tier", "Count", "% of real survivors"],
            [
                [
                    TIERS[tier],
                    sum(f.tier == tier for f in gaps),
                    f"{100 * sum(f.tier == tier for f in gaps) / len(gaps):.2f}%"
                    if gaps
                    else "N/A",
                ]
                for tier in range(1, 5)
            ],
        ),
        "## Equivalent Mutants (False Positives)",
        result.equivalent_intro,
        table(
            ["#", "File", "Line", "Mutation", "Equivalence reason"],
            [
                [
                    f.index,
                    sites[f.index]["file"],
                    sites[f.index]["line"],
                    f"{sites[f.index]['original']} → {sites[f.index]['mutated']}",
                    f.reason,
                ]
                for f in equivalent
            ],
        ),
    ]
    labels = {}
    recommendations: dict[str, list[str]] = defaultdict(list)
    for tier in range(1, 5):
        group = sorted((f for f in gaps if f.tier == tier), key=lambda f: f.index)
        if not group:
            continue
        lines.append(
            f"## Tier {tier}: {TIERS[tier]} Findings\n\nThis tier contains {len(group)} findings."
        )
        for number, finding in enumerate(group, 1):
            label = f"{PREFIXES[tier - 1]}-{number}"
            labels[finding.index] = label
            row = sites[finding.index]
            lines.append(
                f"### Finding {label}: {finding.title}\n\n**File:** `{row['file']}`\n\n"
                f"**Line:** {row['line']}\n\n**Mutation:** `{row['original']}` → "
                f"`{row['mutated']}`\n\n**Mutation Operator:** {row['operator']}\n\n"
                f"**Context:**\n{finding.context}\n\n**Responsible test file(s):** "
                f"{', '.join(finding.tests) or 'No existing test identified'}\n\n"
                f"**Relevant test case(s):** {', '.join(finding.cases) or 'None identified'}\n\n"
                f"**Why this was not caught:**\n{finding.gap}\n\n"
                f"**Recommended test improvement:**\n{finding.recommendation}"
            )
            for test in finding.tests or ["No existing test file identified"]:
                recommendations[test].append(f"- {label}: {finding.recommendation}")
    lines.append("## Recommendations")
    lines.extend(
        f"### `{test}`\n\n" + "\n".join(items) for test, items in sorted(recommendations.items())
    )
    if unresolved:
        lines.append("## Unresolved Cases")
        lines.extend(
            f"- `{sites[f.index]['file']}:{sites[f.index]['line']}`: {f.reason}" for f in unresolved
        )
    source_rows = [
        [
            filename,
            sum(row["file"] == filename for row in survivors),
            *[
                sum(sites[f.index]["file"] == filename and f.tier == tier for f in gaps)
                for tier in range(1, 5)
            ],
        ]
        for filename in sorted({row["file"] for row in survivors})
    ]
    lines.extend(
        [
            "## Appendix\n\n### Input Files Analyzed",
            "\n".join(f"- `{p}`" for p in inputs),
            "### Source Files with Surviving Mutants",
            table(["File", "Total Surviving", "Critical", "High", "Medium", "Low"], source_rows),
            "### Methodology\n\nThe analysis follows Trail of Bits' mutation testing "
            "methodology and the supplied equivalence and severity criteria. Findings "
            "prioritize testing gaps and do not establish vulnerabilities in original code.",
        ]
    )
    return "\n\n".join(lines) + "\n"


def observe(root: Path, argv: list[str]) -> str:
    result = c.run_command(argv, timeout_seconds=60, working_directory=root, mutating=False)
    if result.exit_code:
        c.fail(f"Command failed: {argv!r}\n{result.stderr}\n{result.stdout}")
    return result.stdout


@c.recipe(
    version="1",
    agents=("worker",),
    capabilities=("Bash",),
    budget=c.Budget(max_agent_calls=2, max_wall_seconds=3600),
    output_root=".",
)
def mutation_testing(
    task: str,
    project: str = ".",
    workflow: Literal["configure", "hunt", "analyze", "assist"] = "analyze",
    engine: Literal["mewt", "muton", "other"] = "mewt",
    result_files: tuple[str, ...] = (),
    results_scope: Literal["all", "survivors-only", "unknown"] = "unknown",
    blockchain: bool = False,
) -> str:
    root = Path(project).resolve()
    if not root.is_dir():
        c.fail("The project must be an existing directory.")
    paths = tuple(Path(p).resolve() for p in result_files)
    names = list(WORKFLOWS[workflow])
    if workflow == "analyze" and blockchain:
        names.append("references/blockchain-patterns.md")
    if workflow == "analyze" and engine == "other":
        names.append("references/input-formats.md")
    references = tuple(c.resource(name) for name in names)
    observations: dict[str, Any] = {"records": [], "scope": results_scope}
    for path in paths:
        observations["records"].extend(parse(path.read_text(encoding="utf-8"), path.suffix))
    if not paths and engine != "other":
        observations["help"] = observe(root, [engine, "--help"])
        if workflow in ("hunt", "analyze"):
            observations["status"] = observe(root, [engine, "status"])
            argv = [engine, "results", "--all", "--format", "json"]
            observations["records"] = parse(observe(root, argv), ".json")
            observations["scope"] = "all"
    rows = observations["records"]
    for index, row in enumerate(rows, 1):
        row["index"] = index
    if workflow in ("hunt", "analyze") and not any(r["category"] == "survived" for r in rows):
        c.fail("The inspection scope contains no parsed survivors; no clean report is produced.")
    instructions = (
        f"Assigned workflow: {workflow}. Project: {root}. References: {references}. "
        "Read complete applicable references and preserve the original workflow order and checks. "
        "Optimization guidance is applicable only when its original trigger holds. "
        "Mechanical parsing and command observations do not complete any reasoning phase. "
        "Analyze receives every survivor and returns one Finding per index; use tier zero for "
        "equivalent/unresolved cases. Keep verification reasoning internal; reasons must explain "
        "equivalence or missing evidence. Populate every report field, including responsible "
        "tests, relevant cases, context, gaps, and prose recommendations. Do not implement tests "
        "during analysis; only save intermediate progress if needed. For other workflows, "
        "overview is the complete deliverable and findings is empty. Preserve required user "
        "consultation and campaign data before purging; return needs_user_input when necessary. "
        "Execute adaptive configuration or PoC commands as required. Never commit. Document "
        "configuration choices and identify committing configuration as an owner follow-up. "
        "The recipe renders the final analysis report; do not write that report yourself."
    )
    context = c.prepare_context(
        task,
        instructions=instructions,
        prior_results=json.dumps(observations),
        files=paths,
        readable_roots=(root, *paths),
    )
    result = c.agent(
        "worker",
        "Complete the assigned original workflow using the prepared context.",
        working_directory=root,
        readable_paths=(root, *references, *paths),
        writable_paths=(root,),
        required_capabilities=("commands",),
        context=context,
        output=Result,
        timeout=3600,
    )
    if not result.overview.strip():
        c.fail("The worker returned no deliverable.")
    inputs = [str(path) for path in paths] or [f"{engine} results --all --format json"]
    if workflow == "analyze" and result.state == "completed":
        report = render(result, rows, root, inputs, observations["scope"])
    else:
        report = f"Workflow state: {result.state}\n\n{result.overview}\n"
    filename = "mutation-testing-report.md" if workflow == "analyze" else f"{workflow}-report.md"
    c.emit(str(c.write_text(filename, report)), name="report-path")
    return c.emit(report, name="report")


if __name__ == "__main__":
    raise SystemExit(mutation_testing.cli())


# --- calcifier metadata (skill provenance + sha256) ---
_CALCIFIER_COMPILATION = "compiled"
_CALCIFIER_SKILL = {
    "path": "../SKILL.md",
    "sha256": ("20e6ee2b6cec91bad7572dea966b5fce1e50f9ef8d4bf2e4ba69ac9b679792ff"),
}
_CALCIFIER_RESOURCES = [
    {
        "path": "references/blockchain-patterns.md",
        "sha256": ("8e556f661dfaa88792eee7c0593bef586b02ce7502f2167cc104e83dfcf967c0"),
        "size": 4864,
        "source": None,
    },
    {
        "path": "references/equivalent-mutants.md",
        "sha256": ("ff4e959ec429133b61010892b213c2fd2a2a2b1b4e7d5424e52fc51f909c3e26"),
        "size": 7165,
        "source": None,
    },
    {
        "path": "references/input-formats.md",
        "sha256": ("59107dd286158a4bfbb486f60640053cc8b249948cb6b8bf5bbf19e59270c06c"),
        "size": 2490,
        "source": None,
    },
    {
        "path": "references/optimization-strategies.md",
        "sha256": ("3dda9d912cee153b7340b243cf8823a28b66c03aa34f5516790232075e276614"),
        "size": 8882,
        "source": None,
    },
    {
        "path": "references/report-template.md",
        "sha256": ("6cf4e3b89d5cc3e5be380a4429d68f6796c8d57387a080f5c67f76bfff2c086e"),
        "size": 4426,
        "source": None,
    },
    {
        "path": "references/severity-classification.md",
        "sha256": ("7fe0c245c4599c25fed53f29e5c7048f24e00cba5e5e62eff9ae92728b163b5c"),
        "size": 6066,
        "source": None,
    },
    {
        "path": "workflows/analyzing-results.md",
        "sha256": ("e3e17d2e66cf0dbaa359c051a00540dcdca86a4c5a18147b8268aed03fccd3f7"),
        "size": 6843,
        "source": None,
    },
    {
        "path": "workflows/bug-hunter.md",
        "sha256": ("db4274ed9634cbe7aadef295d594ad15d163f57e6c66a896a20d80827f791a47"),
        "size": 7591,
        "source": None,
    },
    {
        "path": "workflows/configuration.md",
        "sha256": ("f5651cd506c9eb843d25a5e468549c3f417370d9b635b779461549e4083224b0"),
        "size": 11531,
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
        "ed inspection that finds zero issues.\n\nThe last candidat"
        "e passed Calcifier checks but failed the destination repos"
        "itory\nRuff E501 check: it embedded a long mode-to-workflo"
        "w dictionary inside an f-string.\nUse short named lookup c"
        "onstants and keep all generated code lines at most 100\nch"
        "aracters after Ruff formatting for target-version py311. P"
        "reserve the complete\noriginal workflow and the previous c"
        "andidate's functional scope.\n"
    ),
    "sha256": ("9055af200926151a234bea1197131bb80d3ab66a1f8aadee24142645cfd310b2"),
}
_CALCIFIER_SUBRECIPES = []
