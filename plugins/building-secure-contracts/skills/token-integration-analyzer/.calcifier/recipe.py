# /// script
# requires-python = ">=3.13"
# dependencies = ["calcifier==0.2.0"]
# ///

"""Analyze token implementations and integrations without changing the supplied project."""

import json
import re
from datetime import date
from pathlib import Path
from typing import Any, Literal

from calcifier import (
    Budget,
    agent,
    emit,
    ensure_directory,
    fail,
    output_type,
    prepare_context,
    recipe,
    resource,
    run_command,
    step,
    write_json,
    write_text,
)

Risk = Literal["CRITICAL", "HIGH", "MEDIUM", "LOW"]


@output_type
class Check:
    status: Literal["Pass", "Fail", "Unknown", "Not applicable"]
    evidence: str


@output_type
class Pattern:
    presence: Literal["Found", "Not Found", "Blocked", "Not applicable"]
    risk: Literal["Critical", "High", "Medium", "Low"] | None
    evidence: str
    mitigation: str


@output_type
class Recommendation:
    severity: Risk
    issue: str
    evidence: str
    fix: str


@output_type
class OnChain:
    token_information: str
    holder_distribution: str
    exchange_distribution: str
    configuration: str


@output_type
class Integration:
    safe_transfer_usage: str
    defensive_patterns: str
    weird_token_handling: str


@output_type
class Assessment:
    project: str
    token_analyzed: str
    platform: str
    analysis_kind: Literal["implementation", "integration", "both"]
    overall_risk: Risk
    executive_summary: str
    categories: dict[str, str]
    checklist: dict[str, Check]
    patterns: dict[str, Pattern]
    on_chain: OnChain | None
    integration: Integration | None
    recommendations: list[Recommendation]
    limitations: list[str]


@step
def snapshot(
    project_directory: str, source_suffixes: tuple[str, ...]
) -> tuple[str, str, list[str]]:
    root = Path(project_directory).resolve()
    if not root.is_dir():
        fail("Project directory does not exist.")
    out = ensure_directory(".", output_files=("report.md", "assessment.json"))
    if root == out or root.is_relative_to(out):
        fail("Choose an output directory separate from the inspected project.")
    files: list[str] = []
    source_count = 0
    for path in sorted(root.rglob("*")):
        relative = path.relative_to(root)
        if ".git" in relative.parts or path.is_relative_to(out):
            continue
        if path.is_symlink():
            fail("Resolve project symlinks before analysis: " + str(relative))
        if not path.is_file():
            continue
        name = str(relative)
        files.append(name)
        source_count += int(path.suffix.lower() in source_suffixes and path.stat().st_size > 0)
    if not source_count:
        fail("No nonempty source files to inspect; check the directory and source_suffixes.")
    workspace = ensure_directory("workspace", output_files=tuple(files))
    for name in files:
        target = ensure_directory(
            Path("workspace") / Path(name).parent, output_files=(Path(name).name,)
        )
        copied = run_command(
            ["cp", str(root / name), str(target)],
            working_directory=root,
            mutating=True,
            timeout_seconds=120,
        )
        if copied.exit_code:
            fail("Project snapshot failed: " + copied.stderr)
    return str(root), str(workspace), files


def markdown(value: Any, depth: int = 2) -> str:
    if isinstance(value, dict):
        return "\n\n".join(
            "#" * min(depth, 6)
            + " "
            + str(key).replace("_", " ")
            + "\n\n"
            + markdown(item, depth + 1)
            for key, item in value.items()
        )
    if isinstance(value, list):
        return "\n\n".join(markdown(item, depth) for item in value) or "None provided."
    if isinstance(value, str) and not value.strip():
        fail("Assessment contains an empty required report field.")
    return "N/A" if value is None else str(value)


def render(
    result: Assessment,
    categories: dict[str, str],
    patterns: dict[str, str],
    checks: list[tuple[str, str]],
) -> str:
    data = result.model_dump()
    data["analysis_date"] = date.today().isoformat()
    grouped: dict[str, list[str]] = {}
    for number, (group, label) in enumerate(checks, 1):
        item = result.checklist[str(number)]
        mark = "x" if item.status == "Pass" else " "
        grouped.setdefault(group, []).append(
            f"- [{mark}] {label} ({item.status})\n\n{item.evidence}"
        )
    data["checklist"] = grouped
    data["categories"] = {
        f"{key}. {title}": result.categories[key] for key, title in categories.items()
    }
    data["patterns"] = {
        f"{key} {title}": result.patterns[key].model_dump() for key, title in patterns.items()
    }
    data["recommendations"] = {
        severity: [
            item.model_dump() for item in result.recommendations if item.severity == severity
        ]
        for severity in ("CRITICAL", "HIGH", "MEDIUM", "LOW")
    }
    return "# Token Integration Analysis Report\n\n" + markdown(data) + "\n"


@recipe(
    name="token_integration_analyzer",
    version="1",
    capabilities=("Bash",),
    agents=("worker",),
    budget=Budget(max_agent_calls=2, max_wall_seconds=3600),
    output_root="token-analysis-output",
)
def analyze(
    project_directory: str,
    request: str = "",
    contract_address: str = "",
    rpc_endpoint: str = "",
    source_suffixes: tuple[str, ...] = (
        ".sol",
        ".vy",
        ".rs",
        ".move",
        ".cairo",
        ".fc",
        ".func",
        ".tact",
        ".js",
        ".jsx",
        ".ts",
        ".tsx",
        ".mjs",
        ".cjs",
        ".py",
        ".go",
        ".c",
        ".cpp",
    ),
) -> Assessment:
    original, workspace, files = snapshot(project_directory, source_suffixes)
    criteria = resource("resources/ASSESSMENT_CATEGORIES.md")
    templates = resource("resources/REPORT_TEMPLATES.md")
    reference = criteria.read_text(encoding="utf-8")
    categories = dict(re.findall(r"(?m)^##\s+(\d+)\.\s+(.+)$", reference))
    patterns = dict(re.findall(r"(?m)^###\s+(7\.\d+)\s+(.+)$", reference))
    checks: list[tuple[str, str]] = []
    group = ""
    first_template = re.split(r"(?m)^##\s+2\.", templates.read_text(encoding="utf-8"), maxsplit=1)[
        0
    ]
    for line in first_template.splitlines():
        heading = re.match(r"\s*\*\*(.+?)\*\*", line)
        check = re.match(r"\s*-\s+\[x/☐\]\s+(.+)", line)
        if heading:
            group = heading[1]
        if check:
            checks.append((group, check[1]))
    if len(categories) != 10 or len(patterns) != 24 or not checks:
        fail("Packaged assessment references have an unexpected or empty structure.")
    context = prepare_context(
        task=json.dumps(
            {
                "request": request,
                "contract_address": contract_address,
                "rpc_endpoint": rpc_endpoint,
                "snapshot_files": files,
                "category_ids": list(categories),
                "pattern_ids": list(patterns),
                "checklist_count": len(checks),
            }
        ),
        files=(criteria, templates),
        readable_roots=(criteria, templates),
    )
    result = agent(
        "worker",
        "Follow the authoritative skill in order, including all rationalization checks. "
        "The snapshot excludes .git and run outputs; preparation performed no security analysis. "
        "Read the entire workspace and interpret both full references. Use embedded context; "
        "read backing files when absent or verifying them. Adapt tools/tests in the workspace; "
        "keep writes there and distinguish generated properties from actual test results. "
        "Disclose gaps and apply the prescribed manual fallback. Query only with address AND RPC; "
        "otherwise set on_chain=None and disclose missing RPC. With both fill all on-chain fields, "
        "labeling unavailable observations. Include integration for integration/both. Return all "
        "supplied category/pattern IDs and checklist IDs 1 through checklist_count, numbered "
        "across checkbox rows in the first report template. Include evidence and mitigations; use "
        "Blocked/Unknown for unresolved checks and null risk where inapplicable. Address every "
        "reference field; return structured deliverables and keep internal reasoning internal.",
        working_directory=workspace,
        readable_paths=(original, criteria, templates),
        writable_paths=(workspace,),
        required_capabilities=("commands",),
        context=context,
        output=Assessment,
        timeout=3600,
    )
    expected_checks = {str(i) for i in range(1, len(checks) + 1)}
    if (
        set(result.categories) != set(categories)
        or set(result.patterns) != set(patterns)
        or set(result.checklist) != expected_checks
    ):
        fail("Assessment must cover exactly the required categories, patterns and checklist rows.")
    if any(not item.evidence.strip() for item in result.checklist.values()):
        fail("A compliance checklist row has no evidence or explanation.")
    if any(item.presence == "Found" and item.risk is None for item in result.patterns.values()):
        fail("A found weird-token pattern is missing its risk level.")
    if result.analysis_kind in ("integration", "both") and result.integration is None:
        fail("The required integration safety assessment is missing.")
    if contract_address and rpc_endpoint and result.on_chain is None:
        fail("The required on-chain analysis or explicit blocked observations are missing.")
    if result.on_chain is not None and not (contract_address and rpc_endpoint):
        fail("On-chain findings require a supplied address and RPC endpoint.")
    report = render(result, categories, patterns, checks)
    write_text("report.md", report)
    write_json("assessment.json", result.model_dump())
    emit(report, name="report")
    return emit(result, name="assessment")


if __name__ == "__main__":
    raise SystemExit(analyze.cli())


# --- calcifier metadata (skill provenance + sha256) ---
_CALCIFIER_COMPILATION = "compiled"
_CALCIFIER_SKILL = {
    "path": "../SKILL.md",
    "sha256": ("4b7f5cb3c52f9b45e2216963a49458e1f23f5a279a0296e702fd9d8df268b301"),
}
_CALCIFIER_RESOURCES = [
    {
        "path": "resources/ASSESSMENT_CATEGORIES.md",
        "sha256": ("bf1313e59c960688cc73bda5b7a98579336a277c521b9b37937aa1cda3a122a7"),
        "size": 12990,
        "source": None,
    },
    {
        "path": "resources/REPORT_TEMPLATES.md",
        "sha256": ("77dc2195901cbca8f0a04687e6ac51347520b6320cfe2ca7c39d9725ffae1177"),
        "size": 3289,
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
