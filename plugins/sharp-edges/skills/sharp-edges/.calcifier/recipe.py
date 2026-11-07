# /// script
# requires-python = ">=3.13"
# dependencies = ["calcifier==0.2.0"]
# ///

"""Review API and configuration designs for security-relevant sharp edges."""

import json
from contextlib import suppress
from pathlib import Path
from typing import Literal

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
    step,
    write_json,
    write_text,
)

REFERENCES = (
    "agents/sharp-edges-analyzer.md",
    "references/auth-patterns.md",
    "references/case-studies.md",
    "references/config-patterns.md",
    "references/crypto-apis.md",
    "references/lang-c.md",
    "references/lang-csharp.md",
    "references/lang-go.md",
    "references/lang-java.md",
    "references/lang-javascript.md",
    "references/lang-kotlin.md",
    "references/lang-php.md",
    "references/lang-python.md",
    "references/lang-ruby.md",
    "references/lang-rust.md",
    "references/lang-swift.md",
    "references/language-specific.md",
)
SEVERITIES = ("Critical", "High", "Medium", "Low")


@output_type
class FileInfo:
    path: str
    size_bytes: int
    text_lines: int | None


@output_type
class Finding:
    severity: Literal["Critical", "High", "Medium", "Low"]
    category: Literal[
        "Algorithm/Mode Selection Footguns",
        "Dangerous Defaults",
        "Primitive vs. Semantic APIs",
        "Configuration Cliffs",
        "Silent Failures",
        "Stringly-Typed Security",
    ]
    title: str
    location: str
    design_issue: str
    misuse_code: str
    misuse_validation: str
    exploitability: str
    documentation: str
    mitigation: str
    mitigation_validation: str


@output_type
class Review:
    status: Literal["complete", "incomplete", "out_of_scope"]
    scope_summary: str
    inspected_files: list[str]
    findings: list[Finding]
    limitations: list[str]


@step
def inventory(scope: Path, artifacts: Path) -> list[FileInfo]:
    records: list[FileInfo] = []
    for path in sorted(scope.rglob("*")):
        relative = path.relative_to(scope)
        if ".git" in relative.parts or path.is_relative_to(artifacts):
            continue
        resolved = path.resolve()
        if not resolved.is_relative_to(scope):
            fail(f"An inspection path escapes the target directory: {relative}")
        if path.is_symlink() and path.is_dir():
            fail(f"Directory symlinks require an explicitly resolved inspection scope: {relative}")
        if not resolved.is_file():
            continue
        data = resolved.read_bytes()
        line_count: int | None = None
        with suppress(UnicodeDecodeError):
            line_count = len(data.decode("utf-8").splitlines())
        records.append(FileInfo(str(relative), len(data), line_count))
    if not records:
        fail("The target contains no inspectable regular files; no analysis was performed.")
    return records


def check_review(review: Review, files: list[FileInfo]) -> list[str]:
    problems: list[str] = []
    if review.status != "complete":
        problems.append("The analysis requires further work; see its scope and limitations.")
    if not review.scope_summary.strip():
        problems.append("The analysis omitted its inspection scope.")
    if not review.inspected_files:
        problems.append("The agent inspected zero files; a clean report cannot be accepted.")
    known = {item.path for item in files}
    if not set(review.inspected_files).issubset(known):
        problems.append("Inspected-file names must identify files in the supplied inventory.")
    for finding in review.findings:
        if any(not str(value).strip() for value in finding.model_dump().values()):
            problems.append(f"A finding omitted required content: {finding.title}")
    return problems


def render(review: Review, problems: list[str]) -> str:
    lines = (
        "# Sharp edges analysis\n\n"
        f"Status: {review.status}\n\n"
        f"{review.scope_summary}\n\n"
        f"## Inspected files ({len(review.inspected_files)})\n"
    ).split("\n")
    lines.extend(f"- {path}" for path in review.inspected_files)
    for severity in SEVERITIES:
        group = [finding for finding in review.findings if finding.severity == severity]
        if group:
            lines.extend(("", f"## {severity}", ""))
        for finding in group:
            lines.extend((f"### {finding.title}", ""))
            for field, value in finding.model_dump().items():
                label = field.replace("_", " ").title()
                lines.extend((f"**{label}**", ""))
                if field == "misuse_code":
                    lines.extend(("```", str(value), "```", ""))
                else:
                    lines.extend((str(value), ""))
    if not review.findings:
        lines.extend(("", "No validated findings reported.", ""))
    lines.extend(("", "## Limitations", ""))
    lines.extend(f"- {item}" for item in review.limitations)
    if not review.limitations:
        lines.append("None reported.")
    if problems:
        lines.extend(("", "## Completion checks", ""))
        lines.extend(f"- {problem}" for problem in problems)
    return "\n".join(lines) + "\n"


@recipe(
    name="sharp-edges",
    version="1.0",
    agents=("worker",),
    capabilities=(),
    budget=Budget(max_agent_calls=2, max_wall_seconds=3600),
    output_root="sharp-edges-artifacts",
)
def sharp_edges(target: str = ".", request: str = "") -> Review:
    scope = Path(target).expanduser().resolve()
    if not scope.is_dir():
        fail("The target must be an existing directory containing the material to inspect.")
    artifacts = ensure_directory(".", output_files=("report.md", "report.json"))
    if scope.is_relative_to(artifacts):
        fail("The inspection target must be outside the recipe's artifact directory.")
    files = inventory(scope, artifacts)
    references = tuple(resource(name) for name in REFERENCES)
    observations = {
        "target_directory": str(scope),
        "excluded": [".git metadata", str(artifacts)],
        "files": [item.model_dump() for item in files],
        "extension_counts": {
            extension: sum(Path(item.path).suffix.lower() == extension for item in files)
            for extension in sorted({Path(item.path).suffix.lower() for item in files})
        },
    }
    context = prepare_context(
        task="Analyze the complete declared target for sharp edges.\n" + request,
        instructions=(
            "Follow the authoritative SKILL.md and complete analyzer reference in one session. "
            "Preserve the four-phase workflow, ordering, quality checklist, severity criteria, "
            "and return to edge-case probing when a finding remains questionable. The inventory "
            "is mechanical preparation, not a list of semantic candidates or proof of coverage. "
            "Understand the complete target and identify its relevant surfaces and choice points; "
            "do not limit analysis to filename extensions or search matches. Read and understand "
            "the applicable complete references, including language guides on demand. Use embedded "
            "assignment and reference text directly; read task.txt or the complete supplied files "
            "when their text is absent. All inventoried files remain in scope, including binaries. "
            "Keep target files unchanged. Use available commands for non-mutating reproduction "
            "and mitigation probes, including in-memory execution when appropriate. Include "
            "minimal misuse code, actual validation observations, exploitability, documentation "
            "review, mitigation, and actual mitigation-test observations for every finding. "
            "An unexecuted example is not a completed reproduction or mitigation test. If any "
            "required validation or meaningful inspection cannot be performed, return incomplete "
            "with explicit limitations instead of claiming completion. Distinguish design "
            "footguns from implementation bugs, business logic flaws, and performance concerns. "
            "Keep reasoning and checklist details internal. Return the requested Review record. "
            "Its scope_summary must explain coverage and exclusions; inspected_files must name "
            "actually inspected files using exact inventory-relative names. Finding locations "
            "should cite supporting files and lines. Include all findings and any unresolved "
            "limitations. A completed inspection may find zero issues; zero inspected files "
            "cannot constitute a completed inspection. Use out_of_scope when appropriate and "
            "explain why in scope_summary."
        ),
        prior_results=json.dumps(observations, ensure_ascii=False),
        files=references,
        readable_roots=references,
    )
    review = agent(
        "worker",
        "Complete the supplied sharp-edges assignment and return the Review record.",
        working_directory=scope,
        readable_paths=(scope, *references),
        writable_paths=(),
        required_capabilities=("commands",),
        output=Review,
        timeout=3600,
        context=context,
    )
    problems = check_review(review, files)
    report = render(review, problems)
    write_json("report.json", review.model_dump())
    write_text("report.md", report)
    emit(review, name="analysis")
    emit(report, name="report")
    if problems:
        fail(" ".join(problems))
    return review


if __name__ == "__main__":
    raise SystemExit(sharp_edges.cli())


# --- calcifier metadata (skill provenance + sha256) ---
_CALCIFIER_COMPILATION = "compiled"
_CALCIFIER_SKILL = {
    "path": "../SKILL.md",
    "sha256": ("3b69a709c2f8f0cfcf57d40a3186e166f307865cc8ed924be4098e549a121e9c"),
}
_CALCIFIER_RESOURCES = [
    {
        "path": "agents/sharp-edges-analyzer.md",
        "sha256": ("c9df773b4a8a56ed88179ef46b8b4eada44092fe4227a683d37bd5219bcbbdae"),
        "size": 8185,
        "source": "../../agents/sharp-edges-analyzer.md",
    },
    {
        "path": "references/auth-patterns.md",
        "sha256": ("1fbf526ca1db7204f9ebb1bf4eb3c48c544676623d23e5d28e01f6f63c355be2"),
        "size": 6999,
        "source": None,
    },
    {
        "path": "references/case-studies.md",
        "sha256": ("2e81a320728b4597bf84c490176d5bf212f1e6ba6f87aafba61ad1734de35332"),
        "size": 8143,
        "source": None,
    },
    {
        "path": "references/config-patterns.md",
        "sha256": ("1d99f2716f7bef18efe71015ce0c56e0f4961c042faa503d796d6d4d1626fdc6"),
        "size": 9729,
        "source": None,
    },
    {
        "path": "references/crypto-apis.md",
        "sha256": ("8baddc83a1f964d6d8b15678d60a37c93029c18dc162bd7c00895e585ff1a825"),
        "size": 5275,
        "source": None,
    },
    {
        "path": "references/lang-c.md",
        "sha256": ("d077d711c73749c924eae81c06018b14bbf1ec9b93d71723c472b43df5d7d5ae"),
        "size": 5683,
        "source": None,
    },
    {
        "path": "references/lang-csharp.md",
        "sha256": ("8fa9e93d36c0e1397b7ca81307163370fc43cf700215b7c6d7aa1b09fdb91fb4"),
        "size": 7324,
        "source": None,
    },
    {
        "path": "references/lang-go.md",
        "sha256": ("839c0e7b4e3fa2f3b37c651e926aa59d69d20bfef5e67f569eedacf11354844d"),
        "size": 6661,
        "source": None,
    },
    {
        "path": "references/lang-java.md",
        "sha256": ("3b93b6049f7e0e356a1ffebc0b4642f3cef315d90be45b63e15c8c4814f9ebeb"),
        "size": 6820,
        "source": None,
    },
    {
        "path": "references/lang-javascript.md",
        "sha256": ("cf72f55d31318666942a8d1d64340befc3c4e7223afc2ca196e6a776ffa4c895"),
        "size": 6933,
        "source": None,
    },
    {
        "path": "references/lang-kotlin.md",
        "sha256": ("c891148c10a4941c3396416a10ac64512eb3a9e13ea5eeaec3902da4b51501dd"),
        "size": 6751,
        "source": None,
    },
    {
        "path": "references/lang-php.md",
        "sha256": ("7960d9773874cf06c5b470a5ca3ab406d896e66b71e713d809bc1ecfcab63485"),
        "size": 6179,
        "source": None,
    },
    {
        "path": "references/lang-python.md",
        "sha256": ("36543becc25b4e3f41eaedcab62e9b204657e6742b8ac95e405bcd040d33bf03"),
        "size": 6616,
        "source": None,
    },
    {
        "path": "references/lang-ruby.md",
        "sha256": ("d9ba749caaccb8a3bb39e2199b2062c0957cf48739218ba8022d49be5cba2088"),
        "size": 6213,
        "source": None,
    },
    {
        "path": "references/lang-rust.md",
        "sha256": ("3d14993ea70b2b2df3fc0f388cbd1631470895c27ccbd9d764296d1da8f5b6ee"),
        "size": 6545,
        "source": None,
    },
    {
        "path": "references/lang-swift.md",
        "sha256": ("a64ab8692db0f3e43526088c63c7fdcb7354d1b24e6fe7ca759aea3260890e04"),
        "size": 6252,
        "source": None,
    },
    {
        "path": "references/language-specific.md",
        "sha256": ("4522b4a37cfd7d3aa689209dfd4569f3b39074bd1f5987a36a6e819f501141b6"),
        "size": 13267,
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
        "ed inspection that finds zero issues.\n\nThe previous comp"
        "lete candidate is supplied below as reference source data."
        "\nPreserve its behavior and make the specific destination "
        "repository lint repair:\nRuff SIM105 rejects try/except Un"
        "icodeDecodeError/pass around line_count. Use\ncontextlib.s"
        "uppress(UnicodeDecodeError) for that optional text decodin"
        "g, without\nchanging scope, source fidelity or binary-file"
        " handling. The destination selects\nE,F,I,UP,B,SIM at line"
        " length 100. Return a complete corrected module.\n"
    ),
    "sha256": ("57909812e53632dc4efa9c73bc379f18a461ef5f500f93c0c98819e4169a3431"),
}
_CALCIFIER_SUBRECIPES = []
