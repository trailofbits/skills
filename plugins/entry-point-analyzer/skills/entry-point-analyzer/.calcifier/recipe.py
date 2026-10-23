# /// script
# requires-python = ">=3.13"
# dependencies = ["calcifier==0.2.0"]
# ///

import json
import re
from datetime import UTC, datetime
from pathlib import Path
from typing import Literal

import calcifier as cf

REFS = {
    ".sol": ("references/solidity.md",),
    ".vy": ("references/vyper.md",),
    ".rs": ("references/solana.md", "references/cosmwasm.md"),
    ".move": ("references/move-sui.md", "references/move-aptos.md"),
    ".fc": ("references/ton.md",),
    ".func": ("references/ton.md",),
    ".tact": ("references/ton.md",),
}


@cf.output_type
class Entry:
    function: str
    line: int
    category: Literal["public", "role", "review", "contract"]
    role_group: Literal["", "admin", "governance", "guardian", "other"]
    role: str
    restriction: str
    detail: str


@cf.output_type
class Analysis:
    languages: list[str]
    warnings: list[str]
    entries: dict[str, list[Entry]]
    gaps: dict[str, str]


def discover(scope: Path, root: Path) -> tuple[list[Path], list[str]]:
    files: list[Path] = []
    warnings: list[str] = []
    pending, seen = [scope], set()
    while pending:
        candidate = pending.pop()
        try:
            resolved = candidate.resolve()
            if not resolved.is_relative_to(root):
                warnings.append(f"Outside-project path omitted: {candidate}")
            elif resolved not in seen:
                seen.add(resolved)
                if candidate.is_dir():
                    pending.extend(p for p in candidate.iterdir() if p.name != ".git")
                elif candidate.is_file():
                    files.append(candidate)
        except (OSError, RuntimeError) as exc:
            warnings.append(f"Unreadable path {candidate}: {exc}")
    return sorted(files), warnings


@cf.step
def slither(project_directory: str) -> str:
    try:
        found = cf.run_command(
            ["which", "slither"],
            timeout_seconds=10,
            working_directory=project_directory,
            mutating=False,
        )
        if found.exit_code or not found.stdout.strip():
            return "Slither unavailable; manual inspection required.\n" + found.stderr
        result = cf.run_command(
            ["slither", ".", "--print", "entry-points"],
            timeout_seconds=180,
            working_directory=project_directory,
            mutating=True,
        )
    except Exception as exc:
        if getattr(exc, "command_failure", None) not in {"launch", "timeout"}:
            raise
        return f"Slither failed; manual inspection required: {exc}"
    return f"Slither exit code: {result.exit_code}\n{result.stdout}\n{result.stderr}"


def table(headers: list[str], rows: list[list[str]]) -> str:
    return "\n".join(
        "| " + " | ".join(c.replace("|", "\\|").replace("\n", "<br>") for c in row) + " |"
        for row in [headers, ["---"] * len(headers), *rows]
    )


def render(title: str, scope: str, a: Analysis, files: list[str]) -> str:
    located = [(reported, e) for reported, entries in a.entries.items() for e in entries]
    names = {
        "public": "Public (Unrestricted)",
        "role": "Role-Restricted",
        "review": "Restricted (Review Required)",
        "contract": "Contract-Only",
    }
    summary = [
        [label, f"{sum(e.category == key for _, e in located)}"] for key, label in names.items()
    ]
    summary.append(["**Total**", f"**{len(located)}**"])
    parts = [
        f"# Entry Point Analysis: {title}\n\n**Analyzed**: {datetime.now(UTC).isoformat()}",
        f"**Scope**: {scope}\n\n**Languages**: {', '.join(a.languages)}",
        "**Focus**: State-changing functions only (view/pure excluded)",
        "## Summary\n\n" + table(["Category", "Count"], summary),
    ]
    specs = [
        ("## Public Entry Points (Unrestricted)", "public", "", "Notes"),
        ("## Role-Restricted Entry Points\n\n### Admin / Owner", "role", "admin", "Restriction"),
        ("### Governance", "role", "governance", "Restriction"),
        ("### Guardian / Pauser", "role", "guardian", "Restriction"),
        ("### Other Roles", "role", "other", "Restriction|Role"),
        ("## Restricted (Review Required)", "review", "", "Pattern|Why Review"),
        ("## Contract-Only (Internal Integration Points)", "contract", "", "Expected Caller"),
    ]
    for heading, kind, group, tail in specs:
        rows = []
        for reported, e in located:
            if e.category == kind and (kind != "role" or e.role_group == group):
                detail = "; ".join(v for v in [e.role, e.restriction, e.detail] if v)
                extra = [e.restriction, e.detail] if kind == "review" else [detail]
                if group == "other":
                    extra.append(e.role)
                rows.append([f"`{e.function}`", f"`{reported}:L{e.line}`", *extra])
        parts.append(heading + "\n\n" + table(["Function", "File", *tail.split("|")], rows))
    file_rows = [
        f"- `{reported}` ({len(a.entries[reported])} state-changing entry points)"
        if reported in a.entries
        else f"- `{reported}` (coverage gap; see Analysis Warnings)"
        for reported in files
    ]
    parts.append("## Files Analyzed\n\n" + "\n".join(file_rows))
    if a.warnings:
        parts.append("## Analysis Warnings\n\n" + "\n".join(f"- {w}" for w in a.warnings))
    return "\n\n".join(parts) + "\n"


@cf.recipe(
    name="entry-point-analyzer",
    agents=("worker",),
    capabilities=("Bash",),
    budget=cf.Budget(max_agent_calls=2, max_wall_seconds=3600),
)
def analyze(project_directory: str = ".", directory_filter: str = ".") -> str:
    root = Path(project_directory).resolve()
    scope = (root / directory_filter).resolve()
    if not root.is_dir() or not scope.is_dir() or not scope.is_relative_to(root):
        cf.fail("The project and filtered scope must be directories within the project.")
    paths, warnings = discover(scope, root)
    for parent in [scope, *scope.parents]:
        if not parent.is_relative_to(root):
            break
        paths.extend(p for p in (parent / "Cargo.toml", parent / "Move.toml") if p.is_file())
    sources = sorted({p for p in paths if p.suffix.lower() in REFS})
    selected = sorted(set(sources) | {p for p in paths if p.name in {"Cargo.toml", "Move.toml"}})
    targets: dict[str, int] = {}
    readable: list[Path] = []
    for source_file in selected:
        try:
            if not source_file.resolve().is_relative_to(root):
                raise ValueError("File resolves outside the project")
            source_text = source_file.read_text(encoding="utf-8")
            readable.append(source_file)
            if source_file in sources:
                targets[source_file.relative_to(root).as_posix()] = len(source_text.splitlines())
        except (OSError, UnicodeError, ValueError, RuntimeError) as exc:
            warnings.append(f"Coverage gap for {source_file}: {exc}; manual review recommended")
    references: list[Path] = []
    reference_names = sorted({ref for p in sources for ref in REFS[p.suffix.lower()]})
    for reference_name in reference_names:
        try:
            reference_file = cf.resource(reference_name)
            reference_file.read_text(encoding="utf-8")
            references.append(reference_file)
        except (OSError, UnicodeError) as exc:
            warnings.append(f"Unreadable reference {reference_name}: {exc}")
    if not targets:
        cf.emit(warnings, name="analysis-warnings")
        cf.fail("No readable contract source files were found; zero files can be inspected.")
    tooling = ""
    if any(p.suffix.lower() == ".sol" for p in sources):
        tooling = slither(project_directory)
    clean = re.sub(r"\x1b\[[0-?]*[ -/]*[@-~]", "", tooling)
    rows = [
        [cell.strip() for cell in line.strip().strip("|").split("|")]
        for line in clean.replace("│", "|").replace("┃", "|").splitlines()
        if "|" in line
    ]
    context = cf.prepare_context(
        "Apply the authoritative skill's complete ordered workflow to every target. "
        "Understand the references; resolve Rust/Move ecosystems from manifests and syntax. "
        "Manually supplement Slither: parsed rows are observations, not exhaustive candidates. "
        "Use embedded files directly; read snapshots/task.txt when absent. Read supporting code "
        "as needed, but report only filtered targets. Map every target exactly once into entries "
        "(possibly empty) or gaps with reasons and manual-review advice. Use qualified signatures "
        "and one-based lines. Restriction records actual checks and access modifiers; detail "
        "records state/call-path conditions, inheritance, signer/capability/object requirements, "
        "review explanations and established caller provenance. Set role/group for role entries.",
        prior_results=json.dumps(
            {"targets": targets, "coverage_gaps": warnings, "slither": tooling, "rows": rows}
        ),
        files=tuple(readable + references),
        readable_roots=(Path(project_directory).resolve(), *references),
    )
    a = cf.agent(
        "worker",
        "Perform the complete assigned analysis and return the typed findings.",
        working_directory=project_directory,
        readable_paths=(Path(project_directory).resolve(), *references),
        context=context,
        output=Analysis,
        timeout=3600,
    )
    covered = set(a.entries) | set(a.gaps)
    if covered != set(targets) or set(a.entries) & set(a.gaps) or not a.languages:
        cf.fail("The analysis omitted or duplicated targets, or did not identify languages.")
    if any(not reason.strip() for reason in a.gaps.values()):
        cf.fail("Every incomplete file requires a coverage-gap explanation.")
    for reported, entries in a.entries.items():
        for e in entries:
            location = bool(e.function.strip()) and 1 <= e.line <= targets[reported]
            role = e.category != "role" or bool(e.role_group and e.role.strip())
            evidence = e.category == "public" or bool(e.restriction.strip())
            detail = e.category not in {"review", "contract"} or bool(e.detail.strip())
            if not (location and role and evidence and detail):
                cf.fail(f"Incomplete classification or invalid source location: {reported}")
    a.warnings.extend(f"{reported}: {reason}" for reported, reason in a.gaps.items())
    a.warnings.extend(warnings)
    files = [p.relative_to(root).as_posix() for p in sources]
    label = "full codebase" if scope == root else scope.relative_to(root).as_posix()
    report = cf.emit(render(root.name, label, a, files), name="entry-point-report")
    if not a.entries:
        cf.fail("No source could be analyzed; review the emitted coverage warnings.")
    return report


if __name__ == "__main__":
    raise SystemExit(analyze.cli())


# --- calcifier metadata (skill provenance + sha256) ---
_CALCIFIER_COMPILATION = "compiled"
_CALCIFIER_SKILL = {
    "path": "../SKILL.md",
    "sha256": ("167dca47592a8bd248916ca06977103cadc6b9492fe701ad6a6464b38fec0aec"),
}
_CALCIFIER_RESOURCES = [
    {
        "path": "references/cosmwasm.md",
        "sha256": ("9190d53ca121d77568dffb86800157770c5f4bb7bcfb58db012d564f15b49d69"),
        "size": 5477,
        "source": None,
    },
    {
        "path": "references/move-aptos.md",
        "sha256": ("8e1f8231ab23bc5eabee0f351338926e6b2a6bf0c55caef45e2e2f68e435e87e"),
        "size": 4009,
        "source": None,
    },
    {
        "path": "references/move-sui.md",
        "sha256": ("681aa8b377d3c622935aaed4eed890a4412b6407e7208c082afd67769424eeac"),
        "size": 3531,
        "source": None,
    },
    {
        "path": "references/solana.md",
        "sha256": ("688de5e95dce753f99c7907566a0dc28fb7c5900156e4cc8b89417a5e7fc3d80"),
        "size": 4810,
        "source": None,
    },
    {
        "path": "references/solidity.md",
        "sha256": ("8e075e3de1800f897da8c7cd2ed5468c2e31f50b3722a490677e97fd79578c78"),
        "size": 5689,
        "source": None,
    },
    {
        "path": "references/ton.md",
        "sha256": ("d2cff4dea2757bd11b222117d7920fbcb9add6a9082027a3fcf054ba699f25c6"),
        "size": 5058,
        "source": None,
    },
    {
        "path": "references/vyper.md",
        "sha256": ("ad1a4c358a36c57e2329e4fe2bc762fac816d0bdc46b1f395b652fd87ef80334"),
        "size": 4306,
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
