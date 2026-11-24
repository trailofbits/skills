"""Run the full dimensional audit with persisted scope and comment-only edits."""

import json
import re
from pathlib import Path
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
    tool,
)


@output_type
class Classification:
    index: int
    category: Literal[
        "math-library",
        "oracle-integration",
        "conversion",
        "core-logic",
        "peripheral",
        "chain-specific",
    ]


@output_type
class ScanReview:
    files: list[Classification]
    explanation: str


@output_type
class Vocabulary:
    base_units: list[str]
    derived_units: list[str]
    precision_prefixes: list[str]
    protocol_specific: list[str]
    uncertainties: list[str]


@output_type
class Finding:
    id: str
    severity: Literal["CRITICAL", "HIGH", "MEDIUM", "LOW"]
    type: str
    line: int
    description: str
    analysis: str
    impact: str
    recommendation: str
    code_snippet: str
    fix_snippet: str


@output_type
class Outcome:
    index: int
    status: Literal[
        "ANNOTATED",
        "REVIEWED_NO_ANCHOR_CHANGES",
        "PROPAGATED",
        "REVIEWED_NO_PROPAGATION_CHANGES",
        "VALIDATED",
        "BLOCKED",
    ]
    reason: str
    annotations_added: int
    confidence_counts: dict[str, int]
    functions_analyzed: int
    expressions_checked: int
    annotations_used: int
    annotated_functions: int
    total_functions: int
    annotated_variables: int
    total_variables: int
    uncertainties_resolved: int
    interface_context: str
    formula_analysis: str
    coverage_gaps: list[str]
    findings: list[Finding]
    confirmed_ids: list[str]
    refuted_ids: list[str]


@output_type
class BatchResult:
    files: list[Outcome]


def reference(name: str) -> str:
    return resource(name).read_text(encoding="utf-8")


def persist(root: Path, name: str, value: Any) -> None:
    content = value if isinstance(value, str) else json.dumps(value, indent=2)
    tool("Write", file_path=str(root / name), content=content)


def invoke(root: Path, task: str, refs: list[str], data: Any, output: Any) -> Any:
    instructions = "\n\n".join(reference(name) for name in refs)
    context = prepare_context(
        task,
        instructions=instructions,
        prior_results=json.dumps(data),
    )
    return agent(
        "worker",
        task,
        working_directory=root,
        readable_paths=(root,),
        writable_paths=(root,),
        context=context,
        output=output,
        timeout=3600,
    )


def batches(entries: list[dict[str, Any]]) -> list[list[int]]:
    if len(entries) <= 10:
        return [[entry["index"] for entry in entries]] if entries else []
    result = []
    for category in (
        "math-library",
        "oracle-integration",
        "conversion",
        "core-logic",
        "chain-specific",
        "peripheral",
    ):
        group = [e["index"] for e in entries if e["category"] == category]
        size = 8 if len(entries) > 30 and len(group) > 10 else max(len(group), 1)
        result.extend(group[start : start + size] for start in range(0, len(group), size))
    return result


@recipe(
    name="dimensional_analysis",
    version="1",
    agents=("worker",),
    capabilities=("Write",),
    budget=Budget(max_agent_calls=None, max_wall_seconds=3600),
)
def dimensional_analysis(project_root: str) -> dict[str, Any]:
    root = Path(project_root).resolve()
    if not root.is_dir():
        fail("BLOCKED: target must be an existing writable project directory.")
    emit("Selected mode: full-auto", name="mode")
    scanner = reference("agents/arithmetic-scanner.md")
    groups = re.findall(r"^\| ([^|]+) \| `([^`]+)` \|", scanner, re.MULTILINE)
    suffixes = {".sol", ".rs", ".go", ".py", ".ts", ".tsx", ".js", ".cairo"}
    excluded = {"test", "tests", "node_modules", "vendor", "target", "third_party"}
    excluded.update({"external", "script", "scripts", "mock", "mocks"})
    inventory = sorted(
        p
        for p in root.rglob("*")
        if p.is_file()
        and p.suffix in suffixes
        and ".git" not in p.parts
        and p.resolve().is_relative_to(root)
    )
    observations = []
    excluded_count = 0
    for path in inventory:
        relative = path.relative_to(root).as_posix()
        if excluded.intersection(path.relative_to(root).parts) or any(
            marker in relative for marker in (".t.sol", "_test.", "_test/")
        ):
            excluded_count += 1
            continue
        lines = path.read_text(encoding="utf-8").splitlines()
        hits = {}
        for position, (name, pattern) in enumerate(groups):
            regex = re.compile(pattern.replace("\\|", "|"))
            count = sum(bool(regex.search(line)) for line in lines)
            if count:
                hits[name.strip()] = {"count": count, "high": position < 8}
        score = sum(v["count"] * (3 if v["high"] else 2) for v in hits.values())
        score += min(len(hits), 5)
        tier = "CRITICAL" if score >= 20 else "HIGH" if score >= 10 else "MEDIUM"
        observations.append(
            {
                "index": len(observations),
                "path": str(path),
                "patterns_found": hits,
                "score": score,
                "priority": tier if score >= 5 else "LOW",
            }
        )
    review = invoke(
        root,
        (
            "Perform arithmetic-scanner review using the complete inventory and exhaustive "
            "pattern counts. Read the target as needed. Return every in-scope arithmetic "
            "file by its supplied index and semantic category, including all matching files. "
            "Search observations are not a semantic exclusion screen. No source edits yet."
        ),
        ["references/step1.md", "agents/arithmetic-scanner.md"],
        observations,
        ScanReview,
    )
    indexes = [item.index for item in review.files]
    required = {e["index"] for e in observations if e["patterns_found"]}
    if len(indexes) != len(set(indexes)) or not required.issubset(indexes):
        fail("Scanner omitted matching files or returned duplicate scope entries.")
    if any(index < 0 or index >= len(observations) for index in indexes):
        fail("Scanner returned an unknown inventory index.")
    entries = [dict(observations[item.index], category=item.category) for item in review.files]
    for entry in entries:
        entry.update(phase2="PENDING", phase3="PENDING", phase4="PENDING")
    focus = [
        e["path"]
        for e in entries
        if len(entries) <= 50
        or e["priority"]
        in (
            "CRITICAL",
            "HIGH",
        )
    ]
    ordered = batches(entries)
    scope = {
        "project_root": str(root),
        "in_scope_files": entries,
        "discoverer_focus_files": focus,
        "recommended_discovery_order": [
            {"phase": i + 1, "files": [observations[j]["path"] for j in batch]}
            for i, batch in enumerate(ordered)
        ],
        "scan_summary": {
            "total_files_scanned": len(inventory),
            "files_excluded": excluded_count,
            "files_with_arithmetic": len(entries),
            "files_without_matches": len(observations) - len(entries),
        },
    }
    persist(root, "DIMENSIONAL_SCOPE.json", scope)
    vocabulary_path = root / "DIMENSIONAL_UNITS.md"
    vocabulary = Vocabulary([], [], [], [], [])
    if entries:
        existing = vocabulary_path.read_text(encoding="utf-8") if vocabulary_path.exists() else None
        vocabulary = invoke(
            root,
            (
                "Complete Phase 1 vocabulary work. Existing vocabulary, when supplied, must "
                "be parsed and reused without rediscovery. Otherwise follow discovery focus "
                "and dependency order. Return the glossary fields with confidence and sources "
                "in each description. Scope has already been persisted."
            ),
            ["references/step1.md", "agents/dimension-discoverer.md"],
            {
                "scope": scope,
                "existing_vocabulary": existing,
            },
            Vocabulary,
        )
        if existing is None:
            sections = ["# Dimensional Units"]
            for key, values in vocabulary.model_dump().items():
                sections.append("## " + key.replace("_", " ").title())
                sections.extend("- " + value for value in values)
            persist(root, "DIMENSIONAL_UNITS.md", "\n\n".join(sections))
    history = []
    by_index = {e["index"]: e for e in entries}
    roles = ("dimension-annotator", "dimension-propagator", "dimension-validator")
    allowed = (
        {"ANNOTATED", "REVIEWED_NO_ANCHOR_CHANGES"},
        {"PROPAGATED", "REVIEWED_NO_PROPAGATION_CHANGES"},
        {"VALIDATED"},
    )
    for phase, role in enumerate(roles, 2):
        if not entries:
            break
        refs = [f"references/step{phase}.md", f"agents/{role}.md"]
        refs += (
            ["references/annotate.md"]
            if phase == 2
            else [
                "references/dimension-algebra.md",
            ]
        )
        if phase == 4:
            refs += ["references/bug-patterns.md", "references/common-dimensions.md"]
        work = ordered
        if phase == 4:
            work = [[e["index"]] for e in entries]
        for batch in work:
            pending = batch
            for attempt in range(2):
                result = invoke(
                    root,
                    (
                        f"Execute Phase {phase} for every assigned index in order. Preserve "
                        "the authoritative role workflow and read full source files, glossary, "
                        "scope, and relevant callees. Comments only; preserve pre-existing edits. "
                        "Return per-file outcomes, actual counters and formula analyses. "
                        "Use zero counters for inapplicable fields. Validation must confirm or "
                        "refute prior mismatch IDs and return confirmed plus new dimensional "
                        "findings only, with no duplicates. Do not fix code or commit. "
                        "This is a focused BLOCKED retry when attempt is 1."
                    ),
                    refs,
                    {
                        "assigned": [by_index[i] for i in pending],
                        "scope": scope,
                        "prior_results": history,
                        "attempt": attempt,
                    },
                    BatchResult,
                )
                if sorted(o.index for o in result.files) != sorted(pending):
                    fail("Missing or duplicate required per-file outcomes.")
                retry = []
                for outcome in result.files:
                    if outcome.status not in allowed[phase - 2] | {"BLOCKED"}:
                        fail("Invalid status for the active phase.")
                    if not outcome.reason.strip():
                        fail("Every phase outcome requires a reason.")
                    by_index[outcome.index][f"phase{phase}"] = outcome.status
                    history.append({"phase": phase, **outcome.model_dump()})
                    if outcome.status == "BLOCKED":
                        retry.append(outcome.index)
                persist(root, "DIMENSIONAL_SCOPE.json", scope)
                pending = retry
                if not pending:
                    break
    report = {
        "mode": "full-auto",
        "project_root": str(root),
        "vocabulary": vocabulary.model_dump(),
        "scope": scope,
        "results": history,
    }
    persist(root, "DIMENSIONAL_REPORT.json", report)
    return emit(report, name="dimensional-analysis")


if __name__ == "__main__":
    raise SystemExit(dimensional_analysis.cli())


# --- calcifier metadata (skill provenance + sha256) ---
_CALCIFIER_COMPILATION = "compiled"
_CALCIFIER_SKILL = {
    "path": "../SKILL.md",
    "sha256": ("e3a091ca6acd079a00044a74929153bd569731b08c24b4bbaba59203c734a67c"),
}
_CALCIFIER_RESOURCES = [
    {
        "path": "agents/arithmetic-scanner.md",
        "sha256": ("9083b95023653649d84a8a3a5e97f8016dabef7d07bc8ea46a1217872ea66145"),
        "size": 11046,
        "source": "../../agents/arithmetic-scanner.md",
    },
    {
        "path": "agents/dimension-annotator.md",
        "sha256": ("29ab595a4d4361062f542bffdf89d613eebe9a800f566fcc17788d3b7e2c049c"),
        "size": 8808,
        "source": "../../agents/dimension-annotator.md",
    },
    {
        "path": "agents/dimension-discoverer.md",
        "sha256": ("520971dca1b7a9fbc3f6595732a4ab8af0f473452487c14f5ebfa97c9b3a2863"),
        "size": 7947,
        "source": "../../agents/dimension-discoverer.md",
    },
    {
        "path": "agents/dimension-propagator.md",
        "sha256": ("4f4fe60e30e143ba94b2d388b8e20ee1f1730bff2c7fa285818ed3651bbf1457"),
        "size": 9878,
        "source": "../../agents/dimension-propagator.md",
    },
    {
        "path": "agents/dimension-validator.md",
        "sha256": ("1235c0bc3377ff8efd272026ada7787a5cd1dca3bb38dc3d1f5f40b38a88046b"),
        "size": 12918,
        "source": "../../agents/dimension-validator.md",
    },
    {
        "path": "references/annotate.md",
        "sha256": ("c7d1a0987d4da875067ee8523c1a0f40984eae4c6e6b344df59d2bbf3b7f0cd9"),
        "size": 11953,
        "source": None,
    },
    {
        "path": "references/bug-patterns.md",
        "sha256": ("36818df67fc45815ce288412fac6d0bdd93da5e856d7cf8dcbe56b1d255dd526"),
        "size": 11930,
        "source": None,
    },
    {
        "path": "references/common-dimensions.md",
        "sha256": ("5743496a380719fc601b592abbe357c0d2d95273ae38b019ff6da28cac77ee2d"),
        "size": 7524,
        "source": None,
    },
    {
        "path": "references/dimension-algebra.md",
        "sha256": ("e60adc2108c89cb698626a8c62fe3ed65480e434c00b44a2bc9f2e43deb2bfd7"),
        "size": 6500,
        "source": None,
    },
    {
        "path": "references/step1.md",
        "sha256": ("a8efef39c615993eb99f3d8739f640f283ef05ef9c092ef235b5082a455736d6"),
        "size": 5232,
        "source": None,
    },
    {
        "path": "references/step2.md",
        "sha256": ("4b56acee23259c5528b28c035e61ce5d2db7720003a49d4c1bf0a84d18da8460"),
        "size": 3682,
        "source": None,
    },
    {
        "path": "references/step3.md",
        "sha256": ("e6a43d2fc5f7a7adf0df560627add775d2b3f3b3da6044d31212fc4d8948ff77"),
        "size": 4027,
        "source": None,
    },
    {
        "path": "references/step4.md",
        "sha256": ("5512f35bc4c458e0ea311b29397a92dc5ec4b788f9ddd4adbe7ef31c14a30f09"),
        "size": 6697,
        "source": None,
    },
]
_CALCIFIER_INTERFACE = {
    "text": (
        "Preserve the complete full-auto dimensional analysis workf"
        "low using all five packaged role prompts. Include .cairo e"
        "xactly in any source extension filter; source suffixes are"
        " lowercase and contain no spaces. Honor root Ruff E,F,I,UP"
        ",B,SIM at a 100-character line length.\n"
    ),
    "sha256": ("638e29c397f443a7575503c4dabc43ba3f824da3277e9dd61f88b9350c90665e"),
}
_CALCIFIER_SUBRECIPES = []
