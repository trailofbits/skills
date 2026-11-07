# /// script
# requires-python = ">=3.13"
# dependencies = ["calcifier==0.2.0"]
# ///

"""Native variant hunting with host-owned selectors and explicit coverage accounting."""

import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Literal
from urllib.parse import unquote, urlsplit

from calcifier import (
    Budget,
    CommandResult,
    agent,
    emit,
    ensure_directory,
    fail,
    output_type,
    parallel,
    prepare_context,
    recipe,
    resource,
    run_command,
    write_json,
    write_text,
)


@output_type
class Axis:
    kind: Literal["identifier", "manifestation", "edge-case"]
    description: str
    hints: list[str]


@output_type
class RootCause:
    statement: str
    exact_pattern: str
    axes: list[Axis]


@output_type
class Pattern:
    tool: Literal["ripgrep", "semgrep", "codeql"]
    level: Literal[0, 1, 2, 3]
    content: str
    single_change: str


@output_type
class Match:
    match_id: int
    file_index: int
    file: str
    line: int
    end_line: int
    code: str


@output_type
class Verdict:
    match_id: int
    title: str
    is_variant: bool
    severity: Literal["critical", "high", "medium", "low", "informational"]
    confidence: Literal["high", "medium", "low"]
    reasoning: str
    exploitability: str
    reachable: bool
    controllable: bool
    unprotected: bool
    fp_reason: str


@output_type
class Turn:
    verdicts: list[Verdict]
    done: bool
    stopping_reason: str
    next_pattern: Pattern


@output_type
class SearchData:
    matches: list[Match]
    error: str
    diagnostics: str
    argv: list[str]


@output_type
class Scan:
    pattern: Pattern
    matches: list[Match]
    error: str
    diagnostics: str
    argv: list[str]


@output_type
class ReportParts:
    immediate: list[str]
    preventive: list[str]
    limitations: str
    regression_rule: str
    regression_explanation: str


SOURCE_EXTENSIONS = {
    ".py",
    ".pyi",
    ".js",
    ".jsx",
    ".mjs",
    ".cjs",
    ".ts",
    ".tsx",
    ".java",
    ".go",
    ".c",
    ".cc",
    ".cpp",
    ".cxx",
    ".h",
    ".hpp",
    ".rs",
    ".rb",
    ".php",
    ".cs",
    ".swift",
    ".kt",
    ".scala",
    ".sh",
    ".vue",
    ".svelte",
}
LANGUAGE_EXTENSIONS = {
    "python": {".py", ".pyi"},
    "javascript": {".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx", ".vue", ".svelte"},
    "java": {".java"},
    "go": {".go"},
    "cpp": {".c", ".cc", ".cpp", ".cxx", ".h", ".hpp"},
}
SIZING_EXCLUSIONS = {
    "vendor",
    "node_modules",
    "third_party",
    "generated",
    "dist",
    "build",
    "assets",
    "fixtures",
    "testdata",
    "__pycache__",
}
RANKS = {"critical": 0, "high": 1, "medium": 2, "low": 3, "informational": 4}


def cell(value: object) -> str:
    return str(value).replace("|", "&#124;").replace("\n", "<br>")


def block(text: str, language: str = "text") -> str:
    fence = "```"
    while fence in text:
        fence += "`"
    return fence + language + "\n" + text + "\n" + fence


def exclusion(root: Path, destination: Path) -> list[str]:
    if destination.is_relative_to(root):
        return ["--glob", "!" + destination.relative_to(root).as_posix() + "/**"]
    return []


def is_seed(match: Match, seed_index: int, seed_line: int) -> bool:
    return match.file_index == seed_index and match.line <= seed_line <= match.end_line


def execute_search(
    root: Path,
    files: list[Path],
    lookup: dict[str, int],
    backend: Literal["ripgrep", "semgrep", "codeql"],
    stem: Path,
    result: CommandResult,
) -> SearchData:
    """Decode host tool results without launching commands or accepting model selectors."""
    write_text(stem.with_suffix(".stdout"), result.stdout)
    write_text(stem.with_suffix(".stderr"), result.stderr)
    accepted_codes = (0, 1) if backend == "ripgrep" else (0,)
    if result.exit_code not in accepted_codes:
        error = "Search exited with code " + str(result.exit_code)
        return SearchData([], error, result.stderr, result.argv)
    locations: list[tuple[str, int, int]] = []
    diagnostics = result.stderr
    error = ""
    try:
        if backend == "ripgrep":
            for line in result.stdout.splitlines():
                record = json.loads(line)
                if record.get("type") != "match":
                    continue
                data = record["data"]
                if "text" not in data["path"] or "text" not in data["lines"]:
                    error = "A non-UTF-8 match could not be represented; coverage is incomplete."
                    continue
                start = int(data["line_number"])
                length = max(1, len(data["lines"]["text"].splitlines()))
                locations.append((data["path"]["text"], start, start + length - 1))
        elif backend == "semgrep":
            data = json.loads(result.stdout)
            if data.get("errors"):
                error = "Semgrep reported errors: " + json.dumps(data["errors"])
            diagnostics += "\nScan coverage: " + json.dumps(data.get("paths", {}))
            for record in data.get("results", []):
                locations.append(
                    (record["path"], int(record["start"]["line"]), int(record["end"]["line"]))
                )
        else:
            data = json.loads(stem.with_suffix(".sarif").read_text(encoding="utf-8"))
            for run in data.get("runs", []):
                for invocation in run.get("invocations", []):
                    if invocation.get("executionSuccessful") is False:
                        error = "CodeQL reported an unsuccessful analysis invocation."
                for record in run.get("results", []):
                    for location in record.get("locations", []):
                        physical = location["physicalLocation"]
                        uri = physical["artifactLocation"]["uri"]
                        parsed = urlsplit(uri)
                        name = unquote(parsed.path if parsed.scheme else uri)
                        region = physical["region"]
                        start = int(region["startLine"])
                        locations.append((name, start, int(region.get("endLine", start))))
    except (KeyError, TypeError, ValueError) as exc:
        return SearchData([], "Unparseable search results: " + str(exc), diagnostics, result.argv)
    matches: list[Match] = []
    seen: set[tuple[int, int]] = set()
    for name, start, end in locations:
        candidate = Path(name)
        path = (root / candidate).resolve() if not candidate.is_absolute() else candidate.resolve()
        index = lookup.get(str(path))
        if index is None:
            error = "Search returned a location outside the inventoried regular files."
            continue
        try:
            lines = files[index].read_text(encoding="utf-8").splitlines()
        except UnicodeError:
            error = "A matched file is not UTF-8; coverage is incomplete."
            continue
        if not 1 <= start <= end <= len(lines):
            error = "Search returned an invalid source line range."
            continue
        key = (index, start)
        if key not in seen:
            seen.add(key)
            matches.append(
                Match(
                    -1,
                    index,
                    path.relative_to(root).as_posix(),
                    start,
                    end,
                    "\n".join(lines[start - 1 : end]),
                )
            )
    return SearchData(matches, error, diagnostics, result.argv)


def ripgrep_search(
    root: Path,
    destination: Path,
    files: list[Path],
    lookup: dict[str, int],
    stem: Path,
) -> SearchData:
    """Selectors are host-owned; the search expression is read only as file content."""
    result = run_command(
        [
            "rg",
            "--json",
            "--multiline",
            "--hidden",
            "--no-ignore",
            "--glob",
            "!.git/**",
            *exclusion(root, destination),
            "--file",
            str(stem.with_suffix(".pattern")),
            "--",
            str(root),
        ],
        timeout_seconds=300,
        working_directory=root,
        mutating=False,
    )
    return execute_search(root, files, lookup, "ripgrep", stem, result)


def semgrep_search(
    root: Path,
    destination: Path,
    files: list[Path],
    lookup: dict[str, int],
    stem: Path,
) -> SearchData:
    argv = [
        "semgrep",
        "scan",
        "--json",
        "--metrics=off",
        "--disable-version-check",
        "--no-git-ignore",
        "--config",
        str(stem.with_suffix(".pattern")),
        "--exclude",
        ".git",
    ]
    if destination.is_relative_to(root):
        argv.extend(["--exclude", destination.relative_to(root).as_posix()])
    argv.extend(["--", str(root)])
    result = run_command(argv, timeout_seconds=300, working_directory=root, mutating=False)
    return execute_search(root, files, lookup, "semgrep", stem, result)


def codeql_search(
    root: Path,
    files: list[Path],
    lookup: dict[str, int],
    stem: Path,
    database: Path,
) -> SearchData:
    result = run_command(
        [
            "codeql",
            "database",
            "analyze",
            str(database),
            str(stem.with_suffix(".ql")),
            "--format=sarif-latest",
            "--output",
            str(stem.with_suffix(".sarif")),
            "--rerun",
        ],
        timeout_seconds=300,
        working_directory=root,
        mutating=True,
    )
    return execute_search(root, files, lookup, "codeql", stem, result)


def attach_pattern(pattern: Pattern, observed: SearchData) -> Scan:
    return Scan(pattern, observed.matches, observed.error, observed.diagnostics, observed.argv)


def counts(
    scan: Scan,
    verdicts: dict[int, Verdict],
    seed_index: int,
    seed_line: int,
) -> tuple[int, int, int]:
    tp = 0
    fp = 0
    unresolved = 0
    for match in scan.matches:
        verdict = verdicts.get(match.match_id)
        if is_seed(match, seed_index, seed_line) or (verdict and verdict.is_variant):
            tp += 1
        elif verdict is not None:
            fp += 1
        else:
            unresolved += 1
    return tp, fp, unresolved


def axis_turn(
    index: int,
    lane: dict[str, Any],
    root: Path,
    inventory: str,
    issue: str,
    statement: str,
    origin: str,
    exact_pattern: str,
    references: tuple[Path, ...],
    available: list[str],
    known: list[dict[str, Any]],
) -> Turn:
    context = prepare_context(
        "Hunt variants on expansion axis " + str(index) + ".\nKnown bug:\n" + issue,
        prior_results=json.dumps(
            {
                "root_cause": statement,
                "origin": origin,
                "calibrated_exact_pattern": exact_pattern,
                "axis": lane["axis"].model_dump(),
                "complete_inventory": inventory,
                "available_search_tools": available,
                "history": lane["history"],
                "assigned_matches": [m.model_dump() for m in lane["pending"]],
                "known_verdicts": known,
                "remaining_search_slots": max(0, 6 - lane["searches"]),
            }
        ),
    )
    return agent(
        "worker",
        "Continue this axis's connected sweep and adversarial triage using its full "
        "history. Read searching.md now and triage.md before judging candidates. The "
        "complete original workflow remains authoritative. Read surrounding functions, "
        "callers, types, guards and applicable edge cases for EVERY assigned match. "
        "Return exactly one verdict per assigned match_id, including minor and currently "
        "unreachable unprotected variants; attach severity and separate confidence to "
        "every verdict. These are host-discovered matches, not the entire semantic "
        "candidate universe: pursue the whole assigned axis across the whole repository. "
        "You can read all repository files. Do not run commands or change files. "
        "After triage, propose ONE next abstraction change, preserving the ladder and "
        "its one-element-at-a-time reasoning. next_pattern.content is a complete rg "
        "regex file, Semgrep configuration, or CodeQL query, never a command or path. "
        "Read the supplied language template before adapting that tool. Choose only an "
        "available tool; database availability is included there. Retain failed patterns. "
        "When noise exceeds half the matches, revert to the last accepted pattern and "
        "try a different abstraction. Explain the single change. Do not repeat searches "
        "already exhausted in the history. Set done only when this axis has no further "
        "grounded leads, explaining why; on a search-slot cap, describe remaining work. "
        "Return all assigned verdicts even when done. Keep detailed reasoning internal.",
        working_directory=root,
        readable_paths=(root, *references),
        output=Turn,
        timeout=3600,
        context=context,
    )


def render_report(
    issue: str,
    root: Path,
    origin: str,
    original_code: str,
    cause: RootCause,
    scans: list[dict[str, Any]],
    matches: dict[int, Match],
    verdicts: dict[int, Verdict],
    coverage: dict[str, Any],
    parts: ReportParts,
    seed_index: int,
    seed_line: int,
) -> str:
    confirmed = [v for v in verdicts.values() if v.is_variant]
    confirmed.sort(key=lambda verdict: (RANKS[verdict.severity], verdict.match_id))
    lines = [
        "# Variant Analysis Report",
        "",
        "## Summary",
        "",
        "| Field | Value |",
        "|-------|-------|",
        "| Original Bug | " + cell(issue) + " |",
        "| Analysis Date | " + datetime.now(UTC).date().isoformat() + " |",
        "| Codebase | " + cell(root) + " |",
        "| Variants Found | " + str(len(confirmed)) + " |",
        "",
        "## Original Vulnerability",
        "",
        "**Root Cause:** " + cause.statement,
        "",
        "**Location:** `" + origin + "`",
        "",
        block(original_code),
        "",
        "## Search Methodology",
        "",
        "| Version | Pattern | Tool | Matches | TP | FP |",
        "|---------|---------|------|---------|----|----|",
    ]
    for number, record in enumerate(scans):
        scan = record["scan"]
        tp, fp, unresolved = counts(scan, verdicts, seed_index, seed_line)
        fields = [number, scan.pattern.content, scan.pattern.tool, len(scan.matches), tp, fp]
        lines.append("| " + " | ".join(cell(value) for value in fields) + " |")
        if unresolved:
            lines.append("\nUnresolved matches for version " + str(number) + ": " + str(unresolved))
    for number, record in enumerate(scans):
        scan = record["scan"]
        lines.extend(
            [
                "",
                "### Search " + str(number),
                "",
                "Round/axis: " + str(record["round"]) + "/" + str(record["axis"]),
                "",
                "Level " + str(scan.pattern.level) + ": " + scan.pattern.single_change,
                "",
                block(scan.pattern.content),
                "",
                block(json.dumps(scan.argv)),
                "",
                scan.error or "Search command completed.",
                "",
                scan.diagnostics,
            ]
        )
    lines.extend(
        ["", "## Coverage and Stopping Conditions", "", block(json.dumps(coverage, indent=2))]
    )
    lines.extend(["", parts.limitations, "", "## Expansion Axes", ""])
    for index, axis in enumerate(cause.axes):
        lines.append(str(index) + ". " + axis.kind + ": " + axis.description)
        lines.append("   Grounded leads: " + ", ".join(axis.hints))
    if coverage["NEVER_SWEPT"]:
        lines.extend(["", "## Never Swept", ""])
        for index in coverage["NEVER_SWEPT"]:
            lines.append(str(index) + ": " + cause.axes[index].description)
    lines.extend(["", "## Findings", ""])
    if not confirmed:
        lines.append("No variants confirmed within the documented coverage bounds.")
    for number, verdict in enumerate(confirmed, 1):
        match = matches[verdict.match_id]
        lines.extend(
            [
                "",
                "### Variant #" + str(number) + ": " + verdict.title,
                "",
                "| Severity | Confidence | Status |",
                "|----------|------------|--------|",
                "| " + verdict.severity + " | " + verdict.confidence + " | Confirmed |",
                "",
                "**Location:** `" + match.file + ":" + str(match.line) + "`",
                "",
                block(match.code),
                "",
                "**Analysis:** " + verdict.reasoning,
                "",
                "**Exploitability:**",
                "",
            ]
        )
        for label, checked in (
            ("Reachable from external input", verdict.reachable),
            ("User-controlled data", verdict.controllable),
            ("Required protection absent", verdict.unprotected),
        ):
            lines.append("- [" + ("x" if checked else " ") + "] " + label)
        lines.extend(["", verdict.exploitability])
    groups: dict[str, int] = {}
    rejected = [v for v in verdicts.values() if not v.is_variant]
    for verdict in rejected:
        groups.update({verdict.fp_reason: groups.get(verdict.fp_reason, 0) + 1})
    lines.extend(
        [
            "",
            "## False Positive Patterns",
            "",
            "| Pattern | Count | Reason |",
            "|---------|-------|--------|",
        ]
    )
    for reason, count in groups.items():
        lines.append("| Safe candidate group | " + str(count) + " | " + cell(reason) + " |")
    for verdict in rejected:
        match = matches[verdict.match_id]
        lines.extend(
            [
                "",
                "**Candidate:** `" + match.file + ":" + str(match.line) + "`",
                "",
                "Severity: " + verdict.severity + "; confidence: " + verdict.confidence,
                "",
                verdict.reasoning,
                "",
                verdict.exploitability,
            ]
        )
    lines.extend(["", "## Recommendations", "", "### Immediate", ""])
    lines.extend(str(i) + ". " + text for i, text in enumerate(parts.immediate, 1))
    lines.extend(["", "### Preventive", ""])
    lines.extend(str(i) + ". " + text for i, text in enumerate(parts.preventive, 1))
    lines.extend(
        [
            "",
            parts.regression_explanation,
            "",
            "**Final Pattern / Regression Guard:**",
            "",
            block(parts.regression_rule, "yaml"),
            "",
        ]
    )
    return "\n".join(lines)


@recipe(
    name="variant_analysis",
    version="1",
    agents=("worker",),
    capabilities=("Bash",),
    budget=Budget(max_agent_calls=340, max_wall_seconds=3600),
    output_root="variant-analysis-output",
)
def variant_analysis(
    project_directory: str,
    original_issue: str,
    seed_file: str,
    seed_line: int,
    language: Literal["python", "javascript", "java", "go", "cpp"],
    codeql_database: str = "",
    rounds: Literal[2, 4] = 2,
) -> dict[str, Any]:
    root = Path(project_directory).resolve()
    if not root.is_dir() or not original_issue.strip():
        fail("An existing codebase root and a known vulnerability are required.")
    destination = ensure_directory(
        ".",
        output_files=(
            "baseline.pattern",
            "baseline.stdout",
            "baseline.stderr",
            "report.md",
            "regression.yaml",
            "hunt.json",
        ),
    ).resolve()
    if destination == root:
        fail("The output directory must differ from the audited codebase root.")
    inventory_result = run_command(
        [
            "rg",
            "--files",
            "--hidden",
            "--no-ignore",
            "--glob",
            "!.git/**",
            *exclusion(root, destination),
            "--",
            str(root),
        ],
        timeout_seconds=60,
        working_directory=root,
        mutating=False,
    )
    if inventory_result.exit_code not in (0, 1):
        fail("Repository inventory failed: " + inventory_result.stderr)
    files: list[Path] = []
    for name in inventory_result.stdout.splitlines():
        path = Path(name).resolve()
        if not path.is_relative_to(root):
            fail("Inventory contains an escaping symlink: " + name)
        if path.is_file() and path not in files:
            files.append(path)
    files.sort()
    source_files = [p for p in files if p.suffix.lower() in SOURCE_EXTENSIONS]
    if not source_files:
        fail("Inventory contains zero recognized source files; no clean report can be issued.")
    lookup = {str(path): index for index, path in enumerate(files)}
    seed = (root / seed_file).resolve()
    seed_index = lookup.get(str(seed))
    if seed_index is None or seed.suffix.lower() not in SOURCE_EXTENSIONS:
        fail("The trusted seed input must name an inventoried source file inside the root.")
    seed_lines = seed.read_text(encoding="utf-8").splitlines()
    if not 1 <= seed_line <= len(seed_lines):
        fail("The known vulnerable seed line is outside the source file.")
    original_code = "\n".join(seed_lines[max(0, seed_line - 4) : seed_line + 3])
    origin = seed.relative_to(root).as_posix() + ":" + str(seed_line)
    inventory = "\n".join(
        str(i) + ": " + p.relative_to(root).as_posix() for i, p in enumerate(files)
    )
    availability = run_command(
        ["which", "rg", "semgrep", "codeql"],
        timeout_seconds=30,
        working_directory=root,
        mutating=False,
    )
    installed = {Path(line).name for line in availability.stdout.splitlines()}
    available = ["ripgrep"]
    if "semgrep" in installed:
        available.append("semgrep")
    database = Path(codeql_database).resolve() if codeql_database else None
    if database is not None and not database.is_dir():
        fail("The supplied CodeQL database directory does not exist.")
    if "codeql" in installed and database is not None:
        available.append("codeql")
    root_reference = resource("references/root-cause.md")
    context = prepare_context(
        "Extract the known bug's root cause and expansion axes.\n" + original_issue,
        prior_results=json.dumps(
            {
                "origin": origin,
                "actual_seed_context": original_code,
                "complete_inventory": inventory,
                "language": language,
            }
        ),
    )
    cause = agent(
        "worker",
        "Perform the root-cause stage of the original workflow. Read root-cause.md in "
        "full, then the actual vulnerable function and relevant codebase context. State "
        "why the bug exists or the violated invariant. Return an exact ripgrep regex "
        "matching the supplied known vulnerable line, and 3-12 independent grounded "
        "axes spanning identifier families, alternative manifestations and type edge "
        "cases. Include documentation/code mismatches where applicable. Ground hints "
        "in actual repository code, not plausible invented names. You have the complete "
        "repository view; the inventory does not limit semantic analysis. Do not run "
        "commands or modify files. The host will execute and verify exact calibration.",
        working_directory=root,
        readable_paths=(root, root_reference),
        context=context,
        output=RootCause,
        timeout=3600,
    )
    kinds = {axis.kind for axis in cause.axes}
    if not cause.statement.strip() or not 3 <= len(cause.axes) <= 12:
        fail("Root-cause extraction did not supply the required statement and 3-12 axes.")
    if kinds != {"identifier", "manifestation", "edge-case"}:
        fail("Expansion axes omit a required root-cause manifestation family.")
    if any(not axis.hints or not axis.description.strip() for axis in cause.axes):
        fail("Every expansion axis needs a concrete scope and grounded leads.")
    baseline_stem = destination / "baseline"
    write_text(baseline_stem.with_suffix(".pattern"), cause.exact_pattern)
    baseline_observations = ripgrep_search(root, destination, files, lookup, baseline_stem)
    baseline_pattern = Pattern("ripgrep", 0, cause.exact_pattern, "Exact seed calibration")
    baseline = attach_pattern(baseline_pattern, baseline_observations)
    if baseline.error or not any(is_seed(m, seed_index, seed_line) for m in baseline.matches):
        emit(baseline, name="failed-calibration")
        fail("Exact-seed calibration failed; no generalized search was performed.")
    sized = [
        p
        for p in source_files
        if p.suffix.lower() in LANGUAGE_EXTENSIONS[language]
        and not SIZING_EXCLUSIONS.intersection(p.relative_to(root).parts)
    ]
    source_count = len(sized) or len(source_files)
    small = source_count <= 40
    max_rounds = 1 if small else rounds
    width = 2 if small else 6
    references = (
        resource("references/searching.md"),
        resource("references/triage.md"),
        resource("resources/semgrep/" + language + ".yaml"),
        resource("resources/codeql/" + language + ".ql"),
    )
    lanes: list[dict[str, Any]] = [
        {
            "axis": axis,
            "history": [],
            "pending": [],
            "searches": 0,
            "stopped": False,
            "failed": False,
            "exhausted": False,
            "latest": None,
        }
        for axis in cause.axes
    ]
    # Model data only enables existing host slots. It never supplies their values.
    host_slots: list[int] = []
    for slot in range(12):
        if slot < len(lanes):
            host_slots.append(slot)
    matches: dict[int, Match] = {}
    by_location: dict[tuple[int, int], int] = {}
    verdicts: dict[int, Verdict] = {}
    scans: list[dict[str, Any]] = []
    swept: set[int] = set()
    coverage_events: list[dict[str, Any]] = []

    def register(scan: Scan) -> None:
        for match in scan.matches:
            key = (match.file_index, match.line)
            existing = by_location.get(key)
            if existing is None:
                match.match_id = len(matches)
                by_location.update({key: match.match_id})
                matches.update({match.match_id: match})
            else:
                match.match_id = existing

    register(baseline)
    scans.append({"round": 0, "axis": -1, "scan": baseline})
    baseline_pending = [m for m in baseline.matches if not is_seed(m, seed_index, seed_line)]
    dry = 0
    completed_rounds = 0
    # Every path-producing loop uses the fixed host catalog, never model-sized ranges.
    for round_index in range(4):
        if round_index >= max_rounds:
            break
        selected: list[int] = []
        for position in range(6):
            if position < width and position < len(host_slots):
                chosen = host_slots[(round_index * width + position) % len(host_slots)]
                selected.append(chosen)
        before = sum(v.is_variant for v in verdicts.values())
        round_complete = True
        for index in range(12):
            if index not in selected:
                continue
            lane = lanes[index]
            lane.update(
                {"pending": [], "searches": 0, "stopped": False, "exhausted": False, "latest": None}
            )
            folder = "search/r" + str(round_index) + "/a" + str(index)
            planned = tuple(
                "s" + str(i) + suffix
                for i in range(7)
                for suffix in (".pattern", ".ql", ".sarif", ".stdout", ".stderr")
            )
            ensure_directory(folder, output_files=planned)
        if round_index == 0:
            lanes[0]["pending"] = baseline_pending
        for cycle in range(7):
            active: list[int] = []
            for index in range(12):
                if index in selected and not lanes[index]["stopped"]:
                    active.append(index)
            if not active:
                break
            known = [verdict.model_dump() for verdict in verdicts.values()]
            turns = parallel(
                lambda slot, known=known: axis_turn(
                    slot,
                    lanes[slot],
                    root,
                    inventory,
                    original_issue,
                    cause.statement,
                    origin,
                    cause.exact_pattern,
                    references,
                    available,
                    known,
                ),
                active,
                max_workers=6,
            )
            valid: set[int] = set()
            # Separate host positions from model responses; never unpack mixed tuples.
            for position in range(6):
                if position >= len(active):
                    continue
                index = active[position]
                lane = lanes[index]
                if position >= len(turns):
                    lane.update({"failed": True, "stopped": True})
                    lane["history"].append({"error": "Axis worker returned no result."})
                    round_complete = False
                    continue
                turn = turns[position]
                expected = {m.match_id for m in lane["pending"]}
                supplied = [v.match_id for v in turn.verdicts]
                if set(supplied) != expected or len(supplied) != len(expected):
                    lane.update({"failed": True, "stopped": True})
                    lane["history"].append({"error": "Missing, duplicate or extra verdicts."})
                    round_complete = False
                    continue
                if any(
                    not v.reasoning.strip()
                    or not v.exploitability.strip()
                    or (not v.is_variant and not v.fp_reason.strip())
                    for v in turn.verdicts
                ):
                    lane.update({"failed": True, "stopped": True})
                    lane["history"].append({"error": "A verdict omitted required analysis."})
                    round_complete = False
                    continue
                for verdict in turn.verdicts:
                    verdicts.update({verdict.match_id: verdict})
                lane["history"].append({"turn": turn.model_dump()})
                lane["pending"] = []
                valid.add(index)
            jobs: dict[int, Pattern] = {}
            for position in range(6):
                if position >= len(active):
                    continue
                index = active[position]
                if index not in valid:
                    continue
                lane = lanes[index]
                turn = turns[position]
                latest = lane["latest"]
                noisy = False
                if latest is not None:
                    tp, fp, unresolved = counts(latest, verdicts, seed_index, seed_line)
                    noisy = fp > (tp + fp) / 2
                    lane["history"].append(
                        {
                            "host_counts": {"tp": tp, "fp": fp, "unresolved": unresolved},
                            "revert": noisy,
                        }
                    )
                if turn.done:
                    lane["stopped"] = True
                    lane["exhausted"] = (
                        lane["searches"] > 0
                        and not lane["failed"]
                        and bool(turn.stopping_reason.strip())
                    )
                    if not lane["exhausted"]:
                        round_complete = False
                    continue
                if cycle == 6 or lane["searches"] >= 6:
                    lane["stopped"] = True
                    round_complete = False
                    lane["history"].append({"coverage_bound": "Axis iteration cap reached."})
                    continue
                if noisy:
                    lane["latest"] = None
                    lane["history"].append(
                        {
                            "instruction": "Proposed next pattern was not run. Revert and try "
                            "another axis change."
                        }
                    )
                    continue
                if (
                    not turn.next_pattern.content.strip()
                    or not turn.next_pattern.single_change.strip()
                ):
                    lane.update({"failed": True, "stopped": True})
                    round_complete = False
                    continue
                jobs.update({index: turn.next_pattern})
            assigned = {m.match_id for lane in lanes for m in lane["pending"]}
            # The command path uses only fixed host loop indexes and the output root.
            # Membership tests can skip a slot, but model containers never supply it.
            for index in range(12):
                if index not in selected or index not in jobs:
                    continue
                stem = (
                    destination
                    / "search"
                    / ("r" + str(round_index))
                    / ("a" + str(index))
                    / ("s" + str(cycle))
                )
                lane = lanes[index]
                pattern = jobs[index]
                write_text(stem.with_suffix(".pattern"), pattern.content)
                if pattern.tool not in available:
                    observed = SearchData([], "Requested search tool is unavailable.", "", [])
                elif not pattern.content.strip():
                    observed = SearchData([], "The proposed pattern is empty.", "", [])
                elif pattern.tool == "ripgrep":
                    observed = ripgrep_search(root, destination, files, lookup, stem)
                elif pattern.tool == "semgrep":
                    observed = semgrep_search(root, destination, files, lookup, stem)
                elif database is None:
                    observed = SearchData([], "CodeQL requires a supplied database.", "", [])
                else:
                    write_text(stem.with_suffix(".ql"), pattern.content)
                    observed = codeql_search(root, files, lookup, stem, database)
                scan = attach_pattern(pattern, observed)
                lane["searches"] += 1
                lane["latest"] = scan
                register(scan)
                scans.append({"round": round_index + 1, "axis": index, "scan": scan})
                lane["history"].append({"scan": scan.model_dump()})
                if scan.error:
                    lane["failed"] = True
                    round_complete = False
                else:
                    swept.add(index)
                for match in scan.matches:
                    if (
                        not is_seed(match, seed_index, seed_line)
                        and match.match_id not in verdicts
                        and match.match_id not in assigned
                    ):
                        lane["pending"].append(match)
                        assigned.add(match.match_id)
        completed_rounds += 1
        hits = sum(v.is_variant for v in verdicts.values()) - before
        complete = round_complete and all(lanes[i]["exhausted"] for i in selected)
        dry = dry + 1 if hits == 0 and complete else 0
        coverage_events.append(
            {
                "round": completed_rounds,
                "axes": selected,
                "new_confirmed": hits,
                "complete": complete,
            }
        )
        if dry >= 2:
            break
    unresolved_ids = [
        i
        for i, match in matches.items()
        if not is_seed(match, seed_index, seed_line) and i not in verdicts
    ]
    unswept = [i for i in host_slots if i not in swept]
    failed = [i for i in host_slots if lanes[i]["failed"]]
    inspected = sum(not record["scan"].error for record in scans[1:])
    if inspected == 0:
        emit(
            {"scans": [record["scan"].model_dump() for record in scans], "unswept_axes": unswept},
            name="incomplete-hunt",
        )
        fail(
            "Zero successful expansion searches inspected the repository; no clean report is valid."
        )
    swept_to_dry = dry >= 2 and not unswept and not failed and not unresolved_ids
    coverage = {
        "source_file_count": source_count,
        "inventory_file_count": len(files),
        "rounds": completed_rounds,
        "round_events": coverage_events,
        "axes_total": len(lanes),
        "axes_successfully_searched": sorted(swept),
        "NEVER_SWEPT": unswept,
        "failed_axes": failed,
        "unresolved_matches": unresolved_ids,
        "swept_to_dry": swept_to_dry,
        "stop_reason": "swept to dry"
        if swept_to_dry
        else ("small-tree single-round bound" if small else "round/axis/coverage bound"),
        "scope": "Whole repository; source-count exclusions affect sizing only.",
        "codeql_database": str(database) if database else "not supplied",
    }
    eligible = [record["scan"] for record in scans if not record["scan"].error]
    best = max(
        eligible,
        key=lambda scan: sum(
            bool(verdicts.get(m.match_id) and verdicts[m.match_id].is_variant)
            for m in scan.matches
            if not is_seed(m, seed_index, seed_line)
        ),
    )
    report_refs = (
        resource("references/reporting.md"),
        resource("resources/variant-report-template.md"),
        *references[2:],
    )
    data = {
        "root_cause": cause.model_dump(),
        "origin": origin,
        "coverage": coverage,
        "matches": [m.model_dump() for m in matches.values()],
        "verdicts": [v.model_dump() for v in verdicts.values()],
        "searches": [
            {"round": record["round"], "axis": record["axis"], "scan": record["scan"].model_dump()}
            for record in scans
        ],
        "best_pattern": best.pattern.model_dump(),
        "axis_histories": [lane["history"] for lane in lanes],
    }
    report_context = prepare_context(
        "Synthesize recommendations and a regression guard for this completed bounded hunt.",
        prior_results=json.dumps(data),
    )
    parts = agent(
        "worker",
        "Read reporting.md and the complete report template, then the supplied full hunt "
        "data. The host renders every finding separately, severity-ordered, with exact "
        "host-read quotes and Location lines, methodology including failed patterns, "
        "grouped false positives, and explicit coverage bounds. Supply immediate and "
        "preventive recommendations and material limitations without claiming omitted "
        "or failed work was completed. Re-read confirmed code and relevant context as "
        "needed; all repository files are readable. Produce a complete CI-ready Semgrep "
        "YAML rule derived from best_pattern, the host-selected pattern finding the most "
        "confirmed variants. Read the language-specific templates before adapting them. "
        "Explain its derivation and CI use, expected false positives and remaining "
        "validation needs. No variants is a valid result only within actual coverage. "
        "Do not run commands, change files, or invent additional findings.",
        working_directory=root,
        readable_paths=(root, *report_refs),
        context=report_context,
        output=ReportParts,
        timeout=3600,
    )
    if not parts.regression_rule.strip() or not parts.regression_explanation.strip():
        fail("Reporting omitted the required regression guard or its derivation.")
    report = render_report(
        original_issue,
        root,
        origin,
        original_code,
        cause,
        scans,
        matches,
        verdicts,
        coverage,
        parts,
        seed_index,
        seed_line,
    )
    rule_path = destination / "regression.yaml"
    report_path = destination / "report.md"
    write_text(rule_path, parts.regression_rule)
    write_text(report_path, report)
    data.update(
        {
            "recommendations": parts.model_dump(),
            "report": str(report_path),
            "regression_rule": str(rule_path),
        }
    )
    write_json(destination / "hunt.json", data)
    emit(parts.regression_rule, name="regression-rule")
    emit(report, name="variant-report")
    return emit(data, name="hunt-data")


if __name__ == "__main__":
    raise SystemExit(variant_analysis.cli())


# --- calcifier metadata (skill provenance + sha256) ---
_CALCIFIER_COMPILATION = "compiled"
_CALCIFIER_SKILL = {
    "path": "../SKILL.md",
    "sha256": ("7b6b78e499bcb88d05c68254ffc91ebc28edabf4e9808adcc40e2628ebb9407e"),
}
_CALCIFIER_RESOURCES = [
    {
        "path": "references/reporting.md",
        "sha256": ("07a1d8f25537ec3da44b7c6e484bf922ab2eeaee733ced6df423df7bea517906"),
        "size": 1547,
        "source": None,
    },
    {
        "path": "references/root-cause.md",
        "sha256": ("b4556f22adadc894b22c8df01d98bb94596d4e035386c780fbca73594014660c"),
        "size": 4209,
        "source": None,
    },
    {
        "path": "references/searching.md",
        "sha256": ("22834e63e7412220feec9bd1d4cfd9298c17679489ad66d13be450928bf5d158"),
        "size": 4585,
        "source": None,
    },
    {
        "path": "references/triage.md",
        "sha256": ("f1f0277096ae41641be311c783f2f7a1c677c2c6b6e8a485986d8d5ed7fa3653"),
        "size": 3587,
        "source": None,
    },
    {
        "path": "resources/codeql/cpp.ql",
        "sha256": ("efd574081969d2bdd19e1756302d843fdbf936968a72de62eb24d66db43efc0c"),
        "size": 3503,
        "source": None,
    },
    {
        "path": "resources/codeql/go.ql",
        "sha256": ("d3fa419af29bb15bf81510c54bc1ce0cf55f5b7adbdbf79cc2c8cd922d2365fb"),
        "size": 2018,
        "source": None,
    },
    {
        "path": "resources/codeql/java.ql",
        "sha256": ("ee4a92a5cbde67304d17a2c5fb739fe9acf1d39ebac9406e3d3a2c1cbbbb19c1"),
        "size": 2365,
        "source": None,
    },
    {
        "path": "resources/codeql/javascript.ql",
        "sha256": ("b6ceaa3acb6ba6fa89903c14c8fd3aa7cf48316e6b2588dcacae51bb423b3526"),
        "size": 1733,
        "source": None,
    },
    {
        "path": "resources/codeql/python.ql",
        "sha256": ("135ec55760e1e827065e34b002c6d954b4c4293d07233a93d7ff31d9d97528a9"),
        "size": 2447,
        "source": None,
    },
    {
        "path": "resources/semgrep/cpp.yaml",
        "sha256": ("41f034c9a5967cc3b87bf5880243ed21f633017111489ee843dd5d002271b10a"),
        "size": 2795,
        "source": None,
    },
    {
        "path": "resources/semgrep/go.yaml",
        "sha256": ("8a8257eb8e0a7150cb7dffa2b64813691fd560de24b0f85fa6640ec2bfc6595f"),
        "size": 1797,
        "source": None,
    },
    {
        "path": "resources/semgrep/java.yaml",
        "sha256": ("5be3990b052bc9ce5e1aa203d1f3c93cb3cde7d46eba463c24c661fc6b342902"),
        "size": 2011,
        "source": None,
    },
    {
        "path": "resources/semgrep/javascript.yaml",
        "sha256": ("2f97e3545fcac449820c2d058bcb9cc36822e238b6249efa3a5dcb4f5f576912"),
        "size": 1715,
        "source": None,
    },
    {
        "path": "resources/semgrep/python.yaml",
        "sha256": ("c1ce15574569d45555d582707db030b226763d81b2d521d9e61d6067440948f2"),
        "size": 2002,
        "source": None,
    },
    {
        "path": "resources/variant-report-template.md",
        "sha256": ("03333c762318a89dd819784a62695f7660713479a5009a15189314400836202f"),
        "size": 1356,
        "source": None,
    },
    {
        "path": "workflows/variants.js",
        "sha256": ("325fc6b077cd8e2b107d2e13ded23582b573d278928fda7dd23d55c4f8b8e404"),
        "size": 24721,
        "source": "../../workflows/variants.js",
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
        "ed inspection that finds zero issues.\n\nFocused one-line "
        "lint repair of the complete supplied native candidate, whi"
        "ch already passed every Calcifier0.2 source/conformance ch"
        "eck. Preserve ALL behavior, inputs, prompts, model-free ho"
        "st slot catalog, actual search backends, calibration, loop"
        "s, coverage, triage, outputs, resource interfaces and boun"
        "ds. Fix only repository Ruff B023 at the parallel lambda i"
        "nside variant_analysis: bind the loop-local known explicit"
        "ly as a default parameter, using lambda slot, known=known:"
        " axis_turn(slot, lanes[slot], root, inventory, original_is"
        "sue, cause.statement, origin, cause.exact_pattern, referen"
        "ces, available, known). The other captured values do not c"
        "hange inside that loop and were not flagged. Keep max_work"
        "ers=6 and active items unchanged. No redesign, other seman"
        "tic changes, generic wrapper, platform adapters or unavail"
        "able stub. Keep published Calcifier0.2 APIs, Python>=3.13 "
        "and calcifier==0.2.0, Ruff E,F,I,UP,B,SIM py311 maxline100"
        ". Do not copy provenance constants; host owns fresh metada"
        "ta.\n"
    ),
    "sha256": ("dc44277e0773ff3118be79d5cb126d71015231c5a6a1112f03b206f5e7624254"),
}
_CALCIFIER_SUBRECIPES = []
