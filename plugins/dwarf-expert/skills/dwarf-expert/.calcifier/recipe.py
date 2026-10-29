# /// script
# requires-python = ">=3.13"
# dependencies = ["calcifier==0.2.0"]
# ///

"""Prepare DWARF evidence and retain connected reasoning in one expert session."""

import json
from pathlib import Path
from shutil import which
from typing import Any, Literal

from calcifier import (
    Budget,
    agent,
    emit,
    fail,
    output_type,
    prepare_context,
    recipe,
    run_command,
    step,
    tool,
)


@output_type
class Observation:
    argv: list[str]
    exit_code: int
    stdout: str
    stderr: str
    parsed_json: Any


@output_type
class Answer:
    status: Literal["complete", "blocked"]
    answer: str


@step
def capture(argv: list[str], json_output: bool = False) -> Observation:
    result = run_command(argv, timeout_seconds=120, mutating=False)
    parsed: Any = None
    if result.exit_code == 0 and json_output:
        try:
            parsed = json.loads(result.stdout)
        except json.JSONDecodeError:
            fail("The statistics command succeeded but did not return valid JSON.")
    return Observation(argv, result.exit_code, result.stdout, result.stderr, parsed)


def resolve_inputs(values: tuple[str, ...], root: Path, bundles: bool = False) -> list[str]:
    paths: list[str] = []
    for value in values:
        path = (root / value).resolve(strict=True)
        if bundles and path.is_dir() and path.suffix.lower() == ".dsym":
            payload = path / "Contents" / "Resources" / "DWARF"
            if not payload.is_dir():
                fail(f"No DWARF payload directory exists in {path}.")
            members = sorted(item for item in payload.iterdir() if item.is_file())
            if not members:
                fail(f"The dSYM inspection scope is empty: {path}.")
            if any(not item.resolve().is_relative_to(path) for item in members):
                fail(f"The dSYM contains a payload symlink escaping its bundle: {path}.")
            paths.extend(str(item.resolve()) for item in members)
        elif path.is_file():
            paths.append(str(path))
        else:
            fail(f"Expected a regular file or supported dSYM bundle: {path}.")
    return list(dict.fromkeys(paths))


@step
def inspect_binaries(
    paths: list[str],
    section: Literal["all", "info", "line"],
    verify: bool,
    statistics: bool,
    symbol: str,
    program_address: str,
) -> list[Observation]:
    observations: list[Observation] = []
    if not paths:
        return observations
    llvm: str | None = None
    other: str | None = None
    for name in ("llvm-dwarfdump", "dwarfdump"):
        executable = which(name)
        if executable is None:
            continue
        version = capture([executable, "--version"])
        observations.append(version)
        if version.exit_code == 0 and "llvm" in (version.stdout + version.stderr).lower():
            llvm = llvm or executable
        elif name == "dwarfdump":
            other = executable
    fallback = which("readelf")
    if (verify or statistics) and llvm is None:
        fail("Verification and statistics require llvm-dwarfdump or LLVM dwarfdump.")
    if llvm is None and other is None and fallback is None:
        fail("Install llvm-dwarfdump, dwarfdump, or readelf before inspecting binaries.")
    for path in paths:
        if llvm:
            flag = {"all": "--all", "info": "--debug-info", "line": "--debug-line"}[section]
            observations.append(capture([llvm, flag, "--show-form", path]))
            if symbol:
                found = capture([llvm, f"--find={symbol}", "--show-children", path])
                observations.append(found)
                if found.exit_code != 0 or "DW_TAG_" not in found.stdout:
                    observations.append(
                        capture([llvm, f"--name={symbol}", "--show-children", path])
                    )
            if program_address:
                observations.append(capture([llvm, f"--lookup={program_address}", path]))
            if verify:
                observations.append(capture([llvm, "--verify", "--error-display=full", path]))
            if statistics:
                observations.append(capture([llvm, "--statistics", path], json_output=True))
        elif other:
            observations.append(capture([other, path]))
        elif fallback:
            observations.append(capture([fallback, f"--debug-dump={section}", path]))
    return observations


@recipe(
    name="dwarf-expert",
    version="1",
    agents=("worker",),
    capabilities=("Bash", "WebSearch", "WebFetch"),
    budget=Budget(max_agent_calls=2, max_wall_seconds=3600),
    output_root="dwarf-expert-output",
)
def dwarf_expert(
    request: str,
    mode: Literal["inspect", "verify", "standard", "code", "review"] = "inspect",
    directory: str = ".",
    binary_inputs: tuple[str, ...] = (),
    source_inputs: tuple[str, ...] = (),
    reference_inputs: tuple[str, ...] = (),
    section: Literal["all", "info", "line"] = "info",
    symbol: str = "",
    program_address: str = "",
    verify_binaries: bool = False,
    statistics: bool = False,
    standard_query: str = "",
    source_urls: tuple[str, ...] = (),
    edit_project: bool = False,
) -> Answer:
    if not request.strip():
        fail("Provide a concrete DWARF question or task.")
    root = Path(directory).expanduser().resolve(strict=True)
    if not root.is_dir():
        fail("The working directory must be an existing directory.")
    targets = resolve_inputs(binary_inputs, root, bundles=True)
    sources = resolve_inputs(source_inputs, root)
    references = resolve_inputs(reference_inputs, root)
    if (mode in ("inspect", "verify") or verify_binaries or statistics) and not targets:
        fail("The binary inspection scope is empty; provide binaries, objects, or dSYMs.")
    if mode == "review" and not sources:
        fail("The code review scope is empty; provide the complete source files to review.")
    if mode == "review" and not any(Path(path).stat().st_size for path in sources):
        fail("The code review scope contains only empty files.")
    for path in targets:
        if Path(path).stat().st_size == 0:
            fail(f"The binary inspection target is empty: {path}.")
    observations = inspect_binaries(
        targets, section, verify_binaries or mode == "verify", statistics, symbol, program_address
    )
    online: list[Any] = []
    query = standard_query or (request if mode == "standard" else "")
    if query:
        online.append(
            {"query": query, "result": tool("WebSearch", query=f"{query} site:dwarfstd.org")}
        )
    for url in source_urls:
        online.append(
            {
                "url": url,
                "result": tool(
                    "WebFetch",
                    url=url,
                    prompt="Return the complete fetched source text without summarizing it.",
                ),
            }
        )
    evidence = {
        "binary_targets": targets,
        "source_files": sources,
        "references": references,
        "commands": [item.model_dump() for item in observations],
        "online_sources": online,
        "symbol": symbol,
        "program_address": program_address,
    }
    emit(evidence, name="observations")
    context = prepare_context(
        task=json.dumps({"request": request, "mode": mode, "edit_project": edit_project}),
        prior_results=json.dumps(evidence, ensure_ascii=False),
        files=tuple(dict.fromkeys((*sources, *references))),
        readable_roots=(root, *sources, *references),
        instructions=(
            "Handle the complete assignment under the authoritative source skill. Keep its "
            "connected investigation, interpretation, implementation, and checks in this "
            "session. The host prepared command transcripts and optional online evidence; "
            "these are observations and do not complete any reasoning phase. Inspect every "
            "declared target and source file. Search matches may prioritize investigation "
            "but do not exhaust the semantic candidates. Full binary targets remain readable "
            "for additional commands and parsing. Read and interpret complete references. "
            "Use embedded context directly; read task.txt or backing files when omitted or "
            "when a file check is needed. Apply the original search escalation, platform "
            "caveats, source priorities, code pitfalls, and verification requirements. "
            "Perform remaining suitable commands with the provided execution capability. "
            "The role has no online research capability: use host-provided source evidence "
            "or return blocked with the missing source or provider configuration needed "
            "for precise claims. Edit files under the working directory only when "
            "edit_project is true; otherwise include requested code in the answer. "
            "Return complete only when the task is finished. An inspection that examines "
            "zero DWARF or code items must return blocked with an explanation. Report "
            "actual verification outcomes, findings, requested code, supporting sources, "
            "and material limitations as applicable. Preserve findings even when DWARF "
            "verification reports errors. Out-of-scope or otherwise unfinished work must "
            "return blocked and explain what remains."
        ),
    )
    result = agent(
        "worker",
        context.prompt,
        context=context,
        working_directory=root,
        readable_paths=(root, *targets, *sources, *references),
        writable_paths=(root,) if edit_project else (),
        required_capabilities=("commands", "write") if edit_project else ("commands",),
        output=Answer,
        timeout=3600,
    )
    if not result.answer.strip():
        fail("The expert returned no answer.")
    emit(result, name="answer")
    if result.status == "blocked":
        fail(result.answer)
    return result


if __name__ == "__main__":
    raise SystemExit(dwarf_expert.cli())


# --- calcifier metadata (skill provenance + sha256) ---
_CALCIFIER_COMPILATION = "compiled"
_CALCIFIER_SKILL = {
    "path": "../SKILL.md",
    "sha256": ("c4623d2d9c5a31c7722a293a96038817631e7d511f256613b4cbfa417c24466a"),
}
_CALCIFIER_RESOURCES = []
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
