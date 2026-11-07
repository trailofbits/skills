# /// script
# requires-python = ">=3.13"
# dependencies = ["calcifier==0.2.0"]
# ///

import json
import re
from pathlib import Path
from typing import Literal

from calcifier import (
    Budget,
    CommandResult,
    agent,
    emit,
    fail,
    output_type,
    prepare_context,
    recipe,
    resource,
    run_command,
    step,
)

Kind = Literal[
    "call-graph", "class-hierarchy", "module-deps", "containment", "complexity", "data-flow"
]
RequestedKind = Literal[
    "auto",
    "call-graph",
    "class-hierarchy",
    "module-deps",
    "containment",
    "complexity",
    "data-flow",
]


@output_type
class DiagramAnswer:
    kind: Kind
    use_prepared: bool
    mermaid: str
    diagnostics: str
    notes: str
    error: str


def observation(result: CommandResult) -> dict[str, object]:
    return {
        "argv": result.argv,
        "exit_code": result.exit_code,
        "stdout": result.stdout,
        "stderr": result.stderr,
    }


@step
def invoke(argv: list[str], directory: Path, mutating: bool = False) -> CommandResult:
    try:
        return run_command(
            argv, working_directory=directory, timeout_seconds=300, mutating=mutating
        )
    except Exception as exc:
        failure = getattr(exc, "command_failure", None)
        if failure not in ("launch", "timeout"):
            raise
        return CommandResult(argv, 127 if failure == "launch" else 124, "", str(exc))


def inspect_mermaid(text: str) -> tuple[str, int, str]:
    raw = text.lstrip("\ufeff").strip()
    lines = [line.strip() for line in raw.splitlines() if line.strip()]
    lines = [line for line in lines if not line.startswith("%%")]
    if not lines:
        return raw, 0, "No Mermaid output was produced."
    if re.fullmatch(r"flowchart\s+(?:TB|TD|BT|LR|RL)\s*;?", lines[0]):
        nodes = re.findall(r"(?m)^\s*([A-Za-z_]\w*)\s*[\[({]", raw)
        edges = re.findall(r"(?m)^\s*(\w+)\s*(?:-->|-\.->|\.\.->)\s*(\w+)", raw)
    elif re.fullmatch(r"classDiagram\s*;?", lines[0]):
        nodes = re.findall(r"(?m)^\s*class\s+([A-Za-z_]\w*)", raw)
        edges = re.findall(r"(?m)^\s*(\w+)\s*(?:<\|--|<\|\.\.)\s*(\w+)", raw)
    else:
        return raw, 0, "Output must begin with flowchart or classDiagram."
    identifiers = set(nodes) | {node for edge in edges for node in edge}
    if not identifiers:
        return raw, 0, "The Mermaid inspection found zero nodes."
    return raw, len(identifiers), ""


ASSIGNMENT = (
    "Carry the original skill's ordered reasoning and checks through to a diagram for the "
    "complete target and request. Understand both complete references. Prepared observations "
    "and any search matches are not exhaustive semantic candidates. Use embedded context "
    "directly; read task.txt when absent. Prerequisite analysis, installation when necessary, "
    "and native command checks are prepared. Interpret analysis and parse diagnostics; reject "
    "zero matching source files. Keep diagram selection, focus identification, any explicit "
    "language reanalysis, generation, verification and corrections together in this session. "
    "If the prepared candidate satisfies the request and all original checks, return "
    "use_prepared=true and leave mermaid empty. Otherwise use the prepared command prefix "
    "with the skill's CLI flags, obtaining successful analysis for the selected language. "
    "Return exact complete diagram stdout as mermaid with use_prepared=false. Generate only "
    "through Trailmark, never by writing or editing Mermaid manually. Consult the complete "
    "syntax reference for empty or malformed output and correct commands before returning. "
    "Report final parse warnings and limitations in diagnostics and notes. Set error for a "
    "blocker; do not claim unperformed checks. Python checks nodes and renders the response."
)


@recipe(
    version="1",
    agents=("worker",),
    capabilities=("Bash",),
    budget=Budget(2, 3600),
)
def diagramming_code(
    request: str,
    target_directory: str,
    diagram_type: RequestedKind = "auto",
    focus: str = "",
) -> str:
    target = Path(target_directory).expanduser().resolve()
    if not target.is_dir():
        fail(f"Target directory does not exist: {target}")
    if not any(
        p.is_file()
        and ".git" not in p.relative_to(target).parts
        and p.resolve().is_relative_to(target)
        for p in target.rglob("*")
    ):
        fail("The target contains zero inspectable files.")
    analyze = ["uv", "run", "trailmark", "analyze", "--language", "auto", "--summary", str(target)]
    analysis = invoke(analyze, target)
    if analysis.exit_code != 0:
        installation = invoke(["uv", "tool", "install", "trailmark"], target, mutating=True)
        if installation.exit_code != 0:
            emit(observation(installation), name="installation-error")
            fail("Trailmark installation failed; see installation-error for the actual error.")
        analysis = invoke(analyze, target)
    script = resource("scripts/diagram.py")
    gates = [invoke(["trailmark", "diagram", "--help"], target)]
    prefix = ["trailmark", "diagram"]
    if gates[0].exit_code != 0:
        gates.append(invoke(["uv", "run", "trailmark", "diagram", "--help"], target))
        prefix = ["uv", "run", "trailmark", "diagram"]
    version = invoke(prefix[:-1] + ["--version"], target)
    if gates[-1].exit_code != 0:
        prefix = ["uv", "run", str(script)]
    candidate: CommandResult | None = None
    can_prepare = diagram_type != "auto" and (diagram_type != "call-graph" or bool(focus))
    if can_prepare and analysis.exit_code == 0:
        layout = "LR" if diagram_type == "module-deps" else "TB"
        argv = prefix + ["--target", str(target), "--language", "auto", "--type", diagram_type]
        argv += ["--depth", "2", "--direction", layout, "--threshold", "10"]
        if focus:
            argv += ["--focus", focus]
        candidate = invoke(argv, target)
    resources = (
        resource("references/diagram-types.md"),
        resource("references/mermaid-syntax.md"),
        script,
    )
    prepared = {
        "target": str(target),
        "requested_type": diagram_type,
        "provided_focus": focus,
        "command_prefix": prefix,
        "analysis": observation(analysis),
        "native_gate": [observation(value) for value in gates],
        "version": observation(version),
        "candidate": observation(candidate) if candidate is not None else None,
    }
    emit(prepared, name="preparation")
    context = prepare_context(
        request,
        instructions=ASSIGNMENT,
        prior_results=json.dumps(prepared),
        files=resources,
        readable_roots=(target, *resources),
    )
    answer = agent(
        "worker",
        "Complete the source skill workflow using the full prepared context and target.",
        working_directory=target,
        readable_paths=(target, *resources),
        required_capabilities=("commands",),
        context=context,
        output=DiagramAnswer,
        timeout=3600,
    )
    emit(answer, name="selection")
    if answer.error.strip():
        fail(answer.error)
    if answer.use_prepared:
        if candidate is None or candidate.exit_code != 0:
            fail("The worker selected a missing or unsuccessful prepared diagram.")
        if answer.kind != diagram_type:
            fail("The selected diagram type does not match the prepared candidate.")
        raw = candidate.stdout
        diagnostics = "\n".join([candidate.stderr, answer.diagnostics])
    else:
        raw = answer.mermaid
        diagnostics = answer.diagnostics
    raw, node_count, issue = inspect_mermaid(raw)
    if issue:
        emit({"mermaid": raw, "problem": issue}, name="invalid-output")
        fail(issue)
    response = f"```mermaid\n{raw}\n```"
    if answer.notes.strip():
        response += "\n\n" + answer.notes.strip()
    if answer.kind == "data-flow":
        response += (
            "\n\nGraph paths represent possible call reachability; runtime data flow "
            "requires separate evidence."
        )
    if node_count > 100:
        response += f"\n\nThis diagram has {node_count} nodes; use focus to reduce clutter."
    if diagnostics.strip():
        response += "\n\nTrailmark diagnostics:\n```text\n" + diagnostics.strip() + "\n```"
    return emit(response, name="diagram")


if __name__ == "__main__":
    raise SystemExit(diagramming_code.cli())


# --- calcifier metadata (skill provenance + sha256) ---
_CALCIFIER_COMPILATION = "compiled"
_CALCIFIER_SKILL = {
    "path": "../SKILL.md",
    "sha256": ("b32fac23f47f0037a968214e65b970974f64f7425b8ac4e0dcc5bb1c5dd5d262"),
}
_CALCIFIER_RESOURCES = [
    {
        "path": "agents/code-slice-worker.md",
        "sha256": ("6b427cf3aa5caf357cd0fb18eca324b4207706bcd7e79eaff157590cd5816cb7"),
        "size": 1912,
        "source": "../../agents/code-slice-worker.md",
    },
    {
        "path": "references/diagram-types.md",
        "sha256": ("f87a59e21779510920fe3b76c1f4d17f0776a24fed0193f836e982b622394e73"),
        "size": 5186,
        "source": None,
    },
    {
        "path": "references/mermaid-syntax.md",
        "sha256": ("5932e0ecb7cfa4d49e5fa54af723880eeecdf1a9419e87ff05ec7021270b53b4"),
        "size": 2947,
        "source": None,
    },
    {
        "path": "scripts/diagram.py",
        "sha256": ("a619c23ecaaa73f3acf6205b088c70b22a92b065beb35ca0aa3308efa36a3682"),
        "size": 389,
        "source": None,
    },
    {
        "path": "scripts/test_skill_commands.py",
        "sha256": ("bd8d726b9b2b4aca7299be81c76b0961ccc9adacb3a96e2d4f13c9b59b769670"),
        "size": 1118,
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
