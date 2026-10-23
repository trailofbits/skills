# /// script
# requires-python = ">=3.13"
# dependencies = ["calcifier==0.2.0"]
# ///

"""Collect Trailmark structural evidence and retain version-specific interpretation."""

import json
from pathlib import Path
from typing import Any, Literal

from calcifier import (
    Budget,
    CommandResult,
    agent,
    emit,
    fail,
    output_type,
    prepare_context,
    recipe,
    run_command,
    step,
)

_QUERY = """
import inspect
import json
import sys

mode, target = sys.argv[1:3]
try:
    try:
        from trailmark.parse import detect_languages
    except ModuleNotFoundError:
        from trailmark.query.api import detect_languages
    if mode == "analyze":
        from trailmark.query.api import QueryEngine
except ImportError as error:
    print(str(error), file=sys.stderr)
    raise SystemExit(75)

languages = detect_languages(target)
if mode == "detect":
    print(json.dumps({"languages": languages}))
    raise SystemExit(0)

if not languages:
    raise SystemExit("Trailmark found no supported languages under target")

engine = QueryEngine.from_directory(target, language="auto")
preanalysis = engine.preanalysis()
graph = json.loads(engine.to_json())
summary = engine.summary()
if "source_files" in summary and not summary["source_files"]:
    raise SystemExit("Trailmark inspected zero source files")
counts = summary.get("source_file_counts")
if isinstance(counts, dict) and not any(counts.values()):
    raise SystemExit("Trailmark inspected zero source files")

def summarize_subgraph(name, limit=25):
    nodes = engine.subgraph(name)
    result = {"count": len(nodes), "sample_ids": [node["id"] for node in nodes[:limit]]}
    if hasattr(engine, "subgraph_edges"):
        result["edge_count"] = len(engine.subgraph_edges(name))
    return result

nodes = graph.get("nodes", {})
proxies = [
    node_id for node_id, node in nodes.items()
    if node.get("kind") == "proxy" or node.get("origin") == "proxy"
]
payload = {
    "languages": languages,
    "summary": summary,
    "preanalysis": preanalysis,
    "attack_surface": engine.attack_surface()[:25],
    "hotspots": engine.complexity_hotspots(10)[:25],
    "proxy_nodes": proxies[:25],
    "proxy_node_count": len(proxies),
    "subgraphs": {
        name: summarize_subgraph(name) for name in engine.subgraph_names()
    },
}
if hasattr(engine, "type_references"):
    payload["type_reference_samples"] = {
        node_id: engine.type_references(node_id)[:10]
        for node_id in list(nodes)[:25]
    }
for key in ("trailmark_version", "schema_version", "parse_diagnostics"):
    if key in graph:
        payload[key] = graph[key]
for name in ("call_resolution", "unresolved_calls"):
    if hasattr(engine, name):
        method = getattr(engine, name)
        payload[name] = method() if callable(method) else method

interfaces = {}
for name in ("state_read_by", "state_written_by", "readers_of", "writers_of"):
    if hasattr(engine, name):
        method = getattr(engine, name)
        try:
            signature = str(inspect.signature(method))
        except (TypeError, ValueError):
            signature = None
        interfaces[name] = {"signature": signature, "doc": inspect.getdoc(method)}
print(json.dumps({"payload": payload, "graph": graph, "solidity_api": interfaces}))
"""


@output_type
class QueryResult:
    data: dict[str, Any]
    python_argv: list[str]


@output_type
class Supplement:
    solidity_state_access: dict[str, Any]
    limitations: list[str]
    error: str | None


def _attempt(argv: list[str], directory: str, timeout: float) -> CommandResult | None:
    try:
        return run_command(
            argv,
            timeout_seconds=timeout,
            working_directory=directory,
            mutating=False,
        )
    except Exception as exc:
        if getattr(exc, "command_failure", None) not in ("launch", "timeout"):
            raise
        return None


@step
def available(directory: str) -> bool:
    for argv in (
        ["trailmark", "analyze", "--help"],
        ["uv", "run", "trailmark", "analyze", "--help"],
    ):
        result = _attempt(argv, directory, 60)
        if result is not None and result.exit_code == 0:
            return True
    return False


@step
def query(mode: Literal["detect", "analyze"], directory: str) -> QueryResult:
    for prefix in (["python3"], ["uv", "run", "--with", "trailmark", "python"]):
        result = _attempt(prefix + ["-c", _QUERY, mode, directory], directory, 3600)
        if result is None or result.exit_code == 75:
            continue
        if result.exit_code != 0:
            fail(result.stderr or result.stdout or "Trailmark analysis command failed")
        try:
            data = json.loads(result.stdout)
        except json.JSONDecodeError:
            fail("Trailmark did not return valid JSON")
        if not isinstance(data, dict):
            fail("Trailmark returned a non-object JSON result")
        return QueryResult(data=data, python_argv=prefix)
    fail("The Trailmark Python API could not be imported or its command could not run")


@recipe(
    name="trailmark_structural",
    version="1",
    capabilities=("Bash",),
    agents=("worker",),
    budget=Budget(max_agent_calls=2, max_wall_seconds=3600),
)
def trailmark_structural(args: str = ".") -> dict[str, Any]:
    root = Path(args).expanduser().resolve()
    if not root.is_dir():
        fail(f"Target directory does not exist or is not a directory: {root}")
    directory = str(root)
    if not available(directory):
        return emit(
            {"status": "unavailable", "message": "trailmark is not installed"},
            name="structural",
        )
    detected = query("detect", directory)
    if not detected.data.get("languages"):
        emit(
            {
                "status": "empty_scope",
                "message": "Trailmark found no supported languages under target",
            },
            name="structural",
        )
        fail("Trailmark found no supported languages under target; zero files were inspected")
    collected = query("analyze", directory)
    context = prepare_context(
        "Complete the agent-owned interpretation of this structural analysis under the "
        "authoritative source workflow. Python performed the availability and language "
        "checks and collected the graph and QueryEngine evidence. The complete graph, "
        "payload, feature-probed Solidity API documentation, and successful Python argv "
        "are in the observations. Use this context directly when embedded; otherwise "
        "read task.txt. Review the complete target and observations as needed. Perform "
        "the required direct Solidity state-access queries where appropriate, retaining "
        "their raw results in solidity_state_access. Use the recorded Python argv and "
        "probe method signatures and keywords rather than assuming version support. "
        "Keep the original reasoning order and checks intact. Account for parser and "
        "resolution gaps, self-path semantics, deferred edges, and current graph IDs "
        "where relevant. Python retains every unchanged payload field. Return only "
        "additive Solidity evidence, material limitations, and an error if required "
        "available work could not be completed. Empty or unavailable optional methods "
        "are valid; use an empty state-access object when inapplicable. Do not install "
        "software or mutate the target.",
        prior_results=collected.model_dump_json(),
    )
    supplement = agent(
        "worker",
        "Finish the assigned structural-evidence interpretation and applicable queries. "
        "Use the authoritative skill and the complete prepared observations.",
        working_directory=root,
        readable_paths=(root,),
        required_capabilities=("commands",),
        context=context,
        output=Supplement,
        timeout=3600,
    )
    payload = collected.data["payload"]
    if supplement.solidity_state_access:
        payload["solidity_state_access"] = supplement.solidity_state_access
    if supplement.limitations:
        payload["limitations"] = supplement.limitations
    emit(payload, name="structural")
    if supplement.error:
        fail(supplement.error)
    return payload


if __name__ == "__main__":
    raise SystemExit(trailmark_structural.cli())


# --- calcifier metadata (skill provenance + sha256) ---
_CALCIFIER_COMPILATION = "compiled"
_CALCIFIER_SKILL = {
    "path": "../SKILL.md",
    "sha256": ("c71c53845b0429cb0dbe7a25aed5634bab3e26bd0f441140691273f7f8bbb412"),
}
_CALCIFIER_RESOURCES = [
    {
        "path": "agents/code-slice-worker.md",
        "sha256": ("6b427cf3aa5caf357cd0fb18eca324b4207706bcd7e79eaff157590cd5816cb7"),
        "size": 1912,
        "source": "../../agents/code-slice-worker.md",
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
