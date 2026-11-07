# /// script
# requires-python = ">=3.13"
# dependencies = ["calcifier==0.2.0"]
# ///

"""Build complete Trailmark evidence and interpret it in one worker session."""

import json
from pathlib import Path
from shutil import which
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

QUERY = """
import json
import re
import sys
from importlib.metadata import version
from pathlib import Path

from trailmark.models import AnnotationKind
from trailmark.query.api import QueryEngine

cfg = json.loads(sys.argv[1])
installed = version("trailmark")
numbers = [int(part) for part in re.findall(r"[0-9]+", installed)[:3]]
release = tuple((numbers + [0, 0, 0])[:3])
try:
    from trailmark.parse import detect_languages, supported_languages
except ImportError:
    from trailmark.query.api import detect_languages
    supported = None
else:
    supported = supported_languages()
engine = QueryEngine.from_directory(cfg["root"], language=cfg["language"])
graph = json.loads(engine.to_json())
summary = engine.summary()
coverage = summary.get("source_files")
if coverage is not None and coverage <= 0:
    raise RuntimeError("No source files were inspected; check root and language selection")
if coverage is None and not any(
    node.get("origin", "source") == "source" for node in graph.get("nodes", {}).values()
):
    raise RuntimeError(
        "No inspected source scope could be established with this build; "
        "use Trailmark 0.7+ to distinguish empty source files from an empty scope"
    )
for format_name in ("sarif", "weaudit"):
    paths = cfg[format_name]
    if len(paths) > 1 and release < (0, 7, 0):
        raise RuntimeError("Appending same-format findings requires Trailmark 0.7+")
    importer = getattr(engine, "augment_" + format_name)
    for path in paths:
        if release >= (0, 7, 0):
            importer(path, replace_existing=False)
        else:
            importer(path)
if cfg["binary"]:
    if not hasattr(engine, "augment_binary"):
        raise RuntimeError("Binary augmentation requires Trailmark 0.4+")
    engine.augment_binary(cfg["binary"])
engine.preanalysis()
graph = json.loads(engine.to_json())
annotations = []
if cfg["annotations_file"]:
    annotations = json.loads(Path(cfg["annotations_file"]).read_text(encoding="utf-8"))
for annotation in annotations:
    kind = AnnotationKind(annotation["kind"])
    if not engine.annotate(
        annotation["node_id"], kind, annotation["description"], source="llm"
    ):
        raise RuntimeError("Annotation target was not found: " + annotation["node_id"])
data = {
    "trailmark_version": installed,
    "supported_languages": supported,
    "detected_languages": detect_languages(cfg["root"]),
    "summary": engine.summary(),
    "graph": graph,
    "attack_surface": engine.attack_surface(),
    "findings": engine.findings(),
    "complexity_hotspots": engine.complexity_hotspots(threshold=10),
    "annotations": {node: engine.annotations_of(node) for node in graph["nodes"]},
    "subgraphs": {name: engine.subgraph(name) for name in engine.subgraph_names()},
}
for method in ("call_resolution", "unresolved_calls", "parse_diagnostics"):
    if hasattr(engine, method):
        data[method] = getattr(engine, method)()
queries = {}
for symbol in dict.fromkeys((cfg["source"], cfg["sink"])):
    if symbol:
        queries[symbol] = {
            name: getattr(engine, name)(symbol)
            for name in (
                "callers_of", "callees_of", "ancestors_of", "reachable_from",
                "entrypoint_paths_to", "type_references", "generic_parameters",
            )
            if hasattr(engine, name)
        }
data["queries"] = queries
if cfg["source"] and cfg["sink"]:
    data["paths"] = engine.paths_between(cfg["source"], cfg["sink"])
print(json.dumps(data))
"""


@output_type
class Annotation:
    node_id: str
    kind: Literal["assumption", "precondition", "postcondition", "invariant"]
    description: str


@output_type
class Analysis:
    answer: str
    annotations: list[Annotation]


@step
def collect(config: dict[str, Any], root: Path) -> dict[str, Any]:
    package = str(config.get("package", "trailmark"))
    result = run_command(
        ["uv", "run", "--with", package, "python", "-c", QUERY, json.dumps(config)],
        timeout_seconds=600,
        working_directory=root,
        mutating=False,
    )
    if result.exit_code:
        fail("Trailmark graph/query execution failed: " + result.stderr + result.stdout)
    data = json.loads(result.stdout)
    if not isinstance(data, dict) or not data.get("graph") or not data.get("summary"):
        fail("Trailmark did not return a complete graph evidence object.")
    return data


@recipe(
    version="1",
    agents=("worker",),
    capabilities=("Bash",),
    budget=Budget(max_agent_calls=2, max_wall_seconds=3600),
    output_root="trailmark-results",
)
def trailmark(
    target_dir: str,
    request: str,
    language: str = "auto",
    source: str = "",
    sink: str = "",
    sarif: tuple[str, ...] = (),
    weaudit: tuple[str, ...] = (),
    binary: str = "",
    configure_links: bool = False,
) -> Analysis:
    root = Path(target_dir).expanduser().resolve()
    if not root.is_dir():
        fail("The analysis root must be an existing directory.")
    if not request.strip():
        fail("Supply the graph-analysis question or requested handoff.")
    destination = ensure_directory(
        ".", output_files=("evidence.json", "enriched.json", "annotations.json", "report.md")
    )
    if which("trailmark") is None:
        installation = run_command(
            ["uv", "tool", "install", "trailmark"], timeout_seconds=300, mutating=True
        )
        if installation.exit_code:
            fail("Trailmark installation failed: " + installation.stderr + installation.stdout)
    config: dict[str, Any] = {"root": str(root), "language": language}
    config.update(source=source, sink=sink, sarif=[], weaudit=[], binary="", annotations_file="")
    inputs: list[Path] = []
    for key, values in (("sarif", sarif), ("weaudit", weaudit), ("binary", (binary,))):
        paths = [Path(value).expanduser().resolve() for value in values if value]
        for path in paths:
            if not path.is_file():
                fail("Finding or binary-graph input is not a regular file: " + str(path))
        inputs.extend(paths)
        resolved = [str(path) for path in paths]
        config[key] = (resolved[0] if resolved else "") if key == "binary" else resolved
    data = collect(config, root)
    config["package"] = "trailmark==" + data["trailmark_version"]
    enriched_config = dict(config, annotations_file=str(destination / "annotations.json"))
    evidence = write_json("evidence.json", data)
    references = (
        resource("references/preanalysis-passes.md"),
        resource("references/query-patterns.md"),
    )
    context = prepare_context(
        request,
        prior_results=json.dumps({"configuration": config, "configure_links": configure_links}),
        files=(evidence,),
        readable_roots=(destination,),
    )
    result = agent(
        "worker",
        (
            "Complete the supplied request under the authoritative Trailmark skill and "
            "both complete references in one connected session. Evidence contains the "
            "full graph, preanalysis, findings, coverage, diagnostics and initial queries; "
            "interpret these alongside the entire target. Use embedded context directly; "
            "read task.txt or evidence when omitted. Run additional task-specific queries "
            "programmatically with uv run --with and the pinned package in configuration. "
            "Return the requested answer and inferred annotations using exact node IDs; "
            "state unresolved work. The host applies annotations from structured JSON data. "
            "configure_links authorizes only .trailmark/links.toml changes. Establish "
            "justified boundaries before relevant queries and rebuild to verify; otherwise "
            "identify missing configuration. The host re-collects after links or annotations "
            "change. Provide evidence or a handoff for downstream skills unavailable here."
        ),
        context=context,
        working_directory=root,
        readable_paths=(root, *inputs, *references),
        writable_paths=(root,) if configure_links else (),
        required_capabilities=("commands", "write") if configure_links else ("commands",),
        output=Analysis,
        timeout=3600,
    )
    if not result.answer.strip():
        fail("The analysis returned no answer.")
    write_json("annotations.json", [item.model_dump() for item in result.annotations])
    if configure_links or result.annotations:
        data = collect(enriched_config, root)
        write_json("enriched.json", data)
    emit(data, name="graph-evidence")
    write_text("report.md", result.answer)
    return emit(result, name="analysis")


if __name__ == "__main__":
    raise SystemExit(trailmark.cli())


# --- calcifier metadata (skill provenance + sha256) ---
_CALCIFIER_COMPILATION = "compiled"
_CALCIFIER_SKILL = {
    "path": "../SKILL.md",
    "sha256": ("753b4bedbffe939a191ca72bdeb19ec633a4a9443ebede6f5df1671e38367d1b"),
}
_CALCIFIER_RESOURCES = [
    {
        "path": "agents/code-slice-worker.md",
        "sha256": ("6b427cf3aa5caf357cd0fb18eca324b4207706bcd7e79eaff157590cd5816cb7"),
        "size": 1912,
        "source": "../../agents/code-slice-worker.md",
    },
    {
        "path": "references/preanalysis-passes.md",
        "sha256": ("939cb7f9d0cd9d2d6d899b4c1e26625221b2f1c28a11b397844c338972fae5e5"),
        "size": 5778,
        "source": None,
    },
    {
        "path": "references/query-patterns.md",
        "sha256": ("e8e651e753960804e1426b1bc73c0680e594a9905561eca5436e05d609cd4050"),
        "size": 8934,
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
