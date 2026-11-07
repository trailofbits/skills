# /// script
# requires-python = ">=3.13"
# dependencies = ["calcifier==0.2.0"]
# ///

"""Audit overlays using the [Query API](https://github.com/trailofbits/trailmark)."""

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

DRIVER = """
import contextlib
import json
import re
import sys
import traceback
from importlib.metadata import version
from pathlib import Path
from trailmark.query.api import QueryEngine
def collect(config, result):
    target = Path(config["target"])
    details = result["details"]
    details["version"] = installed = version("trailmark")
    engine = QueryEngine.from_directory(str(target), language=config["language"])
    details["preanalysis"] = engine.preanalysis()
    initial = json.loads(engine.to_json())
    source = [n for n in initial["nodes"].values()
              if n.get("origin", "source") == "source" and n["kind"] != "proxy"]
    result["source_nodes"] = len(source)
    details["source_files"] = sorted({n["location"]["file_path"] for n in source})
    if not source:
        raise RuntimeError("Zero source nodes inspected; rerun with an explicit language.")
    files = config["files"]
    loaded = {}
    for paths in files.values():
        for path in paths:
            loaded[path] = json.loads(Path(path).read_text(encoding="utf-8"))
    tree = sorted(p for p in target.rglob("*") if p.is_file())
    details["tree_files"] = [str(p.relative_to(target)) for p in tree]
    for path in tree:
        if not path.resolve().is_relative_to(target) or str(path.resolve()) in loaded:
            continue
        suffix = path.suffix.lower()
        if suffix not in (".sarif", ".weaudit", ".json"):
            continue
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except (ValueError, UnicodeError):
            if suffix != ".json":
                raise
            continue
        kind = ""
        if suffix == ".sarif" or isinstance(data, dict) and "runs" in data:
            kind = "sarif"
        elif suffix == ".weaudit" or isinstance(data, dict) and "treeEntries" in data:
            kind = "weaudit"
        elif isinstance(data, dict) and {"artifact", "functions", "calls"} <= data.keys():
            kind = "binary"
        if kind:
            key = str(path.resolve())
            files[kind].append(key)
            loaded[key] = data
    files = {kind: sorted(set(paths)) for kind, paths in files.items()}
    details["inputs"] = files
    result["input_files"] = sum(len(paths) for paths in files.values())
    if not result["input_files"]:
        raise RuntimeError("No audit inputs found; inspection scope is empty.")
    current = tuple(int(n) for n in re.findall(r"\\d+", installed)[:2])
    if current < (0, 7) and any(len(files[k]) > 1 for k in ("sarif", "weaudit")):
        raise RuntimeError("Multiple same-format imports require Trailmark >= 0.7.")
    if files["binary"] and not hasattr(engine, "augment_binary"):
        raise RuntimeError("Binary augmentation requires Trailmark >= 0.4.0.")
    details["sarif_resolution"] = {
        path: [{"artifacts": run.get("artifacts", []),
                "uri_bases": run.get("originalUriBaseIds", {})}
               for run in loaded[path].get("runs", [])]
        for path in files["sarif"]
    }
    details["augmentations"] = []
    for kind, paths in files.items():
        for index, path in enumerate(paths):
            kwargs = {"replace_existing": False} if index and kind != "binary" else {}
            summary = getattr(engine, "augment_" + kind)(path, **kwargs)
            details["augmentations"].append({"format": kind, "path": path, "result": summary})
    names = set(engine.subgraph_names()) | {
        "sarif:error", "sarif:warning", "sarif:note",
        "weaudit:high", "weaudit:medium", "weaudit:low", "weaudit:informational",
        "weaudit:findings", "weaudit:notes",
        "tainted", "high_blast_radius", "privilege_boundary",
    }
    details["subgraphs"] = groups = {name: engine.subgraph(name) for name in sorted(names)}
    members = {name: {node["id"] for node in nodes} for name, nodes in groups.items()}
    details["cross_references"] = {
        name: {context: sorted(ids & members[context])
               for context in ("tainted", "high_blast_radius", "privilege_boundary")}
        for name, ids in members.items()
        if name.startswith(("sarif:", "weaudit:", "binary:"))
    }
    details["findings"] = findings = engine.findings()
    details["annotations"] = {n["id"]: engine.annotations_of(n["id"]) for n in findings}
    details["graph"] = json.loads(engine.to_json())
config = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))
if len(sys.argv) > 2:
    config["language"] = sys.argv[2]
result = {"source_nodes": 0, "input_files": 0, "error": "", "details": {}}
try:
    with contextlib.redirect_stdout(sys.stderr):
        collect(config, result)
except Exception:
    result["error"] = traceback.format_exc()
print(json.dumps(result, default=str))
"""


@output_type
class Evidence:
    source_nodes: int
    input_files: int
    error: str
    details: dict[str, Any]


@output_type
class Assessment:
    status: Literal["complete", "blocked"]
    source_nodes_inspected: int
    input_files_inspected: int
    report: str


@step
def collect_evidence(driver: Path, config: Path, directory: Path) -> Evidence:
    probe = run_command(
        ["uv", "run", "--no-project", "trailmark", "augment", "--help"],
        timeout_seconds=120,
        working_directory=directory,
    )
    if probe.exit_code:
        install = run_command(
            ["uv", "tool", "install", "trailmark"],
            timeout_seconds=300,
            working_directory=directory,
        )
        if install.exit_code:
            fail("Trailmark installation failed: " + install.stderr)
    return run_command(
        ["uv", "run", "--no-project", "--with", "trailmark", "python", str(driver), str(config)],
        timeout_seconds=1200,
        working_directory=directory,
        output=Evidence,
    )


@recipe(
    name="audit-augmentation",
    version="1",
    agents=("worker",),
    capabilities=("Bash",),
    budget=Budget(max_agent_calls=2, max_wall_seconds=3600),
    output_root="audit-augmentation",
)
def audit_augmentation(
    target_dir: str,
    request: str = "Overlay available audit findings and explain their graph context.",
    language: str = "auto",
    sarif_files: list[str] | None = None,
    weaudit_files: list[str] | None = None,
    binary_files: list[str] | None = None,
) -> Assessment:
    target = Path(target_dir).expanduser().resolve()
    if not target.is_dir():
        fail("Target must be an existing directory; there is no inspection scope.")
    inputs: dict[str, list[str]] = {}
    external: list[Path] = []
    for kind, values in (
        ("sarif", sarif_files),
        ("weaudit", weaudit_files),
        ("binary", binary_files),
    ):
        inputs[kind] = []
        for value in values or []:
            path = Path(value).expanduser()
            path = (path if path.is_absolute() else target / path).resolve()
            if not path.is_file():
                fail("Audit input is not a regular file: " + str(path))
            inputs[kind].append(str(path))
            external.append(path)
    directory = ensure_directory(
        ".",
        output_files=("driver.py", "inputs.json"),
        exclude_roots=(target,),
    )
    driver = write_text("driver.py", DRIVER)
    config = write_json(
        "inputs.json",
        {
            "target": str(target),
            "language": language,
            "files": inputs,
        },
    )
    evidence = collect_evidence(driver, config, directory)
    emit(evidence, name="observations")
    context = prepare_context(
        request,
        instructions=(
            "Complete the original workflow in one session. Driver observations do not "
            "complete interpretation. Use complete embedded reference text directly; read "
            "its backing file if absent or needed for a file check. Understand relevant "
            "inputs, and inspect the full target as needed. Discovery is not exhaustive "
            "semantic coverage. Investigate unmatched results, indexed artifacts, URI-base "
            "relocation and source coverage. Interpret every severity and preanalysis overlap. "
            "If detection is wrong or collection failed, investigate with commands and rerun: "
            "uv run --no-project --with trailmark python <driver.py absolute path> "
            "<inputs.json absolute path> [explicit language or comma-separated languages]. "
            "Preserve preanalysis, version gates and accumulation; use installed APIs for "
            "additional live-engine queries. Keep target and bundled files unchanged. "
            "Report every input's import and unmatched counts, all severity groups, coverage "
            "gaps and contextual priorities. If triage handoff is requested, identify a bound "
            "candidate without requiring another recipe. Resolve driver errors before "
            "completion; otherwise return blocked with a clear explanation. Counts must "
            "reflect actual inspected source nodes and audit inputs. Empty scope must fail; "
            "zero findings in an inspected scope can be valid."
        ),
        prior_results=evidence.model_dump_json(),
        files=(driver, config),
        readable_roots=(directory,),
    )
    assessment = agent(
        "worker",
        context.prompt,
        context=context,
        working_directory=directory,
        readable_paths=(target, *external, resource("references/formats.md")),
        required_capabilities=("commands",),
        output=Assessment,
        timeout=3600,
    )
    if not assessment.report.strip():
        fail("The worker returned no augmentation report.")
    emit(assessment, name="audit-report")
    if assessment.status != "complete":
        fail(assessment.report)
    if assessment.source_nodes_inspected <= 0 or assessment.input_files_inspected <= 0:
        fail("No source nodes or audit inputs were inspected; a clean report is invalid.")
    return assessment


if __name__ == "__main__":
    raise SystemExit(audit_augmentation.cli())


# --- calcifier metadata (skill provenance + sha256) ---
_CALCIFIER_COMPILATION = "compiled"
_CALCIFIER_SKILL = {
    "path": "../SKILL.md",
    "sha256": ("d147cf8c0811c9e50b20b2cdf4071853c27ada44d6648122bd8eaa9c32e3c422"),
}
_CALCIFIER_RESOURCES = [
    {
        "path": "agents/code-slice-worker.md",
        "sha256": ("6b427cf3aa5caf357cd0fb18eca324b4207706bcd7e79eaff157590cd5816cb7"),
        "size": 1912,
        "source": "../../agents/code-slice-worker.md",
    },
    {
        "path": "references/formats.md",
        "sha256": ("6cd3a692beab075ecf8aff4a2f3b5bfb25372b16be2ac796eb23b9881667ab0d"),
        "size": 3609,
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
