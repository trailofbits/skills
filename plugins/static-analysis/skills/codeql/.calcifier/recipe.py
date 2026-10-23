# /// script
# requires-python = ">=3.13"
# dependencies = ["calcifier==0.2.0"]
# ///

import json
from hashlib import sha256
from math import isfinite
from pathlib import Path
from typing import Any, Literal

import calcifier as c

RESOURCE_PINS = {
    "references/build-fixes.md": (
        "e4af17ecbe5a6784e3c011fec1f093ce25e5c852cd92be97caaeaea0be10ca1a"
    ),
    "references/diagnostic-query-templates.md": (
        "c27a979094f8de6d1d341a838de52952a98385ff75c9439a7e76ba3bb3fbe662"
    ),
    "references/extension-yaml-format.md": (
        "c98903da4f21fd94816c520f6fdaba8d12e08b4bd55f85233c487e3baf39a1a6"
    ),
    "references/important-only-suite.md": (
        "9f2fbb57b0e02fe964ad268b11ad88c9598b38314fc008016caa615cf303b3a5"
    ),
    "references/language-details.md": (
        "f0857914eeabfb96929c2d1a8f086e92c0a3973cc2ac8460f371fedc2d023818"
    ),
    "references/macos-arm64e-workaround.md": (
        "72d7c9fc2be8368968516857fe4e32211473b92cc8bc3ef1d28530aaf744d1fe"
    ),
    "references/performance-tuning.md": (
        "536473b91e8574c18a3a943df2e4328615bbabbd899c76827d345ff7be986b7d"
    ),
    "references/quality-assessment.md": (
        "2acbb61d487211a0d6342ef86f774de3d4e05496185d337e09cb39810bcae08a"
    ),
    "references/ruleset-catalog.md": (
        "2b139ae593865548a596fb5b78694cb09d4a1959beb5225a5d8a914155a72165"
    ),
    "references/run-all-suite.md": (
        "bbac653d6e8ea115fa7df47307729745157bb60868939a71167c30cc18dcffb6"
    ),
    "references/sarif-processing.md": (
        "abde04ca479a372ed134150cd9cd1fd2b45cd7b4b45386034a2b3f4d415f6f9b"
    ),
    "references/threat-models.md": (
        "fd4252f0fc71734ab756ff51bead1b894397bf67382b2337cbe0b0de4672cefd"
    ),
    "workflows/build-database.md": (
        "06794bb67182303b0c81d30b3772531537d9f986b7b2cbe2a9ffa4b4f3e230ba"
    ),
    "workflows/create-data-extensions.md": (
        "f3643e4916e7586c7738c14f781e3919bce35129d75beb00812b963efbbc4673"
    ),
    "workflows/run-analysis.md": (
        "83b0e0bccdb7f9f3962022b4477bcc888a6728eebcd25495378a860da72930c6"
    ),
    "scripts/build_log.sh": ("83c98d08c85a96b0b46246c14f3ffbe61370f5d184338455c6c288ddcf8df5de"),
    "scripts/check_db_quality.py": (
        "fca99a149eb4689730b7d3a3314527a5716823fb5f19b6b79114f4949b726c36"
    ),
    "scripts/find_databases.sh": (
        "a56995c048b322bce45baf4482388a3cdf78dd59d562eca39e169c065f7f9b18"
    ),
    "scripts/generate_suite.sh": (
        "489516c52155c2061ec2a53d8190ebe474f4bdcb53ddc53b1216dc72ff7b1d9f"
    ),
    "scripts/verify_query_suite.py": (
        "ad1bb120201c9af5ae199d3d36a727ba12d897162f817045e8a8006e691154f8"
    ),
}
RESOURCES = tuple(RESOURCE_PINS)
PLANNED = (
    "codeql.db",
    "build.log",
    "codeql-config.yml",
    "rulesets.txt",
    "evaluator.log",
    "raw/results.sarif",
    "raw/run-all.qls",
    "raw/important-only.qls",
    "results/results.sarif",
    "diagnostics/list-sources.ql",
    "diagnostics/list-sinks.ql",
    "diagnostics/qlpack.yml",
    "diagnostics/codeql-pack.lock.yml",
    "diagnostics/sources.bqrs",
    "diagnostics/sinks.bqrs",
    "diagnostics/sources.csv",
    "diagnostics/sinks.csv",
    "diagnostics/baseline.sarif",
    "diagnostics/with-extensions.sarif",
    "extensions/sources.yml",
    "extensions/sinks.yml",
    "extensions/summaries.yml",
    "extensions/qlpack.yml",
)
SOURCE_SUFFIXES = {
    ".c",
    ".cc",
    ".cpp",
    ".cxx",
    ".h",
    ".hh",
    ".hpp",
    ".hxx",
    ".cs",
    ".go",
    ".java",
    ".kt",
    ".kts",
    ".js",
    ".jsx",
    ".ts",
    ".tsx",
    ".mjs",
    ".cjs",
    ".py",
    ".rb",
    ".rs",
    ".swift",
}


@c.output_type
class UserDecision:
    checkpoint_digest: str
    option: int
    response: str = ""


@c.output_type
class Reply:
    state: Literal["question", "complete", "blocked"]
    report: str
    question: str
    options: list[str]
    continuation: str
    database_index: int
    workflow: Literal["full", "build", "extensions", "analysis"]
    mode: Literal["run-all", "important-only"]
    suite_origin: Literal["generated", "reused", "edited", "not-applicable"]
    override_justified: bool
    zero_findings_investigation: str


@c.output_type
class Result:
    status: Literal["complete", "blocked", "pending"]
    report: str
    output_directory: str
    summary: dict[str, Any]
    checkpoint: str
    checkpoint_digest: str
    question: str
    options: list[str]


@c.output_type
class HostInventory:
    project: str
    new_output: str
    databases: list[str]
    outputs: list[str]
    caches: list[str]
    resources: list[str]
    executables: list[str]
    pins: dict[str, str]
    preparation: dict[str, Any]
    resource_views: dict[str, str]


def digest(value: Any) -> str:
    encoded = json.dumps(
        value, sort_keys=True, ensure_ascii=False, separators=(",", ":"), allow_nan=False
    ).encode("utf-8")
    return sha256(encoded).hexdigest()


def file_hash(path: Path, cache: dict[str, str]) -> str:
    key = str(path)
    if key not in cache:
        before = path.stat()
        value = sha256(path.read_bytes()).hexdigest()
        after = path.stat()
        if (before.st_size, before.st_mtime_ns) != (after.st_size, after.st_mtime_ns):
            c.fail(f"Evidence changed while it was being hashed: {path}. Retry the run.")
        cache[key] = value
    return cache[key]


def tree_hash(root: Path, ignored: Path, cache: dict[str, str]) -> dict[str, Any]:
    if not root.exists():
        return {"path": str(root), "sha256": digest("missing"), "files": 0}
    entries: list[Any] = []
    pending = [root]
    files = 0
    while pending:
        path = pending.pop()
        if path == ignored:
            continue
        relative = str(path.relative_to(root))
        mode = path.lstat().st_mode
        if path.is_symlink():
            entries.append([relative, "symlink", mode, str(path.readlink())])
        elif path.is_dir():
            entries.append([relative, "directory", mode])
            pending.extend(sorted(path.iterdir(), reverse=True))
        elif path.is_file():
            stat = path.stat()
            entries.append(
                [relative, "file", mode, stat.st_size, stat.st_mtime_ns, file_hash(path, cache)]
            )
            files += 1
        else:
            c.fail(f"Cannot bind a decision to an unsupported filesystem entry: {path}")
    return {"path": str(root), "sha256": digest(entries), "files": files}


def source_observations(root: Path, excluded: tuple[Path, ...]) -> dict[str, Any]:
    sources = []
    histogram: dict[str, int] = {}
    pending = [root]
    skipped = {".git", "node_modules", "vendor", "venv", ".venv", "__pycache__"}
    while pending:
        directory = pending.pop()
        for path in sorted(directory.iterdir()):
            if path.is_symlink() or any(path == item for item in excluded):
                continue
            if path.is_dir():
                legacy = path.name.startswith("codeql_") and path.name.endswith(".db")
                if (
                    path.name not in skipped
                    and not path.name.startswith("static_analysis_codeql_")
                    and not legacy
                ):
                    pending.append(path)
            elif path.is_file() and path.suffix.lower() in SOURCE_SUFFIXES:
                suffix = path.suffix.lower()
                sources.append(str(path.relative_to(root)))
                histogram[suffix] = histogram.get(suffix, 0) + 1
    if not sources:
        c.fail("The project inspection scope contains no supported source files; no scan ran.")
    return {"expected_source_files": len(sources), "files": sorted(sources), "suffixes": histogram}


def checked(argv: list[str], directory: Path) -> c.CommandResult:
    result = c.run_command(argv, working_directory=directory, timeout_seconds=300, mutating=False)
    if result.exit_code:
        c.fail(f"Command failed: {argv!r}\n{result.stderr}\n{result.stdout}")
    return result


@c.step
def inspect_host(
    project: str,
    database: str,
    output_directory: str,
    checkpoint: str,
    workflow: Literal["auto", "full", "build", "extensions", "analysis"],
    scan_mode: Literal["run-all", "important-only"],
    quality_error_limit: float,
    toolchain_directories: list[str],
) -> HostInventory:
    # This phase accepts only recipe inputs. It never reads a conversation checkpoint.
    root = Path(project).resolve()
    if not root.is_dir() or not isfinite(quality_error_limit) or quality_error_limit < 0:
        c.fail("Provide an existing project and a finite, nonnegative quality error limit.")
    resources = tuple(c.resource(name) for name in RESOURCES)
    pins = {}
    resource_views = {}
    for name, path in zip(RESOURCES, resources, strict=True):
        actual = sha256(path.read_bytes()).hexdigest()
        if actual != RESOURCE_PINS[name]:
            c.fail(f"Packaged resource does not match its source pin: {name}")
        pins[name] = actual
        resource_views[name] = str(path)
    executables = checked(
        ["bash", "-c", 'for t in codeql jq uv; do command -v "$t" || exit 1; done'], root
    ).stdout.splitlines()
    if len(executables) != 3:
        c.fail("Preflight did not identify CodeQL, jq, and uv executables.")
    checked(["codeql", "--version"], root)
    if checkpoint:
        checkpoint_path = Path(checkpoint).absolute()
        new_output = checkpoint_path.parent.parent.resolve()
        if not new_output.is_dir():
            c.fail("The user-supplied checkpoint's output directory does not exist.")
    else:
        number = 1
        while not output_directory and Path(f"static_analysis_codeql_{number}").exists():
            number += 1
        new_output = c.ensure_directory(
            output_directory or f"static_analysis_codeql_{number}", output_files=PLANNED
        ).resolve()
    if database:
        databases = [(root / database).resolve()]
    else:
        discovery = checked(
            [
                "bash",
                str(c.resource("scripts/find_databases.sh")),
                str(new_output),
                str(root),
            ],
            root,
        )
        databases = [Path(line).resolve() for line in discovery.stdout.splitlines() if line]
    outputs = [new_output if output_directory else db.parent for db in databases]
    cache_paths = [Path(executables[0]).resolve().parent, Path.home() / ".codeql"]
    cache_paths += [Path(path).resolve() for path in toolchain_directories]
    caches = tuple(dict.fromkeys(path for path in cache_paths if path.is_dir()))
    metadata = []
    markers = []
    for db in databases:
        resolution = c.run_command(
            ["codeql", "resolve", "database", "--format=json", "--", str(db)],
            working_directory=root,
            timeout_seconds=300,
            mutating=False,
        )
        if resolution.exit_code:
            metadata.append({"exit_code": resolution.exit_code, "diagnostic": resolution.stderr})
        else:
            metadata.append(json.loads(resolution.stdout))
        marker = db / "codeql-database.yml"
        markers.append(marker.read_text(encoding="utf-8") if marker.is_file() else "")
    observations = source_observations(root, (new_output, *databases, *outputs))
    preparation = {
        "workflow": workflow,
        "scan_mode": scan_mode,
        "explicit_database": database,
        "new_output": str(new_output),
        "databases": [str(db) for db in databases],
        "metadata": metadata,
        "output_choices": [str(path) for path in outputs],
        "quality_error_limit": quality_error_limit,
        "markers": markers,
        "source_observations": observations,
    }
    return HostInventory(
        project=str(root),
        new_output=str(new_output),
        databases=[str(db) for db in databases],
        outputs=[str(path) for path in outputs],
        caches=[str(path) for path in caches],
        resources=[str(path) for path in resources],
        executables=executables,
        pins=pins,
        preparation=preparation,
        resource_views=resource_views,
    )


def load_checkpoint(path: Path) -> tuple[dict[str, Any], str]:
    if path.is_symlink() or path.parent.name != ".codeql-checkpoints":
        c.fail("Resume from a regular checkpoint file in its .codeql-checkpoints directory.")
    if path.parent.is_symlink() or path.suffix != ".json" or not path.stem.isdecimal():
        c.fail("Checkpoint filenames must be host-allocated numeric JSON filenames.")
    c.verify_artifact(path)
    envelope = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(envelope, dict) or envelope.get("version") != "1":
        c.fail("The checkpoint envelope is invalid.")
    payload = envelope.get("payload")
    if not isinstance(payload, dict):
        c.fail("The checkpoint payload is invalid.")
    checksum = digest(payload)
    if envelope.get("sha256") != checksum:
        c.fail("Checkpoint contents do not match the saved digest.")
    required = {"config", "preparation", "conversation", "reply", "evidence", "parent"}
    if set(payload) != required or payload["reply"].get("state") != "question":
        c.fail("Only a pending decision checkpoint can be resumed.")
    if not isinstance(payload["conversation"], list) or not payload["conversation"]:
        c.fail("The checkpoint does not retain its executed conversation.")
    return payload, checksum


def checkpoint_destination(output: Path) -> Path:
    directory = output / ".codeql-checkpoints"
    number = 1
    path = directory / f"{number:06d}.json"
    while path.exists() or path.is_symlink():
        number += 1
        path = directory / f"{number:06d}.json"
    return path


def persist_checkpoint(path: Path, payload: dict[str, Any]) -> str:
    checksum = digest(payload)
    envelope = {"version": "1", "sha256": checksum, "payload": payload}
    if path.exists() or path.is_symlink():
        c.fail("The allocated checkpoint destination is occupied; existing records are immutable.")
    c.ensure_directory(path.parent, output_files=(path.name,))
    c.write_json(path, envelope)
    c.verify_artifact(path)
    return checksum


def pending_result(payload: dict[str, Any], path: Path, checksum: str) -> Result:
    reply = payload["reply"]
    resume_inputs = dict(payload["config"])
    resume_inputs["checkpoint"] = str(path)
    resume_inputs["resume_databases"] = payload["preparation"]["databases"]
    resume_inputs["decision"] = {
        "checkpoint_digest": checksum,
        "option": "Supply an integer from 1 through the number of ordered options",
        "response": "Optional instructions answering this exact saved question",
    }
    report = (
        reply["report"]
        + "\nPending user decision. Supply the exact resume_inputs shown in summary, "
        + "including checkpoint, resume_databases, and a UserDecision with this digest "
        + "and a one-based option number. No pending choice has been approved. "
        + "The host rediscovers current locations on resume; saved conversation and "
        + "routing lists are evidence only and never supply effect locations."
    )
    return c.emit(
        Result(
            status="pending",
            report=report,
            output_directory=payload["preparation"]["new_output"],
            summary={"resume_inputs": resume_inputs, "evidence": payload["evidence"]},
            checkpoint=str(path),
            checkpoint_digest=checksum,
            question=reply["question"],
            options=reply["options"],
        ),
        name="report",
    )


def snapshot(
    root: Path,
    output: Path,
    databases: list[Path],
    outputs: list[Path],
    caches: tuple[Path, ...],
    executables: list[str],
    pins: dict[str, str],
) -> dict[str, Any]:
    ignored = output / ".codeql-checkpoints"
    cache: dict[str, str] = {}
    trees = {}
    for path in dict.fromkeys((root, output, *databases, *outputs, *caches)):
        trees.update({str(path): tree_hash(path, ignored, cache)})
    return {
        "recipe_sha256": sha256(Path(__file__).read_bytes()).hexdigest(),
        "project": trees[str(root)],
        "outputs": [trees[str(path)] for path in dict.fromkeys((output, *outputs))],
        "databases": [trees[str(path)] for path in databases],
        "toolchains": [trees[str(path)] for path in caches],
        "executables": {
            str(Path(path).resolve()): file_hash(Path(path).resolve(), cache)
            for path in executables
        },
        "resources": pins,
    }


@c.step
def process_sarif(
    raw: Path, final: Path, mode: Literal["run-all", "important-only"]
) -> dict[str, Any]:
    text = raw.read_text(encoding="utf-8")
    data = json.loads(text)
    runs = data.get("runs")
    if not isinstance(runs, list) or not runs:
        c.fail("SARIF contains no runs; a completed inspection cannot be established.")
    stats: dict[str, Any] = {
        "levels": {},
        "rules": {},
        "security_severity": {},
        "locations": [],
        "raw_total": 0,
    }
    for run in runs:
        rules = run.get("tool", {}).get("driver", {}).get("rules", [])
        results = run.get("results", [])
        if not isinstance(results, list):
            c.fail("SARIF results must be a list.")
        stats["raw_total"] += len(results)
        kept = []
        for finding in results:
            index = finding.get("ruleIndex")
            if type(index) is not int or not 0 <= index < len(rules):
                c.fail("A CodeQL result has an invalid or missing ruleIndex.")
            rule = rules[index]
            properties = rule.get("properties", {})
            precision = properties.get("precision", "unknown")
            try:
                score = (
                    float(properties.get("security-severity") or 0)
                    if precision == "medium"
                    else 10.0
                )
            except (TypeError, ValueError):
                c.fail("A medium-precision rule has an invalid security-severity score.")
            if not isfinite(score):
                c.fail("A rule has a nonfinite security-severity score.")
            keep = precision in {"high", "very-high", "unknown"}
            keep = keep or (precision == "medium" and score >= 6)
            if mode == "important-only" and not keep:
                continue
            kept.append(finding)
            entries = (
                ("levels", rule.get("defaultConfiguration", {}).get("level", "unknown")),
                ("rules", str(finding.get("ruleId", rule.get("id", "unknown")))),
                ("security_severity", str(properties.get("security-severity", "none"))),
            )
            for group, key in entries:
                stats[group][key] = stats[group].get(key, 0) + 1
            stats["locations"].append(
                {"rule": finding.get("ruleId"), "locations": finding.get("locations", [])}
            )
        run["results"] = kept
    if mode == "run-all":
        c.write_text(final, text)
    else:
        c.write_json(final, data)
    stats["total"] = sum(stats["levels"].values())
    return stats


@c.recipe(
    name="codeql",
    version="1",
    agents=("worker",),
    capabilities=("Bash",),
    output_root=".",
    budget=c.Budget(max_agent_calls=2, max_wall_seconds=3600),
)
def codeql(
    request: str,
    project: str = ".",
    workflow: Literal["auto", "full", "build", "extensions", "analysis"] = "auto",
    database: str = "",
    output_directory: str = "",
    scan_mode: Literal["run-all", "important-only"] = "run-all",
    quality_error_limit: float = 5.0,
    toolchain_directories: list[str] | None = None,
    checkpoint: str = "",
    decision: UserDecision | None = None,
    resume_databases: list[str] | None = None,
) -> Result:
    if not checkpoint and (decision is not None or resume_databases is not None):
        c.fail("Resume inputs require the checkpoint containing the exact question and routing.")

    # Build every effect location before loading any model-bearing saved content.
    host = inspect_host(
        project,
        database,
        output_directory,
        checkpoint,
        workflow,
        scan_mode,
        quality_error_limit,
        toolchain_directories or [],
    )
    root = Path(host.project)
    new_output = Path(host.new_output)
    databases = [Path(path) for path in host.databases]
    outputs = [Path(path) for path in host.outputs]
    caches = tuple(Path(path) for path in host.caches)
    resources = tuple(Path(path) for path in host.resources)
    writable = tuple(dict.fromkeys((root, new_output, *outputs, *caches)))
    readable = (*writable, *databases, *resources)
    record_path = checkpoint_destination(new_output)
    checkpoint_path = Path(checkpoint).absolute() if checkpoint else None
    preparation = json.loads(json.dumps(host.preparation))
    observations = preparation["source_observations"]
    config = {
        "request": request,
        "project": str(root),
        "workflow": workflow,
        "database": database,
        "output_directory": output_directory,
        "scan_mode": scan_mode,
        "quality_error_limit": quality_error_limit,
        "toolchain_directories": toolchain_directories or [],
    }
    evidence = snapshot(root, new_output, databases, outputs, caches, host.executables, host.pins)
    saved: dict[str, Any] | None = None
    parent_digest = ""
    history: list[Any] = []
    changed = False
    if checkpoint_path is not None:
        saved, parent_digest = load_checkpoint(checkpoint_path)
        if saved["config"] != config:
            c.fail("Resume with the checkpoint's exact saved inputs; answer through decision.")
        if resume_databases is None:
            c.fail("Supply resume_databases from the pending result's exact resume_inputs.")
        if resume_databases != saved["preparation"]["databases"]:
            c.fail("resume_databases must reproduce the saved question's routing evidence.")
        if str(new_output) != saved["preparation"]["new_output"]:
            c.fail("The checkpoint is outside its saved invocation output directory.")
        history = list(saved["conversation"])
        changed = saved["evidence"] != evidence or saved["preparation"] != preparation
        previous = saved["reply"]
        if changed:
            history.append(
                {
                    "kind": "state-change",
                    "checkpoint_digest": parent_digest,
                    "previous_preparation": saved["preparation"],
                    "current_preparation": preparation,
                    "previous_evidence": saved["evidence"],
                    "current_evidence": evidence,
                    "unaccepted_decision": decision.model_dump() if decision is not None else None,
                    "instruction": "Reinspect and refresh the pending question before acting.",
                }
            )
        elif decision is None:
            return pending_result(saved, checkpoint_path, parent_digest)
        else:
            if decision.checkpoint_digest != parent_digest:
                c.fail("The decision digest does not match the saved question and inspected state.")
            if type(decision.option) is not int or not 1 <= decision.option <= len(
                previous["options"]
            ):
                c.fail("Supply a one-based option number from the exact saved ordered options.")
            history.append(
                {
                    "kind": "user-decision",
                    "checkpoint_digest": parent_digest,
                    "question": previous["question"],
                    "report": previous["report"],
                    "options": previous["options"],
                    "selected_option": decision.option,
                    "selected_label": previous["options"][decision.option - 1],
                    "response": decision.response,
                    "evidence": saved["evidence"],
                }
            )

    instructions = (
        "Execute the original requested CodeQL workflow, retaining its reasoning order and "
        "checks. Read complete applicable workflows, supplied programs and references through "
        "the declared filesystem view. Inspect the whole project. Mechanical source lists and "
        "search matches are observations, not an exhaustive semantic candidate selection. "
        "Perform expected-source comparisons, build interpretation, ordered methods and fixes, "
        "macOS workarounds, quality improvements, extension assessment and validation, plan "
        "confirmation, execution and zero-result investigation as required by the source. "
        "Reuse the packaged programs with their actual interfaces, including build_log.sh, "
        "find_databases.sh, check_db_quality.py, generate_suite.sh and verify_query_suite.py. "
        "The generator verifies generated suites; explicitly verify reused or edited suites. "
        "Never report an empty inspection scope as a clean scan. Preserve explicit choices. "
        "Use native reads, writes and commands only. Do not call AskUserQuestion or any Task, "
        "Skill, Workflow, Agent, Glob or other platform orchestration adapter. Track progress "
        "in the connected working record instead. Execute the workflows directly; do not "
        "require the separately distributed codeql-build workflow or another skill recipe. "
        "Every original required user question must instead return state=question, the exact "
        "complete question in question, its context in report, and two to four exact ordered "
        "option labels. Include descriptions and all selection evidence in report where "
        "applicable. Stop before dependent actions. The host persists that question and returns "
        "pending; it does not approve anything. Interpret accepted user-decision events only "
        "against their saved question/options. A default is not an answer to a mandatory "
        "decision. Do not silently bypass original database, language, plan, missing-pack, "
        "private-registry, build or extension decisions. Allow the original plan's mode, packs, "
        "models and threat choices to be changed together. Do not treat unrelated response "
        "text as approval of another question. An event marked unaccepted is not authorization. "
        "After a state-change event, inspect the changed evidence, reassess affected previous "
        "conclusions and approvals, and return a refreshed question. During that refresh, "
        "perform read-only inspection and do not execute actions dependent on the pending "
        "choice. Return blocked if inspection cannot be performed. Keep the connected "
        "assignment in this conversation; do not restart or declare unperformed phases "
        "complete. The full earlier conversation is supplied intact. In continuation retain "
        "the complete observable working record needed to resume: executed commands and their "
        "outcomes, evidence, findings, conclusions, unresolved work and original user decisions. "
        "Earlier responses are preserved verbatim by Python. Use embedded context directly; "
        "read task.txt if the complete assignment is not embedded. Index -1 selects "
        "new_output/codeql.db; other indexes select the current prepared databases and "
        "output_choices. Match any earlier selection to the freshly inspected inventory; "
        "never assume an index remains stable after state changes. Use only these output "
        "locations. All generated scan artifacts belong in the chosen output directory. "
        "Do not read or modify .codeql-checkpoints; the host owns those immutable conversation "
        "records. Reserve results/results.sarif for the host. Inspect raw SARIF and determine "
        "the final-mode count before completing. For extension validation, make the baseline "
        "genuinely exclude the new models, verify loading and compare counts; preserve "
        "diagnostic artifacts. Include every original final-report field and actual guard "
        "outcomes, selected/excluded packs, model coverage and extraction limitations. A raised "
        "quality_error_limit requires examination and recorded justification; do not invent "
        "another limit or override an empty database. Return blocked for missing access, "
        "provider configuration or unfinished required work."
    )
    context = c.prepare_context(
        request,
        instructions=instructions,
        prior_results=json.dumps(
            {
                "preparation": preparation,
                "resource_files": host.resource_views,
                "conversation": history,
                "current_evidence": evidence,
                "refresh_pending_question_only": changed,
            },
            ensure_ascii=False,
        ),
    )
    # A model-bearing checkpoint may choose a control-flow branch, never a path expression.
    if changed:
        reply = c.agent(
            "worker",
            "Continue the complete assignment in read-only refresh mode and return the answer.",
            working_directory=root,
            readable_paths=readable,
            writable_paths=(),
            required_capabilities=("commands",),
            context=context,
            output=Reply,
            timeout=3600,
        )
    else:
        reply = c.agent(
            "worker",
            "Continue the complete assignment from the supplied conversation and return the ans"
            "wer.",
            working_directory=root,
            readable_paths=readable,
            writable_paths=writable,
            required_capabilities=("commands",),
            context=context,
            output=Reply,
            timeout=3600,
        )
    history.append(reply.model_dump())
    if not reply.report.strip() or not reply.continuation.strip():
        c.fail("The worker omitted the required report or observable continuation record.")
    if reply.state == "question" and (
        not reply.question.strip() or not 2 <= len(reply.options) <= 4
    ):
        c.fail("A pending decision requires its exact question and two to four ordered options.")
    evidence = snapshot(root, new_output, databases, outputs, caches, host.executables, host.pins)
    payload = {
        "config": config,
        "preparation": preparation,
        "conversation": history,
        "reply": reply.model_dump(),
        "evidence": evidence,
        "parent": parent_digest,
    }
    record_digest = persist_checkpoint(record_path, payload)
    if changed and reply.state == "complete":
        c.fail("Changed evidence requires a refreshed user decision before dependent work resumes.")
    if reply.state == "question":
        return pending_result(payload, record_path, record_digest)
    if reply.state == "blocked":
        return c.emit(
            Result(
                status="blocked",
                report=reply.report,
                output_directory=str(new_output),
                summary={"conversation_record": str(record_path)},
                checkpoint="",
                checkpoint_digest="",
                question="",
                options=[],
            ),
            name="report",
        )
    if workflow != "auto" and reply.workflow != workflow:
        c.fail("The worker did not complete the explicitly requested workflow.")
    if quality_error_limit > 5 and not reply.override_justified:
        c.fail("A raised error threshold requires examination and recorded justification.")
    choices = [(new_output / "codeql.db", new_output), *zip(databases, outputs, strict=True)]
    if not -1 <= reply.database_index < len(databases):
        c.fail("The selected database is outside the prepared choices.")
    # Enumerate trusted host routes. The model only decides which branch executes.
    for choice_index, (selected_db, selected_output) in enumerate(choices, start=-1):
        if choice_index != reply.database_index:
            continue
        quality = checked(
            [
                "uv",
                "run",
                str(c.resource("scripts/check_db_quality.py")),
                str(selected_db),
                "--format=json",
                "--max-error-ratio",
                str(quality_error_limit),
            ],
            root,
        )
        metrics = json.loads(quality.stdout)
        if not metrics.get("finalised"):
            c.fail("The database is not finalised; completion cannot be reported.")
        if metrics.get("baseline_loc", 0) <= 0 or metrics.get("project_files", 0) <= 0:
            c.fail("The independent quality check inspected no analysable project source.")
        summary: dict[str, Any] = {
            "quality": metrics,
            "expected_source_files": observations["expected_source_files"],
            "conversation_record": str(record_path),
        }
        report = reply.report + "\nIndependent quality check: " + json.dumps(metrics)
        if reply.workflow in {"full", "analysis"}:
            for final_mode in ("run-all", "important-only"):
                if final_mode != reply.mode:
                    continue
                suite = selected_output / "raw" / f"{final_mode}.qls"
                c.verify_artifact(suite)
                if reply.suite_origin in {"reused", "edited"}:
                    checked(
                        [
                            "uv",
                            "run",
                            str(c.resource("scripts/verify_query_suite.py")),
                            str(suite),
                        ],
                        root,
                    )
                elif reply.suite_origin != "generated":
                    c.fail("Completed analysis must identify its explicit suite and origin.")
                c.verify_artifact(selected_output / "rulesets.txt")
                c.ensure_directory(selected_output, output_files=("results/results.sarif",))
                raw = c.verify_artifact(selected_output / "raw" / "results.sarif")
                final = selected_output / "results" / "results.sarif"
                summary.update(process_sarif(raw, final, final_mode))
                c.verify_artifact(final)
                if summary["total"] == 0 and not reply.zero_findings_investigation.strip():
                    c.fail("Zero final findings require investigation and an explanation.")
                report += "\n" + reply.zero_findings_investigation + f"\nFinal SARIF: {final}"
        return c.emit(
            Result(
                status="complete",
                report=report,
                output_directory=str(selected_output),
                summary=summary,
                checkpoint="",
                checkpoint_digest="",
                question="",
                options=[],
            ),
            name="report",
        )
    c.fail("The selected database is outside the prepared choices.")


if __name__ == "__main__":
    raise SystemExit(codeql.cli())


# --- calcifier metadata (skill provenance + sha256) ---
_CALCIFIER_COMPILATION = "compiled"
_CALCIFIER_SKILL = {
    "path": "../SKILL.md",
    "sha256": ("1a6d919ff80f83b262daf650552af6eb6d2c32b19d0c529b70efe0c116b675cf"),
}
_CALCIFIER_RESOURCES = [
    {
        "path": "references/build-fixes.md",
        "sha256": ("e4af17ecbe5a6784e3c011fec1f093ce25e5c852cd92be97caaeaea0be10ca1a"),
        "size": 3290,
        "source": None,
    },
    {
        "path": "references/diagnostic-query-templates.md",
        "sha256": ("c27a979094f8de6d1d341a838de52952a98385ff75c9439a7e76ba3bb3fbe662"),
        "size": 9751,
        "source": None,
    },
    {
        "path": "references/extension-yaml-format.md",
        "sha256": ("c98903da4f21fd94816c520f6fdaba8d12e08b4bd55f85233c487e3baf39a1a6"),
        "size": 7621,
        "source": None,
    },
    {
        "path": "references/important-only-suite.md",
        "sha256": ("9f2fbb57b0e02fe964ad268b11ad88c9598b38314fc008016caa615cf303b3a5"),
        "size": 5270,
        "source": None,
    },
    {
        "path": "references/language-details.md",
        "sha256": ("f0857914eeabfb96929c2d1a8f086e92c0a3973cc2ac8460f371fedc2d023818"),
        "size": 5811,
        "source": None,
    },
    {
        "path": "references/macos-arm64e-workaround.md",
        "sha256": ("72d7c9fc2be8368968516857fe4e32211473b92cc8bc3ef1d28530aaf744d1fe"),
        "size": 7455,
        "source": None,
    },
    {
        "path": "references/performance-tuning.md",
        "sha256": ("536473b91e8574c18a3a943df2e4328615bbabbd899c76827d345ff7be986b7d"),
        "size": 2835,
        "source": None,
    },
    {
        "path": "references/quality-assessment.md",
        "sha256": ("2acbb61d487211a0d6342ef86f774de3d4e05496185d337e09cb39810bcae08a"),
        "size": 7969,
        "source": None,
    },
    {
        "path": "references/ruleset-catalog.md",
        "sha256": ("2b139ae593865548a596fb5b78694cb09d4a1959beb5225a5d8a914155a72165"),
        "size": 2197,
        "source": None,
    },
    {
        "path": "references/run-all-suite.md",
        "sha256": ("bbac653d6e8ea115fa7df47307729745157bb60868939a71167c30cc18dcffb6"),
        "size": 5552,
        "source": None,
    },
    {
        "path": "references/sarif-processing.md",
        "sha256": ("abde04ca479a372ed134150cd9cd1fd2b45cd7b4b45386034a2b3f4d415f6f9b"),
        "size": 3119,
        "source": None,
    },
    {
        "path": "references/threat-models.md",
        "sha256": ("fd4252f0fc71734ab756ff51bead1b894397bf67382b2337cbe0b0de4672cefd"),
        "size": 2799,
        "source": None,
    },
    {
        "path": "scripts/build_log.sh",
        "sha256": ("83c98d08c85a96b0b46246c14f3ffbe61370f5d184338455c6c288ddcf8df5de"),
        "size": 2144,
        "source": None,
    },
    {
        "path": "scripts/check_db_quality.py",
        "sha256": ("fca99a149eb4689730b7d3a3314527a5716823fb5f19b6b79114f4949b726c36"),
        "size": 15069,
        "source": None,
    },
    {
        "path": "scripts/find_databases.sh",
        "sha256": ("a56995c048b322bce45baf4482388a3cdf78dd59d562eca39e169c065f7f9b18"),
        "size": 2515,
        "source": None,
    },
    {
        "path": "scripts/generate_suite.sh",
        "sha256": ("489516c52155c2061ec2a53d8190ebe474f4bdcb53ddc53b1216dc72ff7b1d9f"),
        "size": 3406,
        "source": None,
    },
    {
        "path": "scripts/pyproject.toml",
        "sha256": ("c78fce8eeb7d91895dfc44296bdf547bcf77a156c8c057ae5238032883dfa41b"),
        "size": 585,
        "source": None,
    },
    {
        "path": "scripts/test_build_log.py",
        "sha256": ("3d58186d066d0ebf8117f89dfb03d49a8db8907e43cb013bd51b7669aa478f2d"),
        "size": 3244,
        "source": None,
    },
    {
        "path": "scripts/test_build_mode_claims.py",
        "sha256": ("eeddedd49a2aa33790425f828c808a0504fab66a635c7902878cac2a292db89e"),
        "size": 3678,
        "source": None,
    },
    {
        "path": "scripts/test_check_db_quality.py",
        "sha256": ("842c78079bb0a033f7e3ec0d2608ac5913906c87e96132e85fb38577eb170c29"),
        "size": 20247,
        "source": None,
    },
    {
        "path": "scripts/test_find_databases.py",
        "sha256": ("eb9895c35f94ccb334997b296774dc36c5997ce520acb606bfd83b0934d4982a"),
        "size": 6116,
        "source": None,
    },
    {
        "path": "scripts/test_generation_scripts.py",
        "sha256": ("9b092f2c0ebf630f21276214dc05b72b681a5c3e5e26816621e028d880cf2feb"),
        "size": 11900,
        "source": None,
    },
    {
        "path": "scripts/test_script_flags.py",
        "sha256": ("7aa9ca403051f4bd7690ee4ce46b3d9e16050119a24b4eb2858653e489c7edeb"),
        "size": 6451,
        "source": None,
    },
    {
        "path": "scripts/test_section_pointers.py",
        "sha256": ("46aa000803005d5e3328b4c028b3431f67c7105997bddd15aa361a3e2511695c"),
        "size": 8072,
        "source": None,
    },
    {
        "path": "scripts/test_shell_blocks.py",
        "sha256": ("bf800714b9bee72292d74ac0c80acd47c00e6bb7e2624731e8b30a82c840358e"),
        "size": 29804,
        "source": None,
    },
    {
        "path": "scripts/test_suite_templates.py",
        "sha256": ("94028929d16a3bbcdcc4b92b5f32bda396360cbbb34198c4f2405b3397957d5d"),
        "size": 5120,
        "source": None,
    },
    {
        "path": "scripts/test_verify_query_suite.py",
        "sha256": ("21089b2b06407c6dcf43ff2bf44644b64ad4fd028713eadeafb92e8db8d5732d"),
        "size": 1902,
        "source": None,
    },
    {
        "path": "scripts/verify_query_suite.py",
        "sha256": ("ad1bb120201c9af5ae199d3d36a727ba12d897162f817045e8a8006e691154f8"),
        "size": 2802,
        "source": None,
    },
    {
        "path": "workflows/build-database.md",
        "sha256": ("06794bb67182303b0c81d30b3772531537d9f986b7b2cbe2a9ffa4b4f3e230ba"),
        "size": 13273,
        "source": None,
    },
    {
        "path": "workflows/create-data-extensions.md",
        "sha256": ("f3643e4916e7586c7738c14f781e3919bce35129d75beb00812b963efbbc4673"),
        "size": 10555,
        "source": None,
    },
    {
        "path": "workflows/run-analysis.md",
        "sha256": ("83b0e0bccdb7f9f3962022b4477bcc888a6728eebcd25495378a860da72930c6"),
        "size": 13598,
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
        "ed inspection that finds zero issues.\n\nThe complete prev"
        "ious native candidate is supplied below. Preserve its full"
        " original CodeQL workflows, source/resource pins, helper i"
        "nterfaces, quality gates, suite checks, SARIF processing, "
        "zero-finding investigation, and connected conversation. Re"
        'pair the user-decision mechanism: NEVER require tool("AskU'
        'serQuestion") or any other platform orchestration adapter '
        "(Task, Skill, Workflow, Agent, Glob). These are not bundle"
        "d native providers. Use explicit typed user decision input"
        "s; when required choices are absent, persist a pending che"
        "ckpoint containing the exact question, ordered options, co"
        "nversation and actual project/resource/output evidence has"
        "hes and return a pending result that tells the user what t"
        "o supply. Resume only with explicit checkpoint/digest-boun"
        "d decisions against the same inspected state; do not auto-"
        "approve or silently bypass required plan/build/extension d"
        "ecisions. Retain complete executed reasoning across resume"
        "s. Input decisions must be interpreted only against the ex"
        "act saved question/options; changed state must require a n"
        "ew decision. Host filesystem persistence must respect Calc"
        "ifier declared output paths. Keep only native Calcifier ag"
        "ent/parallel/run_command/filesystem primitives, no unshipp"
        "ed platform adapters. This is a targeted functional repair"
        " to a complete previous candidate, not a request for a pre"
        "flight-only stub; retain all actual scanning implementatio"
        "n. You may exceed 250 lines as needed for faithful complet"
        "e behavior. Repository Ruff E,F,I,UP,B,SIM, target py311, "
        "max line100 must pass. No _CALCIFIER_* constants should be"
        " copied from context; Calcifier injects fresh provenance."
        "\n\nPrecise host diagnosis, reproduced against published0."
        "2.0: the taint binding walker wrongly marks EVERY ast.Name"
        " under a subscript assignment target as model-derived. In "
        "snapshot(), hashes[str(path)] = tree_hash(path, ignored, c"
        "ache) therefore taints built-in str globally once tree_has"
        "h is tainted via the shared digest helper used for model c"
        "heckpoint content. All unrelated trusted str(root), str(db"
        "), etc then fail. Minimal proven repro: answer=agent(...);"
        ' data={}; data[str(root)]=answer; run_command(["git","-C",'
        'str(root),"status"]) is wrongly rejected. Equivalent data.'
        "update({str(root):answer}) preserves data-content taint bu"
        "t does NOT taint the selector or built-in and passes. Repa"
        "ir model-containing or model-hash-containing mapping write"
        "s with dictionary literal/update/comprehension forms; avoi"
        "d assigning through computed subscript targets containing "
        "callable names. In particular snapshot's hashes[str(path)]"
        " assignment needs this equivalent storage repair. Preserve"
        " all complete native CodeQL workflows, independently recom"
        "puted trusted host selectors, evidence-bound pending/resum"
        "e decisions, original helper interfaces and quality/SARIF "
        "gates. Do not bypass taint validation or suppress diagnost"
        "ics; the actual command/path selectors must remain derived"
        " from trusted current inputs or deterministic host discove"
        "ry. This is a targeted equivalent storage-form fix to the "
        "supplied complete candidate; no stub and no platform adapt"
        "ers.\n\nFocused continuation: supplied complete candidate "
        "already has native evidence-bound user checkpoints and ind"
        "ependently reconstructed host selectors. Apply the precise"
        " equivalent dictionary-storage repair for hashes[str(path)"
        "] to avoid the proven false-positive on built-in str, whil"
        "e retaining all actual host and model separation. Keep exi"
        "sting functional code; do not redesign the entire module."
        "\n"
    ),
    "sha256": ("42d31d3c4ab03cf3a8dbcf94c86940cc0fb699698391da26ec68b53de8dea958"),
}
_CALCIFIER_SUBRECIPES = []
