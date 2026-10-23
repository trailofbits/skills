# /// script
# requires-python = ">=3.13"
# dependencies = ["calcifier==0.2.0"]
# ///

import json
import re
import shlex
from collections import Counter
from hashlib import sha256
from pathlib import Path
from typing import Any, Literal

from calcifier import (
    Budget,
    CommandResult,
    agent,
    emit,
    ensure_directory,
    fail,
    output_type,
    prepare_context,
    recipe,
    resource,
    run_command,
    verify_artifact,
    write_json,
)


@output_type
class Selection:
    detected: list[str]
    detection: str
    rulesets: dict[str, list[str]]


STAGES = (
    "Detect languages and Pro availability",
    "Select scan mode and rulesets",
    "Present exact plan and get approval",
    "Execute approved scans",
    "Merge results and report",
)


def progress(completed: int, current: str) -> None:
    ledger = []
    for index, title in enumerate(STAGES):
        status = "completed" if index < completed else "blocked"
        if index == completed:
            status = current
        ledger.append(
            dict(stage=index + 1, title=title, status=status, blocked_by=[index] if index else [])
        )
    emit(ledger, name=f"progress-{completed}")


def command(args: list[str], write: bool = False, seconds: int = 180) -> CommandResult:
    result = run_command(args, timeout_seconds=seconds, mutating=write)
    emit(
        dict(argv=args, exit_code=result.exit_code, stdout=result.stdout, stderr=result.stderr),
        name="process",
    )
    if result.exit_code:
        fail(
            "Command failed; stopping without adjusted scans or a clean-result claim.\n"
            + result.stderr
            + "\n"
            + result.stdout
        )
    return result


def document(path: Path) -> dict[str, Any]:
    data = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        fail(f"Expected a JSON object in {path}.")
    return data


def inventory(tree: Path, out: Path, patterns: dict[str, str]) -> dict[str, list[str]]:
    files = [p for p in tree.rglob("*") if p.is_file() and not p.is_relative_to(out)]
    if any(not p.resolve().is_relative_to(tree) for p in files):
        fail("The target contains a file symlink escaping its declared filesystem view.")
    markers = dict(
        python="pyproject.toml requirements.txt",
        javascript="package.json",
        go="go.mod",
        ruby="Gemfile",
        java="pom.xml",
        php="composer.json",
        rust="Cargo.toml",
    )
    observed = {}
    for category, globs in patterns.items():
        if category in {"c", "typescript", "cloudformation", "kubernetes", "github-actions"}:
            continue
        names = (globs + " " + markers.get(category, "")).split()
        observed[category] = sorted(
            str(p.relative_to(tree)) for p in files if any(p.match(name) for name in names)
        )
    if not any(observed.values()):
        fail("No supported source, infrastructure candidates, or framework manifests found.")
    return observed


def choose_groups(
    selected: Selection,
    patterns: dict[str, str],
    registry: list[str],
    repos: list[str],
    overrides: dict[str, list[str]] | None,
) -> dict[str, list[str]]:
    expected = set(selected.detected)
    if not expected <= set(patterns):
        fail("Detection must use canonical categories supported by the supplied runner.")
    proposed = selected.rulesets if overrides is None else overrides
    if set(proposed) - {"baseline", "third_party"} != expected:
        fail("Supply exactly one ruleset group for each detected category.")
    if "third_party" not in proposed:
        fail("The plan must explicitly account for required third-party rulesets.")
    groups = {}
    for key, values in proposed.items():
        pool = repos if key == "third_party" else registry
        if overrides is None and not set(values) <= set(pool):
            fail("Worker recommendations must select entries from the packaged catalog.")
        groups[key] = (
            [entry for entry in pool if entry in values]
            if overrides is None
            else sorted(set(values))
        )
        for value in groups[key]:
            expression = (
                r"https://[A-Za-z0-9.-]+(:[0-9]+)?(/[A-Za-z0-9._-]+)+/?"
                if key == "third_party"
                else r"[A-Za-z0-9._-]+(/[A-Za-z0-9._-]+)*"
            )
            if not re.fullmatch(expression, value) or ".." in value.split("/"):
                fail(f"Invalid ruleset entry: {value}")
    if not {"p/security-audit", "p/secrets"} <= set(groups.get("baseline", [])):
        fail("Both mandatory security baseline rulesets must remain present.")
    return groups


def render_plan(saved: dict[str, Any]) -> str:
    lines = [
        "Semgrep Scan Plan",
        f"Target: {saved['target']}",
        f"Output directory: {saved['output']}",
        f"Engine: {saved['engine']}",
        f"Scan mode: {saved['mode']}",
        f"Concurrent scans: {saved['jobs']}",
        f"Maximum target bytes: {saved['max_target_bytes']} (0 means unlimited)",
        saved["detection"],
    ]
    for key, values in saved["rulesets"].items():
        lines.append(key + ":")
        lines.extend(f"- [x] {value}" for value in values)
    if saved["mode"] == "important-only":
        lines.append(
            "Every scan uses --severity WARNING --severity ERROR, including third-party "
            "repos. CLI INFO rules are dropped before metadata filtering; choose run-all "
            "to retain them. Missing metadata otherwise receives the reference defaults."
        )
    lines.append(
        "To modify rulesets, create a new plan with ruleset_overrides. Review the updated "
        "plan before approving it. The original scan request is not plan approval."
    )
    return "\n".join(lines)


def review_plan(saved: dict[str, Any], out: Path) -> dict[str, Any]:
    digest = sha256(json.dumps(saved, sort_keys=True).encode("utf-8")).hexdigest()
    return emit(
        dict(
            plan=render_plan(saved),
            plan_sha256=digest,
            output_directory=str(out),
            next_step=(
                "Review every ruleset. To approve, rerun with the same target and "
                "output_directory, action='scan', an explicit approval such as 'proceed', "
                "and approved_plan_sha256 equal to this digest. To modify rulesets, run "
                "action='plan' with overrides and a fresh output directory, then review "
                "its new plan. No scans have run at this gate."
            ),
        ),
        name="scan-plan",
    )


def raw_path(value: str, out: Path) -> Path:
    path = Path(value).resolve()
    if path.parent != out / "raw" or path.suffix != ".json":
        fail("A scan manifest JSON path escaped the reserved raw-result directory.")
    return path


def create_plan(
    tree: Path,
    destination: Path,
    mode: Literal["run-all", "important-only"],
    overrides: dict[str, list[str]] | None,
    jobs: int,
    max_target_bytes: int,
) -> dict[str, Any]:
    progress(0, "running")
    out = ensure_directory(destination, output_files=("plan.json", "raw", "results")).resolve()
    for part in ("raw", "results"):
        ensure_directory(out / part)
    names = (
        "references/rulesets.md",
        "references/scan-modes.md",
        "workflows/scan-workflow.md",
        "scripts/run-scans.sh",
        "scripts/merge_sarif.py",
    )
    refs = tuple(resource(name) for name in names)
    catalog = resource("references/rulesets.md").read_text(encoding="utf-8")
    registry = sorted(set(re.findall(r"`([pr]/[A-Za-z0-9._/-]+)`", catalog)))
    repos = sorted(set(re.findall(r"https://github.com/[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", catalog)))
    patterns = dict(
        re.findall(
            r"^\s*([a-z-]+)\) echo '([^']+)' ;;",
            resource("scripts/run-scans.sh").read_text(encoding="utf-8"),
            re.MULTILINE,
        )
    )
    if not patterns or not registry or not repos:
        fail("Packaged runner or catalog could not be parsed; selection is incomplete.")
    observed = inventory(tree, out, patterns)
    version = command(["semgrep", "--version", "--metrics=off"], seconds=60)
    pro = run_command(
        ["semgrep", "--pro", "--validate", "--metrics=off", "--config", "p/default"],
        timeout_seconds=180,
        mutating=False,
    )
    context = prepare_context(
        "Apply the original connected detection and ruleset-selection workflow to the "
        "whole target, in its original order. Inventory and counts are observations, "
        "not an exhaustive semantic candidate screen. Inspect framework markers across "
        "the monorepo, disambiguate YAML and JSON using the source methodology, and "
        "include every applicable mandatory third-party source. Use complete embedded "
        "instructions and references directly; read complete reference files when text "
        "is absent or a file check is needed. Return canonical detected categories, "
        "file counts and frameworks in detection, and structured ruleset selections. "
        "Do not execute scans. The host handles user choices, registry verification, "
        "approval, scripts, filtering, merging and reporting with native primitives.",
        prior_results=json.dumps(dict(inventory=observed, mode=mode, pro_exit=pro.exit_code)),
        files=refs,
        readable_roots=refs,
    )
    selected = agent(
        "worker",
        "Perform the assigned interpretation using the authoritative source workflow.",
        context=context,
        working_directory=tree,
        readable_paths=(tree, *refs),
        output=Selection,
        timeout=3600,
    )
    progress(1, "running")
    groups = choose_groups(selected, patterns, registry, repos, overrides)
    verification_pool = registry
    if overrides is not None:
        verification_pool = sorted(
            {value for key, values in overrides.items() if key != "third_party" for value in values}
        )
    # The worker chooses whether a trusted catalog entry is needed, never the command value.
    for identifier in verification_pool:
        if any(identifier in values for key, values in groups.items() if key != "third_party"):
            command(["semgrep", "--validate", "--metrics=off", "--config", identifier])
    saved = dict(
        target=str(tree),
        output=str(out),
        mode=mode,
        pro=pro.exit_code == 0,
        engine="Semgrep Pro (cross-file)" if pro.exit_code == 0 else "Semgrep OSS (single-file)",
        pro_unavailable_reason="\n".join((pro.stdout + pro.stderr).splitlines()[-3:])
        if pro.exit_code
        else "",
        version=version.stdout,
        detection=selected.detection,
        detected=selected.detected,
        inventory=observed,
        rulesets=groups,
        jobs=jobs,
        max_target_bytes=max_target_bytes,
    )
    write_json(out / "plan.json", saved)
    progress(2, "awaiting-approval")
    return emit(review_plan(saved, out), name="approval-required")


def execute_plan(
    tree: Path,
    out: Path,
    mode: Literal["run-all", "important-only"] | None,
    approval: str,
    approved_plan_sha256: str,
    jobs: int | None,
    max_target_bytes: int | None,
) -> dict[str, Any]:
    # Execution receives only trusted recipe inputs and reads its reviewed artifact itself.
    # No worker result or planning return value supplies command arguments or destinations.
    path = out / "plan.json"
    if not path.is_file() or path.is_symlink():
        fail("No regular saved plan found. Run action='plan' first and review its output.")
    saved = document(path)
    if saved.get("target") != str(tree) or saved.get("output") != str(out):
        fail("The saved plan belongs to a different target or output directory.")
    if saved.get("mode") not in {"run-all", "important-only"}:
        fail("The saved plan has no supported mode; generate a new plan.")
    if (
        not isinstance(saved.get("jobs"), int)
        or saved["jobs"] < 1
        or not isinstance(saved.get("max_target_bytes"), int)
        or saved["max_target_bytes"] < 0
        or not isinstance(saved.get("pro"), bool)
    ):
        fail("The saved execution settings are invalid; generate a new plan.")
    if (
        (mode is not None and mode != saved["mode"])
        or (jobs is not None and jobs != saved["jobs"])
        or (max_target_bytes is not None and max_target_bytes != saved["max_target_bytes"])
    ):
        fail("Execution choices differ from the saved plan; create and approve a new plan.")
    progress(2, "awaiting-approval")
    review = review_plan(saved, out)
    digest = sha256(json.dumps(saved, sort_keys=True).encode("utf-8")).hexdigest()
    if approval == "pending" or approved_plan_sha256 != digest:
        fail("Scanning remains unapproved. Supply explicit approval and the reviewed plan digest.")
    if any((out / part).is_symlink() for part in ("raw", "results", "repos", "tmp")):
        fail("A reserved output directory is a symlink; use a fresh output directory.")
    if not (out / "raw").is_dir() or any((out / "raw").iterdir()):
        fail("The reviewed plan needs its empty raw directory; create a fresh plan to rerun.")
    ensure_directory(
        out,
        output_files=("rulesets.json", "scans.json", "repos", "tmp", "results/results.sarif"),
    )
    ensure_directory(out / "tmp")
    write_json(out / "rulesets.json", saved["rulesets"])
    progress(3, "running")
    scan_mode = "important-only" if saved["mode"] == "important-only" else "run-all"
    runner = resource("scripts/run-scans.sh")
    argv = [
        "bash",
        "-c",
        'export TMPDIR="$1"; shift; exec bash "$@"',
        "semgrep",
        str(out / "tmp"),
        str(runner),
        "--target",
        str(tree),
        "--output-dir",
        str(out),
        "--mode",
        scan_mode,
        "--rulesets",
        str(out / "rulesets.json"),
        "--jobs",
        str(saved["jobs"]),
        "--max-target-bytes",
        str(saved["max_target_bytes"]),
    ] + (["--pro"] if saved["pro"] else [])
    preview = command(argv + ["--dry-run"], write=True)
    outputs = []
    for line in preview.stdout.splitlines():
        args = shlex.split(line)
        if not args or args[0] != "semgrep" or "-o" not in args:
            fail("The supplied runner returned an unrecognized command preview.")
        raw = raw_path(args[args.index("-o") + 1], out)
        outputs.extend(
            str(p.relative_to(out))
            for p in (raw, raw.with_suffix(".sarif"), raw.with_name(raw.stem + "-important.json"))
        )
    if not outputs:
        fail("The approved plan produced no scan commands; no inspection can be claimed.")
    ensure_directory(out, output_files=tuple(outputs))
    scan_result = run_command(argv, timeout_seconds=3600, mutating=True)
    emit(
        dict(
            argv=argv,
            exit_code=scan_result.exit_code,
            stdout=scan_result.stdout,
            stderr=scan_result.stderr,
        ),
        name="scan-process",
    )
    if scan_result.exit_code:
        fail(
            "No scan succeeded. Stopping without adjusted arguments or a clean report.\n"
            + scan_result.stderr
            + "\n"
            + scan_result.stdout
        )
    data = document(out / "scans.json")
    if not isinstance(data.get("scans"), list) or not data["scans"]:
        fail("No scan succeeded; stopping without adjusted arguments or a clean report.")
    progress(4, "running")
    scanned: set[str] = set()
    lookup: dict[tuple[str, str, int], Any] = {}
    for scan in data["scans"]:
        content = document(raw_path(scan["json"], out))
        scanned.update((content.get("paths") or {}).get("scanned") or [])
        for finding in content["results"]:
            key = (finding["check_id"], finding["path"], finding["start"]["line"])
            lookup[key] = finding["extra"]
            scanned.add(finding["path"])
    filter_diagnostics = []
    if scan_mode == "important-only":
        reference = resource("references/scan-modes.md").read_text(encoding="utf-8")
        matched = re.search(r"if ! jq '([\s\S]+?)' \"\$f\"", reference)
        if matched is None:
            fail("The packaged reference has no recognizable important-only JSON filter.")
        for raw in sorted((out / "raw").glob("*-*.json")):
            if raw.stem.endswith(("-important", "-triage")):
                continue
            filtered = run_command(
                ["jq", matched[1], str(raw)], timeout_seconds=180, mutating=False
            )
            if filtered.exit_code:
                diagnostic = dict(file=str(raw), error=filtered.stderr)
                filter_diagnostics.append(diagnostic)
                emit(diagnostic, name="filter-failure")
            else:
                write_json(raw.with_name(raw.stem + "-important.json"), json.loads(filtered.stdout))
    merge = command(
        [
            "uv",
            "run",
            "--no-project",
            str(resource("scripts/merge_sarif.py")),
            str(out / "raw"),
            str(out / "results/results.sarif"),
            "--scans",
            str(out / "scans.json"),
        ]
        + (["--important"] if scan_mode == "important-only" else []),
        write=True,
        seconds=300,
    )
    merged = document(verify_artifact(out / "results/results.sarif"))
    if merged.get("version") != "2.1.0" or not isinstance(merged.get("runs"), list):
        fail("Merged output is JSON but does not have the expected SARIF document structure.")
    command(["rm", "-rf", "--", str(out / "repos")], write=True)
    if not scanned:
        fail("No inspected files confirmed; an empty inspection scope is not a clean result.")
    severity, categories = Counter[str](), Counter[str]()
    for run in merged["runs"]:
        for finding in run.get("results", []):
            physical = (finding.get("locations") or [{}])[0].get("physicalLocation", {})
            key = (
                finding.get("ruleId", ""),
                physical.get("artifactLocation", {}).get("uri", ""),
                physical.get("region", {}).get("startLine", 0),
            )
            extra = lookup.get(key, {})
            fallback = {"error": "ERROR", "warning": "WARNING", "note": "INFO"}
            level = fallback.get(finding.get("level", ""), "UNKNOWN")
            severity[str(extra.get("severity", level))] += 1
            categories[str((extra.get("metadata") or {}).get("category", "Unannotated"))] += 1
    missing_names = set()
    for line in merge.stdout.splitlines():
        if line.startswith("unparseable:"):
            missing_names.update(line.rsplit("merge: ", 1)[-1].split(", "))
    missing = [
        dict(file=scan["sarif"], omitted_findings=scan["findings"])
        for scan in data["scans"]
        if Path(scan["sarif"]).name in missing_names
    ]
    report = emit(
        dict(
            approved_plan=review["plan"],
            approved_plan_sha256=digest,
            approval_quote=approval,
            engine=saved["engine"],
            mode=scan_mode,
            version=saved["version"],
            pro_unavailable_reason=saved["pro_unavailable_reason"],
            files_scanned=len(scanned),
            scanned_count_basis="Union of reported scanned paths and paths with actual findings.",
            rulesets_used=len(data["scans"]),
            total_findings=sum(severity.values()),
            by_severity=dict(severity),
            by_category=dict(categories),
            coverage=data,
            missing_from_merge=missing,
            merge_diagnostics=merge.stdout,
            filter_diagnostics=filter_diagnostics,
            coverage_explanation=(
                "Failed/skipped rulesets did not run. Partial scans lost rules to compilation "
                "errors but retain their findings. coveredNothing opened no files. Oversized "
                "files remain unscanned; maxTargetBytes also limits unscoped scans, whose "
                "size gap is not enumerable here. Unparseable SARIF findings are missing from "
                "the merged total. excludePattern matches anywhere in the tree. alsoShared "
                "retains baseline coverage; unscoped languages ran without include globs. "
                "A filesScanned value of -1 means that scan did not report its file count."
            ),
            default_ignore=""
            if (tree / ".semgrepignore").is_file()
            else (
                "No root .semgrepignore: built-in defaults plus .gitignore governed exclusions, "
                "including vendored, minified, dist, build and test paths. Those omitted paths "
                "are not clean results. Re-run suspected paths or add a repository "
                ".semgrepignore to control exclusions."
            ),
            outputs=dict(
                sarif=str(out / "results/results.sarif"),
                raw=str(out / "raw"),
                approved_rulesets=str(out / "rulesets.json"),
                reviewed_plan=str(out / "plan.json"),
            ),
        ),
        name="report",
    )
    progress(5, "completed")
    return report


@recipe(
    name="semgrep",
    agents=("worker",),
    output_root=".",
    capabilities=("Bash",),
    budget=Budget(max_agent_calls=2, max_wall_seconds=3600),
)
def semgrep(
    target: str,
    action: Literal["plan", "scan"] = "plan",
    mode: Literal["run-all", "important-only"] | None = None,
    output_directory: str = "",
    approval: Literal[
        "pending", "yes", "proceed", "approved", "go ahead", "looks good", "run it"
    ] = "pending",
    approved_plan_sha256: str = "",
    ruleset_overrides: dict[str, list[str]] | None = None,
    jobs: int | None = None,
    max_target_bytes: int | None = None,
) -> dict[str, Any]:
    if action == "plan" and mode is None:
        fail("Choose mode='run-all' or mode='important-only', then run action='plan'.")
    if action == "scan" and not output_directory:
        fail("Provide the output_directory emitted by action='plan'; scanning needs its plan.")
    if action == "scan" and ruleset_overrides is not None:
        fail("Ruleset changes require action='plan' and approval of its new digest.")
    if (jobs is not None and jobs < 1) or (max_target_bytes is not None and max_target_bytes < 0):
        fail("jobs must be positive; max_target_bytes must be a nonnegative integer.")
    tree = Path(target).resolve()
    if not target or not tree.is_dir():
        fail("Provide an existing target directory.")
    root = ensure_directory(".").resolve()
    number = 1
    while not output_directory and (root / f"static_analysis_semgrep_{number}").exists():
        number += 1
    destination = root / (output_directory or f"static_analysis_semgrep_{number}")
    resolved = destination.resolve()
    if not resolved.is_relative_to(root) or tree.is_relative_to(resolved):
        fail("Output must be inside the recipe output root and must not contain the target.")
    for location in (tree, resolved):
        if any(character in str(location) for character in ('"', "$", "`", "\\")) or any(
            ord(character) < 32 or ord(character) == 127 for character in str(location)
        ):
            fail("Target or output path contains a character the supplied runner rejects.")
    if action == "plan":
        if mode is None:
            fail("Choose mode='run-all' or mode='important-only' before planning.")
        return create_plan(
            tree,
            resolved,
            mode,
            ruleset_overrides,
            4 if jobs is None else jobs,
            20000000 if max_target_bytes is None else max_target_bytes,
        )
    return execute_plan(
        tree, resolved, mode, approval, approved_plan_sha256, jobs, max_target_bytes
    )


if __name__ == "__main__":
    raise SystemExit(semgrep.cli())


# --- calcifier metadata (skill provenance + sha256) ---
_CALCIFIER_COMPILATION = "compiled"
_CALCIFIER_SKILL = {
    "path": "../SKILL.md",
    "sha256": ("52162605593f871cf45f48f9cf00b7c2d7e0759ccb7507981088442b7cc5d76c"),
}
_CALCIFIER_RESOURCES = [
    {
        "path": "references/rulesets.md",
        "sha256": ("e641bf7b2f32cd81b2623759f72a560dd96f6747f1295157f2984fe8ebac3f74"),
        "size": 7695,
        "source": None,
    },
    {
        "path": "references/scan-modes.md",
        "sha256": ("99ed0ffb9e9ee68bcb175da469f1310f28f96e356c69c65918a0afc430027d3d"),
        "size": 8713,
        "source": None,
    },
    {
        "path": "scripts/merge_sarif.py",
        "sha256": ("8b6094e18a0e4d36250c72c81903edac914552df7eb2a7eebd1ac449d105f7ba"),
        "size": 14034,
        "source": None,
    },
    {
        "path": "scripts/run-scans.sh",
        "sha256": ("ac3d815dbd5cdfa0419596411058378ab659bd243c7dc87495114e773aa40347"),
        "size": 34393,
        "source": None,
    },
    {
        "path": "scripts/test_merge_sarif.py",
        "sha256": ("8f235bface6ff37f813c1a44b2a6c2edf273cd548b95b770c362f0a443473c75"),
        "size": 22943,
        "source": None,
    },
    {
        "path": "workflows/scan-workflow.md",
        "sha256": ("ddb630d34a51a749157140d71fd05044b09301352126f2c169a3119d5eb1d1a4"),
        "size": 24630,
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
        "ed inspection that finds zero issues.\n\nThe complete last"
        " candidate is supplied as reference data. Preserve its rea"
        "l\nSemgrep analysis workflow, commands, source methodology"
        ", rule selection and\nreporting, while removing unavailabl"
        "e interactive/task platform adapters.\nCalcifier 0.2.0 doe"
        "s not ship AskUserQuestion, TaskCreate, TaskUpdate, TaskLi"
        "st,\nTaskOutput or TaskStop adapters. Use explicit typed r"
        "ecipe inputs for all user\nchoices/approvals, with actiona"
        "ble missing-choice guidance rather than silent\napproval. "
        "Use host-owned native progress state/ledger with the sourc"
        "e's stage\nordering and dependencies; mark stages complete"
        "d only after their actual work.\nUse deterministic Python "
        "pathlib or rg inventory for the existing Glob operation.\n"
        "Keep actual analysis and uncertain decisions with the nati"
        "ve worker session(s);\nuse native agent/parallel/run_comma"
        "nd/resource primitives. Preserve a complete\nrunnable impl"
        "ementation, not a permanently unavailable preflight. All r"
        "esource\ntext is supplied as compiler data. Fidelity has p"
        "riority over the suggested\n250 lines. Satisfy destination"
        " Ruff E,F,I,UP,B,SIM and 100-column formatting.\n"
    ),
    "sha256": ("96fbc32a63942d856f8e1d23cd571b3b5c441b4b4f75b8bef8a8b339d0f37828"),
}
_CALCIFIER_SUBRECIPES = []
