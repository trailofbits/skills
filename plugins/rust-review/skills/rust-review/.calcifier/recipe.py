# /// script
# requires-python = ">=3.13"
# dependencies = ["calcifier==0.2.0"]
# ///

import json
import re
import tomllib
from pathlib import Path
from typing import Literal

import calcifier as c


@c.output_type
class Reply:
    abort: str
    findings: list[list[str]]
    seeds: list[str]
    summary: str
    report: str
    truncated: bool


INCIDENTAL_EXCLUSIONS = frozenset(
    (
        ".git",
        "target",
        "build",
        "dist",
        ".cache",
        "__pycache__",
        "node_modules",
        ".rust-review-results",
        "rust-review-output",
    )
)


def incidental_inventory(root: Path) -> list[Path]:
    """Enumerate incidental context without traversing build, VCS, or cache trees."""
    if root.is_file():
        return [root]
    found: list[Path] = []
    pending = [root]
    while pending:
        directory = pending.pop()
        for path in sorted(directory.iterdir()):
            if path.is_symlink():
                assert path.resolve().is_relative_to(root), "Context symlink escape."
            if path.is_dir():
                if path.name not in INCIDENTAL_EXCLUSIONS and not path.is_symlink():
                    pending.append(path)
            elif path.is_file():
                found.append(path)
    return sorted(found)


def preflight_flat(directory: Path, filenames: tuple[str, ...]) -> None:
    """Check disjoint flat batches before any producer writes into this directory."""
    assert len(filenames) == len(set(filenames)), "Overlapping output declarations."
    assert all(Path(name).name == name for name in filenames), "Expected flat outputs."
    if not filenames:
        c.ensure_directory(directory)
    for start in range(0, len(filenames), 256):
        c.ensure_directory(
            directory,
            output_files=filenames[start : start + 256],
            overwrite=True,
        )


def front(text: str) -> dict[str, str]:
    head = text[4:].split("\n---", 1)[0] if text.startswith("---\n") else ""
    return {k: v.strip().strip("'\"") for k, v in re.findall(r"(?m)^(\w+):[ \t]*(.*)$", head)}


def command(argv: list[str], cwd: Path, *, mutating: bool = False) -> str:
    result = c.run_command(argv, working_directory=cwd, timeout_seconds=120, mutating=mutating)
    return (result.stderr or result.stdout or "Command failed") if result.exit_code else ""


def consult(task: str, protocol: str, view: tuple[Path, ...], prior: str = "") -> Reply:
    reference = c.resource(protocol)
    ctx = c.prepare_context(
        task,
        prior_results=prior,
        files=(reference,),
        readable_roots=(reference,),
        instructions=(
            "Apply the complete pinned protocol to the full assigned target, preserving its "
            "reasoning order, inventories, searches, interpretation, and checks. The original "
            "SKILL.md remains authoritative. This native execution interface replaces only "
            "file persistence and platform bookkeeping: the host writes your returned content "
            "and runs the supplied helper programs. Use available read tools and read-only "
            "commands, including rg, for source inspection. Do not mutate source or output "
            "files, invoke platform adapters, or run the report helpers yourself. If tools "
            "required for analysis are unavailable, return an explicit abort. Read the complete "
            "reference from the context bundle when it is not embedded. Workers return "
            "findings as one list of complete finding Markdown strings per assigned pass in "
            "assignment order, and seeds as one coverage explanation per assigned pass. Use "
            "the host's sequential finding identities within each assigned prefix. Return ALL "
            "findings; never drop, combine, or truncate findings to fit persistence capacity. "
            "The host retains your entire Reply before checking its output slots. Retain "
            "NOT SEARCHED and truncation markers for any unperformed pass. Judges return "
            "findings as exactly one list containing every complete finding file in the "
            "host-provided canonical order, including unchanged absorbed findings. Perform "
            "the full judge protocol, with deterministic Tier 1 and interpretation of all "
            "later tiers for dedup, and actual source verification for FP/severity. Return "
            "summary as the complete required summary Markdown. The FP judge returns the "
            "complete final Markdown report in report. Unused fields are empty; abort names "
            "any incomplete reasoning or unavailable prerequisite. Never claim a search or "
            "verification occurred merely because its coverage row or artifact is present. "
            "Incidental inventory exclusions do not restrict semantic inspection: inspect "
            "the complete declared finding scope and context roots as the protocol requires."
        ),
    )
    try:
        return c.agent(
            "worker",
            ctx.prompt,
            context=ctx,
            working_directory=view[0],
            readable_paths=view,
            required_capabilities=("commands",),
            output=Reply,
            timeout=3600,
        )
    except Exception as exc:
        if type(exc).__name__ == "BudgetExceeded":
            raise
        return Reply(abort=str(exc), findings=[], seeds=[], summary="", report="", truncated=True)


def exceeds_capacity(reply: Reply, slots: list[tuple[Path, ...]]) -> bool:
    return any(
        len(findings) > len(slots[i]) for i, findings in enumerate(reply.findings) if i < len(slots)
    )


def save_worker(
    reply: Reply,
    assignment: dict,
    out: Path,
    allowed: set[str],
    slots: list[tuple[Path, ...]],
) -> str:
    """Persist content only into destinations enumerated and preflighted by the host."""
    if exceeds_capacity(reply, slots):
        return (
            "INCOMPLETE: finding slot capacity exceeded. All returned findings are preserved "
            "in the worker JSON receipt. Increase finding_slots_per_pass and rerun; never "
            "drop findings to fit."
        )
    if reply.abort:
        return reply.abort
    prefixes = assignment["pass_prefixes"]
    bugs = assignment["pass_bug_classes"]
    if len(reply.findings) != len(prefixes) or len(reply.seeds) != len(prefixes):
        return "Malformed completion: missing assigned coverage"
    wid = f"worker-{assignment['worker_n']}"
    written: list[Path] = []
    rows = []
    sections = (
        "Description",
        "Code",
        "Data flow",
        "Reachability trace",
        "Impact",
        "Mitigations checked",
        "Recommendation",
    )
    for i in range(len(prefixes)):
        ids = []
        if not reply.findings[i] and not reply.seeds[i].strip():
            return "Missing cleared seed"
        for n, destination in enumerate(slots[i]):
            if n >= len(reply.findings[i]):
                continue
            text = reply.findings[i][n]
            fid = destination.stem
            fm = front(text)
            location = fm.get("location", "")
            if (fm.get("id"), fm.get("bug_class"), fm.get("worker")) != (fid, bugs[i], wid):
                return "Malformed finding identity"
            if (
                not re.fullmatch(r"[^:,\n]+:[1-9]\d*", location)
                or location.rpartition(":")[0] not in allowed
                or fm.get("confidence") not in ("High", "Medium", "Low")
                or any(not fm.get(k) for k in ("title", "function"))
                or "," in fm["function"]
                or any(f"## {s}" not in text for s in sections)
                or any(k in fm for k in ("severity", "fp_verdict", "merged_into", "also_known_as"))
            ):
                return "Malformed finding schema, scope, or sections"
            ids.append(fid)
            c.write_text(destination, text)
            written.append(destination)
        outcome = "filed: " + ", ".join(ids) if ids else f"cleared ({reply.seeds[i]})"
        rows.append(f"| {prefixes[i]} | {bugs[i]} | {outcome} |")
    c.write_text(
        out / "findings-index.d" / f"{wid}.txt",
        "".join(f"{path}\n" for path in sorted(written)),
    )
    c.write_text(
        out / "coverage" / f"{wid}.md",
        "| Pass prefix | Bug class | Outcome |\n|---|---|---|\n" + "\n".join(rows),
    )
    return ""


@c.recipe(
    name="rust-review",
    version="1",
    agents=("worker",),
    capabilities=("Bash",),
    budget=c.Budget(286, 3600),
    output_root="rust-review-output",
)
def rust_review(
    project: str,
    threat_model: Literal["REMOTE", "LOCAL_UNPRIVILEGED", "BOTH"],
    severity_filter: Literal["all", "medium", "high"],
    worker_model: Literal["inherit", "haiku", "sonnet", "opus"] = "inherit",
    scope_subpath: str = ".",
    context_roots: tuple[str, ...] = (".",),
    finding_slots_per_pass: int = 64,
) -> dict:
    """Use the configured worker role; capacity is an explicit trusted CLI input."""
    if worker_model != "inherit":
        c.fail(
            "Platform model brands cannot be verified or selected by this recipe. Configure "
            "the Calcifier runtime worker role for the desired provider/model, then use "
            "worker_model='inherit'."
        )
    if isinstance(finding_slots_per_pass, bool) or finding_slots_per_pass <= 0:
        c.fail("finding_slots_per_pass must be a positive integer; the default is 64.")
    repo = Path(project).resolve()
    scope = (repo / scope_subpath).resolve()
    roots = tuple((repo / p).resolve() for p in context_roots)
    assert scope.is_dir() and scope.is_relative_to(repo) and roots, "Invalid finding scope."
    assert all(p.exists() and p.is_relative_to(repo) for p in roots), "Invalid context roots."
    # Incidental enumeration is pruned. Semantic Rust enumeration remains complete,
    # including Rust sources inside build/cache-named directories in the requested scope.
    rust = sorted(p for p in scope.rglob("*.rs") if p.is_file())
    scoped = sorted(set(incidental_inventory(scope)) | set(rust))
    assert all(p.resolve().is_relative_to(scope) for p in scoped), "Scope symlink escape."
    if not rust:
        c.fail("Empty inspection scope: no Rust files; no review performed.")
    files = {p for root in (*roots, scope) for p in incidental_inventory(root)}
    assert all(any(p.resolve().is_relative_to(r) for r in (*roots, scope)) for p in files)
    error = command(["uv", "--version"], repo)
    assert not error, "Install uv. " + error
    # Only actual Rust text and Cargo manifests are read for capability detection.
    # Output sizing never reads source lines or arbitrary repository binary contents.
    code = "\n".join(p.read_text(encoding="utf-8") for p in rust)
    cargo = sorted(p for p in files if p.name == "Cargo.toml" and p.is_file())
    manifests = [tomllib.loads(p.read_text(encoding="utf-8")) for p in cargo]
    patterns = dict(
        has_unsafe=r"\bunsafe\b",
        has_ffi=r"extern|cstr|c_|libc|bind|ffi|repr|cty|raw",
        has_concurrency=r"thread|sync|atomic|cell|static|map|shm|signal|ray|cross|"
        r"once|mem|parking",
        has_async=r"async|await|tokio|futures",
        has_packed_repr="packed",
        has_fs_io=r"path|fs::|file|options|exists|metadata|read_dir|read_to_string",
    )
    flags = {k: bool(re.search(v, code, re.I)) for k, v in patterns.items()}
    flags["has_async"] |= bool(re.search("tokio|async-std|futures", str(manifests)))
    meta = dict(
        threat_model=threat_model,
        severity_filter=severity_filter,
        **flags,
        finding_scope_root=str(scope),
        scope_subpath=str(scope.relative_to(repo)),
        context_roots=",".join(map(str, roots)),
        cargo_paths=list(map(str, cargo)),
        cargo_manifest="workspace"
        if any("workspace" in m for m in manifests)
        else "single-crate"
        if cargo
        else "absent",
        worker_model="inherited Calcifier worker role configuration",
        finding_slots_per_pass=finding_slots_per_pass,
        incidental_inventory_exclusions=sorted(INCIDENTAL_EXCLUSIONS),
        inventory_note=(
            "Exclusions affect incidental context enumeration only. Full Rust source scope "
            "and declared context remain available for semantic inspection."
        ),
    )
    body = c.agent(
        "worker",
        "Perform original Phase 3 in full using the complete declared source/context view. "
        "Skim existing README and build/manifest files after checking their presence. Return "
        "the context body with Purpose (1-3 sentences), Scope, Entry points, Trust boundaries, "
        "and Existing hardening. Findings remain limited to finding_scope_root. Prefix "
        "ABORT: for unsupported targets; ADVISORY: for kernel review. Incidental inventory "
        "exclusions do not narrow the semantic review scope. " + json.dumps(meta),
        working_directory=scope,
        readable_paths=(scope, *roots),
        required_capabilities=("commands",),
        output=str,
        timeout=3600,
    )
    assert body.strip() and not body.startswith("ABORT:"), body or "Missing codebase context."
    manifest = json.loads(c.resource("prompts/clusters/manifest.json").read_text(encoding="utf-8"))
    pins = {"prompts/clusters/manifest.json"}
    for cluster in manifest["clusters"]:
        pins.add(cluster["prompt"])
        pins.update(p["prompt"] for p in cluster["passes"] if "prompt" in p)
    plugin = c.ensure_directory("pinned")
    pin_directories = sorted({str(Path(rel).parent) for rel in pins})
    for directory in pin_directories:
        preflight_flat(
            plugin / directory,
            tuple(sorted(Path(rel).name for rel in pins if str(Path(rel).parent) == directory)),
        )
    for rel in sorted(pins):
        c.write_text(plugin / rel, c.resource(rel).read_text(encoding="utf-8"))
    names = (
        "plan.json",
        "context.md",
        "tasks.json",
        "REPORT.md",
        "REPORT.sarif",
        "run-summary.md",
        "findings-index.txt",
        "dedup-summary.md",
        "fp-summary.md",
    )
    out = c.ensure_directory("run", output_files=names)
    for directory, extension in (
        ("worker-prompts", "txt"),
        ("coverage", "md"),
        ("findings-index.d", "txt"),
    ):
        preflight_flat(
            out / directory,
            tuple(f"worker-{n}.{extension}" for n in range(1, 70)),
        )
    preflight_flat(
        out / "receipts",
        tuple(f"worker-{n}-attempt-{attempt}.json" for n in range(1, 70) for attempt in (1, 2)),
    )
    c.ensure_directory(out / "findings")
    c.write_text(
        out / "context.md",
        "---\n"
        + "\n".join(f"{k}: {json.dumps(v)}" for k, v in meta.items())
        + f"\noutput_dir: {json.dumps(str(out))}\n---\n\n"
        + body,
    )
    prefix = ["uv", "run", "--no-project", "python", "-B"]
    plan_args = [
        *prefix,
        str(c.resource("scripts/build_run_plan.py")),
        "--plugin-root",
        str(plugin),
        "--output-dir",
        str(out),
        "--threat-model",
        threat_model,
        "--severity-filter",
        severity_filter,
        "--scope-subpath",
        str(scope),
        "--context-roots",
        ",".join(map(str, roots)),
        "--max-passes-per-worker",
        "4",
        "--cache-primer",
        "false",
    ]
    for k, v in flags.items():
        plan_args.extend(["--" + k.replace("_", "-"), str(v).lower()])
    error = command(plan_args, repo, mutating=True)
    assert not error, error
    workers = json.loads((out / "plan.json").read_text(encoding="utf-8"))["workers"]
    assert 0 < len(workers) <= 69, "Invalid planner worker count."
    worker_slots = [
        [
            tuple(
                out / "findings" / f"{pass_prefix}-{n + 1:03d}.md"
                for n in range(finding_slots_per_pass)
            )
            for pass_prefix in w["pass_prefixes"]
        ]
        for w in workers
    ]
    # All possible finding destinations come from the trusted explicit slot bound.
    # Each preflight receives at most 256 distinct flat filenames. Complete every
    # batch before workers or persistence can produce a finding file.
    preflight_flat(
        out / "findings",
        tuple(
            destination.name
            for assignment_slots in worker_slots
            for pass_slots in assignment_slots
            for destination in pass_slots
        ),
    )
    receipt_paths = [
        tuple(
            out / "receipts" / f"worker-{w['worker_n']}-attempt-{attempt}.json"
            for attempt in (1, 2)
        )
        for w in workers
    ]
    fatal = False
    validations = [
        [
            *prefix,
            str(c.resource("scripts/validate_artifacts.py")),
            str(out / "plan.json"),
            "--worker",
            f"worker-{w['worker_n']}",
        ]
        for w in workers
    ]
    cleanups = [
        [
            [
                "find",
                str(out / "findings"),
                "-maxdepth",
                "1",
                "-type",
                "f",
                "-name",
                pass_prefix + "-*.md",
                "-delete",
            ]
            for pass_prefix in w["pass_prefixes"]
        ]
        for w in workers
    ]
    sarif_generator = c.resource("scripts/generate_sarif.py")
    sarif_args = [*prefix, str(sarif_generator), str(out)]
    tasks: list[dict] = [
        dict(
            kind="cluster",
            worker_n=w["worker_n"],
            cluster_id=w["cluster_id"],
            spawn_prompt_path=w["spawn_prompt_path"],
            pass_prefixes=w["pass_prefixes"],
            status="pending",
            attempt=1,
            error="",
            claimed=0,
            truncated=False,
            capacity_exceeded=False,
        )
        for w in workers
    ]
    c.write_json(out / "tasks.json", tasks)
    allowed = {str(p.relative_to(repo)) for p in scoped}
    accepted: dict[int, Reply] = {}

    def review(i: int) -> Reply:
        if tasks[i]["status"] == "completed" or tasks[i]["capacity_exceeded"]:
            return accepted[i]
        prompt = Path(workers[i]["spawn_prompt_path"]).read_text(encoding="utf-8")
        return consult(prompt, "agents/rust-review-worker.md", (scope, *roots, plugin))

    for attempt in range(1, 3):
        waves = (len(workers) + 15) // 16
        width = (len(workers) + waves - 1) // waves
        for start in range(0, len(workers), width):
            wave = list(range(start, min(start + width, len(workers))))
            replies = c.parallel(review, wave, max_workers=16)
            for position in range(len(wave)):
                i = wave[position]
                if tasks[i]["status"] == "completed" or tasks[i]["capacity_exceeded"]:
                    continue
                reply = replies[position]
                # Persist the ENTIRE returned Reply before checking capacity or schema.
                # Paths depend only on the original plan and bounded host attempt loop.
                receipt = receipt_paths[i][attempt - 1]
                c.write_json(receipt, reply.model_dump())
                c.verify_artifact(receipt)
                accepted.update({i: reply})
                overflow = exceeds_capacity(reply, worker_slots[i])
                error = save_worker(reply, workers[i], out, allowed, worker_slots[i])
                if not error:
                    error = command(validations[i], out)
                shard = out / "findings-index.d" / f"worker-{workers[i]['worker_n']}.txt"
                lines = shard.read_text(encoding="utf-8").splitlines() if shard.is_file() else []
                count = len(lines) if shard.is_file() else -1
                claim = sum(map(len, reply.findings))
                error = error or ("Claim/shard count mismatch" if count != claim else "")
                tasks[i].update(
                    shard_count=count,
                    coverage=f"coverage/worker-{workers[i]['worker_n']}.md",
                    status="incomplete" if overflow else "pending" if error else "completed",
                    attempt=attempt,
                    error=error,
                    needs_respawn=bool(error) and not overflow,
                    claimed=claim,
                    truncated=reply.truncated or any("NOT SEARCHED" in s for s in reply.seeds),
                    capacity_exceeded=overflow,
                    receipt=str(receipt),
                )
        c.write_json(out / "tasks.json", tasks)
        fatal = any(
            re.search("spawn prompt malformed|pre-work budget exceeded|TaskList", str(t["error"]))
            for t in tasks
        )
        if fatal:
            break
        if attempt == 1:
            for i in range(len(workers)):
                if tasks[i]["status"] != "completed" and not tasks[i]["capacity_exceeded"]:
                    for argv in cleanups[i]:
                        assert not command(argv, out, mutating=True), "Retry cleanup failed."
    paths = sorted(p for p in (out / "findings").glob("*.md") if p.is_file())
    assert all(p.resolve().parent == (out / "findings").resolve() for p in paths)
    c.write_text(out / "findings-index.txt", "".join(f"{p}\n" for p in paths))
    warnings = [body.splitlines()[0]] if body.startswith("ADVISORY:") else []
    warnings += [
        f"{workers[i]['spawn_prompt_path']}: {tasks[i]}"
        for i in range(len(workers))
        if tasks[i]["status"] != "completed" or tasks[i]["truncated"]
    ]
    recorded = {
        Path(v).name
        for p in (out / "findings-index.d").glob("*.txt")
        for v in p.read_text(encoding="utf-8").splitlines()
        if v.strip()
    }
    warnings += [f"Orphan retained: {p.name}" for p in paths if p.name not in recorded]
    if len(paths) != sum(t["claimed"] for t in tasks):
        warnings.append("Index/claim mismatch; complete worker replies remain in receipts/.")
    judges = []
    for kind in () if fatal else ("dedup", "fp"):
        task = f"output_dir: {out}\nsarif_generator_path: {sarif_generator}"
        task += "\nCanonical finding order:\n" + "\n".join(map(str, paths))
        previous = ""
        for _repair in range(2):
            judged = consult(
                task, f"agents/rust-review-{kind}-judge.md", (scope, *roots, out, plugin), previous
            )
            updates = judged.findings[0] if len(judged.findings) == 1 else []
            valid = bool(judged.summary.strip()) and len(updates) == len(paths)
            valid = valid and all(
                front(updates[i]).get("id") == paths[i].stem for i in range(len(paths))
            )
            if kind == "fp":
                valid = valid and all(
                    fm.get("fp_verdict")
                    in ("TRUE_POSITIVE", "LIKELY_TP", "LIKELY_FP", "FALSE_POSITIVE", "OUT_OF_SCOPE")
                    and fm.get("fp_rationale")
                    and (
                        fm["fp_verdict"] not in ("TRUE_POSITIVE", "LIKELY_TP")
                        or (
                            fm.get("severity") in ("CRITICAL", "HIGH", "MEDIUM", "LOW")
                            and fm.get("attack_vector") in ("Remote", "Local", "Both")
                            and fm.get("exploitability") in ("Reliable", "Difficult", "Theoretical")
                            and fm.get("severity_rationale")
                        )
                    )
                    for fm in map(front, updates)
                    if not fm.get("merged_into")
                )
            if judged.abort or valid:
                break
            previous = judged.model_dump_json()
        if judged.abort or not valid:
            warnings.append(f"{kind} failed: {judged.abort or 'malformed completion'}")
            break
        for i in range(len(paths)):
            c.write_text(paths[i], updates[i])
        c.write_text(out / f"{kind}-summary.md", judged.summary)
        c.verify_artifact(out / f"{kind}-summary.md")
        if kind == "fp" and judged.report.strip():
            c.write_text(out / "REPORT.md", judged.report)
        judges.append(kind)
    assert not command(sarif_args, out, mutating=True), "SARIF safety net failed."
    sarif = json.loads((out / "REPORT.sarif").read_text(encoding="utf-8"))["runs"][0]
    if sarif["invocations"][0]["properties"]["skipped_findings"]:
        warnings.append("DROPPED FINDINGS: " + json.dumps(sarif["invocations"][0]))
    texts = {p.stem: p.read_text(encoding="utf-8") for p in paths}
    for text in texts.values():
        fm = front(text)
        if not fm.get("merged_into") and (
            not fm.get("fp_verdict")
            or not fm.get("fp_rationale")
            or (
                fm.get("fp_verdict") in ("TRUE_POSITIVE", "LIKELY_TP")
                and any(
                    not fm.get(k)
                    for k in ("severity", "attack_vector", "exploitability", "severity_rationale")
                )
            )
        ):
            warnings.append("Incomplete primary judgment: " + fm.get("id", "missing identity"))
    if not (out / "REPORT.md").is_file():
        items = sarif["results"]
        levels = ("CRITICAL", "HIGH", "MEDIUM", "LOW", "Unvalidated (severity not judged)")
        groups = [
            (
                item["properties"]["severity"]
                if item["properties"]["severity_validated"]
                else levels[-1],
                item,
            )
            for item in items
        ]
        primary_count = sum(not front(t).get("merged_into") for t in texts.values())
        report = [
            f"---\nstage: final-report\nthreat_model: {threat_model}\n"
            f"severity_filter: {severity_filter}\ntotal_primaries: {primary_count}\n"
            f"reported_findings: {len(items)}\n---",
            "# Rust Security Review — Final Report",
            f"**Threat Model:** {threat_model}\n\n**Severity Filter:** {severity_filter}\n\n"
            f"**Primaries (after dedup):** {primary_count}\n\n**Reported:** {len(items)}",
            "## Severity distribution (reported)\n\n| Severity | Count |\n|---|---|",
        ]
        report += [f"| {level} | {sum(g == level for g, _ in groups)} |" for level in levels]
        report += [
            f"## {group}: {item['message']['text']}\n\n"
            + (
                f"[Finding](findings/{item['properties']['finding_id']}.md)"
                if group in ("MEDIUM", "LOW")
                else texts.get(
                    item["properties"]["finding_id"],
                    "Finding content unavailable; see run-summary.md.",
                )
            )
            for group, item in sorted(groups, key=lambda pair: levels.index(pair[0]))
        ]
        report += [
            "## Scope notes\n\nThis report was synthesized by the orchestrator. "
            "See run-summary.md for incomplete workers, coverage, and judgment status.",
            "## Artifacts\n\n- findings/\n- receipts/\n- findings-index.txt\n- run-summary.md\n"
            "- dedup-summary.md\n- fp-summary.md\n- REPORT.md\n- REPORT.sarif",
        ]
        c.write_text(out / "REPORT.md", "\n\n".join(report))
        warnings.append("REPORT.md was orchestrator-synthesized, not judge-authored.")
    failed = sum(t["status"] != "completed" for t in tasks)
    summary = dict(
        parameters=meta,
        workers=workers,
        outcomes=tasks,
        judges=judges,
        context=body,
        index_count=len(paths),
        claimed_count=sum(t["claimed"] for t in tasks),
        failed_workers=failed,
        sarif_status="generated by supplied helper",
        report_status="present",
        warnings=warnings,
    )
    table = "| Worker | Cluster | Outcome |\n|---|---|---|\n" + "\n".join(
        f"| {workers[i]['worker_n']} | {workers[i]['cluster_id']} | {json.dumps(tasks[i])} |"
        for i in range(len(workers))
    )
    c.write_text(
        out / "run-summary.md",
        "# Run summary\n\n"
        + ("**PARTIAL RUN**\n\n" if warnings else "")
        + "\n".join(warnings)
        + "\n\n"
        + table
        + "\n\n"
        + json.dumps(summary, indent=2),
    )
    for name in ("REPORT.md", "REPORT.sarif", "run-summary.md", "findings-index.txt"):
        c.verify_artifact(out / name, nonempty=name != "findings-index.txt")
    report_content = (out / "REPORT.md").read_text(encoding="utf-8")
    final_content = report_content
    if warnings:
        final_content = "**PARTIAL RUN**\n\n" + "\n".join(warnings) + "\n\n" + report_content
    final_content += "\n\nArtifacts:\n" + "\n".join(
        f"- {out / name}"
        for name in (
            "findings",
            "receipts",
            "findings-index.txt",
            "run-summary.md",
            "dedup-summary.md",
            "fp-summary.md",
            "REPORT.md",
            "REPORT.sarif",
        )
    )
    return c.emit(
        dict(
            report=final_content,
            summary=summary,
            status="partial" if warnings else "complete",
            warnings=warnings,
            artifacts=[str(out / n) for n in ("findings", "receipts", *names)],
        ),
        name="report",
    )


if __name__ == "__main__":
    raise SystemExit(rust_review.cli())


# --- calcifier metadata (skill provenance + sha256) ---
_CALCIFIER_COMPILATION = "compiled"
_CALCIFIER_SKILL = {
    "path": "../SKILL.md",
    "sha256": ("52ee8b08876b0ad90ecdf4a58de8d41fb2d8627f1e4d259a806a35a6e187ae91"),
}
_CALCIFIER_RESOURCES = [
    {
        "path": "agents/rust-review-dedup-judge.md",
        "sha256": ("23f09a5af3c3cc5f350bfa937a368c10ae931dad1077ca7e7099e83170b5ed47"),
        "size": 20862,
        "source": "../../agents/rust-review-dedup-judge.md",
    },
    {
        "path": "agents/rust-review-fp-judge.md",
        "sha256": ("ebb25be71a2f7d078e6c9a79be7ad6481d81423c7bc21d1dce061f04321175b8"),
        "size": 23654,
        "source": "../../agents/rust-review-fp-judge.md",
    },
    {
        "path": "agents/rust-review-worker.md",
        "sha256": ("ee116cafa60d1b64df641793b5e7c0df909a31a94e5e953db31d9a3a578c688e"),
        "size": 32587,
        "source": "../../agents/rust-review-worker.md",
    },
    {
        "path": "prompts/clusters/async-runtime.md",
        "sha256": ("5c1e493b1317217574cc27d45159775c2cfa3fa25090b9f9f737b525bfcc8369"),
        "size": 855,
        "source": "../../prompts/clusters/async-runtime.md",
    },
    {
        "path": "prompts/clusters/concurrency-data-race.md",
        "sha256": ("344fdfe042ea014f920215589fa603f5e85a5056e4f8a79f49b191627f87e0d6"),
        "size": 2632,
        "source": ("../../prompts/clusters/concurrency-data-race.md"),
    },
    {
        "path": "prompts/clusters/concurrency-locking.md",
        "sha256": ("a1c771a6dc73df18d244363f051ff37e54153e1bef848f130e30a3a14f456080"),
        "size": 7072,
        "source": "../../prompts/clusters/concurrency-locking.md",
    },
    {
        "path": "prompts/clusters/error-handling.md",
        "sha256": ("fcc8d9b999a17ced9c54e1aafa9071238a7e66538d453937196b8ebc4694b58b"),
        "size": 1597,
        "source": "../../prompts/clusters/error-handling.md",
    },
    {
        "path": "prompts/clusters/ffi-cross-language.md",
        "sha256": ("5f1d2184a34f6d000a6e18c695c82e2607d0dd56e6a6d9380bfe5c2df4c5280b"),
        "size": 3401,
        "source": "../../prompts/clusters/ffi-cross-language.md",
    },
    {
        "path": "prompts/clusters/info-disclosure.md",
        "sha256": ("5a1c23addc4cc12ff164f98ba34678be6c9b63cf9b7987f21dedc9a43b27f52f"),
        "size": 562,
        "source": "../../prompts/clusters/info-disclosure.md",
    },
    {
        "path": "prompts/clusters/input-os-safety.md",
        "sha256": ("aa00fa03182c2c1117c3340a5d7c578b256b2be2ef376ef71840c1c3e18c35ea"),
        "size": 1082,
        "source": "../../prompts/clusters/input-os-safety.md",
    },
    {
        "path": "prompts/clusters/layout-safety.md",
        "sha256": ("c25e2582b9302c7de66d695f634ccb618d30fbf874661b88f0f80915eedbc127"),
        "size": 572,
        "source": "../../prompts/clusters/layout-safety.md",
    },
    {
        "path": "prompts/clusters/logic-correctness.md",
        "sha256": ("e18dd1a9fd4d33d00399ec1ed5af05071b469095aaa6d27b4ea2455f678b4a0e"),
        "size": 3884,
        "source": "../../prompts/clusters/logic-correctness.md",
    },
    {
        "path": "prompts/clusters/manifest.json",
        "sha256": ("76dbca40fa7a46df81d8af6eda3a0e66229c7277e254e86c7ab95bba0b8eb1cd"),
        "size": 11150,
        "source": "../../prompts/clusters/manifest.json",
    },
    {
        "path": "prompts/clusters/memory-safety.md",
        "sha256": ("24a788bd692e90870265addec88f05707bf88c422cbca097785702521eb09195"),
        "size": 4663,
        "source": "../../prompts/clusters/memory-safety.md",
    },
    {
        "path": "prompts/clusters/panic-dos.md",
        "sha256": ("bc0a365f423bdde596834f995a6a1c003fad568d52d5e9509b98d8f0a3e38d9f"),
        "size": 6143,
        "source": "../../prompts/clusters/panic-dos.md",
    },
    {
        "path": "prompts/clusters/recursion-dos.md",
        "sha256": ("4de2aec45f196b36584226fd70b56a82df1b6d75b33056d46ae8e2c292022947"),
        "size": 5425,
        "source": "../../prompts/clusters/recursion-dos.md",
    },
    {
        "path": "prompts/clusters/resource-handling.md",
        "sha256": ("5b5702c57166f9f8cb183f7602702baf16a0a20821bf8ba1efd911a64df1aa84"),
        "size": 1519,
        "source": "../../prompts/clusters/resource-handling.md",
    },
    {
        "path": "prompts/clusters/static-hygiene.md",
        "sha256": ("d9045ccb6e90f64273845c43d6b9b79bf77df2e520b2ac2714de890cc467e90a"),
        "size": 746,
        "source": "../../prompts/clusters/static-hygiene.md",
    },
    {
        "path": "prompts/clusters/unsafe-boundary.md",
        "sha256": ("10f7dabee93a1ff0b9229ba7e23c5b0900da64825d2b3d186ffcc297f6da4dfd"),
        "size": 15998,
        "source": "../../prompts/clusters/unsafe-boundary.md",
    },
    {
        "path": "prompts/general/abi-mismatch-finder.md",
        "sha256": ("235bbd82a8794e6a2b8d5c360811a362a5927ca1d417a8508e4e0abba9fb04ee"),
        "size": 705,
        "source": "../../prompts/general/abi-mismatch-finder.md",
    },
    {
        "path": "prompts/general/adversarial-trait-finder.md",
        "sha256": ("7cd0587f25560c80bca17767931ca3cbd833dbc6a7b352c82a1d54ebdfe63e16"),
        "size": 1558,
        "source": ("../../prompts/general/adversarial-trait-finder.md"),
    },
    {
        "path": "prompts/general/arithmetic-overflow-finder.md",
        "sha256": ("f2a1fb7fc32898a7f54c4da1467db149bce55e6d4b1d2ee08e01648862b63488"),
        "size": 2187,
        "source": ("../../prompts/general/arithmetic-overflow-finder.md"),
    },
    {
        "path": "prompts/general/assertion-reachable-finder.md",
        "sha256": ("9bab8d87093e4dabf3461d9575dd23fc66c3f83949eafd5e30b9fab94bd7dc30"),
        "size": 879,
        "source": ("../../prompts/general/assertion-reachable-finder.md"),
    },
    {
        "path": "prompts/general/async-blocking-finder.md",
        "sha256": ("05cd757a948d102fdd547874d8267167ca0895d393119f9af6fc3a08167b48d1"),
        "size": 1236,
        "source": "../../prompts/general/async-blocking-finder.md",
    },
    {
        "path": "prompts/general/atomic-race-finder.md",
        "sha256": ("3128365d7e44adf4b69058b77bb63432648cbc9adb10e8b6d4a902da25ce54e1"),
        "size": 1292,
        "source": "../../prompts/general/atomic-race-finder.md",
    },
    {
        "path": ("prompts/general/buffer-overflow-unsafe-finder.md"),
        "sha256": ("13c538ed4dbc0535a0fbef691f4c79fe538ed9d675af0c88ff6d48594ff08570"),
        "size": 2701,
        "source": ("../../prompts/general/buffer-overflow-unsafe-finder.md"),
    },
    {
        "path": "prompts/general/bufwriter-unflushed-finder.md",
        "sha256": ("d6bb277a0ea6575862b6620f7820c425f4321dc9d8f7d7627b026f01d169517c"),
        "size": 995,
        "source": ("../../prompts/general/bufwriter-unflushed-finder.md"),
    },
    {
        "path": "prompts/general/cancel-safety-finder.md",
        "sha256": ("75fea515a1e818c90ec1ff024b7e3d595e4247fb8a9f6c5b2004baa56bc3c51c"),
        "size": 1227,
        "source": "../../prompts/general/cancel-safety-finder.md",
    },
    {
        "path": "prompts/general/cargo-lint-config-finder.md",
        "sha256": ("ae2eddc58db7394b212ac8b7b8cc38a2a94138a5cc932f073ce7beb639b1036a"),
        "size": 2502,
        "source": ("../../prompts/general/cargo-lint-config-finder.md"),
    },
    {
        "path": "prompts/general/closure-ffi-finder.md",
        "sha256": ("e02de116960cd52bc81074e11a522ace6ab70fa4773fe9235c86d85154f7f36a"),
        "size": 3991,
        "source": "../../prompts/general/closure-ffi-finder.md",
    },
    {
        "path": "prompts/general/closure-panic-finder.md",
        "sha256": ("9ec22b968985aa82e068996107bb2027eaf7aadb4ae135f5871ed562984a750b"),
        "size": 1091,
        "source": "../../prompts/general/closure-panic-finder.md",
    },
    {
        "path": ("prompts/general/collection-key-mutation-finder.md"),
        "sha256": ("ade9461584d12c45fa434bfd55a83e974dbef1e8315a133dc08bccfcf12d0089"),
        "size": 1935,
        "source": ("../../prompts/general/collection-key-mutation-finder.md"),
    },
    {
        "path": "prompts/general/cstring-dangling-finder.md",
        "sha256": ("3bbd4e310ad0fac5303729f5d693eaba4ffee77aa32dd408877412c0e002b26c"),
        "size": 1368,
        "source": ("../../prompts/general/cstring-dangling-finder.md"),
    },
    {
        "path": "prompts/general/deprecated-api-finder.md",
        "sha256": ("2356c3a229d51939bb377c2d1ce32fd1df4959411c679c62fb1199fff01ec63a"),
        "size": 1968,
        "source": "../../prompts/general/deprecated-api-finder.md",
    },
    {
        "path": "prompts/general/destructor-skip-finder.md",
        "sha256": ("258025c6150e5f4edda8669743bcb556ea50c87b070b5221032b0b7630f03b8c"),
        "size": 1406,
        "source": ("../../prompts/general/destructor-skip-finder.md"),
    },
    {
        "path": "prompts/general/double-free-finder.md",
        "sha256": ("c6b15798988e9a05bd03ff49ee27cd180224c44545b91b2dd53d9db580b701a3"),
        "size": 1685,
        "source": "../../prompts/general/double-free-finder.md",
    },
    {
        "path": "prompts/general/drop-panic-finder.md",
        "sha256": ("b37e62548f486406183b2ecfd395b1f070954ada3c7499bf65f76718e0d85968"),
        "size": 973,
        "source": "../../prompts/general/drop-panic-finder.md",
    },
    {
        "path": "prompts/general/dyn-trait-ffi-finder.md",
        "sha256": ("73dc05f43283ff438052a142a78a8bb9da18b5946ae4bbf87c07f27e5b162f56"),
        "size": 2849,
        "source": "../../prompts/general/dyn-trait-ffi-finder.md",
    },
    {
        "path": "prompts/general/float-edge-finder.md",
        "sha256": ("c4dc578ae38787a5bc54544a9c876a7a80e3d9a0bdcec8bb239a5c6dc8790e58"),
        "size": 798,
        "source": "../../prompts/general/float-edge-finder.md",
    },
    {
        "path": "prompts/general/foreign-drop-finder.md",
        "sha256": ("76a52b3ed8077443e8ead91faaa1c5b7e4bafab7c68e6504a081899ad683dfac"),
        "size": 2803,
        "source": "../../prompts/general/foreign-drop-finder.md",
    },
    {
        "path": "prompts/general/invalid-free-finder.md",
        "sha256": ("ee7faafdb62f1cd5c696b1e2afa7bfc42078fd47121af55ab2e14004006e1ffd"),
        "size": 1185,
        "source": "../../prompts/general/invalid-free-finder.md",
    },
    {
        "path": "prompts/general/lossy-from-into-finder.md",
        "sha256": ("104ff498f652f9fdf4d2798dfebb092dc380b708df2ea97e9960f65d8d308b75"),
        "size": 603,
        "source": ("../../prompts/general/lossy-from-into-finder.md"),
    },
    {
        "path": "prompts/general/lossy-str-conversion-finder.md",
        "sha256": ("3b7e787ee0dec3651af699293258e5997d468bc0fdf55fa8314cb6ead9903fa3"),
        "size": 1240,
        "source": ("../../prompts/general/lossy-str-conversion-finder.md"),
    },
    {
        "path": "prompts/general/msrv-mismatch-finder.md",
        "sha256": ("61663658007d08e2ef2911a096b54d837e829badf4ac92d688fb01c459d9e5d1"),
        "size": 401,
        "source": "../../prompts/general/msrv-mismatch-finder.md",
    },
    {
        "path": "prompts/general/nondeterminism-finder.md",
        "sha256": ("dad119c84180920e4258e493d969a9598f7b8aaa22b7bd2a44437ddb5fd7e5eb"),
        "size": 1657,
        "source": "../../prompts/general/nondeterminism-finder.md",
    },
    {
        "path": "prompts/general/opaque-pointer-finder.md",
        "sha256": ("3469427249df12d83b82ff90b3d72837d8d4c215e98d4d35f2d35f2a197d4d40"),
        "size": 1948,
        "source": "../../prompts/general/opaque-pointer-finder.md",
    },
    {
        "path": "prompts/general/ord-eq-hash-finder.md",
        "sha256": ("58055286593db6ad08917709582f3cef6da17fd01793182abc567b4bb67a627f"),
        "size": 754,
        "source": "../../prompts/general/ord-eq-hash-finder.md",
    },
    {
        "path": "prompts/general/out-of-bounds-index-finder.md",
        "sha256": ("8629f653d73e0e267e2ba548a3c88295efe03793f5853473dda2b0cfbe42845d"),
        "size": 727,
        "source": ("../../prompts/general/out-of-bounds-index-finder.md"),
    },
    {
        "path": "prompts/general/packed-field-ref-finder.md",
        "sha256": ("eb28bd82060275326b718a4839e252345fd4ed86dcb828f28c5e039fa9e16f37"),
        "size": 3776,
        "source": ("../../prompts/general/packed-field-ref-finder.md"),
    },
    {
        "path": "prompts/general/panic-unwind-unsafe-finder.md",
        "sha256": ("30a82a7d83ee1cbea971a2d87f6e996db077c48fc1e6b1afbed3c27dd3d26459"),
        "size": 3031,
        "source": ("../../prompts/general/panic-unwind-unsafe-finder.md"),
    },
    {
        "path": "prompts/general/path-traversal-join-finder.md",
        "sha256": ("13c8e5ad1330baa012cf7014d386e61e243a0f31fa42bab498ffb4838116c934"),
        "size": 1768,
        "source": ("../../prompts/general/path-traversal-join-finder.md"),
    },
    {
        "path": "prompts/general/pointer-exposure-finder.md",
        "sha256": ("e5dda8d39ec41c1d83be1de783e5c1f379913aa6467dbaba8353f8bcd7ff3e18"),
        "size": 1878,
        "source": ("../../prompts/general/pointer-exposure-finder.md"),
    },
    {
        "path": "prompts/general/raw-fd-lifecycle-finder.md",
        "sha256": ("f4e485de5943cfb1128bc7a1bdd6bb23bef4c422bfbd63b2c5229a95bd4befcd"),
        "size": 2024,
        "source": ("../../prompts/general/raw-fd-lifecycle-finder.md"),
    },
    {
        "path": ("prompts/general/recursive-deserialize-stack-overflow-finder.md"),
        "sha256": ("0f16fbc717bf048c5adbe23bbe2c056993becec796e8ec36325e6fd75ef44c5c"),
        "size": 4945,
        "source": ("../../prompts/general/recursive-deserialize-stack-overflow-finder.md"),
    },
    {
        "path": ("prompts/general/recursive-drop-stack-overflow-finder.md"),
        "sha256": ("212ccf950aa2bd0b91950179c4d7e5d42ad7eb4a2707950ff9112017f43575b0"),
        "size": 2757,
        "source": ("../../prompts/general/recursive-drop-stack-overflow-finder.md"),
    },
    {
        "path": ("prompts/general/recursive-format-stack-overflow-finder.md"),
        "sha256": ("085f4241ffa49123f1be72a9b26fab67b231ee20c90fa402e66fc3a113bfae46"),
        "size": 4248,
        "source": ("../../prompts/general/recursive-format-stack-overflow-finder.md"),
    },
    {
        "path": "prompts/general/refcell-borrow-panic-finder.md",
        "sha256": ("119970e1ef75547d54d76e1bb7251b83e189621e2aa817f0f5b47cede8c81414"),
        "size": 1213,
        "source": ("../../prompts/general/refcell-borrow-panic-finder.md"),
    },
    {
        "path": "prompts/general/repr-c-padding-finder.md",
        "sha256": ("31d73bff27df552ef2d8e4d9d1b203757f128ca818823ea4363f184f86995667"),
        "size": 2235,
        "source": "../../prompts/general/repr-c-padding-finder.md",
    },
    {
        "path": "prompts/general/resource-exhaustion-finder.md",
        "sha256": ("d8a169f355cfa18d30177bb19171190c290890d51af8ebde996767c1e07098f5"),
        "size": 2506,
        "source": ("../../prompts/general/resource-exhaustion-finder.md"),
    },
    {
        "path": "prompts/general/result-discarded-finder.md",
        "sha256": ("99fbad8883f690e690c6509008e1acd7654b5b98f087b896bae4082b7d14c79b"),
        "size": 1601,
        "source": ("../../prompts/general/result-discarded-finder.md"),
    },
    {
        "path": "prompts/general/select-bias-finder.md",
        "sha256": ("24c1284014a89c74327b0dc123b6c5ec0a9bf57bd0971f883ec51426ac69dfb5"),
        "size": 1278,
        "source": "../../prompts/general/select-bias-finder.md",
    },
    {
        "path": "prompts/general/send-sync-bounds-finder.md",
        "sha256": ("8f27a590734113e7094f45f2b71d115e807e9eb35d33fe8de2883c403e7957f4"),
        "size": 2639,
        "source": ("../../prompts/general/send-sync-bounds-finder.md"),
    },
    {
        "path": ("prompts/general/serialize-struct-mismatch-finder.md"),
        "sha256": ("3a4f25ef4afa7a676016fe0b1631b5b1a41c53a532a4ed5e6128f5807f52ac1e"),
        "size": 2324,
        "source": ("../../prompts/general/serialize-struct-mismatch-finder.md"),
    },
    {
        "path": "prompts/general/shared-memory-race-finder.md",
        "sha256": ("400c82d7872b1e848daadd6fe3fc4834397198b6340777dbbf57cfd28a5f7daf"),
        "size": 2867,
        "source": ("../../prompts/general/shared-memory-race-finder.md"),
    },
    {
        "path": "prompts/general/static-mut-race-finder.md",
        "sha256": ("dc3edd55cad150f52c6f1a2e5ccffc1d1224d831766ba9ec952e76128bc7b9d8"),
        "size": 2887,
        "source": ("../../prompts/general/static-mut-race-finder.md"),
    },
    {
        "path": "prompts/general/str-slice-boundary-finder.md",
        "sha256": ("870e5114e4d318e7cdaccf96315d67d8b3e3fafab01f497ab74d4e40dc72d4a9"),
        "size": 1068,
        "source": ("../../prompts/general/str-slice-boundary-finder.md"),
    },
    {
        "path": "prompts/general/string-comparison-finder.md",
        "sha256": ("bc7ec9e43749b367c4aeb88c60a8fd5139b37b98a72d1faf66f47a9d0525f548"),
        "size": 1394,
        "source": ("../../prompts/general/string-comparison-finder.md"),
    },
    {
        "path": "prompts/general/toctou-finder.md",
        "sha256": ("87917e3b47b0f2c6ee83af499144dabca50bd91e7a87f63963c301582457e09f"),
        "size": 1316,
        "source": "../../prompts/general/toctou-finder.md",
    },
    {
        "path": "prompts/general/uninitialized-read-finder.md",
        "sha256": ("591021ed80c16ab7e4b4552b90773b508e68cbc4aaf124f1c64a823c308623fe"),
        "size": 1884,
        "source": ("../../prompts/general/uninitialized-read-finder.md"),
    },
    {
        "path": "prompts/general/union-ub-finder.md",
        "sha256": ("be8259632d1bd20dff2cc53c3fbedd48358fab381d64abef0cb0f2feee0bd9c1"),
        "size": 3541,
        "source": "../../prompts/general/union-ub-finder.md",
    },
    {
        "path": "prompts/general/unsafe-sync-impl-finder.md",
        "sha256": ("88f21b78fc146827e10ddfe823ed34057aaaedcd834141cb1ef10f1c3c4d3d65"),
        "size": 3803,
        "source": ("../../prompts/general/unsafe-sync-impl-finder.md"),
    },
    {
        "path": "prompts/general/unwrap-on-untrusted-finder.md",
        "sha256": ("49fd0889307a1ab13c32ef654f2541d1424500ebb5d50db231feede71f2cb8b7"),
        "size": 1303,
        "source": ("../../prompts/general/unwrap-on-untrusted-finder.md"),
    },
    {
        "path": "prompts/general/use-after-free-finder.md",
        "sha256": ("8a8237880088a98a3b49c402672809431cda66f6e03fb0e98f84e7a96faf4bda"),
        "size": 2963,
        "source": "../../prompts/general/use-after-free-finder.md",
    },
    {
        "path": "prompts/general/vec-set-len-uninit-finder.md",
        "sha256": ("b641f302ec14455aeb2a1fcfaeae4986d2b0a91fd26966e1228786d3932f2195"),
        "size": 2551,
        "source": ("../../prompts/general/vec-set-len-uninit-finder.md"),
    },
    {
        "path": "scripts/build_run_plan.py",
        "sha256": ("2fa42b567741e6735d2e1099561dae9cde5c631ea7408bc84bc1aaac74d3f782"),
        "size": 24572,
        "source": "../../scripts/build_run_plan.py",
    },
    {
        "path": "scripts/generate_sarif.py",
        "sha256": ("0cfd2f1f0ff6927f64bbe0be2c75cf84954602d49cb338a15c4908b841373fe8"),
        "size": 23499,
        "source": "../../scripts/generate_sarif.py",
    },
    {
        "path": "scripts/validate_artifacts.py",
        "sha256": ("f373bc7dafabd027afe0fd825169440736c7425c559b7bf4a8779e9ec3ace658"),
        "size": 11677,
        "source": "../../scripts/validate_artifacts.py",
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
        "ed inspection that finds zero issues.\n\nFocused native Ru"
        "st-review repair. Preserve the supplied complete candidate"
        "'s original deterministic run-plan generation, worker/task"
        " assignment, cluster and multi-pass prompts, per-worker fi"
        "ndings ledger, independent false-positive/severity judgeme"
        "nt stages, deduplication, exact final Markdown/SARIF gener"
        "ation, nonempty Rust-source inspection guard, failed-worke"
        "r/incomplete coverage accounting and validation. The exact"
        " original packaged workflow, ALL70prompt resources and3hel"
        'pers are supplied in full below. Use resource("scripts/bui'
        'ld_run_plan.py"), resource("scripts/validate_artifacts.py"'
        ') and resource("scripts/generate_sarif.py") for helper com'
        "mands; NEVER use a user input or filesystem Path join to l"
        "ocate these packaged resources. Host filesystem locations "
        "and command args must derive only from trusted recipe inpu"
        "t, original deterministic run-plan helper results, and act"
        "ual host directory/file enumeration. A model can select a "
        "conditional branch among host-enumerated candidate records"
        ", but never supply filenames, IDs, path indexes or argv va"
        "lues. Persist model content into fixed host-selected outpu"
        "t paths. If an assignment associates model content with a "
        "dict entry, avoid computed subscript assignments containin"
        "g built-in names: published0.2taint incorrectly taints all"
        " ast.Name under a target such as data[str(root)]=model_ans"
        "wer. Equivalent data.update({str(root):model_answer}) corr"
        "ectly keeps the CONTENT tainted without corrupting the tru"
        "sted selector/built-in str (upstream calcifier issue22). D"
        "o not weaken or bypass validation. Keep native agent/paral"
        "lel/run_command/filesystem APIs only; no Task/Workflow/Ski"
        "ll/Agent/AskUserQuestion platform adapters and no generic "
        "baseline/preflight-only stub. Retain source FP-review stag"
        "e (this Rust skill intentionally includes it). Return a fu"
        "ll syntactically complete module, may exceed250lines. Ruff"
        " E,F,I,UP,B,SIM targetpy311 maxline100, PEP723Python>=3.13"
        " calcifier==0.2.0. Fresh provenance belongs to host, do no"
        "t copy _CALCIFIER_* constants.\n\n\nThe complete native ca"
        "ndidate is accepted by static gates but root review found "
        "a blocking real-project performance problem. It computes s"
        "lot_count from ALL scoped repository files (including bina"
        "ries/.git/build contents), allocates every source-line xev"
        "erypass possible finding Path, then passes the entire huge"
        " Cartesian set to one ensure_directory. Published0.2prefli"
        "ght does O(N squared) overlap checks: this becomes million"
        "s of paths and cannot run on a normal Rust codebase. Repai"
        "r only these mechanics while preserving the full original "
        "native review/dedup/FP/severity/report flow and helpers. A"
        "dd an explicit positive TRUSTED recipe input finding_slots"
        "_per_pass (reasonable default64), make all host finding sl"
        "ots derive from this bounded input rather than source-line"
        " counts, and preflight all possible outputs in bounded dis"
        "joint flat chunks of at most256 paths before external writ"
        "es. Exclude .git/build/cache directories from incidental s"
        "cope inventory (never narrow semantic source scope silentl"
        "y); do not read arbitrary binary repository contents merel"
        "y to size outputs. Retain all actually returned findings a"
        "nd no silent truncation: persist each complete worker Repl"
        "y as a fixed host-named JSON receipt before validating slo"
        "t capacity; if a pass exceeds capacity mark the worker/run"
        " incomplete with an explicit instruction to increase findi"
        "ng_slots_per_pass. Never ask a worker to drop findings to "
        "fit. Keep real finding Markdown and original validation/in"
        "dex/coverage semantics. Separate runtime provider model se"
        'lection from platform model brands: allow worker_model="in'
        'herit" and use the actually configured Calcifier worker ro'
        "le without requiring a false haiku/sonnet/opus attestation"
        " against the default Codex provider. Remove configured_wor"
        "ker_model or clearly support inherit with default inherit;"
        " non-inherit brand choices must fail with a precise instru"
        "ction to configure the runtime role and use inherit, as th"
        "e sibling c-review native recipe does. Report the model se"
        "lection honestly as inherited configuration; do not assert"
        " a brand you cannot verify. All path/command selectors rem"
        "ain trusted host values; model output is content only. No "
        "Task/Workflow/Ask/Agent platform adapters. Keep full origi"
        "nal reasoning/prompts/independent judgement/report artifac"
        "t validation and all fixes from prior candidate. No baseli"
        "ne or stub. Fresh provenance host-owned. Ruff100 E,F,I,UP,"
        "B,SIM.\n"
    ),
    "sha256": ("dce3cf14028cce954128d3bd951f8e7580348d6033b88351d92270600ac491d5"),
}
_CALCIFIER_SUBRECIPES = []
