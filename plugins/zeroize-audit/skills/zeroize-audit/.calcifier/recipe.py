# /// script
# requires-python = ">=3.13"
# dependencies = ["calcifier==0.2.0"]
# ///

import hashlib
import json
import re
from datetime import UTC, datetime
from pathlib import Path
from time import monotonic
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
    tool,
    write_json,
)

COMMON = [
    "prompts/system.md",
    "prompts/task.md",
    "schemas/input.json",
    "schemas/output.json",
    "configs/default.yaml",
    "configs/c.yaml",
    "configs/rust.yaml",
    "references/compile-commands.md",
    "references/detection-strategy.md",
    "references/ir-analysis.md",
    "references/mcp-analysis.md",
    "references/poc-generation.md",
    "references/rust-zeroization-patterns.md",
]
ROLES = [
    "0-preflight",
    "1-mcp-resolver",
    "2-source-analyzer",
    "2b-rust-source-analyzer",
    "3-tu-compiler-analyzer",
    "3b-rust-compiler-analyzer",
    "4-report-assembler",
    "5-poc-generator",
    "5b-poc-validator",
    "5c-poc-verifier",
    "6-test-generator",
]
PHASES = [
    "preflight",
    "source-analysis",
    "compiler-analysis",
    "interim-report",
    "poc-generation",
    "poc-validation",
    "final-report",
    "test-generation",
]
PROGRAMS = [
    "extract_compile_flags.py",
    "emit_ir.sh",
    "emit_asm.sh",
    "emit_rust_mir.sh",
    "emit_rust_ir.sh",
    "emit_rust_asm.sh",
    "validate_rust_toolchain.sh",
    "generate_poc.py",
    "diff_rust_mir.sh",
    "mcp/check_mcp.sh",
    "mcp/normalize_mcp_evidence.py",
    "scripts/semantic_audit.py",
    "scripts/find_dangerous_apis.py",
    "scripts/check_mir_patterns.py",
    "scripts/check_llvm_patterns.py",
    "scripts/check_rust_asm.py",
    "scripts/check_rust_asm_x86.py",
    "scripts/check_rust_asm_aarch64.py",
]
CHECKS = {
    "target_variable_match",
    "target_function_match",
    "technique_appropriate",
    "optimization_level",
    "exit_code_interpretation",
    "result_plausibility",
}
CHECKPOINT = "pending-checkpoint.json"
HOST_OUTPUTS = (
    "poc/poc_validation_results.json",
    "poc/poc_verification.json",
    "poc/poc_final_results.json",
    CHECKPOINT,
)
Category = Literal[
    "MISSING_SOURCE_ZEROIZE",
    "PARTIAL_WIPE",
    "NOT_ON_ALL_PATHS",
    "SECRET_COPY",
    "INSECURE_HEAP_ALLOC",
    "OPTIMIZED_AWAY_ZEROIZE",
    "STACK_RETENTION",
    "REGISTER_SPILL",
    "MISSING_ON_ERROR_PATH",
    "NOT_DOMINATING_EXITS",
    "LOOP_UNROLLED_INCOMPLETE",
]


@output_type
class Review:
    finding_id: str
    checks: dict[str, Literal["pass", "fail", "warn"]]
    notes: str


@output_type
class VerificationDecision:
    finding_id: str
    evidence_digest: str
    action: Literal["accept", "reject"]


def read(path: Path) -> Any:
    if not path.is_file():
        fail(f"Required artifact missing: {path}")
    return json.loads(path.read_text(encoding="utf-8"))


def digest(value: Any) -> str:
    encoded = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return hashlib.sha256(encoded.encode("utf-8")).hexdigest()


def file_hashes(root: Path, *, repository: bool = False) -> dict[str, str]:
    result: dict[str, str] = {}
    for item in sorted(root.rglob("*")):
        relative = item.relative_to(root)
        if repository and ".git" in relative.parts:
            continue
        if not repository and ".git" in relative.parts:
            fail("Run artifacts must not contain Git metadata.")
        if item.is_symlink():
            fail(f"Cannot bind a checkpoint through a symlink: {item}")
        if item.is_dir():
            continue
        if not item.is_file():
            fail(f"Cannot checkpoint a nonregular file: {item}")
        if not repository and relative.as_posix() == CHECKPOINT:
            continue
        result[relative.as_posix()] = hashlib.sha256(item.read_bytes()).hexdigest()
    return result


def restore_artifacts(prior: Path, work: Path, hashes: dict[str, str], repo: Path) -> None:
    groups: dict[str, list[str]] = {}
    for relative in hashes:
        parent = Path(relative).parent.as_posix()
        groups.setdefault(parent, []).append(relative)
    for parent, relatives in sorted(groups.items()):
        destination = ensure_directory(
            "run" if parent == "." else "run/" + parent,
            output_files=tuple(Path(relative).name for relative in relatives),
            exclude_roots=(repo, prior),
        )
        copied = run_command(
            ["cp", *(str(prior / relative) for relative in relatives), str(destination)],
            timeout_seconds=120,
            working_directory=work,
        )
        if copied.exit_code:
            fail("Could not restore prior artifacts: " + copied.stderr)
    if file_hashes(work) != hashes:
        fail("Restored artifacts differ from the verified checkpoint.")


def poc_sources(work: Path, prior: Path | None) -> dict[str, str]:
    result: dict[str, str] = {}
    folder = work / "poc"
    for item in sorted(folder.rglob("*")):
        if item.is_file() and item.suffix in {".c", ".cc", ".cpp", ".cxx", ".rs", ".h"}:
            text = item.read_text(encoding="utf-8")
            result[item.relative_to(folder).as_posix()] = text
            result[str(item)] = text
            if prior is not None:
                result[str(prior / item.relative_to(work))] = text
    return result


@recipe(
    name="zeroize_audit",
    version="1",
    agents=("worker",),
    capabilities=(
        "Bash",
        "mcp__serena__activate_project",
        "mcp__serena__find_symbol",
        "mcp__serena__find_referencing_symbols",
        "mcp__serena__get_symbols_overview",
    ),
    budget=Budget(max_agent_calls=6, max_wall_seconds=3600),
    output_root="zeroize-audit",
)
def zeroize_audit(
    path: str,
    compile_db: str | None = None,
    cargo_manifest: str | None = None,
    config: str | None = None,
    max_tus: int = 50,
    languages: tuple[Literal["c", "cpp", "rust"], ...] = ("c", "cpp", "rust"),
    opt_levels: tuple[Literal["O0", "O1", "O2", "O3", "Os", "Oz"], ...] = ("O0", "O1", "O2"),
    mcp_mode: Literal["off", "prefer", "require"] = "prefer",
    mcp_required_for_advanced: bool = True,
    mcp_timeout_ms: int = 10000,
    enable_asm: bool = True,
    enable_semantic_ir: bool = False,
    enable_cfg: bool = False,
    enable_runtime_tests: bool = False,
    poc_categories: tuple[Category, ...] | None = None,
    verification_decisions: tuple[VerificationDecision, ...] = (),
    prior_artifacts: str | None = None,
    prior_checkpoint_sha256: str | None = None,
) -> str:
    """Audit fresh inputs or resume an explicitly identified pending decision checkpoint."""
    repo = Path(path).resolve()
    db = Path(compile_db).resolve() if compile_db else repo / "compile_commands.json"
    cargo = Path(cargo_manifest).resolve() if cargo_manifest else repo / "Cargo.toml"
    if (compile_db and not db.is_file()) or (cargo_manifest and not cargo.is_file()):
        fail("An explicitly supplied build database or Cargo manifest does not exist.")
    if not repo.is_dir() or max_tus < 1 or mcp_timeout_ms < 100:
        fail("Invalid repository, TU limit, or MCP timeout.")
    if bool(prior_artifacts) != bool(prior_checkpoint_sha256):
        fail("Resume requires both prior_artifacts and prior_checkpoint_sha256.")
    tus: list[tuple[Path, Path, str]] = []
    for entry in read(db) if db.is_file() and set(languages) & {"c", "cpp"} else []:
        cwd = Path(entry["directory"]).resolve()
        src = (cwd / entry["file"]).resolve()
        language = {".c": "c", ".C": "cpp", ".cc": "cpp", ".cpp": "cpp", ".cxx": "cpp"}
        if language.get(src.suffix) in languages:
            if not src.is_file() or not cwd.is_dir() or not src.is_relative_to(repo):
                fail(f"Invalid translation unit or source outside the audited repository: {src}")
            if src not in [item[0] for item in tus]:
                tus.append((src, cwd, hashlib.sha256(str(src).encode()).hexdigest()[:12]))
    tus = tus[:max_tus]
    rust = cargo.is_file() and "rust" in languages
    sources = [src for src, _, _ in tus]
    sources += sorted((cargo.parent / "src").rglob("*.rs")) if rust else []
    if not sources:
        fail("Empty audit scope: provide buildable C/C++ or Rust sources.")
    names = COMMON + [f"agents/{role}.md" for role in ROLES]
    names += [f"workflows/phase-{n}-{name}.md" for n, name in enumerate(PHASES)]
    names += ["tools/" + name for name in PROGRAMS]
    assets = {name: resource(name) for name in names}
    external = tuple(
        Path(value).resolve() for value in (compile_db, cargo_manifest, config) if value
    )
    inputs = {
        "path": str(repo),
        "compile_db": str(db) if tus else None,
        "cargo_manifest": str(cargo) if rust else None,
        "config": str(Path(config).resolve()) if config else None,
        "languages": languages,
        "max_tus": max_tus,
        "opt_levels": opt_levels,
        "mcp_mode": mcp_mode,
        "mcp_required_for_advanced": mcp_required_for_advanced,
        "mcp_timeout_ms": mcp_timeout_ms,
        "enable_asm": enable_asm,
        "enable_semantic_ir": enable_semantic_ir,
        "enable_cfg": enable_cfg,
        "enable_runtime_tests": enable_runtime_tests,
        "poc_categories": poc_categories,
        "tu_list": [{"file": str(src), "tu_hash": h} for src, _, h in tus],
    }
    scope = {
        "inputs": inputs,
        "repository_files": file_hashes(repo, repository=True),
        "external_inputs": {
            str(item): hashlib.sha256(item.read_bytes()).hexdigest() for item in external
        },
        "resources": {
            name: hashlib.sha256(item.read_bytes()).hexdigest() for name, item in assets.items()
        },
    }
    scope_digest = digest(scope)
    prior = Path(prior_artifacts).resolve() if prior_artifacts else None
    saved: dict[str, Any] = {}
    saved_hashes: dict[str, str] = {}
    if prior is not None:
        if not prior.is_dir() or prior.is_relative_to(repo) or repo.is_relative_to(prior):
            fail("Prior artifacts must be a separate run directory outside the audited repository.")
        checkpoint_path = prior / CHECKPOINT
        if checkpoint_path.is_symlink() or not checkpoint_path.is_file():
            fail("The supplied prior directory has no regular pending checkpoint.")
        actual_digest = hashlib.sha256(checkpoint_path.read_bytes()).hexdigest()
        if actual_digest != prior_checkpoint_sha256:
            fail("Prior checkpoint SHA-256 does not match the explicit resume input.")
        saved = read(checkpoint_path)
        if (
            saved.get("format") != "zeroize-audit-pending-v1"
            or saved.get("status") != "awaiting_decisions"
            or saved.get("current_phase") != 5
            or saved.get("phase6_complete") is not False
            or saved.get("scope_digest") != scope_digest
            or digest(saved.get("scope")) != scope_digest
        ):
            fail("Prior checkpoint is incompatible or its audit scope has changed.")
        saved_hashes = file_hashes(prior)
        if saved_hashes != saved.get("artifacts"):
            fail("Prior artifacts changed after the pending checkpoint was recorded.")
    work = ensure_directory(
        "run",
        exclude_roots=(repo,) if prior is None else (repo, prior),
        output_files=tuple(sorted(set((*saved_hashes, *HOST_OUTPUTS)))),
    )
    if prior is not None:
        restore_artifacts(prior, work, saved_hashes, repo)
    params = {
        **inputs,
        "poc_output_dir": str(work / "poc"),
        "workdir": str(work),
        "resource_paths": {name: str(value) for name, value in assets.items()},
        "prior_artifacts": str(prior) if prior is not None else None,
    }
    preparation: list[dict[str, Any]] = []
    mcp: dict[str, Any] = {"status": "off", "results": []}
    if prior is None:
        for src, cwd, h in tus:
            extracted = run_command(
                [
                    "python3",
                    str(assets["tools/extract_compile_flags.py"]),
                    "--compile-db",
                    str(db),
                    "--src",
                    str(src),
                    "--format",
                    "json",
                ],
                timeout_seconds=60,
                working_directory=cwd,
                mutating=False,
            )
            if extracted.exit_code:
                fail("Compile-flag preflight failed: " + extracted.stderr)
            flags = [flag for flag in json.loads(extracted.stdout) if not flag.startswith("-O")]
            levels = tuple(dict.fromkeys(("O0", *opt_levels)))
            folder = ensure_directory(
                f"run/compiler-analysis/{h}",
                exclude_roots=(repo,),
                output_files=tuple(f"{h}.{level}.ll" for level in levels),
            )
            for level in levels:
                emitted = run_command(
                    [
                        "bash",
                        str(assets["tools/emit_ir.sh"]),
                        "--src",
                        str(src),
                        "--opt",
                        level,
                        "--out",
                        str(folder / f"{h}.{level}.ll"),
                        "--",
                        *flags,
                    ],
                    timeout_seconds=600,
                    working_directory=cwd,
                )
                preparation.append(
                    {
                        "tu": str(src),
                        "level": level,
                        "exit_code": emitted.exit_code,
                        "stderr": emitted.stderr,
                    }
                )
        if tus and mcp_mode != "off":
            probe = run_command(
                ["bash", str(assets["tools/mcp/check_mcp.sh"]), "--compile-db", str(db)],
                timeout_seconds=60,
                mutating=False,
            )
            mcp["probe"] = {"exit_code": probe.exit_code, "stdout": probe.stdout}
            mcp["status"] = "unavailable"
            if probe.exit_code == 0:
                deadline = monotonic() + mcp_timeout_ms / 1000
                try:
                    activation = tool("mcp__serena__activate_project", project=str(repo))
                    mcp["activation"] = activation
                    failed = isinstance(activation, dict) and (
                        activation.get("isError") or activation.get("success") is False
                    )
                    mcp["status"] = "failed" if failed else "uninterpreted"
                    queue = sorted(
                        {
                            word
                            for src, _, _ in tus
                            for word in re.findall(r"\b\w+\b", src.read_text(encoding="utf-8"))
                            if re.search(
                                r"(?i)key|secret|seed|priv|nonce|token|pwd|pass|zero", word
                            )
                        }
                    )
                    for symbol in [] if failed else queue:
                        if monotonic() >= deadline:
                            mcp["query_timeout"] = True
                            break
                        mcp["results"].append(
                            {
                                "query": symbol,
                                "definition": tool(
                                    "mcp__serena__find_symbol",
                                    symbol_name=symbol,
                                    include_body=True,
                                ),
                                "references": tool(
                                    "mcp__serena__find_referencing_symbols", symbol_name=symbol
                                ),
                            }
                        )
                    for src, _, _ in [] if failed else tus:
                        if monotonic() >= deadline:
                            break
                        mcp.setdefault("overviews", []).append(
                            {
                                "file": str(src),
                                "result": tool(
                                    "mcp__serena__get_symbols_overview", file_path=str(src)
                                ),
                            }
                        )
                except Exception as exc:
                    if type(exc).__name__ == "BudgetExceeded":
                        raise
                    mcp["status"] = "unavailable"
                    mcp["error"] = str(exc)
                    mcp["configuration_required"] = (
                        "Configure the declared Serena MCP host capabilities. "
                        "The uvx probe alone does not establish a working MCP connection."
                    )
            if mcp_mode == "require" and mcp["status"] in {"failed", "unavailable"}:
                emit(mcp, name="mcp-failure")
                fail("Required Serena MCP integration is unavailable; configure its host tools.")
    context = prepare_context(
        "Execute original Phases 0-4 in one connected session, preserving their order, "
        "checks, early termination and reasoning. Read complete workflows, role prompts "
        "and references through resource_paths, which supplies resolved replacements for "
        "baseDir resource references. Do not launch nested workers. Compiler/MCP preparation "
        "contains observations, not interpretation or exhaustive candidates. Normalize MCP "
        "using the supplied normalizer's actual --out interface. Interpret actual activation "
        "and query results and honor require/prefer/off behavior, evidence gates and coverage. "
        "Use supplied programs and their actual interfaces. Preserve raw findings, all Rust "
        "script findings, cross-references and Section D coverage gaps. Missing auxiliary "
        "programs must be reported; perform the prescribed reasoning where supported, and "
        "never claim an unavailable analysis ran. Keep audited code read-only and redirect "
        "build outputs into workdir. Read required artifacts before updating phase state. "
        "Bespoke PoCs must use build/test and C binary target names za_NNNN for sequential "
        "ZA-NNNN IDs. Preserve per-finding source filenames in the PoC manifest. Defer Phase "
        "5 onward, including final rendering after early termination. Return a blocking error "
        "or null after the assigned artifacts are complete. On resume Phases 0-4 and runtime "
        "validation are already preserved in verified prior artifacts; do not repeat them.",
        prior_results=json.dumps(
            {"inputs": params, "preparation": preparation, "raw_mcp": mcp, "resume": bool(prior)}
        ),
        files=tuple(assets.values()),
        readable_roots=tuple(assets.values()),
    )
    readable = (repo, work, *external, *assets.values())
    if prior is not None:
        readable = (*readable, prior)
    if prior is None:
        error = agent(
            "worker",
            context.prompt,
            context=context,
            output=str | None,
            timeout=3600,
            working_directory=work,
            readable_paths=readable,
            writable_paths=(work,),
            required_capabilities=("commands",),
        )
        if error:
            fail(error)
    report, poc = work / "report", work / "poc"
    objects = read(work / "source-analysis/sensitive-objects.json")
    findings = read(report / "findings.json")["findings"] if objects else []
    manifest = read(poc / "poc_manifest.json") if findings else {"pocs": []}
    manifest_items = manifest.get("pocs", manifest.get("entries", []))
    entries = {item["finding_id"]: item for item in manifest_items}
    if len(entries) != len(manifest_items):
        fail("PoC manifest contains duplicate finding IDs.")
    if prior is None:
        results: list[dict[str, Any]] = []
        ensure_directory(
            "run/poc",
            output_files=tuple(f"za_{i:04d}" for i in range(1, len(findings) + 1)),
            exclude_roots=(repo,),
        )
        for index, finding in enumerate(findings, 1):
            target, fid = f"za_{index:04d}", f"ZA-{index:04d}"
            if finding["id"] != fid:
                fail("Interim findings must have sequential normalized IDs.")
            item = entries.get(fid)
            if (poc_categories is None or finding["category"] in poc_categories) and not item:
                fail(f"Mandatory PoC manifest entry missing for {fid}.")
            result: dict[str, Any] = {
                "finding_id": fid,
                "category": finding["category"],
                "compile_success": False,
                "poc_file": item.get("poc_file", item.get("file")) if item else None,
                "exit_code": None,
                "validation_result": "no_poc",
                "reason": item.get("reason") if item else "Outside selected PoC categories.",
            }
            if item and item.get("poc_supported", True):
                is_rust = finding["language"] == "rust"
                base = (
                    ["cargo", "test", "--manifest-path", str(poc / "Cargo.toml"), "--test", target]
                    if is_rust
                    else ["make", target]
                )
                compiled = run_command(
                    base + (["--no-run"] if is_rust else []),
                    timeout_seconds=600,
                    working_directory=poc,
                )
                result.update(
                    compile_success=compiled.exit_code == 0,
                    compile_stdout=compiled.stdout,
                    compile_stderr=compiled.stderr,
                    stdout=compiled.stdout,
                    stderr=compiled.stderr,
                    validation_result="compile_failure",
                )
                if compiled.exit_code == 0:
                    ran = run_command(
                        base if is_rust else ["./" + target],
                        timeout_seconds=120,
                        working_directory=poc,
                    )
                    result.update(
                        exit_code=ran.exit_code,
                        stdout=ran.stdout,
                        stderr=ran.stderr,
                        validation_result="exploitable"
                        if ran.exit_code == 0
                        else "not_exploitable"
                        if is_rust or ran.exit_code == 1
                        else "runtime_failure",
                    )
            results.append(result)
        stamp = datetime.now(UTC).isoformat()
        write_json(poc / "poc_validation_results.json", {"timestamp": stamp, "results": results})
        reviews = (
            agent(
                "worker",
                "Independently execute 5c for every non-no_poc result, including compile "
                "failures. Read complete PoC source, build settings, actual findings, runtime "
                "outputs and original audited source. Return all six prescribed checks for "
                "each result. Follow the complete verifier role and its references. Use the "
                "embedded assignment directly; read task.txt only if absent or needed for "
                "a file check. This session performs independent verification only.",
                context=context,
                output=list[Review],
                timeout=3600,
                working_directory=work,
                readable_paths=readable,
            )
            if any(item["validation_result"] != "no_poc" for item in results)
            else []
        )
        verification = [
            {
                **review.model_dump(),
                "verified": "fail" not in review.checks.values(),
            }
            for review in reviews
        ]
        write_json(poc / "poc_verification.json", {"timestamp": stamp, "results": verification})
    results = read(poc / "poc_validation_results.json")["results"]
    verification = read(poc / "poc_verification.json")["results"]
    findings_by_id = {item["id"]: item for item in findings}
    result_ids = [item["finding_id"] for item in results]
    if len(set(result_ids)) != len(result_ids) or set(result_ids) != set(findings_by_id):
        fail("Runtime results must cover every interim finding exactly once.")
    by_id = {item["finding_id"]: item for item in verification}
    required_ids = {item["finding_id"] for item in results if item["validation_result"] != "no_poc"}
    if len(by_id) != len(verification) or set(by_id) != required_ids:
        fail("Independent verification must cover every generated PoC exactly once.")
    for review in verification:
        if set(review["checks"]) != CHECKS or any(
            value not in {"pass", "fail", "warn"} for value in review["checks"].values()
        ):
            fail("Independent verification omitted or malformed a required check.")
        if review.get("verified") != ("fail" not in review["checks"].values()):
            fail("Stored verification outcome contradicts its checks.")
    if file_hashes(repo, repository=True) != scope["repository_files"]:
        fail("Audited repository changed during the run; its evidence cannot be reused.")
    artifacts = file_hashes(work)
    if prior is not None and artifacts != saved_hashes:
        fail("Restored evidence changed before its decisions were checked.")
    choices: dict[tuple[str, str], str] = {}
    for item in saved.get("decisions", []):
        if set(item) != {"finding_id", "evidence_digest", "action"} or item["action"] not in {
            "accept",
            "reject",
        }:
            fail("Prior checkpoint contains a malformed saved user decision.")
        key = (item["finding_id"], item["evidence_digest"])
        if key in choices:
            fail("Prior checkpoint contains duplicate user decisions.")
        choices[key] = item["action"]
    supplied: set[tuple[str, str]] = set()
    for decision in verification_decisions:
        key = (decision.finding_id, decision.evidence_digest)
        if key in supplied:
            fail("Supply only one current decision for each finding and evidence digest.")
        supplied.add(key)
        choices[key] = decision.action
    source_texts = poc_sources(work, prior)
    requests: list[dict[str, Any]] = []
    merged: list[dict[str, Any]] = []
    required_decisions: set[tuple[str, str]] = set()
    for original in results:
        result = dict(original)
        fid = result["finding_id"]
        review = by_id.get(fid)
        result["verified"] = review is not None and review["verified"]
        result["verification"] = review
        if review is not None and not review["verified"]:
            evidence_digest = digest(
                {
                    "format": "zeroize-audit-decision-v1",
                    "scope_digest": scope_digest,
                    "finding": findings_by_id[fid],
                    "manifest_entry": entries.get(fid),
                    "validation": original,
                    "verification": review,
                    "artifact_hashes": artifacts,
                }
            )
            key = (fid, evidence_digest)
            required_decisions.add(key)
            action = choices.get(key)
            result["evidence_digest"] = evidence_digest
            result["original_validation_result"] = result["validation_result"]
            requests.append(
                {
                    "finding_id": fid,
                    "category": result["category"],
                    "evidence_digest": evidence_digest,
                    "poc_file": result["poc_file"],
                    "poc_source": source_texts.get(
                        str(result["poc_file"]), "PoC source file was not found."
                    ),
                    "failed_checks": [
                        name for name, value in review["checks"].items() if value == "fail"
                    ],
                    "verification": review,
                    "runtime_result": original,
                    "recorded_action": action,
                    "requested_action": (
                        "Provide a VerificationDecision with this finding_id and evidence_digest "
                        "and action='accept' to retain weaker evidence or action='reject' to "
                        "discard this PoC result. No decision is inferred."
                    ),
                }
            )
            if action is not None:
                result["user_accepted"] = action == "accept"
                if action == "reject":
                    result["validation_result"] = "rejected"
        merged.append(result)
    unmatched = set(choices) - required_decisions
    pending = [item for item in requests if item["recorded_action"] is None]
    if pending or unmatched:
        checkpoint = {
            "format": "zeroize-audit-pending-v1",
            "status": "awaiting_decisions",
            "current_phase": 5,
            "phase6_complete": False,
            "scope": scope,
            "scope_digest": scope_digest,
            "artifacts": artifacts,
            "inputs": params,
            "findings": findings,
            "manifest": manifest,
            "validation_results": results,
            "verification_results": verification,
            "merged_results": merged,
            "requests": requests,
            "decisions": [
                {"finding_id": fid, "evidence_digest": value, "action": action}
                for (fid, value), action in sorted(choices.items())
                if (fid, value) in required_decisions
            ],
            "unmatched_decisions": [
                {"finding_id": fid, "evidence_digest": value} for fid, value in sorted(unmatched)
            ],
            "requested_action": (
                "Review every unresolved request, then resume with prior_artifacts, the emitted "
                "prior_checkpoint_sha256, the same audit inputs, and individual typed "
                "verification_decisions. Remove unmatched or stale decisions."
            ),
        }
        checkpoint_path = write_json(work / CHECKPOINT, checkpoint)
        checkpoint_sha256 = hashlib.sha256(checkpoint_path.read_bytes()).hexdigest()
        emit(checkpoint, name="pending-decisions")
        emit(
            {
                "prior_artifacts": str(work),
                "prior_checkpoint_sha256": checkpoint_sha256,
                "scope_digest": scope_digest,
            },
            name="resume-inputs",
        )
        fail(
            "Phase 5 awaits explicit evidence-bound user decisions or removal of stale "
            "decisions. The complete checkpoint and prior artifacts are preserved; "
            "Phase 6 has not run."
        )
    write_json(
        poc / "poc_final_results.json",
        {"timestamp": datetime.now(UTC).isoformat(), "results": merged},
    )
    final_prompt = (
        "Finish Phase 5 state, original Phase 6 and optional Phase 7, including empty reports. "
        "Read complete applicable workflows, roles, references and actual artifacts. The "
        "host has compiled and run PoCs, independently verified all generated PoCs, and "
        "merged only explicit evidence-bound user decisions. Preserve original runtime "
        "results, all checks, notes, rejection details, and user_accepted values. Treat "
        "runtime_failure as inconclusive. Follow the authoritative output schema, report "
        "requirements and confidence gates. Render all findings and Section D coverage gaps. "
        "On resume, artifacts were copied from the explicitly supplied prior directory; "
        "current inputs identify the new workdir. Update state paths accordingly and write "
        "only beneath the new workdir. Prior absolute artifact references remain readable. "
        "Keep the target repository read-only. Use the embedded assignment and resource map; "
        "read task.txt when absent or needed for a file check. Return a blocking error or null."
    )
    error = agent(
        "worker",
        final_prompt,
        context=context,
        output=str | None,
        timeout=3600,
        working_directory=report,
        readable_paths=readable,
        writable_paths=(work,),
        required_capabilities=("commands",),
    )
    if error:
        fail(error)
    emit(read(report / "findings.json"), name="findings")
    markdown = (report / "final-report.md").read_text(encoding="utf-8")
    if not markdown.strip():
        fail("Final report is empty.")
    return emit(markdown, name="final-report")


if __name__ == "__main__":
    raise SystemExit(zeroize_audit.cli())


# --- calcifier metadata (skill provenance + sha256) ---
_CALCIFIER_COMPILATION = "compiled"
_CALCIFIER_SKILL = {
    "path": "../SKILL.md",
    "sha256": ("933273f0c9cd0ae197c010a4d3de81782a593b2160507b897f1e04d579bfba6f"),
}
_CALCIFIER_RESOURCES = [
    {
        "path": "agents/0-preflight.md",
        "sha256": ("3d6082b0ab0e5744bb7b9b4c91ab54883c031e63f2c07c04a8c7179c97fe4170"),
        "size": 6343,
        "source": "../../agents/0-preflight.md",
    },
    {
        "path": "agents/1-mcp-resolver.md",
        "sha256": ("52904c58ca67bd5be51a7ab42aed73190512b6c69a8d303cd9a3915baec82622"),
        "size": 4208,
        "source": "../../agents/1-mcp-resolver.md",
    },
    {
        "path": "agents/2-source-analyzer.md",
        "sha256": ("155e5f51b2e5a1ececc192346d14e667d3363b9553f6d75ffebc77c73b5f5046"),
        "size": 6569,
        "source": "../../agents/2-source-analyzer.md",
    },
    {
        "path": "agents/2b-rust-source-analyzer.md",
        "sha256": ("c9822a957d5329da7b379deb849c9be8a6fd160d8fc5bc60139fbe321ac9efbe"),
        "size": 10035,
        "source": "../../agents/2b-rust-source-analyzer.md",
    },
    {
        "path": "agents/3-tu-compiler-analyzer.md",
        "sha256": ("a8320e12c20d873ccfbfe10289b914889b3d6e6ba318e0a25b18004971c4b9d7"),
        "size": 8877,
        "source": "../../agents/3-tu-compiler-analyzer.md",
    },
    {
        "path": "agents/3b-rust-compiler-analyzer.md",
        "sha256": ("de7f69e73a88bb6b1fef17ceae97e4c0c4942563a7c4acd39be98ba36c1f5063"),
        "size": 16445,
        "source": "../../agents/3b-rust-compiler-analyzer.md",
    },
    {
        "path": "agents/4-report-assembler.md",
        "sha256": ("7d9340359125a631be066bf183a2776f4d64d52caff7c5af6c9ea3f39fb89a2f"),
        "size": 14433,
        "source": "../../agents/4-report-assembler.md",
    },
    {
        "path": "agents/5-poc-generator.md",
        "sha256": ("5089828221c6da282ef87e46685bfce79720a10c4a2e183048d8284aad958614"),
        "size": 16591,
        "source": "../../agents/5-poc-generator.md",
    },
    {
        "path": "agents/5b-poc-validator.md",
        "sha256": ("2c918168c4b7b3e10a1c079e60c48d892c124db6269af81d1d8d355e43005803"),
        "size": 3843,
        "source": "../../agents/5b-poc-validator.md",
    },
    {
        "path": "agents/5c-poc-verifier.md",
        "sha256": ("c06227b90d7e3ef8672933085481c564be76615184988c0f769b1f4f9b0b1349"),
        "size": 10828,
        "source": "../../agents/5c-poc-verifier.md",
    },
    {
        "path": "agents/6-test-generator.md",
        "sha256": ("246a83d2b75062ef55939b11af70fdb367ca400d1951ad64c7461db1c88d5bd7"),
        "size": 2970,
        "source": "../../agents/6-test-generator.md",
    },
    {
        "path": "configs/c.yaml",
        "sha256": ("64c1bf6e6dcb0639e6d66178a741b5fd7f7c79266b91b3dbccfb9e9271e5c956"),
        "size": 456,
        "source": None,
    },
    {
        "path": "configs/default.yaml",
        "sha256": ("bf694a729a8b3cfa5bfe778f60ddba3a393162caf2bcf56e84ff69ed915d4d72"),
        "size": 3955,
        "source": None,
    },
    {
        "path": "configs/rust.yaml",
        "sha256": ("3d52fe38092491aea4f3e4745393a61dd08a129c76a34a295dee8c8c614ab1f3"),
        "size": 3263,
        "source": None,
    },
    {
        "path": "prompts/system.md",
        "sha256": ("2ca13b383f53f87dfc5933ed72e06f3162102b5d16f2866540ccb43cbd58569d"),
        "size": 8443,
        "source": None,
    },
    {
        "path": "prompts/task.md",
        "sha256": ("cb318918dd864a654a201479d0f9b9b5f7e95b96d464952ed576a2e3b4bb3b2c"),
        "size": 4684,
        "source": None,
    },
    {
        "path": "references/compile-commands.md",
        "sha256": ("ec353fc404fe2aea30e35fd10ae381f35f178c5121b12761b92c658bfe60024d"),
        "size": 10230,
        "source": None,
    },
    {
        "path": "references/detection-strategy.md",
        "sha256": ("42f5342e35f065eafcba5547aa0845498f406087cf0bacfa298ea7d86c489067"),
        "size": 10226,
        "source": None,
    },
    {
        "path": "references/ir-analysis.md",
        "sha256": ("15aa18ce8592cd969cf4343e36cb2bfafa4971ea9ca5acb3d760cee0ace9e55f"),
        "size": 11221,
        "source": None,
    },
    {
        "path": "references/mcp-analysis.md",
        "sha256": ("018b4247ead8e058a27f17b6680f0bfa31c26331818dde699d32c8eec436f7c1"),
        "size": 9283,
        "source": None,
    },
    {
        "path": "references/poc-generation.md",
        "sha256": ("61fb008ce7bab1a19b56b25a934d2586d3a6e43bfdbb0327f33f36b9505f5f5c"),
        "size": 21651,
        "source": None,
    },
    {
        "path": "references/rust-zeroization-patterns.md",
        "sha256": ("5a86f5accad96827da494e08fef557de845df643c02685e26530403e43e707f2"),
        "size": 35542,
        "source": None,
    },
    {
        "path": "schemas/input.json",
        "sha256": ("0a93fd1ec9e9a4f85355bf40600fd29c76c3f98089d9b6ac76795d1aa0a02421"),
        "size": 3174,
        "source": None,
    },
    {
        "path": "schemas/output.json",
        "sha256": ("642b4f77d447167d2887d9b5d2ae41d67ac80ba35d7d0be26498adcfbdc02e53"),
        "size": 6040,
        "source": None,
    },
    {
        "path": "tools/diff_rust_mir.sh",
        "sha256": ("2d383e50a3ccca17f5a8e5af26f08241cd5811e330f9e5d2ce9e5a249778cbdd"),
        "size": 6397,
        "source": None,
    },
    {
        "path": "tools/emit_asm.sh",
        "sha256": ("af4db5b52071eb52f1f5579438c199142453e9fb6e6dd775c31a3edd9ea5f34e"),
        "size": 1026,
        "source": None,
    },
    {
        "path": "tools/emit_ir.sh",
        "sha256": ("82a3c91291ff5bc4b0ca78c3b1587aae88c1752774e0b6837c455dec5475ebf4"),
        "size": 1340,
        "source": None,
    },
    {
        "path": "tools/emit_rust_asm.sh",
        "sha256": ("d23f859b9f4871a625d2b1fffd8857625c5b49a1a8b5e8f4878d0e800fb05847"),
        "size": 4337,
        "source": None,
    },
    {
        "path": "tools/emit_rust_ir.sh",
        "sha256": ("3117475bba0a1fe350a938403597dec7a86d032a6d51494d708ae0037747dd17"),
        "size": 3411,
        "source": None,
    },
    {
        "path": "tools/emit_rust_mir.sh",
        "sha256": ("95e3588f4484c6a872363a44e16587a51f5ba47cb05e6047edd7c598c6aa192d"),
        "size": 3536,
        "source": None,
    },
    {
        "path": "tools/extract_compile_flags.py",
        "sha256": ("96bd2e753db421e0b86d9cadb37a61dc562e3dc84cde567a6018834565da658b"),
        "size": 8821,
        "source": None,
    },
    {
        "path": "tools/generate_poc.py",
        "sha256": ("5c9f504ba3d421d0dcce4c1e2aea19b8366eb321eb256959f797c2ec6e084677"),
        "size": 48466,
        "source": None,
    },
    {
        "path": "tools/mcp/check_mcp.sh",
        "sha256": ("68c9291036b42551f926bb2bd0adeeb11e920232f2d09d4a22712575f1a9a3ae"),
        "size": 1251,
        "source": None,
    },
    {
        "path": "tools/mcp/normalize_mcp_evidence.py",
        "sha256": ("5c7132a27f7ca1ac88728115273a78d6b11a8f87050d8262fa1c9dd47483b7eb"),
        "size": 3906,
        "source": None,
    },
    {
        "path": "tools/scripts/check_llvm_patterns.py",
        "sha256": ("0a17e661233fa48feab2b84fa08b685632bef51c8a479c0504e2de6369e73b5c"),
        "size": 17576,
        "source": None,
    },
    {
        "path": "tools/scripts/check_mir_patterns.py",
        "sha256": ("6591eac1ea39b5e2e4cab93fcc01a3f9db6ea421676583bb31e6677140ff6cef"),
        "size": 19399,
        "source": None,
    },
    {
        "path": "tools/scripts/check_rust_asm.py",
        "sha256": ("3c82bdb8db9c4393949cc437ff3ade8da3a610c27ebbfb54501132f58ad6d675"),
        "size": 16243,
        "source": None,
    },
    {
        "path": "tools/scripts/check_rust_asm_aarch64.py",
        "sha256": ("0d63782b2b2f1a0e632451823d6001e4c8b240844a23c45c1e646602698e8db4"),
        "size": 10246,
        "source": None,
    },
    {
        "path": "tools/scripts/check_rust_asm_x86.py",
        "sha256": ("6edcdc741d1f202566c5914b5d577c879d11ba61a841ba42398e05579b919cea"),
        "size": 9587,
        "source": None,
    },
    {
        "path": "tools/scripts/find_dangerous_apis.py",
        "sha256": ("5a7b873e17a64bdbe0743a0301f1abd0aba4bbe79e552eccdf7dc39e80563469"),
        "size": 14132,
        "source": None,
    },
    {
        "path": "tools/scripts/semantic_audit.py",
        "sha256": ("b84e3e885e07f88dce17da03d067c1bf7a7ade0305209bdc2e9be28ecad757d9"),
        "size": 33243,
        "source": None,
    },
    {
        "path": "tools/validate_rust_toolchain.sh",
        "sha256": ("4f294646864874bb93ef0aaceecfcaa3f81743278ffe9c48540f53a70004f49f"),
        "size": 8434,
        "source": None,
    },
    {
        "path": "workflows/phase-0-preflight.md",
        "sha256": ("758b424590b2fbba4eca0831d13288f173c1c6aff3a32f228f16a2ad75cbf54d"),
        "size": 7564,
        "source": None,
    },
    {
        "path": "workflows/phase-1-source-analysis.md",
        "sha256": ("9b433ef005dcef14df1b070e0f1f1edc24b2503a28ac8b0d01c1d38b43fe8f62"),
        "size": 5091,
        "source": None,
    },
    {
        "path": "workflows/phase-2-compiler-analysis.md",
        "sha256": ("b1b3ea9fcf61f1ca71e169ba06d7cc11daadf3bdf964b96aee10b659d84816fe"),
        "size": 6128,
        "source": None,
    },
    {
        "path": "workflows/phase-3-interim-report.md",
        "sha256": ("030bda9e7d1a01a1959c8bc1c6156dce84150500f74f679b693d495dfa545d12"),
        "size": 1149,
        "source": None,
    },
    {
        "path": "workflows/phase-4-poc-generation.md",
        "sha256": ("2f5ca69c303807791c9cbe4f05349573a7297ec5df362055053a0245296b79c2"),
        "size": 1301,
        "source": None,
    },
    {
        "path": "workflows/phase-5-poc-validation.md",
        "sha256": ("c1a87bc8f9d8eb3c59bff3f9ca5860d4910efcffe4c2937d84d702f673cbc8ec"),
        "size": 4351,
        "source": None,
    },
    {
        "path": "workflows/phase-6-final-report.md",
        "sha256": ("93dd23c99a30832477fcfedaa76f1a66de4d189f3d3389373637b7c8ba0ff80b"),
        "size": 1166,
        "source": None,
    },
    {
        "path": "workflows/phase-7-test-generation.md",
        "sha256": ("d865b2fff2a081ce5966bc2e6ad7fe7d04dad897fcbd7139daceeeee9b3a2a63"),
        "size": 862,
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
        "ed inspection that finds zero issues.\n\nThe previous comp"
        "lete candidate is supplied below as reference source data."
        "\nPreserve its complete audit, compiler, PoC and independe"
        'nt verification workflow.\nIts conditional tool("AskUserQu'
        'estion") requires an interactive platform adapter\nthat Ca'
        "lcifier does not ship. Replace that capability with explic"
        "it trusted typed\ninputs for the user's individual failed-"
        "verification accept/reject decisions.\nBind a decision to "
        "the finding and a deterministic digest of the actual PoC a"
        "nd\nverification evidence, not only a potentially reordere"
        "d model-generated ID.\nNever assume acceptance. If a neede"
        "d decision is absent, persist the full pending\ncheckpoint"
        ", identifiers/evidence digests and requested action, then "
        "stop without\nclaiming the final phase is complete. If sup"
        "porting resume, use an explicit user\ninput for prior arti"
        "facts and verify their scope/evidence bindings before reus"
        "e.\nA fresh run whose independent verification passes must"
        " still complete normally.\nDo not reduce this to an always"
        "-blocked preflight. Preserve the actual supplied\nhelper i"
        "nterfaces; their full exact text is supplied as compiler r"
        "eference data.\nThe optional Serena MCP capabilities are g"
        "enuine source integrations, not\nplatform orchestration. R"
        "etain their explicit dependency/configuration and\nsource-"
        "stated prefer/require/off behavior; do not silently invent"
        " MCP results.\nNative host run_command needs no generic Ba"
        "sh adapter. Keep repository Ruff\nE,F,I,UP,B,SIM and 100-c"
        "haracter line length. Fidelity has priority over 250 lines"
        ".\n"
    ),
    "sha256": ("63361ac351ee7d00e23abf86312abce7f2c62beda601e973e87428d1c6524816"),
}
_CALCIFIER_SUBRECIPES = []
