# /// script
# requires-python = ">=3.13"
# dependencies = ["calcifier==0.2.0"]
# ///

"""Native, persisted orchestration for the pinned code-improver workflow."""

import base64
import difflib
import hashlib
import json
import re
import stat
import sys
import uuid
from pathlib import Path
from typing import Any, Literal

from calcifier import (
    Budget,
    CommandResult,
    agent,
    emit,
    ensure_directory,
    output_type,
    parallel,
    prepare_context,
    recipe,
    resource,
    run_command,
    step,
    verify_artifact,
    write_json,
    write_text,
)

BLOCKING = {"critical", "major"}
SEVERITIES = ("critical", "major", "minor", "info")
SKIP_DIRS = {".git", ".code-improver", ".skill-improver", "node_modules", "__pycache__"}
NARRATION = (
    r"\b(round|iteration|pass) [0-9]\b",
    r"previous(ly)? (fix|attempt|version|round)",
    r"(was|were) (added|moved|changed|renamed|removed) (here|to|from)",
    r"per (the )?(review|reviewer|finding)",
)
METADATA_UPDATE = (
    "import json, pathlib, sys\n"
    "config = json.loads(sys.argv[1])\n"
    "for item in config['files']:\n"
    "    path = pathlib.Path(item['path'])\n"
    "    data = json.loads(path.read_text(encoding='utf-8'))\n"
    "    if item['kind'] == 'plugin':\n"
    "        data['version'] = config['version']\n"
    "    else:\n"
    "        for index in item['indices']:\n"
    "            data['plugins'][index]['version'] = config['version']\n"
    "    path.write_text(json.dumps(data, indent=2) + '\\n', encoding='utf-8')\n"
)


class StopLoop(Exception):
    def __init__(self, code: str, detail: str) -> None:
        super().__init__(detail)
        self.code = code


@output_type
class Finding:
    id: str
    file: str
    line: int
    defect_class: str
    severity: Literal["critical", "major", "minor", "info"]
    title: str
    evidence: str
    new_evidence: bool


@output_type
class Review:
    findings: list[Finding]
    verified_fixed: list[str]
    summary: str


@output_type
class Dispatch:
    agent_type: str
    prompt: str
    label: str


@output_type
class SkillReview:
    mode: Literal["direct", "dispatch"]
    findings: list[Finding]
    verified_fixed: list[str]
    summary: str
    agents: list[Dispatch]


@output_type
class Verdict:
    id: str
    verdict: Literal["fixed", "rejected", "deferred"]
    reason: str
    structural: bool
    pin: str


@output_type
class Fix:
    verdicts: list[Verdict]
    notes: str


@output_type
class SpecialistReport:
    name: str
    label: str
    ok: bool
    report: str
    error: str


@output_type
class Finalize:
    narration_sites_removed: int
    version: str
    notes: str


@output_type
class Regression:
    file: str
    line: int
    why: str


@output_type
class FinalizeCheck:
    regressions: list[Regression]
    summary: str


@output_type
class Guard:
    changed: list[str]
    untracked: list[str]
    violations: list[str]
    new_untracked_files: list[str]
    scope_count: int
    snapshot: dict[str, Any]


@output_type
class RunResult:
    converged: bool
    capped: bool
    halted: str
    escalation: dict[str, Any] | None
    violations: list[str]
    finalize_regressions: list[Regression]
    rounds_run: int
    fix_rounds: int
    fixer_failed_rounds: list[int]
    open_blocking: list[dict[str, str]]
    open_minor_count: int
    new_untracked_files: list[str]
    ledger_path: str
    out_dir: str
    metrics: str
    notes: list[str]
    partial_unreviewed_edits: bool
    artifacts_complete: bool
    status_path: str
    ledger_markdown: str
    baseline_path: str


def propagate_interruption(exc: BaseException) -> None:
    if not isinstance(exc, Exception) or type(exc).__name__ == "BudgetExceeded":
        raise exc


def git(root: Path, args: list[str], *, mutate: bool = False) -> CommandResult:
    return run_command(
        ["git", "-C", str(root), *args],
        timeout_seconds=120,
        working_directory=root,
        mutating=mutate,
    )


def git_text(root: Path, args: list[str], *, mutate: bool = False) -> str:
    result = git(root, args, mutate=mutate)
    if result.exit_code:
        raise StopLoop("git-failed", f"{result.argv}: {result.stderr}")
    return result.stdout


def nul_paths(text: str) -> list[str]:
    return [value for value in text.split("\0") if value]


def artifact_path(path: str, out_rel: str) -> bool:
    return bool(out_rel and (path == out_rel or path.startswith(out_rel + "/")))


def scope_patterns(scope: list[str]) -> list[re.Pattern[str]]:
    patterns = []
    for glob in scope:
        if not glob or glob.startswith("/") or ".." in glob.split("/"):
            raise StopLoop("invalid-scope", f"Scope must be explicit repo-relative globs: {glob!r}")
        escaped = re.escape(glob).replace(r"\*\*", "\x01")
        escaped = escaped.replace(r"\*", "[^/]*").replace("\x01", ".*")
        patterns.append(re.compile("^" + escaped + "$"))
    if not patterns:
        raise StopLoop(
            "scope-required",
            "Supply explicitly authorized scope globs; this entry does not guess or widen scope.",
        )
    return patterns


def in_scope(path: str, patterns: list[re.Pattern[str]]) -> bool:
    return any(pattern.fullmatch(path) is not None for pattern in patterns)


def repo_path(root: Path, rel: str) -> Path:
    value = Path(rel)
    if value.is_absolute() or ".." in value.parts:
        raise StopLoop("unsafe-git-path", f"Git returned an unsafe repository path: {rel!r}")
    path = root / value
    if not path.parent.resolve().is_relative_to(root):
        raise StopLoop("unsafe-git-path", f"A repository path traverses a symlink: {rel!r}")
    return path


def fingerprint(path: Path) -> dict[str, Any]:
    try:
        metadata = path.lstat()
    except FileNotFoundError:
        return {"kind": "missing", "sha": "MISSING", "mode": 0}
    mode = stat.S_IMODE(metadata.st_mode)
    if stat.S_ISLNK(metadata.st_mode):
        payload = str(path.readlink()).encode("utf-8", errors="surrogateescape")
        kind = "symlink"
    elif stat.S_ISREG(metadata.st_mode):
        payload = path.read_bytes()
        kind = "file"
    else:
        return {"kind": "special", "sha": "SPECIAL", "mode": mode}
    return {"kind": kind, "sha": hashlib.sha256(payload).hexdigest(), "mode": mode}


def scoped_files(root: Path, patterns: list[re.Pattern[str]], out_rel: str) -> list[str]:
    selected = []
    for path in root.rglob("*"):
        rel = path.relative_to(root).as_posix()
        if artifact_path(rel, out_rel) or any(part in SKIP_DIRS for part in Path(rel).parts):
            continue
        if path.is_file() and not path.is_symlink() and in_scope(rel, patterns):
            repo_path(root, rel)
            selected.append(rel)
    return sorted(selected)


def snapshot(
    root: Path,
    sha: str,
    patterns: list[re.Pattern[str]],
    out_rel: str,
    *,
    contents: bool = False,
) -> dict[str, Any]:
    tracked = nul_paths(git_text(root, ["ls-files", "--cached", "-z"]))
    untracked = nul_paths(git_text(root, ["ls-files", "--others", "--exclude-standard", "-z"]))
    selected = scoped_files(root, patterns, out_rel)
    paths = sorted(set(tracked + untracked + selected))
    files = {
        rel: fingerprint(repo_path(root, rel)) for rel in paths if not artifact_path(rel, out_rel)
    }
    index: dict[str, list[str]] = {}
    for entry in nul_paths(git_text(root, ["ls-files", "--stage", "-z"])):
        metadata, rel = entry.split("\t", 1)
        if not artifact_path(rel, out_rel):
            index.setdefault(rel, []).append(metadata)
    branch = git(root, ["symbolic-ref", "--quiet", "HEAD"])
    state: dict[str, Any] = {
        "git_root": git_text(root, ["rev-parse", "--show-toplevel"]).strip(),
        "head_sha": git_text(root, ["rev-parse", "HEAD"]).strip(),
        "branch": branch.stdout.strip() if branch.exit_code == 0 else "DETACHED",
        "tracked": sorted(set(tracked)),
        "untracked": untracked,
        "untracked_digests": [
            {"path": rel, "sha": files[rel]["sha"]} for rel in untracked if rel in files
        ],
        "digest_algorithm": "sha256; symlinks hash their link text without following them",
        "files": files,
        "index": index,
        "scope_files": selected,
        "status": git_text(root, ["status", "--porcelain=v1", "-z", "--untracked-files=all"]),
        "changed": nul_paths(git_text(root, ["diff", "--name-only", "--no-renames", "-z", sha])),
        "diff": git_text(root, ["diff", "--binary", "--no-ext-diff", sha]),
        "staged_diff": git_text(root, ["diff", "--cached", "--binary", sha]),
        "worktree_diff": git_text(root, ["diff", "--binary"]),
    }
    if contents:
        full_contents: dict[str, Any] = {}
        for rel in selected:
            payload = repo_path(root, rel).read_bytes()
            try:
                full_contents[rel] = {"encoding": "utf-8", "text": payload.decode("utf-8")}
            except UnicodeDecodeError:
                full_contents[rel] = {
                    "encoding": "base64",
                    "text": base64.b64encode(payload).decode("ascii"),
                }
        state["contents"] = full_contents
    return state


@step
def check_scope(root: str, baseline: dict[str, Any], scope: list[str], out_rel: str) -> Guard:
    directory = Path(root)
    patterns = scope_patterns(scope)
    current = snapshot(directory, baseline["head_sha"], patterns, out_rel)
    violations = []
    for key in ("head_sha", "git_root", "branch"):
        if current[key] != baseline[key]:
            violations.append(f"Immutable git baseline changed: {key}")
    for rel in sorted(set(baseline["files"]) | set(current["files"])):
        if (
            not in_scope(rel, patterns)
            and not artifact_path(rel, out_rel)
            and baseline["files"].get(rel) != current["files"].get(rel)
        ):
            violations.append(rel + " (out-of-scope content, mode, creation, or deletion)")
    for rel in sorted(set(baseline["index"]) | set(current["index"])):
        if (
            not in_scope(rel, patterns)
            and not artifact_path(rel, out_rel)
            and baseline["index"].get(rel) != current["index"].get(rel)
        ):
            violations.append(rel + " (out-of-scope index change)")
    old_untracked = set(baseline["untracked"])
    new_untracked = [
        rel
        for rel in current["untracked"]
        if rel not in old_untracked and in_scope(rel, patterns) and not artifact_path(rel, out_rel)
    ]
    return Guard(
        changed=current["changed"],
        untracked=current["untracked"],
        violations=violations,
        new_untracked_files=new_untracked,
        scope_count=len(current["scope_files"]),
        snapshot=current,
    )


def enforce_guard(guard: Guard, result: RunResult, *, registered: bool) -> None:
    if guard.violations:
        result.violations = guard.violations
        raise StopLoop(
            "scope-violation",
            "Scope guard fired; edits remain in the tree: " + "; ".join(guard.violations),
        )
    if not guard.scope_count:
        raise StopLoop("empty-inspection-scope", "The authorized scope now contains zero files.")
    if registered and guard.new_untracked_files:
        result.new_untracked_files = guard.new_untracked_files
        raise StopLoop(
            "untracked-files-in-scope",
            "Register new files with git add -N before completion: "
            + ", ".join(guard.new_untracked_files),
        )


def save_json(out: Path, name: str, value: Any, artifacts: list[str]) -> None:
    write_json(out / name, value)
    if name not in artifacts:
        artifacts.append(name)


def save_text(out: Path, name: str, value: str, artifacts: list[str]) -> None:
    write_text(out / name, value)
    if name not in artifacts:
        artifacts.append(name)


def open_blocking(ledger: dict[str, Any]) -> list[dict[str, Any]]:
    return [
        finding
        for finding in ledger["findings"].values()
        if finding["status"] == "open" and finding["severity"] in BLOCKING
    ]


def severity_counts(ledger: dict[str, Any]) -> dict[str, int]:
    return {
        severity: sum(
            finding["status"] == "open" and finding["severity"] == severity
            for finding in ledger["findings"].values()
        )
        for severity in SEVERITIES
    }


def table_cell(value: Any) -> str:
    return str(value).replace("|", "\\|").replace("\r", "").replace("\n", "<br>")


def outcome(result: RunResult) -> str:
    if result.halted:
        return "HALTED: " + result.halted
    if result.escalation:
        return "ESCALATED: " + str(result.escalation["type"])
    if result.capped:
        return "CAPPED, NOT CONVERGED"
    if result.converged:
        return "CONVERGED"
    return "IN PROGRESS; NOT CERTIFIED"


def status_text(ledger: dict[str, Any], result: RunResult) -> str:
    lines = [
        outcome(result),
        f"Review rounds: {result.rounds_run}; fix rounds: {result.fix_rounds}.",
        f"Open minor/info findings: {result.open_minor_count}.",
        f"Partial or unreviewed edits: {result.partial_unreviewed_edits}.",
        f"Artifacts complete: {result.artifacts_complete}.",
        "",
    ]
    for finding in open_blocking(ledger):
        lines.append(f"- {finding['id']} [{finding['severity']}]: {finding['title']}")
    if result.escalation:
        lines.extend(
            [
                "",
                str(result.escalation["message"]),
                "Finding ids: " + ", ".join(result.escalation["finding_ids"]),
            ]
        )
    for regression in result.finalize_regressions:
        lines.append(f"- {regression.file}:{regression.line}: {regression.why}")
    if result.violations:
        lines.extend(["", "Violations:", *["- " + path for path in result.violations]])
    if result.new_untracked_files:
        lines.extend(["", "Unregistered files:", *result.new_untracked_files])
    lines.extend(["", "Notes:", *["- " + note for note in result.notes]])
    lines.extend(
        [
            "",
            "Changes remain uncommitted. Re-run with the same target and reviewer to resume.",
            "After escalation, supply the user's ruling verbatim as decision.",
            "Scope changes require explicitly authorized scope inputs.",
            "Ledger: " + result.ledger_path,
            "Findings and rounds: " + result.ledger_markdown,
            "Metrics: " + result.metrics,
            "Baseline: " + result.baseline_path,
        ]
    )
    return "\n".join(lines) + "\n"


def checkpoint(out: Path, ledger: dict[str, Any], result: RunResult, artifacts: list[str]) -> None:
    result.open_blocking = [
        {"id": item["id"], "severity": item["severity"], "title": item["title"]}
        for item in open_blocking(ledger)
    ]
    result.open_minor_count = sum(
        item["status"] == "open" and item["severity"] not in BLOCKING
        for item in ledger["findings"].values()
    )
    ledger["result"] = result.model_dump()
    rows = [
        "| id | severity | status | title | evidence | verdict reason | pin |",
        "| --- | --- | --- | --- | --- | --- | --- |",
    ]
    columns = ("id", "severity", "status", "title", "evidence", "verdict_reason", "pin")
    for finding in ledger["findings"].values():
        cells = [table_cell(finding.get(column, "")) for column in columns]
        rows.append("| " + " | ".join(cells) + " |")
    rows.extend(["", "Rounds:"])
    rows.extend("- " + json.dumps(record, ensure_ascii=False) for record in ledger["rounds"])
    save_json(out, "ledger.json", ledger, artifacts)
    save_json(out, "result.json", result.model_dump(), artifacts)
    save_text(out, "ledger.md", "\n".join(rows) + "\n", artifacts)
    save_text(out, "status.md", status_text(ledger, result), artifacts)


def load_prior(ledger: dict[str, Any], raw: str, notes: list[str]) -> None:
    if not raw:
        return
    try:
        prior = json.loads(raw)
    except json.JSONDecodeError as exc:
        notes.append(f"PRIOR LEDGER UNREADABLE ({exc}); prior text is archived, verdicts lost.")
        return
    if prior.get("target") != ledger["target"] or prior.get("reviewer") != ledger["reviewer"]:
        raise StopLoop(
            "continuation-mismatch", "Prior ledger target/reviewer differs; it is archived."
        )
    ledger["prior_rounds"] = prior.get("prior_rounds", []) + prior.get("rounds", [])
    ledger["decisions"] = prior.get("decisions", []) + ledger["decisions"]
    for finding_id, old in prior.get("findings", {}).items():
        finding = dict(old)
        finding["rounds_seen"] = []
        finding["seen_prior"] = old.get("seen_prior", []) + old.get("rounds_seen", [])
        finding["fixed_rounds"] = []
        finding["fixed_prior"] = old.get("fixed_prior", 0) + len(old.get("fixed_rounds", []))
        ledger["findings"][finding_id] = finding
    notes.append(f"Loaded prior ledger: {len(ledger['findings'])} findings carried over.")


def normalized_file(value: str) -> str:
    return re.sub(r"^\./", "", value).strip()


def normalized_class(value: str) -> str:
    return re.sub(r"[^a-z0-9]+", "-", value.lower().strip()).strip("-")


def identity(finding: Finding) -> str:
    return (
        f"{normalized_file(finding.file)}:{finding.line}:{normalized_class(finding.defect_class)}"
    )


def coarse_identity(finding: Finding) -> str:
    return normalized_file(finding.file) + "::" + normalized_class(finding.defect_class)


def clip(value: str, limit: int) -> str:
    return value[:limit] + "…" if len(value) > limit else value


def existing_finding(
    ledger: dict[str, Any], raw: Finding, round_number: int
) -> dict[str, Any] | None:
    findings = ledger["findings"]
    given = raw.id.strip()
    if given in findings:
        return findings[given]
    computed = identity(raw)
    if computed in findings:
        return findings[computed]
    candidates = [
        item
        for item in findings.values()
        if item["coarse"] == coarse_identity(raw)
        and round_number not in item.get("rounds_seen", [])
    ]
    return candidates[0] if len(candidates) == 1 else None


def merge_review(ledger: dict[str, Any], round_number: int, review: Review) -> None:
    if not review.summary.strip():
        raise StopLoop("reviewer-failed", "Reviewer returned an empty summary.")
    for raw in review.findings:
        if not normalized_file(raw.file) or not normalized_class(raw.defect_class):
            raise StopLoop("reviewer-failed", "Finding lacks a file or stable defect class.")
    for item in ledger["findings"].values():
        if item["status"] == "fixed" and not item["verified"]:
            refiled = any(
                existing_finding(ledger, raw, round_number) is item for raw in review.findings
            )
            if item["id"] not in review.verified_fixed and not refiled:
                raise StopLoop(
                    "reviewer-incomplete",
                    "Required fix verification was omitted: " + item["id"],
                )
    fresh = reopened = refiled_rejected = 0
    for raw_id in review.verified_fixed:
        found = ledger["findings"].get(raw_id.strip())
        if found and found["status"] == "fixed":
            found["verified"] = True
    for raw in review.findings:
        found = existing_finding(ledger, raw, round_number)
        if found is None:
            finding_id = identity(raw)
            ledger["findings"][finding_id] = {
                "id": finding_id,
                "coarse": coarse_identity(raw),
                "file": normalized_file(raw.file),
                "line": raw.line,
                "class": normalized_class(raw.defect_class),
                "severity": raw.severity,
                "title": clip(raw.title, 200),
                "evidence": clip(raw.evidence, 400),
                "status": "open",
                "verdict_reason": "",
                "verified": False,
                "first_round": round_number,
                "last_round": round_number,
                "rounds_seen": [round_number],
                "fixed_rounds": [],
                "refiled_after_verdict": 0,
                "notes": [],
            }
            fresh += 1
            continue
        if found["status"] == "rejected" and not raw.new_evidence:
            found["refiled_after_verdict"] += 1
            refiled_rejected += 1
            continue
        if found["status"] == "deferred":
            if raw.severity not in BLOCKING:
                continue
            found["notes"].append(
                f"round {round_number}: severity raised to {raw.severity}, reopened"
            )
        if found["status"] == "rejected":
            found["notes"].append(f"round {round_number}: reopened with new evidence")
        if found["status"] == "fixed":
            found["notes"].append(f"round {round_number}: fix did not hold, reopened")
            reopened += 1
        found.update(
            status="open",
            verified=False,
            line=raw.line,
            severity=raw.severity,
            evidence=clip(raw.evidence, 400),
            last_round=round_number,
        )
        found["rounds_seen"].append(round_number)
    ledger["rounds"].append(
        {
            "round": round_number,
            "type": "review",
            "open": severity_counts(ledger),
            "new": fresh,
            "reopened": reopened,
            "refiled_rejected": refiled_rejected,
        }
    )


def merge_verdicts(
    ledger: dict[str, Any], round_number: int, fixed: Fix, ids: list[str], diff_file: str
) -> list[str]:
    tally = {"fixed": 0, "rejected": 0, "deferred": 0}
    seen: set[str] = set()
    structural = []
    for verdict in fixed.verdicts:
        finding_id = verdict.id.strip()
        if finding_id not in ids or finding_id in seen:
            raise StopLoop("fixer-invalid-result", "Verdicts contain an unknown or duplicate id.")
        seen.add(finding_id)
    seen.clear()
    for verdict in fixed.verdicts:
        finding_id = verdict.id.strip()
        found = ledger["findings"][finding_id]
        seen.add(finding_id)
        if verdict.verdict == "fixed":
            found.update(status="fixed", verified=False, pin=clip(verdict.pin, 300))
            found["fixed_rounds"].append(round_number)
            tally["fixed"] += 1
        elif verdict.verdict == "rejected":
            found.update(status="rejected", verdict_reason=clip(verdict.reason, 400))
            if verdict.structural and found["severity"] in BLOCKING:
                found["structural"] = True
                structural.append(finding_id)
            tally["rejected"] += 1
        else:
            if found["severity"] in BLOCKING:
                found["notes"].append(
                    f"round {round_number}: fixer deferred a {found['severity']} "
                    "finding — kept open"
                )
            else:
                found.update(status="deferred", verdict_reason=clip(verdict.reason, 400))
            tally["deferred"] += 1
    ledger["rounds"].append(
        {
            "round": round_number,
            "type": "fix",
            "verdicts": tally,
            "unaddressed": [finding_id for finding_id in ids if finding_id not in seen],
            "failed": False,
            "diff_file": diff_file,
        }
    )
    return structural


def failed_fix(ledger: dict[str, Any], round_number: int, ids: list[str], error: str) -> None:
    ledger["rounds"].append(
        {
            "round": round_number,
            "type": "fix",
            "verdicts": {"fixed": 0, "rejected": 0, "deferred": 0},
            "unaddressed": ids,
            "failed": True,
            "diff_file": "",
            "error": error,
        }
    )


def three_consecutive(rounds: list[int]) -> bool:
    values = set(rounds)
    return any(value + 1 in values and value + 2 in values for value in values)


def escalation(
    kind: str, message: str, ids: list[str], round_number: int, ledger: dict[str, Any]
) -> dict[str, Any]:
    return {
        "type": kind,
        "round": round_number,
        "finding_ids": ids or [finding["id"] for finding in open_blocking(ledger)],
        "message": (
            message
            + " This needs a design decision, not another fix round. Do not weaken documented "
            "guarantees. Continue with the user's ruling verbatim in decision; the stable "
            "ledger preserves findings and verdicts."
        ),
    }


def protocol_record(filename: str) -> dict[str, str]:
    if not filename.strip():
        return {"error": "No original protocol file was configured."}
    path = Path(filename).expanduser().resolve()
    try:
        payload = path.read_bytes()
        text = payload.decode("utf-8")
    except (OSError, UnicodeError) as exc:
        return {"error": f"Cannot read protocol {path}: {exc}"}
    if not text.strip():
        return {"error": f"Original protocol file is empty: {path}"}
    return {"path": str(path), "sha256": hashlib.sha256(payload).hexdigest()}


def protocol_path(record: dict[str, str], name: str) -> Path:
    if "error" in record:
        raise StopLoop(
            "reviewer-unavailable",
            f"Original instructions for {name} are required: {record['error']} "
            "Configure its actual protocol file and native role; no substitute review was used.",
        )
    path = Path(record["path"])
    try:
        current = hashlib.sha256(path.read_bytes()).hexdigest()
    except OSError as exc:
        raise StopLoop("reviewer-unavailable", f"Protocol for {name} disappeared: {exc}") from exc
    if current != record["sha256"]:
        raise StopLoop("reviewer-unavailable", f"Pinned runtime protocol for {name} changed.")
    return path


def check_protocol_bindings(
    reviewer_protocol: dict[str, str],
    reviewer_name: str,
    specialists: dict[str, dict[str, str]],
) -> None:
    protocol_path(reviewer_protocol, reviewer_name)
    for name, binding in specialists.items():
        if "error" not in binding:
            protocol_path(binding, name)


def native_context(
    task: str,
    data: dict[str, Any],
    root: Path,
    references: tuple[Path, ...],
) -> Any:
    return prepare_context(
        task,
        prior_results=json.dumps(data, ensure_ascii=False),
        files=references,
        readable_roots=(root, *references),
        byte_budget=65536,
    )


@step
def perform_review(
    root: str,
    target: str,
    reviewer_kind: Literal["agent", "skill"],
    reviewer_name: str,
    reviewer_notes: str,
    reviewer_protocol: dict[str, str],
    specialists: dict[str, dict[str, str]],
    ledger: dict[str, Any],
    round_number: int,
    final_round: bool,
    references: tuple[Path, ...],
    out: str,
    prefix: str,
    artifacts: list[str],
    notes: list[str],
) -> Review:
    directory = Path(root)
    transcript: list[dict[str, Any]] = []
    wave = 0
    while True:
        check_protocol_bindings(reviewer_protocol, reviewer_name, specialists)
        data = {
            "target": target,
            "git_root": root,
            "reviewer": {"kind": reviewer_kind, "name": reviewer_name, "notes": reviewer_notes},
            "reviewer_original_protocol": reviewer_protocol,
            "round": round_number,
            "final_review_only_round": final_round,
            "ledger": ledger,
            "specialist_original_protocols": specialists,
            "specialist_protocols_available": sorted(specialists),
            "specialist_waves_used": wave,
            "specialist_waves_remaining": 3 - wave,
            "conversation": transcript,
        }
        task = (
            "Perform the requested original reviewer's complete review of the whole target. "
            "The complete original protocol identified by reviewer_original_protocol is "
            "supplied among the context files and is authoritative for your methodology. "
            "Other named protocols are references for their corresponding roles, not "
            "substitutes for yours. The pinned improve.js supplies the review and continuation "
            "contracts. Preserve the original reasoning order and all required checks. "
            "Complete embedded context is usable directly; read saved task.txt or reference "
            "files when not embedded. All configured valid protocol files are passed in full; "
            "a dispatch name never expands the filesystem view. The whole repository view "
            "is available; scope limits edits, not review candidates. Review every severity, "
            "mapping to critical/major/minor/info. Use defect_class for the source schema's "
            "class field. Apply the full persisted ledger discipline, including fix "
            "verification, exact known ids, rejection reasons and new evidence, deferred "
            "findings, and binding user decisions. Read current code to verify fixes. "
            "Do not write or fix files. Do not declare unperformed checks complete. If the "
            "original methodology needs an unavailable essential dependency, return a summary "
            "starting REVIEWER-UNAVAILABLE: with the precise dependency and no substitute review."
        )
        if reviewer_kind == "skill":
            task += (
                " Native roles cannot invoke platform Skill/Task. Apply the full supplied "
                "skill protocol directly. For its named specialist work, return mode dispatch "
                "and agents with agent_type, full self-contained prompt, and label. The host "
                "runs at most eight per wave and at most three waves. Keep findings empty "
                "during dispatch. Continue the same connected review using the complete "
                "conversation and reports. Failures are not completed required checks. Use "
                "mode direct and an empty agents list only for the finished review."
            )
        context = native_context(task, data, directory, references)
        if reviewer_kind == "skill":
            response = agent(
                "reviewer",
                task,
                working_directory=directory,
                readable_paths=(directory,),
                required_capabilities=("commands",),
                context=context,
                output=SkillReview,
                timeout=3600,
            )
            review = Review(response.findings, response.verified_fixed, response.summary)
            mode = response.mode
            requested = response.agents
            raw_response = response.model_dump()
        else:
            review = agent(
                "reviewer",
                task,
                working_directory=directory,
                readable_paths=(directory,),
                required_capabilities=("commands",),
                context=context,
                output=Review,
                timeout=3600,
            )
            mode = "direct"
            requested = []
            raw_response = review.model_dump()
        transcript.append({"reviewer_response": raw_response})
        save_json(Path(out), f"{prefix}/review-round-{round_number}.json", transcript, artifacts)
        if review.summary.startswith("REVIEWER-UNAVAILABLE:"):
            raise StopLoop("reviewer-unavailable", review.summary)
        if not review.summary.strip():
            raise StopLoop("reviewer-failed", "Reviewer returned an empty response summary.")
        if mode == "direct":
            if requested:
                raise StopLoop("reviewer-failed", "A direct review still requested specialists.")
            return review
        if not requested or wave >= 3:
            raise StopLoop(
                "reviewer-failed", "Empty specialist dispatch or three-wave cap exceeded."
            )
        wave += 1
        plan = requested[:8]
        deferred = requested[8:]
        if deferred:
            notes.append(
                f"Review {round_number}, wave {wave}: {len(deferred)} requests exceed the "
                "eight-agent wave cap; full requests are retained in the continuation."
            )
        for request in plan:
            if request.agent_type not in specialists:
                raise StopLoop(
                    "reviewer-unavailable",
                    f"Required named specialist {request.agent_type} has no trusted original "
                    "protocol binding. Supply specialist_protocols[name] with its full protocol.",
                )
            binding = specialists[request.agent_type]
            if "error" in binding:
                raise StopLoop(
                    "reviewer-unavailable",
                    f"Required named specialist {request.agent_type}: {binding['error']} "
                    "Supply its actual original protocol; no substitute was dispatched.",
                )

        def dispatch(request: Dispatch) -> SpecialistReport:
            assignment = (
                "Act as the actual named specialist identified in specialist_name. Its full "
                "original protocol, identified by original_protocol_binding, is supplied in "
                "the context files. That named protocol is authoritative for your role. "
                "Follow it and the complete requested assignment in order. Other protocols "
                "belong to their named roles and do not replace yours. Read the whole assigned "
                "target; observations do not restrict semantic candidates. Do not edit files "
                "or invoke platform Skill/Task. Report the actual work and any unavailable "
                "required dependency or failure honestly. Begin REVIEWER-UNAVAILABLE: when "
                "an essential named dependency cannot be represented or is unavailable."
            )
            specialist_data = {
                "specialist_name": request.agent_type,
                "original_protocol_binding": specialists[request.agent_type],
                "assignment": request.prompt,
                "target": target,
                "scope": ledger["scope"],
                "ledger": ledger,
                "review_conversation": transcript,
            }
            specialist_context = native_context(assignment, specialist_data, directory, references)
            try:
                report = agent(
                    "specialist",
                    assignment,
                    working_directory=directory,
                    readable_paths=(directory,),
                    required_capabilities=("commands",),
                    context=specialist_context,
                    output=str,
                    timeout=3600,
                )
            except Exception as exc:
                propagate_interruption(exc)
                return SpecialistReport(request.agent_type, request.label, False, "", str(exc))
            unavailable = report.startswith("REVIEWER-UNAVAILABLE:")
            return SpecialistReport(
                request.agent_type,
                request.label,
                bool(report.strip()) and not unavailable,
                report,
                report if unavailable else ("" if report.strip() else "Returned nothing"),
            )

        reports = parallel(dispatch, plan, max_workers=8)
        transcript.append(
            {
                "specialist_wave": wave,
                "requests": [request.model_dump() for request in plan],
                "deferred_over_cap": [request.model_dump() for request in deferred],
                "reports": [report.model_dump() for report in reports],
            }
        )
        save_json(Path(out), f"{prefix}/review-round-{round_number}.json", transcript, artifacts)
        unavailable_reports = [
            report for report in reports if report.error.startswith("REVIEWER-UNAVAILABLE:")
        ]
        if unavailable_reports:
            raise StopLoop("reviewer-unavailable", unavailable_reports[0].error)


def plugin_metadata(root: Path, target: Path) -> dict[str, Any]:
    result: dict[str, Any] = {
        "plugin_dir": "",
        "plugin_file": "",
        "plugin_version": "",
        "marketplace_file": "",
        "marketplace_indices": [],
    }
    for directory in (target, *target.parents):
        if directory != root and not directory.is_relative_to(root):
            break
        candidate = directory / ".claude-plugin" / "plugin.json"
        if candidate.is_file():
            rel = candidate.relative_to(root).as_posix()
            checked = repo_path(root, rel)
            if checked.is_symlink():
                raise StopLoop("unsupported-metadata", "Plugin metadata must be a regular file.")
            document = json.loads(checked.read_text(encoding="utf-8"))
            result.update(
                plugin_dir=str(directory),
                plugin_file=rel,
                plugin_version=str(document.get("version") or ""),
            )
            break
    marketplace = root / ".claude-plugin" / "marketplace.json"
    if result["plugin_dir"] and marketplace.is_file():
        document = json.loads(marketplace.read_text(encoding="utf-8"))
        for index, entry in enumerate(document.get("plugins", [])):
            source = entry.get("source") if isinstance(entry, dict) else None
            if isinstance(source, str) and (root / source).resolve() == Path(result["plugin_dir"]):
                result["marketplace_indices"].append(index)
        if result["marketplace_indices"]:
            result["marketplace_file"] = marketplace.relative_to(root).as_posix()
    return result


def next_version(version: str, increment: Literal["patch", "minor", "major"]) -> str:
    matched = re.fullmatch(r"(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)", version)
    if matched is None:
        raise StopLoop(
            "unsupported-version",
            f"Cannot mechanically increment {version!r}; disable version_bump or provide "
            "a supported numeric major.minor.patch baseline after owner review.",
        )
    major, minor, patch = (int(value) for value in matched.groups())
    if increment == "major":
        return f"{major + 1}.0.0"
    if increment == "minor":
        return f"{major}.{minor + 1}.0"
    return f"{major}.{minor}.{patch + 1}"


def metadata_files(metadata: dict[str, Any]) -> list[str]:
    return [metadata[key] for key in ("plugin_file", "marketplace_file") if metadata.get(key)]


def apply_version(root: Path, metadata: dict[str, Any], version: str) -> None:
    files: list[dict[str, Any]] = [
        {"path": str(repo_path(root, metadata["plugin_file"])), "kind": "plugin", "indices": []}
    ]
    if metadata["marketplace_file"]:
        files.append(
            {
                "path": str(repo_path(root, metadata["marketplace_file"])),
                "kind": "marketplace",
                "indices": metadata["marketplace_indices"],
            }
        )
    for item in files:
        path = Path(item["path"])
        if path.is_symlink() or not path.is_file():
            raise StopLoop("unsupported-metadata", f"Metadata is not a regular file: {path}")
    command = run_command(
        [sys.executable, "-c", METADATA_UPDATE, json.dumps({"files": files, "version": version})],
        timeout_seconds=60,
        working_directory=root,
        mutating=True,
    )
    if command.exit_code:
        raise StopLoop("finalize-failed", "Metadata bump failed: " + command.stderr)


def metadata_versions(root: Path, metadata: dict[str, Any]) -> dict[str, Any]:
    versions: dict[str, Any] = {}
    if metadata["plugin_file"]:
        document = json.loads(repo_path(root, metadata["plugin_file"]).read_text(encoding="utf-8"))
        versions[metadata["plugin_file"]] = document.get("version")
    if metadata["marketplace_file"]:
        document = json.loads(
            repo_path(root, metadata["marketplace_file"]).read_text(encoding="utf-8")
        )
        versions[metadata["marketplace_file"]] = [
            document["plugins"][index].get("version") for index in metadata["marketplace_indices"]
        ]
    return versions


def narration_observations(root: Path, files: list[str]) -> list[dict[str, Any]]:
    observations = []
    for rel in files:
        try:
            text = repo_path(root, rel).read_text(encoding="utf-8")
        except UnicodeDecodeError:
            continue
        for expression in NARRATION:
            for matched in re.finditer(expression, text, flags=re.IGNORECASE):
                observations.append(
                    {
                        "file": rel,
                        "line": text.count("\n", 0, matched.start()) + 1,
                        "pattern": expression,
                        "match": matched.group(0),
                    }
                )
    return observations


def initialize_repository(
    target: Path,
    initialization_root: str,
    authorized: bool,
    out: Path,
    notes: list[str],
) -> Path:
    existing = git(target, ["rev-parse", "--show-toplevel"])
    if existing.exit_code == 0:
        return Path(existing.stdout.strip()).resolve()
    if not authorized or not initialization_root.strip():
        raise StopLoop(
            "git-baseline-unavailable",
            "Target is outside git. Initialization and its baseline commit require explicit "
            "initialize_git=True and an explicit initialization_root. No repository was created.",
        )
    root = Path(initialization_root).expanduser().resolve()
    if not root.is_dir() or root == Path(root.anchor) or not target.is_relative_to(root):
        raise StopLoop(
            "invalid-initialization-root", "Initialization root must contain the target."
        )
    notes.append(
        f"Explicitly authorized git initialization at {root}, including a baseline commit."
    )
    git_text(root, ["init"], mutate=True)
    notes.append(f"A git repository was INITIALIZED at {root}; this must be disclosed.")
    additions = ["add", "--all", "--", "."]
    if out.is_relative_to(root):
        rel = out.relative_to(root).as_posix()
        additions.append(":(exclude)" + rel + "/**")
    git_text(root, additions, mutate=True)
    git_text(
        root,
        [
            "-c",
            "user.name=code-improver-baseline",
            "-c",
            "user.email=code-improver@trailofbits.com",
            "commit",
            "--allow-empty",
            "--message",
            "Baseline snapshot for explicitly authorized improvement run",
        ],
        mutate=True,
    )
    return Path(git_text(target, ["rev-parse", "--show-toplevel"]).strip()).resolve()


@step
def finalize_run(
    root: str,
    target: str,
    scope: list[str],
    out_rel: str,
    baseline: dict[str, Any],
    metadata: dict[str, Any],
    expected_version: str,
    narration_strip: bool,
    docs_pass: bool,
    reviewer_name: str,
    reviewer_protocol: dict[str, str],
    references: tuple[Path, ...],
    ledger: dict[str, Any],
    result: RunResult,
    out: str,
    prefix: str,
    artifacts: list[str],
) -> None:
    directory = Path(root)
    output = Path(out)
    patterns = scope_patterns(scope)
    initial_guard = check_scope(root, baseline, scope, out_rel)
    enforce_guard(initial_guard, result, registered=True)
    before = snapshot(directory, baseline["head_sha"], patterns, out_rel, contents=True)
    save_json(output, f"{prefix}/pre-finalize-files.json", before, artifacts)
    save_text(output, f"{prefix}/pre-finalize.diff", before["diff"], artifacts)
    versions_before = metadata_versions(directory, metadata)
    observations = narration_observations(directory, before["scope_files"])
    result.partial_unreviewed_edits = True
    checkpoint(output, ledger, result, artifacts)
    worker_error = ""
    finalized: Finalize | None = None
    try:
        if expected_version:
            apply_version(directory, metadata, expected_version)
        assignment = (
            "Perform only the pinned improve.js finalization mandate over the whole authorized "
            "scope. Read its complete finalization instructions and the fixer safety contract. "
            "Interpret the supplied narration matches in context; they are observations, not "
            "an exhaustive semantic candidate list. Leave legitimate algorithm, tournament, "
            "historical changelog, or otherwise arguable content intact. Strip narration only "
            "when enabled. Read complete scoped documentation and correct statements made "
            "false by this run only when docs_pass is enabled. Do not weaken documented "
            "guarantees, refactor, or make additional fixes. The host performs the exact "
            "metadata bump before your session; do not change any version fields. Report the "
            "expected version, or an empty version when disabled, actual narration sites "
            "removed, and notes. Respect scope and git safety, register newly created files "
            "with git add -N, and leave all bookkeeping and snapshots to the host."
        )
        context = native_context(
            assignment,
            {
                "target": target,
                "scope": scope,
                "ledger": ledger,
                "narration_strip": narration_strip,
                "docs_pass": docs_pass,
                "expected_version": expected_version,
                "metadata": metadata,
                "narration_observations": observations,
                "pre_finalize_state": before,
            },
            directory,
            references,
        )
        finalized = agent(
            "worker",
            assignment,
            working_directory=directory,
            readable_paths=(directory,),
            writable_paths=(directory,),
            required_capabilities=("commands",),
            context=context,
            output=Finalize,
            timeout=3600,
        )
    except Exception as exc:
        propagate_interruption(exc)
        worker_error = str(exc)
        result.notes.append(
            "Finalization failed; partial edits are checked anyway: " + worker_error
        )
    if finalized is not None:
        ledger["finalize"] = {
            "narration_sites_removed": finalized.narration_sites_removed,
            "version": finalized.version,
            "notes": clip(finalized.notes, 500),
        }
        save_json(output, f"{prefix}/finalize.json", finalized.model_dump(), artifacts)
        if finalized.notes:
            result.notes.append(finalized.notes)
    guard = check_scope(root, baseline, scope, out_rel)
    save_json(output, f"{prefix}/finalize-scope.json", guard.model_dump(), artifacts)
    after = snapshot(directory, baseline["head_sha"], patterns, out_rel, contents=True)
    save_json(output, f"{prefix}/post-finalize-files.json", after, artifacts)
    save_text(output, f"{prefix}/post-finalize.diff", after["diff"], artifacts)
    delta = "".join(
        difflib.unified_diff(
            before["diff"].splitlines(keepends=True),
            after["diff"].splitlines(keepends=True),
            fromfile="pre-finalize.diff",
            tofile="post-finalize.diff",
        )
    )
    changed_sites = [
        rel
        for rel in sorted(set(before["files"]) | set(after["files"]))
        if before["files"].get(rel) != after["files"].get(rel)
    ]
    save_text(output, f"{prefix}/finalization-delta.diff", delta, artifacts)
    checkpoint(output, ledger, result, artifacts)
    enforce_guard(guard, result, registered=True)
    protocol_path(reviewer_protocol, reviewer_name)
    assignment = (
        "Independently check the pinned improve.js finalization mandate and regression "
        "criteria. Apply the complete original reviewer protocol identified by "
        "reviewer_original_protocol in the supplied context files wherever relevant, "
        "retaining its reasoning and checks. Read every actual finalize edit and current "
        "surrounding content. Complete before/after file texts, git/index snapshots and "
        "the difference between cumulative diffs are provided; existing untracked-file "
        "edits also appear in the file snapshots. Check legitimate content removed as "
        "narration, unsupported documentation, the exact version rule, and edits outside "
        "the finalize mandate. Scope is nonempty even when no edits were needed: verify "
        "the enabled mandates against the current scoped files. Return every regression "
        "site as file/line/why, and a summary. Do not edit files. An empty regression list "
        "requires completed reading and sound edits; do not claim unperformed checks. "
        "Return a summary starting REVIEWER-UNAVAILABLE: if an essential original-protocol "
        "dependency is unavailable."
    )
    context = native_context(
        assignment,
        {
            "target": target,
            "scope": scope,
            "ledger": ledger,
            "reviewer_original_protocol": reviewer_protocol,
            "before": before,
            "after": after,
            "changed_sites": changed_sites,
            "cumulative_diff_delta": delta,
            "narration_strip": narration_strip,
            "docs_pass": docs_pass,
            "expected_version": expected_version,
            "metadata": metadata,
            "versions_before": versions_before,
            "finalizer_error": worker_error,
        },
        directory,
        references,
    )
    check = agent(
        "reviewer",
        assignment,
        working_directory=directory,
        readable_paths=(directory,),
        required_capabilities=("commands",),
        context=context,
        output=FinalizeCheck,
        timeout=3600,
    )
    save_json(output, f"{prefix}/finalize-check.json", check.model_dump(), artifacts)
    if check.summary.startswith("REVIEWER-UNAVAILABLE:"):
        raise StopLoop("reviewer-unavailable", check.summary)
    if not check.summary.strip():
        raise StopLoop("finalize-check-failed", "Independent finalization check was incomplete.")
    regressions = list(check.regressions)
    versions_after = metadata_versions(directory, metadata)
    if expected_version:
        for rel, actual in versions_after.items():
            values = actual if isinstance(actual, list) else [actual]
            if any(value != expected_version for value in values):
                regressions.append(Regression(rel, 1, "Version does not equal " + expected_version))
    elif versions_after != versions_before:
        for rel in metadata_files(metadata):
            if versions_before.get(rel) != versions_after.get(rel):
                regressions.append(Regression(rel, 1, "Version handling was disabled."))
    if finalized is not None and finalized.version != expected_version:
        worker_error = "Finalizer's reported version disagrees with the configured version rule."
    final_guard = check_scope(root, baseline, scope, out_rel)
    enforce_guard(final_guard, result, registered=True)
    if regressions:
        result.finalize_regressions = regressions
        raise StopLoop(
            "finalize-regression",
            "Finalization introduced regressions; named edits remain in the working tree.",
        )
    if worker_error:
        raise StopLoop("finalize-failed", worker_error)
    result.partial_unreviewed_edits = False
    result.converged = True


def collect_exit_metrics(
    out: Path,
    prefix: str,
    root: Path | None,
    baseline: dict[str, Any] | None,
    scope: list[str],
    result: RunResult,
    artifacts: list[str],
    *,
    interrupted: bool,
) -> dict[str, Any]:
    error = ""
    if interrupted:
        error = (
            "Run interrupted; metrics collection was not executed. Last checkpoint is preserved."
        )
    else:
        argv = [
            "uv",
            "run",
            "--no-project",
            str(resource("scripts/collect_metrics.py")),
            "--ledger",
            str(out / "ledger.json"),
            "--out",
            str(out / "metrics.json"),
            "--diff-dir",
            str(out / prefix),
        ]
        if root is not None and baseline is not None:
            argv.extend(["--repo", str(root), "--baseline-sha", baseline["head_sha"]])
            for glob in scope:
                argv.extend(["--scope", glob])
        try:
            command = run_command(
                argv,
                timeout_seconds=120,
                working_directory=root if root is not None else Path.cwd(),
                mutating=True,
            )
            save_json(
                out,
                f"{prefix}/metrics-command.json",
                {
                    "argv": command.argv,
                    "exit_code": command.exit_code,
                    "stdout": command.stdout,
                    "stderr": command.stderr,
                },
                artifacts,
            )
            if command.exit_code:
                error = command.stderr or command.stdout or "Metrics collector failed."
            elif not (out / "metrics.json").is_file():
                error = "Metrics collector produced no metrics.json."
            else:
                metrics = json.loads((out / "metrics.json").read_text(encoding="utf-8"))
                if not isinstance(metrics, dict) or "rounds_used" not in metrics:
                    error = "Metrics collector produced an invalid metrics object."
                else:
                    if "metrics.json" not in artifacts:
                        artifacts.append("metrics.json")
                    return metrics
        except Exception as exc:
            propagate_interruption(exc)
            error = "Metrics collection requires the pinned helper and uv: " + str(exc)
    result.artifacts_complete = False
    result.notes.append("METRICS INCOMPLETE: " + error)
    metrics = {"valid": False, "error": error, "converged_claim": False}
    save_json(out, "metrics.json", metrics, artifacts)
    return metrics


@recipe(
    name="code_improver",
    version="1",
    capabilities=("Bash",),
    agents=("worker", "reviewer", "specialist"),
    budget=Budget(max_agent_calls=1220, max_wall_seconds=3600),
    output_root=".code-improver",
)
def code_improver(
    target: str,
    reviewer_name: str,
    reviewer_kind: Literal["agent", "skill"],
    reviewer_protocol: str,
    scope: list[str],
    specialist_protocols: dict[str, str] | None = None,
    reviewer_notes: str = "",
    max_rounds: int = 5,
    decision: str = "",
    initialize_git: bool = False,
    initialization_root: str = "",
    version_bump: bool | None = None,
    version_increment: Literal["patch", "minor", "major"] = "patch",
    narration_strip: bool = True,
    docs_pass: bool = True,
) -> RunResult:
    target_dir = Path(target).expanduser().resolve()
    identity_text = json.dumps([str(target_dir), reviewer_kind, reviewer_name])
    suffix = hashlib.sha256(identity_text.encode("utf-8")).hexdigest()[:12]
    label = re.sub(r"[^A-Za-z0-9_.-]+", "-", target_dir.name) or "target"
    job = label + "-" + suffix
    prefix = "runs/" + uuid.uuid4().hex
    run_files = [
        "prior-ledger.json",
        "baseline.json",
        "pre-finalize-files.json",
        "post-finalize-files.json",
        "pre-finalize.diff",
        "post-finalize.diff",
        "finalization-delta.diff",
        "finalize.json",
        "finalize-scope.json",
        "finalize-check.json",
        "exit-scope.json",
        "metrics-command.json",
    ]
    for round_number in range(1, 22):
        run_files.extend(
            [
                f"review-round-{round_number}.json",
                f"fixer-round-{round_number}.json",
                f"scope-round-{round_number}.json",
                f"fixes-round-{round_number}.diff",
            ]
        )
    root_files = ["ledger.json", "ledger.md", "status.md", "result.json", "metrics.json"]
    planned = tuple(root_files + [prefix + "/" + name for name in run_files])
    out = ensure_directory(job, output_files=planned, overwrite=True)
    ensure_directory(Path(job) / prefix, output_files=tuple(run_files), overwrite=True)
    artifacts: list[str] = []
    result = RunResult(
        converged=False,
        capped=False,
        halted="",
        escalation=None,
        violations=[],
        finalize_regressions=[],
        rounds_run=0,
        fix_rounds=0,
        fixer_failed_rounds=[],
        open_blocking=[],
        open_minor_count=0,
        new_untracked_files=[],
        ledger_path=str(out / "ledger.json"),
        out_dir=str(out),
        metrics=str(out / "metrics.json"),
        notes=[],
        partial_unreviewed_edits=False,
        artifacts_complete=True,
        status_path=str(out / "status.md"),
        ledger_markdown=str(out / "ledger.md"),
        baseline_path=str(out / prefix / "baseline.json"),
    )
    ledger: dict[str, Any] = {
        "version": 1,
        "target": str(target_dir),
        "reviewer": {"kind": reviewer_kind, "name": reviewer_name},
        "scope": list(scope),
        "decisions": [decision] if decision else [],
        "prior_rounds": [],
        "rounds": [],
        "findings": {},
        "result": None,
    }
    root: Path | None = None
    baseline: dict[str, Any] | None = None
    out_rel = ""
    active_phase = "baseline"
    active_round = 0
    dispatched_ids: list[str] = []
    pending: BaseException | None = None
    interrupted = False
    metrics: dict[str, Any] = {}
    try:
        prior_file = out / "ledger.json"
        if prior_file.is_file():
            prior_raw = prior_file.read_text(encoding="utf-8")
            save_text(out, prefix + "/prior-ledger.json", prior_raw, artifacts)
            load_prior(ledger, prior_raw, result.notes)
        checkpoint(out, ledger, result, artifacts)
        if not target_dir.is_dir():
            raise StopLoop(
                "invalid-target", "Target must be an existing directory: " + str(target_dir)
            )
        if not reviewer_name.strip():
            raise StopLoop(
                "reviewer-required", "The user must explicitly name the actual reviewer."
            )
        if not 1 <= max_rounds <= 20:
            raise StopLoop("invalid-round-cap", "max_rounds must be between 1 and 20.")
        patterns = scope_patterns(scope)
        pinned_references = (resource("workflows/improve.js"), resource("agents/fixer.md"))
        for path in (*pinned_references, resource("scripts/collect_metrics.py")):
            if not path.read_text(encoding="utf-8").strip():
                raise StopLoop("missing-resource", "Pinned resource is empty: " + str(path))
        reviewer_binding = protocol_record(reviewer_protocol)
        reviewer_file = protocol_path(reviewer_binding, reviewer_name)
        specialist_bindings = {
            name: protocol_record(filename)
            for name, filename in (specialist_protocols or {}).items()
        }
        protocol_files = [reviewer_file]
        for name, binding in specialist_bindings.items():
            if "error" not in binding:
                protocol_files.append(protocol_path(binding, name))
        references = (*pinned_references, *protocol_files)
        root = initialize_repository(
            target_dir, initialization_root, initialize_git, out, result.notes
        )
        if not target_dir.is_relative_to(root):
            raise StopLoop("invalid-git-root", "Git root does not contain the target.")
        out_rel = out.relative_to(root).as_posix() if out.is_relative_to(root) else ""
        meaningful_target = [
            path
            for path in target_dir.rglob("*")
            if path.is_file()
            and ".git" not in path.relative_to(target_dir).parts
            and not path.is_relative_to(out)
        ]
        if not meaningful_target:
            raise StopLoop("empty-target", "Target contains zero files to inspect.")
        sha = git_text(root, ["rev-parse", "HEAD"]).strip()
        if not sha:
            raise StopLoop("git-baseline-unavailable", "Repository has no immutable HEAD.")
        baseline = snapshot(root, sha, patterns, out_rel)
        metadata = plugin_metadata(root, target_dir)
        baseline["target_dir"] = str(target_dir)
        baseline["metadata"] = metadata
        baseline["scope"] = list(scope)
        baseline["artifact_exclusion"] = out_rel
        baseline["reviewer_protocol"] = reviewer_binding
        baseline["specialist_protocols"] = specialist_bindings
        baseline["run_artifacts"] = prefix
        ledger["baseline"] = {
            "sha": sha,
            "git_root": str(root),
            "snapshot_path": str(out / prefix / "baseline.json"),
            "run_artifacts": prefix,
        }
        save_json(out, prefix + "/baseline.json", baseline, artifacts)
        if not baseline["scope_files"]:
            raise StopLoop(
                "empty-inspection-scope",
                "Explicit scope matches zero inspectable repository files.",
            )
        bump_enabled = bool(metadata["plugin_version"]) if version_bump is None else version_bump
        expected_version = ""
        if bump_enabled:
            if not metadata["plugin_file"]:
                raise StopLoop(
                    "unsupported-version", "Version bump requested without plugin metadata."
                )
            for rel in metadata_files(metadata):
                if not in_scope(rel, patterns):
                    raise StopLoop(
                        "version-bump-outside-scope",
                        "Exactly one consistent metadata bump requires explicit scope for " + rel,
                    )
            expected_version = next_version(metadata["plugin_version"], version_increment)
        checkpoint(out, ledger, result, artifacts)
        counts_history: list[int] = []
        clean_review = False
        for round_number in range(1, max_rounds + 2):
            active_phase = "review"
            active_round = round_number
            checkpoint(out, ledger, result, artifacts)
            review = perform_review(
                str(root),
                str(target_dir),
                reviewer_kind,
                reviewer_name,
                reviewer_notes,
                reviewer_binding,
                specialist_bindings,
                ledger,
                round_number,
                round_number == max_rounds + 1,
                references,
                str(out),
                prefix,
                artifacts,
                result.notes,
            )
            merge_review(ledger, round_number, review)
            result.rounds_run = round_number
            result.partial_unreviewed_edits = False
            blocking = open_blocking(ledger)
            counts_history.append(len(blocking))
            checkpoint(out, ledger, result, artifacts)
            if not blocking:
                clean_review = True
                break
            recurring = [item["id"] for item in blocking if three_consecutive(item["rounds_seen"])]
            if (
                len(counts_history) >= 3
                and counts_history[-3] > 0
                and counts_history[-2] >= counts_history[-3]
                and counts_history[-1] >= counts_history[-2]
            ):
                result.escalation = escalation(
                    "counts-non-decreasing",
                    "Open blocker counts did not decrease for three reviews: "
                    + " → ".join(str(value) for value in counts_history[-3:]),
                    recurring,
                    round_number,
                    ledger,
                )
            elif recurring:
                result.escalation = escalation(
                    "recurrence",
                    "Blocking findings recurred in three consecutive review rounds.",
                    recurring,
                    round_number,
                    ledger,
                )
            if result.escalation:
                break
            if round_number == max_rounds + 1:
                result.capped = True
                result.notes.append(
                    "CAPPED, NOT CONVERGED: the final independent review still found blockers."
                )
                break
            active_phase = "fix"
            dispatched_ids = [item["id"] for item in blocking]
            result.partial_unreviewed_edits = True
            checkpoint(out, ledger, result, artifacts)
            assignment = (
                "Apply the complete pinned agents/fixer.md contract and improve.js fix-phase "
                "instructions to only the dispatched blocking findings. Preserve the "
                "original reasoning and pin requirements, including pre-fix-failing pins and "
                "table pins for heuristics. Respect scope, existing work, recorded verdicts, "
                "and binding user decisions. Return one verdict per finding with reason, pin "
                "and structural flag. Real immutable-promise conflicts require structural "
                "rejection, never weakened guarantees. Deferred blockers remain open. "
                "Register created files using git add -N. Never commit, reset, clean, stash, "
                "or checkout away work. No process narration. The host owns ledger, diffs, "
                "scope/digest checks, and metrics; do not write its artifacts."
            )
            context = native_context(
                assignment,
                {
                    "target": str(target_dir),
                    "git_root": str(root),
                    "scope": scope,
                    "ledger": ledger,
                    "dispatched": blocking,
                    "baseline_sha": sha,
                    "round": round_number,
                },
                root,
                references,
            )
            fixed: Fix | None = None
            error = ""
            try:
                fixed = agent(
                    "worker",
                    assignment,
                    working_directory=root,
                    readable_paths=(root,),
                    writable_paths=(root,),
                    required_capabilities=("commands",),
                    context=context,
                    output=Fix,
                    timeout=3600,
                )
            except Exception as exc:
                propagate_interruption(exc)
                error = str(exc)
            diff_file = f"{prefix}/fixes-round-{round_number}.diff"
            structural = []
            if fixed is not None:
                save_json(
                    out, f"{prefix}/fixer-round-{round_number}.json", fixed.model_dump(), artifacts
                )
                try:
                    structural = merge_verdicts(
                        ledger, round_number, fixed, dispatched_ids, diff_file
                    )
                except StopLoop as exc:
                    error = str(exc)
                    fixed = None
                else:
                    if fixed.notes:
                        result.notes.append(fixed.notes)
            if fixed is None:
                failed_fix(ledger, round_number, dispatched_ids, error or "Fixer returned nothing")
                result.fixer_failed_rounds.append(round_number)
                result.notes.append(
                    f"Fixer failed in round {round_number}; partial edits require the next review. "
                    + error
                )
            result.fix_rounds = round_number
            checkpoint(out, ledger, result, artifacts)
            guard = check_scope(str(root), baseline, scope, out_rel)
            save_json(
                out, f"{prefix}/scope-round-{round_number}.json", guard.model_dump(), artifacts
            )
            save_text(out, diff_file, guard.snapshot["diff"], artifacts)
            ledger["rounds"][-1]["diff_file"] = diff_file
            checkpoint(out, ledger, result, artifacts)
            enforce_guard(guard, result, registered=False)
            if structural:
                result.escalation = escalation(
                    "structural-rejection",
                    "Real blockers conflict with documented immutable demands.",
                    structural,
                    round_number,
                    ledger,
                )
                break
            refixed = [
                item["id"] for item in ledger["findings"].values() if len(item["fixed_rounds"]) >= 2
            ]
            if refixed:
                result.escalation = escalation(
                    "relocation",
                    "Findings were fixed more than once; the latest attempt is UNREVIEWED.",
                    refixed,
                    round_number,
                    ledger,
                )
                break
        if clean_review:
            active_phase = "finalize"
            checkpoint(out, ledger, result, artifacts)
            finalize_run(
                str(root),
                str(target_dir),
                scope,
                out_rel,
                baseline,
                metadata,
                expected_version,
                narration_strip,
                docs_pass,
                reviewer_name,
                reviewer_binding,
                references,
                ledger,
                result,
                str(out),
                prefix,
                artifacts,
            )
        active_phase = "finished"
    except StopLoop as exc:
        result.converged = False
        result.halted = exc.code
        result.notes.append(str(exc))
    except BaseException as exc:
        result.converged = False
        interrupted = not isinstance(exc, Exception) or type(exc).__name__ == "BudgetExceeded"
        result.halted = "interrupted" if interrupted else active_phase + "-failed"
        result.notes.append(f"{active_phase}: {type(exc).__name__}: {exc}")
        if interrupted:
            pending = exc
    finally:
        if active_phase == "fix" and not any(
            record["type"] == "fix" and record["round"] == active_round
            for record in ledger["rounds"]
        ):
            failed_fix(ledger, active_round, dispatched_ids, "Interrupted or failed fixer session")
            result.fix_rounds = active_round
            result.fixer_failed_rounds.append(active_round)
            result.partial_unreviewed_edits = True
        checkpoint(out, ledger, result, artifacts)
        if root is not None and baseline is not None and not interrupted:
            try:
                exit_guard = check_scope(str(root), baseline, scope, out_rel)
                save_json(out, prefix + "/exit-scope.json", exit_guard.model_dump(), artifacts)
                enforce_guard(exit_guard, result, registered=result.converged)
            except Exception as exc:
                if type(exc).__name__ == "BudgetExceeded":
                    interrupted = True
                    pending = exc
                    result.halted = "interrupted"
                else:
                    result.halted = exc.code if isinstance(exc, StopLoop) else "scope-check-failed"
                result.converged = False
                result.notes.append("Exit scope check: " + str(exc))
        if interrupted and active_phase in {"fix", "finalize"}:
            result.partial_unreviewed_edits = True
            result.notes.append(
                "Cancellation/deadline left the last completed persisted round intact. "
                "Current partial edits have not been certified; resume with the stable ledger."
            )
        checkpoint(out, ledger, result, artifacts)
        try:
            metrics = collect_exit_metrics(
                out, prefix, root, baseline, scope, result, artifacts, interrupted=interrupted
            )
        except BaseException as exc:
            propagate = not isinstance(exc, Exception) or type(exc).__name__ == "BudgetExceeded"
            if propagate:
                pending = exc
                result.converged = False
                result.halted = "interrupted"
            result.artifacts_complete = False
            result.notes.append("Metrics interrupted or failed: " + str(exc))
            metrics = {"valid": False, "error": str(exc), "converged_claim": False}
            save_json(out, "metrics.json", metrics, artifacts)
        checkpoint(out, ledger, result, artifacts)
        verification_errors = []
        for name in artifacts:
            try:
                verify_artifact(out / name, nonempty=not name.endswith(".diff"))
            except Exception as exc:
                if type(exc).__name__ == "BudgetExceeded":
                    pending = exc
                verification_errors.append(name + ": " + str(exc))
        if verification_errors:
            result.artifacts_complete = False
            result.converged = False
            result.halted = "artifact-verification-failed"
            result.notes.extend(verification_errors)
            metrics = {
                "valid": False,
                "error": "Artifact verification failed",
                "details": verification_errors,
            }
            save_json(out, "metrics.json", metrics, artifacts)
            checkpoint(out, ledger, result, artifacts)
        emit(ledger, name="ledger")
        emit(metrics, name="metrics")
        emit(status_text(ledger, result), name="status")
        emit(result, name="result")
    if pending is not None:
        raise pending
    return result


if __name__ == "__main__":
    raise SystemExit(code_improver.cli())


# --- calcifier metadata (skill provenance + sha256) ---
_CALCIFIER_COMPILATION = "compiled"
_CALCIFIER_SKILL = {
    "path": "../SKILL.md",
    "sha256": ("a4e33a24c853da3df13262da9bce1fd833dce694493b344e001f18df73692d2f"),
}
_CALCIFIER_RESOURCES = [
    {
        "path": "agents/fixer.md",
        "sha256": ("01be81bb44de98ecad48f60a4d29bd028bf09b5e209917c7977b12ec878e5158"),
        "size": 3058,
        "source": "../../agents/fixer.md",
    },
    {
        "path": "scripts/collect_metrics.py",
        "sha256": ("352f6ddda1e4e6f5b6c7e8233665db2d7522cb2fbe46f52cfd8111bc207f879f"),
        "size": 9355,
        "source": "../../scripts/collect_metrics.py",
    },
    {
        "path": "workflows/improve.js",
        "sha256": ("ddbea6ea127f0f1be3df5ee02fb39971bb780ba86b186d8576bde9ceba1bf594"),
        "size": 68114,
        "source": "../../workflows/improve.js",
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
        "ed inspection that finds zero issues.\n\nUse native Python"
        " orchestration and Calcifier agent()/run_command() for the"
        " source mechanics. Workflow, Skill, Agent, AskUserQuestion"
        ", TaskOutput, TaskStop and TaskCreate/TaskUpdate/TaskList "
        "are platform orchestration names, not shipped Calcifier 0."
        "2.0 built-in adapters: do not emit generic tool() adapters"
        " for these names. Use validated recipe inputs for choices,"
        " await native calls, and persist host-owned bookkeeping. T"
        "he built-in Claude worker has read/search/write tools but "
        "no Bash; host Python/run_command must perform mechanical c"
        "ommands and artifact persistence. Use pinned resources rat"
        "her than searching home/plugin caches or invoking an unpin"
        "ned installation. Preserve the complete source method, wit"
        "h explicit unsupported outcomes if an essential external d"
        "ependency cannot be represented. Generic research tools su"
        "ch as WebSearch/WebFetch are separate legitimate adapters;"
        " this guidance does not replace them.\n\nThe real loop imp"
        "lementation is pinned workflows/improve.js, with agents/fi"
        "xer.md and scripts/collect_metrics.py. Port its complete d"
        "eterministic loop into native Python, preserving the sourc"
        "e contracts, rather than reducing the entry point to a Wor"
        "kflow adapter or an improvised review/fix loop.\nAn actual"
        " external reviewer is essential. skill-improver requires t"
        "he plugin-dev:skill-reviewer protocol; pr-improver default"
        "s to pr-review-toolkit:review-pr; code-improver requires a"
        "n explicit reviewer. Those external reviewer prompts are n"
        "ot bundled here. Expose an explicitly configured native re"
        "viewer role carrying the full original reviewer instructio"
        "ns, or halt reviewer-unavailable with a precise dependency"
        " explanation. A generic worker is not proof that the named"
        " reviewer is installed; never self-substitute. If a skill "
        "reviewer calls specialists, preserve the bounded continuat"
        "ion protocol (maximum 3 waves, 8 agents per wave), actual "
        "named specialist instructions/availability, and failures. "
        "Native agent() roles cannot themselves invoke Claude platf"
        "orm Skill/Task.\nPreserve the full host-owned baseline: im"
        "mutable HEAD, git root, existing tracked/untracked changes"
        ", content hashes for protected out-of-scope untracked file"
        "s, target/plugin metadata, exact scope globs and artifact "
        "exclusions. Port glob semantics (** crosses directories, *"
        " does not), and execute scope/digest checks mechanically i"
        "n the host after every fix, including a failed fixer, and "
        "after finalization. Preserve no-source-commit behavior of "
        "the established-repository loop; initialization of a non-g"
        "it target is a separate explicit mutating input/authorizat"
        "ion boundary and must be disclosed if enabled. Do not sile"
        "ntly initialize and commit an unasked directory.\nPersist "
        "the exact cross-round ledger structure and stable file:lin"
        "e:class/coarse identity logic. On continuation carry findi"
        "ngs/verdicts and the user's ruling verbatim, archive prior"
        " per-round counters, and restart current round numbering s"
        "o stale history cannot cause false recurrence. Review ever"
        "y severity and apply critical/major blocking only at the l"
        "edger verdict. Preserve rejected/deferred semantics, new e"
        "vidence/reopening and structural rejection of a real issue"
        " whose immutable documented promise cannot be met.\nBound "
        "fixes by maxRounds (default 5, source 1..20 bounds), and a"
        "lways perform a final independent review after the fix cap"
        "; only a clean completed review can start convergence fina"
        "lization. Preserve escalation for three nondecreasing bloc"
        "ker-count rounds, three consecutive recurrence rounds, rep"
        "eated fixed/relocated findings, and structural rejections."
        " Do not weaken documented guarantees to reach convergence."
        " A dead fixer may leave edits: persist its failure and sco"
        "pe-check them, then review instead of another blind fix.\n"
        "Preserve scope-violation and unregistered-new-file halts, "
        "protected untracked-file changes, exact one version bump i"
        "n both metadata copies when applicable, narration cleanup "
        "and docs-match-code finalization. Snapshot before finaliza"
        "tion, scope-check its own edits, then independently read t"
        "hose edits for finalization regressions before claiming co"
        "nvergence. Preserve the source behavior that blocks a meta"
        "data bump outside authorized scope. Persist ledger/status "
        "and metrics on every exit, verify artifacts, and clearly d"
        "istinguish converged, capped, escalated, halted and partia"
        "l/unreviewed edits. No background task polling or cancella"
        "tion adapters; native cancellation must leave the last com"
        "pleted persisted round.\n\nThe previous generated prefligh"
        "t is rejected: it never implements an improvement\nloop an"
        "d always reports reviewer-unavailable. Generate the comple"
        "te native loop.\nThe registry now provides worker (fixing)"
        ", reviewer (independent review), and\nspecialist (independ"
        "ent named specialist) native roles. The recipe must requir"
        "e\ntrusted user inputs for the actual original reviewer pr"
        "otocol file, and for any\nrequired specialist-name-to-prot"
        "ocol-file mapping. Read and pass those full texts\nas the "
        "authoritative instructions for the corresponding native ro"
        "le. The user\nprovides the actual requested reviewer's ins"
        "tructions, not a generic replacement.\nReject missing/empt"
        "y protocol files when needed; do not hardcode that the rev"
        "iewer\nis unavailable or that only worker exists. These ex"
        "plicit runtime dependencies\nallow a genuinely runnable lo"
        "op without copying unavailable external prompts.\nAll exac"
        "t pinned workflow/helper contents are appended to the comp"
        "iler input\nas reference data, so no file tool is required"
        " to inspect their real interfaces.\nThe no-Bash limitation"
        " describes builtin Claude workers only; configured Codex\n"
        "workers support commands. Host Python still owns mechanica"
        "l orchestration.\nPreserve the complete deterministic work"
        "flow even if the module needs more than\n250 lines; source"
        " fidelity takes priority over the prompt's suggested size."
        "\nDo not emit a preflight-only or permanently halted recip"
        "e as an implementation.\n\nThe last candidate now implemen"
        "ts the complete native loop and is supplied as\nprevious-c"
        "andidate source data. Preserve its complete behavior and m"
        "ake this\nspecific destination E501 fix: the f-string cont"
        "aining 'fixer deferred a' and\n'finding — kept open' is 10"
        "1 columns after Ruff 0.14.13 formatting. Split it into\nim"
        "plicitly concatenated adjacent string literals inside the "
        "append parentheses,\nretaining the exact resulting text. D"
        "o not remove workflow mechanics or return\nto an unavailab"
        "le preflight. Return the complete corrected module and sat"
        "isfy\nthe destination E,F,I,UP,B,SIM lint selection at 100"
        " columns.\n"
    ),
    "sha256": ("59bb4914ef52a5b3154c63c9b950f7fc58b7379b0814eb4e4c2f685698ec5d7b"),
}
_CALCIFIER_SUBRECIPES = []
