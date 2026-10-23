# /// script
# requires-python = ">=3.13"
# dependencies = ["calcifier==0.2.0"]
# ///

"""Native, journaled skill improvement using the pinned improvement workflow."""

import difflib
import hashlib
import json
import re
from pathlib import Path
from typing import Any, Literal, NoReturn

from calcifier import (
    Budget,
    CommandResult,
    PreparedContext,
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

REVIEWER_NAME = "plugin-dev:skill-reviewer"
BLOCKING = {"critical", "major"}
SEVERITIES = ("critical", "major", "minor", "info")
SKIP_DIRS = {".git", ".code-improver", ".skill-improver", "node_modules", "__pycache__"}
NARRATION = (
    r"\b(round|iteration|pass) [0-9]\b",
    r"previous(ly)? (fix|attempt|version|round)",
    r"(was|were) (added|moved|changed|renamed|removed) (here|to|from)",
    r"per (the )?(review|reviewer|finding)",
)


@output_type
class TargetResolution:
    target: str
    candidates: list[str]
    available: list[str]


@output_type
class Finding:
    id: str
    file: str
    line: int
    defect_class: str
    severity: Literal["critical", "major", "minor", "info"]
    title: str
    evidence: str
    new_evidence: bool = False


@output_type
class Dispatch:
    agent_type: str
    prompt: str
    label: str


@output_type
class Review:
    mode: Literal["direct", "dispatch"]
    findings: list[Finding]
    verified_fixed: list[str]
    summary: str
    agents: list[Dispatch]


@output_type
class SpecialistReport:
    agent_type: str
    label: str
    ok: bool
    report: str
    error: str


@output_type
class Verdict:
    id: str
    verdict: Literal["fixed", "rejected", "deferred"]
    reason: str
    structural: bool = False
    pin: str = ""


@output_type
class Fix:
    verdicts: list[Verdict]
    notes: str


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


@output_type
class OpenFinding:
    id: str
    severity: Literal["critical", "major", "minor", "info"]
    title: str


@output_type
class Escalation:
    type: str
    round: int
    finding_ids: list[str]
    message: str


@output_type
class RunResult:
    converged: bool
    capped: bool
    halted: str
    escalation: Escalation | None
    violations: list[str]
    finalize_regressions: list[Regression]
    rounds_run: int
    fix_rounds: int
    fixer_failed_rounds: list[int]
    open_blocking: list[OpenFinding]
    open_minor_count: int
    new_untracked_files: list[str]
    ledger_path: str
    out_dir: str
    metrics: str
    metrics_ok: bool
    notes: list[str]
    partial_unreviewed_edits: bool
    stage: str
    target_candidates: list[str]
    available_skills: list[str]


class LoopHalt(Exception):
    pass


def halt(reason: str, message: str) -> NoReturn:
    raise LoopHalt(reason, message)


def propagate_budget(exc: Exception) -> None:
    if "BudgetExceeded" in str(type(exc)):
        raise exc


def clip(value: object, size: int) -> str:
    text = str(value or "")
    return text[:size] + "…" if len(text) > size else text


def norm_file(value: str) -> str:
    return value.removeprefix("./").strip()


def norm_class(value: str) -> str:
    return re.sub(r"[^a-z0-9]+", "-", value.lower().strip()).strip("-")


def line_number(value: int) -> int:
    return (value + 2**31) % 2**32 - 2**31


def identity(finding: Finding) -> str:
    return (
        f"{norm_file(finding.file)}:{line_number(finding.line)}:{norm_class(finding.defect_class)}"
    )


def coarse(finding: Finding) -> str:
    return f"{norm_file(finding.file)}::{norm_class(finding.defect_class)}"


def glob_regex(pattern: str) -> re.Pattern[str]:
    escaped = re.escape(pattern).replace(r"\*\*", "\x01")
    escaped = escaped.replace(r"\*", "[^/]*").replace("\x01", ".*")
    return re.compile("^" + escaped + "$")


def consecutive_three(rounds: list[int]) -> bool:
    ordered = sorted(set(rounds))
    return any(
        ordered[index + 1] == ordered[index] + 1 and ordered[index + 2] == ordered[index] + 2
        for index in range(len(ordered) - 2)
    )


def markdown_cell(value: object) -> str:
    return str(value).replace("|", "\\|").replace("\r", "").replace("\n", "<br>")


@step
def resolve_target(target: str, search_root: str) -> TargetResolution:
    direct = Path(target).resolve() if target.strip() else None
    if direct is not None:
        if direct.name == "SKILL.md" and direct.is_file():
            return TargetResolution(str(direct.parent), [], [])
        if direct.is_dir() and (direct / "SKILL.md").is_file():
            return TargetResolution(str(direct), [], [])
    root = Path(search_root).resolve()
    if not root.is_dir():
        return TargetResolution("", [], [])
    available = sorted(
        {
            str(path.resolve().parent)
            for path in root.rglob("SKILL.md")
            if path.is_file() and path.resolve().is_relative_to(root)
        }
    )
    needle = target.strip().removesuffix("/SKILL.md")
    matches = [path for path in available if needle and needle in path]
    resolved = matches[0] if len(matches) == 1 else ""
    return TargetResolution(resolved, matches, available)


class ImprovementLoop:
    def __init__(
        self,
        resolution: TargetResolution,
        out: Path,
        reviewer_protocol: str,
        specialist_protocols: dict[str, str],
        protocol_readable_roots: list[str],
        max_rounds: int,
        decision: str,
    ) -> None:
        self.resolution = resolution
        self.out = out
        self.target = Path(resolution.target) if resolution.target else Path.cwd()
        self.root = self.target
        self.base_sha = ""
        self.scope: list[str] = []
        self.regexes: list[re.Pattern[str]] = []
        self.out_rel = ""
        self.max_rounds = max_rounds
        self.decision = decision
        self.reviewer_input = reviewer_protocol
        self.specialist_inputs = specialist_protocols
        self.extra_read_inputs = protocol_readable_roots
        self.extra_reads: tuple[Path, ...] = ()
        self.reviewer_path = Path.cwd()
        self.reviewer_text = ""
        self.workflow = resource("workflows/improve.js")
        self.fixer = resource("agents/fixer.md")
        self.metrics_script = resource("scripts/collect_metrics.py")
        self.plugin: Path | None = None
        self.plugin_file: Path | None = None
        self.marketplace: Path | None = None
        self.marketplace_index: int | None = None
        self.plugin_version = ""
        self.initial_untracked: set[str] = set()
        self.initial_digests: dict[str, str] = {}
        self.protected: dict[str, str] = {}
        self.baseline: dict[str, Any] = {"established": False}
        self.written: set[str] = set()
        self.count_history: list[int] = []
        self.result = RunResult(
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
            metrics_ok=False,
            notes=[],
            partial_unreviewed_edits=False,
            stage="baseline",
            target_candidates=resolution.candidates,
            available_skills=resolution.available if not resolution.target else [],
        )
        self.ledger: dict[str, Any] = {
            "version": 1,
            "target": resolution.target,
            "reviewer": {"kind": "agent", "name": REVIEWER_NAME},
            "scope": [],
            "decisions": [decision] if decision else [],
            "prior_rounds": [],
            "rounds": [],
            "findings": {},
            "result": None,
        }
        prior_path = out / "ledger.json"
        self.prior_text = prior_path.read_text(encoding="utf-8") if prior_path.is_file() else ""
        self.prior_escalation = False

    def json_artifact(self, name: str, value: Any) -> None:
        write_json(self.out / name, value)
        self.written.add(name)

    def text_artifact(self, name: str, text: str) -> None:
        write_text(self.out / name, text)
        self.written.add(name)

    def findings(self) -> dict[str, Any]:
        return self.ledger["findings"]

    def blockers(self) -> list[dict[str, Any]]:
        return [
            finding
            for finding in self.findings().values()
            if finding["status"] == "open" and finding["severity"] in BLOCKING
        ]

    def counts(self) -> dict[str, int]:
        return {
            severity: sum(
                finding["status"] == "open" and finding["severity"] == severity
                for finding in self.findings().values()
            )
            for severity in SEVERITIES
        }

    def update_result(self) -> None:
        self.result.open_blocking = [
            OpenFinding(finding["id"], finding["severity"], finding["title"])
            for finding in self.blockers()
        ]
        self.result.open_minor_count = sum(
            finding["status"] == "open" and finding["severity"] not in BLOCKING
            for finding in self.findings().values()
        )
        self.ledger["result"] = self.result.model_dump()

    def outcome(self) -> str:
        if self.result.converged:
            return "Converged: a clean completed review and checked finalization."
        if self.result.escalation is not None:
            return "Escalated: " + self.result.escalation.message
        if self.result.capped:
            return "CAPPED, NOT CONVERGED: the final review still found blockers."
        if self.result.halted:
            return "Halted: " + self.result.halted
        return "Running: " + self.result.stage

    def checkpoint(self) -> None:
        self.update_result()
        self.json_artifact("ledger.json", self.ledger)
        self.json_artifact("baseline.json", self.baseline)
        rows = [
            "| id | severity | status | title | verdict reason |",
            "| --- | --- | --- | --- | --- |",
        ]
        for finding in self.findings().values():
            values = [
                finding["id"],
                finding["severity"],
                finding["status"],
                finding["title"],
                finding.get("verdict_reason", ""),
            ]
            rows.append("| " + " | ".join(markdown_cell(value) for value in values) + " |")
        rows.extend(["", "Rounds:", ""])
        rows.extend(json.dumps(record, sort_keys=True) for record in self.ledger["rounds"])
        self.text_artifact("ledger.md", "\n".join(rows) + "\n")
        status = [
            self.outcome(),
            "",
            f"Review rounds: {self.result.rounds_run}; fix rounds: {self.result.fix_rounds}.",
            f"Open minor/info findings: {self.result.open_minor_count}.",
            "",
            "Open blocking findings:",
            "",
        ]
        status.extend(
            f"- {finding.id} [{finding.severity}]: {finding.title}"
            for finding in self.result.open_blocking
        )
        if self.result.escalation is not None:
            status.extend(["", "Escalation ids:", ""])
            status.extend("- " + item for item in self.result.escalation.finding_ids)
        if self.result.partial_unreviewed_edits:
            status.extend(["", "The working tree may contain partial, unreviewed edits."])
        if self.result.target_candidates:
            status.extend(["", "Choose an exact target and re-run:", ""])
            status.extend("- " + item for item in self.result.target_candidates)
        if self.result.available_skills:
            status.extend(["", "Available skills:", ""])
            status.extend("- " + item for item in self.result.available_skills)
        status.extend(["", "Notes:", ""])
        status.extend("- " + note for note in self.result.notes)
        status.extend(
            [
                "",
                "Re-run with the same artifact name to reload the ledger. After an escalation,",
                "pass the user's ruling verbatim as decision. Round numbering restarts.",
                f"Ledger: {self.result.ledger_path}",
                f"Metrics: {self.result.metrics}; valid: {self.result.metrics_ok}",
            ]
        )
        self.text_artifact("status.md", "\n".join(status) + "\n")

    def load_prior(self) -> None:
        if not self.prior_text:
            return
        try:
            prior = json.loads(self.prior_text)
            if not isinstance(prior, dict):
                raise ValueError("ledger is not an object")
            findings = prior.get("findings", {})
            if not isinstance(findings, dict):
                raise ValueError("findings is not an object")
            carried: dict[str, Any] = {}
            for key, finding in findings.items():
                if not isinstance(finding, dict):
                    raise ValueError("a finding is not an object")
                if finding.get("severity") not in SEVERITIES:
                    raise ValueError("a finding has an invalid severity")
                carried[key] = {
                    **finding,
                    "rounds_seen": [],
                    "seen_prior": finding.get("seen_prior", []) + finding.get("rounds_seen", []),
                    "fixed_rounds": [],
                    "fixed_prior": finding.get("fixed_prior", 0)
                    + len(finding.get("fixed_rounds", [])),
                }
            self.ledger["prior_rounds"] = prior.get("prior_rounds", []) + prior.get("rounds", [])
            self.ledger["decisions"] = prior.get("decisions", []) + self.ledger["decisions"]
            self.ledger["findings"] = carried
            self.prior_escalation = bool((prior.get("result") or {}).get("escalation"))
            self.result.notes.append(f"Loaded prior ledger: {len(carried)} findings carried over.")
        except (KeyError, TypeError, ValueError) as exc:
            self.result.notes.append(
                f"PRIOR LEDGER UNREADABLE ({exc}): starting a fresh ledger. "
                "Prior verdicts are lost; the on-disk ledger will be overwritten."
            )

    def command(
        self,
        argv: list[str],
        directory: Path,
        *,
        mutating: bool = False,
        required: bool = True,
    ) -> CommandResult:
        result = run_command(
            argv,
            working_directory=directory,
            timeout_seconds=120,
            mutating=mutating,
        )
        if required and result.exit_code:
            halt("command-failed", f"{argv!r}: {result.stderr or result.stdout}")
        return result

    def git(self, *args: str, mutating: bool = False, required: bool = True) -> CommandResult:
        return self.command(
            ["git", "-C", str(self.root), *args],
            self.root,
            mutating=mutating,
            required=required,
        )

    def paths_from_git(self, *args: str) -> list[str]:
        return [item for item in self.git(*args, "-z").stdout.split("\x00") if item]

    def in_scope(self, path: str) -> bool:
        return any(pattern.fullmatch(path) is not None for pattern in self.regexes)

    def is_artifact(self, path: str) -> bool:
        return bool(self.out_rel) and (path == self.out_rel or path.startswith(self.out_rel + "/"))

    def scope_files(self) -> list[Path]:
        selected = []
        for path in sorted(self.root.rglob("*")):
            relative = path.relative_to(self.root).as_posix()
            if any(part in SKIP_DIRS for part in Path(relative).parts):
                continue
            if self.is_artifact(relative) or not self.in_scope(relative):
                continue
            if path.is_file():
                if not path.resolve().is_relative_to(self.root):
                    halt("scope-path-escape", f"Scoped file escapes the repository: {relative}")
                selected.append(path)
        if not selected:
            halt("empty-inspection-scope", "Scope matches zero files; nothing was inspected.")
        return selected

    def protocol(self, value: str, name: str) -> tuple[Path, str]:
        if not value.strip():
            halt(
                "reviewer-unavailable",
                f"Missing original protocol file for {name}. Supply the actual plugin "
                "instructions from plugin-dev in claude-plugins-official, or the named "
                "specialist's providing plugin. No generic reviewer is substituted.",
            )
        path = Path(value).resolve()
        if not path.is_file():
            halt("reviewer-unavailable", f"Original protocol file for {name} is missing: {path}")
        text = path.read_text(encoding="utf-8")
        if not text.strip():
            halt("reviewer-unavailable", f"Original protocol file for {name} is empty: {path}")
        return path, text

    def establish_baseline(
        self,
        requested_scope: list[str],
        initialize_repository: bool,
        version_bump: bool | None,
    ) -> None:
        if not self.resolution.target:
            if self.resolution.candidates:
                halt("target-choice-required", "Multiple skills match; choose an exact target.")
            halt(
                "target-not-found", "No skill matches. Available skills are included in the result."
            )
        if not self.target.is_dir() or not any(self.target.iterdir()):
            halt("target-invalid", "Target must be an existing, nonempty skill directory.")
        for directory in (self.target, *self.target.parents):
            manifest = directory / ".claude-plugin" / "plugin.json"
            if manifest.is_file():
                self.plugin = directory
                self.plugin_file = manifest
                metadata = json.loads(manifest.read_text(encoding="utf-8"))
                self.plugin_version = str(metadata.get("version", ""))
                break
        probe = self.command(
            ["git", "-C", str(self.target), "rev-parse", "--show-toplevel"],
            self.target,
            required=False,
        )
        initialized = False
        if probe.exit_code:
            if not initialize_repository:
                halt(
                    "git-baseline-unavailable",
                    "Target is outside a git repository. Initialization and its baseline "
                    "commit require the explicit initialize_repository=True input.",
                )
            cwd = Path.cwd().resolve()
            self.root = (
                cwd if self.target.is_relative_to(cwd) else self.plugin or self.target.parent
            )
            self.command(["git", "init", str(self.root)], self.root, mutating=True)
            initialized = True
            self.result.notes.append(
                f"A git repository was INITIALIZED at {self.root}; the explicitly authorized "
                "initialization creates a baseline commit. Established repositories are never "
                "committed by this loop."
            )
            add_args = ["add", "-A", "--", "."]
            if self.out.is_relative_to(self.root):
                excluded = self.out.relative_to(self.root).as_posix()
                add_args.append(":(exclude)" + excluded)
            self.git(*add_args, mutating=True)
            self.git(
                "-c",
                "user.name=code-improver-baseline",
                "-c",
                "user.email=code-improver@trailofbits.com",
                "commit",
                "--allow-empty",
                "-m",
                "Baseline for skill improvement",
                mutating=True,
            )
        else:
            self.root = Path(probe.stdout.strip()).resolve()
        if not self.root.is_absolute() or not self.target.is_relative_to(self.root):
            halt("git-baseline-invalid", "Git root is not an absolute ancestor of the target.")
        self.base_sha = self.git("rev-parse", "HEAD").stdout.strip()
        if not self.base_sha:
            halt("git-baseline-invalid", "No immutable HEAD is available.")
        if self.out.is_relative_to(self.root):
            self.out_rel = self.out.relative_to(self.root).as_posix()
        scope_root = self.plugin or self.target
        relative = scope_root.relative_to(self.root).as_posix()
        self.scope = requested_scope or ["**" if relative == "." else relative + "/**"]
        for pattern in self.scope:
            if (
                not pattern
                or pattern.startswith("/")
                or "\x00" in pattern
                or ".." in pattern.split("/")
            ):
                halt("scope-invalid", f"Scope must contain repo-relative globs: {pattern!r}")
        self.regexes = [glob_regex(pattern) for pattern in self.scope]
        self.ledger["scope"] = self.scope
        self.ledger["baseline"] = {"sha": self.base_sha, "git_root": str(self.root)}
        marketplace = self.root / ".claude-plugin" / "marketplace.json"
        if self.plugin is not None and marketplace.is_file():
            market = json.loads(marketplace.read_text(encoding="utf-8"))
            for index, entry in enumerate(market.get("plugins", [])):
                source = entry.get("source")
                if isinstance(source, str):
                    candidate = (self.root / source).resolve()
                    if candidate == self.plugin:
                        self.marketplace = marketplace
                        self.marketplace_index = index
                        break
        self.initial_untracked = set(
            self.paths_from_git("ls-files", "--others", "--exclude-standard")
        )
        for path in sorted(self.initial_untracked):
            self.initial_digests[path] = self.git("hash-object", "--", path).stdout.strip()
        self.protected = {
            path: digest
            for path, digest in self.initial_digests.items()
            if not self.in_scope(path) and not self.is_artifact(path)
        }
        tracked_diff = self.git("diff", "--binary", self.base_sha).stdout
        self.baseline = {
            "established": True,
            "target_dir": str(self.target),
            "plugin_dir": str(self.plugin or ""),
            "plugin_file": str(self.plugin_file or ""),
            "plugin_version": self.plugin_version,
            "marketplace_file": (
                self.marketplace.relative_to(self.root).as_posix()
                if self.marketplace is not None
                else ""
            ),
            "marketplace_index": self.marketplace_index,
            "git_root": str(self.root),
            "git_initialized": initialized,
            "head_sha": self.base_sha,
            "status_porcelain_z": self.git("status", "--porcelain=v1", "-z").stdout,
            "tracked_diff": tracked_diff,
            "index_diff": self.git("diff", "--cached", "--binary", self.base_sha).stdout,
            "changed": self.paths_from_git("diff", "--name-only", self.base_sha),
            "untracked": sorted(self.initial_untracked),
            "untracked_digests": [
                {"path": path, "sha": digest}
                for path, digest in sorted(self.initial_digests.items())
            ],
            "protected_untracked": self.protected,
            "scope": self.scope,
            "out_dir": str(self.out),
            "out_rel": self.out_rel,
            "artifact_exclusions": [self.out_rel] if self.out_rel else [],
        }
        self.scope_files()
        bump_enabled = bool(self.plugin_version) if version_bump is None else version_bump
        if bump_enabled:
            if self.plugin_file is None or not self.plugin_version:
                halt("version-baseline-unavailable", "Version bump needs baseline plugin metadata.")
            for metadata_file in (self.plugin_file, self.marketplace):
                if metadata_file is not None:
                    relative_file = metadata_file.relative_to(self.root).as_posix()
                    if not self.in_scope(relative_file):
                        halt(
                            "version-outside-scope",
                            f"Version metadata {relative_file} is outside authorized scope. "
                            "Widen scope explicitly or disable the version bump; scope is "
                            "never silently extended.",
                        )
        self.reviewer_path, self.reviewer_text = self.protocol(self.reviewer_input, REVIEWER_NAME)
        roots = []
        for value in self.extra_read_inputs:
            path = Path(value).resolve()
            if not path.is_dir():
                halt("protocol-view-invalid", f"Protocol readable root is not a directory: {path}")
            roots.append(path)
        self.extra_reads = tuple(roots)
        self.baseline["reviewer_protocol"] = {
            "name": REVIEWER_NAME,
            "path": str(self.reviewer_path),
            "sha256": hashlib.sha256(self.reviewer_path.read_bytes()).hexdigest(),
        }
        self.baseline["specialist_protocol_files"] = self.specialist_inputs
        self.checkpoint()

    def context(
        self, task: str, instructions: str, data: Any, files: tuple[Path, ...]
    ) -> PreparedContext:
        references = (self.workflow, *files)
        return prepare_context(
            task,
            instructions=instructions,
            prior_results=json.dumps(data, ensure_ascii=False),
            files=references,
            readable_roots=references,
        )

    def assignment(self) -> dict[str, Any]:
        return {
            "target": str(self.target),
            "git_root": str(self.root),
            "baseline_sha": self.base_sha,
            "scope": self.scope,
            "artifact_directory_read_only": str(self.out),
            "ledger": self.ledger,
        }

    def existing(self, finding: Finding, round_number: int) -> dict[str, Any] | None:
        findings = self.findings()
        if finding.id.strip() in findings:
            return findings[finding.id.strip()]
        exact = identity(finding)
        if exact in findings:
            return findings[exact]
        matches = [
            item
            for item in findings.values()
            if item["coarse"] == coarse(finding) and round_number not in item.get("rounds_seen", [])
        ]
        return matches[0] if len(matches) == 1 else None

    def review_problem(self, review: Review, round_number: int) -> str:
        if review.mode == "dispatch":
            if not review.agents or review.findings or review.verified_fixed:
                return "Dispatch requires specialists and cannot claim completed review results."
            return ""
        if review.agents:
            return "A direct completed review must have an empty agents list."
        pending = {
            finding["id"]
            for finding in self.findings().values()
            if finding["status"] == "fixed" and not finding.get("verified", False)
        }
        addressed = set(review.verified_fixed)
        for finding in review.findings:
            existing = self.existing(finding, round_number)
            if existing is not None:
                addressed.add(existing["id"])
        missing = sorted(pending - addressed)
        if missing:
            return "Verify or re-file every pending fix under its ledger id: " + ", ".join(missing)
        return ""

    def reviewer_call(self, round_number: int, wave: int, history: list[dict[str, Any]]) -> Review:
        task = (
            "Perform the complete original plugin-dev:skill-reviewer protocol supplied "
            "as instructions, on the entire declared target. Read full references when "
            "not embedded. The pinned workflow supplies ledger and review discipline. "
            "This is a read-only independent review; make no edits or bookkeeping writes. "
            "Report EVERY defect, including minor and info, using the native Review schema. "
            "defect_class maps to the ledger's class field. Reuse exact known ledger ids, "
            "even when lines shift. Verify every fixed/unverified entry by reading current "
            "code and its pins; return verified_fixed ids or re-file failed fixes. Do not "
            "re-file rejected entries without genuinely new evidence outside verdict_reason; "
            "then use the same id and new_evidence=true. Deferred findings stay parked unless "
            "raised to blocking. Apply user decisions verbatim and never weaken guarantees. "
            "Native agents cannot call platform Skill or Task. If the original protocol "
            "requires named specialists, return mode=dispatch, empty findings and "
            "verified_fixed, and their full original prompts in agents. Native orchestration "
            "runs up to 8 requests per wave, for at most 3 waves, then continues this same "
            "review with complete previous returns and reports. Finish with mode=direct "
            "and agents=[]. Specialist failures are evidence of incomplete work, not clean "
            "reports; retry within the wave bound or state inability to complete. If the "
            "original protocol or an essential dependency is unavailable, summary must "
            "start REVIEWER-UNAVAILABLE:. If review cannot complete, start REVIEW-INCOMPLETE:. "
            "Do not substitute a generic methodology or declare unperformed phases complete."
        )
        for attempt in range(2):
            self.result.stage = f"review:{round_number}.{wave}:{attempt + 1}"
            self.checkpoint()
            data = {
                **self.assignment(),
                "round": round_number,
                "final_review_only": round_number == self.max_rounds + 1,
                "specialist_waves_remaining": 3 - wave,
                "configured_specialist_names": sorted(self.specialist_inputs),
                "connected_review_history": history,
            }
            context = self.context(task, self.reviewer_text, data, (self.reviewer_path,))
            review = agent(
                "reviewer",
                context.prompt,
                working_directory=self.root,
                readable_paths=(self.root, self.reviewer_path, *self.extra_reads),
                output=Review,
                context=context,
                timeout=3600,
            )
            if review.summary.startswith("REVIEWER-UNAVAILABLE:"):
                halt("reviewer-unavailable", review.summary)
            if review.summary.startswith("REVIEW-INCOMPLETE:"):
                halt("reviewer-failed", review.summary)
            problem = self.review_problem(review, round_number)
            if not problem:
                return review
            history.append({"invalid_response": review.model_dump(), "correction": problem})
        halt("reviewer-failed", "Review omitted required results after two attempts: " + problem)

    def review_round(self, round_number: int) -> Review:
        history: list[dict[str, Any]] = []
        for wave in range(4):
            review = self.reviewer_call(round_number, wave, history)
            history.append({"reviewer_return": review.model_dump()})
            if review.mode == "direct":
                return review
            if wave == 3:
                halt("reviewer-failed", "Reviewer exceeded the 3-wave specialist continuation cap.")
            requested = review.agents
            plan = requested[:8]
            if len(requested) > 8:
                self.result.notes.append(
                    f"Review {round_number}, wave {wave + 1}: "
                    f"{len(requested) - 8} specialist requests exceeded the 8-agent cap."
                )
            prepared: list[tuple[Dispatch, Path, str]] = []
            for request in plan:
                path, text = self.protocol(
                    self.specialist_inputs.get(request.agent_type, ""), request.agent_type
                )
                prepared.append((request, path, text))
            self.checkpoint()

            def dispatch(item: tuple[Dispatch, Path, str]) -> SpecialistReport:
                request, path, instructions = item
                try:
                    context = self.context(
                        "Perform the requested independent named specialist review using "
                        "the full original specialist protocol supplied as instructions. "
                        "Inspect the complete assigned target and references. Make no "
                        "edits. You cannot invoke platform Skill or Task; report an "
                        "essential missing dependency explicitly. Return your complete "
                        "report, including every severity and any inability to finish.",
                        instructions,
                        {
                            **self.assignment(),
                            "specialist_name": request.agent_type,
                            "requested_prompt": request.prompt,
                        },
                        (path,),
                    )
                    report = agent(
                        "specialist",
                        context.prompt,
                        working_directory=self.root,
                        readable_paths=(self.root, path, *self.extra_reads),
                        output=str,
                        context=context,
                        timeout=3600,
                    )
                    if not report.strip():
                        return SpecialistReport(
                            request.agent_type, request.label, False, "", "Returned nothing"
                        )
                    return SpecialistReport(request.agent_type, request.label, True, report, "")
                except Exception as exc:
                    propagate_budget(exc)
                    return SpecialistReport(request.agent_type, request.label, False, "", str(exc))

            reports = parallel(dispatch, prepared, max_workers=8)
            for report in reports:
                if not report.ok:
                    self.result.notes.append(
                        f"SPECIALIST FAILED: {report.agent_type} ({report.label}): {report.error}"
                    )
                elif report.report.startswith("REVIEWER-UNAVAILABLE:"):
                    halt("reviewer-unavailable", report.report)
            history.append(
                {
                    "specialist_wave": wave + 1,
                    "requests": [request.model_dump() for request in requested],
                    "executed": [request.model_dump() for request in plan],
                    "reports": [report.model_dump() for report in reports],
                }
            )
        halt("reviewer-failed", "Reviewer did not complete a bounded continuation.")

    def merge_review(self, round_number: int, review: Review) -> None:
        fresh = reopened = refiled = 0
        for identifier in review.verified_fixed:
            finding = self.findings().get(identifier.strip())
            if finding is not None and finding["status"] == "fixed":
                finding["verified"] = True
        for raw in review.findings:
            finding = self.existing(raw, round_number)
            if finding is None:
                identifier = identity(raw)
                self.findings()[identifier] = {
                    "id": identifier,
                    "coarse": coarse(raw),
                    "file": norm_file(raw.file),
                    "line": line_number(raw.line),
                    "class": norm_class(raw.defect_class),
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
            if finding["status"] == "rejected" and not raw.new_evidence:
                finding["refiled_after_verdict"] += 1
                refiled += 1
                continue
            if finding["status"] == "deferred":
                if raw.severity not in BLOCKING:
                    continue
                finding["notes"].append(
                    f"round {round_number}: severity raised to {raw.severity}, reopened"
                )
            if finding["status"] == "rejected":
                finding["notes"].append(f"round {round_number}: reopened with new evidence")
            if finding["status"] == "fixed":
                finding["notes"].append(f"round {round_number}: fix did not hold, reopened")
                reopened += 1
            finding.update(
                {
                    "status": "open",
                    "verified": False,
                    "line": line_number(raw.line),
                    "severity": raw.severity,
                    "evidence": clip(raw.evidence, 400),
                    "last_round": round_number,
                }
            )
            finding["rounds_seen"].append(round_number)
        self.ledger["rounds"].append(
            {
                "round": round_number,
                "type": "review",
                "open": self.counts(),
                "new": fresh,
                "reopened": reopened,
                "refiled_rejected": refiled,
            }
        )
        self.result.rounds_run = round_number
        self.result.partial_unreviewed_edits = False
        self.json_artifact(f"review-round-{round_number}.json", review.model_dump())
        self.checkpoint()

    def escalation(
        self, kind: str, message: str, identifiers: list[str], round_number: int
    ) -> Escalation:
        named = identifiers or [finding["id"] for finding in self.blockers()]
        return Escalation(
            kind,
            round_number,
            named,
            message + " This is structural: it needs a design decision, not another fix "
            "round. Do not weaken documented guarantees. Continue with the user's "
            "ruling verbatim as decision; the stable on-disk ledger preserves verdicts.",
        )

    def review_escalation(self, round_number: int) -> Escalation | None:
        recurring = [
            finding["id"]
            for finding in self.blockers()
            if consecutive_three(finding["rounds_seen"])
        ]
        history = self.count_history
        if len(history) >= 3 and 0 < history[-3] <= history[-2] <= history[-1]:
            return self.escalation(
                "counts-non-decreasing",
                f"Open blocker counts did not decrease for 3 reviews: {history[-3:]}.",
                recurring,
                round_number,
            )
        if recurring:
            return self.escalation(
                "recurrence",
                "Findings stayed open for 3 consecutive reviews.",
                recurring,
                round_number,
            )
        return None

    def surface(self, *, require_registered: bool) -> None:
        if self.git("rev-parse", "HEAD").stdout.strip() != self.base_sha:
            halt("git-baseline-changed", "HEAD changed; the immutable baseline was violated.")
        current_root = self.git("rev-parse", "--show-toplevel").stdout.strip()
        if Path(current_root).resolve() != self.root:
            halt("git-baseline-changed", "The repository root changed during the run.")
        self.scope_files()
        changed = self.paths_from_git("diff", "--name-only", self.base_sha)
        untracked = self.paths_from_git("ls-files", "--others", "--exclude-standard")
        violations = [
            path for path in changed if not self.in_scope(path) and not self.is_artifact(path)
        ]
        violations.extend(
            path
            for path in untracked
            if not self.in_scope(path)
            and not self.is_artifact(path)
            and path not in self.initial_untracked
        )
        for path, initial_hash in self.protected.items():
            current = self.root / path
            if not current.exists():
                violations.append(path + " (deleted)")
                continue
            current_hash = self.git("hash-object", "--", path).stdout.strip()
            if current_hash != initial_hash:
                violations.append(path + " (modified)")
        new_untracked = [
            path
            for path in untracked
            if self.in_scope(path)
            and not self.is_artifact(path)
            and path not in self.initial_untracked
        ]
        if violations:
            self.result.violations = list(dict.fromkeys(violations))
            halt(
                "scope-violation",
                "Out-of-scope changes detected; nothing was reverted: "
                + ", ".join(self.result.violations),
            )
        if require_registered and new_untracked:
            self.result.new_untracked_files = new_untracked
            halt(
                "untracked-files-in-scope",
                "Register new files with git add -N, or remove them, before completion: "
                + ", ".join(new_untracked),
            )

    def merge_verdicts(
        self, round_number: int, fixed: Fix, dispatched: list[str], diff_file: str
    ) -> list[str]:
        tally = {"fixed": 0, "rejected": 0, "deferred": 0}
        seen: set[str] = set()
        structural = []
        for verdict in fixed.verdicts:
            finding = self.findings()[verdict.id.strip()]
            seen.add(finding["id"])
            if verdict.verdict == "fixed":
                finding["status"] = "fixed"
                finding["verified"] = False
                finding["fixed_rounds"].append(round_number)
                finding["pin"] = clip(verdict.pin, 300)
            elif verdict.verdict == "rejected":
                finding["status"] = "rejected"
                finding["verdict_reason"] = clip(verdict.reason, 400)
                if verdict.structural and finding["severity"] in BLOCKING:
                    finding["structural"] = True
                    structural.append(finding["id"])
            elif finding["severity"] in BLOCKING:
                finding["notes"].append(
                    f"round {round_number}: fixer deferred a {finding['severity']} "
                    "finding — kept open"
                )
            else:
                finding["status"] = "deferred"
                finding["verdict_reason"] = clip(verdict.reason, 400)
            tally[verdict.verdict] += 1
        missing = [identifier for identifier in dispatched if identifier not in seen]
        self.ledger["rounds"].append(
            {
                "round": round_number,
                "type": "fix",
                "verdicts": tally,
                "unaddressed": missing,
                "failed": bool(missing),
                "diff_file": diff_file,
            }
        )
        if missing:
            self.result.fixer_failed_rounds.append(round_number)
            self.result.notes.append(
                "Fixer omitted required verdicts; those findings remain open: " + ", ".join(missing)
            )
        return structural

    def fix_round(self, round_number: int) -> Escalation | None:
        dispatched = [
            {
                key: finding[key]
                for key in ("id", "file", "line", "class", "severity", "title", "evidence")
            }
            for finding in self.blockers()
        ]
        identifiers = [finding["id"] for finding in dispatched]
        self.result.stage = f"fix:{round_number}"
        self.result.partial_unreviewed_edits = True
        self.checkpoint()
        fixed: Fix | None = None
        failure = ""
        try:
            context = self.context(
                "Apply the complete pinned agents/fixer.md contract to ONLY the dispatched "
                "blockers. Read that reference fully when not embedded. The complete pinned "
                "workflow explains ledger verdicts and verification. Apply binding user "
                "decisions. Respect existing working-tree changes. Stay inside exact scope "
                "globs, including untracked files. Never weaken documented guarantees or "
                "immutable promises. Never checkout, stash, reset, clean, or commit. "
                "Register files you create with git add -N. Executable fixes require pins "
                "that fail against pre-fix behavior; heuristic fixes require table pins. "
                "Return one fixed/rejected/deferred verdict per dispatched id, with specific "
                "reasons and pins. A real blocker made unsatisfiable by an immutable promise "
                "must be rejected with structural=true. Do not write ledger, metrics, or "
                "diff artifacts: native Python owns all bookkeeping and snapshots. "
                "Use native commands for execution and pins; report unavailable execution "
                "rather than claiming checks passed. The next independent review verifies fixes.",
                self.fixer.read_text(encoding="utf-8"),
                {**self.assignment(), "round": round_number, "dispatched": dispatched},
                (self.fixer,),
            )
            fixed = agent(
                "worker",
                context.prompt,
                working_directory=self.root,
                readable_paths=(self.root, *self.extra_reads),
                writable_paths=(self.root,),
                required_capabilities=("commands",),
                output=Fix,
                context=context,
                timeout=3600,
            )
            returned = [verdict.id.strip() for verdict in fixed.verdicts]
            if len(returned) != len(set(returned)) or set(returned) - set(identifiers):
                failure = "Fixer returned duplicate or undispatched verdict ids."
                fixed = None
        except Exception as exc:
            propagate_budget(exc)
            failure = str(exc)
            fixed = None
        diff_name = f"fixes-round-{round_number}.diff"
        structural = []
        self.result.fix_rounds = round_number
        if fixed is None:
            self.ledger["rounds"].append(
                {
                    "round": round_number,
                    "type": "fix",
                    "verdicts": {"fixed": 0, "rejected": 0, "deferred": 0},
                    "unaddressed": identifiers,
                    "failed": True,
                    "diff_file": diff_name,
                }
            )
            self.result.fixer_failed_rounds.append(round_number)
            self.result.notes.append(
                f"Fixer {round_number} failed: {failure or 'returned nothing'}. "
                "Partial edits may remain. A native worker with commands support is "
                "required for execution pins and git add -N; configure that provider if "
                "execution is unavailable. Scope-check these edits, then review them; "
                "never follow a dead fixer with a blind fix."
            )
        else:
            structural = self.merge_verdicts(round_number, fixed, identifiers, diff_name)
            self.json_artifact(f"fix-round-{round_number}.json", fixed.model_dump())
            if fixed.notes:
                self.result.notes.append(f"Fix {round_number}: {fixed.notes}")
        self.checkpoint()
        self.text_artifact(diff_name, self.git("diff", "--binary", self.base_sha).stdout)
        self.surface(require_registered=False)
        self.checkpoint()
        if structural:
            return self.escalation(
                "structural-rejection",
                "Real blockers conflict with documented immutable demands.",
                structural,
                round_number,
            )
        refixed = [
            finding["id"]
            for finding in self.findings().values()
            if len(finding["fixed_rounds"]) >= 2
        ]
        if refixed:
            return self.escalation(
                "relocation",
                "Findings were fixed in more than one round; the problem is relocating. "
                "The latest attempt remains UNREVIEWED.",
                refixed,
                round_number,
            )
        return None

    def snapshot(self) -> dict[str, bytes]:
        return {
            path.relative_to(self.root).as_posix(): path.read_bytes() for path in self.scope_files()
        }

    def narration_observations(self, snapshot: dict[str, bytes]) -> list[dict[str, Any]]:
        observations = []
        for path, content in snapshot.items():
            try:
                text = content.decode("utf-8")
            except UnicodeDecodeError:
                continue
            for expression in NARRATION:
                for match in re.finditer(expression, text, re.IGNORECASE):
                    observations.append(
                        {
                            "file": path,
                            "line": text.count("\n", 0, match.start()) + 1,
                            "match": match.group(),
                            "pattern": expression,
                        }
                    )
        return observations

    def finalize_changes(
        self, before: dict[str, bytes], after: dict[str, bytes]
    ) -> tuple[list[dict[str, Any]], str]:
        changes = []
        patches = []
        for path in sorted(before.keys() | after.keys()):
            old = before.get(path)
            new = after.get(path)
            if old == new:
                continue
            old_text: str | None = None
            new_text: str | None = None
            try:
                old_text = old.decode("utf-8") if old is not None else ""
                new_text = new.decode("utf-8") if new is not None else ""
            except UnicodeDecodeError:
                pass
            changes.append(
                {
                    "file": path,
                    "before_text": old_text,
                    "after_text": new_text,
                    "before_sha256": hashlib.sha256(old).hexdigest() if old is not None else None,
                    "after_sha256": hashlib.sha256(new).hexdigest() if new is not None else None,
                    "deleted": new is None,
                    "created": old is None,
                }
            )
            if old_text is not None and new_text is not None:
                patches.extend(
                    difflib.unified_diff(
                        old_text.splitlines(keepends=True),
                        new_text.splitlines(keepends=True),
                        fromfile="before/" + path,
                        tofile="after/" + path,
                    )
                )
            else:
                patches.append(f"Binary finalize change: {path}\n")
        return changes, "".join(patches)

    def version_regressions(self, bump: bool, changes: list[dict[str, Any]]) -> list[Regression]:
        regressions = []
        if bump and self.plugin_file is not None:
            metadata = json.loads(self.plugin_file.read_text(encoding="utf-8"))
            version = metadata.get("version", "")
            relative = self.plugin_file.relative_to(self.root).as_posix()
            if not isinstance(version, str) or not version or version == self.plugin_version:
                regressions.append(
                    Regression(
                        relative, 1, "Final plugin version does not increment the baseline version."
                    )
                )
            if self.marketplace is not None and self.marketplace_index is not None:
                market = json.loads(self.marketplace.read_text(encoding="utf-8"))
                entries = market.get("plugins", [])
                entry = (
                    entries[self.marketplace_index] if self.marketplace_index < len(entries) else {}
                )
                if entry.get("version") != version:
                    regressions.append(
                        Regression(
                            self.marketplace.relative_to(self.root).as_posix(),
                            1,
                            "Marketplace entry and plugin.json versions disagree.",
                        )
                    )
        if not bump:
            expression = r'(?m)["\x27]?version["\x27]?\s*[:=]\s*["\x27]?([^\n,}\x27"]+)'
            for change in changes:
                old = change["before_text"]
                new = change["after_text"]
                if (
                    old is not None
                    and new is not None
                    and re.findall(expression, old) != re.findall(expression, new)
                ):
                    regressions.append(
                        Regression(change["file"], 1, "Finalize changed a disabled version field.")
                    )
        return regressions

    def finalize_run(self, bump: bool, narration_strip: bool, docs_pass: bool) -> None:
        self.result.stage = "pre-finalize"
        self.surface(require_registered=True)
        before = self.snapshot()
        self.text_artifact("pre-finalize.diff", self.git("diff", "--binary", self.base_sha).stdout)
        self.json_artifact(
            "finalize-before.json",
            {path: hashlib.sha256(content).hexdigest() for path, content in before.items()},
        )
        self.result.partial_unreviewed_edits = True
        self.checkpoint()
        finalized: Finalize | None = None
        try:
            context = self.context(
                "Perform only the pinned workflow's finalization mandate. Read the complete "
                "finalization contract and references when not embedded. The last review "
                "was clean. Stay inside exact authorized scope and preserve existing work. "
                "If narration_strip is enabled, inspect every scoped file and use the "
                "complete mechanical matches as observations; remove session narration "
                "only. Leave legitimate algorithm steps, tournament rounds, and preexisting "
                "changelog history. Count changed narration sites. If version_bump is "
                "enabled, collapse all churn to exactly ONE increment above baseline, "
                "updating plugin.json and its matching marketplace entry identically. "
                "The independent check will read whether that increment is correct. If "
                "disabled, touch no version fields and return version=''. If docs_pass is "
                "enabled, read the documentation throughout scope and repair only claims "
                "made false by this run's changes; never weaken immutable guarantees. "
                "Do not refactor, re-fix, or otherwise improve the target. Register any "
                "new files with git add -N. Never commit, reset, clean, stash, or checkout. "
                "Do not write bookkeeping or snapshots; Python owns them. Partial failed "
                "edits will still receive scope and independent regression checks.",
                self.fixer.read_text(encoding="utf-8"),
                {
                    **self.assignment(),
                    "finalize": {
                        "version_bump": bump,
                        "narration_strip": narration_strip,
                        "docs_pass": docs_pass,
                    },
                    "baseline_plugin_version": self.plugin_version,
                    "plugin_file": str(self.plugin_file or ""),
                    "marketplace_file": str(self.marketplace or ""),
                    "marketplace_entry_index": self.marketplace_index,
                    "complete_scope_files": sorted(before),
                    "narration_observations": self.narration_observations(before),
                },
                (self.fixer,),
            )
            finalized = agent(
                "worker",
                context.prompt,
                working_directory=self.root,
                readable_paths=(self.root, *self.extra_reads),
                writable_paths=(self.root,),
                required_capabilities=("commands",),
                output=Finalize,
                context=context,
                timeout=3600,
            )
        except Exception as exc:
            propagate_budget(exc)
            self.result.notes.append(
                f"Finalize failed: {exc}. Partial edits may remain; checks still run."
            )
        if finalized is not None:
            self.ledger["finalize"] = {
                "narration_sites_removed": finalized.narration_sites_removed,
                "version": finalized.version,
                "notes": clip(finalized.notes, 500),
            }
            self.json_artifact("finalize.json", finalized.model_dump())
            if finalized.notes:
                self.result.notes.append("Finalize: " + finalized.notes)
        self.checkpoint()
        self.text_artifact("post-finalize.diff", self.git("diff", "--binary", self.base_sha).stdout)
        self.surface(require_registered=True)
        after = self.snapshot()
        changes, patch = self.finalize_changes(before, after)
        self.text_artifact("finalize.patch", patch)
        mechanical_regressions = self.version_regressions(bump, changes)
        self.result.stage = "finalize-check"
        self.checkpoint()
        context = self.context(
            "Independently check the pinned workflow's finalization contract, read-only. "
            "Read ALL finalization edits and current surrounding contents, including full "
            "before/after texts provided here and the entire scoped target where needed. "
            "The nonempty scope inventory is the inspection scope even when finalize made "
            "zero edits. Verify finalization's enabled mandates completed. Report every "
            "site where legitimate content was rewritten as narration, documentation "
            "became false or unsupported, an immutable guarantee was weakened, version "
            "is not exactly ONE increment above the original baseline, metadata copies "
            "disagree, a disabled mandate was performed, or changes exceed narration, "
            "version, and docs-match-code. Check binary changes directly where needed. "
            "Read and interpret complete references; mechanical matches are observations. "
            "An empty regressions list means you actually checked all these edits and "
            "mandates and they are sound. Make no edits or bookkeeping writes. Return "
            "file, line, and concrete why per regression. Report inability to establish "
            "soundness as a regression at the affected site; never certify unperformed work.",
            self.reviewer_text,
            {
                **self.assignment(),
                "complete_scope_files": sorted(after),
                "finalize_changes": changes,
                "finalize_patch": patch,
                "baseline_plugin_version": self.plugin_version,
                "plugin_file": str(self.plugin_file or ""),
                "marketplace_file": str(self.marketplace or ""),
                "marketplace_entry_index": self.marketplace_index,
                "finalize": {
                    "version_bump": bump,
                    "narration_strip": narration_strip,
                    "docs_pass": docs_pass,
                },
                "mechanical_regressions": [item.model_dump() for item in mechanical_regressions],
                "finalizer_return": finalized.model_dump() if finalized is not None else None,
            },
            (self.reviewer_path,),
        )
        check = agent(
            "reviewer",
            context.prompt,
            working_directory=self.root,
            readable_paths=(self.root, self.reviewer_path, *self.extra_reads),
            output=FinalizeCheck,
            context=context,
            timeout=3600,
        )
        self.json_artifact("finalize-check.json", check.model_dump())
        self.surface(require_registered=True)
        if self.snapshot() != after:
            halt("finalize-check-failed", "Repository contents changed during read-only audit.")
        regressions = mechanical_regressions + check.regressions
        if regressions:
            self.result.finalize_regressions = regressions
            halt(
                "finalize-regression",
                "Finalize edits failed independent inspection. Edits remain in the tree: "
                + "; ".join(f"{item.file}:{item.line}: {item.why}" for item in regressions),
            )
        self.result.partial_unreviewed_edits = False
        self.result.converged = True
        self.checkpoint()

    def execute(
        self,
        scope: list[str],
        initialize_repository: bool,
        version_bump: bool | None,
        narration_strip: bool,
        docs_pass: bool,
    ) -> None:
        self.load_prior()
        if not 1 <= self.max_rounds <= 20:
            halt("max-rounds-invalid", "max_rounds must be an integer between 1 and 20.")
        if self.prior_escalation and not self.decision:
            halt(
                "decision-required",
                "The prior run escalated. Supply the user's design ruling verbatim as "
                "decision before continuing; findings and verdicts have been retained.",
            )
        self.establish_baseline(scope, initialize_repository, version_bump)
        bump = bool(self.plugin_version) if version_bump is None else version_bump
        self.json_artifact(
            "metrics.json",
            {
                "valid": False,
                "error": "Run in progress; no final metrics have been collected.",
            },
        )
        for round_number in range(1, self.max_rounds + 2):
            self.result.stage = f"review:{round_number}"
            self.checkpoint()
            try:
                review = self.review_round(round_number)
            except LoopHalt:
                raise
            except Exception as exc:
                propagate_budget(exc)
                halt("reviewer-failed", f"Independent reviewer did not complete: {exc}")
            self.merge_review(round_number, review)
            self.count_history.append(len(self.blockers()))
            if not self.blockers():
                self.finalize_run(bump, narration_strip, docs_pass)
                return
            escalation = self.review_escalation(round_number)
            if escalation is not None:
                self.result.escalation = escalation
                return
            if round_number == self.max_rounds + 1:
                self.result.capped = True
                self.result.notes.append(
                    f"CAPPED, NOT CONVERGED: {self.max_rounds} fix rounds were spent "
                    "and the final independent review still found blocking issues. "
                    "Changes remain uncommitted in the working tree."
                )
                return
            escalation = self.fix_round(round_number)
            if escalation is not None:
                self.result.escalation = escalation
                return
        halt("loop-incomplete", "The bounded loop exited without a completed outcome.")

    def finish(self) -> RunResult:
        self.result.stage = "finished"
        self.checkpoint()
        arguments = [
            "uv",
            "run",
            "--no-project",
            str(self.metrics_script),
            "--ledger",
            str(self.out / "ledger.json"),
            "--out",
            str(self.out / "metrics.json"),
        ]
        if self.base_sha:
            arguments.extend(
                [
                    "--repo",
                    str(self.root),
                    "--baseline-sha",
                    self.base_sha,
                    "--diff-dir",
                    str(self.out),
                ]
            )
            for pattern in self.scope:
                arguments.extend(["--scope", pattern])
        metrics: Any = None
        metrics_error = ""
        try:
            collected = run_command(
                arguments,
                working_directory=self.root if self.root.is_dir() else Path.cwd(),
                timeout_seconds=300,
                mutating=True,
            )
            if collected.exit_code:
                metrics_error = collected.stderr or collected.stdout or "Collector failed."
            else:
                metrics = json.loads((self.out / "metrics.json").read_text(encoding="utf-8"))
                if not isinstance(metrics, dict) or "rounds_used" not in metrics:
                    metrics_error = "Collector did not produce its documented metrics object."
        except Exception as exc:
            propagate_budget(exc)
            metrics_error = str(exc)
        if metrics_error:
            self.result.metrics_ok = False
            self.result.notes.append(
                "collect_metrics.py FAILED; metrics are invalid, not a clean zero-item "
                "report: " + metrics_error
            )
            metrics = {"valid": False, "error": metrics_error}
            self.json_artifact("metrics.json", metrics)
        else:
            self.result.metrics_ok = True
            self.written.add("metrics.json")
        self.checkpoint()
        for name in sorted(self.written):
            verify_artifact(
                self.out / name,
                nonempty=not name.endswith((".diff", ".patch")),
            )
        emit(self.ledger, name="ledger")
        emit(metrics, name="metrics")
        return emit(self.result, name="result")


@recipe(
    name="skill-improver",
    version="1",
    capabilities=("Bash",),
    agents=("worker", "reviewer", "specialist"),
    budget=Budget(max_agent_calls=1400, max_wall_seconds=3600),
    output_root=".code-improver",
)
def improve_skill(
    target: str,
    reviewer_protocol: str,
    specialist_protocols: dict[str, str] | None = None,
    protocol_readable_roots: list[str] | None = None,
    search_root: str = ".",
    artifact_name: str = "",
    scope: list[str] | None = None,
    max_rounds: int = 5,
    decision: str = "",
    initialize_repository: bool = False,
    finalize_version_bump: bool | None = None,
    narration_strip: bool = True,
    docs_pass: bool = True,
) -> RunResult:
    """Require actual original reviewer protocols; never substitute generic prompts.

    specialist_protocols maps exact names prescribed by that protocol to their
    original instruction files. protocol_readable_roots grants explicit access to
    any additional referenced material. Reuse artifact_name to resume a ledger.
    initialize_repository explicitly authorizes git init and an initial commit;
    the normal established-repository path never commits.
    """
    resolution = resolve_target(target, search_root)
    name = artifact_name or (Path(resolution.target).name if resolution.target else "unresolved")
    if not re.fullmatch(r"[A-Za-z0-9._-]+", name) or name in {".", ".."}:
        halt("artifact-name-invalid", "artifact_name must be one simple directory name.")
    planned = [
        "ledger.json",
        "ledger.md",
        "status.md",
        "baseline.json",
        "metrics.json",
        "pre-finalize.diff",
        "post-finalize.diff",
        "finalize-before.json",
        "finalize.patch",
        "finalize.json",
        "finalize-check.json",
    ]
    for round_number in range(1, 22):
        planned.append(f"review-round-{round_number}.json")
        if round_number <= 20:
            planned.extend([f"fix-round-{round_number}.json", f"fixes-round-{round_number}.diff"])
    out = ensure_directory(name, output_files=tuple(planned), overwrite=True)
    loop = ImprovementLoop(
        resolution,
        out,
        reviewer_protocol,
        specialist_protocols or {},
        protocol_readable_roots or [],
        max_rounds,
        decision,
    )
    completed = False
    try:
        try:
            loop.execute(
                scope or [],
                initialize_repository,
                finalize_version_bump,
                narration_strip,
                docs_pass,
            )
        except LoopHalt as exc:
            loop.result.converged = False
            loop.result.halted = str(exc.args[0])
            loop.result.notes.append(str(exc.args[1]))
        except Exception as exc:
            propagate_budget(exc)
            loop.result.converged = False
            loop.result.halted = (
                "finalize-check-failed"
                if loop.result.stage == "finalize-check"
                else "execution-failed"
            )
            loop.result.notes.append(str(exc))
        completed = True
    finally:
        if not completed:
            loop.result.converged = False
            loop.result.halted = "interrupted"
            loop.result.notes.append(
                "Native execution was interrupted. The last completed round is retained; "
                "partial edits may remain. No background task or cancellation adapter exists."
            )
            loop.json_artifact(
                "metrics.json",
                {
                    "valid": False,
                    "error": "Interrupted before final metric collection; no clean claim is made.",
                },
            )
        loop.checkpoint()
    return loop.finish()


if __name__ == "__main__":
    raise SystemExit(improve_skill.cli())


# --- calcifier metadata (skill provenance + sha256) ---
_CALCIFIER_COMPILATION = "compiled"
_CALCIFIER_SKILL = {
    "path": "../SKILL.md",
    "sha256": ("5764d6f51c5cd2e9dccb650b2a8f04282e44aa6d118abbfd051c0eebfaa86fe3"),
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
        "e as an implementation.\n\nThe last candidate finally impl"
        "ements the native loop and must be retained in\nfull. It i"
        "s supplied below as previous-candidate reference source. M"
        "ake only\nthis destination lint correction, preserving its"
        " behavior: Ruff SIM102 rejects\nthe nested if old is not N"
        "one and new is not None / if re.findall differs in\nfinali"
        "zation regressions. Combine these conditions with and in a"
        " parenthesized\ncondition that formats to at most 100 colu"
        "mns. Do not return to a preflight or\nremove any workflow "
        "mechanics to fix lint. Return the complete corrected modul"
        "e.\n"
    ),
    "sha256": ("e895a4a1d5b74cfb4df8d0acc569b507f93485b7aaf589940d14a212fcc5925e"),
}
_CALCIFIER_SUBRECIPES = []
