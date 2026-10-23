# /// script
# requires-python = ">=3.13"
# dependencies = ["calcifier==0.2.0"]
# ///

"""Native PR improvement loop, ported from the pinned improve workflow."""

import difflib
import hashlib
import json
import re
from pathlib import Path
from typing import Any, Literal

from calcifier import (
    Budget,
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
    re.compile(r"\b(round|iteration|pass) [0-9]\b", re.IGNORECASE),
    re.compile(r"previous(ly)? (fix|attempt|version|round)", re.IGNORECASE),
    re.compile(
        r"(was|were) (added|moved|changed|renamed|removed) (here|to|from)",
        re.IGNORECASE,
    ),
    re.compile(r"per (the )?(review|reviewer|finding)", re.IGNORECASE),
)


@output_type
class Finding:
    id: str
    file: str
    line: int
    class_name: str
    severity: Literal["critical", "major", "minor", "info"]
    title: str
    evidence: str
    new_evidence: bool


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
    notes: str


class Halt(RuntimeError):
    pass


class ReviewerUnavailable(RuntimeError):
    pass


class ReviewerFailed(RuntimeError):
    pass


def propagate_budget(error: Exception) -> None:
    if type(error).__name__ == "BudgetExceeded":
        raise error


def artifact_path(rel: str, out_rel: str) -> bool:
    return bool(out_rel) and (rel == out_rel or rel.startswith(out_rel + "/"))


def glob_regex(pattern: str) -> re.Pattern[str]:
    escaped = re.escape(pattern).replace(r"\*\*", "\x01")
    escaped = escaped.replace(r"\*", "[^/]*").replace("\x01", ".*")
    return re.compile("^" + escaped + "$")


def in_scope(rel: str, scope: list[str]) -> bool:
    return any(glob_regex(pattern).match(rel) for pattern in scope)


def normalize_scope(patterns: list[str]) -> list[str]:
    for pattern in patterns:
        if (
            not pattern
            or pattern.startswith("/")
            or "\\" in pattern
            or any(part in {"", ".", ".."} for part in pattern.split("/"))
        ):
            raise Halt("invalid-scope: expected repository-relative literal/*/** globs")
    unique = sorted(set(patterns), key=lambda item: (len(item), item))
    result: list[str] = []
    for pattern in unique:
        covered = any(
            parent == "**" or (parent.endswith("/**") and pattern.startswith(parent[:-2]))
            for parent in result
        )
        if not covered:
            result.append(pattern)
    return result


def norm_file(value: str) -> str:
    return re.sub(r"^\./", "", value).strip()


def norm_class(value: str) -> str:
    return re.sub(r"[^a-z0-9]+", "-", value.lower().strip()).strip("-")


def identities(raw: Finding) -> tuple[str, str]:
    filename = norm_file(raw.file)
    category = norm_class(raw.class_name)
    return f"{filename}:{raw.line}:{category}", f"{filename}::{category}"


def clip(value: str, limit: int) -> str:
    return value[:limit] + "…" if len(value) > limit else value


def three_consecutive(rounds: list[int]) -> bool:
    values = sorted(set(rounds))
    return any(
        values[index + 1] == values[index] + 1 and values[index + 2] == values[index] + 2
        for index in range(max(0, len(values) - 2))
    )


def git(root: str, args: list[str]) -> str:
    result = run_command(
        ["git", "-C", root, *args],
        timeout_seconds=120,
        mutating=False,
    )
    if result.exit_code:
        raise RuntimeError(f"git {args!r} failed: {result.stderr.strip()}")
    return result.stdout


def git_paths(root: str, args: list[str]) -> list[str]:
    return sorted(set(path for path in git(root, args).split("\x00") if path))


def fingerprint(root: str, rel: str) -> str:
    path = Path(root) / rel
    try:
        mode = path.lstat().st_mode
        if path.is_symlink():
            content = str(path.readlink()).encode("utf-8")
        elif path.is_file():
            if not path.resolve().is_relative_to(Path(root)):
                raise RuntimeError(f"refusing an escaping file path: {rel}")
            content = path.read_bytes()
        elif path.is_dir():
            content = b"DIRECTORY"
        else:
            content = b"SPECIAL"
    except FileNotFoundError:
        return "MISSING"
    digest = hashlib.sha256(content).hexdigest()
    return f"{mode}:{digest}"


@step
def inspect_surface(root: str, head: str, out_rel: str) -> dict[str, Any]:
    tracked = git_paths(root, ["ls-files", "--cached", "-z"])
    untracked = git_paths(root, ["ls-files", "--others", "--exclude-standard", "-z"])
    index: dict[str, list[str]] = {}
    for record in git(root, ["ls-files", "--stage", "-z"]).split("\x00"):
        if record:
            entry, rel = record.split("\t", 1)
            index.setdefault(rel, []).append(entry)
    paths = sorted(set(tracked + untracked))
    fingerprints = {rel: fingerprint(root, rel) for rel in paths if not artifact_path(rel, out_rel)}
    return {
        "tracked": tracked,
        "untracked": untracked,
        "index": index,
        "fingerprints": fingerprints,
        "changed": git_paths(root, ["diff", "--name-only", "-z", head, "--"]),
        "status": git(root, ["status", "--porcelain=v1", "-z"]),
        "diff": git(
            root,
            ["diff", "--binary", "--no-ext-diff", "--no-textconv", head, "--"],
        ),
        "staged_diff": git(
            root,
            ["diff", "--cached", "--binary", "--no-ext-diff", head, "--"],
        ),
    }


def scope_files(root: str, scope: list[str], out_rel: str) -> list[str]:
    repository = Path(root)
    pending = [repository]
    found: list[str] = []
    while pending:
        directory = pending.pop()
        for path in sorted(directory.iterdir()):
            rel = path.relative_to(repository).as_posix()
            if artifact_path(rel, out_rel) or path.name in SKIP_DIRS:
                continue
            if path.is_dir() and not path.is_symlink():
                pending.append(path)
            elif (path.is_file() or path.is_symlink()) and in_scope(rel, scope):
                found.append(rel)
    return sorted(found)


def matching_market_entries(root: str, plugin_dir: str, document: dict[str, Any]) -> list[int]:
    indices: list[int] = []
    for index, entry in enumerate(document.get("plugins", [])):
        source = entry.get("source") if isinstance(entry, dict) else None
        if isinstance(source, str) and (Path(root) / source).resolve() == Path(plugin_dir):
            indices.append(index)
    return indices


@step
def establish_baseline(target: str, base_branch: str, out: str) -> dict[str, Any]:
    directory = Path(target).expanduser().resolve()
    if not directory.is_dir() or not any(directory.iterdir()):
        raise Halt("invalid-target: target must be an existing nonempty directory")
    root_result = run_command(
        ["git", "-C", str(directory), "rev-parse", "--show-toplevel"],
        timeout_seconds=60,
        mutating=False,
    )
    if root_result.exit_code:
        raise Halt(
            "not-a-repository: PR improvement requires an existing Git repository; "
            "this recipe never initializes repositories or creates commits"
        )
    root = str(Path(root_result.stdout.strip()).resolve())
    if Path(root).is_relative_to(Path(out)):
        raise Halt("artifact-root-conflict: the output directory must not contain the repository")
    out_rel = Path(out).relative_to(root).as_posix() if Path(out).is_relative_to(root) else ""
    current = git(root, ["branch", "--show-current"]).strip()
    base = base_branch.strip()
    if not base:
        symbolic = run_command(
            ["git", "-C", root, "symbolic-ref", "refs/remotes/origin/HEAD"],
            timeout_seconds=60,
            mutating=False,
        )
        base = symbolic.stdout.strip() if symbolic.exit_code == 0 else "main"
    if base.startswith("-") or any(char in base for char in "\x00\n\r"):
        raise Halt("invalid-base: expected a Git reference")
    short_base = re.sub(r"^refs/(heads/|remotes/origin/)", "", base)
    short_base = re.sub(r"^origin/", "", short_base)
    if current and current == short_base:
        raise Halt("on-base-branch: switch to the branch whose changes should be improved")
    base_sha = git(root, ["rev-parse", "--verify", base + "^{commit}"]).strip()
    head = git(root, ["rev-parse", "--verify", "HEAD"]).strip()
    branch_files = git_paths(root, ["diff", "--name-only", "-z", base_sha + "...HEAD", "--"])
    plugin_dir = ""
    plugin_file = ""
    plugin_version = ""
    cursor = directory
    while cursor.is_relative_to(Path(root)):
        manifest = cursor / ".claude-plugin" / "plugin.json"
        if manifest.is_file():
            document = json.loads(manifest.read_text(encoding="utf-8"))
            plugin_dir = str(cursor)
            plugin_file = manifest.relative_to(root).as_posix()
            plugin_version = str(document.get("version", ""))
            break
        if cursor == Path(root):
            break
        cursor = cursor.parent
    marketplace_file = ""
    marketplace_indices: list[int] = []
    marketplace = Path(root) / ".claude-plugin" / "marketplace.json"
    if plugin_dir and marketplace.is_file():
        document = json.loads(marketplace.read_text(encoding="utf-8"))
        marketplace_indices = matching_market_entries(root, plugin_dir, document)
        if marketplace_indices:
            marketplace_file = marketplace.relative_to(root).as_posix()
    surface = inspect_surface(root, head, out_rel)
    return {
        "target_dir": str(directory),
        "git_root": root,
        "git_initialized": False,
        "head_sha": head,
        "base": base,
        "base_sha": base_sha,
        "branch": current,
        "branch_files": branch_files,
        "plugin_dir": plugin_dir,
        "plugin_file": plugin_file,
        "plugin_version": plugin_version,
        "marketplace_file": marketplace_file,
        "marketplace_indices": marketplace_indices,
        "untracked": surface["untracked"],
        "untracked_digests": [
            {"path": rel, "sha": surface["fingerprints"][rel]}
            for rel in surface["untracked"]
            if rel in surface["fingerprints"]
        ],
        "digest_format": "lstat mode plus SHA-256 of bytes or symlink target",
        "surface": surface,
        "out_dir": out,
        "out_rel": out_rel,
    }


def protocol_file(value: str, description: str) -> Path:
    if not value.strip():
        raise ReviewerUnavailable(f"{description}: no original protocol file was configured")
    path = Path(value).expanduser().resolve()
    try:
        text = path.read_text(encoding="utf-8") if path.is_file() else ""
    except (OSError, UnicodeError) as error:
        raise ReviewerUnavailable(f"{description}: cannot read {path}: {error}") from error
    if not text.strip():
        raise ReviewerUnavailable(f"{description}: protocol file is missing or empty: {path}")
    return path


def markdown_cell(value: Any) -> str:
    return str(value).replace("|", "\\|").replace("\n", " ").replace("\r", " ")


class Loop:
    def __init__(self, config: dict[str, Any], out: Path) -> None:
        self.config = config
        self.out = out
        self.workflow = resource("workflows/improve.js")
        self.fixer = resource("agents/fixer.md")
        self.collector = resource("scripts/collect_metrics.py")
        self.baseline: dict[str, Any] = {}
        self.scope: list[str] = []
        self.root = ""
        self.head = ""
        self.out_rel = ""
        self.reviewer_protocol: Path | None = None
        self.references: list[Path] = []
        self.specialist_paths = {
            name: Path(path).expanduser().resolve()
            for name, path in config["specialist_protocols"].items()
        }
        self.notes: list[str] = []
        self.ledger: dict[str, Any] = {
            "version": 1,
            "target": config["target"],
            "reviewer": {"kind": config["reviewer_kind"], "name": config["reviewer_name"]},
            "scope": [],
            "decisions": [config["decision"]] if config["decision"] else [],
            "prior_rounds": [],
            "rounds": [],
            "findings": {},
            "result": None,
        }
        self.result: dict[str, Any] = {
            "converged": False,
            "capped": False,
            "halted": "",
            "escalation": None,
            "violations": [],
            "finalize_regressions": [],
            "rounds_run": 0,
            "fix_rounds": 0,
            "fixer_failed_rounds": [],
            "open_blocking": [],
            "open_minor_count": 0,
            "new_untracked_files": [],
            "ledger_path": str(out / "ledger.json"),
            "out_dir": str(out),
            "metrics": str(out / "metrics.json"),
            "metrics_valid": False,
            "partial_unreviewed_edits": False,
            "last_completed_action": "baseline-not-established",
            "notes": self.notes,
        }

    def blocking(self) -> list[dict[str, Any]]:
        return [
            finding
            for finding in self.ledger["findings"].values()
            if finding["status"] == "open" and finding["severity"] in BLOCKING
        ]

    def finish_fields(self) -> None:
        self.result["open_blocking"] = [
            {key: finding[key] for key in ("id", "severity", "title")}
            for finding in self.blocking()
        ]
        self.result["open_minor_count"] = sum(
            finding["status"] == "open" and finding["severity"] not in BLOCKING
            for finding in self.ledger["findings"].values()
        )
        self.ledger["result"] = self.result

    def checkpoint(self) -> None:
        self.finish_fields()
        write_json(self.out / "ledger.json", self.ledger)
        if self.result["converged"]:
            outcome = "converged"
        elif self.result["escalation"]:
            outcome = "escalated"
        elif self.result["capped"]:
            outcome = "capped, NOT converged"
        else:
            outcome = self.result["halted"] or "in progress; completion is not certified"
        lines = [
            f"Outcome: {outcome}",
            f"Review rounds: {self.result['rounds_run']}",
            f"Fix rounds: {self.result['fix_rounds']}",
            f"Remaining open minor/info findings: {self.result['open_minor_count']}",
            f"Partial/unreviewed edits: {self.result['partial_unreviewed_edits']}",
            "",
            "Open blocking findings:",
        ]
        lines.extend(f"- {finding['id']}: {finding['title']}" for finding in self.blocking())
        if self.result["escalation"]:
            lines.extend(["", self.result["escalation"]["message"]])
        lines.extend(["", "Notes:", *self.notes])
        lines.extend(
            [
                "",
                "Changes remain in the working tree; this recipe never commits or reverts.",
                "Continue with the same output directory or resume_ledger and a user ruling",
                "verbatim in decision. The ledger carries findings and verdicts forward.",
                f"Ledger: {self.out / 'ledger.json'}",
                f"Metrics: {self.out / 'metrics.json'}",
            ]
        )
        write_text(self.out / "status.md", "\n".join(lines) + "\n")
        table = ["| id | severity | status | verdict reason |", "| --- | --- | --- | --- |"]
        for finding in self.ledger["findings"].values():
            cells = [
                markdown_cell(finding.get(key, ""))
                for key in ("id", "severity", "status", "verdict_reason")
            ]
            table.append("| " + " | ".join(cells) + " |")
        table.extend(["", "Rounds:", ""])
        table.extend(json.dumps(record, ensure_ascii=False) for record in self.ledger["rounds"])
        write_text(self.out / "ledger.md", "\n".join(table) + "\n")

    def load_prior(self) -> None:
        configured = self.config["resume_ledger"]
        path = Path(configured).expanduser().resolve() if configured else self.out / "ledger.json"
        if not path.is_file():
            if configured:
                raise Halt("prior-ledger-missing: the configured continuation ledger is absent")
            return
        try:
            prior = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, ValueError) as error:
            self.notes.append(
                f"PRIOR LEDGER UNREADABLE ({error}): starting fresh; prior verdicts are lost."
            )
            return
        if (
            prior.get("version") != 1
            or Path(prior.get("target", "")).resolve() != Path(self.baseline["target_dir"])
            or prior.get("reviewer") != self.ledger["reviewer"]
        ):
            raise Halt("prior-ledger-mismatch: target, reviewer, and ledger version must match")
        self.ledger["prior_rounds"] = prior.get("prior_rounds", []) + prior.get("rounds", [])
        self.ledger["decisions"] = prior.get("decisions", []) + self.ledger["decisions"]
        for identity, finding in prior.get("findings", {}).items():
            restored = dict(finding)
            restored["rounds_seen"] = []
            restored["seen_prior"] = finding.get("seen_prior", []) + finding.get("rounds_seen", [])
            restored["fixed_rounds"] = []
            restored["fixed_prior"] = finding.get("fixed_prior", 0) + len(
                finding.get("fixed_rounds", [])
            )
            self.ledger["findings"][identity] = restored
        self.notes.append(
            f"Loaded prior ledger: {len(self.ledger['findings'])} findings carried over."
        )
        escalation = (prior.get("result") or {}).get("escalation")
        if escalation and not self.config["decision"]:
            self.result["escalation"] = escalation
            self.notes.append("The prior escalation needs a user ruling before another run.")

    def start(self) -> None:
        self.baseline = establish_baseline(
            self.config["target"], self.config["base_branch"], str(self.out)
        )
        self.root = self.baseline["git_root"]
        self.head = self.baseline["head_sha"]
        self.out_rel = self.baseline["out_rel"]
        self.ledger["target"] = self.baseline["target_dir"]
        directories = [Path(rel).parent.as_posix() for rel in self.baseline["branch_files"]]
        derived = ["**" if directory == "." else directory + "/**" for directory in directories]
        self.scope = normalize_scope(derived + self.config["extra_scope"])
        self.ledger["scope"] = self.scope
        self.baseline["scope"] = self.scope
        self.baseline["artifact_exclusion"] = self.out_rel
        self.baseline["pinned_workflow_sha256"] = hashlib.sha256(
            self.workflow.read_bytes()
        ).hexdigest()
        self.ledger["baseline"] = self.baseline
        write_json(self.out / "baseline.json", self.baseline)
        verify_artifact(self.out / "baseline.json")
        self.load_prior()
        if not self.baseline["branch_files"]:
            raise Halt("no-changes: the branch has no changed files against its base")
        files = scope_files(self.root, self.scope, self.out_rel)
        if not files:
            raise Halt(
                "empty-inspection-scope: scope matches zero files; no clean result is possible"
            )
        self.baseline["scope_files"] = files
        write_json(self.out / "baseline.json", self.baseline)
        self.reviewer_protocol = protocol_file(
            self.config["reviewer_protocol"],
            "Original " + self.config["reviewer_name"] + " reviewer instructions",
        )
        self.references = [
            protocol_file(path, "Configured reviewer/specialist reference")
            for path in self.config["reference_files"]
        ]
        version_setting = self.config["version_bump"]
        self.baseline["finalize"] = {
            "version_bump": (
                bool(self.baseline["plugin_version"])
                if version_setting == "auto"
                else version_setting == "on"
            ),
            "narration_strip": self.config["narration_strip"],
            "docs_pass": self.config["docs_pass"],
        }
        if self.baseline["finalize"]["version_bump"]:
            if not self.baseline["plugin_file"] or not self.baseline["plugin_version"]:
                raise Halt("version-baseline-missing: a version bump needs plugin metadata")
            required = [self.baseline["plugin_file"], self.baseline["marketplace_file"]]
            outside = [path for path in required if path and not in_scope(path, self.scope)]
            if outside:
                self.result["violations"] = outside
                raise Halt(
                    "version-bump-out-of-scope: both metadata copies need authorization; "
                    "add the listed paths to extra_scope or disable version_bump"
                )
        self.result["last_completed_action"] = "baseline"
        self.checkpoint()

    def context(self, task: str, data: dict[str, Any], files: list[Path]) -> Any:
        selected = tuple(dict.fromkeys([self.workflow, *files, *self.references]))
        return prepare_context(
            task,
            prior_results=json.dumps(data, ensure_ascii=False),
            files=selected,
            readable_roots=(Path(self.root), *selected),
        )

    def common_data(self) -> dict[str, Any]:
        return {
            "target": self.baseline["target_dir"],
            "repo_root": self.root,
            "base": self.baseline["base"],
            "base_sha": self.baseline["base_sha"],
            "immutable_head": self.head,
            "scope": self.scope,
            "artifact_exclusion": self.out_rel,
            "ledger": self.ledger,
            "reviewer": self.ledger["reviewer"],
            "reviewer_notes": self.config["reviewer_notes"],
            "configured_specialists": sorted(self.specialist_paths),
        }

    def review(self, round_number: int) -> Review:
        if self.reviewer_protocol is None:
            raise ReviewerUnavailable("The original reviewer protocol has not been loaded")
        final_round = round_number == self.config["max_rounds"] + 1
        data = self.common_data()
        data["round"] = round_number
        data["final_review_only_round"] = final_round
        data["working_tree_diff_against_base"] = git(
            self.root,
            [
                "diff",
                "--binary",
                "--no-ext-diff",
                "--no-textconv",
                self.baseline["base_sha"],
                "--",
            ],
        )
        data["scope_files"] = scope_files(self.root, self.scope, self.out_rel)
        if not data["scope_files"]:
            raise Halt("empty-inspection-scope: no files remain to review")
        history: list[dict[str, Any]] = []
        pending: set[str] = set()
        for wave in range(4):
            data["continuation_history"] = history
            data["specialist_waves_remaining"] = 3 - wave
            task = (
                "Perform or continue this one connected PR review using the complete original "
                "reviewer protocol file as the authoritative methodology. The pinned workflow "
                "defines the loop, ledger discipline, and reporting contract. Apply the caller's "
                "reviewer notes and all user rulings verbatim from the ledger. Review the current "
                "working tree against the supplied base, including the branch's commits. "
                "Scope globs constrain fixes; they do not screen semantic review candidates. "
                "Read the complete target and required references under the original protocol. "
                "Use embedded complete context directly; read saved task/files when not embedded. "
                "Do not edit, fix, write artifacts, or invoke platform Skill/Task tools. "
                "The provided original protocol replaces platform Skill invocation. "
                "For kind=agent, finish directly under that agent's original instructions. "
                "For kind=skill, request the exact named specialists prescribed by the original "
                "skill using mode=dispatch and agents. The host runs them with their actual "
                "configured protocol files; never replace a missing named specialist yourself. "
                "At most 3 specialist waves and 8 agents per wave are available. Dispatch mode "
                "must have empty findings and verified_fixed. To retry a failed or omitted "
                "dispatch, repeat its exact agent_type and prompt. Retain connected reasoning "
                "and all earlier reports across continuations. Finish with mode=direct and "
                "agents=[] only after the complete prescribed review is done. If an essential "
                "reviewer dependency is unavailable, start summary with REVIEWER-UNAVAILABLE: "
                "and explain it; never return an apparently clean substitute review. "
                "Report EVERY surfaced defect, including minor/info, mapping severities to "
                "critical|major|minor|info. Finding.class_name represents the source schema's "
                "class field. Reuse exact ledger ids even at shifted lines. Verify every fixed "
                "but unverified finding by reading current code: list genuine fixes in "
                "verified_fixed and re-file failures under the same id. Rejected findings "
                "stand unless genuinely new evidence contradicts verdict_reason; then reuse "
                "the id and set new_evidence=true. Deferred findings remain parked unless "
                "raised to blocking severity. Do not weaken guarantees to reach convergence. "
                "In the final review-only round no fix follows: report the true state."
            )
            self.checkpoint()
            reply = agent(
                "reviewer",
                task,
                working_directory=self.root,
                readable_paths=(Path(self.root), self.reviewer_protocol, *self.references),
                output=Review,
                context=self.context(task, data, [self.reviewer_protocol]),
                timeout=3600,
            )
            if reply.summary.startswith("REVIEWER-UNAVAILABLE:"):
                raise ReviewerUnavailable(reply.summary)
            history.append({"reviewer": reply.model_dump()})
            if reply.mode == "direct":
                if reply.agents or pending:
                    raise ReviewerFailed(
                        "Reviewer finished with undispatched/failed specialist work or agents "
                        "on a direct response; the review is incomplete"
                    )
                return reply
            if self.config["reviewer_kind"] != "skill":
                raise ReviewerFailed("An agent-kind reviewer must complete its own direct review")
            if wave == 3 or not reply.agents or reply.findings or reply.verified_fixed:
                raise ReviewerFailed("Invalid specialist dispatch or the 3-wave limit was exceeded")
            plan = reply.agents[:8]
            omitted = reply.agents[8:]
            for request in reply.agents:
                if request.agent_type not in self.specialist_paths:
                    raise ReviewerUnavailable(
                        f"Required named specialist {request.agent_type!r} has no original "
                        "protocol in specialist_protocols; supply its actual plugin instructions"
                    )
            protocols = {
                request.agent_type: protocol_file(
                    str(self.specialist_paths[request.agent_type]),
                    "Original named specialist " + request.agent_type,
                )
                for request in plan
            }

            def run_specialist(
                request: Dispatch,
                bound_protocols: dict[str, Path] = protocols,
            ) -> dict[str, Any]:
                original = bound_protocols[request.agent_type]
                assignment = (
                    "Act as the exact named specialist in the supplied original protocol file. "
                    "Apply its full original methodology to the reviewer's complete dispatch. "
                    "Read the complete target and necessary references. This is independent "
                    "read-only review; do not edit, invoke platform agents, or substitute "
                    "another specialist. Report failures explicitly. Use the complete embedded "
                    "context; read saved files when text is not embedded.\n\n" + request.prompt
                )
                specialist_data = self.common_data()
                specialist_data["dispatch"] = request.model_dump()
                try:
                    report = agent(
                        "specialist",
                        assignment,
                        working_directory=self.root,
                        readable_paths=(Path(self.root), original, *self.references),
                        output=str,
                        context=self.context(assignment, specialist_data, [original]),
                        timeout=3600,
                    )
                    return {
                        "dispatch": request.model_dump(),
                        "ok": bool(report.strip()),
                        "report": report,
                        "error": "" if report.strip() else "SPECIALIST FAILED: empty response",
                    }
                except Exception as error:
                    propagate_budget(error)
                    return {
                        "dispatch": request.model_dump(),
                        "ok": False,
                        "report": "",
                        "error": "SPECIALIST FAILED: " + str(error),
                    }

            reports = parallel(run_specialist, plan, max_workers=8)
            for report in reports:
                request = report["dispatch"]
                key = request["agent_type"] + "\x00" + request["prompt"]
                if report["ok"]:
                    pending.discard(key)
                else:
                    pending.add(key)
            for request in omitted:
                pending.add(request.agent_type + "\x00" + request.prompt)
            if omitted:
                self.notes.append(
                    f"Review {round_number}, wave {wave + 1}: {len(omitted)} requests "
                    "exceeded the 8-agent cap; continuation must dispatch the omitted work."
                )
            history.append(
                {
                    "wave": wave + 1,
                    "reports": reports,
                    "not_dispatched_over_cap": [request.model_dump() for request in omitted],
                }
            )
        raise ReviewerFailed("The reviewer never completed its bounded continuation protocol")

    def existing(self, raw: Finding, round_number: int) -> dict[str, Any] | None:
        findings = self.ledger["findings"]
        identity, coarse = identities(raw)
        if raw.id.strip() in findings:
            return findings[raw.id.strip()]
        if identity in findings:
            return findings[identity]
        matches = [
            finding
            for finding in findings.values()
            if finding["coarse"] == coarse and round_number not in finding["rounds_seen"]
        ]
        return matches[0] if len(matches) == 1 else None

    def merge_review(self, round_number: int, review: Review) -> None:
        fresh = reopened = refiled = 0
        for identity in review.verified_fixed:
            finding = self.ledger["findings"].get(identity.strip())
            if finding and finding["status"] == "fixed":
                finding["verified"] = True
        claimed: set[str] = set()
        for raw in review.findings:
            identity, coarse = identities(raw)
            if not norm_file(raw.file) or not norm_class(raw.class_name):
                raise ReviewerFailed("A finding lacks a file or defect class")
            finding = self.existing(raw, round_number)
            canonical = finding["id"] if finding else identity
            if canonical in claimed:
                raise ReviewerFailed(f"The review reported duplicate finding identity {canonical}")
            claimed.add(canonical)
            if finding is None:
                self.ledger["findings"][identity] = {
                    "id": identity,
                    "coarse": coarse,
                    "file": norm_file(raw.file),
                    "line": raw.line,
                    "class": norm_class(raw.class_name),
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
                reopened += 1
                finding["notes"].append(f"round {round_number}: fix did not hold, reopened")
            finding.update(
                status="open",
                verified=False,
                line=raw.line,
                severity=raw.severity,
                evidence=clip(raw.evidence, 400),
                last_round=round_number,
            )
            finding["rounds_seen"].append(round_number)
        missing = [
            finding["id"]
            for finding in self.ledger["findings"].values()
            if finding["status"] == "fixed" and not finding["verified"]
        ]
        if missing:
            raise ReviewerFailed("Review omitted required fix verification: " + ", ".join(missing))
        counts = {
            severity: sum(
                finding["status"] == "open" and finding["severity"] == severity
                for finding in self.ledger["findings"].values()
            )
            for severity in SEVERITIES
        }
        self.ledger["rounds"].append(
            {
                "round": round_number,
                "type": "review",
                "open": counts,
                "new": fresh,
                "reopened": reopened,
                "refiled_rejected": refiled,
                "summary": review.summary,
            }
        )

    def guard(self, surface: dict[str, Any]) -> bool:
        initial = self.baseline["surface"]
        before = initial["fingerprints"]
        after = surface["fingerprints"]
        violations: list[str] = []
        if git(self.root, ["rev-parse", "HEAD"]).strip() != self.head:
            violations.append("HEAD changed: commits or branch movement are forbidden")
        for rel in sorted(set(before) | set(after)):
            if artifact_path(rel, self.out_rel) or in_scope(rel, self.scope):
                continue
            if before.get(rel, "MISSING") != after.get(rel, "MISSING"):
                violations.append(rel + " (out-of-scope content/type/mode changed)")
        before_index = initial["index"]
        after_index = surface["index"]
        for rel in sorted(set(before_index) | set(after_index)):
            if artifact_path(rel, self.out_rel) or in_scope(rel, self.scope):
                continue
            if before_index.get(rel) != after_index.get(rel):
                violations.append(rel + " (out-of-scope index changed)")
        initial_untracked = set(initial["untracked"])
        unregistered = [
            rel
            for rel in surface["untracked"]
            if rel not in initial_untracked
            and in_scope(rel, self.scope)
            and not artifact_path(rel, self.out_rel)
        ]
        if violations or unregistered:
            self.result["converged"] = False
            self.result["halted"] = "scope-violation" if violations else "untracked-files-in-scope"
            self.result["violations"] = violations
            self.result["new_untracked_files"] = unregistered
            self.notes.append(
                "Guard halted the run. Nothing was reverted. Inspect the reported paths; "
                "register intended new files with git add -N, or explicitly authorize scope."
            )
            return False
        return True

    def escalation(self, kind: str, message: str, identities: list[str], round_number: int) -> None:
        self.result["escalation"] = {
            "type": kind,
            "round": round_number,
            "finding_ids": identities or [finding["id"] for finding in self.blocking()],
            "message": (
                message + " This needs a design decision, not another fix round. Do not weaken "
                "documented guarantees. Continue with the user's ruling verbatim in decision; "
                "the persisted ledger carries findings and verdicts forward."
            ),
        }

    def merge_verdicts(
        self, round_number: int, fixed: Fix | None, dispatched: list[str], diff_name: str
    ) -> list[str]:
        tally = {"fixed": 0, "rejected": 0, "deferred": 0}
        seen: set[str] = set()
        structural: list[str] = []
        if fixed is not None:
            ids = [verdict.id.strip() for verdict in fixed.verdicts]
            if len(ids) != len(set(ids)) or any(identity not in dispatched for identity in ids):
                self.notes.append("Invalid fixer verdict identities; no verdicts were accepted.")
                fixed = None
        if fixed is not None:
            for verdict in fixed.verdicts:
                finding = self.ledger["findings"][verdict.id.strip()]
                seen.add(finding["id"])
                tally[verdict.verdict] += 1
                if verdict.verdict == "fixed":
                    if not verdict.pin.strip():
                        seen.remove(finding["id"])
                        tally["fixed"] -= 1
                        self.notes.append(f"Missing required pin for {finding['id']}; kept open.")
                        continue
                    finding["status"] = "fixed"
                    finding["verified"] = False
                    finding["fixed_rounds"].append(round_number)
                    finding["pin"] = clip(verdict.pin, 300)
                elif verdict.verdict == "rejected":
                    if not verdict.reason.strip():
                        seen.remove(finding["id"])
                        tally["rejected"] -= 1
                        continue
                    finding["status"] = "rejected"
                    finding["verdict_reason"] = clip(verdict.reason, 400)
                    if verdict.structural and finding["severity"] in BLOCKING:
                        finding["structural"] = True
                        structural.append(finding["id"])
                elif finding["severity"] in BLOCKING:
                    finding["notes"].append(
                        f"round {round_number}: fixer deferred a blocker — kept open"
                    )
                else:
                    finding["status"] = "deferred"
                    finding["verdict_reason"] = clip(verdict.reason, 400)
            if fixed.notes:
                self.notes.append(f"Fix {round_number}: {fixed.notes}")
        failed = fixed is None
        if failed:
            self.result["fixer_failed_rounds"].append(round_number)
        unaddressed = [identity for identity in dispatched if identity not in seen]
        self.ledger["rounds"].append(
            {
                "round": round_number,
                "type": "fix",
                "verdicts": tally,
                "unaddressed": unaddressed,
                "failed": failed,
                "diff_file": diff_name,
            }
        )
        if unaddressed:
            self.notes.append("Unaddressed findings remain open: " + ", ".join(unaddressed))
        return structural

    def fix_round(self, round_number: int) -> bool:
        dispatched = [dict(finding) for finding in self.blocking()]
        ids = [finding["id"] for finding in dispatched]
        data = self.common_data()
        data["round"] = round_number
        data["dispatched_findings"] = dispatched
        task = (
            "Apply the complete pinned agents/fixer.md contract to exactly the dispatched "
            "blocking findings, in one connected fixing session. The complete original "
            "workflow and ledger are context. Honor user rulings and recorded verdicts. "
            "Return one verdict per dispatched id, including a specific rejection reason, "
            "structural=true for a real issue made impossible by an immutable documented "
            "promise, and a regression pin for behavioral fixes. Table-test string/severity "
            "heuristics across classes. For prose/frontmatter use pin='none: prose-only change'. "
            "Never weaken a guarantee, threat model, or stated behavior to obtain convergence. "
            "Touch only the supplied repository-relative scope globs, excluding artifacts. "
            "Preserve other uncommitted work. Never git checkout --, stash, reset, clean, or "
            "commit. Register new files with git add -N. Execute necessary pins/tests with "
            "your configured command capability. No process narration or unrelated cleanup. "
            "The HOST persists ledger, status, metrics, and cumulative diffs; do not write "
            "those artifacts. Return verdicts and notes after all edits."
        )
        self.result["partial_unreviewed_edits"] = True
        self.checkpoint()
        fixed: Fix | None = None
        try:
            fixed = agent(
                "worker",
                task,
                working_directory=self.root,
                readable_paths=(Path(self.root), self.fixer, *self.references),
                writable_paths=(Path(self.root),),
                required_capabilities=("commands",),
                output=Fix,
                context=self.context(task, data, [self.fixer]),
                timeout=3600,
            )
        except Exception as error:
            propagate_budget(error)
            self.notes.append(
                f"Fixer failed in round {round_number}: {error}. Partial edits may remain. "
                "The configured worker must support commands for tests and git add -N. "
                "After the host guard, the next action is an independent review."
            )
        surface = inspect_surface(self.root, self.head, self.out_rel)
        diff_name = f"fixes-round-{round_number}.diff"
        write_text(self.out / diff_name, surface["diff"])
        verify_artifact(self.out / diff_name, nonempty=False)
        structural = self.merge_verdicts(round_number, fixed, ids, diff_name)
        self.result["fix_rounds"] = round_number
        self.result["last_completed_action"] = "fix"
        guard_ok = self.guard(surface)
        self.checkpoint()
        if not guard_ok:
            return False
        refixed = [
            finding["id"]
            for finding in self.ledger["findings"].values()
            if len(finding["fixed_rounds"]) >= 2
        ]
        if structural:
            self.escalation(
                "structural-rejection",
                "Real blocking findings conflict with documented immutable demands.",
                structural,
                round_number,
            )
            return False
        if refixed:
            self.escalation(
                "relocation",
                "Findings have been fixed in multiple rounds; the latest edits are UNREVIEWED.",
                refixed,
                round_number,
            )
            return False
        return True

    def versions(self) -> dict[str, Any]:
        plugin_file = self.baseline["plugin_file"]
        if not plugin_file:
            return {"plugin": "", "marketplace": [], "version_fields": {}}
        document = json.loads((Path(self.root) / plugin_file).read_text(encoding="utf-8"))
        values: dict[str, Any] = {
            "plugin": document.get("version", ""),
            "marketplace": [],
            "version_fields": {},
        }

        def gather(value: Any, prefix: str) -> None:
            if isinstance(value, dict):
                for key, child in value.items():
                    location = prefix + "/" + key
                    if key == "version":
                        values["version_fields"][location] = child
                    gather(child, location)
            elif isinstance(value, list):
                for index, child in enumerate(value):
                    gather(child, prefix + "/" + str(index))

        gather(document, plugin_file)
        marketplace = self.baseline["marketplace_file"]
        if marketplace:
            document = json.loads((Path(self.root) / marketplace).read_text(encoding="utf-8"))
            entries = matching_market_entries(self.root, self.baseline["plugin_dir"], document)
            values["marketplace"] = [
                document["plugins"][index].get("version", "") for index in entries
            ]
            gather(document, marketplace)
        return values

    def capture(self) -> dict[str, Any]:
        surface = inspect_surface(self.root, self.head, self.out_rel)
        untracked_contents: dict[str, Any] = {}
        for rel in surface["untracked"]:
            if not in_scope(rel, self.scope) or artifact_path(rel, self.out_rel):
                continue
            path = Path(self.root) / rel
            if path.is_symlink():
                untracked_contents[rel] = {"symlink_target": str(path.readlink())}
            elif path.is_file() and path.resolve().is_relative_to(Path(self.root)):
                content = path.read_bytes()
                try:
                    untracked_contents[rel] = {"utf8": content.decode("utf-8")}
                except UnicodeDecodeError:
                    untracked_contents[rel] = {"hex": content.hex()}
        return {
            "surface": surface,
            "untracked_contents": untracked_contents,
            "versions": self.versions(),
        }

    def narration_observations(self, files: list[str]) -> list[dict[str, Any]]:
        observations: list[dict[str, Any]] = []
        for rel in files:
            path = Path(self.root) / rel
            if not path.resolve().is_relative_to(Path(self.root)):
                continue
            try:
                text = path.read_text(encoding="utf-8")
            except (OSError, UnicodeError):
                continue
            for line_number, line in enumerate(text.splitlines(), 1):
                if any(pattern.search(line) for pattern in NARRATION):
                    observations.append({"file": rel, "line": line_number, "text": line})
        return observations

    def next_versions(self) -> list[str]:
        baseline = self.baseline["plugin_version"]
        match = re.fullmatch(r"(\d+)\.(\d+)\.(\d+)(?:-([^+]+))?(?:\+.*)?", baseline)
        if not match:
            return []
        major, minor, patch = (int(match.group(index)) for index in (1, 2, 3))
        choices = [
            f"{major + 1}.0.0",
            f"{major}.{minor + 1}.0",
            f"{major}.{minor}.{patch + 1}",
        ]
        prerelease = match.group(4)
        if prerelease:
            choices.append(f"{major}.{minor}.{patch}")
            numeric = re.fullmatch(r"(.*?)(\d+)", prerelease)
            if numeric:
                prefix, number = numeric.groups()
                choices.append(f"{major}.{minor}.{patch}-{prefix}{int(number) + 1}")
        return choices

    def finalize(self) -> None:
        before = self.capture()
        if not self.guard(before["surface"]):
            return
        files = scope_files(self.root, self.scope, self.out_rel)
        if not files:
            raise Halt("empty-inspection-scope: finalization has no files to inspect")
        write_text(self.out / "pre-finalize.diff", before["surface"]["diff"])
        write_json(self.out / "pre-finalize.json", before)
        settings = self.baseline["finalize"]
        choices = self.next_versions() if settings["version_bump"] else []
        data = self.common_data()
        data.update(
            finalize_settings=settings,
            scope_files=files,
            narration_matches=self.narration_observations(files),
            baseline_plugin_version=self.baseline["plugin_version"],
            ordinary_single_increment_versions=choices,
            before_versions=before["versions"],
        )
        task = (
            "Finalize the tree after a completed independent review found zero blocking "
            "findings. Follow the pinned workflow's complete finalization mandate in one "
            "session. Touch only authorized scope and exclude artifacts; preserve uncommitted "
            "work and all fixer Git-safety/no-goalpost-moving rules. Do not otherwise improve, "
            "refactor, or re-fix the target. The host owns all snapshots and ledger writes. "
            "When narration_strip is enabled, inspect every scope file and remove/rewrite "
            "only actual process narration matching the workflow patterns. Supplied regex "
            "matches are observations, not exhaustive semantic candidates. Leave legitimate "
            "algorithm/tournament/pass text, old changelogs, and arguable hits unchanged. "
            "Count sites actually changed. When version_bump is enabled, make plugin.json "
            "exactly one increment above the recorded baseline for the entire run, collapsing "
            "any intermediate bumps, and set every matching marketplace entry to the identical "
            "version. Choose the appropriate single increment; supplied ordinary SemVer "
            "choices are mechanically calculated. For other version schemes, preserve the "
            "project's documented single-increment rule and explain it in notes. If disabled, "
            "do not change any version field and return version=''. When docs_pass is enabled, "
            "read documentation throughout scope, including README/SKILL.md and equivalents, "
            "and correct only statements made false by this run's changes. Do not weaken "
            "immutable promises or invent claims. Register any new files with git add -N. "
            "Return actual narration_sites_removed, resulting version, and notes."
        )
        self.result["partial_unreviewed_edits"] = True
        self.checkpoint()
        finalized: Finalize | None = None
        try:
            finalized = agent(
                "worker",
                task,
                working_directory=self.root,
                readable_paths=(Path(self.root), self.fixer, *self.references),
                writable_paths=(Path(self.root),),
                required_capabilities=("commands",),
                output=Finalize,
                context=self.context(task, data, [self.fixer]),
                timeout=3600,
            )
        except Exception as error:
            propagate_budget(error)
            self.notes.append(
                f"Finalize failed: {error}. Its possible partial edits are checked anyway."
            )
        after = self.capture()
        write_text(self.out / "post-finalize.diff", after["surface"]["diff"])
        write_json(self.out / "post-finalize.json", after)
        for filename in (
            "pre-finalize.diff",
            "post-finalize.diff",
            "pre-finalize.json",
            "post-finalize.json",
        ):
            verify_artifact(self.out / filename, nonempty=not filename.endswith(".diff"))
        if finalized is not None:
            if finalized.narration_sites_removed < 0:
                raise Halt("finalize-failed: narration_sites_removed cannot be negative")
            self.ledger["finalize"] = {
                "narration_sites_removed": finalized.narration_sites_removed,
                "version": finalized.version,
                "notes": clip(finalized.notes, 500),
            }
            if finalized.notes:
                self.notes.append("Finalize: " + finalized.notes)
        if not self.guard(after["surface"]):
            return
        before_surface = before["surface"]
        after_surface = after["surface"]
        candidates = set(before_surface["fingerprints"]) | set(after_surface["fingerprints"])
        candidates |= set(before_surface["index"]) | set(after_surface["index"])
        edits = sorted(
            rel
            for rel in candidates
            if not artifact_path(rel, self.out_rel)
            and (
                before_surface["fingerprints"].get(rel) != after_surface["fingerprints"].get(rel)
                or before_surface["index"].get(rel) != after_surface["index"].get(rel)
            )
        )
        mechanical_regressions: list[dict[str, Any]] = []
        if settings["version_bump"]:
            version = after["versions"]["plugin"]
            invalid = not version or version == self.baseline["plugin_version"]
            invalid = invalid or (bool(choices) and version not in choices)
            copies = after["versions"]["marketplace"]
            if self.baseline["marketplace_file"]:
                invalid = invalid or not copies or any(copy != version for copy in copies)
            invalid = invalid or (finalized is not None and finalized.version != version)
            if invalid:
                mechanical_regressions.append(
                    {
                        "file": self.baseline["plugin_file"],
                        "line": 0,
                        "why": "Expected exactly one baseline-relative bump in both metadata co"
                        "pies",
                    }
                )
        elif before["versions"]["version_fields"] != after["versions"]["version_fields"]:
            mechanical_regressions.append(
                {
                    "file": self.baseline["plugin_file"],
                    "line": 0,
                    "why": "Finalize changed version fields while version handling was disabled",
                }
            )
        elif finalized is not None and finalized.version:
            mechanical_regressions.append(
                {"file": "", "line": 0, "why": "Disabled version handling requires version=''"}
            )
        regressions = list(mechanical_regressions)
        if edits:
            delta = "".join(
                difflib.unified_diff(
                    before_surface["diff"].splitlines(keepends=True),
                    after_surface["diff"].splitlines(keepends=True),
                    fromfile="pre-finalize.diff",
                    tofile="post-finalize.diff",
                )
            )
            check_data = self.common_data()
            check_data.update(
                finalize_settings=settings,
                baseline_plugin_version=self.baseline["plugin_version"],
                ordinary_single_increment_versions=choices,
                finalize_changed_paths=edits,
                cumulative_diff_delta=delta,
                before=before,
                after=after,
                mechanical_regressions=mechanical_regressions,
            )
            check_task = (
                "Independently check EVERY finalize edit under the pinned workflow's "
                "Finalize-check contract. This is a dedicated read-only regression check, "
                "not another fixing pass. The host has mechanically checked scope, protected "
                "untracked content, HEAD, and new-file registration. Read the complete "
                "before/after snapshots, cumulative-diff delta, and CURRENT content around "
                "every changed site; baseline-untracked contents are included in snapshots. "
                "Do not treat an empty diff delta as proof that untracked/index edits are "
                "clean. Report every regression by file, line, and concrete why: legitimate "
                "content mistaken for narration; algorithm/tournament/pass/changelog text "
                "rewritten; false docs or unsupported claims; a version other than exactly "
                "one increment above baseline or disagreement between metadata copies; any "
                "version-field change when disabled; or any refactor, re-fix, weakening of "
                "guarantees, or improvement outside the finalization mandate. Validate any "
                "nonstandard version increment using the project's actual documented rule. "
                "An empty regressions list means all actual edits were read and are sound. "
                "Do not write, fix, invoke platform agents, or persist artifacts."
            )
            check = agent(
                "reviewer",
                check_task,
                working_directory=self.root,
                readable_paths=(Path(self.root), *self.references),
                output=FinalizeCheck,
                context=self.context(check_task, check_data, []),
                timeout=3600,
            )
            regressions.extend(
                {
                    "file": norm_file(regression.file),
                    "line": regression.line,
                    "why": clip(regression.why, 300),
                }
                for regression in check.regressions
            )
            if check.notes:
                self.notes.append("Finalize check: " + check.notes)
        else:
            self.notes.append(
                "Finalize made no tree/index edits; the completed clean review still covers it."
            )
        if regressions:
            self.result["halted"] = "finalize-regression"
            self.result["finalize_regressions"] = regressions
            self.notes.append("Finalize regressions remain in the tree; nothing was reverted.")
            return
        if finalized is None:
            self.result["halted"] = "finalize-failed"
            self.notes.append("Finalization did not complete; its mandate cannot be certified.")
            return
        self.result["partial_unreviewed_edits"] = False
        self.result["last_completed_action"] = "clean-review-and-checked-finalize"
        self.result["converged"] = True

    def run(self) -> None:
        self.start()
        if self.result["escalation"]:
            return
        counts: list[int] = []
        for round_number in range(1, self.config["max_rounds"] + 2):
            review = self.review(round_number)
            previous_findings = json.loads(json.dumps(self.ledger["findings"]))
            try:
                self.merge_review(round_number, review)
            except Exception:
                self.ledger["findings"] = previous_findings
                raise
            self.result["rounds_run"] = round_number
            self.result["partial_unreviewed_edits"] = False
            self.result["last_completed_action"] = "review"
            self.checkpoint()
            blocking = self.blocking()
            counts.append(len(blocking))
            if not blocking:
                self.finalize()
                return
            recurring = [
                finding["id"] for finding in blocking if three_consecutive(finding["rounds_seen"])
            ]
            if len(counts) >= 3 and 0 < counts[-3] <= counts[-2] <= counts[-1]:
                self.escalation(
                    "counts-non-decreasing",
                    f"Blocking counts did not decrease over three reviews: {counts[-3:]}",
                    recurring,
                    round_number,
                )
                return
            if recurring:
                self.escalation(
                    "recurrence",
                    "Blocking findings persisted across three consecutive review rounds.",
                    recurring,
                    round_number,
                )
                return
            if round_number == self.config["max_rounds"] + 1:
                self.result["capped"] = True
                self.notes.append(
                    "CAPPED, NOT CONVERGED: the final independent review still found blockers. "
                    "Uncommitted changes remain in the tree."
                )
                return
            if not self.fix_round(round_number):
                return

    def persist_exit(self, collect: bool = True) -> None:
        self.checkpoint()
        serious: Exception | None = None
        metrics_error = ""
        if collect:
            command = [
                "uv",
                "run",
                "--no-project",
                str(self.collector),
                "--ledger",
                str(self.out / "ledger.json"),
                "--out",
                str(self.out / "metrics.json"),
                "--diff-dir",
                str(self.out),
            ]
            if self.baseline:
                command.extend(["--repo", self.root, "--baseline-sha", self.head])
                for pattern in self.scope:
                    command.extend(["--scope", pattern])
            try:
                result = run_command(command, timeout_seconds=120, mutating=True)
                if result.exit_code:
                    metrics_error = result.stderr.strip() or result.stdout.strip()
                    metrics_error = metrics_error or "The pinned collector failed without output"
                else:
                    verify_artifact(self.out / "metrics.json")
                    self.result["metrics_valid"] = True
            except Exception as error:
                metrics_error = str(error)
                if type(error).__name__ == "BudgetExceeded" or (
                    type(error).__name__ == "RecipeError"
                    and getattr(error, "command_failure", None) not in {"launch", "timeout"}
                ):
                    serious = error
        else:
            metrics_error = "Interrupted or deadline exhausted; collector was not run"
        if metrics_error:
            self.result["metrics_valid"] = False
            self.notes.append("collect_metrics.py did not produce valid metrics: " + metrics_error)
            write_json(
                self.out / "metrics.json",
                {
                    "valid": False,
                    "error": metrics_error,
                    "ledger_path": str(self.out / "ledger.json"),
                    "note": "No clean zero-item metrics are synthesized.",
                },
            )
            if self.result["converged"]:
                self.result["converged"] = False
                self.result["halted"] = "metrics-failed"
        self.checkpoint()
        for filename in ("ledger.json", "ledger.md", "status.md", "metrics.json"):
            verify_artifact(self.out / filename)
        emit(self.ledger, name="ledger")
        if serious is not None:
            raise serious


@recipe(
    name="pr_improver",
    version="1",
    agents=("reviewer", "worker", "specialist"),
    capabilities=("Bash",),
    budget=Budget(max_agent_calls=1220, max_wall_seconds=3600),
    output_root=".pr-improver",
)
def pr_improver(
    reviewer_protocol: str,
    target: str = ".",
    base_branch: str = "",
    reviewer_kind: Literal["skill", "agent"] = "skill",
    reviewer_name: str = "pr-review-toolkit:review-pr",
    reviewer_notes: str = "",
    specialist_protocols: dict[str, str] | None = None,
    reference_files: list[str] | None = None,
    max_rounds: int = 5,
    extra_scope: list[str] | None = None,
    version_bump: Literal["auto", "on", "off"] = "auto",
    narration_strip: bool = True,
    docs_pass: bool = True,
    decision: str = "",
    resume_ledger: str = "",
) -> dict[str, Any]:
    """Supply actual original reviewer and named-specialist protocol files as trusted inputs."""
    if not 1 <= max_rounds <= 20:
        raise ValueError("max_rounds must be between 1 and 20")
    if not reviewer_name.strip():
        raise ValueError("reviewer_name must name the requested original reviewer")
    outputs = (
        "ledger.json",
        "ledger.md",
        "status.md",
        "metrics.json",
        "baseline.json",
        "pre-finalize.diff",
        "post-finalize.diff",
        "pre-finalize.json",
        "post-finalize.json",
        *(f"fixes-round-{number}.diff" for number in range(1, max_rounds + 1)),
    )
    out = ensure_directory(".", output_files=outputs, overwrite=True)
    config: dict[str, Any] = {
        "target": target,
        "base_branch": base_branch,
        "reviewer_protocol": reviewer_protocol,
        "reviewer_kind": reviewer_kind,
        "reviewer_name": reviewer_name.strip(),
        "reviewer_notes": reviewer_notes
        or (
            "Review the working tree against the resolved base as a pull request: correctness, "
            "tests, error handling, and every dimension the original reviewer prescribes."
        ),
        "specialist_protocols": specialist_protocols or {},
        "reference_files": reference_files or [],
        "max_rounds": max_rounds,
        "extra_scope": extra_scope or [],
        "version_bump": version_bump,
        "narration_strip": narration_strip,
        "docs_pass": docs_pass,
        "decision": decision,
        "resume_ledger": resume_ledger,
    }
    loop = Loop(config, out)
    fatal: Exception | None = None
    try:
        loop.run()
    except ReviewerUnavailable as error:
        loop.result["halted"] = "reviewer-unavailable"
        loop.notes.append(
            f"REVIEWER UNAVAILABLE: {error}. Supply the actual {reviewer_name} protocol "
            "and any required named-specialist protocols from their providing plugins; "
            "the default reviewer comes from pr-review-toolkit. No generic replacement "
            "review was performed. Existing edits and completed rounds remain in the ledger."
        )
    except ReviewerFailed as error:
        loop.result["halted"] = "reviewer-failed"
        loop.notes.append(str(error) + "; the current review is incomplete, not clean.")
    except Halt as error:
        kind, _, reason = str(error).partition(":")
        loop.result["halted"] = kind
        loop.notes.append(reason.strip() or kind)
    except Exception as error:
        loop.result["converged"] = False
        if type(error).__name__ == "BudgetExceeded":
            loop.result["halted"] = "budget-exhausted"
            fatal = error
        else:
            loop.result["halted"] = "host-operation-failed"
        loop.notes.append(
            f"{type(error).__name__}: {error}. Completion is not certified; inspect the "
            "last persisted round and any partial/unreviewed edits before continuing."
        )
    loop.persist_exit(collect=fatal is None)
    if fatal is not None:
        raise fatal
    return emit(loop.result, name="result")


if __name__ == "__main__":
    raise SystemExit(pr_improver.cli())


# --- calcifier metadata (skill provenance + sha256) ---
_CALCIFIER_COMPILATION = "compiled"
_CALCIFIER_SKILL = {
    "path": "../SKILL.md",
    "sha256": ("8bb6055905f95d4e0bbd6dbbab2be930a3d3e09cd22a18afbd306abcf9e0828f"),
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
        "e as an implementation.\n\nThe last candidate implements t"
        "he native workflow and is supplied below as\nprevious-cand"
        "idate reference source. Preserve its complete behavior and"
        " make the\nspecific destination Ruff B023 repair: run_spec"
        "ialist is defined inside a loop\nand captures the loop-ass"
        "igned protocols mapping. Bind that trusted mapping\nexplic"
        "itly at function definition (or move the function to a hel"
        "per and pass it\nas an argument), preserving the native fa"
        "n-out. Return the complete corrected\nmodule and satisfy a"
        "ll E,F,I,UP,B,SIM rules; do not reduce this to a preflight"
        ".\n"
    ),
    "sha256": ("d0880753c10cd77549152a22bb60a857ff7634a615cc047735daa1d50175d4ae"),
}
_CALCIFIER_SUBRECIPES = []
