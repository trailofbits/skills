# /// script
# requires-python = ">=3.13"
# dependencies = ["calcifier==0.2.0"]
# ///

"""Build a Trailmark structural review packet from complete before/after targets."""

import json
from pathlib import Path
from typing import Literal

import calcifier as cf


@cf.output_type
class Signal:
    rule: Literal[
        "entrypoint",
        "sink_path",
        "removed_guard",
        "tainted_boundary",
        "blast_radius",
        "complexity",
        "uncertain_edge",
        "dead_security",
    ]
    identifier: str
    source: str
    entrypoint_path: str
    evidence: str
    review_target: str
    before: int | None
    after: int | None
    local_threshold: float | None


@cf.output_type
class Analysis:
    adequate: bool
    inspected_before: int
    inspected_after: int
    before_version: str
    after_version: str
    before_languages: list[str]
    after_languages: list[str]
    confidence: Literal["High", "Medium", "Low"]
    metadata: dict[str, str]
    signals: list[Signal]
    changes: list[list[str]]
    entrypoints: str
    privilege_taint: str
    blast_complexity: str
    limitations: list[str]
    actions: list[str]


def git(root: Path, args: list[str], *, mutating: bool = False) -> str:
    argv = ["git", "-C", str(root), *args]
    result = cf.run_command(argv, timeout_seconds=120, mutating=mutating)
    if result.exit_code:
        cf.fail(f"Git operation failed: {result.stderr}")
    return result.stdout


def commit(root: Path, ref: str) -> str:
    return git(root, ["rev-parse", "--verify", "--end-of-options", ref + "^{commit}"]).strip()


def table(headers: list[str], rows: list[list[str]]) -> str:
    def row(values: list[str]) -> str:
        cells = [value.replace("|", "&#124;").replace("\n", "<br>") for value in values]
        return "| " + " | ".join(cells) + " |"

    return "\n".join([row(headers), row(["---"] * len(headers)), *map(row, rows)])


@cf.recipe(
    name="trailmark-review-gate",
    agents=("worker",),
    capabilities=("Bash",),
    budget=cf.Budget(max_agent_calls=2, max_wall_seconds=3600),
    output_root="trailmark-review-gate",
)
def review_gate(
    repository: str = ".",
    before: str = "",
    after: str = "HEAD",
    mode: Literal["refs", "branch", "range", "fix", "directories"] = "refs",
    languages: str = "auto",
    review_context: str = "",
    output_format: Literal["markdown", "json"] = "markdown",
) -> str:
    root = Path(repository).expanduser().resolve()
    prepared = {"mode": mode, "languages": languages, "review_context": review_context}
    plans = ["packet.md", "packet.json"]
    plans.extend("evidence/" + name for name in ("before.json", "after.json", "diff.json"))
    refs: list[str] = []
    if mode == "directories":
        if not before or not after:
            cf.fail("Directory comparison requires both complete directory inputs.")
        targets = [Path(value).expanduser().resolve() for value in (before, after)]
        if any(not target.is_dir() for target in targets):
            cf.fail("Both directory inputs must exist.")
    else:
        if mode == "range":
            separator = "..." if "..." in after else ".."
            parts = after.split(separator)
            if len(parts) != 2 or not all(parts):
                cf.fail("Supply an explicit A..B or A...B range.")
            base, head = [commit(root, value) for value in parts]
            if separator == "...":
                base = git(root, ["merge-base", base, head]).strip()
        else:
            head = commit(root, after)
            base = commit(root, before or ("HEAD" if mode == "branch" else head + "^"))
            if mode == "branch":
                base = git(root, ["merge-base", base, head]).strip()
        refs = [base, head]
        prepared["resolved_refs"] = json.dumps(refs)
        prepared["changed_paths"] = git(root, ["diff", "--name-status", base, head, "--"])
        for label, ref in zip(("before", "after"), refs, strict=True):
            listing = git(root, ["ls-tree", "-rz", "--full-tree", ref])
            prepared[label + "_tree"] = listing
            names = [item.split("\t", 1)[1] for item in listing.split("\0") if item]
            plans.extend(label + "/" + name for name in names)
            plans.append(label + "/.git")
        targets = []
    directory = cf.ensure_directory(".", output_files=tuple(plans), exclude_roots=tuple(targets))
    exports = ("before.json", "after.json", "diff.json")
    evidence = cf.ensure_directory("evidence", output_files=exports)
    worktrees: list[Path] = []
    try:
        for label, ref in zip(("before", "after"), refs, strict=False):
            target = directory / label
            git(root, ["worktree", "add", "--detach", str(target), ref], mutating=True)
            worktrees.append(target)
        targets = worktrees if refs else targets
        prepared["targets"] = json.dumps([str(target) for target in targets])
        files = tuple(
            cf.resource(path)
            for path in (
                "references/gate-rules.md",
                "references/output-format.md",
                "references/review-integration.md",
            )
        )
        context = cf.prepare_context(
            "Perform the authoritative workflow in order on the complete prepared targets. "
            "Refs were resolved and detached snapshots prepared without changing branches; "
            "directory inputs are already snapshots. Interpret full applicable references and "
            "local rules. Discover installed Trailmark interfaces; no other recipe is required. "
            "Keep connected analysis and checks in this session. Write only native before.json, "
            "after.json and diff.json exports in your working directory, preserving provenance. "
            "Targets are read-only. Report missing required evidence as inadequate. "
            "Return all normalized changes and applicable rule observations. For metric signals, "
            "include only rule-eligible nodes and return integer before/after values. Thresholds "
            "are null unless a stricter local rule is documented in evidence. Include other "
            "signals only when their rule fired. Include identifiers, available source locations, "
            "relevant entrypoint paths, evidence and review targets. Counts are inspected source "
            "files, not declarations. Metadata keys: provenance, features, coverage, "
            "native_diff_metadata, diagnostics. Changes have four columns: change, before, after, "
            "review target. Complete every narrative, limitation and action. Do not publish notes.",
            prior_results=json.dumps(prepared),
            files=files,
            readable_roots=files,
        )
        analysis = cf.agent(
            "worker",
            context.prompt,
            context=context,
            working_directory=evidence,
            readable_paths=(root, *targets),
            writable_paths=(evidence,),
            required_capabilities=("commands",),
            output=Analysis,
            timeout=3600,
        )
        problems = [*analysis.limitations, "PASS still requires human line-level review."]
        required = ("provenance", "features", "coverage", "native_diff_metadata", "diagnostics")
        complete = all(analysis.metadata.get(key, "").strip() for key in required)
        adequate = analysis.adequate and complete
        if not adequate:
            problems.append("Required evidence is unavailable or inadequate; review manually.")
        if (
            not analysis.before_version
            or analysis.before_version != analysis.after_version
            or not analysis.before_languages
            or analysis.before_languages != analysis.after_languages
        ):
            adequate = False
            problems.append("Snapshot version or language selection is missing or inconsistent.")
        zero_scope = analysis.inspected_before <= 0 or analysis.inspected_after <= 0
        if zero_scope:
            adequate = False
            problems.append("A snapshot inspected zero source files; scope is unverified.")
        for name in exports:
            path = evidence / name
            if path.is_file() and path.stat().st_size > 0:
                cf.verify_artifact(path)
            else:
                adequate = False
                problems.append(f"Required native evidence is missing: {name}.")
        triggered: list[list[str]] = []
        for signal in analysis.signals:
            severity = "FAIL"
            if signal.rule in ("blast_radius", "complexity"):
                if signal.before is None or signal.after is None or signal.before < 0:
                    cf.fail("Metric observation lacks valid before/after evidence.")
                default = max(5.0, signal.before * 0.25) if signal.rule == "blast_radius" else 3.0
                threshold = signal.local_threshold
                if threshold is not None and not 0 <= threshold <= default:
                    cf.fail("Local metric threshold must be documented and at least as strict.")
                threshold = default if threshold is None else threshold
                delta = signal.after - signal.before
                fires = delta > threshold if signal.rule == "blast_radius" else delta >= threshold
                if delta <= 0 or not fires:
                    continue
                severity = "WARN"
            elif signal.rule in ("uncertain_edge", "dead_security"):
                severity = "WARN"
            if not all(
                value.strip()
                for value in (signal.identifier, signal.evidence, signal.review_target)
            ):
                cf.fail("Triggered rule lacks exact evidence or a manual review target.")
            detail = "\n".join(
                filter(
                    None,
                    (
                        signal.identifier,
                        signal.source,
                        signal.entrypoint_path,
                        signal.evidence,
                        f"Before: {signal.before}; after: {signal.after}"
                        if signal.rule in ("blast_radius", "complexity")
                        else "",
                        "Review target: " + signal.review_target,
                    ),
                )
            )
            triggered.append([signal.rule, severity, detail])
        verdict: Literal["PASS", "WARN", "FAIL", "UNKNOWN"] = "UNKNOWN" if not adequate else "PASS"
        if adequate and triggered:
            verdict = "FAIL" if any(row[1] == "FAIL" for row in triggered) else "WARN"
        sections = {
            "Entrypoint And Reachability Changes": analysis.entrypoints,
            "Privilege And Taint Changes": analysis.privilege_taint,
            "Blast Radius And Complexity Changes": analysis.blast_complexity,
            "Evidence And Provenance": json.dumps(analysis.metadata, indent=2),
            "Limitations": "\n".join(problems),
            "Recommended Reviewer Actions": "\n".join(analysis.actions),
        }
        changes = analysis.changes
        if any(len(row) != 4 for row in changes):
            cf.fail("Structural change rows must include all four output columns.")
        payload = {
            "gate": verdict,
            "confidence": analysis.confidence,
            "triggered_rules": triggered,
            "structural_changes": changes,
            "sections": sections,
        }
        report = (
            "# Trailmark Review Gate\n\n## Verdict\n\n"
            f"Gate: {verdict}\nConfidence: {analysis.confidence}\n\n"
            "## Triggered Rules\n\n"
            + table(["Rule", "Verdict", "Evidence"], triggered)
            + "\n\n## Structural Changes\n\n"
            + table(["Change", "Before", "After", "Review target"], changes)
            + "".join(f"\n\n## {title}\n\n{text}" for title, text in sections.items())
        )
        cf.write_json("packet.json", payload)
        cf.write_text("packet.md", report)
        result = report if output_format == "markdown" else json.dumps(payload, indent=2)
        cf.emit(analysis, name="normalized-evidence")
        cf.emit(result, name="review-packet")
        if zero_scope:
            cf.fail("Gate UNKNOWN: zero inspected source files; see the emitted review packet.")
        return result
    finally:
        for target in reversed(worktrees):
            git(root, ["worktree", "remove", "--force", str(target)], mutating=True)


if __name__ == "__main__":
    raise SystemExit(review_gate.cli())


# --- calcifier metadata (skill provenance + sha256) ---
_CALCIFIER_COMPILATION = "compiled"
_CALCIFIER_SKILL = {
    "path": "../SKILL.md",
    "sha256": ("2678e6cc81ecba270cf94e4b91021e7b0e74d6f92a964b8889ebb0ac9ae0ee71"),
}
_CALCIFIER_RESOURCES = [
    {
        "path": "agents/code-slice-worker.md",
        "sha256": ("6b427cf3aa5caf357cd0fb18eca324b4207706bcd7e79eaff157590cd5816cb7"),
        "size": 1912,
        "source": "../../agents/code-slice-worker.md",
    },
    {
        "path": "references/gate-rules.md",
        "sha256": ("dff93b5606f6c2bbae013299925f2f8a48d0349fdb3d7b6dae838241f6d6e9d2"),
        "size": 2297,
        "source": None,
    },
    {
        "path": "references/output-format.md",
        "sha256": ("2d98fcb94cca3a73db481d123262653870a150e139ff29eec9d7905a94d9778f"),
        "size": 1028,
        "source": None,
    },
    {
        "path": "references/review-integration.md",
        "sha256": ("13d13913029ec06fa489b294a932ba4e9900929ed4455649756a82e6ed80e146"),
        "size": 1399,
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
