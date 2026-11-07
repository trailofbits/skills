# /// script
# requires-python = ">=3.13"
# dependencies = ["calcifier==0.2.0"]
# ///

import base64
import json
import re
from collections import Counter
from pathlib import Path
from typing import Any, Literal
from urllib.parse import quote, urlencode

from calcifier import (
    Budget,
    agent,
    emit,
    fail,
    output_type,
    prepare_context,
    recipe,
    resource,
    run_command,
    step,
)

REFERENCES = [
    "action-profiles",
    "cross-file-resolution",
    "foundations",
    "vector-a-env-var-intermediary",
    "vector-b-direct-expression-injection",
    "vector-c-cli-data-fetch",
    "vector-d-pr-target-checkout",
    "vector-e-error-log-injection",
    "vector-f-subshell-expansion",
    "vector-g-eval-of-ai-output",
    "vector-h-dangerous-sandbox-configs",
    "vector-i-wildcard-allowlists",
]
ACTIONS = ("Claude Code Action", "Gemini CLI", "OpenAI Codex", "GitHub AI Inference")
VECTORS = (
    "Env Var Intermediary",
    "Direct Expression Injection",
    "CLI Data Fetch",
    "PR Target + Checkout",
    "Error Log Injection",
    "Subshell Expansion",
    "Eval of AI Output",
    "Dangerous Sandbox Configs",
    "Wildcard Allowlists",
)
SEVERITIES = ("High", "Medium", "Low", "Info")


@output_type
class Finding:
    vector: Literal["A", "B", "C", "D", "E", "F", "G", "H", "I"]
    severity: Literal["High", "Medium", "Low", "Info"]
    file: str
    source: str
    step: str
    impact: str
    evidence: str
    data_flow: list[str]
    remediation: str
    interactions: str


@output_type
class Instance:
    action: Literal["Claude Code Action", "Gemini CLI", "OpenAI Codex", "GitHub AI Inference"]
    reference: str
    location: str
    security_context: str
    findings: list[Finding]


@output_type
class Unresolved:
    reference: str
    source: str
    reason: str


@output_type
class Review:
    workflow: str
    instances: list[Instance]
    unresolved: list[Unresolved]


def github(endpoint: str, listing: bool = False) -> Any:
    argv = ["gh", "api", endpoint] + (["--paginate", "--slurp"] if listing else [])
    result = run_command(argv, timeout_seconds=60, mutating=False)
    if result.exit_code:
        error = (result.stderr + result.stdout).lower()
        if any(term in error for term in ("401", "403", "authentication", "gh auth login")):
            fail(
                f"GitHub authentication required. Run {chr(96)}gh auth login{chr(96)} "
                "to authenticate."
            )
        if "404" in error:
            fail(
                "Repository or workflow directory not found/private; no workflows inspected. "
                "Check the name and your token permissions."
            )
        fail("GitHub API failed: " + result.stderr)
    return json.loads(result.stdout)


def remote_target(target: str) -> tuple[str, str] | None:
    value = re.sub(r"^(?:https?://)?(?:www\.)?github\.com/", "", target.rstrip("/"))
    is_url = value != target.rstrip("/")
    if is_url and "/pull/" in value:
        fail("Did you mean to analyze " + "/".join(value.split("/")[:2]) + "?")
    if is_url and "/tree/" in value:
        base, tail = value.split("/tree/", 1)
        value = base + "@" + tail.split("/")[0]
    match = re.fullmatch(r"([A-Za-z0-9_.-]+)/([A-Za-z0-9_.-]+)(?:@(.+))?", value)
    if match:
        owner, repo, ref = match.groups()
        return owner + "/" + repo.removesuffix(".git"), ref or ""
    if is_url:
        fail("Unsupported GitHub URL; use owner/repo or owner/repo@ref.")
    return None


def collect(target: str) -> tuple[dict[str, dict[str, str]], str, str, Path]:
    remote = remote_target(target)
    docs: dict[str, dict[str, str]] = {}
    if remote:
        repository, ref = remote
        suffix = "?" + urlencode({"ref": ref}) if ref else ""
        endpoint = f"repos/{repository}/contents/"
        pages = github(endpoint + ".github/workflows" + suffix, listing=True)
        selected = sorted(
            (
                entry
                for page in pages
                for entry in page
                if entry["type"] == "file" and entry["name"].endswith((".yml", ".yaml"))
            ),
            key=lambda entry: entry["name"],
        )
        if not selected:
            fail(f"Empty inspection scope in {repository}: 0 root workflow files; audit stopped.")
        for entry in selected:
            path = entry["path"]
            data = github(endpoint + quote(path, safe="/") + suffix)
            if data.get("encoding") != "base64":
                fail(f"Cannot obtain complete workflow content: {path}")
            docs[path] = {
                "text": base64.b64decode(data["content"]).decode("utf-8"),
                "url": entry["html_url"],
                "source": repository + "/" + path,
            }
        return docs, repository, ref, Path.cwd()
    root = Path(target).expanduser().resolve()
    if not root.is_dir():
        fail("Local target must be a repository root directory.")
    paths = sorted(p for ext in ("*.yml", "*.yaml") for p in root.glob(".github/workflows/" + ext))
    if not paths:
        fail("No workflow files found. Empty inspection scope: 0 root workflows; audit stopped.")
    for path in paths:
        if not path.resolve().is_relative_to(root) or not path.is_file():
            fail(f"Workflow is not a regular file inside the repository: {path}")
        docs[path.relative_to(root).as_posix()] = {
            "text": path.read_text(encoding="utf-8"),
            "url": "",
            "source": "",
        }
    return docs, "", "", root


@step
def render(docs: dict[str, dict[str, str]], reviews: list[Review], repo: str, ref: str) -> str:
    indexed = {review.workflow: review for review in reviews}
    if len(reviews) != len(docs) or set(indexed) != set(docs):
        fail("Agent omitted, duplicated, or added workflow reviews; audit is incomplete.")
    grouped = {path: [f for i in indexed[path].instances for f in i.findings] for path in docs}
    instances = [instance for review in reviews for instance in review.instances]
    findings = [finding for items in grouped.values() for finding in items]
    counts = Counter(finding.severity for finding in findings)
    actions = Counter(instance.action for instance in instances)
    lines = [f"## Remote Analysis: {repo}" + (f" (@{ref})" if ref else "")] if repo else []
    names = ", ".join(path.rsplit("/", 1)[-1] for path in docs)
    summary = ", ".join(f"{counts[level]} {level}" for level in SEVERITIES)
    lines += [
        f"**Analyzed {len(docs)} workflows containing {len(instances)} AI action instances. "
        f"Found {len(findings)} findings: {summary}.**",
        "",
    ]
    lines += [f"Found {len(docs)} workflow files" + (f" in {repo}: {names}" if repo else "")]
    distribution = ", ".join(f"{actions[action]} {action}" for action in ACTIONS)
    lines += [
        f"Found {len(instances)} AI action instances across {len(docs)} workflow files: "
        + distribution,
        "",
    ]
    if not instances:
        lines += [f"No AI action steps found in {len(docs)} workflow files", ""]
    lines += (
        ["| Workflow File | Findings | Highest Severity |", "|---|---:|---|"]
        if findings
        else ["| Workflow File | AI Action Instances |", "|---|---:|"]
    )
    for path, items in grouped.items():
        highest = min((f.severity for f in items), key=SEVERITIES.index) if items else "None"
        lines.append(
            f"| {path} | {len(items)} | {highest} |"
            if findings
            else f"| {path} | {len(indexed[path].instances)} |"
        )
    if not findings:
        lines += ["", "| Action Type | Count |", "|---|---:|"]
        lines += [f"| {action} | {actions[action]} |" for action in ACTIONS if actions[action]]
    for path in docs:
        if indexed[path].instances:
            lines += ["", f"### {path}", "", "#### Security Context"]
        for instance in indexed[path].instances:
            if not all(
                s.strip()
                for s in (instance.reference, instance.location, instance.security_context)
            ):
                fail("Agent returned an incomplete AI action instance.")
            lines += [
                "",
                f"**{instance.action}: {instance.location}**",
                f"Action: {instance.reference}",
                instance.security_context,
            ]
        for finding in sorted(grouped[path], key=lambda f: SEVERITIES.index(f.severity)):
            required = (
                finding.file,
                finding.step,
                finding.impact,
                finding.evidence,
                finding.remediation,
                *finding.data_flow,
            )
            if not finding.data_flow or any(not value.strip() for value in required):
                fail("Agent returned an incomplete finding.")
            if repo and not finding.source.strip():
                fail("Remote finding is missing source attribution.")
            title = VECTORS["ABCDEFGHI".index(finding.vector)]
            lines += [
                "",
                f"### {title}",
                f"**Severity:** {finding.severity}",
                f"**File:** {finding.file}",
                f"**Step:** {finding.step}",
            ]
            if repo:
                lines += [f"**Source:** {finding.source}"]
            lines += [
                f"**Impact:** {finding.impact}",
                "**Evidence:**",
                "~~~yaml",
                finding.evidence,
                "~~~",
            ]
            label = "Impact Amplification" if finding.vector in "HI" else "Data Flow"
            lines += [f"**{label}:**"]
            lines += (
                finding.data_flow
                if finding.vector in "HI"
                else [f"{index}. {hop}" for index, hop in enumerate(finding.data_flow, 1)]
            )
            lines += [f"**Remediation:** {finding.remediation}"]
            if finding.interactions.strip():
                lines += [finding.interactions]
    if not findings:
        lines += ["", "No security findings identified."]
    unresolved = [item for review in reviews for item in review.unresolved]
    if unresolved:
        lines += [
            "",
            "## Unresolved References",
            "",
            "| Reference | Source | Reason |",
            "|---|---|---|",
        ]
        lines += [f"| {item.reference} | {item.source} | {item.reason} |" for item in unresolved]
    if repo:
        lines += [
            "",
            f"Analyzed {len(docs)} workflows, {len(instances)} AI action instances, "
            f"{len(findings)} findings in {repo}",
        ]
    return "\n".join(lines)


@recipe(agents=("worker",), capabilities=("Bash",), budget=Budget(2, 3600))
def audit_agentic_actions(target: str = ".") -> str:
    docs, repository, ref, directory = collect(target)
    for data in docs.values():
        data["lines"] = "\n".join(f"{n}: {s}" for n, s in enumerate(data["text"].splitlines(), 1))
    context = prepare_context(
        "Follow SKILL.md's full ordered audit for all input workflows in one session. Understand "
        "all references; use embedded texts or read declared files if absent. Use embedded task "
        "data, reading task.txt if absent. Numbered lines are observations. Resolve depth one and "
        "prompt/settings files before no-AI conclusions. Only fetch with gh api or diagnose auth "
        "with gh auth status; no edits, execution of YAML or runtime testing. Return one Review "
        "per input path with all direct/hidden instances and required contexts/findings. Evidence "
        "has line comments; traces have runtime notes. File includes remote GitHub links; source "
        "is attribution. H/I data_flow is amplification; keep caller mappings and unresolved refs.",
        prior_results=json.dumps({"repository": repository, "ref": ref, "workflows": docs}),
    )
    reviews = agent(
        "worker",
        context.prompt,
        context=context,
        working_directory=directory,
        readable_paths=tuple(resource(f"references/{name}.md") for name in REFERENCES)
        + ((directory,) if not repository else ()),
        required_capabilities=("commands",),
        output=list[Review],
        timeout=3600,
    )
    return emit(render(docs, reviews, repository, ref), name="audit-report")


if __name__ == "__main__":
    raise SystemExit(audit_agentic_actions.cli())


# --- calcifier metadata (skill provenance + sha256) ---
_CALCIFIER_COMPILATION = "compiled"
_CALCIFIER_SKILL = {
    "path": "../SKILL.md",
    "sha256": ("b2bdb88d559bc37e6c2c8314e28e7a2eb47e7cdd9da51e77da347d3517326dc0"),
}
_CALCIFIER_RESOURCES = [
    {
        "path": "references/action-profiles.md",
        "sha256": ("bbfaf6abe69b57e6289948340aa649482378b53f752a25cba92e7d4a740c4324"),
        "size": 8966,
        "source": None,
    },
    {
        "path": "references/cross-file-resolution.md",
        "sha256": ("b7d0d31fa24f1b987953ef0c11dc22ad48e81675b34de65c65ff79a74a3e6084"),
        "size": 12597,
        "source": None,
    },
    {
        "path": "references/foundations.md",
        "sha256": ("722ee7ea1dc06af8fa8cbb6cacb62f3c7c70139c8ed402752dd12c851a195d0e"),
        "size": 6659,
        "source": None,
    },
    {
        "path": "references/vector-a-env-var-intermediary.md",
        "sha256": ("7903992f54409760aae64ddb45bb3c26032223443f746ac6e3d8fd281bda877d"),
        "size": 4482,
        "source": None,
    },
    {
        "path": ("references/vector-b-direct-expression-injection.md"),
        "sha256": ("be6e5baff68d6770665ce6c7b7995c92dfdec3866b96ea21330c94b340499631"),
        "size": 4645,
        "source": None,
    },
    {
        "path": "references/vector-c-cli-data-fetch.md",
        "sha256": ("f11d2333f2b3800215311047c0b0ad35a1020c79dbb77614ff66a8c1fef16252"),
        "size": 5042,
        "source": None,
    },
    {
        "path": "references/vector-d-pr-target-checkout.md",
        "sha256": ("fc029037bb219aed5e130708eb4911ad235e47f1394e2155b5e40175ddb2d187"),
        "size": 5235,
        "source": None,
    },
    {
        "path": "references/vector-e-error-log-injection.md",
        "sha256": ("2c93623d96f49c4ab70bc2dd92e111b2cfca68ff70aaf579efd86812b0df15a9"),
        "size": 5380,
        "source": None,
    },
    {
        "path": "references/vector-f-subshell-expansion.md",
        "sha256": ("d6ede1d6a7769e1b75faed3dfeba7d212e0115fb9ddb09d39145bf65d062ba7f"),
        "size": 5917,
        "source": None,
    },
    {
        "path": "references/vector-g-eval-of-ai-output.md",
        "sha256": ("b9a47a41dd1470cc469cc030cd6cd6059b35741c78ba9f494c1d18b2fd65b686"),
        "size": 5602,
        "source": None,
    },
    {
        "path": ("references/vector-h-dangerous-sandbox-configs.md"),
        "sha256": ("892cb478d91c2e155b4084c5cf707bea5045bb4e2a11c7a5a1131b6212690b86"),
        "size": 5758,
        "source": None,
    },
    {
        "path": "references/vector-i-wildcard-allowlists.md",
        "sha256": ("68a4cd774ad829e535a8ec15ee492caefbae8e46f115f345b7f2bf2fecf88f86"),
        "size": 4372,
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
        "ed inspection that finds zero issues.\n\nThe previous acce"
        "pted candidate returned a successful emitted report when n"
        "o\nworkflow files were found. This violates the repository"
        "'s explicit instruction\nthat a checker inspecting zero it"
        "ems must exit nonzero. Fail with a clear message\nwhen the"
        " root workflow inspection scope is empty for either a loca"
        "l or remote\ntarget. A completed inspection of one or more"
        " workflows finding zero AI actions\nor zero vulnerabilitie"
        "s is a valid result and must remain distinguishable.\n"
    ),
    "sha256": ("df58864679afcdd2a4d2ad579c5436d55646bb40d9d21c412d6638474331c82d"),
}
_CALCIFIER_SUBRECIPES = []
