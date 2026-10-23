# /// script
# requires-python = ">=3.13"
# dependencies = ["calcifier==0.2.0"]
# ///

"""Prepare a repository for public release using the original ordered workflow."""

import json
from pathlib import Path
from shutil import which
from typing import Literal

from calcifier import (
    Budget,
    CommandResult,
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

LANGUAGE_REFS = (
    (("pyproject.toml", "setup.py"), "references/python.md"),
    (("CMakeLists.txt", "Makefile"), "references/c-cpp.md"),
    (("Cargo.toml",), "references/rust.md"),
    (("go.mod",), "references/go.md"),
    (("package.json",), "references/javascript.md"),
    (("Gemfile",), "references/ruby.md"),
)


@output_type
class Indicator:
    label: str
    present: bool


@output_type
class WorkerResult:
    status: Literal["prepared", "blocked", "advisory"]
    report: str


@output_type
class Review:
    status: Literal["prepared", "blocked", "advisory"]
    report: str
    organization: Literal["generic", "trailofbits"]
    tracked_file_count: int
    final_readiness: str
    indicators: list[Indicator]


def command(argv: list[str], directory: Path, timeout: float = 60.0) -> CommandResult:
    return run_command(argv, timeout_seconds=timeout, working_directory=directory, mutating=False)


def checked(argv: list[str], directory: Path) -> CommandResult:
    result = command(argv, directory)
    if result.exit_code != 0:
        fail(f"Command failed ({result.exit_code}): {argv!r}\n{result.stderr}")
    return result


@step
def parse_checklist(text: str) -> list[Indicator]:
    indicators: list[Indicator] = []
    for line in text.splitlines():
        stripped = line.strip()
        if stripped.startswith(("[x] ", "[ ] ")):
            indicators.append(Indicator(label=stripped[4:], present=stripped[1] == "x"))
    if not indicators:
        fail("The readiness checker inspected zero checklist items; inspect its output.")
    return indicators


@recipe(
    name="open-sourcing",
    version="1",
    agents=("worker",),
    capabilities=("Bash",),
    budget=Budget(max_agent_calls=2, max_wall_seconds=3600),
    output_root="open-sourcing-results",
)
def open_sourcing(
    project_directory: str,
    validation_directory: str,
    request: str,
    confidentiality_history: str,
    external_audit_evidence: str = "",
    scope: Literal["public-repository", "private-package"] = "public-repository",
    organization: Literal["auto", "generic", "trailofbits"] = "auto",
) -> Review:
    """Disclose any past secrets, client material, and engagement-derived test fixtures."""
    repo = Path(project_directory).resolve()
    validation = Path(validation_directory).resolve()
    if not repo.is_dir() or not validation.is_dir():
        fail("Project and validation directories must both exist.")
    if repo == validation or repo in validation.parents or validation in repo.parents:
        fail("Use a separate validation directory outside the repository.")
    if not request.strip():
        fail("Provide the requested preparation, review, licensing, or release task.")
    root = checked(["git", "rev-parse", "--show-toplevel"], repo)
    if Path(root.stdout.strip()).resolve() != repo:
        fail("project_directory must name the repository root.")
    tracked_output = checked(["git", "ls-files", "-z"], repo)
    tracked = [name for name in tracked_output.stdout.split("\0") if name]
    if not tracked:
        fail("There are zero tracked files; no repository inspection can be reported clean.")
    other_output = checked(["git", "ls-files", "--others", "--exclude-standard", "-z"], repo)
    others = [name for name in other_output.stdout.split("\0") if name]
    paths = sorted(set(tracked) | set(others))
    count = int(checked(["git", "rev-list", "--count", "--all"], repo).stdout.strip())
    if scope == "public-repository" and count == 0:
        fail("There are zero commits; a full-history inspection has no items to inspect.")
    detection_script = resource("scripts/detect_org.sh")
    readiness_script = resource("scripts/check_readiness.sh")
    detected = command(["bash", str(detection_script)], repo)
    detection = detected.stdout.strip()
    profile: Literal["generic", "trailofbits"]
    if organization == "auto":
        if detected.exit_code != 0 or detection not in ("generic", "trailofbits"):
            fail("Organization detection failed; supply an explicit organization override.")
        profile = "trailofbits" if detection == "trailofbits" else "generic"
    else:
        profile = organization
    scan: CommandResult | None = None
    gitleaks = which("gitleaks") if scope == "public-repository" else None
    trufflehog = which("trufflehog") if scope == "public-repository" else None
    if gitleaks is not None:
        scan = command([gitleaks, "git", "."], repo, 900.0)
    elif trufflehog is not None:
        scan = command([trufflehog, "git", repo.as_uri()], repo, 900.0)
    names = {Path(name).name for name in paths}
    candidates = [
        ref for markers, ref in LANGUAGE_REFS if any(marker in names for marker in markers)
    ]
    if any(path.endswith(".gemspec") for path in paths):
        candidates.append("references/ruby.md")
    reference_names = ["references/licensing.md"] + [ref for _markers, ref in LANGUAGE_REFS]
    if profile == "trailofbits":
        reference_names.append("references/trailofbits.md")
    reference_paths = tuple(resource(name) for name in reference_names)
    scan_data: dict[str, object] | None = None
    if scan is not None:
        scan_data = {
            "argv": scan.argv,
            "exit_code": scan.exit_code,
            "stdout": scan.stdout,
            "stderr": scan.stderr,
        }
    observations = {
        "scope": scope,
        "organization": profile,
        "tracked_files": tracked,
        "untracked_files": others,
        "commits_across_refs": count,
        "marker_reference_candidates": sorted(set(candidates)),
        "confidentiality_history": confidentiality_history,
        "external_audit_evidence": external_audit_evidence,
        "initial_scanner_observation": scan_data,
        "detect_script": str(detection_script),
        "readiness_script": str(readiness_script),
        "available_references": [str(path) for path in reference_paths],
        "validation_directory": str(validation),
    }
    context = prepare_context(
        task=request, prior_results=json.dumps(observations, ensure_ascii=False)
    )
    prompt = (
        "Perform the requested work using the authoritative skill and references, keeping "
        "its connected reasoning and original ordering in this session. The full repository "
        "is your target; marker matches are routing hints, not an exhaustive candidate set. "
        "Use complete embedded references directly; otherwise read the matching references "
        "through the declared filesystem view. Apply the chosen organization throughout. "
        "For private-package scope, follow only applicable release-management guidance. "
        "The scanner transcript is an observation, not a completed audit: establish full "
        "history coverage across refs and rerun with supported options when necessary. "
        "Ask the source's confidentiality questions if disclosures are absent or ambiguous. "
        "Audit logs/artifacts, old releases, issues, PRs and wiki using available access. "
        "Complete Step 2 before readiness checks or unrelated modifications. If that audit "
        "is unresolved, stop progression and report the missing evidence or questions. If "
        "sensitive history exists, follow the source's fresh-repository guidance; revoked "
        "keys, rewritten history and client-derived fixtures do not justify publication. "
        "Do not expose secret values in the report. Run the supplied readiness script for "
        "Step 3 yourself when applicable; unchecked indicators are discussion prompts. "
        "Make authorized fixes, retain working tooling, and interpret the complete licensing "
        "and applicable language references. Use documented fallbacks when another skill "
        "is unavailable; do not require another recipe. Use commands for current version "
        "and action-SHA resolution, tests, CI audits, settings and release preparation. "
        "Perform the original Final Review in the separate validation directory. Ensure "
        "clean-clone validation covers the proposed final tree, not merely an old HEAD. "
        "Agents never commit. Report inaccessible services, internal processes and missing "
        "decisions honestly. Return a complete user-facing report covering changes, evidence, "
        "remaining deliberate gaps, warnings and owner actions. Use prepared only after all "
        "applicable work and required checks finish, blocked for unfinished prerequisites, "
        "and advisory for advice alone. The host will repeat the readiness check afterward."
    )
    work = agent(
        "worker",
        prompt,
        working_directory=repo,
        readable_paths=(repo, validation, *reference_paths, detection_script, readiness_script),
        writable_paths=(repo, validation),
        required_capabilities=("commands",),
        context=context,
        output=WorkerResult,
        timeout=3600,
    )
    if not work.report.strip():
        fail("The worker returned no report; required conclusions cannot be invented.")
    emit(work, name="agent-review")
    readiness = ""
    indicators: list[Indicator] = []
    file_count = len(tracked)
    if work.status == "prepared":
        final_output = checked(["git", "ls-files", "-z"], repo)
        final_files = [name for name in final_output.stdout.split("\0") if name]
        if not final_files:
            fail("Final inspection has zero tracked files; no clean result can be issued.")
        file_count = len(final_files)
        if scope == "public-repository":
            final_check = checked(["bash", str(readiness_script)], repo)
            readiness = final_check.stdout
            indicators = parse_checklist(readiness)
    return emit(
        Review(
            status=work.status,
            report=work.report,
            organization=profile,
            tracked_file_count=file_count,
            final_readiness=readiness,
            indicators=indicators,
        ),
        name="open-sourcing-review",
    )


if __name__ == "__main__":
    raise SystemExit(open_sourcing.cli())


# --- calcifier metadata (skill provenance + sha256) ---
_CALCIFIER_COMPILATION = "compiled"
_CALCIFIER_SKILL = {
    "path": "../SKILL.md",
    "sha256": ("da8d876edfc13f234cb88a2531da86a5e37d417d63d5c4b174ad18b6a20e0c53"),
}
_CALCIFIER_RESOURCES = [
    {
        "path": "references/c-cpp.md",
        "sha256": ("5ed6e8fbd5cb84e8fef35fd796b86dd9dfc7b237de682a9d99270a8861bac2e5"),
        "size": 2446,
        "source": None,
    },
    {
        "path": "references/go.md",
        "sha256": ("ebbf308893bdf4630b63b96abc4351f879aeeeacb68c0e838564f8ccd0f34a38"),
        "size": 2441,
        "source": None,
    },
    {
        "path": "references/javascript.md",
        "sha256": ("690f9317588cd3613af31df4e7d01f37ef1dede015cdfe3d9296cbbe083da2b6"),
        "size": 1536,
        "source": None,
    },
    {
        "path": "references/licensing.md",
        "sha256": ("c520acae25b07eec233af5a7f8c799a5b7755c102c6e5f2d8fbb5538807647d5"),
        "size": 4400,
        "source": None,
    },
    {
        "path": "references/python.md",
        "sha256": ("464a91db0a02d1bb9ec731b6e6a7deebc54a3ad7ea0432bb81e82ec381fa9b03"),
        "size": 5096,
        "source": None,
    },
    {
        "path": "references/ruby.md",
        "sha256": ("da9744fed9bcfaae5bff7a3bd33889053224120392c0443d868e199b27c2a03b"),
        "size": 1254,
        "source": None,
    },
    {
        "path": "references/rust.md",
        "sha256": ("6bc26b2a6d3f201ee39b05f9b0292d06345b51dd3eab424247bf14e58e8dd9c0"),
        "size": 2398,
        "source": None,
    },
    {
        "path": "references/trailofbits.md",
        "sha256": ("5e2aeb7382f0dad52d94a67f0f0a13a998cc5502190bc8a2207554ab3b0c6b7b"),
        "size": 3694,
        "source": None,
    },
    {
        "path": "scripts/check_readiness.sh",
        "sha256": ("19c3eab5f1f158a06ef9a9f56d2dd53e26443b79f64665a865a494baa4174ff4"),
        "size": 2487,
        "source": None,
    },
    {
        "path": "scripts/detect_org.sh",
        "sha256": ("79d4de769a6f6422be017b7978d95c274fff131d929d74ec0524f2bd971e9bcf"),
        "size": 741,
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
