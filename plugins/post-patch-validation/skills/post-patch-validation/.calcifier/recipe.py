# /// script
# requires-python = ">=3.13"
# dependencies = ["calcifier==0.2.0"]
# ///

"""Run core post-patch evidence validation and preserve the human-review handoff."""

import json
from hashlib import sha256
from pathlib import Path
from typing import Any, Literal
from uuid import uuid4

import calcifier as cf

Evidence = Literal["source", "build", "runtime"]


@cf.output_type
class Plan:
    unsupported_reason: str
    checks_json: str
    harness_python: str
    evidence_level: Evidence
    coverage_concerns: list[str]


@cf.output_type
class Validation:
    runner_exit_code: int
    evidence_level: Evidence
    assessment: dict[str, Any]
    result: dict[str, Any]
    independent_review: str
    planning_concerns: list[str]
    cleanup_gaps: list[str]
    artifacts: list[str]
    human_review_required: bool


@cf.step
def checked(argv: list[str], cwd: Path, mutating: bool = True) -> cf.CommandResult:
    result = cf.run_command(argv, working_directory=cwd, timeout_seconds=3600, mutating=mutating)
    if result.exit_code != 0:
        cf.fail(f"Command failed ({result.exit_code}): {result.stderr}\n{result.stdout}")
    return result


@cf.recipe(
    version="1",
    agents=("worker",),
    capabilities=("Bash",),
    budget=cf.Budget(max_agent_calls=4, max_wall_seconds=3600),
    output_root="post-patch-validation",
)
def validate_patch(
    finding: str,
    finding_id: str,
    base_ref: str,
    repository: str = ".",
    patched_ref: str = "",
    patch_file: str = "",
    execution_authorized: bool = False,
    allow_env: tuple[str, ...] = (),
) -> Validation:
    if not execution_authorized:
        cf.fail("Explicit authorization to execute the local repository and tests is required.")
    if not finding.strip() or not finding_id.strip():
        cf.fail("Provide the reported finding and a stable finding ID.")
    if bool(patched_ref) == bool(patch_file):
        cf.fail("Supply exactly one patched ref or an existing binary patch file.")
    repo = Path(repository).resolve()
    if not repo.is_dir():
        cf.fail("The local repository directory does not exist.")
    packaged = (
        cf.resource("scripts/post_patch_validation.py"),
        cf.resource("scripts/pyproject.toml"),
        cf.resource("references/evidence-model.md"),
    )
    for path in packaged:
        if not path.read_text(encoding="utf-8").strip():
            cf.fail(f"Required packaged resource is empty: {path}")
    runner = ["uv", "run", str(packaged[0])]
    git = ["git", "-C", str(repo)]
    base = checked(
        [*git, "rev-parse", "--verify", "--end-of-options", f"{base_ref}^{{commit}}"],
        repo,
        False,
    ).stdout.strip()
    pins = ["--repo", str(repo), "--base-ref", base]
    patch = Path(patch_file).resolve() if patch_file else None
    patch_digest, patched = "", ""
    if patch is not None:
        if not patch.is_file():
            cf.fail("The explicit patch file does not exist.")
        patch_digest = sha256(patch.read_bytes()).hexdigest()
        diff = patch.read_text(encoding="utf-8")
        pins += ["--patch-file", str(patch)]
    else:
        patched = checked(
            [*git, "rev-parse", "--verify", "--end-of-options", f"{patched_ref}^{{commit}}"],
            repo,
            False,
        ).stdout.strip()
        pins += ["--patched-ref", patched]
        diff = checked(
            [*git, "diff", "--no-ext-diff", "--no-textconv", "--binary", base, patched],
            repo,
            False,
        ).stdout
    if not diff.strip():
        cf.fail("The patch inspection scope is empty; there is no change to validate.")
    run_name = f"runs/{uuid4().hex}"
    root = cf.ensure_directory(
        run_name,
        output_files=(
            "scaffold.json",
            "pinned.json",
            "handoff.json",
            "plan/plan.json",
            "plan/checks/harness.py",
            "base",
            "patched",
            "results",
            "empty-hooks",
        ),
        exclude_roots=(repo,),
    )
    hooks = cf.ensure_directory(f"{run_name}/empty-hooks")
    git += ["-c", f"core.hooksPath={hooks}"]
    plan_dir = cf.ensure_directory(
        f"{run_name}/plan", output_files=("plan.json", "checks/harness.py")
    )
    cf.ensure_directory(f"{run_name}/plan/checks", output_files=("harness.py",))
    schema = checked([*runner, "print-schema"], root).stdout
    scaffold = [
        *runner,
        "scaffold",
        *pins,
        "--finding-id",
        finding_id,
        "--finding-summary",
        finding,
    ]
    checked(
        [*scaffold, "--evidence-level", "runtime", "--output", str(root / "scaffold.json")],
        root,
    )
    base_tree, patch_tree = root / "base", root / "patched"
    created: list[Path] = []
    cleanup_gaps: list[str] = []
    try:
        for tree, revision in ((base_tree, base), (patch_tree, patched or base)):
            checked([*git, "worktree", "add", "--detach", str(tree), revision], root)
            created.append(tree)
        if patch is not None:
            checked(["git", "-C", str(patch_tree), "apply", "--binary", str(patch)], root)
        context = cf.prepare_context(
            "Author a strict plan under the authoritative skill and complete evidence model. "
            "Inspect the full isolated base and patched trees, callers, siblings, tests, "
            "cleanup, ownership, boundaries and all root-cause surfaces. Preserve the original "
            "reasoning workflow and all seven check kinds. Read the bundled runner and schema "
            "before authoring checks. Return checks_json as the schema's checks array. "
            "Put helpers in harness_python for the fixed {plan_dir}/checks/harness.py path; "
            "they may exercise any language using scratch. Do not execute code or edit files. "
            "Choose the highest honest evidence level. Preserve side-blind security assertions "
            "and flushed stdout PPV_REACHED immediately before each exploit/variant assertion. "
            "Separate compatibility contracts from security assertions. Return uncovered "
            "surfaces in coverage_concerns. Explain unavailable essential inputs or dependencies "
            "in unsupported_reason; otherwise leave it empty. The host runs the pinned runner.",
            files=(*packaged, root / "scaffold.json"),
            readable_roots=(*packaged, root),
            prior_results=json.dumps(
                {
                    "base_checkout": str(base_tree),
                    "patched_checkout": str(patch_tree),
                    "diff": diff,
                    "structural_schema": schema,
                }
            ),
        )
        draft = cf.agent(
            "worker",
            context.prompt,
            context=context,
            working_directory=plan_dir,
            readable_paths=(base_tree, patch_tree, repo),
            output=Plan,
        )
        if draft.unsupported_reason:
            cf.fail(f"Unsupported validation: {draft.unsupported_reason}")
        checks = json.loads(draft.checks_json)
        if not isinstance(checks, list) or not checks:
            cf.fail("The authored plan inspects zero checks.")
        if patch is not None and sha256(patch.read_bytes()).hexdigest() != patch_digest:
            cf.fail("The patch changed during planning; start a fresh pinned run.")
        pinned_path = root / "pinned.json"
        if draft.evidence_level == "source":
            checked([*scaffold, "--evidence-level", "source", "--output", str(pinned_path)], root)
        elif draft.evidence_level == "build":
            checked([*scaffold, "--evidence-level", "build", "--output", str(pinned_path)], root)
        else:
            checked([*scaffold, "--evidence-level", "runtime", "--output", str(pinned_path)], root)
        plan_path = plan_dir / "plan.json"
        plan = json.loads(pinned_path.read_text(encoding="utf-8"))
        plan["checks"] = checks
        cf.write_json(plan_path, plan)
        if draft.harness_python:
            cf.write_text(plan_dir / "checks/harness.py", draft.harness_python)
        checked([*runner, "validate-plan", "--plan", str(plan_path)], root)
        result_dir = root / "results"
        argv = [*runner, "run", "--plan", str(plan_path), "--output", str(result_dir)]
        argv += [part for name in allow_env for part in ("--allow-env", name)]
        execution = cf.run_command(argv, working_directory=root, timeout_seconds=3600)
        if execution.exit_code not in (0, 1, 10):
            cf.fail(f"Runner exit {execution.exit_code}: {execution.stderr}\n{execution.stdout}")
        names = (
            "result.json",
            "report.md",
            "plan.snapshot.json",
            "patch.diff",
            "artifact-manifest.json",
        )
        artifacts = [str(cf.verify_artifact(result_dir / name)) for name in names]
        result_path = result_dir / "result.json"
        result = json.loads(result_path.read_text(encoding="utf-8"))
        if not isinstance(result.get("assessment"), dict) or not result.get("checks"):
            cf.fail("Missing assessment or empty completed inspection scope.")
        review_context = cf.prepare_context(
            "Independently interpret this core runner validation under the authoritative skill "
            "and full evidence model. Inspect all check records, raw logs, archived helpers, "
            "scratch and manifest. Confirm baseline exploit/variant failures are the intended "
            "assertions and inspect stdout markers on both sides. Assess root-cause coverage "
            "and harness validity. Report the evidence level, complete assessment, every finding "
            "with check ID, assertion and logs, each gap and all artifact paths. Keep semantic "
            "concerns separate from the runner assessment. Source/build evidence cannot prove "
            "runtime safety. Require human review; do not claim the optional workflow's two "
            "independent approvals. Report unsupported dependencies and untested surfaces.",
            files=(*packaged, result_path, result_dir / "report.md"),
            readable_roots=(*packaged, root),
            prior_results=draft.model_dump_json(),
        )
        review = cf.agent(
            "worker",
            review_context.prompt,
            context=review_context,
            working_directory=root,
            readable_paths=(base_tree, patch_tree, result_dir),
            output=str,
        )
        if not review.strip():
            cf.fail("The independent evidence interpretation is missing.")
    finally:
        for tree in reversed(created):
            removal = cf.run_command(
                [*git, "worktree", "remove", "--force", str(tree)],
                working_directory=root,
                timeout_seconds=3600,
            )
            if removal.exit_code != 0:
                cleanup_gaps.append(f"Worktree cleanup failed: {tree}: {removal.stderr}")
    assessment = dict(result["assessment"])
    if cleanup_gaps:
        assessment["status"] = "incomplete"
        assessment["gaps"] = [
            *assessment["gaps"],
            *[{"check_id": None, "reason": gap} for gap in cleanup_gaps],
        ]
    report = Validation(
        execution.exit_code,
        draft.evidence_level,
        assessment,
        result,
        review,
        draft.coverage_concerns,
        cleanup_gaps,
        [*artifacts, str(plan_path), str(result_dir)],
        True,
    )
    cf.write_json(root / "handoff.json", report.model_dump())
    return cf.emit(report, name="validation")


if __name__ == "__main__":
    raise SystemExit(validate_patch.cli())


# --- calcifier metadata (skill provenance + sha256) ---
_CALCIFIER_COMPILATION = "compiled"
_CALCIFIER_SKILL = {
    "path": "../SKILL.md",
    "sha256": ("33b604f4d7d62eab393d710edb98b18505fcbe079c07c9428daa018f29439b54"),
}
_CALCIFIER_RESOURCES = [
    {
        "path": "references/evidence-model.md",
        "sha256": ("450175cb31b9d256c5783627bb7a708a9630f71eb5053fa8035f0daedfa9b7f1"),
        "size": 12305,
        "source": None,
    },
    {
        "path": "scripts/post_patch_validation.py",
        "sha256": ("4f3e0d4c8557d8632ea998e634fc6bd18a932ecabb94ceba8c51045a795decf3"),
        "size": 78163,
        "source": None,
    },
    {
        "path": "scripts/pyproject.toml",
        "sha256": ("81c10874ac5fd399c479b31a3c13713a4608138caad1ef61161ba139643ec02b"),
        "size": 116,
        "source": None,
    },
    {
        "path": "workflows/validate-patch.js",
        "sha256": ("632e39ebdecda2dee79b695346c2f8024c2a31a10b364396f4244757b3e65a71"),
        "size": 16386,
        "source": "../../workflows/validate-patch.js",
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
        " this guidance does not replace them.\n\nThe existing scri"
        "pts/post_patch_validation.py is the deterministic runner; "
        "pin/use it rather than reimplementing execution with a gen"
        "eric worker. The optional workflows/validate-patch.js docu"
        "ments the full orchestration, coverage lenses and two inde"
        "pendent review contracts. Port that orchestration natively"
        " when exposing it; never call Workflow as a generic adapte"
        "r.\nPreserve explicit user authorization before executing "
        "project code; do not infer authorization from the skill in"
        "vocation. Resolve immutable base/patch refs or an explicit"
        " patch file, run only in isolated worktrees, and never mod"
        "ify the user's patch. Scaffold a strict plan, then have an"
        " agent populate it, validate-plan, and run the original ru"
        "nner with argv arrays. Preserve all seven check kinds, sid"
        "e-blind execution, PPV_REACHED stdout evidence on both bas"
        "e/patched sides, minimal environments, helper hashes and a"
        "rchived evidence.\nThe runner's schema-2 result distinguis"
        "hes assessment completeness from findings. Preserve exit 0"
        " (pass), 1 (findings), 10 (incomplete), 64 (invalid); pars"
        "e/report results on 1 and 10 rather than raising before re"
        "ading the artifacts. In the full workflow preserve its cov"
        "erage lenses and two independent reviewer decisions, with "
        "READY only after both approve; supported failures can be N"
        "EEDS_REPAIR even with gaps, gaps alone BLOCKED, and failed"
        " review REVIEW_REQUIRED. Report evidence level, findings, "
        "gaps and all artifact paths honestly; do not claim compile"
        "/dry-run validation executed project checks.\n"
    ),
    "sha256": ("635e196915b4008592591fb4ef0cbd9f1fdae4fde0dcfa6a4f4ea54357c136a0"),
}
_CALCIFIER_SUBRECIPES = []
