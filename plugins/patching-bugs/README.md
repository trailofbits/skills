# Patching Bugs

An agent coordinates focused skills to repair one supplied bug or falsifiable hypothesis in a
local Git repository. Fresh agents reproduce and validate the claim, make a scoped repair, and
prove the patch against the baseline, patched, and completely reverted trees.

Start with [patching-bugs](skills/patching-bugs/SKILL.md). Supply a clean target checkout with a
working project build and a run directory outside its tracked tree. The workflow handles runtime
and compiler failures and requires the `regression-hunt` plugin for the final regression check.
It never pushes or opens a PR.

The coordinator and standalone skills use any root `AGENTS.md`,
`PATCHING_GUIDELINES.md`, and `THREAT_MODEL.md` as described in the
[project guidance](references/records.md#project-guidance).

## Skills

| Skill | Responsibility |
| --- | --- |
| [patching-bugs](skills/patching-bugs/SKILL.md) | Coordinate one claim, repair attempts, regression check, and reports |
| [reproduce-bug](skills/reproduce-bug/SKILL.md) | Exercise the unchanged baseline and retain the PoC and raw receipts |
| [validate-bug](skills/validate-bug/SKILL.md) | Independently rerun the unchanged PoC and judge the claim |
| [implement-patch](skills/implement-patch/SKILL.md) | Fix the scoped invariant, test variants, and create one local commit |
| [prove-patch](skills/prove-patch/SKILL.md) | Independently run scoped checks and three-arm proof |

The [record contract](references/records.md) defines the run records, numbered attempts, and
receipt manifests. A reportable run produces `report.html` for the auditor, including failed and
inconclusive runs. Only a verified patch with a `READY` verdict produces
`maintainer-report.html` for the local handoff.

## Deterministic helpers

The standard-library scripts require Python 3.13+; invoke them with `uv run --no-project`.
They do not dispatch agents or replace independent review.

- [records.py](scripts/records.py): validate records and repair scope, and write or check receipt
  manifests.
- [arms.py](scripts/arms.py): build and exercise baseline, patched, and completely reverted trees
  in isolated worktrees.
- [render.py](scripts/render.py): validate retained evidence and render the auditor report and,
  when ready, the maintainer handoff.

## Development

Run `make check` from the repository root for repository checks and behavioral tests. For the
plugin's type check, run `uv sync --frozen` and `uv run --frozen ty check scripts tests` from this
directory.

## Calcifier recipe for `prove-patch`

The [`prove-patch` Python recipe](skills/prove-patch/.calcifier/recipe.py) was generated with Calcifier 0.2.0. It pins the source skill and its packaged resources so source changes are checked before execution.

Install the matching release with Python 3.13 or later:

```sh
uv tool install 'calcifier==0.2.0'
```

The recipe's PEP 723 inline metadata also declares Python >=3.13 and pins `calcifier==0.2.0`. `uv run` can resolve those script dependencies; use `calcifier exec` for reviewed execution with Calcifier's trust checks.

Configure `worker` in a version-1 agent-config file following [the Calcifier 0.2.0 provider setup](https://github.com/trailofbits/calcifier/blob/v0.2.0/docs/providers.md). Worker tools depend on the configured agent provider; host tool providers do not add tools to an agent.

From this plugin directory, check the recipe before execution:

```sh
calcifier lint skills/prove-patch/.calcifier/recipe.py --portable
```

Review the complete generated Python before granting trust. Run `calcifier exec skills/prove-patch/.calcifier/recipe.py` with `--agent-config agents.json` and one `--input NAME=VALUE` for each required input below. Add `--trust` after review to record consent for those exact bytes.

Choose a fresh, dedicated report directory with `--output-dir PATH`. The override protects existing output files; it does not isolate host commands or grant workers additional tools.

| Input | Type | Default |
| --- | --- | --- |
| `plan` | `Plan` | Required |

The recipe takes one structured plan. Required keys: target_repo, run_dir, attempt (1..3), prover_agent_id, case_specs, project_checks, build_argv, poc_argv, unproven_limits and worktree_output_files; optional timeout defaults to 600 seconds (must be >0 and <=600). Use existing disjoint repository/run roots; run.json.attempts must match the committed patch attempt. The prover identity must differ from patch.json.agent.

run_dir must already contain finding.json, run.json, reproduced reproduce/reproduce.json, independently confirmed validate/validate.json, patch/attempt-N/patch.json and the corresponding complete manifests. build_argv and poc_argv must exactly match reproduction. Runtime poc_argv must name the retained absolute reproduce/poc source while selecting the artifact relative to the active checkout cwd.

case_specs contains exactly one unique entry per declared repair_scope case: {check_id,source,argv}. source names a caller-provided UTF-8 harness. argv is a nonempty string array with one literal {harness} argument after an interpreter; the host copies unchanged bytes under receipts/case-N.source. The harness emits one PATCH_CASE {"input":...,"actual":...}, then PATCH_REACHED as its final stdout line, and uses its assertion exit status. The same source and argv run on both pinned trees.

project_checks entries are {check_id,kind,argv,count_protocol}; kind is suite, behavior, regression or security and count_protocol defaults to PATCH_COUNTS_v1. Every executed project command must emit exactly one stdout line PATCH_COUNTS {"passed":P,"failed":F,"skipped":S}, with nonnegative integer counts and P+F>0. A successful command requires F=0. Missing, ambiguous or all-skipped counts are gaps. Behavior checks and failed patched checks receive baseline attribution.

unproven_limits is a nonempty list of specific limits (each <=400 characters). worktree_output_files lists relative build/test outputs and intermediates for preflight; do not include .git. Evidence is written to prove/attempt-N and prove-review-N; prove-work-N contains temporary owned detached worktrees which are removed after use. Return fields include outcome, record, manifest, receipt_paths, findings and gaps.

The recipe declares `Bash`. Configure `--tool-config` for capabilities called through `tool()`, following the provider setup. Host `run_command()` needs no Bash provider unless the recipe also calls `tool("Bash", ...)`.
