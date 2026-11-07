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

## Calcifier recipe for `reproduce-bug`

The [`reproduce-bug` Python recipe](skills/reproduce-bug/.calcifier/recipe.py) was generated with Calcifier 0.2.0. It pins the source skill and its packaged resources so source changes are checked before execution.

Install the matching release with Python 3.13 or later:

```sh
uv tool install 'calcifier==0.2.0'
```

The recipe's PEP 723 inline metadata also declares Python >=3.13 and pins `calcifier==0.2.0`. `uv run` can resolve those script dependencies; use `calcifier exec` for reviewed execution with Calcifier's trust checks.

Configure `worker` in a version-1 agent-config file following [the Calcifier 0.2.0 provider setup](https://github.com/trailofbits/calcifier/blob/v0.2.0/docs/providers.md). Worker tools depend on the configured agent provider; host tool providers do not add tools to an agent.

From this plugin directory, check the recipe before execution:

```sh
calcifier lint skills/reproduce-bug/.calcifier/recipe.py --portable
```

Review the complete generated Python before granting trust. Run `calcifier exec skills/reproduce-bug/.calcifier/recipe.py` with `--agent-config agents.json` and one `--input NAME=VALUE` for each required input below. Add `--trust` after review to record consent for those exact bytes.

Choose a fresh, dedicated report directory with `--output-dir PATH`. The override protects existing output files; it does not isolate host commands or grant workers additional tools.

| Input | Type | Default |
| --- | --- | --- |
| `q` | `Request` | Required |

Invoke with `--output-dir RUN_DIR` and one structured `q` argument. Required q fields are `repo`, `run`, `identity`, `build` (argv array), `cases` and `kind` (`runtime` or `compile`); optional `artifact` and `diagnostic` default to empty strings, and `timeout` defaults to 600 seconds (must be >0 and <=1800). Repo/run roots must exist, be disjoint and unlinked. `run/finding.json` must be a schema-valid hypothesis with affected files and a usable nonempty repair_scope; a pipeline run also supplies run.json. Existing reproduce/reproduce-checks directories are preserved and cause an input error. The target checkout must start at a clean tracked HEAD and remain at that HEAD with no tracked changes after execution.

`cases` has exactly one ordered object per finding.repair_scope.cases item: `{check_id,source_file,argv}`. Supply an existing nonempty UTF-8 harness source, matching check_id, and an argv array containing a literal `{source}` argument. The host copies unchanged source to `reproduce/poc/case-N<suffix>` and substitutes its retained absolute path. `{artifact}` expands to the relative `artifact` string so the same commands replay in later owned baseline/patched worktrees. Use cwd-relative project selectors; absolute selectors inside the original checkout are rejected. No worker supplies an executable argv or output path.

Runtime requires a relative `artifact` path (<=400 characters); each harness prints one `PATCH_LOADED {"path":"actual absolute artifact path","sha256":"actual hash"}`, one `PATCH_CASE {"input":...,"actual":...}`, and exactly one `PATCH_REACHED` as the final stdout line immediately before its assertion. It exits nonzero for a violated expected invariant and zero for expected behavior. Input observations must match their declared cases; controls must remain valid. Artifact identity is frozen after the real build. Compile reproduction requires an empty artifact and a specific `diagnostic` (1..400 characters); the expanded build argv must equal the first representative case argv. The compiler command and every planned scoped compile command actually execute; expected compiler diagnostic/status evidence gates confirmation.

Canonical outputs are `reproduce/reproduce.json`, unchanged `reproduce/poc/` source, complete `reproduce/manifest.json`, and raw `reproduce/receipts/case-N.{stdout,stderr,exit.json}` plus a runtime build receipt. Exit metadata includes argv, cwd, exit_code, error and elapsed_ms. `reproduce/receipts/commands.json` contains `{baseline,build,commands}` in declared scope order; the validator consumes this protocol. Model review is retained separately in assessment.json. Manifest/check command receipts are under reproduce-checks/. Only successful reproduction/nonreproduction changes finding.status; blocked leaves it as hypothesis. The typed result returns the record, record/manifest paths and retained receipt paths.

The recipe declares `Bash`. Configure `--tool-config` for capabilities called through `tool()`, following the provider setup. Host `run_command()` needs no Bash provider unless the recipe also calls `tool("Bash", ...)`.
