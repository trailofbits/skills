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

## Calcifier recipe for `validate-bug`

The [`validate-bug` Python recipe](skills/validate-bug/.calcifier/recipe.py) was generated with Calcifier 0.2.0. It pins the source skill and its packaged resources so source changes are checked before execution.

Install the matching release with Python 3.13 or later:

```sh
uv tool install 'calcifier==0.2.0'
```

The recipe's PEP 723 inline metadata also declares Python >=3.13 and pins `calcifier==0.2.0`. `uv run` can resolve those script dependencies; use `calcifier exec` for reviewed execution with Calcifier's trust checks.

Configure `worker` in a version-1 agent-config file following [the Calcifier 0.2.0 provider setup](https://github.com/trailofbits/calcifier/blob/v0.2.0/docs/providers.md). Worker tools depend on the configured agent provider; host tool providers do not add tools to an agent.

From this plugin directory, check the recipe before execution:

```sh
calcifier lint skills/validate-bug/.calcifier/recipe.py --portable
```

Review the complete generated Python before granting trust. Run `calcifier exec skills/validate-bug/.calcifier/recipe.py` with `--agent-config agents.json` and one `--input NAME=VALUE` for each required input below. Add `--trust` after review to record consent for those exact bytes.

Choose a fresh, dedicated report directory with `--output-dir PATH`. The override protects existing output files; it does not isolate host commands or grant workers additional tools.

| Input | Type | Default |
| --- | --- | --- |
| `target_repo` | `str` | Required |
| `run_dir` | `str` | Required |
| `validator_agent_id` | `str` | Required |
| `execution_timeout` | `float` | `600` |

Invoke with `--output-dir RUN_DIR`. Required arguments are `target_repo`, `run_dir`, and `validator_agent_id`; `execution_timeout` defaults to 600 seconds and must be >0 and <=3600. Existing target/run roots must be disjoint and unlinked. The run needs schema-valid `run.json`, `finding.json`, `reproduce/reproduce.json`, a complete reproduction manifest, and unchanged UTF-8 source under `reproduce/poc/`. A usable exact-example/bounded-class repair scope is validated by the packaged helper, and the validator identity must differ from the reproducer. Existing validate/ or scratch/validate-bug/ directories are preserved and cause an input error.

The manifested reproduction package supplies commands; the worker never invents replacements. `reproduce/receipts/commands.json` must contain `{baseline,build,commands}`, matching the reproduction baseline/build and exactly one command per declared scope case in order. Every `case-N` requires `.stdout`, `.stderr`, and `.exit.json` raw receipts. Exit metadata requires argv, cwd, exit_code, error, and elapsed_ms, with argv equal to the ordered command. Runtime packages also require the three build receipt files. Commands use cwd-relative target/build selectors and retained unchanged PoC source (absolute source paths, or recognized retained-source-relative names). Absolute selectors into the caller checkout and escaping paths are rejected; use the reproducer's `{artifact}` relative expansion protocol.

Before target commands, a fresh read-only worker applies full pinned root guidance to the exact native command plan. Both that preflight and the final independent review receive the full schema finding, unchanged harness bytes, proof metadata, original raw build/case receipts and command metadata. Their private contexts exclude assessment.json, reproducer conclusions/transcripts, reproduce.json observed/blocker prose, and prior preflight conclusions. A declined or failed preflight produces an honest inconclusive record without claiming a target rerun.

The host rebuilds/reruns in a clean recipe-owned detached baseline worktree under scratch/validate-bug/worktrees/baseline. Runtime loader hash/path, frozen built-artifact identity, final PATCH_REACHED, scoped PATCH_CASE inputs/actuals, controls and status must agree; compile failures require the exact original target diagnostic. Original finding/run/reproduction evidence remains unchanged, caller HEAD/status is preserved, and owned tracked source/HEAD must still be the baseline after replay. Missing or inconsistent observations dominate any model confirmation as inconclusive. Temporary owned worktrees are removed.

Canonical results are validate/validate.json, its complete manifest, and actual rerun stdout/stderr/exit metadata under validate/receipts/. Scratch audit files retain native Git/guidance/helper command receipts, bounded preflight/postflight review/provider diagnostics, and a fixed native-gate-input.json payload for deterministic assessment; raw outputs are never sent through one large argv item. The typed result returns outcome, record/manifest paths, all retained receipt paths and a verified-record flag. This stage does not edit the finding/PoC or produce a patch/proof.

The recipe declares `Bash`. Configure `--tool-config` for capabilities called through `tool()`, following the provider setup. Host `run_command()` needs no Bash provider unless the recipe also calls `tool("Bash", ...)`.
