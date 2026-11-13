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

## Calcifier recipe for `patching-bugs`

The [`patching-bugs` Python recipe](skills/patching-bugs/.calcifier/recipe.py) was generated with Calcifier 0.2.0. It pins the source skill and its packaged resources so source changes are checked before execution.

Install the matching release with Python 3.13 or later:

```sh
uv tool install 'calcifier==0.2.0'
```

The recipe's PEP 723 inline metadata also declares Python >=3.13 and pins `calcifier==0.2.0`. `uv run` can resolve those script dependencies; use `calcifier exec` for reviewed execution with Calcifier's trust checks.

Configure `worker` in a version-1 agent-config file following [the Calcifier 0.2.0 provider setup](https://github.com/trailofbits/calcifier/blob/v0.2.0/docs/providers.md). Worker tools depend on the configured agent provider; host tool providers do not add tools to an agent.

This coordinator requires an explicit caller-supplied host_adapter_argv for genuine primitive fresh-agent launch, messaging, status and interruption. The adapter exchanges the documented JSON request/response for one operation at a time; Python owns campaign progression and validation. Tracked command mutation flags protect hard dry runs. A worker agent configuration alone does not provide this host integration.

From this plugin directory, check the recipe before execution:

```sh
calcifier lint skills/patching-bugs/.calcifier/recipe.py --portable
```

Review the complete generated Python before granting trust. Run `calcifier exec skills/patching-bugs/.calcifier/recipe.py` with `--agent-config agents.json` and one `--input NAME=VALUE` for each required input below. Add `--trust` after review to record consent for those exact bytes.

Choose a fresh, dedicated report directory with `--output-dir PATH`. The override protects existing output files; it does not isolate host commands or grant workers additional tools.

| Input | Type | Default |
| --- | --- | --- |
| `request` | `Request` | Required |

Use published Calcifier 0.2.0 and an external `--output-dir` parent; the coordinator creates its `run/` directory there. Supply one structured `request`. Required fields are `repository`, `regression_plugin`, `host_adapter_argv`, `report`, `build_argv`, `poc_argv`, `failure_type`, `expected_diagnostic`, `target_artifact`, `allowed_production_paths`, `allowed_test_paths`, and `generated_paths`. `include_poc` and `resume` default to false. Use empty lists/strings where inapplicable; runtime uses a real relative artifact and PoC argv, while compile proof uses a specific compiler diagnostic and no runtime artifact. Commands must work in owned baseline/patched worktrees with portable project-relative selectors and unchanged retained harnesses.

`repository` is an existing clean local Git checkout. `regression_plugin` is the explicitly installed regression-hunt plugin root containing its canonical skills, references, definitions and native scripts. The host records dependency hashes and freezes the request; a resume must use unchanged inputs and dependency files. The regression plugin is an external runtime input rather than copied code in this recipe. Finding intake preserves reported details when supplied and leaves absent details absent; a single falsifiable claim and usable repair scope are required.

Production and test path lists must be nonempty, disjoint, safe repo-relative regular-file paths. Known `generated_paths` identify permitted build outputs; supply `[]` when none are needed. Workers operate in their own packages and owned repair worktrees with Git metadata read-only. Python creates and verifies the scoped local commit; it never pushes. Actual native patch, proof and regression records plus raw receipts determine readiness. Source guidance is pinned and passed in full before target execution and fresh handoffs; oversized or incomplete handoffs block.

`host_adapter_argv` names a caller-owned primitive JSON adapter, not a workflow runner. Each stdin request is `{capability,arguments,filesystem}` for one genuine `codex.spawn_agent`, `codex.send_message`, `codex.list_agents`, or `codex.interrupt_agent` operation. Keep actual primitive arguments separate from `working_directory`, `readable_paths`, and `writable_paths`; the adapter must enforce the supplied filesystem restrictions, including read-only Git metadata for workers. Return the exact native response object on stdout. Spawn must return its actual `task_name`; status must contain genuine `agents` entries with `agent_name`/`agent_status`. Never invent a handle, completion, receipt or isolation claim. The host records raw requests/process results and binds launch evidence before releasing work. A worker agent configuration alone does not provide this adapter. Mutation flags track launch/message/interruption and protect hard dry runs; status calls are read-only.

Canonical output is the run's schema-bound finding/run/stage records, complete manifests, scoped local patch commit, independently produced three-arm proof and baseline-to-patch regression receipts, plus `report.html` for the auditor. A maintainer report is emitted only when native validated evidence supports readiness. Incomplete or ambiguous runtime state requires recovery of its saved real handle, not an inferred restart. Returned fields include reports, automated verdict, blockers, local commit and next action. No live host-adapter campaign or target recipe run was performed during generation; compiler stubs do not certify those integrations and no trust was granted.

For a resume, run from the same dedicated external output parent with `resume=true` and omit `--output-dir`: Calcifier 0.2.0 protects pre-existing files whenever that flag is supplied. Review the retained run and unchanged inputs before authorizing this reuse. There is no CLI overwrite flag; the recipe preserves existing collision protection.

The recipe declares `Bash`. Configure `--tool-config` for capabilities called through `tool()`, following the provider setup. Host `run_command()` needs no Bash provider unless the recipe also calls `tool("Bash", ...)`.
