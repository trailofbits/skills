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

## Calcifier recipe for `implement-patch`

The [`implement-patch` Python recipe](skills/implement-patch/.calcifier/recipe.py) was generated with Calcifier 0.2.0. It pins the source skill and its packaged resources so source changes are checked before execution.

Install the matching release with Python 3.13 or later:

```sh
uv tool install 'calcifier==0.2.0'
```

The recipe's PEP 723 inline metadata also declares Python >=3.13 and pins `calcifier==0.2.0`. `uv run` can resolve those script dependencies; use `calcifier exec` for reviewed execution with Calcifier's trust checks.

Configure `worker` in a version-1 agent-config file following [the Calcifier 0.2.0 provider setup](https://github.com/trailofbits/calcifier/blob/v0.2.0/docs/providers.md). Worker tools depend on the configured agent provider; host tool providers do not add tools to an agent.

From this plugin directory, check the recipe before execution:

```sh
calcifier lint skills/implement-patch/.calcifier/recipe.py --portable
```

Review the complete generated Python before granting trust. Run `calcifier exec skills/implement-patch/.calcifier/recipe.py` with `--agent-config agents.json` and one `--input NAME=VALUE` for each required input below. Add `--trust` after review to record consent for those exact bytes.

Choose a fresh, dedicated report directory with `--output-dir PATH`. The override protects existing output files; it does not isolate host commands or grant workers additional tools.

| Input | Type | Default |
| --- | --- | --- |
| `target_repo` | `str` | Required |
| `run_dir` | `str` | Required |
| `attempt` | `Literal[1, 2, 3]` | Required |
| `patcher_agent_id` | `str` | Required |
| `options` | `Options` | Required |

Invoke with `--output-dir RUN_DIR`, the existing external record directory. Required arguments are `target_repo`, `run_dir`, `attempt` (1..3), `patcher_agent_id`, and structured `options`. Reserve the attempt in `run.json.attempts` first; earlier patch attempts and complete reproduction/validation manifests must exist. Reproduction must be `reproduced`, validation `confirmed`; their identities must differ and the patcher identity must differ from the validator. Git needs a configured local commit identity.

`options` requires JSON-array strings `allowed_production_paths_json`, `allowed_test_paths_json`, `suite_argv_json`, and `regression_argv_json`. Optional `build_argv_json` and `generated_paths_json` default to `[]`. Production/test path lists must be nonempty, disjoint repo-relative regular file paths; new files are allowed. Generated paths list known build/test output files for preflight. Commands execute without a shell in a clean detached baseline worktree. The read-only worker proposes ordered replacement contents only for the caller-fixed test-then-production path list; the host applies them through fixed Git paths.

Both suite and regression runners must print exactly one stdout line `PATCH_TEST_REPORT {"passed":["test-id"],"failed":{"test-id":{"kind":"assertion","detail":"raw diagnostic"}},"skipped":["test-id"],"errors":[]}`. IDs must be unique nonempty strings across the three groups, failures must describe exercised assertions, and at least one test must pass or fail. Exit 1 exactly when failed is nonempty, otherwise exit 0. The baseline regression must fail every declared representative check ID and pass every control ID; patched regression must pass all declared check IDs with no failures. Existing-suite failures after patching must match their raw baseline identity/details and existing test coverage cannot disappear.

The host creates one local baseline-child commit in `repair/attempt-N/wt`; it never pushes. This owned worktree remains for review. Canonical output is `patch/attempt-N/{patch.json,fix.patch,tests.patch,manifest.json,receipts/}`; native working command receipts and the ordered worker proposal remain under `repair/attempt-N/`. Typed results contain outcome, record, paths and reason; a failed entered repair records a null patch commit when none was created, while invalid/unverified pre-entry work returns inconclusive without fabricating a patch record.

The recipe declares `Bash`. Configure `--tool-config` for capabilities called through `tool()`, following the provider setup. Host `run_command()` needs no Bash provider unless the recipe also calls `tool("Bash", ...)`.
