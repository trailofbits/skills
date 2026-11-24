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
