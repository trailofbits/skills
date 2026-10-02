---
name: post-patch-validation
description: "Validates a security patch (human or AI-generated commit, pull request, or patch file) with reproducible baseline-versus-patched evidence: the original exploit, root-cause variants, behavior preservation, regressions, and newly introduced security failures. Use after a patch exists and before accepting, merging, or reporting it as fixed."
allowed-tools: Read Write Edit Grep Glob Bash Workflow
---

# Post-Patch Validation

Validate a patch with executable evidence, not the diff, its author, or a passing test suite.
Run only against a local repository when execution is authorized. Do not use this for a remote or
production target, before a patch exists, or only to turn a finding into a permanent test.

## Run the runner

1. Pin a vulnerable base and a patched commit. For uncommitted work, save a binary patch; never
   validate in the user's worktree. Scaffold a plan:

   ```bash
   uv run {baseDir}/scripts/post_patch_validation.py scaffold \
     --repo . --base-ref <vulnerable-ref> --patched-ref <patched-ref> \
     --finding-id <stable-id> --finding-summary "<root cause and impact>" \
     --evidence-level runtime --output post-patch-validation/plan.json
   ```

   Use `--patch-file <path>` instead of `--patched-ref` for a patch artifact. Choose `source` for
   source-only checks, `build` for compiled or analyzed code, and `runtime` only when the affected
   behavior executes.

2. Create checks in `plan.json`, then run `print-schema` and `validate-plan`. Commands are argv
   arrays, never shell strings. Keep helper code beside the plan under `checks/` or checked into
   the target repository.

3. Run the plan and retain the evidence:

   ```bash
   uv run {baseDir}/scripts/post_patch_validation.py run \
     --plan post-patch-validation/plan.json --output post-patch-validation/results
   uv run {baseDir}/scripts/verify_evidence.py \
     --results post-patch-validation/results
   ```

   The runner uses isolated worktrees and records results even when it exits 1 or 10. Do not rerun
   a nonzero result just because it is nonzero. Read `result.json`, `report.md`, and the evidence
   verifier output before reporting the outcome.

4. Give the patch author every finding with its check ID and saved logs. Keep gaps separate from
   findings. A passing result always has `human_review_required: true`.

Read [runner.md](references/runner.md) when configuring environment forwarding, submodules,
placeholders, timeouts, or artifact handling. Read [evidence-model.md](references/evidence-model.md)
when designing coverage or interpreting findings and gaps.

## Evidence contract

Every complete plan has at least one of each kind:

| Kind | Required evidence |
| --- | --- |
| `control` | Benign harness succeeds on base and patch. |
| `exploit` | Original safety assertion fails on base and succeeds on patch. |
| `variant` | Independent root-cause variant fails on base and succeeds on patch. |
| `behavior` | Unaffected behavior has byte-identical selected output. |
| `regression` | A targeted non-security check succeeds on both revisions. |
| `security` | An adjacent-security check succeeds on both revisions. |
| `suite` | A project suite, sanitizer, or bounded deterministic fuzz campaign succeeds on patch. |

`exploit` and `variant` checks must print and flush `PPV_REACHED` as its own stdout line immediately
before their assertion. A nonzero exit without it is a gap, not reproduction. These checks are
side-blind: their argv and environment must not mention `{side}` or `PPV_SIDE`. Their assertion must
exercise real project code, not a mock or copied vulnerable logic.

## Coverage rules

- Derive variants from the root cause. Inspect sibling callers, alternate inputs and outputs, error
  and teardown paths, boundaries, ownership, serialization, and state transitions.
- Keep security assertions separate from liveness, error messages, timing, and compatibility.
  Test the latter as behavior or regression checks.
- A behavior check compares stable output exactly. Make its harness deterministic instead of
  normalizing unstable output.
- A security check must pass on base and patch. A suite runs on patch first; if it fails, the runner
  also runs it on base to determine whether the patch introduced the failure.
- Do not edit the patch during validation. Pin a new input and save a new run after a revision.

## Result and workflow

`complete` means every required check produced usable evidence; it does not mean no findings.
`incomplete` means one or more gaps remain. Preserve both. The runner exits 0 for a clean complete
result, 1 for complete evidence with findings, 10 for incomplete evidence, and 64 for invalid input.

For Claude Code, use `/post-patch-validation:validate-patch` with `finding`, `baseRef`, either
`patchRef` or `patchFile`, and an optional relative `workdir`; through the `Workflow` tool, pass
`name: 'post-patch-validation:validate-patch'` with those `args`. The workflow pins the inputs,
proposes checks through four fixed coverage lenses, writes and validates the plan, runs the runner
once, verifies recorded helper hashes with the bundled script, and returns separate coverage and
evidence-integrity reviews. `NEEDS_REPAIR` returns supported failures even when other checks left
gaps; `BLOCKED` means evidence is incomplete without a supported failure; passing checks reach
`READY_FOR_HUMAN_REVIEW` only after both reviews approve, otherwise `REVIEW_REQUIRED`. It cannot
ask for missing input after launch.
