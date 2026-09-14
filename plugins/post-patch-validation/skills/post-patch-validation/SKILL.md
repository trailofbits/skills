---
name: post-patch-validation
description: >
  Validates security patches with reproducible baseline-versus-patched evidence, including
  original exploits, root-cause variants, behavior preservation, regressions, and newly
  introduced security failures. Use after a patch exists and before accepting, merging, or
  reporting it as fixed; also use when an AI-generated patch, remediation commit, pull request,
  or proposed upstream fix needs adversarial post-patch validation across any language.
allowed-tools: Read Write Edit Grep Glob Bash Workflow
---

# Post-Patch Validation

Treat the patch as an untrusted hypothesis. Produce executable evidence in isolated Git
worktrees, then let the bundled runner assign the verdict. Never infer success from the diff,
the patch author, an upstream implementation, or the original proof of concept alone.

## When to Use

- A security fix, remediation commit, patch file, or pull request already exists.
- An AI-generated patch needs validation before human review or merge.
- A fix may cover one exploit path while missing variants of the same root cause.
- A security fix may alter legitimate behavior or introduce a new vulnerability.
- Another pipeline needs a deterministic final patch-validation gate.

## When NOT to Use

- No patch exists yet; use vulnerability discovery or fix implementation first.
- The task is to review an audit finding against a report without executing patch evidence.
- The task is only to convert a finding into a permanent project test.
- The target is remote or production. This skill executes local code and tests only.
- The user has not authorized execution of the repository's code or test suite.

## Quick Start

1. Pin the vulnerable base and patched input. Prefer immutable commits. For uncommitted work,
   create a binary patch file first; do not validate in the user's working tree.
2. Scaffold a pinned plan:

   ```bash
   uv run {baseDir}/scripts/post_patch_validation.py scaffold \
     --repo . \
     --base-ref <vulnerable-ref> \
     --patched-ref <patched-ref> \
     --finding-id <stable-id> \
     --finding-summary "<root cause and impact>" \
     --evidence-level runtime \
     --output post-patch-validation/plan.json
   ```

   Use `--patch-file <path>` instead of `--patched-ref` for a patch artifact. Choose the highest
   honest evidence level: `source` for source/patch invariants only, `build` when target code is
   compiled or analyzed but the reported behavior is not executed, or `runtime` when the checks
   execute the reported behavior and its safety assertions.
3. Inspect the finding, diff, callers, sibling paths, cleanup/error paths, and existing tests.
   Populate `checks` in the generated plan. Run `print-schema` for the exact machine contract:

   ```bash
   uv run {baseDir}/scripts/post_patch_validation.py print-schema
   ```

4. Validate the plan before executing code:

   ```bash
   uv run {baseDir}/scripts/post_patch_validation.py validate-plan \
     --plan post-patch-validation/plan.json
   ```

5. Execute the evidence plan:

   ```bash
   uv run {baseDir}/scripts/post_patch_validation.py run \
     --plan post-patch-validation/plan.json \
     --output post-patch-validation/results
   ```

6. Report `result.json`, `report.md`, the exact verdict, and every failing or inconclusive
   check. An S1 result is ready for human review; it is not permission to merge.

## Evidence Contract

The runner rejects incomplete plans. Supply at least one check of every kind:

| Kind | Required observation |
|---|---|
| `control` | Benign harness succeeds on both base and patch |
| `exploit` | Original safety assertion fails on base and succeeds on patch |
| `variant` | A distinct root-cause variant fails on base and succeeds on patch |
| `behavior` | Unaffected behavior succeeds with byte-identical selected output |
| `regression` | Targeted non-security regression check succeeds on both revisions |
| `security` | Adjacent/new-vulnerability check succeeds on base and patch |
| `suite` | Existing project suite, sanitizer, or deterministic fuzz campaign succeeds on patch |

Commands are argv arrays, never shell strings. Put complex setup in a checked-in or plan artifact
script and invoke it with `{plan_dir}`. The runner fixes locale/timezone/hash-seed inputs, executes
checks in lexical ID order, records raw stdout/stderr, and never edits the original worktree.
Every plan also contains a sorted `submodules` array (`[]` when none). Scaffolding infers affected
Gitlinks from the changed-file inventory. The runner initializes those pinned commits from the
source repository's existing Git module objects, never from `.gitmodules` network URLs; initialize
or fetch them in the source repository before validation.

### Exploit and variant checks must prove they ran

A nonzero exit does not mean the vulnerability reproduced. An import error, a failed build, a
missing dependency, and a failed safety assertion all exit nonzero and are indistinguishable to the
runner. Every `exploit` and `variant` check must print and flush `PPV_REACHED` immediately
before it evaluates its assertion, on both revisions:

```json
"argv": ["python3", "-c", "import app; print('PPV_REACHED', flush=True); assert app.render('<') == '&lt;'"]
```

The token is also in the environment as `PPV_REACHED_MARKER`. It must land on **stdout, as a line
of its own**. Stderr is not scanned, because a Python `SyntaxError` traceback echoes the offending
source and would otherwise satisfy the check for a harness that executed nothing. A run without it
is recorded as `marker_missing` and the whole result is INCONCLUSIVE. Flush explicitly: a harness
whose payload segfaults or calls `_exit` loses buffered output and forfeits its own evidence.

These checks also run **side-blind**. `{side}` is not expanded for them, `PPV_SIDE` is absent from
their environment, the checkout directory is randomly named, and the plan validator rejects any
`exploit` or `variant` check whose `argv` or `env` mentions either. An assertion that can see which
revision it is on can assert on *that* instead of on the code, which is the cheapest possible way
to fake a reproduction followed by a fix.

### Environment

Checks run under a fixed minimal environment: `PATH`, `HOME`, and a handful of temp/user keys,
plus `LANG`/`LC_ALL=C`, `TZ=UTC`, `PYTHONHASHSEED=0`, `NO_COLOR`, `TERM=dumb`. Everything else in
the caller's environment is dropped. Toolchains that need more get it explicitly:

```bash
uv run {baseDir}/scripts/post_patch_validation.py run \
  --plan post-patch-validation/plan.json \
  --output post-patch-validation/results \
  --allow-env JAVA_HOME --allow-env CARGO_HOME
```

Forwarded names and values are recorded in `result.json`. A requested variable that is unset is an
error, not an empty string. Two classes are refused outright: names that read as credentials
(`*SECRET*`, `*TOKEN*`, `*API_KEY*`, …), because the value would be written into the result; and
names that change what executes (`LD_PRELOAD`, `BASH_ENV`, `NODE_OPTIONS`, `GIT_SSH_COMMAND`, …),
because forwarding those would quietly dismantle the isolation the verdict rests on.
The runner's fixed variables and every `PPV_*` name are also reserved and cannot be forwarded.

Placeholders expanded in `argv` and per-check `env` values: `{checkout}` (the revision under test),
`{plan_dir}` (an isolated copy of the plan artifacts for that one invocation), `{scratch}` (a
fresh opaque directory for that one check invocation), and
`{side}` (`base` or `patched`, and not available to `exploit`/`variant` checks). The same values
arrive as `PPV_CHECKOUT`, `PPV_PLAN_DIR`, `PPV_SCRATCH`, `PPV_SIDE`, and `PPV_CASE_ID`. Write only
under `{scratch}`; the evidence directory path is not passed to checks. Base and patched invocations
do not share runner-managed scratch, plan, or worktree roots. After each invocation exits, its
scratch tree is archived under the deterministic `results/scratch/<check-id-and-side>` path, its
private plan copy is discarded, and every readable argv element that resolves to a file is hashed
in `argv_files`. Files inside the isolated plan or checkout roots are additionally retained under
`results/helpers/<sha256>` up to 16 MiB; the record explains why any other file was not archived.
Keep helper code under the plan's `checks/` directory or checked into the target repository so its
bytes are reviewable. Plan symlinks, the machine plan containing commit pins, and prior result trees
are excluded from the per-invocation copies. The clean snapshot remains only in runner memory, and
exploit/variant sides execute in random order while evidence filenames remain deterministic.
Stdout/stderr use anonymous or randomly named capture descriptors and are copied to the named
evidence files only after the child exits, so fd inspection cannot disclose the side label.

This isolation is not a host sandbox: checks run with the caller's privileges and a malicious
helper could use arbitrary external state or deliberately infer the revision from source or Git
metadata. Inspect the content-addressed helper artifacts, and use an OS/container sandbox when the
check code itself is untrusted.

Active validation worktrees are Git-locked with random owner tokens backed by kernel file locks, so
another concurrent validator cannot prune them and PID reuse cannot impersonate an owner. If the
runner is forcibly killed, the next run unlocks stale validator-owned registrations. For manual
recovery, inspect `git worktree list`, then use `git worktree unlock <path>` and
`git worktree remove --force <path>` (or `git worktree prune` after the path is gone).

Read [evidence-model.md](references/evidence-model.md) when designing coverage, selecting
variants, or interpreting S1-S5 and INCONCLUSIVE. Do not read it for routine CLI execution.

## Coverage Rules

- Derive variants from the root cause, not cosmetic mutations of the original payload.
- Enumerate sibling call sites, alternate callbacks/outputs, error paths, teardown, ownership,
  serialization, and boundary values touched by the fix.
- Make each exploit or variant test assert the safe behavior. It must fail on the vulnerable
  base; a test that passes on both revisions proves nothing about remediation. Read the base-side
  stderr and confirm the failure is the assertion you wrote, not a harness that never got there.
- Keep exploit and variant assertions limited to the security invariant. Test liveness, exact
  error types/messages, timing, and compatibility separately as `behavior` or `regression` checks;
  otherwise an unrelated contract change can masquerade as proof that the vulnerability remains.
- Keep the `control` harness benign and make it exercise the changed component. It
  is the only check that says the worktree can run at all, and its failure is INCONCLUSIVE.
- Use `behavior` only for behavior that should remain unchanged. Exact output comparison is
  deliberate; move unstable values behind a deterministic test harness instead of normalizing
  them away in prose.
- Make `security` checks pass on the vulnerable base before treating a patched failure as newly
  introduced. Otherwise the runner returns INCONCLUSIVE rather than inventing causality.
- Do not edit the patch during validation. Return failures to the patch author and start a new,
  freshly pinned run.

## Claude Dynamic Workflow

Claude Code exposes the bundled workflow as `/post-patch-validation:validate-patch`.
To pass structured inputs through the `Workflow` tool, use the name without a leading slash:

```javascript
Workflow({
  name: 'post-patch-validation:validate-patch',
  args: {
    finding: '<finding text or local path>',
    baseRef: '<vulnerable-ref>',
    patchRef: '<patched-ref>',
    workdir: 'post-patch-validation',
  },
})
```

Use `patchFile` instead of `patchRef` when appropriate. The workflow uses fixed coverage
lenses to propose checks and a fixed executor to run this skill. Agents may author test
artifacts, but they do not vote on the S-score: only the Python runner classifies evidence.
It cannot ask questions after launch, so pass every input up front.

## Rationalizations to Reject

| Rationalization | Required response |
|---|---|
| "The original PoC no longer works" | Test at least one independent root-cause variant |
| "The exploit failed on base, so it reproduced" | Confirm the marker and that the failure is the assertion, not a broken harness |
| "The full suite passes" | Prove baseline reproduction and targeted behavior explicitly |
| "This matches the upstream/canonical patch" | Treat provenance as context, not evidence |
| "The diff is tiny" | Exercise callers, failure paths, and teardown affected by the change |
| "The validator says S1" | Preserve artifacts and require human review |
| "A flaky rerun passed" | Keep the first pinned result; fix nondeterminism before retrying |
| "There is no obvious variant" | Inspect sibling sites and boundaries; otherwise stop INCONCLUSIVE |
