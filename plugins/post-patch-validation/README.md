# Post-Patch Validation

Validates an existing security patch as an untrusted hypothesis. The plugin proves the original
failure on a pinned baseline, exercises at least one root-cause variant, checks behavior and
adjacent security properties, runs the project suite, and produces an evidence-backed S1-S5 or
INCONCLUSIVE verdict.

The portable `post-patch-validation` skill works with agents that support Agent Skills. Claude
Code users also get a bundled dynamic workflow.

## Installation

```text
/plugin marketplace add trailofbits/skills
/plugin install post-patch-validation@trailofbits
```

## Skill usage

Ask an agent to validate a patch and provide:

- the vulnerable base commit or tag;
- the patched commit, tag, or patch file;
- the finding or a local path containing it;
- authorization to execute the local project and its tests.

The skill scaffolds a JSON plan, requires executable evidence for seven categories, runs each
check in isolated Git worktrees, and writes:

```text
post-patch-validation/
├── plan.json
└── results/
    ├── artifact-manifest.json
    ├── patch.diff
    ├── plan.snapshot.json
    ├── report.md
    ├── result.json
    ├── helpers/
    │   └── <sha256>                  # invoked file bytes, content-addressed
    ├── scratch/
    │   └── <check-id-and-side>/      # archived per-invocation writable state
    └── 001-<check-id>-<side>.stdout / .stderr
```

The Python runner uses argv arrays rather than shell command strings. It pins commit and patch
hashes, disables Git hooks while materializing worktrees, fixes locale/timezone/hash-seed inputs,
executes checks in lexical order, and preserves raw output. Each check invocation receives a fresh
opaque scratch directory and a private copy of its plan artifacts; base and patched worktrees also
use separate validator-owned roots. Scratch is archived only after exit, while the private plan
copy is discarded; the clean source snapshot remains only in runner memory. Exploit and variant
sides execute in random order with stable evidence filenames; stdout/stderr are copied from
anonymous or random capture descriptors into those named files only after exit. Every argv element
that resolves to a readable file is hashed. Files inside the isolated plan or checkout roots are
also stored under `helpers/<sha256>` for review, up to a 16 MiB limit; `argv_files` says why an
external, unreadable, or oversized file was not archived. Git worktree metadata changes are
serialized and active worktrees are locked, while independent validations may execute their checks
concurrently. The runner exits 0 only for S1; S2-S5 use their score as the exit code and
INCONCLUSIVE uses 10. Invalid or moved inputs use 64.

These controls isolate runner-managed evidence state; they are not a host sandbox. Checks retain
the caller's privileges, so execute untrusted helper code inside an appropriate OS or container
sandbox.

Two rules exist because an exit code carries less information than it appears to:

- `exploit` and `variant` checks must print `PPV_REACHED` before their assertion. A build error
  and a failed assertion both exit nonzero, so an unmarked run is INCONCLUSIVE rather than proof
  that the vulnerability reproduced.
- Checks run under a fixed minimal environment. Real toolchains get what they need through
  `--allow-env NAME`, which records the forwarded name and value in `result.json`.

Every plan declares an evidence level: `source`, `build`, or `runtime`. Reports display it beside
verdict-specific interpretation text so an S1 from source inspection cannot be mistaken for runtime
proof. Exploit and variant checks assert only the security invariant; liveness, exact error behavior,
timing, and compatibility belong in behavior or regression checks.

Scaffolding also records affected Git submodules as sorted relative paths. Their pinned commits are
initialized from module objects already present in the source repository, without contacting the
URLs in `.gitmodules`, and both base and patched pins are recorded in `result.json`.

Active validation worktrees are locked against concurrent pruning with random owner tokens backed
by kernel file locks, so PID reuse cannot confuse stale-owner detection. After a forced
termination, the next run unlocks stale validator-owned registrations; `git worktree unlock`,
followed by `git worktree remove --force` or `git worktree prune`, provides manual recovery.

## Claude Dynamic Workflow

Claude Code exposes `/post-patch-validation:validate-patch`. For structured inputs, ask Claude
to invoke the `Workflow` tool with the following arguments:

```javascript
Workflow({
  name: 'post-patch-validation:validate-patch',
  args: {
    finding: 'UAF when a callback releases the final request reference',
    baseRef: 'vulnerable-tag',
    patchRef: 'HEAD',
    workdir: 'post-patch-validation',
  },
})
```

The `Workflow` tool's `name` omits the leading slash. See the
[workflow documentation](https://code.claude.com/docs/en/workflows#distribute-a-workflow-in-a-plugin)
for plugin command naming.

Use `patchFile` instead of `patchRef` for a patch artifact; supplying both is rejected. `patchRef`
defaults to `HEAD`, but `baseRef` is always required because a validator that guesses the vulnerable
baseline cannot prove reproduction.

The workflow has five fixed phases and at most nine agents:

| Phase | Work |
|---|---|
| Inventory | Pin the inputs and scaffold the plan with the Python runner |
| Coverage | Four read-only lenses map exploit variants, behavior, adjacent security, and test infrastructure |
| Plan | One agent turns proposals into executable artifacts and passes `validate-plan` |
| Execute | One agent invokes the deterministic runner and returns its exact result |
| Review | Two read-only reviewers flag omitted paths or evidence that did not exercise real code |

The review agents cannot change the S-score. They can only keep an S1 result in
`REVIEW_REQUIRED` rather than advancing it to `READY_FOR_HUMAN_REVIEW`.

Dynamic workflows must be enabled in Claude Code. The workflow cannot ask questions after
launch, so pass the base and patch inputs up front.

## Verdicts

| Verdict | Meaning |
|---|---|
| S1 | Fix and variants pass without observed behavior/security regression |
| S2 | Fix passes but behavior, regression, or suite evidence fails |
| S3 | Original exploit or a root-cause variant remains unfixed |
| S4 | Fix passes but a base-clean security property fails on the patch |
| S5 | Patch is both incomplete and introduces a new security failure |
| INCONCLUSIVE | Baseline, marker, control, execution, pinning, coverage, or cleanup evidence is invalid |

Every verdict requires human review. S1 means the supplied checks passed; it cannot prove that a
human or agent supplied every relevant path.

## Requirements

- Git 2.36 or later (for lock reasons and NUL-delimited porcelain worktree metadata)
- Python 3.11 or later
- `uv`
- The target project's local build and test dependencies

No remote-target mode is provided. The validator executes repository code, so run it only for a
local target the user has authorized.

## Development

Run the Python runner tests, eval grader tests, and workflow tests from this repository's root:

```bash
bash plugins/post-patch-validation/tests/run_tests.sh
node plugins/post-patch-validation/tests/workflow_logic.test.mjs
```

The Python suite uses `pytest` and `PyYAML` through `uv`; the runtime runner uses only the Python
standard library. `make check` discovers both suites. The three cases under `evals/` exercise a
complete fix, a missed variant, and a behavior regression. Their grader and scaffold tests run
locally without model calls; live Claude plugin evals require a separate invocation.
