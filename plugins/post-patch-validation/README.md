# Post-Patch Validation

Validate a security patch against the reported bug and the surrounding code it affects. Give the
patch author reproducible failures to fix and identify what still needs testing.

The `post-patch-validation` agent skill tests human and agent patches against pinned revisions.
It checks the original bug, variants of its root cause, behavior that should remain unchanged,
and failures the patch could introduce. Each result preserves the assertions and execution logs
so an author can repair the patch and a reviewer can assess the evidence.

## Installation

```text
/plugin marketplace add trailofbits/skills
/plugin install post-patch-validation@trailofbits
```

The portable skill works with agents that support Agent Skills. Claude Code users also get the
bundled `/post-patch-validation:validate-patch` dynamic workflow.

## Skill usage

Ask an agent to validate a patch and provide:

- The vulnerable base commit or tag.
- The patched commit, tag, or patch file.
- The finding or a local path containing it.
- Authorization to execute the local project and its tests.

The skill creates a pinned JSON plan, authors checks, and runs them in isolated Git worktrees.
It returns every supported failure and every validation gap. The author can then revise the patch
and request a fresh validation against the new inputs. Earlier results remain available for review.

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
    │   └── <sha256>
    ├── scratch/
    │   └── <check-id-and-side>/
    └── 001-<check-id>-<side>.stdout / .stderr
```

## Reading a result

`result.json` contains an `assessment` with four fields:

| Field | Meaning |
|---|---|
| `status` | `complete` when all required checks produced usable evidence, otherwise `incomplete` |
| `findings` | Each supported failure, with its check ID, kind, and message |
| `gaps` | Missing or invalid evidence, with the affected check ID and reason |
| `human_review_required` | Always `true` |

Completeness describes the evidence, including evidence of failure. A missed variant and a
regression both appear in the findings. An unrelated timeout adds a gap without removing either
finding. Failed harness controls prevent attributing other failures to the patch, while preserving
all raw observations.

The project suite runs on the patch first. A completed failure triggers a baseline run. A baseline
pass supports reporting a failure after the patch. If both revisions fail, the result records an
attribution gap and keeps both logs. A timeout alone does not establish a regression.

When the supplied checks pass, the report says: “All supplied checks passed. Human review is still
required.” It displays the evidence level alongside that statement: `source`, `build`, or `runtime`.
Passing source checks cannot establish runtime behavior. Reviewers must still assess the
assertions and any omitted paths.

| Exit code | Meaning |
|---|---|
| `0` | Complete validation with no findings |
| `1` | Complete validation with findings |
| `10` | Incomplete validation, possibly with supported findings |
| `64` | Invalid inputs, including a rejected plan or changed input pins |

Always read the result artifact after exit 10. Invalid inputs may be rejected before a result exists.

## Evidence safeguards

The runner pins commits and patch hashes, disables Git hooks, uses argv arrays, and preserves raw
output. Exploit and variant checks must reproduce the unsafe behavior on baseline and emit
`PPV_REACHED` immediately before their safety assertion. A missing marker leaves a gap.

Each invocation receives private scratch and plan directories. Exploit and variant checks cannot
use runner-provided side labels. Their execution order is randomized, while evidence filenames
remain stable. Invoked helper files are hashed and archived when they are inside the plan or
checkout and within the size limit. The result records unarchived files for review.

Checks use a fixed minimal environment. `--allow-env NAME` forwards required toolchain variables
and records their values, so credentials are refused. Affected submodules use locally available
pinned objects without contacting remote URLs. Worktree metadata locks protect concurrent runs.

These measures isolate evidence state. Checks still run with the caller's privileges. Run untrusted
helper code inside an appropriate OS or container sandbox.

## Claude Dynamic Workflow

Invoke `/post-patch-validation:validate-patch`, or pass structured inputs to the `Workflow` tool:

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

Use `patchFile` instead of `patchRef` for a patch artifact. `patchRef` defaults to `HEAD`, while
`baseRef` is required. Dynamic workflows must be enabled, and all inputs must be supplied before
launch. The workflow pins the inputs, gathers coverage proposals, authors checks, executes the
runner, and has two reviewers assess coverage and evidence integrity.

| Workflow status | Next action |
|---|---|
| `NEEDS_REPAIR` | Return the findings to the patch author and investigate any accompanying gaps |
| `BLOCKED` | Resolve missing inputs or evidence before drawing a conclusion |
| `REVIEW_REQUIRED` | Address missing or negative evidence reviews after supplied checks passed |
| `READY_FOR_HUMAN_REVIEW` | Present passing checks and completed evidence reviews to a human |

The handoff preserves the runner's assessment and includes artifact paths. Reviewer concerns stay
separate from the recorded findings and gaps. The workflow does not edit the patch or approve a merge.

## Version 0.2.0 output changes

Result schema 2.0 replaces `verdict` with `assessment`. Consumers must read `findings` and `gaps`
instead of a grade. Exit codes are now 0, 1, 10, and 64 as described above. The workflow returns
`assessment` instead of `deterministicVerdict` and uses the statuses listed above. No legacy grade
aliases are emitted. The plan and artifact-manifest schemas remain 1.0.

## Requirements and development

The runner needs Git 2.36 or later, Python 3.11 or later, `uv`, and the target project's local build
and test dependencies. Its Python runtime uses only the standard library.

Run the focused checks from the repository root:

```bash
bash plugins/post-patch-validation/tests/run-all.sh
node --test plugins/post-patch-validation/tests/workflow_logic.test.mjs
```

`make check` discovers both suites. The four cases under `evals/` exercise passing checks, a missed
variant, a behavior regression, and simultaneous failures. Their artifact graders and scaffold
tests run locally without model calls. Live Claude plugin evals require a separate invocation.
