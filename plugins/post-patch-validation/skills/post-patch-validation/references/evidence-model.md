# Evidence Model

Use this reference while authoring the validation plan or interpreting its result.

## Contents

- Design basis
- Building independent evidence
- Classification
- Human handoff

## Design basis

Patch correctness is not binary. Empirical reviews of model-generated vulnerability patches
show recurring failures: fixing only the demonstrated path, changing legitimate behavior,
introducing a second vulnerability, accepting incorrect guidance despite contrary evidence,
and copying a flawed upstream pattern. Validators also disagree often enough that a prose-only
second opinion is not a reliable gate.

This skill therefore separates two jobs:

1. Agents or humans identify the root cause and author candidate checks.
2. Code pins the inputs, executes the checks, preserves the evidence, and assigns the verdict.

The runner is deliberately strict. Missing evidence is INCONCLUSIVE, not an optimistic pass.

Every result also states its evidence level. `source` means only source or patch invariants ran;
`build` means target code was compiled or analyzed without executing the reported behavior; and
`runtime` means the reported behavior and its safety assertions executed. This is a declared scope,
not a verdict multiplier: even S1 establishes no more than its stated evidence level and supplied
coverage.

## Building independent evidence

### Baseline first

An exploit test expresses the safe postcondition. It must fail against the vulnerable base and
pass against the patch. A test that never reproduced the vulnerability cannot establish a fix.

The exit code alone cannot carry that claim. `ImportError`, a failed build, a missing shared
library, a typo'd module name, and a failed assertion all exit nonzero, and the runner sees only
the number. Treating any nonzero base exit as reproduction is how a harness that never executed
becomes an S1: it "fails" on base for an unrelated reason, then "passes" on the patch where the
same unrelated reason happens not to bite.

So `exploit` and `variant` checks must print `PPV_REACHED`, flushed, immediately before evaluating
the assertion. A nonzero run without the marker is `marker_missing` and the result is INCONCLUSIVE.
Place the marker after setup and after reaching the vulnerable call, immediately before
the comparison, because everything between the marker and the assertion is still unproven. Flush
explicitly; a payload that segfaults or calls `_exit` discards buffered output and its own evidence
along with it.

The marker must land on stdout as a line of its own. Scanning stderr matched the token inside a
Python `SyntaxError` traceback, which echoes the offending source line, so a harness that never
executed a statement passed the check that exists to catch precisely that.

`exploit` and `variant` checks additionally run side-blind: no `{side}`, no `PPV_SIDE`, a randomly
named checkout, and plan-time rejection of any check that mentions either. Their assertion must be
identical on both revisions by construction, so a check that can identify its revision can only be
using that fact to fake the result.

The marker proves the harness ran. It does not prove the harness was *correct*: a check asserting
the wrong postcondition still fails on base and passes on patch. That remains a human-review job,
which is why `plan.snapshot.json`, the raw stderr, and content-addressed helper copies ship with
every result. `argv_files` records each file's argv index, original argument, SHA-256 digest,
optional archived path, and any reason it could not be archived. Readable files under the isolated
plan and checkout roots are archived up to 16 MiB; external paths are hashed but never copied, so a
data-file argument cannot silently vendor a host credential into the evidence. `argv0_sha256` also
records the resolved executable digest for compatibility with earlier result readers.

Keep that postcondition to the security invariant. Whether the operation remains live, returns an
exact error type or message, meets a timing property, or stays compatible with existing callers is
important, but it is separate behavior/regression evidence. Combining those contracts into an
exploit assertion lets a benign compatibility change manufacture S3 even when the security
invariant is fixed.

Each base or patched invocation receives a fresh opaque scratch directory and an isolated copy of
a clean plan-artifact snapshot. The snapshot excludes the machine plan containing revision pins,
symlinks, the live evidence tree, and detected prior result trees. The runner archives scratch under
a deterministic evidence path only after the process exits and discards the private plan copy.
Base and patched worktrees also use separate, randomly named validator-owned roots, and temp
environment variables point to per-invocation scratch. These measures remove runner-provided shared
writable channels that could otherwise reveal execution order or manufacture the expected base/fix
sequence. Exploit and variant sides execute in random order while retaining deterministic evidence
filenames, and the clean plan-artifact snapshot lives only as immutable runner memory between
invocations. Child stdout/stderr first go to anonymous or randomly named capture descriptors; the
runner copies them to side-labelled evidence paths only after the child exits, so inspecting fd 1
or fd 2 does not reveal the logical side or retained evidence directory.

This is evidence isolation, not an operating-system sandbox. Checks execute with the caller's
privileges and could deliberately communicate through arbitrary host paths, services, or process
inspection. A deliberately adversarial check can also inspect source differences or Git metadata
in the revision it must execute. Review the archived helper bytes before trusting a verdict, and
run untrusted helpers inside a sandbox chosen for the target's threat model.

### Root-cause variants

Choose a variant that reaches the same invariant violation through a meaningfully different
path. Useful dimensions include:

- sibling call sites or alternate public entry points;
- callback, direct-output, streaming, and buffered modes;
- success, error, cancellation, and teardown paths;
- minimum, maximum, empty, repeated, and nested inputs;
- ownership transfer, reference counts, aliases, and object lifetime;
- parser/serializer asymmetry and encode/decode direction;
- concurrency ordering or state-machine transition.

Changing only a literal, filename, or payload size is not independent unless that boundary is
the root cause.

### Behavior preservation

Use a stable benign input whose behavior should not change. The runner compares the selected
stdout, stderr, or combined stream byte-for-byte across base and patch. Put timestamps, random
IDs, absolute paths, addresses, and ordering behind a deterministic harness; do not hide them with
ad hoc output scrubbing. Checkout, plan, and scratch paths differ between invocations.

### New-vulnerability evidence

A `security` check must pass on the base and patch. If it passes on base but fails on patch, the
runner can attribute the new failure to the patch. High-value checks exercise cleanup, ownership,
error handling, authorization, bounds, and state transitions adjacent to changed code.

### Existing suite

Run the narrow deterministic project suite first, then broader tests, sanitizers, or a bounded
fuzz corpus when available. Pin seeds, corpus, worker count, and iteration/time budgets. A suite
supplements targeted evidence; it does not replace it.

Suite checks run only on the patched revision. A suite failure can produce S2 even when the
failure predates the patch; that result alone does not establish a regression caused by the patch.

## Classification

| Code | Meaning | Deterministic condition |
|---|---|---|
| S1 | Clean fix | Exploit and variants fixed; behavior and security checks pass |
| S2 | Fixed with behavior change | Exploit and variants fixed; behavior, regression, or suite fails |
| S3 | Not fixed | Exploit or variant still fails on the patch; no new security failure |
| S4 | Fixed with new vulnerability | Exploit and variants fixed; a base-clean security check fails on patch |
| S5 | Not fixed and new vulnerability | S3 and S4 conditions both hold |
| INCONCLUSIVE | Evidence cannot support a class | Missing category, baseline failure, missing marker, patched-side control failure, timeout, execution error, pin mismatch, or cleanup failure |

Classification precedence is S5, S3/S4 as applicable, S2, then S1. A behavior regression does
not conceal an unfixed vulnerability. Every result sets `human_review_required` to true.

`control` is deliberately not an S2 signal. Its job is to show that both worktrees can execute
the component at all, so a control failure on the patched side invalidates every other patched
observation rather than describing a behavior change. Reporting that as "fixed with behavior
change" would assert a fix on the strength of a harness that demonstrably stopped working.

### Environment determinism

Checks inherit a fixed minimal environment. Anything a real toolchain needs beyond `PATH` and
`HOME` is forwarded by name with `--allow-env`, and the forwarded names and values land in
`result.json` so a reviewer can see exactly what the run depended on. Never forward credentials;
a requested variable that is unset fails the run rather than arriving empty. Fixed deterministic
variables and all `PPV_*` names are reserved so forwarded input cannot replace runner-controlled
state.

Affected submodules are explicit, sorted paths in the plan. Their pinned objects must already exist
in the source repository: validation redirects initialization to those local module stores and does
not contact `.gitmodules` URLs. The result records base and patched submodule commits alongside the
top-level pins.

## Human handoff

Give the reviewer:

- `plan.snapshot.json` and the finding/root-cause statement;
- `patch.diff` and its SHA-256 pin;
- `result.json` and `report.md`;
- raw per-check stdout/stderr;
- content-addressed helper files under `helpers/`, cross-referenced by each run's `argv_files`;
- archived per-invocation scratch trees;
- `artifact-manifest.json` for integrity;
- any coverage concern that was not converted into an executable check.

Human review should inspect whether the declared root-cause surface is complete. The runner can
prove that the supplied checks behaved as claimed; it cannot prove that an omitted path does not
exist.
