# Evidence Model

Use this reference while authoring the validation plan or interpreting its result.

## Contents

- Design basis
- Building independent evidence
- Assessment
- Human handoff

## Design basis

Validate a security patch against the reported bug and the surrounding code it affects. Give the
patch author reproducible failures to fix and identify what still needs testing. A useful result
helps the author decide what to change and helps a reviewer see what was actually exercised.

Agents or humans choose the assertions. The runner pins the inputs, executes those assertions,
and preserves observations. It reports every supported failure and every gap independently.
A missed variant and a regression can both need repair. An unrelated timeout should not hide them.

The result's evidence level describes what ran. `source` means only source or patch invariants
were checked. `build` means target code was compiled or analyzed without executing the reported
behavior. `runtime` means the reported behavior and its safety assertions executed. This is a
declared scope that reviewers must check against the artifacts. Passing source checks does not
establish runtime behavior.

## Building independent evidence

### Baseline first

An exploit test expresses the safe postcondition. It must fail against the vulnerable base and
pass against the patch. A test that never reproduced the vulnerability cannot establish a fix.

The exit code alone cannot carry that claim. `ImportError`, a failed build, a missing shared
library, a typo'd module name, and a failed assertion all exit nonzero, and the runner sees only
the number. Treating any nonzero base exit as reproduction is how a harness that never executed
appears to validate a patch: it "fails" on base for an unrelated reason, then "passes" on the patch where the
same unrelated reason happens not to bite.

So `exploit` and `variant` checks must print `PPV_REACHED`, flushed, immediately before evaluating
the assertion. A run without the marker leaves a `marker_missing` gap, regardless of its exit code.
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
records the resolved executable digest.

Keep that postcondition to the security invariant. Whether the operation remains live, returns an
exact error type or message, meets a timing property, or stays compatible with existing callers is
important, but it is separate behavior/regression evidence. Combining those contracts into an
exploit assertion can make a compatibility change look like a surviving security flaw.

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
in the revision it must execute. Review the archived helper bytes before interpreting a result, and
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

Suite checks run on the patched revision first. If the command completes and fails, the runner
runs the same check on baseline. A baseline pass supports reporting a failure after the patch.
If both fail, the runner records an attribution gap and preserves both logs. Two nonzero exits
do not establish that the failures are identical. A missing command or timeout also leaves a gap.
A timeout alone cannot establish a performance regression.

## Assessment

The assessment separates supported failures from missing or invalid evidence:

| Evidence | Result |
|---|---|
| Original or variant safety assertion reproduces on baseline and still fails on patch | Finding for that exploit or variant check |
| Behavior meant to stay unchanged differs between revisions | Behavior finding |
| Regression or security check passes on baseline and fails on patch | Finding for that check |
| Suite completes and fails on patch, then passes on baseline | Suite finding |
| Suite fails on both revisions | Attribution gap with both logs preserved |
| Missing reproduction, required run, assertion marker, or behavior comparison | Gap for the affected check |
| Failed harness control | Gap, with dependent conclusions withheld |
| Timeout, execution error, or cleanup failure | Gap, with independent findings retained |

The plan declares global harness controls. Until it can express narrower dependencies, a failed
control invalidates conclusions from all other checks. Their raw observations remain in `checks`.
Reviewers can diagnose a broken harness without treating its output as a confirmed patch defect.

Result schema 2.0 replaces the former grade with this object:

```json
{
  "assessment": {
    "status": "incomplete",
    "findings": [
      {
        "check_id": "cancellation-path",
        "kind": "variant",
        "message": "The variant safety assertion still fails on the patched revision."
      }
    ],
    "gaps": [
      {
        "check_id": "project-suite",
        "reason": "patched: execution_error: the test command could not start"
      }
    ],
    "human_review_required": true
  }
}
```

Every finding references a recorded check. A gap references its check or uses `check_id: null`
for a run-level problem such as cleanup or missing coverage. The detailed check records contain
commands, expected and observed exits, markers, saved output paths, and hashes. The `matched`
field alone is an observation, not a finding: baseline reproduction and working controls are also
required. A check that could not start may have null output paths and an error in its run record.

`complete` means all required checks produced usable evidence. It does not mean they all passed.
`incomplete` means at least one gap remains and can coexist with supported findings. No precedence
rule removes a finding because another finding or gap exists. Every result requires human review.

The CLI exits 0 for complete validation with no findings, 1 for complete validation with findings,
10 when gaps remain, and 64 for invalid inputs. Invalid plans and changed input pins are rejected
before execution and may produce no result artifact. Plan and artifact-manifest schemas remain 1.0.

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

Return each finding with its check ID and logs to the patch author. Identify the missing evidence
behind each gap. After a revision, pin the new patch and save a fresh result without overwriting
the earlier run. This gives authors a repair target and reviewers a record of what changed.

Human review should inspect whether the declared root-cause surface is complete. The runner can
prove that the supplied checks behaved as claimed; it cannot prove that an omitted path does not
exist.
