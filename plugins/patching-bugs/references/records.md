# Patching Bugs record contract

One run lives outside the target repository's tracked tree. Records use the version
in their bundled schema (`prove.json` uses version 2). Each is checked by the
[validator](../scripts/records.py).

| Record path | Schema |
| --- | --- |
| `run.json` | [run](../schemas/run.schema.json) |
| `finding.json` | [finding](../schemas/finding.schema.json) |
| `reproduce/reproduce.json` | [reproduce](../schemas/reproduce.schema.json) |
| `validate/validate.json` | [validate](../schemas/validate.schema.json) |
| `patch/attempt-N/patch.json` | [patch](../schemas/patch.schema.json) |
| `prove/attempt-N/prove.json` | [prove](../schemas/prove.schema.json) |
| `regression/regression.json` | [regression](../schemas/regression.schema.json) |
| `report-input.json` | [report-input](../schemas/report-input.schema.json) |

```text
<run>/
  run.json                         orchestrator status and attempt count
  finding.json                     normalized claim and supplied report details
  guidance/<baseline-SHA>/          root guidance copied from the baseline Git commit
    source.md                      source SHA and absent filenames
  reproduce/
    reproduce.json                 reproducer result
    poc/                           unchanged PoC for validator and prover
    receipts/                      raw build and PoC output, exit status, timing
    manifest.json
  validate/
    validate.json                  independent validator decision
    receipts/                      rerun output and status
    manifest.json
  patch/attempt-N/
    patch.json                     patcher commit, variants and suite results
    fix.patch                      production diff from baseline
    tests.patch                    test diff from baseline
    manifest.json                  hashes the record and both patch files
  prove/attempt-N/
    prove.json                     independent prover outcomes
    receipts/                      scoped cases, project checks, three-arm proof
    manifest.json
  regression/
    regression.json                campaign pointer, coverage and decisions
    receipts/                      copied decision records
    manifest.json
  report-input.json                orchestrator prose and disclosure choice
  report.html                      auditor report for every reportable run
  maintainer-report.html           verified-patch handoff only
```

The orchestrator saves root guidance in `guidance/<baseline-SHA>/`, records absences
in `source.md`, and verifies both before each handoff. Guidance is outside the step
manifests and record checker.

## Project guidance

Before target commands, each stage reads every present root `AGENTS.md`,
`PATCHING_GUIDELINES.md`, and `THREAT_MODEL.md` from the baseline commit's Git
objects. `reproduce-bug` uses the clean checkout's `HEAD`; later stages use
`reproduce/reproduce.json.baseline_commit`. Missing files are allowed. If saved
guidance exists, verify its copies and absences against that commit. Stop if the
commit or copies cannot be verified. Follow applicable guidance within stage
permissions; `validate-bug` remains blind to the reproducer's transcript.

`finding.json` states one falsifiable claim and starts as `hypothesis`. Its optional
`reported` object preserves the auditor's supplied `impact`, `reproduction_steps`,
`expected_behavior`, `observed_behavior`, `severity`, and `priority` without filling
gaps from agent assumptions. The reproducer
exercises the current compiler or runtime and updates the finding status. The validator
reruns the same command and any PoC from its package. It writes its own
decision without reading the reproducer's transcript. The patcher fixes the invariant,
records every variant, writes one local commit and splits its diff into `fix.patch` and
`tests.patch`. The prover runs the declared cases and relevant project checks on the
baseline and patch, then runs the [three-arm helper](../scripts/arms.py). The
[native assessor](../scripts/native_proof.py) derives findings and evidence gaps from
the retained `prove.json`, case observations, and project receipts.
`reproduce.json` and `patch.json` identify their agents; `validate.json` and `prove.json`
identify different agents. Reusing the reproducer as validator or patcher as prover makes
the verdict Not ready. A failed patch attempt may record `patch_commit: null`.
The orchestrator reads regression-hunt's per-finding decisions and copies their source
records into regression receipts before writing `regression.json`. It then writes
`report-input.json` and calls the [renderer](../scripts/render.py). The renderer derives
both report claims from validated records, embeds local evidence and the full patch
diff, and removes an obsolete maintainer handoff if a later render is not ready.

Attempts start at 1, increase to at most 3, and are never overwritten. `run.json.attempts`
points to the latest patch and proof pair. A failed proof can start a new pair. Preserve
all prior attempts and receipts. Never infer a result from an agent's account when a raw
receipt is available.
The record checker binds each patch and proof record's `attempt` to its canonical
`attempt-N` directory. Evidence beyond `run.attempts` is a readiness gap; ordinary
checking still permits a report of the contradictory state.

Each step directory's `manifest.json` maps every regular file under that directory,
except its own manifest, to SHA-256 by sorted relative path. This includes step records,
PoC source, patch files, proof records, and receipts. Symlinks are forbidden. A missing
manifest, or a missing, extra or changed file fails validation. Write a manifest only
after the step's files are complete. The arms helper writes an interim proof manifest;
rewrite it after adding `prove.json` and case and project receipts. Verify each step after completion
and again immediately before rendering. Do not rewrite a manifest to conceal a changed
file.

## Repair coverage

New briefs include `finding.repair_scope` with these fields:

| Field | Content |
| --- | --- |
| `mode` | `bounded_class` for the smallest safely bounded behavior behind the example; `exact_example` for an explicit input-only request or when a safe boundary cannot be defined. |
| `boundary` | The behavior covered by this repair. |
| `cases` | One `{check_id, role, input, expected, why}` per representative failure or valid control. `role` is `representative` or `control`; `input` and `expected` are JSON values. `why` states the distinguishing condition or preserved behavior. |
| `exclusions` | Adjacent work outside this repair. |

Each `check_id` identifies one case in `prove.json`. Retain one unchanged harness
source and command per case. Before asserting, each run prints one
`PATCH_CASE {"input": ..., "actual": ...}` from the exercised input and observed
result, then `PATCH_REACHED` as its final stdout line. Retain baseline and patched
stdout, stderr, status, and timing in
the final proof manifest. Planned representatives must fail before and pass after;
controls must pass in both. A failed patched check with trustworthy observations is
a finding. Missing, ambiguous, or contradictory evidence is a gap.
The assessor verifies the retained record and observations; the independent prover
and reviewer must inspect that the recorded command ran the retained harness on
both pinned trees. The receipts alone cannot prove how a command was launched.

`project_checks` record relevant suites, preserved behavior, regression, and security
checks. Each has a command and patched receipts. Compare behavior on baseline and
patch; use baseline receipts to attribute a failed patched check. A passing patched
suite may omit its baseline. `unproven` lists specific limits for the report.

The renderer requires multiple distinct representative inputs that fail before and
pass after, plus passing controls, all matching the plan. This supports a bounded
claim; the relevance of selected cases still requires review. Missing coverage
limits the claim to the proven example.

## Verdict precedence

1. Reproduction other than `reproduced`, or validation other than `confirmed`:
   `NOT_REPRODUCED`.
2. Missing patch commit or proof, reused agent identity, any native proof finding or
   evidence gap, reverted
   arm other than pass, runtime build identity other than pass, `REPRODUCED_REGRESSION`, or
   `INCOMPLETE_FIX`: `NOT_READY`.
3. `UNRESOLVED`, incomplete regression coverage, or a variant marked `not_fixed`:
   `READY_WITH_CONCERNS`.
4. Otherwise: `READY`.

Run the linked scripts with Python 3.13 or newer and no installed runtime packages:

- [Record helper](../scripts/records.py): `uv run --no-project <script> manifest <step-dir>`
  writes a step manifest after all files are present. `uv run --no-project <script> check
  <run-dir>` validates the run. Before repair, add `--before-repair` to require
  `finding.repair_scope` with a usable case plan and a consistent attempt count.
  Missing or incomplete scope remains reportable as INCONCLUSIVE through ordinary
  checking and rendering.
- [Three-arm helper](../scripts/arms.py): `uv run --no-project <script> run --repo <repo>
  --baseline <original-sha> --patch <final-sha> --build <argv-json>
  --out <proof-step-dir>` plus the proof-type arguments below.
- [Report renderer](../scripts/render.py): `uv run --no-project <script> <run-dir>`.

## Proof types

New `reproduce.json` and `prove.json` records name the same `failure_type`:

| Type | Reproduction fields and helper arguments | Target proof |
| --- | --- | --- |
| `runtime` | `poc_argv` and relative `target_artifact`; helper `--failure-type runtime --poc <argv-json> --artifact <relative-file>`. | Successful builds; unchanged PoC fails before, passes after, and fails on the reverted tree, with `PATCH_REACHED` before each assertion. `build_identity: pass` requires the loader observations below and a changed patched artifact hash. |
| `compile` | `build_argv` invokes the compiler; `expected_diagnostic` is a specific literal diagnostic identifying the reported failure; `poc_argv: []`, `target_artifact: null`. Helper `--failure-type compile --expected-diagnostic <text>`. | Baseline and reverted compiler fail with that diagnostic; patched compiler succeeds. Missing tools or unrelated diagnostics are inconclusive. No runtime binary is required: `build_identity: not_applicable`, all runtime `hashes: null`. |

For runtime identity, the unchanged PoC prints one
`PATCH_LOADED {"path": "<resolved loaded file>", "sha256": "<loaded file hash>"}`
line from its actual loader observation. Each arm must match that worktree's
`target_artifact` path and bytes. Hashing a named file alone does not bind execution.

The helper restores and verifies the entire original baseline tree in its owned
reverted worktree, then rebuilds. Keep the unchanged PoC outside these temporary
trees so a complete restoration can remove newly added tests. No history rewrite
is needed for a repair spanning commits. `receipts/source.json` retains original
and final commit IDs and all three tree IDs; each arm retains build/PoC output,
status, timing, and `arm.json`. Temporary worktrees are removed; the caller's
checkout is unchanged. A reverted runtime artifact hash difference remains a note.
The native assessor requires that source receipt, matching pinned commits, and
the reverted tree ID equal to the baseline tree ID. A passing runtime identity
also requires complete artifact hashes with a changed patched hash.

The three-arm proof and scoped case/project checks are both required. The native
assessor reports findings separately from gaps. Neither can make the patch ready.

## Terminal reports

The renderer derives target outcome separately from broader readiness. A proved
repair is repaired; an unestablished result is inconclusive. An unchanged baseline
can establish no patch required for its observed cases with zero attempts,
`not_reproduced`, independent `not_confirmed`, and this
`report-input.baseline_checks` mapping:

```json
[
  {
    "check_id": "example",
    "reproduce": {"stdout": "reproduce/receipts/example.stdout", "exit": "reproduce/receipts/example.exit.json"},
    "validate": {"stdout": "validate/receipts/example.stdout", "exit": "validate/receipts/example.exit.json"}
  }
]
```

Save one stdout and paired `.exit.json` per planned case in each step's `receipts/`.
Run `render.py --prepare-input <run-dir>` to map unique, retained case receipts;
missing or ambiguous checks remain Inconclusive. Each step manifest retains the
referenced stdout and JSON exit receipt (`exit_code: 0`). Both `PATCH_CASE` observations
must match the planned input and expected result; runtime checks also require
`PATCH_REACHED` as the final stdout line. Missing coverage leaves the result
inconclusive. Use `open_risks` for remaining limitations. Checks without an
applicable patch are shown as
inapplicable without creating patch or proof records. Historical command paths
remain raw provenance; current evidence references resolve only to retained files.
