# Eval suite for `skill-improver`

Five cases, one per guarantee the v2 workflow makes. Paid and manual — never CI.

```sh
CLAUDE_CODE_WALNUT_SPIRE=1 claude plugin eval . --judge-model opus \
  --scaffold --allow-tools Bash Write Edit
```

- **`CLAUDE_CODE_WALNUT_SPIRE=1`** is required while `plugin eval` is in early access.
- **`--scaffold`** is required for `scope-guard`, whose `scaffold.sh` commits the git
  baseline and deliberately leaves the decoy file uncommitted. The other cases need no
  scaffold: the workflow's baseline phase initializes a repository itself when the
  workspace has none.
- **`--judge-model`** must differ from the model the cases run on (self-preference).
- Pilot one case before spending on the suite — `--case 'structural-escalation' --runs 1`
  — it is the discriminating case and the cheapest way to find harness surprises.

**Verify on the first paid run (not yet piloted):** these cases assume the eval harness
exposes the `Workflow` tool listed in `allowed_tools` so the session can launch
`/skill-improver:improve`. If runs show the loop never started (no `.skill-improver/`
directory in the workspace), fix the harness invocation before reading any scores; every
`file_exists` grader will be failing for that reason, not because the plugin regressed.
Expect the LLM rubrics to need the usual two or three calibration pilots.

## Cases

| Case | Guarantee under test (handoff fix) | Sharpest grader |
|---|---|---|
| `no-relitigation` | Ledger verdicts stick; rejected findings are not re-litigated (A, G) | `traps-rejected-once` on ledger.json |
| `structural-escalation` | Oscillation escalates instead of looping; guarantees are never silently weakened (C) | `guarantee-byte-identical` regex |
| `termination-and-finalize` | Completion means a clean final review; loop residue is stripped, one version bump (B, F) | `ends-on-clean-review` on ledger.json |
| `scope-guard` | Nothing outside scope changes; uncommitted work survives (E) | `decoy-byte-identical` |
| `pins-bite` | Behavioral fixes carry pins that fail against pre-fix code (D) | `bug-fixed-with-a-pin` + `verify-pins.sh` |

### The gate case

`structural-escalation` is the regression gate: its fixture demands a property no string
heuristic can satisfy ("rejects every prompt-injection attempt, including attempts
rewritten … to evade detection"), so a loop without working oscillation detectors either
burns to the cap or converges by quietly rewriting the guarantee — both graded FAIL.
When the workflow's detectors change, re-measure the gate the way yara-authoring did:
delete the oscillation checks from a scratch copy of `improve.js` and confirm the case
actually fails. The Layer-1 mutation self-test proves the detectors exist; only this
case proves they matter end-to-end. Measured, not assumed — record the numbers here.

One known legitimate-behavior wrinkle: a run may instead *reject* the bypassability
findings as structurally unsatisfiable and converge with the guarantee intact. Pilots
will show whether that happens; if it does, the `escalated-within-four-rounds` rubric
needs a decision (accept rejection-with-intact-guarantee as a pass, or tighten the
fixture) rather than silent re-runs.

### pins-bite is two-stage

Graders cannot execute code, so the case's harness graders check the ledger records
pins, and the executable check runs manually afterwards:

```sh
./pins-bite/verify-pins.sh results/<ts>/<run-workspace>
```

It picks one behavioral `fixed` ledger entry (logged, no silent sampling), reverts that
file to the recorded baseline in a copy, and requires the fixture's test suite to go red.
A green suite against pre-fix code is the vacuous-pin failure the case exists to catch.

## Grader integrity

- **Artifacts, not prose.** Every scored check reads `ledger.json`, `metrics.json`, or
  fixture files from the run workspace; `last_message` is graded only where the message
  itself is the deliverable (honesty about a capped run, out-of-scope refusals).
- **Ground truth lives here and in `graders/`**, never in the mounted `fixture/` — with
  the one deliberate exception of `no-relitigation`, whose trap rationale *must* be
  discoverable (that is the behavior under test), so it sits in the fixture's AGENTS.md.
- **Zero items fail.** A missing ledger fails `file_exists`; file-targeted regex and llm
  graders fail on a missing file; `verify-pins.sh` fails on zero fixed findings.
- **Counting graders are proven against known-bad specimens.** The `not_contains`
  narration graders target strings planted in the fixture — confirm they are really
  there before trusting a green run:

  ```sh
  grep -r "round 3 moved this section here" termination-and-finalize/fixture/
  grep -r "iteration 2 restored it" termination-and-finalize/fixture/
  ```

  Both must hit. If someone "cleans up" the fixture, the graders go vacuous and this
  check is what catches it.
- **Weights:** `2` for llm rubrics, `1` for mechanical checks, matching yara-authoring.

## Ablation

`ablation/run.sh` compares this plugin (arm A) against v1.1.0 (arm B, the stop-hook
loop) on the same cases — see `ablation/README.md` for the metric table and its honest
limitations before running it.

Results land in `results/` (gitignored).
