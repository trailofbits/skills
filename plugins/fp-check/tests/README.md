# fp-check tests

Four layers. Three are free and run in CI; only the Layer 3 capture and the
Layer 4 eval cost money.

| Layer | What it covers | Cost | In CI |
|-------|----------------|------|-------|
| 1 — contract | The shipped workflow scripts: parse, `meta`, phases, a schema on every `agent()`, banned non-determinism, fan-out caps | free | yes |
| 2 — logic | The deterministic JS extracted from those scripts: gate decisions, tallying, build acceptance | free | yes |
| 2b — wiring | The whole script body, run against scripted agents: does it *act* on what the helpers decide | free | yes |
| 3 — regrade | Every assertion re-scored against a saved run | free after one capture | yes |
| 4 — eval | The skill wrapper end to end, with an ablation baseline | paid | no |

```bash
make check                                       # layers 1-3, what CI runs
make js-tests                                    # just the node test half
node --test plugins/fp-check/tests/*.test.mjs
bats plugins/fp-check/tests/poc-lint.bats        # needs bats-core installed
bash plugins/fp-check/tests/mutation-gate.sh     # not in CI; see "The gate"

(cd plugins/fp-check && uv run --no-project --with pytest --with pyyaml \
  --with jsonschema python -m pytest tests -q)
```

Run the suites above for current counts — a number written down here drifts with
the next test added. The gate's bar is **no survivors**; its deferred mutations
are the ones blocked behind the Layer 3 capture.

Two things are open: **Layer 3 does not run**, its capture recording a script
this plugin does not ship; and **Stage 2 has no eval case that discriminates**,
its premise being public evidence the synthetic fixtures do not have.

## Layer 1 — the contract

`test_workflow_contract.py`. Every workflow script must parse under `node --check`,
declare `meta`, wrap each stage in `phase()`, pass a JSON schema on **every**
`agent()` call, carry no `Date.now()` or `Math.random()`, and cap its fan-out — all
shape, never semantics: a script can satisfy Layer 1 and decide wrongly.

**The lexer is hand-written.** It rejects regex literals rather than risk
mis-lexing one — the first `baseDir` guard used one and turned 51 tests red on
unmutated code, taking 27 mutations with it, and a mutation whose baseline is red
proves nothing. An apostrophe inside a *nested* template literal does the same.

## Layer 2 — the deterministic helpers

Workflow scripts have no module system, so pure helpers are defined inline and
`extract.mjs` pulls them out of the source text. `loadFn` throws when a function
is missing — a renamed helper fails loudly rather than silently testing nothing.
`loadFns()` exists because `decideGate` calls `upstreamFixStands`; the alternative
was inlining the sibling's logic at both call sites, and duplicated logic in a
gate is the drift this suite exists to catch, so the harness gives way.

Covered: `missingArgs` (four copies), `selectRoute`, `auditedSearch`,
`citedReference`, `fixedAnswer`, `upstreamFixStands`, `downgradeUnreferencedFix`,
`decideGate`, `missingPrecondition`, `namedLevels`, `externalRootCause`,
`capSeverity`, `blockingProofs`, `decideVerdict`, `settledByStageOne`,
`selectAttempts`, `isAcceptableBuild`, `artifactProblem`, `tallyChallenges`,
`alreadyFixedStands`, `confidenceBand`, `reportProblem`, `severityCapViolation`,
`offlineProblem`, `scopeHalt`, `stageOneStands`, `summaryProblem`,
`needsUserCensus`, `censusProblem`, `accountFindings`, `contextBlock`,
`isChainable`, `blockingLayers`, `pairReason`, `chainCandidates`, `chainProblem`,
`describe`, `chainedInto`.

Five of those are duplicated across scripts and the copies are pinned to agree,
not merely to exist: `citedReference` (three), `namedLevels` and
`externalRootCause` (three each), `auditedSearch` (two), and the cap arithmetic in
`capSeverity` / `severityCapViolation` (three, compared over every `CAP_TABLE`
row). A copy deleted rather than drifted fails loudly — `loadFns` throws on a
function it cannot find.

The fourth `missingArgs` is triage-batch's, and it re-validates each entry
against triage-static's own field list rather than delegating. It duplicates that
list because workflow scripts have no module system, and
`test_the_batch_entry_contract_matches_triage_static` compares the two in both
directions so neither can quietly gain or lose a field. The duplication buys the
one thing delegation cannot: an unusable entry is rejected **before** the
shared-context agent is paid for.

**Two verdict vocabularies, deliberately different.** A layer is asked what
happens to the payload (`PAYLOAD_REACHES_SINK` / `PAYLOAD_STOPPED_HERE`); a
deep-route proof, whether its own argument leaves the finding alive
(`FINDING_SURVIVES` / `FINDING_REFUTED`). They shared `PASSES` / `BLOCKS` until
the rebuild, and an agent returned `BLOCKS` reasoning *"I labeled this BLOCKS meaning
the payload is NOT blocked"* — which `decideGate` read as the label.

`needsUserCensus` is the one gate reading a field **by exclusion** (an omitted
`driver` runs the census). Elsewhere the affirmative value counts, because the
risk is a claim made on no evidence; here a predicate defaulting to "skip" is how
a capability gets lost silently, and one wasted agent is the cheaper error.

**Not covered, deliberately:** dedup-against-SEEN and "N consecutive rounds with
nothing new". There is no loop-until-dry stage — the only loop is the PoC stage's
bounded retry over at most `MAX_ATTEMPTS` paths, and that termination *is* tested.
No such logic was invented to satisfy a test. `tallyChallenges` carries the
equivalent bug class: it tallies against the **expected** challenge list, because
tallying the returned array would let a dead agent shrink the denominator.

## Layer 2b — the helpers where they are used

Layer 2 was not enough: every pure helper was covered, none *where it is used*. A
review disabled twelve call sites — both gate halts, `isAcceptableBuild`,
`alreadyFixedStands`, the confidence band, the severity cap — and the entire free
suite stayed green. `runScript()` in `extract.mjs` wraps the script body in an
async function and injects fakes for `agent`, `parallel`, `pipeline`, `workflow`,
`phase` and `log`, so `wiring.test.mjs` scripts each stage's answer and asserts on
the status back.

**The `workflow` fake was added for triage-batch, and writing the first test
against it found a second gap.** The fake `pipeline` did not catch a throwing
stage while the real runtime does, so a sub-workflow that threw killed the test
instead of producing the `null` the batch ledger exists to report — the harness
was wrong in exactly the direction that would have hidden that workflow's main
gate. Both fakes now mirror the documented contract: a thunk or stage that throws
resolves to `null` in place, and `.filter(Boolean)` is what removes it.

## Layer 3 — capture once, regrade forever

**This layer currently skips, and one paid run re-arms it.** The checked-in
capture records `concept-prover:verify-attack-path`, the plugin fp-check was
merged from, and that script is not shipped here. `test_regrade.py` therefore
skips the whole module — written as a filesystem check rather than a bare `skip`,
so promoting a new capture re-arms it — and the mutation-gate entries that depend
on it stay deferred. Capture against `fp-check:triage-static`, then re-point the
constants.

```bash
# N runs with a pass RATE, each regraded independently (this is the one to use):
RUNS=3 PROMOTE=1 bash plugins/fp-check/tests/capture-runs.sh ./out

# Free, offline, against the saved fixture:
uv run --with pytest --with jsonschema --no-project \
  pytest plugins/fp-check/tests/test_regrade.py
```

`capture-runs.sh` does not stop early and does not retry until green — a 2/3 is a
result; promotion requires run 1 to have **passed**. It cuts the throwaway git
worktree itself, because workflow subagents always run `acceptEdits` whatever the
session mode. **Under `-p` the Workflow tool returns on launch**, so the stream
carries only the *launch* and per-stage results come from `run.journal.jsonl`, and
**invoking the skill is a precondition for dispatch**, so it runs with
`--permission-mode bypassPermissions`.

**A capture is frozen provenance; never renumber one to agree with today's
source** — that deadlocked promotion once, so `guard_lines()` locates the blocking
checks by their code. `scrub_capture.py` must not destroy evidence either: a
greedy path rule once took `search.py:27` out of an agent's `location`, and the
regrade then failed and read as model variance when the plugin was correct.

## Layer 4 — eval

**Three suites, and `--tag` is what keeps them apart.** `claude plugin eval` runs
every `case.yaml` it finds, so the tag is all that stops the online and batch
cases joining the static mean; two tests and `validate_eval_result.py` enforce
that.

```bash
export CLAUDE_CODE_WALNUT_SPIRE=1
# The seven static cases.
claude plugin eval ./plugins/fp-check --tag static \
  --runs 3 --ablation with-without --scaffold \
  --allow-tools Bash Write Skill Workflow WebFetch WebSearch Task TaskCreate TaskUpdate TaskList TaskGet \
  --model sonnet --judge-model sonnet \
  --output-dir /tmp/fp-eval --json /tmp/fp-eval/result.json
uv run --no-project python plugins/fp-check/tests/validate_eval_result.py out.json
```

```bash
# Stage 2, whose ground truth is public record. NEVER averaged with the seven.
claude plugin eval ./plugins/fp-check --tag online \
  --runs 3 --ablation with-without --scaffold \
  --allow-tools Bash Write Skill Workflow WebFetch WebSearch Task TaskCreate TaskUpdate TaskList TaskGet \
  --model sonnet --judge-model sonnet \
  --output-dir /tmp/fp-online --json /tmp/fp-online/result.json
```

```bash
# The batch suite: one case, NEVER measured, NEVER averaged with the seven.
# Its answer is a statement about a PAIR of findings, which nothing in the static
# suite has, so the two means are not the same quantity.
claude plugin eval ./plugins/fp-check --tag batch \
  --runs 3 --ablation with-without --scaffold \
  --allow-tools Bash Write Skill Workflow WebFetch WebSearch Task TaskCreate TaskUpdate TaskList TaskGet \
  --model sonnet --judge-model sonnet \
  --output-dir /tmp/fp-batch --json /tmp/fp-batch/result.json
```

`WebFetch` and `WebSearch` are in **both** grants deliberately: a grant without
them lets the run start, denies it the network, and Stage 2 halts `OFFLINE` —
correct behaviour, scored as a failure, on a run that measured the operator's
flags. `test_the_documented_eval_command_grants_every_tool_the_cases_need` reads
the grant out of this file and pins it against what the cases declare.

| Case | Deterministic pairing (every regex over `last_message`) |
|------|----------------------|
| `blocked-attack-path` | `regex` (weight 2) naming the blocking validator |
| `inflated-impact` | `regex` scoping impact to one connection with the process surviving, `regex` naming the recovery mechanism |
| `should-not-fire` | `tool_used` with `min: 0, max: 0` on Workflow |
| `integration-cap` | `regex` for the balance credited at qty=125, `regex` for the integration root cause |
| `already-fixed` | `regex` for `#412`, plus `tool_used` Bash `min: 1` |
| `dead-route` | `regex` (weight 2) naming the routing table or the absence of a caller |
| `wrong-parameter` | `regex` (weight 2) telling the two subprocess call sites apart |
| `chained-findings` | `regex` (weight 2) connecting the pair — a chain word within 400 characters of the role check, in either order. **`--tag batch`, not `static`** |

**`chained-findings` has been measured zero times.** It is the only multi-finding
case and the only one whose correct answer is a statement about a pair, so it
carries its own tag rather than joining the static mean — the rule two paragraphs
below, applied to itself. Admit it to a mean only after it discriminates at n=3.

`integration-cap` and `already-fixed` are the only cases carrying a finding past
the gate into Phases 4–6; without them the five challenges, `confidenceBand` and
`severityCapViolation` are covered only by the free layers.

### Invocation rules, each learned by paying for a run that measured the harness

- **Target the plugin by NAME** (`fp-check@<marketplace>`), not by path: a path
  target does not register the skill, and `--ablation` silently defaults to `none`
  for a path, which is why the flag is written out above.
- **The installed cache is not your working tree.** The plugin loads from
  `~/.claude/plugins/cache/<marketplace>/<plugin>/<version>/` even for a local
  `directory` marketplace. Bump the version, update marketplace and plugin, and
  restart — "Restart to apply changes" means it. `scriptPath` bypasses the cache.
- **`--scaffold` is off by default**; without it the case runs in an empty
  directory and repo-relative paths in the prompt resolve to nothing.
  **`--output-dir` goes outside the repo:** the default writes machine-absolute
  paths into the plugin tree, failing the repo validator.
- **`--allow-tools` is an *operator* grant** needing every gated tool, not the
  ones you remember — a case's own `allowed_tools` is not enough. Without
  `Workflow` the skill cannot dispatch a phase; without `Skill` it never activates
  and the two arms are identical by construction.
- **`--case` takes one glob and does not accumulate** (unlike `--tag <tag...>`, a
  second replaces the first). `--judge-model` defaults to haiku; pin it, and add
  `--no-publish` unless publishing the report was authorised.
- An errored run is still scored, **as zero**, so a dead arm reads as an arm that
  answered badly; `validate_eval_result.py` counts them and refuses the result.

### Case authoring rules

- **Every file a scaffold writes is held byte-identical to its copy under
  `evals/fixtures/`,** and `SCAFFOLD_SOURCES` keys are asserted against the case
  directories on disk: one unlisted *file* was invisible, shipped to the eval,
  compared against nothing, never scanned for a giveaway comment.
- **No target may state its own verdict.** Three once opened with a header comment
  giving the answer away, two coaching the baseline on the plugin's own
  methodology. A giveaway scan greps for verdict and machinery markers; a second
  test replays the pre-fix headers so the marker list cannot rot into a no-op.
- **Every prompt carries the plugin-neutral multi-agent opt-in**, verbatim:
  *"Multi-agent orchestration is authorised here: use a workflow and fan out to
  subagents if the analysis calls for it."* Naming the skill hands the with-plugin
  arm a usable instruction and the baseline an impossible one, inflating the delta
  by construction; omitting it makes the model refuse to dispatch at all, a policy
  refusal `--allow-tools` cannot lift.
- **Both stage answers are pinned per case.** `stage_answers()` strips the NO
  phrasings before searching for the YES ones, because a pattern for the presence
  of a claim is satisfied by its explicit negation: `ONLINE_YES` once matched all
  seven prompts on the `go online` inside *"do not go online"*.
- **Prove a new case discriminates at n=3 before admitting it.** Two admitted on
  n=1 smoke tests showing +0.60 each came in at +0.07 and −0.20; a third scored
  +0.00 twice and was dropped. A mean over a curated suite answers "how much does
  it help on the modes the suite encodes" — quote the per-case table.
- A question the fixture cannot answer is not neutral: it propagates into every
  gate downstream and the verdict comes back about the missing context. A scaffold
  reaching Phase 4 must also **commit** its tree — Stage 3 builds in a worktree cut
  from HEAD, where an uncommitted file is simply absent.

### Grader design rules

- **Never an LLM grader alone.** `test_eval_suite.py` requires each case to pair
  one with a deterministic grader, plus runs >= 3, an `outcome` grader rather than
  only `tool_used`, and a should-NOT-fire case whose `allowed_tools` still let the
  plugin fire. The deterministic share has a floor of one third: at weight 1
  against 9 it exists and decides nothing.
- **Target `last_message`, not `trace`.** The trace carries tool results, so
  *opening the file* satisfies any pattern built from text in the target; two
  graders passed 6/6 in both arms that way. Two tests now fail a grader satisfied
  by the scaffold alone or by the prompt alone.
- **`tool_used` with `max: 0` needs `min: 0`.** `min` defaults to 1, so `max: 0`
  alone asserts the range `1..0` and fails in both arms for the behaviour the case
  rewards. Likewise `not_contains` on a phrase the right answer must name always
  fails: "this is NOT a process crash" contains "process crash".
- **A grader passable by the plugin's own vocabulary measures plumbing, not
  reasoning.** The bare token `integration` is this plugin's private `rootCause`
  enum value, emitted verbatim in `capSeverity`'s cap note, so relaying that note
  passed while the baseline had no such word to say. It is accepted only where it
  *attributes* — `integration root cause`, `integration failure`.
- **No filename distinguishes "wrote an exploit" from "wrote a harness proving
  there isn't one",** so that judgement stays with `outcome`, not `file_exists`. A
  grader that can never fail scores identically in both arms whatever happens.
- **A literal multi-word phrase is not a safe grader over model prose:** every
  inter-word position is somewhere the model may put `**`, a backtick or a hyphen,
  so admit `[-\s*_`]+` at every seam. And fitting a pattern to the recorded runs
  is memorisation, not validation — one claimed 5/5 against them and then scored
  0/3 on the next two sweeps. Widen to the semantic family, regrade against every
  recorded answer, confirm it still rejects *wrong* verdicts, and check the prompt
  and scaffold do not satisfy it. `GRADER_PROBES` holds that corpus.
- **Several independent runs disagreeing with a grader is the signal to re-read
  the grader, not the runs.** One demanded a 500 from Go's `net/http` on a handler
  panic, which never happens — `conn.serve` recovers and closes the connection.
  Six runs said so correctly and all six failed. Demanding a *specific* fact only
  helps if the fact is true, and no free layer can check that.

## Ablation isolation

The baseline arm has to be empty, and that is verified rather than assumed.
`check_ablation_isolation` in `validate_eval_result.py` reads every
`"subtype":"init"` record in each run's `tracePath` — every record, because a run
that dispatches subagents has one per session — and fails if the no-plugin arm
loaded anything, or the plugin arm loaded other than exactly one.

**It checks skills too, and for a while it did not, which made it weaker than the
failure it was written for.** c-review's bench harness voided a real run on a
*skill* leak — its own skill reached the arm meant to be without it. A skill
arrives from `~/.claude/skills` or a globally installed plugin with `plugins`
still `[]`, so inspecting only `plugins` passed a contaminated baseline.

**It reports UNVERIFIED rather than passing when no trace survives, per arm.**
Without `--keep-temp` the temp dir is deleted, which is legitimate and not a pass;
traces are reaped per temp dir, so one surviving trace once printed "isolation
verified on 1 session(s)" for an ablation whose no-plugin arm was never opened. It
returns a `Counter` over the arms and says UNVERIFIED unless both are non-zero.

## The gate

`mutation-gate.sh` breaks each covered behaviour in a sandbox copy and requires
the suite to go red. Anything that survives is testing the model, not the plugin.
It fails if zero mutations run. **No survivors, none stale.**

**Run it as `bash plugins/fp-check/tests/mutation-gate.sh` — `bash`, not `zsh`.**
Under zsh `BASH_SOURCE` is clobbered, the script cannot locate itself, and every
mutation reports as a survivor. Run it with nothing else going: under contention
one mutation took 25 minutes where it is caught in 60 seconds in isolation.

**Why some are deferred.** They break the recorded run `test_regrade.py` grades,
and that module skips because its capture records
`concept-prover:verify-attack-path` — a skipped pytest exits 0, which this
harness would read as "the mutation survived". So `defer_mutation` counts and
names them instead: as `run_mutation` they would report phantom coverage gaps,
and deleting them would shrink the gate with nothing saying so. One paid capture
(Layer 3) re-arms them.

**A mutation is only "caught" if its test command passes on UNMUTATED code**, so
the harness proves that first in a pristine sandbox. Otherwise anything failing a
command for an unrelated reason reads as full coverage — `bats` not installed, a
missing `--with pyyaml`, `pytest -k` exiting 5 on "no tests collected".

**A mutation that stops applying is an ERROR, not a survivor.** `perl -pi` exits 0
when its pattern matches nothing, so the harness checksums the sandbox and fails
the mutation if nothing changed. **Nothing runs this for you** — not `make check`,
not CI — so the count above is maintained by hand. Re-run it, re-point what goes
stale, update the count in the same commit.

## What the checkpoint gates actually enforce

Layer 2 covers the decisions, not the prose. Each of these was a checkpoint the
reference documents state as a hard rule and the scripts left to an agent's
discretion or to the orchestrator's good behaviour:

| Rule | Where it is now enforced |
|------|--------------------------|
| 2.2 needs ≥1 layer inspected — an empty `layers` dispatched zero agents and fell through to PROCEED | `missingArgs`, and `decideGate(attemptedLayers === 0)` |
| 2.2's "or CONFIRMED NONE EXIST" — the half with no way to be said, so callers passed the absence of a check as a layer | `layersSearched`, in `missingArgs` and again in `decideGate` |
| 2.3 "checked for recovery (not assumed absent)" — a dead recovery agent proceeded as "not established" | `decideGate(!recoveryVerdict)` |
| 2.4b requires the external precondition when the root cause is not internal | `missingPrecondition` |
| "Only PROCEED justifies building" — failing returns carry a populated `impact`, so a forwarded failure passed the shape check | `verification.status` in both downstream workflows |
| 5.1 challenge 4 overrides the band — a dead agent escaped the one unconditional rule | `alreadyFixedStands(unrebutted)` |
| 2.4b/2.5 severity caps — stated in the report prompt, self-reported by the agent | `severityCapViolation` |
| Destructive operations only at safety levels 1–2 | `missingArgs` in Stage 3 |
| The PoC must be readable by its reviewers — the builder runs in an isolated worktree | `poc.absolutePath`, required by the build gate |
| Brocard 5's redirection — "do real consumers exhibit the unsafe pattern?" was a question Stage 1 raised and no agent answered | `needsUserCensus`, dispatching the census |
| A census that searched nothing must never read as "no consumer is affected" | `censusProblem`, and the `unperformed` line in the summary prompt |

The design rules underneath that table, which apply to anything added to it: a
schema on **every** `agent()` call; `.filter(Boolean)` immediately after every
`parallel()`; tally against the expected list, never against what came back; a
missing verdict counts *against* the finding; no `Date.now()` or `Math.random()`;
and `required` validates presence, not content, so anything that matters needs a
predicate as well.

## Provenance

Record model, effort and CLI version with any result — `run.meta.json` and the
eval JSON both carry them. Report the pass rate over N runs; do not re-run until
green.

| | |
|---|---|
| CLI at authoring time | 2.1.224 |
| node | v22.13.1 |
| bats | 1.14.0 (`brew install bats-core`; required, not optional) |
| Layers 1–3 status | pytest, node and bats all passing |
| Mutation gate | no survivors, none stale; the deferred ones are blocked behind the Layer 3 capture |
| Layer 3 capture | stale: records `concept-prover:verify-attack-path`, so the module skips |
| Raw results kept | `eval-result-2026-07-30.json`, which `test_validate_eval_result.py` reads as a real-shaped result so a schema change cannot pass by agreeing with a mock |
