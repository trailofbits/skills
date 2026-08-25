---
name: fp-check
description: "Verifies whether a suspected security bug is real before writing anything up, returning TRUE POSITIVE, FALSE POSITIVE or NEEDS MORE INFO with the evidence behind it. Runs a static verification stage always, and adds online policy checks or a built-and-executed proof-of-concept exploit on request. Use when asked whether a finding is real, exploitable, in scope, already fixed or a false positive; to triage findings from a scanner, a bug bounty submission or an agentic discovery run; and when asked to write a PoC, prove a vulnerability, demonstrate an attack or exploit a bug — those all need the attack path verified first, which is what this does. Not for hunting new bugs."
allowed-tools: Read Grep Glob LSP Bash Write Edit Workflow AskUserQuestion Task TaskCreate TaskUpdate TaskList TaskGet TaskOutput
---

# False Positive Check

Three stages in a fixed order. **Stage 1 always runs and reaches a verdict on its
own.** Stages 2 and 3 run only when the user asks for them, and each can only
narrow or correct what Stage 1 returned.

```text
              ┌─ Stage 1: STATIC  (always) ──────────────────────────┐
  finding ──> │  per-layer reachability → recovery →                  │
              │  already-fixed → impact + severity →                  │
              │  adversarial → the six gates                          │
              └───────────────────────┬──────────────────────────────┘
                                      │ verdict + severity + open questions
  Q2: online checks? ──yes──> ┌───────▼─ Stage 2: ONLINE ────────────┐
                              │  policy → public reachability →       │
                              │  scope → past bugs → consumer census  │
                              │  → summary                            │
                              │  may halt: offline, out-of-scope,     │
                              │  duplicate                            │
                              └───────────────┬──────────────────────┘
  Q1: validate by PoC? ──yes──> ┌─────────────▼─ Stage 3: POC ────────┐
                                │  build → execute → 5 challenges →    │
                                │  confidence band → report            │
                                └──────────────────────────────────────┘
```

The gates in each stage are **code**, not instructions: a workflow script returns
a status you cannot talk it out of.

## When to Use

- "Is this bug real?", "is this a true positive?", "is this a false positive?"
- "Verify this finding", "check if this is exploitable"
- "Is this already fixed?", "is this in scope for their bounty?"
- Filtering findings from a scanner or an agentic discovery run before human review

## When NOT to Use

- Finding or hunting for bugs ("find bugs", "audit this code") — this verifies a
  finding you already have
- General code review for style, performance, or maintainability
- When the user explicitly asks for a quick look without verification

## Step 0: Ask the two questions, then restate the claim

**Ask both questions before Stage 1 runs**, not between stages. The user should
not be interrupted mid-analysis, and knowing the answers up front lets Stage 1
record the open questions each later stage will resolve.

| Question | Default | Why it is a question and not automatic |
|---|---|---|
| **Q1. Validate by building a PoC?** | **no** | It costs several times a static run. Worth it to settle a disputed finding; wasteful when static analysis already answered. A yes authorises the *cost*, not the *conclusion*: Stage 1 may settle the finding first, and then the verdict is what the request gets. |
| **Q2. Run online checks?** | **no** | Needs network access and a real upstream project. Stage 2 fails closed when offline, so defaulting it on makes every offline invocation halt. |

**Read the answers out of the request first, and only fall back to
`AskUserQuestion` when they are genuinely absent.** Answering Q1: *"build a PoC"*,
*"prove it"*, *"write an exploit"*, *"demonstrate it"* → yes; *"static only"*,
*"don't write a PoC"*, *"just tell me if it's real"* → no. Answering Q2: *"check
their security policy"*, *"is this in scope"*, *"look for duplicates"*, *"check
upstream"* → yes; *"offline"*, *"don't go online"*, *"work from the code"* → no.

Asking when the answer was already given is worse than rude: in a non-interactive
harness there is nobody to answer, so the question hangs or falls through to the
default. Both defaults are **no**, so a skill that always asks runs Stage 1 alone
and reports as though all three stages had run.

Then restate the bug in your own words. **Half of false positives collapse here.**
Establish, and if you cannot, ask:

- **The claim** — "heap overflow in `parse_header()` when `content_length` > 4096"
- **The alleged root cause** — "no bounds check before the `memcpy` at line 142"
- **The trigger** — "an HTTP request with an oversized Content-Length"
- **The claimed impact** — "RCE via controlled heap corruption"
- **The threat model** — who the attacker is, what capability they already hold,
  how they exploit it, what harm results. A report that cannot answer *"an
  attacker with [capability] can [action] to achieve [impact]"* is dismissible on
  its face, and Stage 1 rejects the dispatch without it.
- **The bug class** — and read
  [bug-class-verification.md]({baseDir}/references/bug-class-verification.md) for
  what that class specifically has to establish
- **Whether it is a finding at all** — read
  [dismissal-grounds.md]({baseDir}/references/dismissal-grounds.md): the attacker
  already holds what the exploit grants, the behaviour is specified or documented,
  the cure is worse than the disease. **Guidance, not a gate** — recognise the
  shape here, and let the stage holding the trace decide it
- **The entry point and the layers between it and the sink** — the dispatch's
  most important input; see below

## Enumerating the layers

Stage 1 spends one agent per validation layer, so the list you pass is what it
inspects. Walk the path from entry point to sink and name every check between
them: authorization, input sanitisation, allowlists, rate limiting, type and
bounds checking. At most **4** are dispatched; more is rejected before anything is
spent, so narrow the attack path or split the finding.

**A layer must be a check that EXISTS, with a `file:line`.** Never enumerate the
*absence* of one — an agent asked whether a layer that does not exist stops the
payload cannot answer coherently, and kills the finding before impact is reached.

**If nothing on the path validates the payload, send `layers: []` together with
`layersSearched`** — what you read, and what you did not find. An empty list alone
is rejected: a forgotten field and a deliberate "nothing guards this" are the same
value, and the declaration is what tells them apart. It must **name at least one
file you read** (`billing/charge.py`): `n/a`, `none` and `TBD` are rejected exactly
as the empty list is, because a placeholder and an audit are otherwise that same
pair of indistinguishable values all over again.

## Routing: standard or deep

Stage 1 picks the route from the dispatch; override with `route: 'deep'` when the
user asks for full verification. **Standard is the default and is doing real
work** — do not reach for `deep` to feel thorough.

**Deep** adds three proofs to the reachability phase — API contracts and
environmental protections, the algebraic bounds proof, race feasibility — and runs
the full 13 devil's-advocate questions instead of the 7-question spot check; both
lists are in
[false-positive-patterns.md]({baseDir}/references/false-positive-patterns.md). It
fires automatically on 3+ layers, on `crossComponent: true` or `ambiguous: true`,
and on a memory-safety, arithmetic, concurrency or availability bug class — the
Route column of
[bug-class-verification.md]({baseDir}/references/bug-class-verification.md) is
authoritative and the tests pin `selectRoute` against it.

## Dispatch

Wait for each workflow. `Workflow` returns **on launch**, so the run continues in
the background and ending your turn tears it down mid-flight, discarding finished
agents and leaving no report. **Do not end your turn until the workflow has returned.**
Use `TaskOutput` with `block: true` and a timeout of at least 600000.

### `baseDir` — copy it, never reconstruct it

All three stages take `baseDir` and interpolate it into the `references/...` paths
they hand their agents. **Copy the value out of the reference links at the bottom
of this file and strip the trailing `/references/<file>.md`.** Those links are
already expanded to the copy of the skill that is actually running, which is the
only place the correct value exists.

Do not rebuild the path from the plugin name, and above all do not type a version
number. The plugin installs to
`~/.claude/plugins/cache/<marketplace>/fp-check/<version>/skills/fp-check`,
several versions coexist there, and a wrong one **fails silently** — every
reference read resolves to a file that is absent or stale, and the agents answer
without the lookup table they were sent for. Running from a checkout by
`scriptPath` instead, it is that checkout's `plugins/fp-check/skills/fp-check`.
Either way it must be **absolute**: a path relative to your working directory is
not relative to the agent's. On native Windows a drive-letter path
(`C:\...\skills\fp-check`) is absolute and is taken as it stands; translating it to
a POSIX shape names a directory that does not exist.

### Stage 1 — always

```text
Workflow({ name: 'fp-check:triage-static', args })

args = {
  baseDir:    absolute path of this skill's directory — see above
  finding: {
    summary:        one sentence, what the code does wrong
    sink:           file:line of the vulnerable operation
    component:      the module or service it lives in
    claimedImpact:  the impact as reported, before verification
    bugClass:       injection, overflow, race, TOCTOU, authz bypass, crypto, ...
    threatModel:    attacker, capability held, exploit mechanism, harm
  }
  entryPoint: {
    description:  how attacker data enters — the endpoint, RPC, message, upload
    location:     file:line of the entry point itself
    payload:      a concrete example input, not "malicious payload here"
  }
  layers: [ { name, location, checks } ]     at most 4. Checks that EXIST only.
          name and location are required per layer; checks is optional and the
          layer agent derives it from the code when you omit it
  layersSearched: required ONLY when layers is [] — what you read and what you
          did not find, NAMING THE FILES (`billing/charge.py`); a placeholder
          such as n/a is rejected. Never send the absence of a check as a layer
  scope:  a STRING describing the declared scope; an object interpolates as
          [object Object] and is rejected
  route:  'standard' | 'deep'                optional; computed when omitted
  crossComponent: true                       optional routing signal
  ambiguous:      true                       optional routing signal
}
```

Returns one of `TRUE_POSITIVE`, `FALSE_POSITIVE`, `NOT_EXPLOITABLE`,
`NOT_VULNERABLE`, `ALREADY_FIXED`, `OUT_OF_SCOPE`, `NEEDS_MORE_INFO`, `BLOCKED` —
each with a `reason`, and with `severity` and `severityCorrection` when it
reached an impact.

A return that got as far as the verdict also carries `blockingProofs`: deep-route
proofs that reported the finding impossible, carried to the six gates rather than
allowed to end the stage. **A non-empty `blockingProofs` returns `NEEDS_MORE_INFO`
even when all six gates read `PASS`** — the payload will show six passes and the
status will not be `TRUE_POSITIVE`. The `reason` quotes the proof; answering it is
what turns the finding into a verdict.

### Stage 2 — only if Q2 was yes

```text
Workflow({ name: 'fp-check:triage-online', args })

args = {
  baseDir, finding                  as above
  verification:  triage-static's return value, forwarded VERBATIM. status,
                 severity, severityCorrection and every impact.* field are read —
                 rootCause and classification cap and census, result grades impact
  project: { name, url }            the upstream project to look up
  sources: [ { label, query } ]     at least one public venue. Only the first 6
                                    get an agent; the rest come back named in
                                    `beyondCap` as unchecked rather than being
                                    rejected, so do not pad the list:
                                    github-issues, github-prs,
                                    github-advisories, mailing-list, immunefi
}
```

**Only `TRUE_POSITIVE` and `NEEDS_MORE_INFO` are accepted here.** Anything else
returns `BLOCKED`: a finding already dismissed on the code does not need a policy
check, and running one invites the online evidence to argue a dead finding back to
life.

Stage 2 also requires `verification.severity` and all four `verification.impact`
fields, which a return carries only if it reached the impact phase — so a
`NEEDS_MORE_INFO` raised before that is rejected too. Resolve the missing fact and
re-run Stage 1 rather than forwarding a partial return.

**A declared scope is overturned by re-running Stage 1, not here.** `OUT_OF_SCOPE`
is decided before the impact agent runs, so such a return has no impact to forward.
If a published policy contradicts your declared scope, correct the `scope`
argument and dispatch Stage 1 again.

**The downstream-consumer census is decided in code, not asked for.** When severity
turns on how clients use the target — an `integration` or `external` root cause, a
`hardening_gap`, or a sink no in-repo caller drives — Stage 2 searches the
dependents graph and public code indexes, keeping only confirmed occurrences with
links. On a bug exploitable in the target itself it is skipped, with the reason in
`census.why` rather than silently. Read `census.state` first:

| `census.state` | What it means |
|---|---|
| `performed` | consumers were searched. `census.result` is `affected-users-found` or `no-confirmed-users`, and **the latter bounds what was searched — it is not proof no consumer is affected** |
| `unperformed` | the census was needed and could not be run. Downstream usage is UNCHECKED, not clear |
| `not-applicable` | the bug does not depend on a consumer, and `census.why` says which facts decided that |

Returns `TRIAGED`, `OUT_OF_SCOPE`, `DUPLICATE`, `NEEDS_MORE_INFO`, `BLOCKED`, or
`OFFLINE`. **`OFFLINE` is a correct outcome, not an error** — every claim this
stage makes is about the project's *current* public posture, and it will not make
one from memory.

### Stage 3 — only if Q1 was yes **and** Stage 1 returned `TRUE_POSITIVE`

Only a `TRUE_POSITIVE` justifies building an exploit, and the script enforces
that: `verification.status` is checked, because a failing Stage 1 return carries a
fully populated `impact` and `severity` too, so forwarding one satisfies every
other field and buys a PoC for a finding that failed its own gates.

For any other Stage 1 status, **do not dispatch this stage** — the PoC question
has already been answered, and the next section is what to answer it with.

```text
Workflow({ name: 'fp-check:triage-poc', args })

args = {
  baseDir, finding                  as above
  verification:  triage-static's return value, forwarded VERBATIM
                 (its status, reason, impact.impact, impact.rootCause,
                  impact.classification, severity, severityCorrection and
                  history.fixed / history.searched are all read)
  envelope: {
    level:        1-5, per safety-guidelines.md
    hosts:        array of permitted targets; [] means local process only
    destructive:  boolean; only permitted at levels 1-2
  }
  candidates: [ { name, description, entryPoint, payload } ]
                description, entryPoint and payload are required per candidate;
                name is optional and only labels the build agent. At most 2 are
                attempted, the rest are held in reserve, and an empty list
                returns NO_CANDIDATES without spending anything
}
```

Returns `REPORTED`, `DO_NOT_SUBMIT`, `ALREADY_FIXED`, `BUILD_FAILED`, `NO_CANDIDATES`,
`NEEDS_MORE_INFO`, or `BLOCKED`. `REPORTED`'s `reason` is the severity rationale and its
top-level `severity` the number; relay `report.reportPath`, `band` and the tally with it.

## When the user asked for a PoC and Stage 1 said no

Most requests that reach this skill open with *"write a PoC for this"*. When
Stage 1 returns a verdict of its own, that request has been **answered, not
refused**, and answering it is the entire deliverable.

**A terminal Stage 1 verdict ends the PoC work.** Building an exploit by hand
afterwards is the failure, not a fallback — the gate that stopped Stage 3 is the
same gate, and it applies to you. Hand-building after a refusal produces a false
positive with a working exploit attached.

The other half of the failure is wording, and it survives a correct analysis:
*"Confirmed for v1.4.0 as reported, but already fixed on current HEAD"* is what a
session with no verification at all answers. Finding the fix and then writing that
sentence scores as though the fix had never been found.

### The verdict is the first clause of the first sentence

A sentence that opens with what the report got right and closes with the
refutation reads as a confirmation. Lead with the verdict. The reported version's
history goes after it, never before.

| Stage 1 returned | Open with | Not |
|---|---|---|
| `ALREADY_FIXED` | `RETRACTED — already fixed by <reference>`, then all three of: the bug was real at the reported version, a fix landed, **do not pay it and do not report it against current code** | "Confirmed as reported, but already fixed" — and not a lowered severity either; a retraction is not a downgrade |
| `NOT_EXPLOITABLE` | `FALSE POSITIVE — no attacker-reachable path: <the blocking layer, verbatim>` | "The sink is genuinely injectable, however…" |
| `NOT_VULNERABLE` | `FALSE POSITIVE — intended behaviour: <the evidence>` | "Arguably a bug, though by design" |
| `OUT_OF_SCOPE` | `OUT OF SCOPE — <the clause>`, and say plainly that this answers scope and not whether the bug is real | a severity; nothing here established one |
| `FALSE_POSITIVE` | `FALSE POSITIVE — <the reason, verbatim>` | "unproven", which is NEEDS MORE INFO and a different answer |

`NEEDS_MORE_INFO` and `BLOCKED` are **not** on this list and must not be written
up as any row of it. One is a fact still to establish, the other an analysis that
could not run; both are answered by closing the gap and re-running Stage 1.

### A negative PoC is legitimate; an exploit is not

Demonstrating that the guard **rejects** the payload is different work from
demonstrating the bug, and worth doing when the refusal is what the reporter
disputes. Optional — Stage 1 already decided the verdict — and bounded:

- It drives the **entry point**. A harness calling the sink directly is an exploit
  whatever the file is named, and only shows the sink is dangerous in isolation,
  which was never in question.
- Its assertion is the refusal — the payload is rejected, the route has no caller,
  the digests compare in constant time — so it **fails** if the payload ever
  reaches the sink.
- Never call it a PoC for the finding or place it beside a confirmed-vulnerability
  framing. It is evidence for the refutation.
- If it unexpectedly *does* reach the sink, that is a new fact for Stage 1, not a
  licence to report. Re-dispatch with it as a layer.

### If you dispatched Stage 3 anyway

It returns `BLOCKED` carrying `settledBy` — the Stage 1 status that settled it —
and a `deliverable`. That `BLOCKED` is **not** a NEEDS MORE INFO: nothing is
missing, and re-dispatching buys the same refusal twice. Report per the table
above.

## Completion Gate

Before you report anything, check what actually came back.

1. **Did the workflow return at all?** One that was killed or aborted has not
   failed its gates, it has not finished them: say so and re-dispatch. Never infer
   a verdict from partial agent output.
2. **Read `status`, not the shape.** Failing returns carry populated payloads, so
   a result that looks complete may be a `NEEDS_MORE_INFO`.
3. **Relay the `reason` verbatim.** It names the layer, clause, gate or commit
   that decided the outcome, and that specificity is the deliverable.
4. **State the verdict in your final response**, with the severity and evidence —
   Stage 3 writes a report file, and a file is not an answer. If Stage 3 ran, give
   the confidence band and the N/5 tally too.
5. **A stage that correctly refused has finished, not failed.** The opposite of
   item 1, and it needs the opposite handling: relay the refusal, do not
   re-dispatch it.

## Verdicts

Stage statuses collapse onto three user-facing verdicts:

| Verdict | From | Report as |
|---|---|---|
| **TRUE POSITIVE** | `TRUE_POSITIVE`, `REPORTED` | `BUG #N TRUE POSITIVE — <description>`, with severity |
| **FALSE POSITIVE** | `NOT_EXPLOITABLE`, `NOT_VULNERABLE`, `FALSE_POSITIVE` | `BUG #N FALSE POSITIVE — <the reason, verbatim>` |
| **NEEDS MORE INFO** | `NEEDS_MORE_INFO`, `BLOCKED`, `OFFLINE`, `BUILD_FAILED`, `NO_CANDIDATES` | `BUG #N NEEDS MORE INFO — <the missing fact>` |

`ALREADY_FIXED` and `DUPLICATE` are retractions, reported with their reference;
`OUT_OF_SCOPE` answers scope, not whether the bug is real. The opening lines for
each are in the table above.

**Stage 3's `BLOCKED` is four outcomes, and `settledBy` tells the first from the
rest.** With `settledBy`, Stage 1 settled the finding and its verdict is what you
report. Without it the `reason` says which: an unusable arg shape is re-dispatched
with the shape fixed, while a failed independent artifact check or a severity
above the cap names the artifact to correct and is not re-dispatched.

`TRIAGED` is Stage 2 finishing, not a verdict of its own: keep the Stage 1 verdict,
take its open questions from `summary`, and its scope and severity from the
**top-level `scopeVerdict` and `severity`** — not `summary`'s, which are pre-cap
and unvalidated. Out-of-scope ends the stage itself, on a quoted clause.

**An optional stage that did not finish leaves the Stage 1 verdict standing.**
Stage 2's `BLOCKED`, `OFFLINE` and `NEEDS_MORE_INFO` carry `stageOneStatus` and the
`severity` Stage 1 reached: report THAT verdict, with the `reason` as the check
that could not be made — a policy page that would not load has not unmade a TRUE
POSITIVE established from the code. The NEEDS MORE INFO row applies only when
`stageOneStatus` is absent. **An arg-shape `reason` is the one of those you fix
and re-dispatch** rather than report — no network, a dead agent and a blank summary
are not recoverable by retrying, and a bad dispatch is. Reporting it leaves the
online check you asked for never made. Stage 3 is the same rule without the field,
dispatched only on `TRUE_POSITIVE`: its `BUILD_FAILED`, `NO_CANDIDATES` and
`NEEDS_MORE_INFO` are a PoC that could not be produced, not a finding refuted.

**`DO_NOT_SUBMIT` is two outcomes wearing one status, and the `reason` tells them
apart.** Mapping both to FALSE POSITIVE is the rounding error this skill prevents:

| The `reason` starts with | What actually happened | Report as |
|---|---|---|
| `confidence NONE (0/5 defeated)` | not one challenge was rebutted; the reviewers refuted the finding | **FALSE POSITIVE**, naming the unrebutted challenges |
| `confidence LOW (1/5 defeated)` or `(2/5 defeated)` | some challenges were rebutted with evidence and the rest were not — a missing fact, not a refutation | **NEEDS MORE INFO**, naming the unrebutted challenges as the facts to settle |

Both rows are reviewers who argued. **A challenge agent that returned no verdict
never reaches `DO_NOT_SUBMIT`** — Stage 3 returns `NEEDS_MORE_INFO` naming the
silent agents instead. Silence still costs the finding its band step, so it can
withhold a report; it cannot retract one.

## Batch Triage

More than one finding goes through **`fp-check:triage-batch`**, not through your
own loop. It derives the shared context once, dispatches Stage 1 per finding with
it, and **accounts for every finding by id** — one whose sub-workflow returned
nothing comes back in `unverified`, never silently absent. That accounting is the
reason it is a workflow and not an instruction.

1. Run Step 0 for every finding first — restating the claims collapses the obvious
   false positives immediately and costs nothing.
2. Ask the two questions **once**, for the batch.
3. Dispatch `fp-check:triage-batch` once, with all of them.
4. Stages 2 and 3 stay yours, per finding. `workflow()` does not nest, so the
   batch dispatches Stage 1 and nothing else.

```text
Workflow({ name: 'fp-check:triage-batch', args })

args = {
  baseDir   absolute path of this skill's directory — see above
  scope     a STRING, the declared scope for the whole batch; forwarded to every
            Stage 1 dispatch, so a per-finding scope means separate dispatches
  project   optional; what the codebase is, for the shared-context agent
  findings: [ { id, finding, entryPoint, layers, layersSearched, route,
                crossComponent, ambiguous } ]
            at most 5, and more is rejected before anything is spent. `id` is
            yours, must be unique, and is what the ledger and any chain names.
            Every other field is Stage 1's, with the contract documented above
}
```

Returns `BATCH_TRIAGED`, carrying `findings` (a row per verdict), `unverified`,
`chains`, and `notChainable`. Report each row exactly as you would a single
dispatch, using the Verdicts table — **an `unverified` row is NEEDS MORE INFO and
must be reported, not omitted**, and a row carrying `chainedInto` is the exception
described below. A finding is `unverified` when its Stage 1 returned nothing, or
anything that is not one of the verdicts in the table above — an allowlist, so
`BLOCKED`, a payload from the wrong stage and a mis-cased status all land there
and none of them is in `findings`. `BLOCKED` at the batch level means the batch
itself could not run: an unusable arg shape, or no finding reaching a verdict.

The shared context reaches each Stage 1 as its `context` argument. That argument
is the batch's to supply; do not send one on a single dispatch, where the agents
derive those facts themselves.

### The exploit chain check

Findings that individually failed a gate may combine into a viable attack. This is
the only place in the plugin where that comparison exists, because no other
workflow sees a second finding. The pairs worth an agent are chosen in code:

| Pair | Why it is checked |
|---|---|
| two `NOT_EXPLOITABLE` **whose blocking layers differ** | the same wall stopping both composes to nothing; different walls may. This is the shape the check is for |
| `NOT_EXPLOITABLE` + `TRUE_POSITIVE` | "you cannot get there" plus "here is how you get there" |
| `NEEDS_MORE_INFO` + `TRUE_POSITIVE` | the missing fact may be the other finding's established impact |

`ALREADY_FIXED` pairs with nothing — it is dead, and pairing it invites the chain
agent to argue it back to life. `NOT_VULNERABLE`, `OUT_OF_SCOPE` and
`FALSE_POSITIVE` are not chainable either, and come back named in `notChainable`
rather than dropped. A Stage 1 that returned `BLOCKED` is not in that list because
it is not a verdict at all — it is in `unverified`. At most **3** pairs are checked; the rest are named in
`chainsBeyondCap` as unchecked, which is not the same as no chain.

A chain is only reported when the agent names both contributions **and** the
mechanism by which one supplies what the other lacks. "Both are auth bugs" is
rejected in code and logged.

**A confirmed chain is a row with a verdict of its own**, carrying
`status: NEEDS_MORE_INFO` and the mechanism in `reason`, because the composed
attack went through one agent and not Stage 1. Report it as NEEDS MORE INFO and
**re-dispatch the composed finding to Stage 1** with that mechanism given. **A
finding named in a chain is not reported as a false positive**: its row keeps
Stage 1's status and carries `chainedInto`, and printing that `NOT_EXPLOITABLE` as
FALSE POSITIVE beside a chain built on it reads as the dismissal — which loses the
finding this check exists to recover.

## Rationalizations to Reject

| Rationalization | Why it's wrong | Required action |
|---|---|---|
| "Rapid analysis of the remaining bugs" | Every finding gets the same dispatch | Go back and dispatch the next one |
| "This pattern looks dangerous, so it's a vulnerability" | Pattern recognition is not analysis | Let Stage 1 trace the layers |
| "I can see it's unreachable, no need to dispatch" | That judgement is what the per-layer fan-out exists to make independently, and a linear read gets it wrong: naming the blocking guard and concluding correctly are different skills | Dispatch |
| "The sink is genuinely injectable, so the finding is real" | Attacker control **of the sink** is not control of any reachable entry point. A PoC calling the sink directly is the canonical false positive with an exploit attached | Gate 2 (Reachability) decides this, on the entry point |
| "Similar code was vulnerable elsewhere" | Each context has different validation, callers and protections | Verify this instance |
| "This is clearly critical" | LLMs over-rate severity, and the severity caps are arithmetic | Let Stage 1e apply them |
| "I'll skip the PoC question and just build one" | A PoC costs several times a static run, and the user gets a bill they did not agree to | Ask, or read the answer from the request |
| "Stage 3 refused, but the user asked for a PoC, so I'll build one myself" | The refusal **is** the answer to that request | State the Stage 1 verdict; build a *negative* PoC if the refusal is what is disputed |
| "It was real at the reported version, so I'll confirm it and note the fix" | Leading with the confirmation reports a bug the code does not have | Open with the retraction and the reference; the version history comes after |
| "The verdict is unproven, so it is a false positive" | "Unproven" is NEEDS MORE INFO — a fact still to establish, not a refutation | Name the missing fact and re-run Stage 1 with it |

## References

| File | What is in it |
|---|---|
| [checkpoints.md]({baseDir}/references/checkpoints.md) | the pass criteria for every checkpoint, and the crosswalk from stages to checkpoints to the six gates |
| [dismissal-grounds.md]({baseDir}/references/dismissal-grounds.md) | why a report may not be a finding, and the guards against wrongly dismissing a valid one |
| [gate-reviews.md]({baseDir}/references/gate-reviews.md) | the six gates and the verdict format |
| [false-positive-patterns.md]({baseDir}/references/false-positive-patterns.md) | the 13-item checklist and the four red-flag lists |
| [bug-class-verification.md]({baseDir}/references/bug-class-verification.md) | what each bug class specifically has to establish |
| [recovery-mechanisms.md]({baseDir}/references/recovery-mechanisms.md) | what each runtime does on a panic, and the checklist before claiming a crash |
| [validation-dimensions.md]({baseDir}/references/validation-dimensions.md) | scope, security model, and design-intent judgement calls |
| [evidence-templates.md]({baseDir}/references/evidence-templates.md) | the algebraic bounds proof and the data-flow trace, as fillable forms |
| [poc-anti-patterns.md]({baseDir}/references/poc-anti-patterns.md) | PoC construction rules, enforced by `scripts/poc-lint.sh` |
| [test-integration.md]({baseDir}/references/test-integration.md) | framework patterns for a test-integrated PoC |
| [safety-guidelines.md]({baseDir}/references/safety-guidelines.md) | the five envelope levels |
